package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	imapserver "github.com/emersion/go-imap/server"
	webdavcarddav "github.com/emersion/go-webdav/carddav"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-smtp"
	"github.com/emersion/go-vcard"
	"golang.org/x/term"

	"github.com/acheong08/ferroxide/auth"
	"github.com/acheong08/ferroxide/caldav"
	ferrocarddav "github.com/acheong08/ferroxide/carddav"
	"github.com/acheong08/ferroxide/config"
	"github.com/acheong08/ferroxide/events"
	"github.com/acheong08/ferroxide/exports"
	imapbackend "github.com/acheong08/ferroxide/imap"
	"github.com/acheong08/ferroxide/imports"
	"github.com/acheong08/ferroxide/protonmail"
	smtpbackend "github.com/acheong08/ferroxide/smtp"
	"github.com/google/uuid"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	torAPIEndpoint     = "https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api"
	defaultAppVersion  = "Other"
	carddavMaxResourceSize = 100 * 1024
	carddavMaxReportSize   = 1 * 1024 * 1024
)

var (
	debug       bool
	apiEndpoint string
	appVersion  string
	proxyURL    string
	tor         bool
	carddavVCardVersion string
)

func makeHTTPClientFromProxy(proxyArg string) (*http.Client, error) {
	fmtProxy := ""
	client := &http.Client{}
	if tor {
		un, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		// Tor requires socks5. To keep the same format as without tor, we allow
		// the user to specify socks5:// in the proxy URL.
		// But we remove it
		if strings.HasPrefix(proxyArg, "socks5://") {
			proxyArg = strings.Replace(proxyArg, "socks5://", "", 1)
		}
		fmtProxy = fmt.Sprintf("socks5://ferroxide_%s::@%s", un, proxyArg)

	} else {
		if !strings.Contains(proxyArg, "://") {
			// Assume socks5:// if no scheme is provided
			proxyArg = "socks5://" + proxyArg
		}
		fmtProxy = proxyArg // Don't hard code socks5://
	}

	proxy, err := url.Parse(fmtProxy)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}

	client = &http.Client{Transport: tr}
	return client, nil
}
func newClient() *protonmail.Client {
	httpClient := &http.Client{}
	if proxyURL != "" {
		proxiedClient, err := makeHTTPClientFromProxy(proxyURL)
		if err != nil {
			log.Fatal("Error creating proxied http.Client: ", err)
		}

		httpClient = proxiedClient
	}
	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		Debug:      debug,
		HTTPClient: httpClient,
	}
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager, tlsConfig *tls.Config) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost" // TODO: make this configurable
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("SMTP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("IMAP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

type propPatchProp struct {
	Space string
	Local string
}

type propfindProp struct {
	Space string
	Local string
}

func parsePropPatchProps(body io.Reader) []propPatchProp {
	dec := xml.NewDecoder(body)
	props := make([]propPatchProp, 0)
	seen := make(map[string]struct{})
	depth := 0
	propDepth := -1

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return props
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if strings.EqualFold(t.Name.Local, "prop") {
				propDepth = depth
				continue
			}
			if propDepth != -1 && depth == propDepth+1 {
				key := t.Name.Space + "|" + t.Name.Local
				if _, ok := seen[key]; !ok {
					props = append(props, propPatchProp{Space: t.Name.Space, Local: t.Name.Local})
					seen[key] = struct{}{}
				}
			}
		case xml.EndElement:
			if propDepth != -1 && depth == propDepth && strings.EqualFold(t.Name.Local, "prop") {
				propDepth = -1
			}
			depth--
		}
	}

	return props
}

func parsePropfindProps(body io.Reader) []propfindProp {
	dec := xml.NewDecoder(body)
	props := make([]propfindProp, 0)
	seen := make(map[string]struct{})
	depth := 0
	propDepth := -1

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return props
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if strings.EqualFold(t.Name.Local, "prop") {
				propDepth = depth
				continue
			}
			if propDepth != -1 && depth == propDepth+1 {
				key := t.Name.Space + "|" + t.Name.Local
				if _, ok := seen[key]; !ok {
					props = append(props, propfindProp{Space: t.Name.Space, Local: t.Name.Local})
					seen[key] = struct{}{}
				}
			}
		case xml.EndElement:
			if propDepth != -1 && depth == propDepth && strings.EqualFold(t.Name.Local, "prop") {
				propDepth = -1
			}
			depth--
		}
	}

	return props
}

func writePropPatchResponse(resp http.ResponseWriter, req *http.Request) {
	props := parsePropPatchProps(req.Body)

	resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
	resp.WriteHeader(http.StatusMultiStatus)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:">`)
	b.WriteString(`<D:response><D:href>`)
	_ = xml.EscapeText(&b, []byte(req.URL.Path))
	b.WriteString(`</D:href><D:propstat><D:prop>`)

	nsPrefix := make(map[string]string)
	nextIdx := 1
	for _, p := range props {
		if p.Local == "" {
			continue
		}
		if p.Space == "" || p.Space == "DAV:" {
			fmt.Fprintf(&b, "<D:%s/>", p.Local)
			continue
		}
		prefix, ok := nsPrefix[p.Space]
		if !ok {
			prefix = fmt.Sprintf("X%d", nextIdx)
			nextIdx++
			nsPrefix[p.Space] = prefix
		}
		fmt.Fprintf(&b, "<%s:%s xmlns:%s=\"", prefix, p.Local, prefix)
		_ = xml.EscapeText(&b, []byte(p.Space))
		b.WriteString("\"/>")
	}

	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`)
	_, _ = resp.Write(b.Bytes())
}

func writeRootPropfindResponse(resp http.ResponseWriter, req *http.Request) {
	const principalPath = "/caldav/"
	const homeSetPath = "/caldav/calendars/"

	resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
	resp.WriteHeader(http.StatusMultiStatus)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">`)
	b.WriteString(`<D:response><D:href>/</D:href><D:propstat><D:prop>`)
	b.WriteString(`<D:current-user-principal><D:href>`)
	_ = xml.EscapeText(&b, []byte(principalPath))
	b.WriteString(`</D:href></D:current-user-principal>`)
	b.WriteString(`<C:calendar-home-set><D:href>`)
	_ = xml.EscapeText(&b, []byte(homeSetPath))
	b.WriteString(`</D:href></C:calendar-home-set>`)
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`)
	_, _ = resp.Write(b.Bytes())
}

const addressbookHomePath = "/contacts/"

func writeRootPropfindResponseCardDAV(resp http.ResponseWriter, req *http.Request) {
	const principalPath = "/contacts/"
	const homeSetPath = "/contacts/"

	resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
	resp.WriteHeader(http.StatusMultiStatus)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	b.WriteString(`<D:response><D:href>/</D:href><D:propstat><D:prop>`)
	b.WriteString(`<D:current-user-principal><D:href>`)
	_ = xml.EscapeText(&b, []byte(principalPath))
	b.WriteString(`</D:href></D:current-user-principal>`)
	b.WriteString(`<C:addressbook-home-set><D:href>`)
	_ = xml.EscapeText(&b, []byte(homeSetPath))
	b.WriteString(`</D:href></C:addressbook-home-set>`)
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`)
	_, _ = resp.Write(b.Bytes())
}

func writeContactsPropfindResponse(resp http.ResponseWriter, req *http.Request, backend webdavcarddav.Backend) {
	const collectionPath = "/contacts/"

	props := parsePropfindProps(req.Body)

	resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
	resp.WriteHeader(http.StatusMultiStatus)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav" xmlns:CS="http://calendarserver.org/ns/" xmlns:MM="http://me.com/_namespace/" xmlns:ME="urn:mobileme:davservices">`)
	b.WriteString(`<D:response><D:href>`)
	_ = xml.EscapeText(&b, []byte(collectionPath))
	b.WriteString(`</D:href><D:propstat><D:prop>`)

	emitEmpty := func(space, local string) {
		switch space {
		case "DAV:":
			fmt.Fprintf(&b, "<D:%s/>", local)
		case "urn:ietf:params:xml:ns:carddav":
			fmt.Fprintf(&b, "<C:%s/>", local)
		case "http://calendarserver.org/ns/":
			fmt.Fprintf(&b, "<CS:%s/>", local)
		case "http://me.com/_namespace/":
			fmt.Fprintf(&b, "<MM:%s/>", local)
		case "urn:mobileme:davservices":
			fmt.Fprintf(&b, "<ME:%s/>", local)
		default:
			fmt.Fprintf(&b, "<D:%s/>", local)
		}
	}

	for _, p := range props {
		switch {
		case p.Space == "DAV:" && p.Local == "resourcetype":
			b.WriteString(`<D:resourcetype><D:collection/><D:principal/><C:addressbook/></D:resourcetype>`)
		case p.Space == "DAV:" && p.Local == "displayname":
			b.WriteString(`<D:displayname>ProtonMail</D:displayname>`)
		case p.Space == "DAV:" && p.Local == "current-user-principal":
			b.WriteString(`<D:current-user-principal><D:href>`)
			_ = xml.EscapeText(&b, []byte(collectionPath))
			b.WriteString(`</D:href></D:current-user-principal>`)
		case p.Space == "DAV:" && p.Local == "principal-URL":
			b.WriteString(`<D:principal-URL><D:href>`)
			_ = xml.EscapeText(&b, []byte(collectionPath))
			b.WriteString(`</D:href></D:principal-URL>`)
		case p.Space == "DAV:" && p.Local == "owner":
			b.WriteString(`<D:owner><D:href>`)
			_ = xml.EscapeText(&b, []byte(collectionPath))
			b.WriteString(`</D:href></D:owner>`)
		case p.Space == "DAV:" && p.Local == "current-user-privilege-set":
			b.WriteString(`<D:current-user-privilege-set>`)
			b.WriteString(`<D:privilege><D:read/></D:privilege>`)
			b.WriteString(`<D:privilege><D:write/></D:privilege>`)
			b.WriteString(`<D:privilege><D:write-properties/></D:privilege>`)
			b.WriteString(`<D:privilege><D:write-content/></D:privilege>`)
			b.WriteString(`</D:current-user-privilege-set>`)
		case p.Space == "DAV:" && p.Local == "supported-report-set":
			b.WriteString(`<D:supported-report-set>`)
			b.WriteString(`<D:supported-report><D:report><C:addressbook-query/></D:report></D:supported-report>`)
			b.WriteString(`<D:supported-report><D:report><C:addressbook-multiget/></D:report></D:supported-report>`)
			b.WriteString(`<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>`)
			b.WriteString(`</D:supported-report-set>`)
		case p.Space == "DAV:" && p.Local == "sync-token":
			token := "0"
			if backend != nil {
				if provider, ok := backend.(interface{ CurrentSyncToken() string }); ok {
					if t := strings.TrimSpace(provider.CurrentSyncToken()); t != "" {
						token = t
					}
				}
			}
			b.WriteString(`<D:sync-token>`)
			_ = xml.EscapeText(&b, []byte(token))
			b.WriteString(`</D:sync-token>`)
		case p.Space == "DAV:" && p.Local == "add-member":
			b.WriteString(`<D:add-member><D:href>`)
			_ = xml.EscapeText(&b, []byte(collectionPath))
			b.WriteString(`</D:href></D:add-member>`)
		case p.Space == "DAV:" && p.Local == "quota-available-bytes":
			b.WriteString(`<D:quota-available-bytes>0</D:quota-available-bytes>`)
		case p.Space == "DAV:" && p.Local == "quota-used-bytes":
			b.WriteString(`<D:quota-used-bytes>0</D:quota-used-bytes>`)
		case p.Space == "DAV:" && p.Local == "resource-id":
			b.WriteString(`<D:resource-id>contacts</D:resource-id>`)
		case p.Space == "urn:ietf:params:xml:ns:carddav" && p.Local == "addressbook-home-set":
			b.WriteString(`<C:addressbook-home-set><D:href>`)
			_ = xml.EscapeText(&b, []byte(collectionPath))
			b.WriteString(`</D:href></C:addressbook-home-set>`)
		case p.Space == "urn:ietf:params:xml:ns:carddav" && p.Local == "supported-address-data":
			b.WriteString(`<C:supported-address-data><C:address-data-type content-type="text/vcard" version="`)
			_ = xml.EscapeText(&b, []byte(carddavVCardVersion))
			b.WriteString(`"/></C:supported-address-data>`)
		case p.Space == "urn:ietf:params:xml:ns:carddav" && p.Local == "max-resource-size":
			fmt.Fprintf(&b, "<C:max-resource-size>%d</C:max-resource-size>", carddavMaxResourceSize)
		case p.Space == "urn:ietf:params:xml:ns:carddav" && p.Local == "max-image-size":
			b.WriteString(`<C:max-image-size>0</C:max-image-size>`)
		case p.Space == "urn:mobileme:davservices" && p.Local == "quota-available":
			b.WriteString(`<ME:quota-available>0</ME:quota-available>`)
		case p.Space == "urn:mobileme:davservices" && p.Local == "quota-used":
			b.WriteString(`<ME:quota-used>0</ME:quota-used>`)
		default:
			emitEmpty(p.Space, p.Local)
		}
	}

	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`)
	_, _ = resp.Write(b.Bytes())
}

func writeCarddavReportResponse(resp http.ResponseWriter, req *http.Request, backend webdavcarddav.Backend) int {
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))

	report := parseCarddavReport(body)
	if report.reportType == "" {
		reqType := strings.ToLower(string(body))
		if strings.Contains(reqType, "sync-collection") {
			report.reportType = "sync-collection"
		}
	}
	if !report.wantAddressData && !report.wantETag {
		report.wantETag = true
	}
	if debug {
		log.Printf("carddav/report: path=%s type=%s hrefs=%d wantEtag=%t wantData=%t syncToken=%q body=%q", req.URL.Path, report.reportType, len(report.hrefs), report.wantETag, report.wantAddressData, report.syncToken, string(body))
	}

	if report.reportType == "sync-collection" && (report.syncToken == "0" || report.syncToken == "token-empty") {
		report.syncToken = ""
	}

	if report.reportType == "sync-collection" && report.syncToken != "" {
		type syncTokenValidator interface {
			IsSyncTokenValid(token string) bool
		}
		if mgr, ok := backend.(syncTokenValidator); ok && !mgr.IsSyncTokenValid(report.syncToken) {
			resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
			resp.WriteHeader(http.StatusForbidden)
			_, _ = resp.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
				`<D:error xmlns:D="DAV:"><D:valid-sync-token/></D:error>`))
			return http.StatusForbidden
		}
	}

	resp.Header().Set("Content-Type", "application/xml; charset=utf-8")
	resp.WriteHeader(http.StatusMultiStatus)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)

	logCards := debug && (report.reportType == "addressbook-multiget" || report.reportType == "sync-collection")
	loggedCard := false
	writeObjectResponse := func(obj *webdavcarddav.AddressObject) {
		var cardBuf bytes.Buffer
		card := cloneVCard(obj.Card)
		normalizeVCardVersion(card, carddavVCardVersion)
		if report.wantAddressData {
			if err := vcard.NewEncoder(&cardBuf).Encode(card); err != nil {
				return
			}
			if carddavVCardVersion == "3.0" {
				data := cardBuf.String()
				data = strings.ReplaceAll(data, "VERSION:4.0", "VERSION:3.0")
				cardBuf.Reset()
				cardBuf.WriteString(data)
				if debug && strings.Contains(data, "VERSION:4.0") {
					log.Printf("carddav/report: warning vCard version replace failed for %s", obj.Path)
				}
			}
			if logCards && !loggedCard {
				data := cardBuf.String()
				if len(data) > 300 {
					data = data[:300] + "..."
				}
				log.Printf("carddav/report: address-data path=%s bytes=%d sample=%q", obj.Path, cardBuf.Len(), data)
				loggedCard = true
			}
		}

		b.WriteString(`<D:response><D:href>`)
		_ = xml.EscapeText(&b, []byte(obj.Path))
		b.WriteString(`</D:href><D:propstat><D:prop>`)
		if report.wantETag {
			b.WriteString(`<D:getetag>`)
			_ = xml.EscapeText(&b, []byte(`"`+obj.ETag+`"`))
			b.WriteString(`</D:getetag>`)
		}
		if report.wantAddressData {
			b.WriteString(`<C:address-data content-type="text/vcard" version="`)
			_ = xml.EscapeText(&b, []byte(carddavVCardVersion))
			b.WriteString(`">`)
			_ = xml.EscapeText(&b, cardBuf.Bytes())
			b.WriteString(`</C:address-data>`)
		}
		b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	}

	var syncToken string
	var objects []webdavcarddav.AddressObject
	switch report.reportType {
	case "addressbook-multiget":
		for _, href := range report.hrefs {
			path := href
			if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
				if u, err := url.Parse(path); err == nil {
					path = u.Path
				}
			}
			if !strings.HasPrefix(path, "/") {
				path = "/contacts/" + strings.TrimPrefix(path, "contacts/")
			}
			obj, err := backend.GetAddressObject(req.Context(), path, &webdavcarddav.AddressDataRequest{AllProp: true})
			if err != nil {
				b.WriteString(`<D:response><D:href>`)
				_ = xml.EscapeText(&b, []byte(path))
				b.WriteString(`</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>`)
				continue
			}
			writeObjectResponse(obj)
		}
	default:
		var err error
		objects, err = backend.ListAddressObjects(req.Context(), "/contacts/", &webdavcarddav.AddressDataRequest{AllProp: true})
		if err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			return http.StatusInternalServerError
		}
		if debug {
			log.Printf("carddav/report: returned %d contacts", len(objects))
		}
		if report.reportType == "addressbook-query" {
			// Ensure Apple receives full vCards even if it only requested ETags.
			report.wantAddressData = true
		}
		if report.reportType == "sync-collection" {
			type syncTokenManager interface {
				IsSyncTokenValid(token string) bool
				SnapshotForToken(token string) (map[string]string, bool)
				RememberSyncToken(token string, objects []webdavcarddav.AddressObject)
			}

			allObjects := objects
			validToken := false
			var snapshot map[string]string
			if mgr, ok := backend.(syncTokenManager); ok {
				validToken = mgr.IsSyncTokenValid(report.syncToken)
				if validToken {
					snapshot, _ = mgr.SnapshotForToken(report.syncToken)
				}
			}
			// For initial sync (no token), include address-data so clients that don't
			// follow up with multiget still download full cards.
			if report.syncToken == "" {
				report.wantAddressData = true
			}

			syncToken = ferrocarddav.SyncTokenFromObjects(objects)
			var deletions []string
			if report.syncToken != "" && validToken {
				if report.syncToken == syncToken {
					objects = nil
				} else if snapshot != nil {
					current := make(map[string]string, len(objects))
					changed := make([]webdavcarddav.AddressObject, 0, len(objects))
					for _, obj := range objects {
						current[obj.Path] = obj.ETag
						if prev, ok := snapshot[obj.Path]; !ok || prev != obj.ETag {
							changed = append(changed, obj)
						}
					}
					for path := range snapshot {
						if _, ok := current[path]; !ok {
							deletions = append(deletions, path)
						}
					}
					objects = changed
				}
			}
			if mgr, ok := backend.(syncTokenManager); ok {
				mgr.RememberSyncToken(syncToken, allObjects)
			}
			if debug {
				log.Printf("carddav/report: sync-collection tokenValid=%t forceData=%t", validToken, report.wantAddressData)
			}

			if len(deletions) > 0 {
				for _, path := range deletions {
					b.WriteString(`<D:response><D:href>`)
					_ = xml.EscapeText(&b, []byte(path))
					b.WriteString(`</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>`)
				}
			}
		}
		if debug {
			log.Printf("carddav/report: writing %d responses wantData=%t wantEtag=%t", len(objects), report.wantAddressData, report.wantETag)
		}
		for i := range objects {
			obj := objects[i]
			writeObjectResponse(&obj)
		}
	}

	if report.reportType == "sync-collection" {
		if syncToken == "" {
			syncToken = "token-empty"
		}
		b.WriteString(`<D:sync-token>`)
		_ = xml.EscapeText(&b, []byte(syncToken))
		b.WriteString(`</D:sync-token>`)
	}

	b.WriteString(`</D:multistatus>`)
	_, _ = resp.Write(b.Bytes())
	return http.StatusMultiStatus
}

type carddavReport struct {
	reportType      string
	wantETag        bool
	wantAddressData bool
	hrefs           []string
	syncToken       string
}

func parseCarddavReport(body []byte) carddavReport {
	var r carddavReport
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case start.Name.Space == "DAV:" && start.Name.Local == "sync-collection":
			r.reportType = "sync-collection"
		case start.Name.Space == "urn:ietf:params:xml:ns:carddav" && start.Name.Local == "addressbook-multiget":
			r.reportType = "addressbook-multiget"
		case start.Name.Space == "urn:ietf:params:xml:ns:carddav" && start.Name.Local == "addressbook-query":
			r.reportType = "addressbook-query"
		case start.Name.Space == "DAV:" && start.Name.Local == "getetag":
			r.wantETag = true
		case start.Name.Space == "urn:ietf:params:xml:ns:carddav" && start.Name.Local == "address-data":
			r.wantAddressData = true
		case start.Name.Space == "DAV:" && start.Name.Local == "href":
			var href string
			if err := dec.DecodeElement(&href, &start); err == nil {
				href = strings.TrimSpace(href)
				if href != "" {
					r.hrefs = append(r.hrefs, href)
				}
			}
		case start.Name.Space == "DAV:" && start.Name.Local == "sync-token":
			var token string
			if err := dec.DecodeElement(&token, &start); err == nil {
				r.syncToken = strings.TrimSpace(token)
			}
		}
	}
	return r
}

func cloneVCard(card vcard.Card) vcard.Card {
	out := make(vcard.Card, len(card))
	for k, fields := range card {
		copied := make([]*vcard.Field, len(fields))
		copy(copied, fields)
		out[k] = copied
	}
	return out
}

func normalizeVCardVersion(card vcard.Card, version string) {
	if version == "4.0" {
		vcard.ToV4(card)
		return
	}
	// Fall back to a minimal vCard 3.0 conversion.
	// We keep existing fields but rewrite VERSION explicitly.
	card[vcard.FieldVersion] = []*vcard.Field{{Value: "3.0"}}

	// Ensure FN exists; use EMAIL or UID as a fallback display name.
	if fields, ok := card[vcard.FieldFormattedName]; !ok || len(fields) == 0 {
		name := ""
		if emailFields, ok := card[vcard.FieldEmail]; ok && len(emailFields) > 0 {
			name = emailFields[0].Value
		} else if uidFields, ok := card[vcard.FieldUID]; ok && len(uidFields) > 0 {
			name = uidFields[0].Value
		}
		if name != "" {
			card[vcard.FieldFormattedName] = []*vcard.Field{{Value: name}}
		}
	}

	// Ensure N exists for vCard 3.0.
	if fields, ok := card[vcard.FieldName]; !ok || len(fields) == 0 {
		family := ""
		given := ""
		if fnFields, ok := card[vcard.FieldFormattedName]; ok && len(fnFields) > 0 {
			parts := strings.Fields(fnFields[0].Value)
			if len(parts) > 1 {
				family = parts[len(parts)-1]
				given = strings.Join(parts[:len(parts)-1], " ")
			} else if len(parts) == 1 {
				family = parts[0]
			}
		}
		card[vcard.FieldName] = []*vcard.Field{{Value: fmt.Sprintf("%s;%s;;;", family, given)}}
	}

	// Convert PREF parameters to TYPE=PREF for vCard 3.0 compatibility.
	for _, fields := range card {
		for _, f := range fields {
			if f == nil || f.Params == nil {
				continue
			}
			prefVals, ok := f.Params["PREF"]
			if !ok || len(prefVals) == 0 {
				continue
			}
			pref := false
			for _, v := range prefVals {
				if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
					pref = true
					break
				}
			}
			delete(f.Params, "PREF")
			if pref {
				types := f.Params["TYPE"]
				found := false
				for _, t := range types {
					if strings.EqualFold(t, "PREF") {
						found = true
						break
					}
				}
				if !found {
					types = append(types, "PREF")
				}
				f.Params["TYPE"] = types
			}
			if len(f.Params) == 0 {
				f.Params = nil
			}
		}
	}
}

func parseStringFlag(args []string, name string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == name {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		}
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"="), true
		}
	}
	return "", false
}

func handleCarddavPost(resp http.ResponseWriter, req *http.Request, backend webdavcarddav.Backend) int {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}
	_ = req.Body.Close()

	if len(bytes.TrimSpace(body)) == 0 {
		resp.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}

	card, err := vcard.NewDecoder(bytes.NewReader(body)).Decode()
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		return http.StatusBadRequest
	}

	id := uuid.New().String()
	path := "/contacts/" + id + ".vcf"
	ao, err := backend.PutAddressObject(ferrocarddav.WithCreateContext(req.Context()), path, card, nil)
	if err != nil {
		if debug {
			log.Printf("carddav/post: failed to create contact: %v", err)
		}
		resp.WriteHeader(http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	if debug {
		log.Printf("carddav/post: created contact path=%s etag=%s", ao.Path, ao.ETag)
	}

	resp.Header().Set("Location", ao.Path)
	resp.Header().Set("ETag", `"`+ao.ETag+`"`)
	resp.WriteHeader(http.StatusCreated)
	return http.StatusCreated
}

func handleCarddavDelete(resp http.ResponseWriter, req *http.Request, backend webdavcarddav.Backend) int {
	path := req.URL.Path
	if !strings.HasPrefix(path, "/contacts/") || !strings.HasSuffix(path, ".vcf") {
		resp.WriteHeader(http.StatusNotFound)
		return http.StatusNotFound
	}

	if err := backend.DeleteAddressObject(req.Context(), path); err != nil {
		if debug {
			log.Printf("carddav/delete: failed to delete %s: %v", path, err)
		}
		resp.WriteHeader(http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	resp.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

func listenAndServeCalDAV(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = caldav.NewHandler(c, privateKeys, username, ch)

				handlers[username] = h
			}

			if req.Method == "PROPPATCH" {
				writePropPatchResponse(resp, req)
				return
			}

			if req.Method == "PROPFIND" && req.URL.Path == "/" {
				writeRootPropfindResponse(resp, req)
				return
			}

			if debug {
				rec := &statusRecorder{ResponseWriter: resp}
				h.ServeHTTP(rec, req)
				status := rec.status
				if status == 0 {
					status = http.StatusOK
				}
				log.Printf("caldav/http: %s %s -> %d", req.Method, req.URL.Path, status)
				return
			}

			h.ServeHTTP(resp, req)
		}),
	}

	log.Println("CalDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			if req.URL.Path == "/.well-known/carddav" {
				http.Redirect(resp, req, "/contacts/", http.StatusPermanentRedirect)
				return
			}

			if debug {
				hasAuth := req.Header.Get("Authorization") != ""
				log.Printf("carddav/http: %s %s (auth=%t ua=%q)", req.Method, req.URL.Path, hasAuth, req.UserAgent())
			}

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = ferrocarddav.NewHandler(c, privateKeys, ch, carddavVCardVersion)

				handlers[username] = h
			}

			if req.URL.Path == "/contacts" {
				req.URL.Path = "/contacts/"
			}
			// Map legacy principal paths to the addressbook collection.
			if strings.HasPrefix(req.URL.Path, "/principals/") {
				req.URL.Path = "/contacts/"
			}
			if strings.HasPrefix(req.URL.Path, "/contacts/default/") {
				req.URL.Path = "/contacts/" + strings.TrimPrefix(req.URL.Path, "/contacts/default/")
			} else if req.URL.Path == "/contacts/default" {
				req.URL.Path = "/contacts/"
			}

			if req.Method == "PROPPATCH" {
				writePropPatchResponse(resp, req)
				return
			}

			if req.Method == "PROPFIND" && req.URL.Path == "/" {
				writeRootPropfindResponseCardDAV(resp, req)
				return
			}

			if req.Method == "PROPFIND" && req.URL.Path == "/contacts/" {
				if handler, ok := h.(*webdavcarddav.Handler); ok {
					writeContactsPropfindResponse(resp, req, handler.Backend)
					if debug {
						log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, http.StatusMultiStatus)
					}
					return
				}
				writeContactsPropfindResponse(resp, req, nil)
				if debug {
					log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, http.StatusMultiStatus)
				}
				return
			}

			if req.Method == "REPORT" && (req.URL.Path == "/contacts/" || req.URL.Path == "/contacts/default/") {
				handler, ok := h.(*webdavcarddav.Handler)
				if ok {
					status := writeCarddavReportResponse(resp, req, handler.Backend)
					if debug {
						log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, status)
					}
					return
				}
			}

			if req.Method == "POST" && (req.URL.Path == "/contacts/" || req.URL.Path == "/contacts/default/") {
				handler, ok := h.(*webdavcarddav.Handler)
				if ok {
					status := handleCarddavPost(resp, req, handler.Backend)
					if debug {
						log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, status)
					}
					return
				}
			}

			if req.Method == "DELETE" && strings.HasPrefix(req.URL.Path, "/contacts/") {
				handler, ok := h.(*webdavcarddav.Handler)
				if ok {
					status := handleCarddavDelete(resp, req, handler.Backend)
					if debug {
						log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, status)
					}
					return
				}
			}

			if debug && req.Method == "PROPFIND" {
				body, _ := io.ReadAll(req.Body)
				_ = req.Body.Close()
				req.Body = io.NopCloser(bytes.NewReader(body))
				log.Printf("carddav/propfind: path=%s depth=%s body=%q", req.URL.Path, req.Header.Get("Depth"), string(body))
			}

			if debug {
				rec := &statusRecorder{ResponseWriter: resp}
				h.ServeHTTP(rec, req)
				status := rec.status
				if status == 0 {
					status = http.StatusOK
				}
				log.Printf("carddav/http: %s %s -> %d", req.Method, req.URL.Path, status)
				return
			}

			h.ServeHTTP(resp, req)
		}),
	}

	if s.TLSConfig != nil {
		log.Printf("CardDAV server listening with TLS on %s (vCard %s)", s.Addr, carddavVCardVersion)
		return s.ListenAndServeTLS("", "")
	}

	log.Printf("CardDAV server listening on %s (vCard %s)", s.Addr, carddavVCardVersion)
	return s.ListenAndServe()
}

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

const usage = `usage: ferroxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via ferroxide
	carddav			Run ferroxide as a CardDAV server
	caldav			Run ferroxide as a CalDAV server
	export-secret-keys <username> Export secret keys
	imap			Run ferroxide as an IMAP server
	import-messages <username> [file]	Import messages
	export-messages [options...] <username>	Export messages
	sendmail <username> -- <args...>	sendmail(1) interface
	serve			Run all servers
	smtp			Run ferroxide as an SMTP server
	status			View ferroxide status

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead

`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which ferroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which ferroxide listens, defaults to 1025")
	disableSMTP := flag.Bool("disable-smtp", false, "Disable SMTP for ferroxide serve")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which ferroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which ferroxide listens, defaults to 1143")
	disableIMAP := flag.Bool("disable-imap", false, "Disable IMAP for ferroxide serve")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which ferroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which ferroxide listens, defaults to 8080")
	carddavVCardVersionFlag := flag.String("carddav-vcard-version", "4.0", "CardDAV vCard version to serve (3.0 or 4.0)")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for ferroxide serve")

	caldavHost := flag.String("caldav-host", "127.0.0.1", "Allowed CalDAV email hostname on which ferroxide listens, defaults to 127.0.0.1")
	caldavPort := flag.String("caldav-port", "8081", "CalDAV port on which ferroxide listens, defaults to 8081")
	disableCalDAV := flag.Bool("disable-caldav", false, "Disable CalDAV for ferroxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	configHome := flag.String("config-home", "", "Path to the directory where ferroxide stores its configuration")
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL (e.g. socks5://127.0.0.1:1080)")
	flag.BoolVar(&tor, "tor", false, "If set, connect to ProtonMail over Tor")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	exportMessagesCmd := flag.NewFlagSet("export-messages", flag.ExitOnError)
	sendmailCmd := flag.NewFlagSet("sendmail", flag.ExitOnError)

	flag.Usage = func() {
		fmt.Print(usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	carddavVCardVersion = strings.TrimSpace(*carddavVCardVersionFlag)
	if v, ok := parseStringFlag(os.Args, "--carddav-vcard-version"); ok {
		carddavVCardVersion = strings.TrimSpace(v)
	}
	if carddavVCardVersion != "3.0" && carddavVCardVersion != "4.0" {
		log.Printf("carddav: unsupported vCard version %q, defaulting to 4.0", carddavVCardVersion)
		carddavVCardVersion = "4.0"
	}

	if tor && proxyURL == "" {
		log.Fatal("Need -proxy to connect to ProtonMail over Tor")
	}

	if tor {
		log.Println("Connecting to ProtonMail over Tor")
		apiEndpoint = torAPIEndpoint
	}

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	if *configHome != "" {
		config.SetConfigHome(*configHome)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: ferroxide auth <username>")
		}

		c := newClient()

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if a == nil {
			if pass, err := askPass("Password"); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			a, err = c.Auth(username, loginPassword, authInfo)
			if err != nil {
				log.Fatal(err)
			}

			if a.TwoFactor.Enabled != 0 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA TOTP code: ")
				scanner.Scan()
				code := scanner.Text()

				scope, err := c.AuthTOTP(code)
				if err != nil {
					log.Fatal(err)
				}
				a.Scope = scope
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			prompt := "Password"
			if a.PasswordMode == protonmail.PasswordTwo {
				prompt = "Mailbox password"
			}
			if pass, err := askPass(prompt); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth:            *a,
			LoginPassword:   loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(flag.Args()[1:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: ferroxide export-secret-keys <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		_, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "import-messages":
		importMessagesCmd.Parse(flag.Args()[1:])
		username := importMessagesCmd.Arg(0)
		archivePath := importMessagesCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: ferroxide import-messages <username> [file]")
		}

		f := os.Stdin
		if archivePath != "" {
			f, err = os.Open(archivePath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		br := bufio.NewReader(f)
		if ok, err := isMbox(br); err != nil {
			log.Fatal(err)
		} else if ok {
			mr := mbox.NewReader(br)
			for {
				r, err := mr.NextMessage()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}
				if err := imports.ImportMessage(c, r); err != nil {
					log.Fatal(err)
				}
			}
		} else {
			if err := imports.ImportMessage(c, br); err != nil {
				log.Fatal(err)
			}
		}
	case "export-messages":
		// TODO: allow specifying multiple IDs
		var convID, msgID string
		exportMessagesCmd.StringVar(&convID, "conversation-id", "", "conversation ID")
		exportMessagesCmd.StringVar(&msgID, "message-id", "", "message ID")
		exportMessagesCmd.Parse(flag.Args()[1:])
		username := exportMessagesCmd.Arg(0)
		if (convID == "" && msgID == "") || username == "" {
			log.Fatal("usage: ferroxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		mboxWriter := mbox.NewWriter(os.Stdout)

		if convID != "" {
			if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
				log.Fatal(err)
			}
		}
		if msgID != "" {
			if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
				log.Fatal(err)
			}
		}

		if err := mboxWriter.Close(); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, debug, authManager, tlsConfig))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, debug, authManager, eventsManager, tlsConfig))
	case "caldav":
		addr := *caldavHost + ":" + *caldavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCalDAV(addr, debug, authManager, eventsManager, tlsConfig))
	case "carddav":
		addr := *carddavHost + ":" + *carddavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, debug, authManager, eventsManager, tlsConfig))
	case "serve":
		smtpAddr := *smtpHost + ":" + *smtpPort
		imapAddr := *imapHost + ":" + *imapPort
		carddavAddr := *carddavHost + ":" + *carddavPort
		caldavAddr := *caldavHost + ":" + *caldavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		done := make(chan error, 3)
		if !*disableSMTP {
			go func() {
				done <- listenAndServeSMTP(smtpAddr, debug, authManager, tlsConfig)
			}()
		}
		if !*disableIMAP {
			go func() {
				done <- listenAndServeIMAP(imapAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCardDAV {
			go func() {
				done <- listenAndServeCardDAV(carddavAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCalDAV {
			go func() {
				done <- listenAndServeCalDAV(caldavAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		log.Fatal(<-done)
	case "sendmail":
		username := flag.Arg(1)
		if username == "" || flag.Arg(2) != "--" {
			log.Fatal("usage: ferroxide sendmail <username> -- <args...>")
		}

		// TODO: other sendmail flags
		var dotEOF bool
		sendmailCmd.BoolVar(&dotEOF, "i", false, "don't treat a line with only a . character as the end of input")
		sendmailCmd.Parse(flag.Args()[3:])
		rcpt := sendmailCmd.Args()

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		u, err := c.GetCurrentUser()
		if err != nil {
			log.Fatal(err)
		}

		addrs, err := c.ListAddresses()
		if err != nil {
			log.Fatal(err)
		}

		err = smtpbackend.SendMail(c, u, privateKeys, addrs, rcpt, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
