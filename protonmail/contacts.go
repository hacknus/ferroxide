package protonmail

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type Contact struct {
	ID         string
	Name       string
	UID        string
	Size       int
	CreateTime Timestamp
	ModifyTime Timestamp
	LabelIDs   []string

	// Not when using ListContacts
	ContactEmails []*ContactEmail
	Cards         []*ContactCard
}

type ContactEmailDefaults int

type ContactEmail struct {
	ID        string
	Email     string
	Type      []string
	Defaults  ContactEmailDefaults
	Order     int
	ContactID string
	LabelIDs  []string

	// Only when using ListContactsEmails
	Name string
}

type ContactCardType int

const (
	ContactCardCleartext ContactCardType = iota
	ContactCardEncrypted
	ContactCardSigned
	ContactCardEncryptedAndSigned
)

func (t ContactCardType) Signed() bool {
	switch t {
	case ContactCardSigned, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

func (t ContactCardType) Encrypted() bool {
	switch t {
	case ContactCardEncrypted, ContactCardEncryptedAndSigned:
		return true
	default:
		return false
	}
}

type ContactCard struct {
	Type      ContactCardType
	Data      string
	Signature string
}

func NewEncryptedContactCard(r io.Reader, to []*openpgp.Entity, signer *openpgp.Entity) (*ContactCard, error) {
	// TODO: sign and encrypt at the same time
	config := &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
		DefaultHash:            crypto.SHA256,
	}

	var msg, armored bytes.Buffer
	if signer != nil {
		// We'll sign the message later, keep a copy of it
		r = io.TeeReader(r, &msg)
	}

	ciphertext, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	cleartext, err := openpgp.Encrypt(ciphertext, to, nil, nil, config)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(cleartext, r); err != nil {
		return nil, err
	}
	if err := cleartext.Close(); err != nil {
		return nil, err
	}

	if err := ciphertext.Close(); err != nil {
		return nil, err
	}

	card := &ContactCard{
		Type: ContactCardEncrypted,
		Data: armored.String(),
	}

	if signer != nil {
		var sig bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&sig, signer, &msg, nil); err != nil {
			return nil, err
		}

		card.Type = ContactCardEncryptedAndSigned
		card.Signature = sig.String()
	}

	return card, nil
}

func NewSignedContactCard(r io.Reader, signer *openpgp.Entity) (*ContactCard, error) {
	var msg, sig bytes.Buffer
	r = io.TeeReader(r, &msg)
	if err := openpgp.ArmoredDetachSignText(&sig, signer, r, nil); err != nil {
		return nil, err
	}

	return &ContactCard{
		Type:      ContactCardSigned,
		Data:      msg.String(),
		Signature: sig.String(),
	}, nil
}

type detachedSignatureReader struct {
	md        *openpgp.MessageDetails
	body      io.Reader
	signed    bytes.Buffer
	signature string
	keyring   openpgp.KeyRing
	eof       bool
}

func (r *detachedSignatureReader) Read(p []byte) (n int, err error) {
	// TODO: check signature and decrypt at the same time

	n, err = r.body.Read(p)
	if err == io.EOF && !r.eof {
		// Check signature
		signer, signatureError := checkContactSignature(r.keyring, r.signed.Bytes(), r.signature)
		r.md.IsSigned = true
		r.md.SignatureError = signatureError
		if signer != nil {
			r.md.SignedByKeyId = signer.PrimaryKey.KeyId
			r.md.SignedBy = entityPrimaryKey(signer)
		}
		r.eof = true
	}
	return
}

func (card *ContactCard) Read(keyring openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	if !card.Type.Encrypted() {
		md := &openpgp.MessageDetails{
			IsEncrypted:    false,
			IsSigned:       false,
			UnverifiedBody: strings.NewReader(card.Data),
		}

		if !card.Type.Signed() {
			return md, nil
		}

		signer, err := checkContactSignature(keyring, []byte(card.Data), card.Signature)
		md.IsSigned = true
		md.SignatureError = err
		if signer != nil {
			md.SignedByKeyId = signer.PrimaryKey.KeyId
			md.SignedBy = entityPrimaryKey(signer)
		}
		return md, nil
	}

	ciphertextBlock, err := armor.Decode(strings.NewReader(card.Data))
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(ciphertextBlock.Body, keyring, nil, nil)
	if err != nil {
		return nil, err
	}

	if card.Type.Signed() {
		r := &detachedSignatureReader{
			md:        md,
			signature: card.Signature,
			keyring:   keyring,
		}
		r.body = io.TeeReader(md.UnverifiedBody, &r.signed)

		md.UnverifiedBody = r
	}

	return md, nil
}

func checkContactSignature(keyring openpgp.KeyRing, data []byte, signature string) (*openpgp.Entity, error) {
	if signature == "" {
		return nil, errors.New("missing signature")
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), strings.NewReader(signature), nil)
	if err == nil {
		return signer, nil
	}

	lf := normalizeToLF(data)
	crlf := normalizeToCRLF(lf)
	candidates := make([][]byte, 0, 4)
	if !bytes.Equal(lf, data) {
		candidates = append(candidates, lf)
	}
	if !bytes.Equal(crlf, data) && !bytes.Equal(crlf, lf) {
		candidates = append(candidates, crlf)
	}
	lfNL := ensureTrailingNewline(lf, []byte{'\n'})
	if !bytes.Equal(lfNL, lf) {
		candidates = append(candidates, lfNL)
	}
	crlfNL := ensureTrailingNewline(crlf, []byte{'\r', '\n'})
	if !bytes.Equal(crlfNL, crlf) {
		candidates = append(candidates, crlfNL)
	}

	for _, candidate := range candidates {
		signer, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(candidate), strings.NewReader(signature), nil)
		if err == nil {
			return signer, nil
		}
	}

	return signer, err
}

func normalizeToLF(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == '\r' {
			if i+1 < len(data) && data[i+1] == '\n' {
				i++
			}
			out = append(out, '\n')
			continue
		}
		out = append(out, b)
	}
	return out
}

func normalizeToCRLF(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		if b == '\n' {
			out = append(out, '\r', '\n')
			continue
		}
		out = append(out, b)
	}
	return out
}

func ensureTrailingNewline(data []byte, newline []byte) []byte {
	if len(data) == 0 || len(newline) == 0 {
		return data
	}
	if bytes.HasSuffix(data, newline) {
		return data
	}
	out := make([]byte, 0, len(data)+len(newline))
	out = append(out, data...)
	out = append(out, newline...)
	return out
}

type ContactExport struct {
	ID    string
	Cards []*ContactCard
}

type ContactImport struct {
	Cards []*ContactCard
}

func (c *Client) ListContacts(page, pageSize int) (total int, contacts []*Contact, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Contacts []*Contact
		Total    int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Contacts, nil
}

func (c *Client) ListContactsEmails(page, pageSize int) (total int, emails []*ContactEmail, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/emails?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		ContactEmails []*ContactEmail
		Total         int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.ContactEmails, nil
}

func (c *Client) ListContactsExport(page, pageSize int) (total int, contacts []*ContactExport, err error) {
	v := url.Values{}
	v.Set("Page", strconv.Itoa(page))
	if pageSize > 0 {
		v.Set("PageSize", strconv.Itoa(pageSize))
	}

	req, err := c.newRequest(http.MethodGet, "/contacts/export?"+v.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}

	var respData struct {
		resp
		Contacts []*ContactExport
		Total    int
	}
	if err := c.doJSON(req, &respData); err != nil {
		return 0, nil, err
	}

	return respData.Total, respData.Contacts, nil
}

func (c *Client) GetContact(id string) (*Contact, error) {
	req, err := c.newRequest(http.MethodGet, "/contacts/"+id, nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contact *Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contact, nil
}

type CreateContactResp struct {
	Index    int
	Response struct {
		resp
		Contact *Contact
	}
}

func (resp *CreateContactResp) Err() error {
	return resp.Response.Err()
}

func (c *Client) CreateContacts(contacts []*ContactImport) ([]*CreateContactResp, error) {
	reqData := struct {
		Contacts                  []*ContactImport
		Overwrite, Groups, Labels int
	}{contacts, 0, 1, 1}
	req, err := c.newJSONRequest(http.MethodPost, "/contacts", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []*CreateContactResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Responses, nil
}

func (c *Client) UpdateContact(id string, contact *ContactImport) (*Contact, error) {
	req, err := c.newJSONRequest(http.MethodPut, "/contacts/"+id, contact)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Contact *Contact
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Contact, nil
}

type DeleteContactResp struct {
	ID       string
	Response struct {
		resp
	}
}

func (resp *DeleteContactResp) Err() error {
	return resp.Response.Err()
}

func (c *Client) DeleteContacts(ids []string) ([]*DeleteContactResp, error) {
	reqData := struct {
		IDs []string
	}{ids}
	req, err := c.newJSONRequest(http.MethodPut, "/contacts/delete", &reqData)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		Responses []*DeleteContactResp
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.Responses, nil
}

func (c *Client) DeleteAllContacts() error {
	req, err := c.newRequest(http.MethodDelete, "/contacts", nil)
	if err != nil {
		return err
	}

	var respData resp
	if err := c.doJSON(req, &respData); err != nil {
		return err
	}

	return nil
}
