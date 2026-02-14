package carddav

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/acheong08/ferroxide/config"
	"github.com/acheong08/ferroxide/protonmail"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"
)

// TODO: use a HTTP error
var errNotFound = errors.New("carddav: not found")

var (
	cleartextCardProps = []string{vcard.FieldVersion, vcard.FieldProductID, "X-PM-LABEL", "X-PM-GROUP"}
	signedCardProps    = []string{vcard.FieldVersion, vcard.FieldProductID, vcard.FieldFormattedName, vcard.FieldUID, vcard.FieldEmail, "X-PM-LABEL", "X-PM-GROUP"}
	signedOnlyProps    = []string{vcard.FieldVersion, vcard.FieldFormattedName, vcard.FieldUID, vcard.FieldEmail, "X-PM-LABEL", "X-PM-GROUP"}
)

var addressBook = &carddav.AddressBook{
	Path:            "/contacts/",
	Name:            "ProtonMail",
	Description:     "ProtonMail contacts",
	MaxResourceSize: 100 * 1024,
}

const (
	lastServedTTL           = 1 * time.Hour
	lastServedFlushInterval = 5 * time.Second
)

func cloneCard(card vcard.Card) vcard.Card {
	out := make(vcard.Card, len(card))
	for k, fields := range card {
		copied := make([]*vcard.Field, len(fields))
		copy(copied, fields)
		out[k] = copied
	}
	return out
}

func cloneFields(fields []*vcard.Field) []*vcard.Field {
	if len(fields) == 0 {
		return nil
	}
	out := make([]*vcard.Field, len(fields))
	for i, f := range fields {
		if f == nil {
			continue
		}
		nf := *f
		if f.Params != nil {
			nf.Params = make(vcard.Params, len(f.Params))
			for k, v := range f.Params {
				vals := make([]string, len(v))
				copy(vals, v)
				nf.Params[k] = vals
			}
		}
		out[i] = &nf
	}
	return out
}

func fieldSignature(f *vcard.Field) string {
	if f == nil {
		return ""
	}
	var params []string
	for k, vals := range f.Params {
		key := strings.ToUpper(k)
		if len(vals) == 0 {
			params = append(params, key+"=")
			continue
		}
		valsCopy := make([]string, len(vals))
		copy(valsCopy, vals)
		sort.Strings(valsCopy)
		params = append(params, key+"="+strings.Join(valsCopy, ","))
	}
	sort.Strings(params)
	return strings.Join([]string{f.Group, strings.Join(params, ";"), f.Value}, "|")
}

func addStringHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

func contactETag(contact *protonmail.Contact, card vcard.Card) string {
	if contact != nil && len(contact.Cards) > 0 {
		type cardKey struct {
			t   int
			d   string
			sig string
		}
		keys := make([]cardKey, 0, len(contact.Cards))
		for _, c := range contact.Cards {
			if c == nil {
				continue
			}
			keys = append(keys, cardKey{t: int(c.Type), d: c.Data, sig: c.Signature})
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].t != keys[j].t {
				return keys[i].t < keys[j].t
			}
			if keys[i].d != keys[j].d {
				return keys[i].d < keys[j].d
			}
			return keys[i].sig < keys[j].sig
		})

		h := sha256.New()
		for _, k := range keys {
			addStringHash(h, fmt.Sprintf("%d", k.t))
			addStringHash(h, k.d)
			addStringHash(h, k.sig)
		}
		return fmt.Sprintf("%x", h.Sum(nil))
	}

	if card != nil {
		if data, err := serializeCard(card); err == nil && data != "" {
			h := sha256.New()
			addStringHash(h, data)
			return fmt.Sprintf("%x", h.Sum(nil))
		}
	}

	if contact != nil {
		return fmt.Sprintf("%x%x", contact.ModifyTime, contact.Size)
	}
	return ""
}

func fieldsEqual(a, b []*vcard.Field) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	as := make([]string, 0, len(a))
	for _, f := range a {
		as = append(as, fieldSignature(f))
	}
	bs := make([]string, 0, len(b))
	for _, f := range b {
		bs = append(bs, fieldSignature(f))
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func normalizeCardKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func fieldsByName(card vcard.Card) map[string][]*vcard.Field {
	out := make(map[string][]*vcard.Field, len(card))
	for k, fields := range card {
		key := normalizeCardKey(k)
		if key == "" {
			continue
		}
		out[key] = append(out[key], fields...)
	}
	return out
}

func mergeCards(base, incoming, current vcard.Card) vcard.Card {
	merged := cloneCard(current)
	baseMap := fieldsByName(base)
	inMap := fieldsByName(incoming)
	names := make(map[string]struct{}, len(baseMap)+len(inMap))
	for k := range baseMap {
		names[k] = struct{}{}
	}
	for k := range inMap {
		names[k] = struct{}{}
	}

	for name := range names {
		if fieldsEqual(baseMap[name], inMap[name]) {
			continue
		}
		deleteFieldsByName(merged, name)
		if fields := inMap[name]; len(fields) > 0 {
			merged[strings.ToUpper(name)] = cloneFields(fields)
		}
	}
	return merged
}

func mergeUniqueStrings(dst []string, add []string) []string {
	seen := make(map[string]struct{}, len(dst)+len(add))
	out := make([]string, 0, len(dst)+len(add))
	for _, v := range dst {
		key := strings.ToLower(strings.TrimSpace(v))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	for _, v := range add {
		key := strings.ToLower(strings.TrimSpace(v))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

func extractCategories(card vcard.Card) []string {
	var out []string
	for k, fields := range card {
		if !strings.EqualFold(k, "CATEGORIES") {
			continue
		}
		for _, f := range fields {
			parts := strings.Split(f.Value, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				out = append(out, part)
			}
		}
	}
	return out
}

func mergeCategories(card vcard.Card, categories []string) {
	merged := mergeUniqueStrings(extractCategories(card), categories)
	if len(merged) == 0 {
		return
	}
	for k := range card {
		if strings.EqualFold(k, "CATEGORIES") {
			delete(card, k)
		}
	}
	card["CATEGORIES"] = []*vcard.Field{{Value: strings.Join(merged, ",")}}
}

func extractPMGroups(card vcard.Card) []string {
	var out []string
	for k, fields := range card {
		if !strings.EqualFold(k, "X-PM-GROUP") {
			continue
		}
		for _, f := range fields {
			val := strings.TrimSpace(f.Value)
			if val == "" {
				continue
			}
			out = append(out, val)
		}
	}
	return out
}

func setPMGroups(card vcard.Card, groups []string) {
	for k := range card {
		if strings.EqualFold(k, "X-PM-GROUP") {
			delete(card, k)
		}
	}
	if len(groups) == 0 {
		return
	}
	fields := make([]*vcard.Field, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		fields = append(fields, &vcard.Field{Value: g})
	}
	if len(fields) > 0 {
		card["X-PM-GROUP"] = fields
	}
}

func applyAppleCategoriesToPMGroups(card vcard.Card) {
	cats := extractCategories(card)
	if len(cats) == 0 {
		return
	}
	merged := mergeUniqueStrings(extractPMGroups(card), cats)
	setPMGroups(card, merged)
}

func deleteFieldsByName(card vcard.Card, name string) {
	for k := range card {
		if strings.EqualFold(k, name) {
			delete(card, k)
		}
	}
}

func buildContactImport(card vcard.Card, keyRing openpgp.EntityList, encryptKeys openpgp.EntityList, includeEncrypted bool, encryptedVersion string) (*protonmail.ContactImport, error) {
	if len(keyRing) == 0 {
		return nil, errors.New("carddav: no keys available")
	}
	signingKey := findSigningKey(keyRing)
	if signingKey == nil {
		return nil, errors.New("carddav: no signing key available")
	}
	privateKey := signingKey

	applyAppleCategoriesToPMGroups(card)

	cardSign := cloneCard(card)
	// Proton API expects vCard 4.0 for signed cards.
	normalizeVCardForProton(cardSign, "4.0")
	var cardEncrypt vcard.Card
	if includeEncrypted {
		cardEncrypt = cloneCard(card)
		if encryptedVersion == "" {
			encryptedVersion = "4.0"
		}
		normalizeVCardForProton(cardEncrypt, encryptedVersion)
		// Avoid duplicate values between signed and encrypted cards.
		deleteFieldsByName(cardEncrypt, vcard.FieldEmail)
		deleteFieldsByName(cardEncrypt, "X-PM-GROUP")
		deleteFieldsByName(cardEncrypt, "X-PM-LABEL")
	}

	var toEncrypt vcard.Card
	var toSign vcard.Card
	if includeEncrypted {
		toEncrypt = cloneCard(cardEncrypt)
		toSign = make(vcard.Card)
		for _, k := range signedCardProps {
			if fields, ok := cardSign[k]; ok {
				toSign[k] = fields
			}
		}
	} else {
		toSign = make(vcard.Card)
		for _, k := range signedOnlyProps {
			if fields, ok := cardSign[k]; ok {
				toSign[k] = fields
			}
		}
	}

	var contactImport protonmail.ContactImport
	var b bytes.Buffer

	if len(toSign) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toSign); err != nil {
			return nil, err
		}
		signed, err := protonmail.NewSignedContactCard(bytes.NewReader(b.Bytes()), privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, signed)
		b.Reset()
	}

	if includeEncrypted && len(toEncrypt) > 0 {
		if err := vcard.NewEncoder(&b).Encode(toEncrypt); err != nil {
			return nil, err
		}
		if len(encryptKeys) == 0 {
			return nil, errors.New("carddav: no encryption keys available")
		}
		encrypted, err := protonmail.NewEncryptedContactCard(bytes.NewReader(b.Bytes()), encryptKeys, privateKey)
		if err != nil {
			return nil, err
		}
		contactImport.Cards = append(contactImport.Cards, encrypted)
		b.Reset()
	}

	return &contactImport, nil
}

func normalizeVCardForProton(card vcard.Card, vcardVersion string) {
	// Ensure consistent version first.
	if vcardVersion == "4.0" {
		vcard.ToV4(card)
	} else {
		card[vcard.FieldVersion] = []*vcard.Field{{Value: "3.0"}}
	}

	// Normalize grouped properties (e.g., item1.EMAIL) into plain keys
	for k, fields := range card {
		if strings.Contains(k, ".") {
			parts := strings.SplitN(k, ".", 2)
			if len(parts) == 2 && parts[1] != "" {
				for _, f := range fields {
					f.Group = ""
				}
				base := strings.ToUpper(parts[1])
				card[base] = append(card[base], fields...)
				delete(card, k)
			}
		}
	}

	// Clear groups on all fields; we'll reassign email groups below.
	for _, fields := range card {
		for _, f := range fields {
			f.Group = ""
		}
	}

	takeFields := func(name string) []*vcard.Field {
		var out []*vcard.Field
		for k, fields := range card {
			if strings.EqualFold(k, name) {
				out = append(out, fields...)
				delete(card, k)
			}
		}
		return out
	}

	setPref := func(f *vcard.Field, pref bool) {
		if pref {
			if f.Params == nil {
				f.Params = make(vcard.Params)
			} else {
				for k := range f.Params {
					delete(f.Params, k)
				}
			}
			f.Params["PREF"] = []string{"1"}
			return
		}
		f.Params = nil
	}

	// Emails: unique groups (ITEMn) and PREF=1 for first entry, no TYPE params.
	emails := takeFields(vcard.FieldEmail)
	for i, f := range emails {
		f.Group = fmt.Sprintf("ITEM%d", i+1)
		setPref(f, i == 0)
	}
	if len(emails) > 0 {
		card[vcard.FieldEmail] = emails
	}

	// Telephone: no TYPE params, PREF=1 for first entry.
	tels := takeFields("TEL")
	for i, f := range tels {
		setPref(f, i == 0)
	}
	if len(tels) > 0 {
		card["TEL"] = tels
	}

	// Address: no TYPE params, PREF=1 for first entry.
	adrs := takeFields("ADR")
	for i, f := range adrs {
		setPref(f, i == 0)
	}
	if len(adrs) > 0 {
		card["ADR"] = adrs
	}

	// Formatted name: match Proton export with PREF=1 when present.
	fns := takeFields(vcard.FieldFormattedName)
	for i, f := range fns {
		setPref(f, i == 0)
	}
	if len(fns) > 0 {
		card[vcard.FieldFormattedName] = fns
	}
}

func findSigningKey(keys openpgp.EntityList) *openpgp.Entity {
	for _, key := range keys {
		if key.PrivateKey != nil && key.PrivateKey.CanSign() {
			return key
		}
		for _, sub := range key.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.CanSign() {
				return key
			}
		}
	}
	if len(keys) > 0 {
		return keys[0]
	}
	return nil
}

func canSign(key *openpgp.Entity) bool {
	if key == nil {
		return false
	}
	if key.PrivateKey != nil && key.PrivateKey.CanSign() {
		return true
	}
	for _, sub := range key.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.CanSign() {
			return true
		}
	}
	return false
}

func selectSigningKey(keys openpgp.EntityList, encryptKeys openpgp.EntityList) *openpgp.Entity {
	for _, key := range encryptKeys {
		if canSign(key) {
			return key
		}
	}
	return findSigningKey(keys)
}

func filterEncryptKeys(keys openpgp.EntityList) openpgp.EntityList {
	out := make(openpgp.EntityList, 0, len(keys))
	for _, key := range keys {
		if entityCanEncrypt(key) {
			out = append(out, key)
		}
	}
	return out
}

func entityCanEncrypt(key *openpgp.Entity) bool {
	if key.PrivateKey != nil && key.PrivateKey.PublicKey.PubKeyAlgo.CanEncrypt() {
		return true
	}
	if key.PrimaryKey != nil && key.PrimaryKey.PubKeyAlgo.CanEncrypt() {
		return true
	}
	for _, sub := range key.Subkeys {
		if sub.PublicKey != nil && sub.PublicKey.PubKeyAlgo.CanEncrypt() {
			return true
		}
		if sub.PrivateKey != nil && sub.PrivateKey.PublicKey.PubKeyAlgo.CanEncrypt() {
			return true
		}
	}
	return false
}

func filterKeysByFingerprint(keys openpgp.EntityList, allowed map[string]struct{}) openpgp.EntityList {
	if len(allowed) == 0 {
		return nil
	}
	out := make(openpgp.EntityList, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			continue
		}
		matched := false
		if key.PrimaryKey != nil {
			fp := strings.ToLower(hex.EncodeToString(key.PrimaryKey.Fingerprint[:]))
			if _, ok := allowed[fp]; ok {
				matched = true
			}
		}
		if !matched {
			for _, sub := range key.Subkeys {
				if sub.PublicKey != nil {
					fp := strings.ToLower(hex.EncodeToString(sub.PublicKey.Fingerprint[:]))
					if _, ok := allowed[fp]; ok {
						matched = true
						break
					}
				}
				if sub.PrivateKey != nil {
					fp := strings.ToLower(hex.EncodeToString(sub.PrivateKey.PublicKey.Fingerprint[:]))
					if _, ok := allowed[fp]; ok {
						matched = true
						break
					}
				}
			}
		}
		if matched {
			out = append(out, key)
		}
	}
	return out
}

func sameKeySet(a, b openpgp.EntityList) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, key := range a {
		if key == nil || key.PrimaryKey == nil {
			continue
		}
		seen[strings.ToLower(hex.EncodeToString(key.PrimaryKey.Fingerprint[:]))] = struct{}{}
	}
	for _, key := range b {
		if key == nil || key.PrimaryKey == nil {
			continue
		}
		fp := strings.ToLower(hex.EncodeToString(key.PrimaryKey.Fingerprint[:]))
		if _, ok := seen[fp]; !ok {
			return false
		}
	}
	return true
}

func parseAddressObjectPath(p string) (string, error) {
	dirname, filename := path.Split(p)
	ext := path.Ext(filename)
	if dirname != "/contacts/" || ext != ".vcf" {
		return "", errNotFound
	}
	return strings.TrimSuffix(filename, ext), nil
}

func formatAddressObjectPath(id string) string {
	return "/contacts/" + id + ".vcf"
}

func (b *backend) buildCardFromContact(ctx context.Context, contact *protonmail.Contact) (vcard.Card, error) {
	card := make(vcard.Card)
	for _, c := range contact.Cards {
		keyring := b.verifyKeys
		if len(keyring) == 0 {
			keyring = b.privateKeys
		}
		md, err := c.Read(keyring)
		if err != nil {
			return nil, err
		}

		decoded, err := vcard.NewDecoder(md.UnverifiedBody).Decode()
		if err != nil {
			return nil, err
		}

		// The signature can be checked only if md.UnverifiedBody is consumed until
		// EOF
		io.Copy(io.Discard, md.UnverifiedBody)
		if err := md.SignatureError; err != nil {
			name := strings.TrimSpace(contact.Name)
			if name == "" {
				name = extractDisplayName(decoded)
			}
			if name != "" {
				log.Printf("carddav: warning: signature verification failed for contact %s (name=%q): %v", contact.ID, name, err)
			} else {
				log.Printf("carddav: warning: signature verification failed for contact %s: %v", contact.ID, err)
			}
		}

		for k, fields := range decoded {
			for _, f := range fields {
				card.Add(k, f)
			}
		}
	}

	if uid := extractUID(card); uid != "" {
		b.rememberUID(uid, contact.ID)
	}

	if len(contact.LabelIDs) > 0 {
		if labels, err := b.contactLabels(ctx); err == nil {
			names := make([]string, 0, len(contact.LabelIDs))
			for _, id := range contact.LabelIDs {
				if label, ok := labels[id]; ok && label != nil {
					names = append(names, label.Name)
				}
			}
			mergeCategories(card, names)
		} else {
			mergeCategories(card, extractPMGroups(card))
		}
	} else {
		mergeCategories(card, extractPMGroups(card))
	}

	return card, nil
}

func (b *backend) rememberLastServed(id string, card vcard.Card) {
	if id == "" {
		return
	}
	b.locker.Lock()
	if b.lastServed == nil {
		b.lastServed = make(map[string]vcard.Card)
	}
	if b.lastServedAt == nil {
		b.lastServedAt = make(map[string]time.Time)
	}
	b.lastServed[id] = cloneCard(card)
	b.lastServedAt[id] = time.Now()
	shouldFlush := time.Since(b.lastServedFlushAt) >= lastServedFlushInterval
	if shouldFlush {
		b.lastServedFlushAt = time.Now()
	}
	b.locker.Unlock()
	if shouldFlush {
		b.flushLastServed()
	}
}

func (b *backend) lastServedSnapshot(id string) (vcard.Card, bool) {
	if id == "" {
		return nil, false
	}
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.lastServed == nil || b.lastServedAt == nil {
		return nil, false
	}
	at, ok := b.lastServedAt[id]
	if !ok || time.Since(at) > lastServedTTL {
		return nil, false
	}
	card, ok := b.lastServed[id]
	if !ok {
		return nil, false
	}
	return cloneCard(card), true
}

type lastServedEntry struct {
	Card string `json:"card"`
	At   int64  `json:"at"`
}

type lastServedCache struct {
	Entries map[string]lastServedEntry `json:"entries"`
}

func lastServedCachePath() (string, error) {
	return config.Path("carddav-last-served.json")
}

func serializeCard(card vcard.Card) (string, error) {
	var b bytes.Buffer
	if err := vcard.NewEncoder(&b).Encode(card); err != nil {
		return "", err
	}
	return b.String(), nil
}

func parseCard(data string) (vcard.Card, error) {
	return vcard.NewDecoder(strings.NewReader(data)).Decode()
}

func (b *backend) loadLastServed() {
	path, err := lastServedCachePath()
	if err != nil {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var cache lastServedCache
	if err := json.NewDecoder(f).Decode(&cache); err != nil {
		return
	}

	now := time.Now()
	if cache.Entries == nil {
		return
	}

	b.locker.Lock()
	if b.lastServed == nil {
		b.lastServed = make(map[string]vcard.Card)
	}
	if b.lastServedAt == nil {
		b.lastServedAt = make(map[string]time.Time)
	}
	for id, entry := range cache.Entries {
		if entry.At == 0 {
			continue
		}
		at := time.Unix(entry.At, 0)
		if now.Sub(at) > lastServedTTL {
			continue
		}
		card, err := parseCard(entry.Card)
		if err != nil {
			continue
		}
		b.lastServed[id] = card
		b.lastServedAt[id] = at
	}
	b.locker.Unlock()
}

func (b *backend) flushLastServed() {
	path, err := lastServedCachePath()
	if err != nil {
		return
	}
	cache := lastServedCache{Entries: make(map[string]lastServedEntry)}
	now := time.Now()

	b.locker.Lock()
	for id, card := range b.lastServed {
		at, ok := b.lastServedAt[id]
		if !ok || now.Sub(at) > lastServedTTL {
			continue
		}
		encoded, err := serializeCard(card)
		if err != nil {
			continue
		}
		cache.Entries[id] = lastServedEntry{
			Card: encoded,
			At:   at.Unix(),
		}
	}
	b.locker.Unlock()

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&cache); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return
	}
	_ = os.Rename(tmp, path)
}

func (b *backend) toAddressObject(ctx context.Context, contact *protonmail.Contact, req *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	// TODO: handle req

	card, err := b.buildCardFromContact(ctx, contact)
	if err != nil {
		return nil, err
	}
	b.rememberLastServed(contact.ID, card)

	return &carddav.AddressObject{
		Path:    formatAddressObjectPath(contact.ID),
		ModTime: contact.ModifyTime.Time(),
		ETag:    contactETag(contact, card),
	Card: card,
	}, nil
}

type backend struct {
	c           *protonmail.Client
	cache       map[string]*protonmail.Contact
	locker      sync.Mutex
	total       int
	privateKeys openpgp.EntityList
	verifyKeys  openpgp.EntityList
	encryptKeys     openpgp.EntityList
	encryptKeysUser openpgp.EntityList
	encryptKeysAddr openpgp.EntityList
	vcardVer    string
	labelCache  map[string]*protonmail.Label
	labelCacheAt time.Time
	syncToken   string
	syncTokenAt time.Time
	syncSnapshot   map[string]string
	syncSnapshotAt time.Time
	uidCache    map[string]string
	uidCacheAt  time.Time
	lastServed  map[string]vcard.Card
	lastServedAt map[string]time.Time
	lastServedFlushAt time.Time
}

const labelCacheTTL = 5 * time.Minute
const syncTokenTTL = 24 * time.Hour
const uidCacheTTL = 10 * time.Minute

func (b *backend) contactLabels(ctx context.Context) (map[string]*protonmail.Label, error) {
	b.locker.Lock()
	if b.labelCache != nil && time.Since(b.labelCacheAt) < labelCacheTTL {
		cached := b.labelCache
		b.locker.Unlock()
		return cached, nil
	}
	b.locker.Unlock()

	labels, err := b.c.ListLabels()
	if err != nil {
		return nil, err
	}
	contactLabels := make(map[string]*protonmail.Label)
	for _, label := range labels {
		if label == nil || label.Type != protonmail.LabelContact {
			continue
		}
		contactLabels[label.ID] = label
	}

	b.locker.Lock()
	b.labelCache = contactLabels
	b.labelCacheAt = time.Now()
	b.locker.Unlock()

	return contactLabels, nil
}

// IsSyncTokenValid reports whether the provided token matches the last issued one
// within a reasonable TTL. If the server restarted, tokens will be considered invalid.
func (b *backend) IsSyncTokenValid(token string) bool {
	if token == "" {
		return false
	}
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.syncToken == "" || token != b.syncToken {
		return false
	}
	if time.Since(b.syncTokenAt) > syncTokenTTL {
		return false
	}
	return true
}

// SnapshotForToken returns a snapshot of path->etag for a valid token.
func (b *backend) SnapshotForToken(token string) (map[string]string, bool) {
	if token == "" {
		return nil, false
	}
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.syncToken == "" || token != b.syncToken {
		return nil, false
	}
	if time.Since(b.syncTokenAt) > syncTokenTTL {
		return nil, false
	}
	if b.syncSnapshot == nil {
		return nil, false
	}
	out := make(map[string]string, len(b.syncSnapshot))
	for k, v := range b.syncSnapshot {
		out[k] = v
	}
	return out, true
}

// RememberSyncToken stores the most recent token to validate subsequent syncs.
// It also remembers the full set of objects to allow diffing deletions.
func (b *backend) RememberSyncToken(token string, objects []carddav.AddressObject) {
	if token == "" {
		return
	}
	snapshot := make(map[string]string, len(objects))
	for _, obj := range objects {
		if obj.Path == "" {
			continue
		}
		snapshot[obj.Path] = obj.ETag
	}
	b.locker.Lock()
	b.syncToken = token
	b.syncTokenAt = time.Now()
	b.syncSnapshot = snapshot
	b.syncSnapshotAt = b.syncTokenAt
	b.locker.Unlock()
}

func extractUID(card vcard.Card) string {
	for k, fields := range card {
		if !strings.EqualFold(k, vcard.FieldUID) {
			continue
		}
		for _, f := range fields {
			if f == nil {
				continue
			}
			uid := strings.TrimSpace(f.Value)
			if uid != "" {
				return uid
			}
		}
	}
	return ""
}

func extractDisplayName(card vcard.Card) string {
	for k, fields := range card {
		if !strings.EqualFold(k, vcard.FieldFormattedName) {
			continue
		}
		for _, f := range fields {
			if f == nil {
				continue
			}
			name := strings.TrimSpace(f.Value)
			if name != "" {
				return name
			}
		}
	}
	for k, fields := range card {
		if !strings.EqualFold(k, vcard.FieldName) {
			continue
		}
		for _, f := range fields {
			if f == nil {
				continue
			}
			name := strings.TrimSpace(f.Value)
			if name != "" {
				return name
			}
		}
	}
	for k, fields := range card {
		if !strings.EqualFold(k, vcard.FieldEmail) {
			continue
		}
		for _, f := range fields {
			if f == nil {
				continue
			}
			name := strings.TrimSpace(f.Value)
			if name != "" {
				return name
			}
		}
	}
	return ""
}

func (b *backend) rememberUID(uid, id string) {
	uid = strings.TrimSpace(uid)
	id = strings.TrimSpace(id)
	if uid == "" || id == "" {
		return
	}
	b.locker.Lock()
	if b.uidCache == nil {
		b.uidCache = make(map[string]string)
	}
	b.uidCache[uid] = id
	b.uidCacheAt = time.Now()
	b.locker.Unlock()
}

func (b *backend) getUID(uid string) (string, bool) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", false
	}
	b.locker.Lock()
	defer b.locker.Unlock()
	if b.uidCache == nil || time.Since(b.uidCacheAt) > uidCacheTTL {
		return "", false
	}
	id, ok := b.uidCache[uid]
	return id, ok
}

func (b *backend) rebuildUIDCache(ctx context.Context) error {
	b.locker.Lock()
	if b.uidCache == nil {
		b.uidCache = make(map[string]string)
	}
	b.locker.Unlock()

	page := 0
	for {
		_, exports, err := b.c.ListContactsExport(page, 0)
		if err != nil {
			return err
		}
		if len(exports) == 0 {
			break
		}
		for _, contactExport := range exports {
			card := make(vcard.Card)
			for _, c := range contactExport.Cards {
				keyring := b.verifyKeys
				if len(keyring) == 0 {
					keyring = b.privateKeys
				}
				md, err := c.Read(keyring)
				if err != nil {
					continue
				}
				decoded, err := vcard.NewDecoder(md.UnverifiedBody).Decode()
				if err != nil {
					continue
				}
					io.Copy(io.Discard, md.UnverifiedBody)
					if err := md.SignatureError; err != nil {
						name := extractDisplayName(decoded)
						if name != "" {
							log.Printf("carddav: warning: signature verification failed for export %s (name=%q): %v", contactExport.ID, name, err)
						} else {
							log.Printf("carddav: warning: signature verification failed for export %s: %v", contactExport.ID, err)
						}
					}
				for k, fields := range decoded {
					for _, f := range fields {
						card.Add(k, f)
					}
				}
			}
			if uid := extractUID(card); uid != "" {
				b.rememberUID(uid, contactExport.ID)
			}
		}
		page++
	}

	b.locker.Lock()
	b.uidCacheAt = time.Now()
	b.locker.Unlock()
	return nil
}

func (b *backend) hydrateContactCards(contact *protonmail.Contact) error {
	if contact == nil || strings.TrimSpace(contact.ID) == "" {
		return errors.New("carddav: missing contact id for card hydration")
	}
	if len(contact.Cards) > 0 {
		return nil
	}

	page := 0
	for {
		_, exports, err := b.c.ListContactsExport(page, 0)
		if err != nil {
			return err
		}
		if len(exports) == 0 {
			break
		}
		for _, contactExport := range exports {
			if contactExport == nil || contactExport.ID != contact.ID {
				continue
			}
			contact.Cards = contactExport.Cards
			if len(contact.Cards) == 0 {
				return errors.New("carddav: contact export returned no cards")
			}
			return nil
		}
		page++
	}

	return errNotFound
}

func (b *backend) resolveContactID(ctx context.Context, path string, card vcard.Card) (string, error) {
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return "", err
	}
	uid := extractUID(card)
	if uid == "" {
		return id, nil
	}
	if cachedID, ok := b.getUID(uid); ok {
		return cachedID, nil
	}
	if err := b.rebuildUIDCache(ctx); err == nil {
		if cachedID, ok := b.getUID(uid); ok {
			return cachedID, nil
		}
	}
	return id, nil
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/contacts/", nil
}

func (b *backend) AddressBookHomeSetPath(ctx context.Context) (string, error) {
	return "/contacts/", nil
}

func (b *backend) CreateAddressBook(ctx context.Context, ab *carddav.AddressBook) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new address book"))
}

func (b *backend) DeleteAddressBook(ctx context.Context, path string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot delete address book"))
}

func (b *backend) ListAddressBooks(ctx context.Context) ([]carddav.AddressBook, error) {
	return []carddav.AddressBook{*addressBook}, nil
}

func (b *backend) GetAddressBook(ctx context.Context, path string) (*carddav.AddressBook, error) {
	if path != addressBook.Path {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("address book not found"))
	}
	return addressBook, nil
}

func (b *backend) cacheComplete() bool {
	b.locker.Lock()
	defer b.locker.Unlock()
	return b.total >= 0 && len(b.cache) == b.total
}

func (b *backend) getCache(id string) (*protonmail.Contact, bool) {
	b.locker.Lock()
	contact, ok := b.cache[id]
	b.locker.Unlock()
	return contact, ok
}

func (b *backend) putCache(contact *protonmail.Contact) {
	b.locker.Lock()
	b.cache[contact.ID] = contact
	b.locker.Unlock()
}

func (b *backend) deleteCache(id string) {
	b.locker.Lock()
	delete(b.cache, id)
	b.locker.Unlock()
}

func (b *backend) GetAddressObject(ctx context.Context, path string, req *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return nil, err
	}

	contact, ok := b.getCache(id)
	if !ok {
		if b.cacheComplete() {
			return nil, errNotFound
		}

		contact, err = b.c.GetContact(id)
		if apiErr, ok := err.(*protonmail.APIError); ok && (apiErr.Code == 13051 || apiErr.Code == 2501 || apiErr.Code == 2061) {
			return nil, errNotFound
		} else if err != nil {
			return nil, err
		}
		b.putCache(contact)
	}

	return b.toAddressObject(ctx, contact, req)
}

func (b *backend) ListAddressObjects(ctx context.Context, path string, req *carddav.AddressDataRequest) ([]carddav.AddressObject, error) {
	if b.cacheComplete() {
		b.locker.Lock()
		defer b.locker.Unlock()

		aos := make([]carddav.AddressObject, 0, len(b.cache))
		for _, contact := range b.cache {
			ao, err := b.toAddressObject(ctx, contact, req)
			if err != nil {
				return nil, err
			}
			aos = append(aos, *ao)
		}

		return aos, nil
	}

	// Get a list of all contacts
	// TODO: paging support
	total, contacts, err := b.c.ListContacts(0, 0)
	if err != nil {
		return nil, err
	}
	b.locker.Lock()
	b.total = total
	b.locker.Unlock()

	m := make(map[string]*protonmail.Contact, total)
	for _, contact := range contacts {
		m[contact.ID] = contact
	}

	// Get all contacts cards
	aos := make([]carddav.AddressObject, 0, total)
	page := 0
	for {
		_, contacts, err := b.c.ListContactsExport(page, 0)
		if err != nil {
			return nil, err
		}

		for _, contactExport := range contacts {
			contact, ok := m[contactExport.ID]
			if !ok {
				continue
			}
			contact.Cards = contactExport.Cards
			b.putCache(contact)

			ao, err := b.toAddressObject(ctx, contact, req)
			if err != nil {
				return nil, err
			}
			aos = append(aos, *ao)
		}

		if len(aos) >= total || len(contacts) == 0 {
			break
		}
		page++
	}

	return aos, nil
}

func (b *backend) QueryAddressObjects(ctx context.Context, path string, query *carddav.AddressBookQuery) ([]carddav.AddressObject, error) {
	req := carddav.AddressDataRequest{AllProp: true}
	if query != nil {
		req = query.DataRequest
	}

	// TODO: optimize
	all, err := b.ListAddressObjects(ctx, addressBook.Path, &req)
	if err != nil {
		return nil, err
	}

	return carddav.Filter(query, all)
}

func (b *backend) PutAddressObject(ctx context.Context, path string, card vcard.Card, opts *carddav.PutAddressObjectOptions) (ao *carddav.AddressObject, err error) {
	id, err := b.resolveContactID(ctx, path, card)
	if err != nil {
		return nil, err
	}

	contactImport, err := buildContactImport(card, b.privateKeys, b.encryptKeys, true, b.vcardVer)
	if err != nil {
		log.Printf("carddav: buildContactImport failed for %s: %v", path, err)
		return nil, err
	}

	var contact *protonmail.Contact

	exists := false
	if id != "" {
		if existing, getErr := b.c.GetContact(id); getErr == nil {
			contact = existing
			b.putCache(existing)
			exists = true
		} else if apiErr, ok := getErr.(*protonmail.APIError); ok && (apiErr.Code == 13051 || apiErr.Code == 2501 || apiErr.Code == 2061) {
			exists = false
		} else if getErr != nil {
			log.Printf("carddav: GET contact failed for %s (%s): %v", path, id, getErr)
			return nil, getErr
		}
	}

	if exists {
		if base, ok := b.lastServedSnapshot(contact.ID); ok {
			if contact != nil && len(contact.Cards) == 0 {
				if err := b.hydrateContactCards(contact); err != nil {
					if b.c != nil && b.c.Debug {
						log.Printf("carddav: merge skipped for %s (hydrate cards failed: %v)", contact.ID, err)
					}
				} else {
					b.putCache(contact)
				}
			}
			if contact != nil && len(contact.Cards) > 0 {
				if currentCard, buildErr := b.buildCardFromContact(ctx, contact); buildErr == nil {
					card = mergeCards(base, card, currentCard)
				} else if b.c != nil && b.c.Debug {
					log.Printf("carddav: merge skipped for %s (current card build failed: %v)", contact.ID, buildErr)
				}
			}
		} else if b.c != nil && b.c.Debug {
			log.Printf("carddav: merge skipped for %s (no last-served snapshot)", contact.ID)
		}
		contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeys, true, b.vcardVer)
		if err != nil {
			return nil, err
		}

		contact, err = b.c.UpdateContact(id, contactImport)
		if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
			if len(b.encryptKeysAddr) > 0 && !sameKeySet(b.encryptKeysAddr, b.encryptKeys) {
				log.Printf("carddav: encrypted update rejected (2060), retrying with address-only keys")
				contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeysAddr, true, b.vcardVer)
				if err != nil {
					return nil, err
				}
				contact, err = b.c.UpdateContact(id, contactImport)
			}
		}
		if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
			if len(b.encryptKeysUser) > 0 && !sameKeySet(b.encryptKeysUser, b.encryptKeys) {
				log.Printf("carddav: encrypted update rejected (2060), retrying with user-only keys")
				contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeysUser, true, b.vcardVer)
				if err != nil {
					return nil, err
				}
				contact, err = b.c.UpdateContact(id, contactImport)
			}
		}
		if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
			contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeys, false, b.vcardVer)
			if err != nil {
				return nil, err
			}
			contact, err = b.c.UpdateContact(id, contactImport)
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2001 {
				log.Printf("carddav: signed-only update rejected (2001), retrying without TEL")
				stripped := cloneCard(card)
				delete(stripped, "TEL")
				contactImport, err = buildContactImport(stripped, b.privateKeys, b.encryptKeys, false, b.vcardVer)
				if err != nil {
					return nil, err
				}
				contact, err = b.c.UpdateContact(id, contactImport)
			}
		}
		if err != nil {
			log.Printf("carddav: update contact failed for %s (%s): %v", path, id, err)
			return nil, err
		}
	} else {
		resps, err := b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
		if err != nil {
			log.Printf("carddav: create contact failed for %s: %v", path, err)
			return nil, err
		}
		if len(resps) != 1 {
			return nil, errors.New("ferroxide/carddav: expected exactly one response when creating contact")
		}
		resp := resps[0]
		if err := resp.Err(); err != nil {
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
				if len(b.encryptKeysAddr) > 0 && !sameKeySet(b.encryptKeysAddr, b.encryptKeys) {
					log.Printf("carddav: encrypted create rejected (2060), retrying with address-only keys")
					contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeysAddr, true, b.vcardVer)
					if err != nil {
						return nil, err
					}
					resps, err = b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
					if err != nil {
						return nil, err
					}
					if len(resps) != 1 {
						return nil, errors.New("ferroxide/carddav: expected exactly one response when creating contact")
					}
					resp = resps[0]
					err = resp.Err()
				}
			}
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
				if len(b.encryptKeysUser) > 0 && !sameKeySet(b.encryptKeysUser, b.encryptKeys) {
					log.Printf("carddav: encrypted create rejected (2060), retrying with user-only keys")
					contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeysUser, true, b.vcardVer)
					if err != nil {
						return nil, err
					}
					resps, err = b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
					if err != nil {
						return nil, err
					}
					if len(resps) != 1 {
						return nil, errors.New("ferroxide/carddav: expected exactly one response when creating contact")
					}
					resp = resps[0]
					err = resp.Err()
				}
			}
			if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2060 {
				contactImport, err = buildContactImport(card, b.privateKeys, b.encryptKeys, false, b.vcardVer)
				if err != nil {
					return nil, err
				}
				resps, err = b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
				if err != nil {
					return nil, err
				}
				if len(resps) != 1 {
					return nil, errors.New("ferroxide/carddav: expected exactly one response when creating contact")
				}
				resp = resps[0]
				if err := resp.Err(); err != nil {
					if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2001 {
						log.Printf("carddav: signed-only create rejected (2001), retrying without TEL")
						stripped := cloneCard(card)
						delete(stripped, "TEL")
						contactImport, err = buildContactImport(stripped, b.privateKeys, b.encryptKeys, false, b.vcardVer)
						if err != nil {
							return nil, err
						}
						resps, err = b.c.CreateContacts([]*protonmail.ContactImport{contactImport})
						if err != nil {
							return nil, err
						}
						if len(resps) != 1 {
							return nil, errors.New("ferroxide/carddav: expected exactly one response when creating contact")
						}
						resp = resps[0]
						if err := resp.Err(); err != nil {
							return nil, err
						}
					} else {
						return nil, err
					}
				}
			} else if err != nil {
				log.Printf("carddav: create contact failed for %s: %v", path, err)
				return nil, err
			}
		}
		contact = resp.Response.Contact
		if contact == nil {
			if uid := extractUID(card); uid != "" {
				if cachedID, ok := b.getUID(uid); ok {
					contact, _ = b.c.GetContact(cachedID)
				} else if err := b.rebuildUIDCache(ctx); err == nil {
					if cachedID, ok := b.getUID(uid); ok {
						contact, _ = b.c.GetContact(cachedID)
					}
				}
			}
		}
		if contact == nil {
			log.Printf("carddav: create contact returned nil for %s", path)
			return nil, errors.New("ferroxide/carddav: create contact returned nil")
		}
	}
	contact.Cards = contactImport.Cards // Not returned by the server
	if uid := extractUID(card); uid != "" {
		b.rememberUID(uid, contact.ID)
	}

	// TODO: increment b.total if necessary
	b.putCache(contact)
	b.rememberLastServed(contact.ID, card)

	return &carddav.AddressObject{
		Path:    formatAddressObjectPath(contact.ID),
		ModTime: contact.ModifyTime.Time(),
		ETag:    contactETag(contact, card),
		Card: card,
	}, nil
}

func (b *backend) DeleteAddressObject(ctx context.Context, path string) error {
	id, err := parseAddressObjectPath(path)
	if err != nil {
		return err
	}
	resps, err := b.c.DeleteContacts([]string{id})
	if err != nil {
		return err
	}
	if len(resps) != 1 {
		return errors.New("ferroxide/carddav: expected exactly one response when deleting contact")
	}
	resp := resps[0]
	// TODO: decrement b.total if necessary
	b.deleteCache(id)
	return resp.Err()
}

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	for event := range events {
		b.locker.Lock()
		if event.Refresh&protonmail.EventRefreshContacts != 0 {
			b.cache = make(map[string]*protonmail.Contact)
			b.total = -1
			b.syncToken = ""
			b.syncTokenAt = time.Time{}
			b.syncSnapshot = nil
			b.syncSnapshotAt = time.Time{}
		} else if len(event.Contacts) > 0 {
			// Contact events don't always include full card payloads,
			// so invalidate the cache and force a full refresh on next sync.
			b.cache = make(map[string]*protonmail.Contact)
			b.total = -1
			b.syncToken = ""
			b.syncTokenAt = time.Time{}
			b.syncSnapshot = nil
			b.syncSnapshotAt = time.Time{}
		}
		b.locker.Unlock()
	}
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, events <-chan *protonmail.Event, vcardVersion string) http.Handler {
	if len(privateKeys) == 0 {
		panic("ferroxide/carddav: no private key available")
	}

	encryptKeys := filterEncryptKeys(privateKeys)
	allowed := make(map[string]struct{})
	userAllowed := make(map[string]struct{})
	addrAllowed := make(map[string]struct{})
	if user, err := c.GetCurrentUser(); err == nil {
		if len(user.Keys) > 0 {
			for _, key := range user.Keys {
				log.Printf("carddav: user key fp=%s active=%d flags=%d primary=%d", strings.ToLower(strings.TrimSpace(key.Fingerprint)), key.Active, key.Flags, key.Primary)
			}
		}
		for _, key := range user.Keys {
			if key.Active == 0 {
				continue
			}
			fp := strings.ToLower(strings.TrimSpace(key.Fingerprint))
			if fp != "" {
				allowed[fp] = struct{}{}
				userAllowed[fp] = struct{}{}
			}
		}
	} else {
		log.Printf("carddav: warning: failed to fetch user keys for encryption: %v", err)
	}

	var addrs []*protonmail.Address
	if addrList, err := c.ListAddresses(); err == nil {
		addrs = addrList
		for _, addr := range addrs {
			if len(addr.Keys) > 0 {
				for _, key := range addr.Keys {
					log.Printf("carddav: address key email=%s fp=%s active=%d flags=%d primary=%d", addr.Email, strings.ToLower(strings.TrimSpace(key.Fingerprint)), key.Active, key.Flags, key.Primary)
				}
			}
			for _, key := range addr.Keys {
				if key.Active == 0 {
					continue
				}
				fp := strings.ToLower(strings.TrimSpace(key.Fingerprint))
				if fp != "" {
					allowed[fp] = struct{}{}
					addrAllowed[fp] = struct{}{}
				}
			}
		}
	} else {
		log.Printf("carddav: warning: failed to list addresses for encryption keys: %v", err)
	}

	var encryptKeysUser openpgp.EntityList
	var encryptKeysAddr openpgp.EntityList
	if filtered := filterKeysByFingerprint(encryptKeys, allowed); len(filtered) > 0 {
		encryptKeys = filtered
	}
	if filtered := filterKeysByFingerprint(encryptKeys, userAllowed); len(filtered) > 0 {
		encryptKeysUser = filtered
	}
	if filtered := filterKeysByFingerprint(encryptKeys, addrAllowed); len(filtered) > 0 {
		encryptKeysAddr = filtered
	}

	if len(encryptKeysUser) > 0 {
		encryptKeys = encryptKeysUser
	} else if len(encryptKeysAddr) > 0 {
		encryptKeys = encryptKeysAddr
	}

	if len(encryptKeys) == 0 {
		if len(allowed) == 0 {
			log.Printf("carddav: warning: no active encryption keys from API; falling back to any encryptable keys")
			encryptKeys = filterEncryptKeys(privateKeys)
		} else {
			log.Printf("carddav: warning: no matching encryption keys found in keyring for active API keys")
		}
	}

	if len(encryptKeys) > 0 {
		fps := make([]string, 0, len(encryptKeys))
		for _, key := range encryptKeys {
			if key == nil || key.PrimaryKey == nil {
				continue
			}
			fps = append(fps, strings.ToLower(hex.EncodeToString(key.PrimaryKey.Fingerprint[:])))
		}
		if len(fps) > 0 {
			log.Printf("carddav: using %d encryption keys: %s", len(fps), strings.Join(fps, ", "))
		}
	}

	verifyKeys := make(openpgp.EntityList, 0, len(privateKeys))
	verifyKeys = append(verifyKeys, privateKeys...)
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			email := strings.TrimSpace(addr.Email)
			if email == "" {
				continue
			}
			pub, err := c.GetPublicKeys(email)
			if err != nil {
				continue
			}
			for _, key := range pub.Keys {
				entity, err := key.Entity()
				if err != nil {
					continue
				}
				verifyKeys = append(verifyKeys, entity)
			}
		}
	}

	b := &backend{
		c:               c,
		cache:           make(map[string]*protonmail.Contact),
		total:           -1,
		privateKeys:     privateKeys,
		verifyKeys:      verifyKeys,
		encryptKeys:     encryptKeys,
		encryptKeysUser: encryptKeysUser,
		encryptKeysAddr: encryptKeysAddr,
		vcardVer:        vcardVersion,
	}
	b.loadLastServed()

	if events != nil {
		go b.receiveEvents(events)
	}

	return &carddav.Handler{Backend: b}
}
