package eid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
)

// Keys (spec section 4).

var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// DecodeB64URL decodes unpadded base64url and refuses any other spelling of the same bytes.
func DecodeB64URL(s string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || (n >= 0 && len(b) != n) || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fail("invalid_field", "not canonical base64url")
	}
	return b, nil
}

// KeyID is "key_" + hex(SHA-256(SubjectPublicKeyInfo DER)) of a base64url Ed25519 public key.
func KeyID(publicKey string) (string, error) {
	raw, err := DecodeB64URL(publicKey, 32)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append(append([]byte{}, spkiPrefix...), raw...))
	return "key_" + hex.EncodeToString(h[:]), nil
}

func verifySig(publicKey string, msg []byte, sig string) bool {
	raw, err := DecodeB64URL(publicKey, 32)
	if err != nil {
		return false
	}
	s, err := DecodeB64URL(sig, 64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), msg, s) // crypto/ed25519 refuses S >= L
}

// Envelopes (spec section 5).

var types = map[string]bool{"issuer": true, "admission": true, "grant": true, "permit": true, "act": true, "revocation": true}

const maxPayload = 8192

// SigningInput is "eid/1" LF type LF key_id LF canonical(payload).
func SigningInput(typ, keyID string, payload any) ([]byte, error) {
	c, err := Canonical(payload)
	if err != nil {
		return nil, err
	}
	if len(c) > maxPayload {
		return nil, fail("too_large", "payload over 8192 bytes")
	}
	return []byte("eid/1\n" + typ + "\n" + keyID + "\n" + c), nil
}

// Envelope is an opened document: its type, signing key id and payload.
type Envelope struct {
	Type, KeyID string
	Payload     Object
}

// Open checks an envelope's form and signature under publicKey, in the order of spec section 5.2.
// expect may be "" to accept any type.
func Open(v any, publicKey, expect string) (Envelope, error) {
	e, ok := v.(Object)
	if !ok {
		return Envelope{}, fail("malformed", "an envelope is a JSON object")
	}
	if !exactly(e, "eid", "type", "key_id", "payload", "signature") {
		return Envelope{}, fail("invalid_field", "an envelope has exactly eid, type, key_id, payload, signature")
	}
	if e["eid"] != "1" {
		return Envelope{}, fail("unsupported_version", `eid is "1"`)
	}
	typ, _ := e["type"].(string)
	if !types[typ] {
		return Envelope{}, fail("invalid_field", "unknown type")
	}
	if expect != "" && typ != expect {
		return Envelope{}, fail("wrong_type", "expected "+expect)
	}
	kid, _ := e["key_id"].(string)
	want, err := KeyID(publicKey)
	if err != nil || !keyIDForm.MatchString(kid) || kid != want {
		return Envelope{}, fail("unknown_key", "key_id is not this key")
	}
	input, err := SigningInput(typ, kid, e["payload"])
	if err != nil {
		return Envelope{}, err
	}
	sig, _ := e["signature"].(string)
	if !verifySig(publicKey, input, sig) {
		return Envelope{}, fail("bad_signature", "")
	}
	p, ok := e["payload"].(Object)
	if !ok {
		return Envelope{}, fail("invalid_field", "payload is an object")
	}
	if err := CheckPayload(typ, p); err != nil {
		return Envelope{}, err
	}
	return Envelope{typ, kid, p}, nil
}

// Document shapes (spec section 6).

var (
	idForm    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopeForm = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,95}$`)
	keyIDForm = regexp.MustCompile(`^key_[0-9a-f]{64}$`)
	shaForm   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	second = int64(1000)
	day    = 86400 * second
)

var maxWindow = map[string]int64{"issuer": 400 * day, "admission": 30 * day, "grant": 7 * day, "permit": 20 * second, "act": 120 * second}
var reasons = map[string]bool{"holder_request": true, "sponsor_request": true, "key_compromise": true, "policy": true, "superseded": true}

func exactly(o Object, names ...string) bool {
	if len(o) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := o[n]; !ok {
			return false
		}
	}
	return true
}

func str(o Object, k string) string { s, _ := o[k].(string); return s }

// Time returns a member that must be an integer time of at least 1.
func Time(o Object, k string) (int64, bool) {
	f, ok := o[k].(float64)
	if !ok || f < 1 || f > maxSafe || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

func bad(what string) error { return fail("invalid_field", what) }

func isID(v any) bool    { s, ok := v.(string); return ok && idForm.MatchString(s) }
func isScope(v any) bool { s, ok := v.(string); return ok && scopeForm.MatchString(s) }
func isSHA(v any) bool   { s, ok := v.(string); return ok && shaForm.MatchString(s) }

func checkWindow(o Object, typ string) error {
	a, ok1 := Time(o, "issued_at")
	b, ok2 := Time(o, "expires_at")
	if !ok1 || !ok2 || b-a <= 0 || b-a > maxWindow[typ] {
		return bad("the " + typ + " window")
	}
	return nil
}

func checkKeyRef(v any, extra ...string) error {
	k, ok := v.(Object)
	if !ok || !exactly(k, append([]string{"key_id", "public_key"}, extra...)...) {
		return bad("a key entry")
	}
	id, err := KeyID(str(k, "public_key"))
	if err != nil {
		return err
	}
	if str(k, "key_id") != id {
		return bad("key_id matches its public_key")
	}
	return nil
}

func list(v any, min, max int) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok && len(a) >= min && len(a) <= max
}

func distinctKeys(a []any) bool {
	seen := map[string]bool{}
	for _, k := range a {
		id := str(k.(Object), "key_id")
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// CheckPayload checks a payload has exactly the shape its type requires.
func CheckPayload(typ string, o Object) error {
	switch typ {
	case "issuer":
		if !exactly(o, "issuer", "keys", "issued_at", "expires_at") || !isID(o["issuer"]) {
			return bad("issuer")
		}
		if err := checkWindow(o, typ); err != nil {
			return err
		}
		keys, ok := list(o["keys"], 1, 8)
		if !ok {
			return bad("keys")
		}
		for _, k := range keys {
			if err := checkKeyRef(k, "not_before", "not_after"); err != nil {
				return err
			}
			nb, ok1 := Time(k.(Object), "not_before")
			na, ok2 := Time(k.(Object), "not_after")
			if !ok1 || !ok2 || na <= nb {
				return bad("key validity")
			}
		}
		if !distinctKeys(keys) {
			return bad("keys are distinct")
		}
	case "admission":
		if !exactly(o, "admission_id", "issuer", "subject", "holder_keys", "disclosed_ai", "issued_at", "expires_at") ||
			!isID(o["admission_id"]) || !isID(o["issuer"]) || !isID(o["subject"]) {
			return bad("admission")
		}
		if err := checkWindow(o, typ); err != nil {
			return err
		}
		if o["disclosed_ai"] != true {
			return bad("disclosed_ai is true")
		}
		keys, ok := list(o["holder_keys"], 1, 4)
		if !ok {
			return bad("holder_keys")
		}
		for _, k := range keys {
			if err := checkKeyRef(k); err != nil {
				return err
			}
		}
		if !distinctKeys(keys) {
			return bad("holder_keys are distinct")
		}
	case "grant":
		if !exactly(o, "grant_id", "issuer", "admission_id", "subject", "audience", "scopes", "issued_at", "expires_at") ||
			!isID(o["grant_id"]) || !isID(o["issuer"]) || !isID(o["admission_id"]) || !isID(o["subject"]) || !isID(o["audience"]) {
			return bad("grant")
		}
		if err := checkWindow(o, typ); err != nil {
			return err
		}
		scopes, ok := list(o["scopes"], 1, 32)
		if !ok {
			return bad("scopes")
		}
		for i, s := range scopes {
			if !isScope(s) || (i > 0 && !(scopes[i-1].(string) < s.(string))) {
				return bad("scopes are sorted, distinct scope atoms")
			}
		}
	case "permit":
		if !exactly(o, "permit_id", "issuer", "admission_id", "subject", "audience", "scope", "operation_id", "payload_sha256", "issued_at", "expires_at") ||
			!isID(o["permit_id"]) || !isID(o["issuer"]) || !isID(o["admission_id"]) || !isID(o["subject"]) || !isID(o["audience"]) ||
			!isScope(o["scope"]) || !isID(o["operation_id"]) || !isSHA(o["payload_sha256"]) {
			return bad("permit")
		}
		return checkWindow(o, typ)
	case "act":
		if !exactly(o, "act_id", "admission_id", "subject", "audience", "scope", "body_sha256", "issued_at", "expires_at") ||
			!isID(o["act_id"]) || !isID(o["admission_id"]) || !isID(o["subject"]) || !isID(o["audience"]) || !isScope(o["scope"]) || !isSHA(o["body_sha256"]) {
			return bad("act")
		}
		return checkWindow(o, typ)
	case "revocation":
		if !exactly(o, "revocation_id", "issuer", "target_kind", "target_id", "reason", "issued_at") || !isID(o["revocation_id"]) || !isID(o["issuer"]) {
			return bad("revocation")
		}
		if _, ok := Time(o, "issued_at"); !ok {
			return bad("issued_at")
		}
		switch str(o, "target_kind") {
		case "key":
			if !keyIDForm.MatchString(str(o, "target_id")) {
				return bad("a key target is a key id")
			}
		case "admission", "grant":
			if !isID(o["target_id"]) {
				return bad("target_id")
			}
		default:
			return bad("target_kind")
		}
		if !reasons[str(o, "reason")] {
			return bad("reason")
		}
	default:
		return bad("unknown type")
	}
	return nil
}

func scopesOf(o Object) []string {
	a, _ := o["scopes"].([]any)
	out := make([]string, 0, len(a))
	for _, s := range a {
		out = append(out, s.(string))
	}
	return out
}

func contains(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}
