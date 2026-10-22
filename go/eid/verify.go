package eid

import (
	"crypto/sha256"
	"encoding/hex"
)

// Trust is what a relying party pins out of band (spec section 7.1).
type Trust struct {
	Issuer  string
	Anchors []string
}

// Issuer is an opened, current issuer document plus the revocations that count.
type Issuer struct {
	doc         Object
	keys        map[string]Object
	revocations []Object
	revokedKeys map[string]bool
}

func timeOf(o Object, k string) int64 { t, _ := Time(o, k); return t }

// OpenIssuer performs spec sections 7.1 and 7.2.
func OpenIssuer(v any, trust Trust, revocations []any, now int64) (*Issuer, error) {
	e, ok := v.(Object)
	if !ok {
		return nil, fail("untrusted_issuer", "not an envelope")
	}
	kid := str(e, "key_id")
	anchored := false
	for _, a := range trust.Anchors {
		if a == kid {
			anchored = true
		}
	}
	if !anchored {
		return nil, fail("untrusted_issuer", "not signed by a pinned anchor")
	}
	var listed Object
	if p, ok := e["payload"].(Object); ok {
		if keys, ok := p["keys"].([]any); ok {
			for _, k := range keys {
				if ko, ok := k.(Object); ok && str(ko, "key_id") == kid {
					listed = ko
				}
			}
		}
	}
	if listed == nil {
		return nil, fail("untrusted_issuer", "the anchor is not listed in the document")
	}
	env, err := Open(e, str(listed, "public_key"), "issuer")
	if err != nil {
		return nil, err
	}
	doc := env.Payload
	if str(doc, "issuer") != trust.Issuer {
		return nil, fail("untrusted_issuer", "a different issuer")
	}
	if now < timeOf(doc, "issued_at") {
		return nil, fail("not_yet_valid", "issuer document")
	}
	if now >= timeOf(doc, "expires_at") {
		return nil, fail("expired", "issuer document")
	}
	is := &Issuer{doc: doc, keys: map[string]Object{}, revokedKeys: map[string]bool{}}
	for _, k := range doc["keys"].([]any) {
		is.keys[str(k.(Object), "key_id")] = k.(Object)
	}
	// Revocations are checked against key windows only; one that does not open is ignored.
	var good []Object
	for _, r := range revocations {
		env, err := is.OpenSigned(r, "revocation")
		if err == nil && str(env.Payload, "issuer") == trust.Issuer && timeOf(env.Payload, "issued_at") <= now {
			good = append(good, env.Payload)
		}
	}
	is.revocations = good
	for _, r := range good {
		if str(r, "target_kind") == "key" {
			is.revokedKeys[str(r, "target_id")] = true
		}
	}
	return is, nil
}

func (is *Issuer) keyAt(kid string, t int64) bool {
	k, ok := is.keys[kid]
	return ok && t >= timeOf(k, "not_before") && t < timeOf(k, "not_after") && !is.revokedKeys[kid]
}

// OpenSigned opens a document signed by an issuer key valid at its own issued_at (spec section 7.3).
func (is *Issuer) OpenSigned(v any, typ string) (Envelope, error) {
	e, ok := v.(Object)
	if !ok {
		return Envelope{}, fail("malformed", "not an envelope")
	}
	k, ok := is.keys[str(e, "key_id")]
	if !ok {
		return Envelope{}, fail("unknown_key", "not an issuer key")
	}
	env, err := Open(e, str(k, "public_key"), typ)
	if err != nil {
		return Envelope{}, err
	}
	if !is.keyAt(env.KeyID, timeOf(env.Payload, "issued_at")) {
		return Envelope{}, fail("unknown_key", "the issuer key was not valid when this was signed")
	}
	return env, nil
}

// Revoked reports whether a signed, current revocation targets kind/id.
func (is *Issuer) Revoked(kind, id string) bool {
	for _, r := range is.revocations {
		if str(r, "target_kind") == kind && str(r, "target_id") == id {
			return true
		}
	}
	return false
}

// ActInput is everything a relying party needs to verify an act, offline.
type ActInput struct {
	Act, Admission, Grant, IssuerDoc any
	Body                             []byte // nil: the body digest is not checked
	Trust                            Trust
	Revocations                      []any
	Audience                         string
	Now                              int64
	// Accepted reports whether this relying party already accepted an act with this subject and act id. Optional.
	Accepted func(subject, actID string) bool
}

// VerifyAct performs spec section 7.4. It returns "valid" and the act's payload, or a result code.
func VerifyAct(in ActInput) (string, Object, error) {
	is, err := OpenIssuer(in.IssuerDoc, in.Trust, in.Revocations, in.Now)
	if err != nil {
		return CodeOf(err), nil, err
	}
	adm, err := is.OpenSigned(in.Admission, "admission")
	if err != nil {
		return CodeOf(err), nil, err
	}
	a := adm.Payload
	if str(a, "issuer") != in.Trust.Issuer {
		return "mismatch", nil, nil
	}
	ae, ok := in.Act.(Object)
	if !ok {
		return "malformed", nil, nil
	}
	var holderKey Object
	for _, k := range a["holder_keys"].([]any) {
		if str(k.(Object), "key_id") == str(ae, "key_id") {
			holderKey = k.(Object)
		}
	}
	if holderKey == nil {
		return "unknown_key", nil, nil
	}
	act, err := Open(ae, str(holderKey, "public_key"), "act")
	if err != nil {
		return CodeOf(err), nil, err
	}
	gr, err := is.OpenSigned(in.Grant, "grant")
	if err != nil {
		return CodeOf(err), nil, err
	}
	p, g := act.Payload, gr.Payload
	if str(p, "subject") != str(a, "subject") || str(p, "admission_id") != str(a, "admission_id") {
		return "mismatch", nil, nil
	}
	if str(g, "subject") != str(a, "subject") || str(g, "admission_id") != str(a, "admission_id") || str(g, "issuer") != in.Trust.Issuer {
		return "mismatch", nil, nil
	}
	if str(p, "audience") != in.Audience {
		return "wrong_audience", nil, nil
	}
	if is.Revoked("admission", str(a, "admission_id")) || is.Revoked("key", act.KeyID) || is.Revoked("grant", str(g, "grant_id")) {
		return "ended", nil, nil
	}
	now := in.Now
	if now < timeOf(a, "issued_at") {
		return "not_yet_valid", nil, nil
	}
	if now >= timeOf(a, "expires_at") {
		return "dormant", nil, nil
	}
	if str(g, "audience") != in.Audience || !contains(scopesOf(g), str(p, "scope")) {
		return "not_granted", nil, nil
	}
	if now < timeOf(g, "issued_at") {
		return "not_yet_valid", nil, nil
	}
	if now >= timeOf(g, "expires_at") {
		return "dormant", nil, nil
	}
	if now < timeOf(p, "issued_at") {
		return "not_yet_valid", nil, nil
	}
	if now >= timeOf(p, "expires_at") {
		return "expired", nil, nil
	}
	if in.Body != nil {
		h := sha256.Sum256(in.Body)
		if hex.EncodeToString(h[:]) != str(p, "body_sha256") {
			return "body_mismatch", nil, nil
		}
	}
	if in.Accepted != nil && in.Accepted(str(p, "subject"), str(p, "act_id")) {
		return "replayed", nil, nil
	}
	return "valid", p, nil
}

// PermitInput is what a destination needs to verify a permit.
type PermitInput struct {
	Permit, IssuerDoc any
	Payload           []byte
	Trust             Trust
	Revocations       []any
	Audience          string
	Now               int64
	Consumed          func(permitID string) bool
}

// VerifyPermit performs spec section 7.5.
func VerifyPermit(in PermitInput) (string, Object, error) {
	is, err := OpenIssuer(in.IssuerDoc, in.Trust, in.Revocations, in.Now)
	if err != nil {
		return CodeOf(err), nil, err
	}
	env, err := is.OpenSigned(in.Permit, "permit")
	if err != nil {
		return CodeOf(err), nil, err
	}
	p := env.Payload
	switch {
	case str(p, "issuer") != in.Trust.Issuer:
		return "mismatch", nil, nil
	case str(p, "audience") != in.Audience:
		return "wrong_audience", nil, nil
	case is.Revoked("admission", str(p, "admission_id")):
		return "ended", nil, nil
	case in.Consumed != nil && in.Consumed(str(p, "permit_id")):
		return "replayed", nil, nil
	case in.Now < timeOf(p, "issued_at"):
		return "not_yet_valid", nil, nil
	case in.Now >= timeOf(p, "expires_at"):
		return "expired", nil, nil
	}
	h := sha256.Sum256(in.Payload)
	if hex.EncodeToString(h[:]) != str(p, "payload_sha256") {
		return "body_mismatch", nil, nil
	}
	return "valid", p, nil
}
