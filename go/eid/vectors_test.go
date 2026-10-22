package eid

import (
	"encoding/hex"
	"os"
	"testing"
)

// The Go verifier runs every vector in vectors/eid-v1.json and must reach the expected result.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/eid-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := v.(Object)
	cases := func(group string) []Object {
		var out []Object
		for _, c := range root[group].([]any) {
			out = append(out, c.(Object))
		}
		return out
	}
	trust := func(in Object) Trust {
		tr := in["trust"].(Object)
		var a []string
		for _, x := range tr["anchors"].([]any) {
			a = append(a, x.(string))
		}
		return Trust{Issuer: str(tr, "issuer"), Anchors: a}
	}
	arr := func(in Object, k string) []any { a, _ := in[k].([]any); return a }

	for _, c := range cases("canonical") {
		got := "canonical"
		if err := IsCanonicalText([]byte(str(c, "text"))); err != nil {
			got = CodeOf(err)
		}
		if got != str(c, "expect") {
			t.Errorf("canonical/%s: got %s, want %s", str(c, "name"), got, str(c, "expect"))
		}
	}
	for _, c := range cases("signing_input") {
		b, err := SigningInput(str(c, "type"), str(c, "key_id"), c["payload"])
		if err != nil || hex.EncodeToString(b) != str(c, "hex") {
			t.Errorf("signing_input/%s differs", str(c, "name"))
		}
	}
	for _, c := range cases("acts") {
		in := c["input"].(Object)
		ai := ActInput{Act: in["act"], Admission: in["admission"], Grant: in["grant"], IssuerDoc: in["issuer"], Trust: trust(in),
			Revocations: arr(in, "revocations"), Audience: str(in, "audience"), Now: timeOf(in, "now")}
		if b, ok := in["body"].(string); ok {
			ai.Body = []byte(b)
		}
		seen := map[string]bool{}
		for _, x := range arr(in, "accepted") {
			seen[str(x.(Object), "subject")+"\n"+str(x.(Object), "act_id")] = true
		}
		ai.Accepted = func(subject, actID string) bool { return seen[subject+"\n"+actID] }
		if got, _, _ := VerifyAct(ai); got != str(c, "expect") {
			t.Errorf("acts/%s: got %s, want %s", str(c, "name"), got, str(c, "expect"))
		}
	}
	for _, c := range cases("permits") {
		in := c["input"].(Object)
		consumed := map[string]bool{}
		for _, id := range arr(in, "consumed") {
			consumed[id.(string)] = true
		}
		got, _, _ := VerifyPermit(PermitInput{Permit: in["permit"], IssuerDoc: in["issuer"], Payload: []byte(str(in, "payload")), Trust: trust(in),
			Revocations: arr(in, "revocations"), Audience: str(in, "audience"), Now: timeOf(in, "now"), Consumed: func(id string) bool { return consumed[id] }})
		if got != str(c, "expect") {
			t.Errorf("permits/%s: got %s, want %s", str(c, "name"), got, str(c, "expect"))
		}
	}
	for _, c := range cases("id_tokens") {
		in := c["input"].(Object)
		var jwks []JWK
		for _, k := range in["jwks"].(Object)["keys"].([]any) {
			ko := k.(Object)
			jwks = append(jwks, JWK{Kty: str(ko, "kty"), Crv: str(ko, "crv"), X: str(ko, "x"), Kid: str(ko, "kid")})
		}
		got := "valid"
		if _, err := VerifyIDToken(str(in, "token"), IDTokenCheck{JWKS: jwks, Issuer: str(in, "issuer"), Audience: str(in, "audience"), Nonce: str(in, "nonce"), Now: timeOf(in, "now")}); err != nil {
			got = CodeOf(err)
		}
		if got != str(c, "expect") {
			t.Errorf("id_tokens/%s: got %s, want %s", str(c, "name"), got, str(c, "expect"))
		}
	}
}

// Parse must see a lone surrogate rather than replace it, and must refuse what JSON refuses.
func TestParseStrictness(t *testing.T) {
	for _, s := range []string{`{"a":`, `{"a":1,}`, `[1 2]`, `01`, `"\x"`, "\"a\x01\"", `nul`} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
	v, err := Parse([]byte(`"\ud800"`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Canonical(v); CodeOf(err) != "non_canonical" {
		t.Errorf("a lone surrogate must have no canonical form")
	}
}
