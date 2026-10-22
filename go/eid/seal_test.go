package eid

import (
	"os"
	"testing"
)

// Ed25519 is deterministic, so sealing a vector's payload with its published seed in Go must reproduce the
// TypeScript reference's signature exactly: two implementations, one byte string.
func TestSealReproducesTheVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/eid-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := Parse(raw)
	root := v.(Object)
	keys := map[string]Key{}
	for _, s := range root["test_seeds"].(Object) {
		so := s.(Object)
		seed, err := DecodeB64URL(str(so, "seed"), 32)
		if err != nil {
			t.Fatal(err)
		}
		k, err := KeyFromSeed(seed)
		if err != nil || k.PublicKey != str(so, "public_key") || k.KeyID != str(so, "key_id") {
			t.Fatalf("seed does not give its published key")
		}
		keys[k.KeyID] = k
	}
	checked := 0
	for _, c := range root["acts"].([]any) {
		in := c.(Object)["input"].(Object)
		for _, name := range []string{"act", "admission", "grant", "issuer"} {
			e, ok := in[name].(Object)
			if !ok || e["eid"] != "1" {
				continue
			}
			k, ok := keys[str(e, "key_id")]
			p, isObj := e["payload"].(Object)
			if !ok || !isObj || CheckPayload(str(e, "type"), p) != nil {
				continue // invalid on purpose; Seal refuses those
			}
			sealed, err := Seal(str(e, "type"), p, k)
			if err != nil {
				t.Fatalf("%s/%s: %v", str(c.(Object), "name"), name, err)
			}
			if sealed["signature"] != e["signature"] {
				if str(c.(Object), "name") == "act-tampered" || str(c.(Object), "name") == "signature-malleated" {
					continue // their signatures are wrong on purpose
				}
				t.Errorf("%s/%s: Go's signature differs from the reference's", str(c.(Object), "name"), name)
			}
			checked++
		}
	}
	if checked < 100 {
		t.Fatalf("only %d envelopes compared", checked)
	}
}

func TestSealRefusesWhatOpenWouldRefuse(t *testing.T) {
	k, _ := KeyFromSeed(make([]byte, 32))
	if _, err := Seal("act", Object{"act_id": "a"}, k); CodeOf(err) != "invalid_field" {
		t.Errorf("an incomplete act must not be sealed")
	}
	p := Object{"act_id": "a", "admission_id": "adm", "subject": "s", "audience": "x", "scope": "post.create", "body_sha256": "0000000000000000000000000000000000000000000000000000000000000000", "issued_at": float64(1), "expires_at": float64(1000)}
	e, err := Seal("act", p, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e, k.PublicKey, "act"); err != nil {
		t.Errorf("a sealed act must open: %v", err)
	}
}
