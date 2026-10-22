package eid

import (
	"strings"
)

// JWK is one Ed25519 key of an issuer's JWKS.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
}

// IDTokenCheck is what a relying party knows before it reads a sign-in's id token.
type IDTokenCheck struct {
	JWKS     []JWK
	Issuer   string
	Audience string
	Nonce    string
	Now      int64 // milliseconds
}

const maxTokenSeconds, skewSeconds = 600, 60

func decodePart(s string) (Object, error) {
	b, err := DecodeB64URL(s, -1)
	if err != nil {
		return nil, err
	}
	v, err := Parse(b)
	if err != nil {
		return nil, err
	}
	o, ok := v.(Object)
	if !ok {
		return nil, fail("malformed", "token part is not an object")
	}
	return o, nil
}

func validSub(s string) bool {
	if len(s) < 16 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// VerifyIDToken checks a sign-in-with-eID id token (spec/sign-in-with-eid-v1.md section 4).
func VerifyIDToken(token string, c IDTokenCheck) (Object, error) {
	if len(token) > 4096 {
		return nil, fail("malformed", "not a token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail("malformed", "a JWS compact token has three parts")
	}
	h, err := decodePart(parts[0])
	if err != nil {
		return nil, err
	}
	kid, _ := h["kid"].(string)
	if h["alg"] != "EdDSA" || kid == "" {
		return nil, fail("invalid_field", "alg is EdDSA and kid is set")
	}
	for k := range h {
		if k != "alg" && k != "kid" && k != "typ" {
			return nil, fail("invalid_field", "unexpected header")
		}
	}
	if t, ok := h["typ"]; ok && t != "JWT" {
		return nil, fail("invalid_field", "unexpected header")
	}
	var key *JWK
	for i := range c.JWKS {
		if c.JWKS[i].Kid == kid && c.JWKS[i].Kty == "OKP" && c.JWKS[i].Crv == "Ed25519" {
			key = &c.JWKS[i]
		}
	}
	if key == nil {
		return nil, fail("unknown_key", "kid is not in the issuer JWKS")
	}
	if !verifySig(key.X, []byte(parts[0]+"."+parts[1]), parts[2]) {
		return nil, fail("bad_signature", "")
	}
	cl, err := decodePart(parts[1])
	if err != nil {
		return nil, err
	}
	switch {
	case cl["iss"] != c.Issuer:
		return nil, fail("untrusted_issuer", "iss")
	case cl["aud"] != c.Audience:
		return nil, fail("wrong_audience", "aud")
	case cl["nonce"] != c.Nonce:
		return nil, fail("mismatch", "nonce")
	case cl["eid_ai"] != true:
		return nil, fail("invalid_field", "eid_ai is true")
	}
	if sub, _ := cl["sub"].(string); !validSub(sub) {
		return nil, fail("invalid_field", "sub")
	}
	iat, ok1 := intClaim(cl, "iat")
	exp, ok2 := intClaim(cl, "exp")
	if !ok1 || !ok2 {
		return nil, fail("invalid_field", "iat and exp are integers")
	}
	nowS := c.Now / 1000
	if exp <= iat || exp-iat > maxTokenSeconds {
		return nil, fail("invalid_field", "token lifetime")
	}
	if iat > nowS+skewSeconds {
		return nil, fail("not_yet_valid", "iat")
	}
	if nowS >= exp {
		return nil, fail("expired", "exp")
	}
	return cl, nil
}

func intClaim(o Object, k string) (int64, bool) {
	f, ok := o[k].(float64)
	if !ok || f != float64(int64(f)) || f > maxSafe || f < -maxSafe {
		return 0, false
	}
	return int64(f), true
}
