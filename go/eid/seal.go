package eid

import (
	"crypto/ed25519"
	"encoding/base64"
)

// Key is an Ed25519 key in eID's form (spec section 4). Seed is the 32-byte private seed, which never leaves
// its holder.
type Key struct {
	Seed      []byte
	PublicKey string // unpadded base64url
	KeyID     string // "key_" + hex(SHA-256(SubjectPublicKeyInfo DER))
}

// KeyFromSeed derives a Key from a 32-byte seed.
func KeyFromSeed(seed []byte) (Key, error) {
	if len(seed) != ed25519.SeedSize {
		return Key{}, fail("invalid_field", "a seed is 32 bytes")
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	pk := base64.RawURLEncoding.EncodeToString(pub)
	id, err := KeyID(pk)
	if err != nil {
		return Key{}, err
	}
	return Key{Seed: append([]byte(nil), seed...), PublicKey: pk, KeyID: id}, nil
}

// Seal checks a payload's shape for its type and signs it into an envelope (spec section 5).
func Seal(typ string, payload Object, key Key) (Object, error) {
	if !types[typ] {
		return nil, fail("invalid_field", "unknown type")
	}
	if err := CheckPayload(typ, payload); err != nil {
		return nil, err
	}
	input, err := SigningInput(typ, key.KeyID, payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(key.Seed), input)
	return Object{"eid": "1", "type": typ, "key_id": key.KeyID, "payload": payload, "signature": base64.RawURLEncoding.EncodeToString(sig)}, nil
}
