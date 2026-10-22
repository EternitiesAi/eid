// Package eid is a small, dependency-free Go verifier for the eID protocol, version 1 (draft).
// It is an unaudited reference implementation, written from spec/eid-protocol-v1.md.
package eid

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Error carries one of the result codes of spec section 8.
type Error struct{ Code, Reason string }

func (e *Error) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}
func fail(code, reason string) error { return &Error{code, reason} }

// CodeOf returns the result code of an error from this package, or "malformed".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "malformed"
}

// Object is a parsed JSON object. Values are nil, bool, float64, string, []any or Object.
type Object map[string]any

// badString marks a string that held a lone surrogate: it has no canonical form.
type badString struct{}

// Parse reads JSON text the way ECMAScript's JSON.parse does (numbers as float64, the last of repeated
// member names wins), except that it keeps lone surrogates detectable instead of replacing them.
func Parse(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, fail("malformed", "not UTF-8")
	}
	p := parser{s: string(text)}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fail("malformed", "trailing text")
	}
	return v, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) ws() {
	for p.i < len(p.s) && strings.IndexByte(" \t\n\r", p.s[p.i]) >= 0 {
		p.i++
	}
}
func (p *parser) bad() error { return fail("malformed", "not JSON at byte "+strconv.Itoa(p.i)) }

func (p *parser) value(depth int) (any, error) {
	if depth > 512 || p.i >= len(p.s) {
		return nil, p.bad()
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		o := Object{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, p.bad()
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, p.bad()
			}
			p.i++
			p.ws()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				ks = "\x00bad"
			}
			o[ks] = v
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			return nil, p.bad()
		}
	case c == '[':
		p.i++
		a := []any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		for {
			p.ws()
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			return nil, p.bad()
		}
	case c == '"':
		return p.str()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	default:
		return p.number()
	}
}

func (p *parser) number() (any, error) {
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return nil, p.bad()
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, p.bad()
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, p.bad()
		}
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, p.bad()
	}
	return f, nil // like JSON.parse, an out-of-range literal becomes ±Inf, which has no canonical form
}

func (p *parser) str() (any, error) {
	p.i++ // opening quote
	var units []uint16
	lone := false
	for {
		if p.i >= len(p.s) {
			return nil, p.bad()
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			// Decode UTF-16 by hand so a lone surrogate is seen rather than replaced.
			for j := 0; j < len(units); j++ {
				u := units[j]
				if utf16.IsSurrogate(rune(u)) {
					if u < 0xdc00 && j+1 < len(units) && units[j+1] >= 0xdc00 && units[j+1] <= 0xdfff {
						j++
						continue
					}
					lone = true
				}
			}
			if lone {
				return badString{}, nil
			}
			return string(utf16.Decode(units)), nil
		case c < 0x20:
			return nil, p.bad()
		case c == '\\':
			if p.i+1 >= len(p.s) {
				return nil, p.bad()
			}
			e := p.s[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				units = append(units, uint16(e))
			case 'b':
				units = append(units, 8)
			case 'f':
				units = append(units, 12)
			case 'n':
				units = append(units, 10)
			case 'r':
				units = append(units, 13)
			case 't':
				units = append(units, 9)
			case 'u':
				if p.i+4 > len(p.s) {
					return nil, p.bad()
				}
				n, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 16)
				if err != nil {
					return nil, p.bad()
				}
				p.i += 4
				units = append(units, uint16(n))
			default:
				return nil, p.bad()
			}
		default:
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			p.i += size
			units = utf16.AppendRune(units, r)
		}
	}
}

const maxSafe = 1<<53 - 1

// Canonical writes a parsed value in eID canonical form (spec section 3).
func Canonical(v any) (string, error) {
	var b strings.Builder
	if err := canon(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func canon(b *strings.Builder, v any, depth int) error {
	if depth > 16 {
		return fail("non_canonical", "nested too deeply")
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case float64:
		if x != math.Trunc(x) || math.IsInf(x, 0) || x > maxSafe || x < -maxSafe || (x == 0 && math.Signbit(x)) {
			return fail("non_canonical", "numbers are safe integers")
		}
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int:
		return canon(b, float64(x), depth)
	case int64:
		return canon(b, float64(x), depth)
	case string:
		writeString(b, x)
	case badString:
		return fail("non_canonical", "strings are well-formed Unicode")
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Object:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !memberName(k) {
				return fail("non_canonical", "member name "+strconv.Quote(k))
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := canon(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fail("non_canonical", "unsupported value")
	}
	return nil
}

func memberName(k string) bool {
	if len(k) < 1 || len(k) > 64 || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

const hexDigits = "0123456789abcdef"

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == 8:
			b.WriteString(`\b`)
		case c == 9:
			b.WriteString(`\t`)
		case c == 10:
			b.WriteString(`\n`)
		case c == 12:
			b.WriteString(`\f`)
		case c == 13:
			b.WriteString(`\r`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// IsCanonicalText reports whether text is exactly the canonical form of what it parses to.
func IsCanonicalText(text []byte) error {
	v, err := Parse(text)
	if err != nil {
		return err
	}
	c, err := Canonical(v)
	if err != nil {
		return err
	}
	if c != string(text) {
		return fail("non_canonical", "not in canonical form")
	}
	return nil
}
