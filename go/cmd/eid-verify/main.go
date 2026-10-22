// Command eid-verify checks eID documents offline, with no network access and no eID server.
//
//	eid-verify act --issuer issuer.json --anchor key_... --issuer-id eid.example \
//	    --admission admission.json --grant grant.json --act act.json --audience site.example \
//	    [--body body.bin] [--revocations revocations.json] [--now unix-ms]
//	eid-verify conformance vectors/eid-v1.json
//
// act prints one line: the result code (spec section 8), and exits 0 only for "valid".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/EternitiesAi/eid/go/eid"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "act":
		os.Exit(act(os.Args[2:]))
	case "conformance":
		if len(os.Args) != 3 {
			usage()
		}
		os.Exit(conformance(os.Args[2]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: eid-verify act --issuer F --anchor KEY_ID --issuer-id ID --admission F --grant F --act F --audience ID [--body F] [--revocations F] [--now MS]")
	fmt.Fprintln(os.Stderr, "       eid-verify conformance VECTORS")
	os.Exit(2)
}

func load(path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	v, err := eid.Parse(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		os.Exit(2)
	}
	return v
}

func act(args []string) int {
	fs := flag.NewFlagSet("act", flag.ExitOnError)
	issuer := fs.String("issuer", "", "issuer document")
	anchor := fs.String("anchor", "", "pinned issuer key id")
	issuerID := fs.String("issuer-id", "", "expected issuer identifier")
	admission := fs.String("admission", "", "admission document")
	grant := fs.String("grant", "", "grant document")
	actPath := fs.String("act", "", "act document")
	audience := fs.String("audience", "", "this relying party's audience")
	body := fs.String("body", "", "body file (optional)")
	revs := fs.String("revocations", "", "JSON array of revocations (optional)")
	now := fs.Int64("now", 0, "time in unix milliseconds (default: the clock)")
	fs.Parse(args)
	if *issuer == "" || *anchor == "" || *issuerID == "" || *admission == "" || *grant == "" || *actPath == "" || *audience == "" {
		usage()
	}
	in := eid.ActInput{Act: load(*actPath), Admission: load(*admission), Grant: load(*grant), IssuerDoc: load(*issuer),
		Trust: eid.Trust{Issuer: *issuerID, Anchors: []string{*anchor}}, Audience: *audience, Now: *now}
	if in.Now == 0 {
		in.Now = time.Now().UnixMilli()
	}
	if *body != "" {
		b, err := os.ReadFile(*body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		in.Body = b
	}
	if *revs != "" {
		a, ok := load(*revs).([]any)
		if !ok {
			fmt.Fprintln(os.Stderr, "revocations is a JSON array")
			return 2
		}
		in.Revocations = a
	}
	result, _, err := eid.VerifyAct(in)
	if err != nil {
		fmt.Printf("%s (%v)\n", result, err)
	} else {
		fmt.Println(result)
	}
	if result == "valid" {
		return 0
	}
	return 1
}

// acceptedSet turns a vector's accepted acts, [{subject, act_id}], into a lookup.
func acceptedSet(list []any) func(subject, actID string) bool {
	seen := map[[2]string]bool{}
	for _, a := range list {
		if o, ok := a.(eid.Object); ok {
			s, _ := o["subject"].(string)
			id, _ := o["act_id"].(string)
			seen[[2]string{s, id}] = true
		}
	}
	return func(subject, actID string) bool { return seen[[2]string{subject, actID}] }
}

// conformance prints this implementation's verdict on every vector (conformance/README.md).
func conformance(path string) int {
	root, ok := load(path).(eid.Object)
	if !ok {
		return 2
	}
	out := map[string]map[string]string{"canonical": {}, "signing_input": {}, "acts": {}, "permits": {}, "id_tokens": {}}
	each := func(group string, f func(c eid.Object) string) {
		for _, c := range root[group].([]any) {
			o := c.(eid.Object)
			out[group][o["name"].(string)] = f(o)
		}
	}
	str := func(o eid.Object, k string) string { s, _ := o[k].(string); return s }
	num := func(o eid.Object, k string) int64 { f, _ := o[k].(float64); return int64(f) }
	trust := func(in eid.Object) eid.Trust {
		t := in["trust"].(eid.Object)
		var anchors []string
		for _, a := range t["anchors"].([]any) {
			anchors = append(anchors, a.(string))
		}
		return eid.Trust{Issuer: str(t, "issuer"), Anchors: anchors}
	}
	list := func(in eid.Object, k string) []any { a, _ := in[k].([]any); return a }
	each("canonical", func(c eid.Object) string {
		if err := eid.IsCanonicalText([]byte(str(c, "text"))); err != nil {
			return eid.CodeOf(err)
		}
		return "canonical"
	})
	each("signing_input", func(c eid.Object) string {
		b, err := eid.SigningInput(str(c, "type"), str(c, "key_id"), c["payload"])
		if err != nil {
			return eid.CodeOf(err)
		}
		return fmt.Sprintf("%x", b)
	})
	each("acts", func(c eid.Object) string {
		in := c["input"].(eid.Object)
		ai := eid.ActInput{Act: in["act"], Admission: in["admission"], Grant: in["grant"], IssuerDoc: in["issuer"], Trust: trust(in),
			Revocations: list(in, "revocations"), Audience: str(in, "audience"), Now: num(in, "now")}
		if b, ok := in["body"].(string); ok {
			ai.Body = []byte(b)
		}
		ai.Accepted = acceptedSet(list(in, "accepted"))
		r, _, _ := eid.VerifyAct(ai)
		return r
	})
	each("permits", func(c eid.Object) string {
		in := c["input"].(eid.Object)
		consumed := map[string]bool{}
		for _, id := range list(in, "consumed") {
			consumed[id.(string)] = true
		}
		r, _, _ := eid.VerifyPermit(eid.PermitInput{Permit: in["permit"], IssuerDoc: in["issuer"], Payload: []byte(str(in, "payload")), Trust: trust(in),
			Revocations: list(in, "revocations"), Audience: str(in, "audience"), Now: num(in, "now"), Consumed: func(id string) bool { return consumed[id] }})
		return r
	})
	each("id_tokens", func(c eid.Object) string {
		in := c["input"].(eid.Object)
		var jwks []eid.JWK
		for _, k := range in["jwks"].(eid.Object)["keys"].([]any) {
			ko := k.(eid.Object)
			jwks = append(jwks, eid.JWK{Kty: str(ko, "kty"), Crv: str(ko, "crv"), X: str(ko, "x"), Kid: str(ko, "kid")})
		}
		if _, err := eid.VerifyIDToken(str(in, "token"), eid.IDTokenCheck{JWKS: jwks, Issuer: str(in, "issuer"), Audience: str(in, "audience"), Nonce: str(in, "nonce"), Now: num(in, "now")}); err != nil {
			return eid.CodeOf(err)
		}
		return "valid"
	})
	b, _ := json.Marshal(out)
	os.Stdout.Write(append(b, '\n'))
	return 0
}
