// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// An independent SigV4 verifier (written from the AWS specification, not
// the SDK), checked first against an AWS published test vector. The gateway
// signer output must verify with it.

type sigv4Wire struct {
	method, escapedPath, rawQuery, host string
	header                              http.Header
	body                                []byte
}

func sigv4Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sigv4HMAC(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// awsURIEncode is the SigV4 UriEncode: every byte but A-Z a-z 0-9 - . _ ~
// is percent-encoded (upper-case hex); slashes stay when keepSlash.
func awsURIEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x41 && c <= 0x5a, c >= 0x61 && c <= 0x7a, c >= 0x30 && c <= 0x39, c == 0x2d, c == 0x2e, c == 0x5f, c == 0x7e:
			b.WriteByte(c)
		case c == 0x2f && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// verifySigV4 recomputes the signature the way AWS does for a non-S3
// service: the canonical URI is the URI-encoded wire path (so an escaped
// %2F or %3A is encoded once more).
func verifySigV4(w sigv4Wire, secret string) (scope []string, err error) {
	const algo = "AWS4-HMAC-SHA256 "
	auth := w.header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return nil, errors.New("no SigV4 Authorization header")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, algo), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		fields[k] = v
	}
	_, credScope, ok := strings.Cut(fields["Credential"], "/")
	scope = strings.Split(credScope, "/")
	if !ok || len(scope) != 4 || scope[3] != "aws4_request" {
		return nil, fmt.Errorf("bad credential scope %q", credScope)
	}
	amzDate := w.header.Get("X-Amz-Date")
	if !strings.HasPrefix(amzDate, scope[0]) {
		return nil, errors.New("x-amz-date does not match the scope date")
	}
	payloadHash := sigv4Hex(w.body)
	if got := w.header.Get("X-Amz-Content-Sha256"); got != "" && got != payloadHash {
		return nil, errors.New("x-amz-content-sha256 is not the hash of the body")
	}
	var ch strings.Builder
	for _, h := range strings.Split(fields["SignedHeaders"], ";") {
		v := w.header.Get(h)
		if h == "host" {
			v = w.host
		}
		ch.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	q, _ := url.ParseQuery(w.rawQuery)
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsURIEncode(k, false)+"="+awsURIEncode(v, false))
		}
	}
	sort.Strings(pairs)
	canonical := strings.Join([]string{w.method, awsURIEncode(w.escapedPath, true), strings.Join(pairs, "&"), ch.String(), fields["SignedHeaders"], payloadHash}, "\n")
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, sigv4Hex([]byte(canonical))}, "\n")
	key := sigv4HMAC([]byte("AWS4"+secret), scope[0])
	for _, part := range scope[1:] {
		key = sigv4HMAC(key, part)
	}
	want := hex.EncodeToString(sigv4HMAC(key, sts))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return scope, errors.New("signature does not verify")
	}
	return scope, nil
}

func TestSigV4VerifierMatchesTheAWSTestVector(t *testing.T) {
	// aws-sig-v4-test-suite get-vanilla.
	h := http.Header{}
	h.Set("X-Amz-Date", "20150830T123600Z")
	h.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
	w := sigv4Wire{method: "GET", escapedPath: "/", host: "example.amazonaws.com", header: h}
	if _, err := verifySigV4(w, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"); err != nil {
		t.Fatalf("published vector: %v", err)
	}
	w.method = "POST"
	if _, err := verifySigV4(w, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"); err == nil {
		t.Fatal("a changed method still verified")
	}
}
