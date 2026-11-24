// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// flipSpareBit sets the lowest bit of the last char of a base64url part
// whose length leaves spare bits: the decoded bytes do not change.
func flipSpareBit(t *testing.T, part string) string {
	t.Helper()
	if len(part)%4 == 0 {
		t.Fatalf("part of length %d has no spare bits", len(part))
	}
	last := strings.IndexByte(b64urlAlphabet, part[len(part)-1])
	return part[:len(part)-1] + string(b64urlAlphabet[last^1])
}

// GAP-0759 (RV2-01): a token with no jti was keyed by the hash of its
// text, so a copy re-encoded (spare signature bits, an ES256 (r, n-s)
// signature) verified with another key and an ended token worked again.
// Every accepted encoding of one signed token now has one key.
func TestGAP0759TokenKeyIsTheSameForEveryAcceptedEncoding(t *testing.T) {
	p := newIDP(t)
	rsaKey := p.addKey(t, "r1", "RS256")
	ecKey := p.addKey(t, "e1", "ES256")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	ks, err := NewKeySet(KeySetOptions{Issuer: p.srv.URL, HTTPClient: p.srv.Client(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewPersonVerifier([]PersonIssuer{{KeySet: ks, Audience: "dc-launcher"}}, clock)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher", "exp": now.Unix() + 600, "iat": now.Unix() - 30}
	check := func(name, orig, variant string) {
		t.Helper()
		a, err := v.Verify(context.Background(), orig)
		if err != nil {
			t.Fatalf("%s: original: %v", name, err)
		}
		if !strings.HasPrefix(a.TokenKey, "clm:") {
			t.Errorf("%s: a JWT with no jti is keyed %q, want its claims hash", name, a.TokenKey)
		}
		b, err := v.Verify(context.Background(), variant)
		if err != nil {
			return // refused: the ended token stays ended
		}
		if a.TokenKey != b.TokenKey {
			t.Errorf("%s: same signed token, two keys: ending %q leaves %q working", name, a.TokenKey, b.TokenKey)
		}
	}

	rs := sign(t, rsaKey, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "r1"}, claims)
	parts := strings.Split(rs, ".")
	check("RS256 spare bits", rs, parts[0]+"."+parts[1]+"."+flipSpareBit(t, parts[2]))
	check("RS256 claims spare bits", rs, parts[0]+"."+flipSpareBit(t, parts[1])+"."+parts[2])
	check("RS256 line break", rs, parts[0]+"."+parts[1][:4]+"\n"+parts[1][4:]+"."+parts[2])

	es := sign(t, ecKey, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "e1"}, claims)
	parts = strings.Split(es, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	n := elliptic.P256().Params().N
	s := new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:]))
	hi := append([]byte{}, sig[:32]...)
	hi = append(hi, s.FillBytes(make([]byte, 32))...)
	pub := ecKey.Public().(*ecdsa.PublicKey)
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(hi[:32]), s) {
		t.Fatal("(r, n-s) does not verify: the probe is wrong")
	}
	check("ES256 (r, n-s)", es, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(hi))
	check("ES256 spare bits", es, parts[0]+"."+parts[1]+"."+flipSpareBit(t, parts[2]))

	// The keys a token with a jti, and an opaque token, have are the ones
	// 3865df1007 wrote: no stored key of those kinds changes.
	jti := sha256.Sum256([]byte("iss\x00j-1"))
	if got := TokenKey("iss", "j-1", rs); got != "jti:"+hex.EncodeToString(jti[:16]) {
		t.Errorf("jti key changed: %q", got)
	}
	raw := sha256.Sum256([]byte("kube-static-alice"))
	if got := TokenKey(KubeIssuer, "", "kube-static-alice"); got != "tok:"+hex.EncodeToString(raw[:16]) {
		t.Errorf("opaque key changed: %q", got)
	}
}

// GAP-0759: a Kubernetes token was keyed by its text even when it carries
// a jti, and the API server's go-jose accepts it with '=' padding, spare
// bits or a line break. A JWT is keyed by its jti, else by its claims.
func TestGAP0759KubeTokenKeyIgnoresTheEncoding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "alice@example.com"}}})
	}))
	t.Cleanup(srv.Close)
	own := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(own, []byte("gateway-sa"), 0o600)
	now := time.Unix(1_800_000_000, 0)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: own, HTTP: srv.Client(), Now: func() time.Time { return now }}
	key := func(tok string) Person {
		t.Helper()
		p, err := k.Verify(context.Background(), tok)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []string{
		fmt.Sprintf(`{"iat":%d,"exp":%d,"sub":"alice"}`, now.Unix()-30, now.Unix()+600),
		fmt.Sprintf(`{"iat":%d,"exp":%d,"sub":"alice","jti":"k-1"}`, now.Unix()-30, now.Unix()+600),
	} {
		for len(c)%3 != 1 { // 4 spare bits in the claims part
			c = c[:len(c)-1] + ` }`
		}
		body := base64.RawURLEncoding.EncodeToString([]byte(c))
		tok := "eyJhbGciOiJSUzI1NiJ9." + body + ".c2ln"
		want := key(tok)
		if strings.Contains(c, "k-1") {
			if want.TokenID != "k-1" || want.TokenKey != TokenKey(KubeIssuer, "k-1", "") || !strings.HasPrefix(want.TokenKey, "jti:") {
				t.Errorf("a kube token with a jti is keyed %q (jti %q)", want.TokenKey, want.TokenID)
			}
		} else if !strings.HasPrefix(want.TokenKey, "clm:") {
			t.Errorf("a kube JWT with no jti is keyed %q, want its claims hash", want.TokenKey)
		}
		for name, v := range map[string]string{
			"padding":    "eyJhbGciOiJSUzI1NiJ9." + body + "==.c2ln",
			"spare bits": "eyJhbGciOiJSUzI1NiJ9." + flipSpareBit(t, body) + ".c2ln",
			"line break": "eyJhbGciOiJSUzI1NiJ9." + body[:4] + "\n" + body[4:] + ".c2ln",
			"signature":  "eyJhbGciOiJSUzI1NiJ9." + body + ".c2lu",
		} {
			if got := key(v); got.TokenKey != want.TokenKey || !got.IssuedAt.Equal(want.IssuedAt) {
				t.Errorf("%s: kube %s variant keyed %q, want %q", c, name, got.TokenKey, want.TokenKey)
			}
		}
	}
	if p := key("kube-static-alice"); !strings.HasPrefix(p.TokenKey, "tok:") || !p.IssuedAt.IsZero() {
		t.Errorf("opaque kube token keyed %q iat %v", p.TokenKey, p.IssuedAt)
	}
}
