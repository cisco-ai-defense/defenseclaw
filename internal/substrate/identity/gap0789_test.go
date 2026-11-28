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
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gap0789HighS is the (r, n-s) form of an ES256 token: the same signed
// bytes with the other valid signature.
func gap0789HighS(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("not an ES256 signature: %v", err)
	}
	s := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(sig[32:]))
	hi := append(append([]byte{}, sig[:32]...), s.FillBytes(make([]byte, 32))...)
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(hi)
}

// GAP-0789 (RV3-02): claims that start with JSON white space verify, but
// the key re-read the token text and refused them as a JWT, so the key was
// "tok:" over the text and an ES256 (r, n-s) copy of an ended token had
// another key. The OIDC key is now over the verified claims bytes, and the
// kube key reads claims that start with white space.
func TestGAP0789LeadingSpaceClaimsAreKeyedByClaims(t *testing.T) {
	p := newIDP(t)
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
	cb := []byte(fmt.Sprintf(" \n{\"iss\":%q,\"sub\":\"00u1\",\"aud\":\"dc-launcher\",\"exp\":%d,\"iat\":%d}", p.srv.URL, now.Unix()+600, now.Unix()-30))
	hb, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "ES256", "kid": "e1"})
	tok := signRaw(t, ecKey, "ES256", hb, cb)
	a, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("claims with leading white space: %v", err)
	}
	if !strings.HasPrefix(a.TokenKey, "clm:") || a.TokenKey != TokenKey(p.srv.URL, "", tok) {
		t.Fatalf("key %q, want the claims key %q", a.TokenKey, TokenKey(p.srv.URL, "", tok))
	}
	b, err := v.Verify(context.Background(), gap0789HighS(t, tok))
	if err != nil {
		t.Fatalf("(r, n-s) copy: %v", err)
	}
	if b.TokenKey != a.TokenKey {
		t.Fatalf("(r, n-s) copy has key %q, the token %q", b.TokenKey, a.TokenKey)
	}

	// A cluster JWT whose claims start with white space: claims key too.
	var reviews atomic.Int64
	k := gap0787Kube(t, now, &reviews)
	kc := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(" {\"iss\":\"https://kubernetes.default.svc\",\"sub\":\"x\",\"iat\":%d,\"exp\":%d}", now.Unix()-30, now.Unix()+600)))
	kp, err := k.Verify(context.Background(), "eyJhbGciOiJSUzI1NiJ9."+kc+".c2ln")
	if err != nil || !strings.HasPrefix(kp.TokenKey, "clm:") || kp.IssuedAt.IsZero() {
		t.Fatalf("cluster JWT with leading white space: key %q iat %v err %v", kp.TokenKey, kp.IssuedAt, err)
	}
}
