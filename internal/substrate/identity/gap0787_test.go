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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gap0787Kube is an API server whose OIDC authenticator trusts the same IdP
// as DefenseClaw and decodes leniently: it authenticates every token it is
// asked about as oidc:00u1, and counts the reviews.
func gap0787Kube(t *testing.T, now time.Time, reviews *atomic.Int64) *KubeTokenVerifier {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reviews.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "oidc:00u1"}}})
	}))
	t.Cleanup(srv.Close)
	own := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(own, []byte("gateway-sa"), 0o600)
	return &KubeTokenVerifier{Server: srv.URL, TokenFile: own, HTTP: srv.Client(), Now: func() time.Time { return now }}
}

// gap0787Pad is '=' padding for a base64url part; a part that needs none
// gets "==", which go-jose trims as well.
func gap0787Pad(part string) string {
	if n := (4 - len(part)%4) % 4; n > 0 {
		return strings.Repeat("=", n)
	}
	return "=="
}

// GAP-0787 (RV3-01): a re-encoded copy of an OIDC token ('=' padding,
// spare bits, a line break, spaces) is refused by the strict parse as
// malformed, and the combined verifier handed it to the TokenReview, where
// an API server that trusts the same IdP accepted it as another person with
// another token key: an ended token worked again. A token whose claims name
// a configured issuer now stays with OIDC however it is written.
func TestGAP0787ReencodedOIDCTokenNeverFallsToKube(t *testing.T) {
	p := newIDP(t)
	rsaKey := p.addKey(t, "r1", "RS256")
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
	var reviews atomic.Int64
	pv := PersonVerifiers{OIDC: v, Kube: gap0787Kube(t, now, &reviews)}
	for _, withJTI := range []bool{false, true} {
		claims := map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher", "exp": now.Unix() + 600, "iat": now.Unix() - 30}
		if withJTI {
			claims["jti"] = "j-1"
		}
		tok := sign(t, rsaKey, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "r1"}, claims)
		a, err := pv.Verify(context.Background(), tok)
		if err != nil || a.Kind != PersonHuman {
			t.Fatalf("jti=%v: canonical token: %+v %v", withJTI, a, err)
		}
		parts := strings.Split(tok, ".")
		variants := map[string]string{}
		for i, name := range []string{"header", "claims", "signature"} {
			with := func(part string) string {
				q := append([]string{}, parts...)
				q[i] = part
				return strings.Join(q, ".")
			}
			variants[name+" padding"] = with(parts[i] + gap0787Pad(parts[i]))
			variants[name+" line break"] = with(parts[i][:4] + "\n" + parts[i][4:])
			if len(parts[i])%4 != 0 {
				variants[name+" spare bit"] = with(flipSpareBit(t, parts[i]))
				variants[name+" spare bit and padding"] = with(flipSpareBit(t, parts[i]) + gap0787Pad(parts[i]))
			}
		}
		// go-jose strips every Unicode white-space rune, not only the
		// ASCII ones (RV4-02).
		for _, ws := range []rune{'\u00a0', '\u0085', '\u2028', '\v', '\f'} {
			q := append([]string{}, parts...)
			q[1] = parts[1][:4] + string(ws) + parts[1][4:]
			variants[fmt.Sprintf("claims %U", ws)] = strings.Join(q, ".")
		}
		variants["leading space"] = " " + tok
		variants["trailing newline"] = tok + "\n"
		if len(parts[2])%4 == 0 {
			t.Fatal("test needs a signature part with spare bits")
		}
		for name, vt := range variants {
			reviews.Store(0)
			b, err := pv.Verify(context.Background(), vt)
			if err == nil && (b.ID() != a.ID() || b.TokenKey != a.TokenKey) {
				t.Errorf("jti=%v %s: ended %s %s, copy accepted as %s %s", withJTI, name, a.ID(), a.TokenKey, b.ID(), b.TokenKey)
			}
			if n := reviews.Load(); n != 0 {
				t.Errorf("jti=%v %s: a copy of an OIDC token went to the TokenReview (%d reviews)", withJTI, name, n)
			}
		}
	}

	// A token of another issuer, a JWT the cluster issued and an opaque
	// kubeconfig token still go to the TokenReview.
	other := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"https://kubernetes.default.svc","sub":"system:serviceaccount:ns:x","iat":%d,"exp":%d}`, now.Unix()-30, now.Unix()+600))) + ".c2ln"
	for name, tok := range map[string]string{"cluster JWT": other, "cluster JWT padded": other + "==", "opaque": "kube-static-alice"} {
		reviews.Store(0)
		got, err := pv.Verify(context.Background(), tok)
		if err != nil || got.Kind != PersonKube || reviews.Load() == 0 {
			t.Errorf("%s: want the TokenReview to decide, got %+v %v (%d reviews)", name, got, err, reviews.Load())
		}
	}
}
