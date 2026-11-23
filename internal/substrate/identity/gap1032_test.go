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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-1032: the exp rule of a Kubernetes JWT (GAP-0569, GAP-0587) read the
// claims with the strict base64url decoder, while the token key and issue
// time read them like the API server's go-jose does. A copy of a JWT with
// '=' padding or a Unicode white-space rune in its claims was taken for an
// opaque token: one with no exp, a non-finite exp or a past exp skipped
// the refusal and went to the TokenReview, and its answer was kept for the
// full review cache instead of ending at exp. Every encoding now goes
// through the exp rule.
func TestGAP1032ReencodedKubeTokenKeepsTheExpRule(t *testing.T) {
	var reviews atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reviews.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "alice@example.com"}}})
	}))
	t.Cleanup(srv.Close)
	own := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(own, []byte("gateway-sa"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: own, HTTP: srv.Client(), Now: func() time.Time { return now }}
	ctx := context.Background()
	const head = "eyJhbGciOiJSUzI1NiJ9"
	const sub = `"iss":"https://kubernetes.default.svc","sub":"alice"`
	// Re-encodings of one claims part that go-jose reads as the same bytes.
	encodings := func(claims string) map[string]string {
		body := base64.RawURLEncoding.EncodeToString([]byte(claims))
		return map[string]string{
			"canonical":     head + "." + body + ".c2ln",
			"padding":       head + "." + body + gap0787Pad(body) + ".c2ln",
			"no-break sp":   head + "." + body[:4] + "\u00a0" + body[4:] + ".c2ln",
			"line sep":      head + "." + body[:4] + "\u2028" + body[4:] + ".c2ln",
			"inner padding": head + "." + body[:4] + "=" + body[4:] + ".c2ln",
		}
	}

	refused := map[string]struct {
		claims string
		want   Reason
	}{
		"no exp":       {`{` + sub + `}`, ReasonClaims},
		"null exp":     {`{` + sub + `,"exp":null}`, ReasonClaims},
		"string exp":   {`{` + sub + `,"exp":"1800000600"}`, ReasonClaims},
		"huge exp":     {`{` + sub + `,"exp":1e400}`, ReasonClaims},
		"exp twice":    {`{` + sub + `,"exp":1799999990,"exp":1800000600}`, ReasonClaims},
		"past exp":     {`{` + sub + `,"exp":1799999990}`, ReasonExpired},
		"past decimal": {`{` + sub + `,"exp":1.79999999e9}`, ReasonExpired},
	}
	for name, c := range refused {
		for enc, tok := range encodings(c.claims) {
			before := reviews.Load()
			p, err := k.Verify(ctx, tok)
			if err == nil || ReasonOf(err) != c.want {
				t.Errorf("%s, %s: got %+v %v, want refused with %s", name, enc, p, err, c.want)
				continue
			}
			if reviews.Load() != before {
				t.Errorf("%s, %s: sent for review; a token refused on its exp is refused without one", name, enc)
			}
		}
	}

	// A future exp bounds the answer however the token is written, and every
	// encoding has the one key of the canonical token.
	var key string
	for enc, tok := range encodings(`{` + sub + `,"exp":1800000010}`) {
		p, err := k.Verify(ctx, tok)
		if err != nil {
			t.Fatalf("%s: future exp: %v", enc, err)
		}
		if want := time.Unix(1_800_000_010, 0); !p.Expires.Equal(want) || !p.TokenExpires.Equal(want) {
			t.Errorf("%s: Expires %v TokenExpires %v, want the token's exp %v", enc, p.Expires, p.TokenExpires, want)
		}
		if !strings.HasPrefix(p.TokenKey, "clm:") {
			t.Errorf("%s: keyed %q, want the claims key", enc, p.TokenKey)
		}
		if key == "" {
			key = p.TokenKey
		} else if p.TokenKey != key {
			t.Errorf("%s: keyed %q, another encoding %q", enc, p.TokenKey, key)
		}
	}
}
