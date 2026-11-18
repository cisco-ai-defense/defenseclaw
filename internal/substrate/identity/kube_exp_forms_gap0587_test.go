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
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0587: the GAP-0569 exp pre-check of a Kubernetes bearer read exp as
// an integer only, so a JWT whose exp was 1799999990.0 or 1.79999999e9
// (valid NumericDates, already past) skipped it and its review answer was
// kept 30 s. Every exp form is read now, and a JWT whose exp cannot be read
// is refused. This test uses only the API that existed before the fix.
func TestKubeTokenExpFormsGAP0587(t *testing.T) {
	var reviews atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer gateway-sa" {
			w.WriteHeader(403)
			return
		}
		// Like an API server within its own leeway: every token is known.
		reviews.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "alice@example.com"}}})
	}))
	t.Cleanup(srv.Close)
	gw := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(gw, []byte("gateway-sa"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: gw, HTTP: srv.Client(), Now: func() time.Time { return now }}
	ctx := context.Background()
	enc := base64.RawURLEncoding.EncodeToString
	jwt := func(claims string) string {
		return enc([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + enc([]byte(claims)) + "." + enc([]byte("sig"))
	}
	const sub = `"iss":"https://kubernetes.default.svc","sub":"system:serviceaccount:ci:builder"`

	refused := map[string]struct {
		claims string
		want   Reason
	}{
		"decimal exp 10 s ago":        {`{` + sub + `,"exp":1799999990.0}`, ReasonExpired},
		"exponent exp 10 s ago":       {`{` + sub + `,"exp":1.79999999e9}`, ReasonExpired},
		"fraction exp 0.5 s ago":      {`{` + sub + `,"exp":1799999999.5}`, ReasonExpired},
		"negative exp":                {`{` + sub + `,"exp":-1}`, ReasonExpired},
		"no exp":                      {`{` + sub + `}`, ReasonClaims},
		"null exp":                    {`{` + sub + `,"exp":null}`, ReasonClaims},
		"string exp":                  {`{` + sub + `,"exp":"1800000600"}`, ReasonClaims},
		"object exp":                  {`{` + sub + `,"exp":{"v":1800000600}}`, ReasonClaims},
		"out-of-range exp":            {`{` + sub + `,"exp":1e400}`, ReasonClaims},
		"exp twice (past, then late)": {`{` + sub + `,"exp":1799999990,"exp":1800000600}`, ReasonClaims},
	}
	for name, c := range refused {
		before := reviews.Load()
		_, err := k.Verify(ctx, jwt(c.claims))
		if err == nil || ReasonOf(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
			continue
		}
		if reviews.Load() != before {
			t.Errorf("%s: sent for review; a token refused on its exp is refused without one", name)
		}
	}

	// A decimal exp in the future is read exactly: the answer ends at it.
	p, err := k.Verify(ctx, jwt(`{`+sub+`,"exp":1800000010.5}`))
	if err != nil {
		t.Fatalf("decimal exp 10.5 s ahead: %v", err)
	}
	if want := time.Unix(1_800_000_010, 500_000_000); !p.Expires.Equal(want) {
		t.Fatalf("Expires = %v, want the token's exp %v", p.Expires, want)
	}
	// A very large exp is a token that has not expired: the review decides.
	if _, err := k.Verify(ctx, jwt(`{`+sub+`,"exp":1e300}`)); err != nil {
		t.Fatalf("exp 1e300: %v", err)
	}
	// A token that is not a JWT (its middle part is no JSON object) keeps
	// the 30 s review cache, as before.
	for _, opaque := range []string{"kube-opaque", "a.b.c", "k8s-aws-v1." + enc([]byte("https://sts.example/?Action=GetCallerIdentity"))} {
		p, err := k.Verify(ctx, opaque)
		if err != nil || !p.Expires.Equal(now.Add(kubeReviewTTL)) {
			t.Fatalf("opaque %q: %+v %v", opaque[:min(len(opaque), 12)], p, err)
		}
	}
}
