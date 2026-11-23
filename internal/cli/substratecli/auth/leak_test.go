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

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoTokenInErrors drives the failure paths with token-shaped values
// and checks that no returned error carries any part of them.
func TestNoTokenInErrors(t *testing.T) {
	setHome(t)
	ctx := context.Background()
	refresh := "refresh-leak-" + strings.Repeat("r", 300)
	access := testJWT(t, "acc-leak", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	secrets := []string{"refresh-leak", "acc-leak", "devcode-marker", "ghreq-leak", "wl-leak", access, refresh[:40]}
	var errs []error
	collect := func(err error) {
		if err == nil {
			t.Helper()
			t.Fatal("expected an error")
		}
		errs = append(errs, err)
	}

	// Refresh refused, with the issuer echoing the refresh token.
	idp := newFakeIdP(t)
	idp.refreshFn = func(f map[string]string) (int, map[string]any) {
		return 400, map[string]any{"error": "invalid_grant", "error_description": "unknown token " + f["refresh_token"]}
	}
	st := newMemStore()
	st.m["e1"] = Token{AccessToken: access, RefreshToken: refresh}
	_, err := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client()}).Token(ctx)
	collect(err)
	idp.refreshFn = func(f map[string]string) (int, map[string]any) {
		return 400, map[string]any{"error": "invalid_request", "error_description": f["refresh_token"]}
	}
	_, err = NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client()}).Token(ctx)
	collect(err)

	// Device flow, with the issuer echoing the device code.
	idp.steps = []string{"echo"}
	clk := newClock()
	_, err = DeviceLogin(ctx, idp.context(), LoginOptions{HTTPClient: idp.srv.Client(), Now: clk.Now, Sleep: clk.Sleep})
	collect(err)

	// Workload: expired file, GitHub refusal.
	dir := t.TempDir()
	p := filepath.Join(dir, "wl")
	_ = os.WriteFile(p, []byte(testJWT(t, "wl-leak", map[string]any{"exp": 1})), 0o600)
	_, err = WorkloadLogin(ctx, Context{}, WorkloadOptions{TokenFile: p, Env: emptyEnv})
	collect(err)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied "+r.Header.Get("Authorization"), http.StatusForbidden)
	}))
	defer gh.Close()
	env := map[string]string{EnvGitHubRequestURL: gh.URL, EnvGitHubRequestToken: "ghreq-leak"}
	_, err = WorkloadLogin(ctx, Context{}, WorkloadOptions{Env: func(k string) string { return env[k] }, HTTPClient: gh.Client()})
	collect(err)

	// Stores: a corrupt file holding a token.
	fsSt, _ := openStore("file")
	_ = os.MkdirAll(tokenDir(), 0o700)
	_ = os.WriteFile(filepath.Join(tokenDir(), "e1.json"), []byte(`{"refresh_token":"`+refresh+`"`), 0o600)
	_, err = fsSt.Load("e1")
	collect(err)

	for _, err := range errs {
		noSecret(t, err, secrets...)
		if strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), "rrrrrrrr") {
			t.Fatalf("error carries token-shaped text: %v", err)
		}
	}
}
