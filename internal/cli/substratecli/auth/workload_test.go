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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func emptyEnv(string) string { return "" }

func writeTok(t *testing.T, dir, name, v string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWorkloadSources(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	dir := t.TempDir()
	good := func(marker string, extra map[string]any) string {
		c := map[string]any{"exp": future, "aud": DefaultWorkloadAudience}
		for k, v := range extra {
			c[k] = v
		}
		return testJWT(t, marker, c)
	}
	fileTok := writeTok(t, dir, "opt", good("from-opt", nil))
	envTok := writeTok(t, dir, "env", good("from-env", nil))
	k8sTok := writeTok(t, dir, "k8s", good("from-k8s", map[string]any{"sub": "system:serviceaccount:t:ci-workload"}))
	empty := writeTok(t, dir, "empty", "")

	var ghAuth, ghAud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghAuth, ghAud = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		writeJSON(w, 200, map[string]any{"value": good("from-gh", nil)})
	}))
	defer gh.Close()

	tests := []struct {
		name    string
		file    string
		env     map[string]string
		want    string
		wantErr string
	}{
		{name: "option file wins", file: fileTok, env: map[string]string{EnvWorkloadTokenFile: envTok}, want: "from-opt"},
		{name: "env file", env: map[string]string{EnvWorkloadTokenFile: envTok, EnvK8sTokenFile: k8sTok}, want: "from-env"},
		{name: "github", env: map[string]string{EnvGitHubRequestURL: gh.URL + "/idtoken?api-version=2.0", EnvGitHubRequestToken: "gh-req-marker", EnvK8sTokenFile: k8sTok}, want: "from-gh"},
		{name: "k8s env", env: map[string]string{EnvK8sTokenFile: k8sTok}, want: "from-k8s"},
		{name: "named file missing", file: filepath.Join(dir, "nope"), wantErr: "the token file " + filepath.Join(dir, "nope") + " does not exist"},
		{name: "env file empty", env: map[string]string{EnvWorkloadTokenFile: empty}, wantErr: EnvWorkloadTokenFile + " (" + empty + ") is empty"},
		{name: "github half set", env: map[string]string{EnvGitHubRequestURL: gh.URL}, wantErr: "needs both"},
		{name: "github over http off loopback", env: map[string]string{EnvGitHubRequestURL: "http://gh.example.test/x", EnvGitHubRequestToken: "gh-req-marker"}, wantErr: "must use https"},
		{name: "none", wantErr: "no workload token found; looked at 1) --token-file, 2) " + EnvWorkloadTokenFile},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := func(k string) string { return tc.env[k] }
			tok, err := WorkloadLogin(context.Background(), Context{AdminURL: "https://admin.example.test"}, WorkloadOptions{TokenFile: tc.file, Env: env, HTTPClient: gh.Client()})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				noSecret(t, err, "from-", "gh-req-marker")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tok.Kind != KindWorkload || decodeClaimsMarker(tok.AccessToken) != tc.want {
				t.Fatalf("got %s marker %q", tok, decodeClaimsMarker(tok.AccessToken))
			}
		})
	}
	if ghAuth != "bearer gh-req-marker" || ghAud != DefaultWorkloadAudience {
		t.Errorf("github request: auth ok=%v audience=%q", ghAuth == "bearer gh-req-marker", ghAud)
	}
}

// TestWorkloadNoDefaultK8sPath: the pod's own service-account token (for
// the API server) is never picked up without being named.
func TestWorkloadNoDefaultK8sPath(t *testing.T) {
	_, err := WorkloadLogin(context.Background(), Context{AdminURL: "https://admin.example.test"}, WorkloadOptions{Env: emptyEnv})
	if err == nil || strings.Contains(err.Error(), "kubernetes.io/serviceaccount") || !strings.Contains(err.Error(), EnvK8sTokenFile+` (a projected Kubernetes service-account token with audience "defenseclaw")`) {
		t.Fatalf("err = %v", err)
	}
}

// TestWorkloadAudienceCheck runs every token shape through every source.
func TestWorkloadAudienceCheck(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	enc := base64.RawURLEncoding.EncodeToString
	shapes := []struct {
		name    string
		tok     string
		ok      bool
		wantErr []string
	}{
		{name: "aud string", tok: testJWT(t, "tok-marker", map[string]any{"exp": future, "aud": "defenseclaw"}), ok: true},
		{name: "aud list holds it", tok: testJWT(t, "tok-marker", map[string]any{"exp": future, "aud": []string{"other.example.test", "defenseclaw"}}), ok: true},
		{name: "no exp is left to the gateway", tok: testJWT(t, "tok-marker", map[string]any{"aud": "defenseclaw"}), ok: true},
		{name: "wrong aud", tok: testJWT(t, "tok-marker", map[string]any{"exp": future, "aud": "https://kubernetes.default.svc"}),
			wantErr: []string{`is for the audience "https://kubernetes.default.svc", not "defenseclaw", so it is not sent`, `mint the token for the audience "defenseclaw"`, "projected service-account token", EnvK8sTokenFile}},
		{name: "wrong aud list", tok: testJWT(t, "tok-marker", map[string]any{"exp": future, "aud": []string{"a.example.test", "b.example.test"}}),
			wantErr: []string{`for the audience "a.example.test", "b.example.test", not "defenseclaw"`}},
		{name: "missing aud", tok: testJWT(t, "tok-marker", map[string]any{"exp": future}),
			wantErr: []string{`has no aud (audience) claim`, `expects the audience "defenseclaw"`}},
		{name: "empty aud list", tok: testJWT(t, "tok-marker", map[string]any{"exp": future, "aud": []string{}}),
			wantErr: []string{`has no aud (audience) claim`}},
		{name: "expired", tok: testJWT(t, "tok-marker", map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "aud": "defenseclaw"}),
			wantErr: []string{"expired at", "mint a fresh one"}},
		{name: "opaque", tok: "opaque-tok-marker-0123456789",
			wantErr: []string{"is not a JWT (three parts separated by dots)"}},
		{name: "two parts", tok: enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"aud":"defenseclaw","m":"tok-marker"}`)),
			wantErr: []string{"is not a JWT"}},
		{name: "payload not JSON", tok: enc([]byte("head")) + "." + enc([]byte("tok-marker not json")) + "." + enc([]byte("sig")),
			wantErr: []string{"has no readable claims"}},
	}

	var mu sync.Mutex
	ghValue := ""
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, 200, map[string]any{"value": ghValue})
	}))
	defer gh.Close()

	sources := []struct {
		name string
		what string
		opts func(path string) WorkloadOptions
	}{
		{"option file", "the token file", func(p string) WorkloadOptions {
			return WorkloadOptions{TokenFile: p, Env: emptyEnv}
		}},
		{"env file", EnvWorkloadTokenFile, func(p string) WorkloadOptions {
			return WorkloadOptions{Env: func(k string) string { return map[string]string{EnvWorkloadTokenFile: p}[k] }}
		}},
		{"k8s projected file", EnvK8sTokenFile, func(p string) WorkloadOptions {
			return WorkloadOptions{Env: func(k string) string { return map[string]string{EnvK8sTokenFile: p}[k] }}
		}},
		{"github", "GitHub Actions OIDC", func(string) WorkloadOptions {
			env := map[string]string{EnvGitHubRequestURL: gh.URL + "/idtoken", EnvGitHubRequestToken: "gh-req-marker"}
			return WorkloadOptions{Env: func(k string) string { return env[k] }, HTTPClient: gh.Client()}
		}},
	}
	c := Context{AdminURL: "https://admin.example.test"}
	for _, src := range sources {
		for _, sh := range shapes {
			t.Run(src.name+"/"+sh.name, func(t *testing.T) {
				p := writeTok(t, t.TempDir(), "tok", sh.tok)
				mu.Lock()
				ghValue = sh.tok
				mu.Unlock()
				tok, err := WorkloadLogin(context.Background(), c, src.opts(p))
				if sh.ok {
					if err != nil {
						t.Fatal(err)
					}
					if tok.AccessToken != sh.tok {
						t.Fatal("the token sent is not the token read")
					}
					return
				}
				if err == nil {
					t.Fatal("token accepted")
				}
				for _, w := range append([]string{src.what}, sh.wantErr...) {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("err = %v, want %q", err, w)
					}
				}
				noSecret(t, err, sh.tok, "tok-marker", "gh-req-marker", "eyJ")
			})
		}
	}
}

func TestWorkloadGitHubAudience(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	var aud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud = r.URL.Query().Get("audience")
		// The issuer mints for what it was asked.
		writeJSON(w, 200, map[string]any{"value": testJWT(t, "gh", map[string]any{"exp": future, "aud": aud})})
	}))
	defer gh.Close()
	env := map[string]string{EnvGitHubRequestURL: gh.URL + "/idtoken", EnvGitHubRequestToken: "r"}
	c := Context{AdminURL: "https://admin.example.test", WorkloadAudience: "https://dc-e1.example.test"}
	if _, err := WorkloadLogin(context.Background(), c, WorkloadOptions{Env: func(k string) string { return env[k] }, HTTPClient: gh.Client()}); err != nil {
		t.Fatal(err)
	}
	if aud != "https://dc-e1.example.test" {
		t.Errorf("audience = %q", aud)
	}

	// A token for the default audience is not sent to a context that wants its own.
	p := writeTok(t, t.TempDir(), "tok", testJWT(t, "x", map[string]any{"exp": future, "aud": DefaultWorkloadAudience}))
	_, err := WorkloadLogin(context.Background(), c, WorkloadOptions{TokenFile: p, Env: emptyEnv})
	if err == nil || !strings.Contains(err.Error(), `not "https://dc-e1.example.test"`) {
		t.Fatalf("err = %v", err)
	}
}
