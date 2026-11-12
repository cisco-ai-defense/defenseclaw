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
	old := k8sTokenPath
	k8sTokenPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { k8sTokenPath = old })

	future := time.Now().Add(time.Hour).Unix()
	dir := t.TempDir()
	fileTok := writeTok(t, dir, "opt", testJWT(t, "from-opt", map[string]any{"exp": future}))
	envTok := writeTok(t, dir, "env", testJWT(t, "from-env", map[string]any{"exp": future}))
	k8sTok := writeTok(t, dir, "k8s", testJWT(t, "from-k8s", map[string]any{"exp": future, "sub": "system:serviceaccount:t:ci-workload"}))
	expired := writeTok(t, dir, "old", testJWT(t, "from-old", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}))
	empty := writeTok(t, dir, "empty", "")

	var ghAuth, ghAud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghAuth, ghAud = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		writeJSON(w, 200, map[string]any{"value": testJWT(t, "from-gh", map[string]any{"exp": future})})
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
		{name: "expired", file: expired, wantErr: "expired at"},
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

func TestWorkloadGitHubAudience(t *testing.T) {
	var aud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aud = r.URL.Query().Get("audience")
		writeJSON(w, 200, map[string]any{"value": "opaque-gh"})
	}))
	defer gh.Close()
	env := map[string]string{EnvGitHubRequestURL: gh.URL + "/idtoken", EnvGitHubRequestToken: "r"}
	c := Context{AdminURL: "https://admin.example.test", WorkloadAudience: "custom aud"}
	if _, err := WorkloadLogin(context.Background(), c, WorkloadOptions{Env: func(k string) string { return env[k] }, HTTPClient: gh.Client()}); err != nil {
		t.Fatal(err)
	}
	if aud != "custom aud" {
		t.Errorf("audience = %q", aud)
	}
}
