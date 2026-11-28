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
	"testing"
	"time"
)

// RV1-01: a Kubernetes person carries the key of its token and, for a JWT,
// its iat, so logout, logout --all and admin revoke can end it.
func TestKubePersonCarriesTokenKeyAndIssueTime(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec struct{ Token string } `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "alice@example.com"}}})
	}))
	t.Cleanup(srv.Close)
	own := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(own, []byte("gateway-sa"), 0o600)
	now := time.Unix(1_800_000_000, 0)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: own, HTTP: srv.Client(), Now: func() time.Time { return now }}
	jwt := func(claims string) string {
		return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2ln"
	}
	for _, tc := range []struct {
		name, token string
		iat         time.Time
	}{
		{"bound token", jwt(fmt.Sprintf(`{"iat":%d,"exp":%d}`, now.Unix()-30, now.Unix()+3600)), now.Add(-30 * time.Second)},
		{"opaque token", "kube-static-alice", time.Time{}},
		{"no iat", jwt(fmt.Sprintf(`{"sub":"alice","exp":%d}`, now.Unix()+3600)), time.Time{}},
		{"iat far ahead", jwt(fmt.Sprintf(`{"iat":%d,"exp":%d}`, now.Unix()+3600, now.Unix()+7200)), time.Time{}},
	} {
		p, err := k.Verify(context.Background(), tc.token)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if p.TokenKey != TokenKey(KubeIssuer, "", tc.token) || !p.IssuedAt.Equal(tc.iat) {
			t.Errorf("%s: key %q iat %v, want key %q iat %v", tc.name, p.TokenKey, p.IssuedAt, TokenKey(KubeIssuer, "", tc.token), tc.iat)
		}
	}
}
