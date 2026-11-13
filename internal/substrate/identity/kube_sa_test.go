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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// kubeAudienceAPI is an API server whose TokenReview behaves as a real one
// does: a ServiceAccount token is authenticated only for the audiences it
// was minted for (the default, an empty spec.audiences, is the API
// server's own), and a static-token user is audience-agnostic only for the
// API server's audience.
func kubeAudienceAPI(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	const apiAud = "https://kubernetes.default.svc"
	type tok struct {
		user map[string]any
		auds []string
	}
	tokens := map[string]tok{
		// launcher TokenRequest for the DefenseClaw audience (GAP-0192)
		"sa-launcher": {map[string]any{"username": "system:serviceaccount:dev:defenseclaw-launcher", "uid": "sa-1",
			"groups": []string{"system:serviceaccounts", "system:serviceaccounts:dev", "system:authenticated"}}, []string{KubeTokenAudience}},
		// a pod's mounted token: the API server's audience only
		"sa-pod": {map[string]any{"username": "system:serviceaccount:dc:defenseclaw-gateway"}, []string{apiAud}},
		"node":   {map[string]any{"username": "system:node:kind-control-plane"}, []string{apiAud, KubeTokenAudience}},
		"alice":  {map[string]any{"username": "alice", "groups": []string{"dc-devs"}}, []string{apiAud}},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer gateway-sa" {
			w.WriteHeader(403)
			return
		}
		var in struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		want := in.Spec.Audiences
		if len(want) == 0 {
			want = []string{apiAud}
		}
		st := map[string]any{"authenticated": false}
		if tk, ok := tokens[in.Spec.Token]; ok {
			var match []string
			for _, a := range want {
				if slices.Contains(tk.auds, a) {
					match = append(match, a)
				}
			}
			if len(match) > 0 {
				st = map[string]any{"authenticated": true, "user": tk.user, "audiences": match}
			}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st})
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("gateway-sa"), 0o600)
	return srv, file
}

// GAP-0192: a ServiceAccount token the launcher minted for DefenseClaw is a
// Kubernetes person (k8s_user, subject system:serviceaccount:NS:NAME); a
// pod's own token (the API server's audience) and a node are not. The
// gateway checks the audience itself and trusts nothing the client says.
func TestKubeTokenVerifierServiceAccounts(t *testing.T) {
	srv, file := kubeAudienceAPI(t)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: file, HTTP: srv.Client()}
	ctx := context.Background()

	p, err := k.Verify(ctx, "sa-launcher")
	if err != nil || p.Kind != PersonKube || p.Subject != "system:serviceaccount:dev:defenseclaw-launcher" ||
		!slices.Contains(p.Groups, "system:serviceaccounts:dev") {
		t.Fatalf("launcher ServiceAccount token: %+v %v", p, err)
	}
	if p, err := k.Verify(ctx, "alice"); err != nil || p.Subject != "alice" {
		t.Fatalf("static-token user: %+v %v", p, err)
	}
	_, err = k.Verify(ctx, "sa-pod")
	wantReason(t, err, ReasonSubject)
	_, err = k.Verify(ctx, "node")
	wantReason(t, err, ReasonSubject)
	_, err = k.Verify(ctx, "unknown")
	wantReason(t, err, ReasonSignature)
}
