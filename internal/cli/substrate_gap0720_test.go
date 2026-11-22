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

package cli

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
)

// GAP-0720: the egress guard answers a CONNECT to a host the agent's rules
// do not allow with 403, which git reports like a refused token. run
// --clone must say the network rules refused the host (the reason code and
// its fix), not offer a token that cannot help, and add no secret.
func TestGAP0720CloneRefusedByRulesIsNotACredential(t *testing.T) {
	const repo = "https://git.corp.example/team/app.git"
	cases := []struct {
		name, policy string
		allowed      bool
		wantRules    bool
	}{
		{"refused", "in force", false, true},
		{"no policy", "none", false, true},
		{"allowed keeps the token offer", "in force", true, false},
		{"unknown keeps the token offer", "unknown", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			posts := 0
			useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
				"GET secret-templates": func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(b1CloneTemplates))
				},
				"GET secrets": jsonReply(map[string]any{"secrets": []any{}}),
				"POST secrets": func(w http.ResponseWriter, _ *http.Request) {
					mu.Lock()
					posts++
					mu.Unlock()
					w.WriteHeader(http.StatusInternalServerError)
				},
				"GET policy/explain": func(w http.ResponseWriter, r *http.Request) {
					jsonReply(map[string]any{"egress": map[string]any{"policy": tc.policy},
						"host": map[string]any{"host": r.URL.Query().Get("host"), "allowed": tc.allowed}})(w, r)
				},
			}})
			cmd, cl, errb := b1CloneSetup(t, false, true)
			calls := 0
			_, err := substrateCloneOnce(t.Context(), cmd, cl, api.Actor{Atespace: "eng", Name: "a1"}, &substrateRunFlags{clone: repo},
				func() (*workspace.CloneResult, error) {
					calls++
					return nil, &workspace.CloneError{URL: repo, Exit: 128,
						Message: "unable to access '" + repo + "/': CONNECT tunnel failed, response 403"}
				})
			if err == nil || calls != 1 || posts != 0 {
				t.Fatalf("err %v calls=%d posts=%d stderr %q", err, calls, posts, errb.String())
			}
			msg := err.Error()
			rules := strings.Contains(msg, "not_in_allow_only") && strings.Contains(msg, "do not allow git.corp.example")
			if rules != tc.wantRules {
				t.Fatalf("rules message = %v, want %v: %s", rules, tc.wantRules, msg)
			}
			if token := strings.Contains(msg, "needs a token"); token == tc.wantRules {
				t.Fatalf("token offer = %v, want %v: %s", token, !tc.wantRules, msg)
			}
		})
	}
}

// An LFS object host the rules do not allow is named, even when the git
// host itself is allowed.
func TestGAP0720CloneRefusedObjectHost(t *testing.T) {
	const repo = "https://git.corp.example/team/app.git"
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET policy/explain": func(w http.ResponseWriter, r *http.Request) {
			h := r.URL.Query().Get("host")
			jsonReply(map[string]any{"egress": map[string]any{"policy": "in force"},
				"host": map[string]any{"host": h, "allowed": h == "git.corp.example"}})(w, r)
		},
	}})
	cmd, cl, _ := b1CloneSetup(t, false, true)
	_, err := substrateCloneOnce(t.Context(), cmd, cl, api.Actor{Atespace: "eng", Name: "a1"}, &substrateRunFlags{clone: repo},
		func() (*workspace.CloneResult, error) {
			return nil, &workspace.CloneError{URL: repo, Exit: 128,
				Message: "Smudge error: Error downloading lib.bin (abc): batch response: Get \"https://media.example-cdn.test/o/abc\": CONNECT tunnel failed, response 403"}
		})
	if err == nil || !strings.Contains(err.Error(), "do not allow media.example-cdn.test") {
		t.Fatalf("err %v", err)
	}
}
