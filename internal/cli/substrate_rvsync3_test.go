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
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
)

// RV-SYNC3 F3: a failed clone asks policy explain (one audit row per host)
// only when git's error is one the network rules can cause.
func TestRVSync3CloneRefusedExplainsOnlyNetworkErrors(t *testing.T) {
	const repo = "https://git.corp.example/team/app.git"
	var calls atomic.Int32
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET policy/explain": func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			jsonReply(map[string]any{"egress": map[string]any{"policy": "in force"},
				"host": map[string]any{"host": r.URL.Query().Get("host"), "allowed": false}})(w, r)
		},
	}})
	_, cl, _ := b1CloneSetup(t, false, true)
	a := api.Actor{Atespace: "eng", Name: "a1"}
	for _, tc := range []struct{ msg, want string }{
		{"warning: Could not find remote branch nope to clone.\nfatal: Remote branch nope not found in upstream origin", ""},
		{"fatal: repository '" + repo + "/' not found", ""},
		{"fatal: unable to access '" + repo + "/': CONNECT tunnel failed, response 403", "git.corp.example"},
		{"fatal: unable to access '" + repo + "/': The requested URL returned error: 401", "git.corp.example"},
		{"fatal: unable to access '" + repo + "/': Could not resolve host: git.corp.example", "git.corp.example"},
		{"fatal: unable to access '" + repo + "/': Failed to connect to git.corp.example port 443: Connection refused", "git.corp.example"},
	} {
		calls.Store(0)
		got := substrateCloneRefused(t.Context(), cl, a, &workspace.CloneError{URL: repo, Exit: 128, Message: tc.msg}, nil)
		if got != tc.want {
			t.Errorf("%q: refused host %q, want %q", tc.msg, got, tc.want)
		}
		if tc.want == "" && calls.Load() != 0 {
			t.Errorf("%q: asked policy explain %d times", tc.msg, calls.Load())
		}
	}
}
