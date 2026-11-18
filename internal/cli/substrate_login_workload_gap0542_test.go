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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0542: login --workload warns when the cluster says no
// match.substrate.workloads entry matches the workload's subject; a match,
// and an older cluster that sends no workload answer, give no warning. The
// subject is printed as one safe line.
func TestGAP0542LoginWorkloadWarnsWhenNoEntryMatches(t *testing.T) {
	answers := map[string]string{
		"/none":  `{"actors":[],"workload":{"subject":"repo:acme@1/web@2:ref:refs/heads/main","entry":"","profile":""}}`,
		"/match": `{"actors":[],"workload":{"subject":"repo:acme@1/web@2:ref:refs/heads/main","entry":"repo:acme@1/web@2:*","profile":"ci"}}`,
		"/old":   `{"actors":[]}`,
		"/esc":   `{"actors":[],"workload":{"subject":"repo:x\u001b[2J\nfake line","entry":""}}`,
	}
	cur := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/substrate/actors" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answers[cur]))
	}))
	defer srv.Close()
	warning := func(base, tokenSubject string) string {
		t.Helper()
		cur = base
		cl, err := api.New(api.Options{Base: srv.URL, Token: func(context.Context) (string, error) { return "t", nil }})
		if err != nil {
			t.Fatal(err)
		}
		_, wm, err := cl.ListWithWorkload(context.Background(), api.ListOptions{})
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		return substrateWorkloadWarning(wm, tokenSubject)
	}
	if got := warning("/none", "from-token"); got != "no match.substrate.workloads entry matches repo:acme@1/web@2:ref:refs/heads/main; it gets the default profile" {
		t.Errorf("no match: %q", got)
	}
	if got := warning("/match", "from-token"); got != "" {
		t.Errorf("match: %q", got)
	}
	if got := warning("/old", "from-token"); got != "" {
		t.Errorf("older cluster: %q", got)
	}
	if got := warning("/esc", "from-token"); strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, "fake line") {
		t.Errorf("unsafe subject printed: %q", got)
	}
	// No subject from the cluster: the token's is named.
	if got := substrateWorkloadWarning(&api.WorkloadMatch{}, "repo:acme/web:ref:refs/heads/main"); !strings.Contains(got, "matches repo:acme/web:ref:refs/heads/main;") {
		t.Errorf("token subject: %q", got)
	}
}
