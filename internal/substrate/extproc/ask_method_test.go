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

package extproc

import (
	"context"
	"testing"
)

// TestURLRuleAskBindsTheMethodGAP0177 is the 03:40Z ruling: an approval
// binds to host, rule id, method and path prefix. One rule listing POST
// and DELETE asks three different questions for a POST, a DELETE and a
// POST that overrides to DELETE, so an approved POST never covers a
// DELETE. The person sees the method in the summary.
func TestURLRuleAskBindsTheMethodGAP0177(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = []URLRuleCfg{
			{Name: "repo-writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST", "DELETE"}, PathPrefix: "/repos/", Action: "ask"},
		}
	})
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/repos/acme/web"))
	h.eng.DecideHeaders(ctx, req("eng-web", "DELETE", "api.github.com", "/repos/acme/web"))
	h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/repos/acme/web", "x-http-method-override", "DELETE"))
	if len(h.asks.got) != 3 {
		t.Fatalf("asks: %+v", h.asks.got)
	}
	for i, want := range []struct{ rule, method string }{
		{"url_rules:repo-writes POST", "POST"},
		{"url_rules:repo-writes DELETE", "DELETE"},
		{"url_rules:repo-writes DELETE,POST", "DELETE,POST"},
	} {
		if g := h.asks.got[i]; g.Rule != want.rule || g.Method != want.method || g.PathPrefix != "/repos/" {
			t.Errorf("ask %d: %+v, want rule %q method %q", i, g, want.rule, want.method)
		}
	}
}
