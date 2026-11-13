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

// Lane R3a proof tests (claude:c7409eb0/r3a), uncommitted. A failing test
// is a bypass on feat/substrate 7537ad2ea0; TestR3aCheck* are controls that
// pass.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
)

// GAP-0046: Express method-override (the header getter) takes the first
// value of a comma list ("DELETE, GET" is DELETE); the callout compares the
// whole header value, so the deny DELETE rule does not apply.
func TestR3aMethodOverrideHeaderList(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	for _, val := range []string{"DELETE, GET", "DELETE,GET", "delete , post"} {
		r := req("eng-web", "POST", "api.github.com", "/repos/acme/web", "x-http-method-override", val)
		if v := h.eng.DecideHeaders(ctx, r); v.Allow {
			t.Errorf("POST with X-HTTP-Method-Override %q passed the DELETE deny rule: %+v", val, v)
		}
	}
}

// GAP-0046: Rails (Rack::MethodOverride, in the default middleware stack)
// and Symfony/Laravel read _method from a form body first; a POST with the
// form body _method=DELETE runs as DELETE there. The callout reads _method
// from the query only.
func TestR3aMethodOverrideFormBody(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	body := []byte("_method=DELETE")
	r := req("eng-web", "POST", "api.github.com", "/repos/acme/web", "content-type", "application/x-www-form-urlencoded")
	r.ContentType, r.ContentLength, r.EndOfStream = "application/x-www-form-urlencoded", int64(len(body)), false
	v := h.eng.DecideHeaders(ctx, r)
	if v.Allow && v.WantBody {
		v = h.eng.DecideBody(ctx, r, v, body)
	}
	if v.Allow {
		t.Errorf("POST with form body _method=DELETE passed the DELETE deny rule: %+v", v)
	}
}

// New (GAP-0171 keys): the chart renders substrate.admin's url_rules, then
// the profile's (config.tightenAskKeys), and the first rule that applies
// decides. A profile deny after an admin ask that covers the same requests
// is never reached: the request is asked, and an approval lets through a
// request the profile refuses.
func TestR3aAdminAskShadowsProfileDeny(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = []URLRuleCfg{
			{Name: "admin-repo-ask", Hosts: []string{"api.github.com"}, PathPrefix: "/repos/", Action: "ask"},
			{Name: "profile-no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, PathPrefix: "/repos/acme/", Action: "deny"},
		}
	})
	v := h.eng.DecideHeaders(context.Background(), req("eng-web", "DELETE", "api.github.com", "/repos/acme/web"))
	if v.Allow || v.Category != CategoryURLRule || v.Rule != "profile-no-delete" {
		t.Errorf("the profile's deny was shadowed by the admin's ask (asks raised %d): %+v", len(h.asks.got), v)
	}
}

// P3: a deny prefix written with a trailing slash (/admin/, the gap's own
// example) does not cover the bare path; Express (non-strict routing, the
// default) serves /admin with the /admin/ route.
func TestR3aP3TrailingSlashDenyPrefix(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = append([]URLRuleCfg{
			{Name: "no-admin", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "deny"},
		}, c.Profiles[0].URLRules...)
	})
	if v := h.eng.DecideHeaders(context.Background(), req("eng-web", "POST", "api.github.com", "/admin")); v.Allow {
		t.Errorf("POST /admin passed a deny /admin/ rule: %+v", v)
	}
}

// Controls (pass): GAP-0156 folding holds for escaped keys, a batch, and a
// body with trailing data; GAP-0046 encodings stay refused.
func TestR3aCheckJSONRPCFoldVariants(t *testing.T) {
	ctx := context.Background()
	judged := map[string]string{
		"escaped M":        `{"jsonrpc":"2.0","id":1,"\u004dethod":"tools/call","params":{"name":"drop_tables"}}`,
		"batch METHOD":     `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"METHOD":"tools/call","params":{"NAME":"drop_tables"}}]`,
		"long s in nested": "[{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"paramſ\":{\"name\":\"drop_tables\"}}]",
		"escaped value":    `{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"drop_tables"}}`,
	}
	for name, b := range judged {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = FailureClosed })
			h.judge.block = true
			r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
			r.ContentType = "application/json"
			if v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, []byte(b)); v.Allow {
				t.Errorf("allowed (judge calls %d): %+v", len(h.judge.calls), v)
			}
		})
	}
	refused := map[string]string{
		"trailing object": `{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop_tables"}}`,
		"dup id folded":   `{"jsonrpc":"2.0","id":1,"ID":2,"method":"tools/call","params":{"name":"x"}}`,
	}
	for name, b := range refused {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = FailureClosed })
			r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
			r.ContentType = "application/json"
			if v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, []byte(b)); v.Allow {
				t.Errorf("allowed: %+v", v)
			}
		})
	}
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = append([]URLRuleCfg{
			{Name: "no-admin", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/admin", Action: "deny"},
		}, c.Profiles[0].URLRules...)
	})
	for _, p := range []string{"/public/%2e%2e/admin/x", "/admin/x/..", "/x/..;/admin", "/%252e%252e/admin", "/x/%5c../admin",
		"/ADMIN/x", "/admin;x=1/y", "/./admin", "//admin", "/x/%2E%2e/admin", "/admin/x?y=1&_METHOD=post"} {
		m := "POST"
		if strings.Contains(p, "_METHOD") {
			m = "GET"
		}
		if v := h.eng.DecideHeaders(ctx, req("eng-web", m, "api.github.com", p)); v.Allow {
			t.Errorf("%s %s allowed: %+v", m, p, v)
		}
	}
}

// P3 (GAP-0168 residual, open mode only): AskClient reads every answer but
// 200 as an outage (ErrAskUnreachable), so the failure mode decides. The
// gateway's deliberate answers (404 actor_not_found for an actor with no
// person or a stale UID, 404 ask_not_found when a held ask is gone) then
// allow an ask-required host with failure_mode open. Closed mode refuses
// (control, passes).
func TestR3aAskRefusalAnswersAreNotOutages(t *testing.T) {
	var polls atomic.Int32
	cases := map[string]http.HandlerFunc{
		"actor_not_found": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"actor_not_found"}`))
		},
		"held ask gone": func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"id":"ask-9","state":"pending"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"ask_not_found"}`))
		},
	}
	for name, hf := range cases {
		for _, mode := range []string{FailureOpen, FailureClosed} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				polls.Store(0)
				srv := httptest.NewServer(hf)
				defer srv.Close()
				tok := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
					t.Fatal(err)
				}
				var cfgJudge JudgeConfig
				cfgJudge.URL, cfgJudge.TokenFile = srv.URL+calloutapi.Path, tok
				c, err := NewAskClient(&Config{Judge: cfgJudge})
				if err != nil || c == nil {
					t.Fatal(c, err)
				}
				h := newHarness(t, func(cfg *Config, o *Options) {
					cfg.FailureMode = mode
					o.Asks = c
				})
				v := h.eng.DecideHeaders(context.Background(), req("eng-web", "GET", "files.example.io", "/x"))
				if v.Allow {
					t.Errorf("an ask-required host was allowed after the gateway answered %s: %+v", name, v)
				}
			})
		}
	}
}
