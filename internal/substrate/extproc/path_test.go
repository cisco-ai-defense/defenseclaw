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
	"errors"
	"testing"
)

func TestCanonicalPath(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"*", "*"},
		{"/admin", "/admin"},
		{"/admin/", "/admin/"},
		{"/./admin/", "/admin/"},
		{"/%61dmin/", "/admin/"},
		{"/%2e/admin", "/admin"},
		{"/%2E%2E/admin", "/admin"},
		{"//admin//x", "/admin/x"},
		{"/a/b/../../admin/", "/admin/"},
		{"/../../admin", "/admin"},
		{"/admin/.", "/admin/"},
		{"/admin/x/..", "/admin/"},
		{"/admin;jsessionid=1/x", "/admin/x"},
		{"/caf%C3%A9", "/café"},
	} {
		got, err := canonicalPath(c.in)
		if err != nil || got != c.want {
			t.Errorf("canonicalPath(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{"/admin%2Fx", "/admin%2fx", "/a%5Cb", "/a\\b", "/a%00", "/a%252e", "/a%zz", "/a%2", "/a\x01b", "relative", "http://x/admin",
		// GAP-0046: a dot segment hidden behind parameters, and an encoded ';'.
		"/admin/..;/public/x", "/admin/..;x=1/public", "/admin/.;/x", "/admin/;x/y", "/admin/%2e%2e;/x", "/admin%3Bx/", "/admin%3b/"} {
		if got, err := canonicalPath(in); !errors.Is(err, errAmbiguousPath) {
			t.Errorf("canonicalPath(%q) = %q, %v; want errAmbiguousPath", in, got, err)
		}
	}
}

// TestURLAllowRuleExactGAP0046: an allow rule matches the exact case and
// every method, so a case variant or an override header falls through to
// the deny rule after it.
func TestURLAllowRuleExactGAP0046(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = []URLRuleCfg{
			{Name: "public-read", Hosts: []string{"api.example.net"}, Methods: []string{"get"}, PathPrefix: "/public/", Action: "allow"},
			{Name: "nothing-else", Hosts: []string{"api.example.net"}, PathPrefix: "/", Action: "deny"},
		}
	})
	ctx := context.Background()
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.example.net", "/public/x")); !v.Allow {
		t.Fatalf("allowed path: %+v", v)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/PUBLIC/x"},
		{"POST", "/public/x"},
	} {
		if v := h.eng.DecideHeaders(ctx, req("eng-web", c.method, "api.example.net", c.path)); v.Allow || v.Rule != "nothing-else" {
			t.Errorf("%s %s: %+v", c.method, c.path, v)
		}
	}
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.example.net", "/public/x", "x-http-method-override", "DELETE")); v.Allow || v.Rule != "nothing-else" {
		t.Errorf("GET with override DELETE: %+v", v)
	}
}

func TestPathHasPrefix(t *testing.T) {
	for _, c := range []struct {
		p, prefix string
		want      bool
	}{
		{"/admin", "/admin", true},
		{"/admin/x", "/admin", true},
		{"/administrator", "/admin", false},
		{"/admin/x", "/admin/", true},
		{"/admin", "/admin/", false},
		{"/x", "/", true},
	} {
		if got := pathHasPrefix(c.p, c.prefix); got != c.want {
			t.Errorf("pathHasPrefix(%q, %q) = %v", c.p, c.prefix, got)
		}
	}
}

// TestURLRulesCanonicalPath is GAP-0046: an equivalent spelling of a denied
// path is denied, and an ambiguous encoding is refused on a host with path
// rules but not elsewhere.
func TestURLRulesCanonicalPath(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = append([]URLRuleCfg{
			{Name: "no-admin", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "deny"},
		}, c.Profiles[0].URLRules...)
	})
	ctx := context.Background()
	for _, p := range []string{"/admin/", "/./admin/", "/%61dmin/", "//admin/x", "/x/../admin/y", "/admin;a=b/", "/%2e%2e/admin/?q=1"} {
		v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", p))
		if v.Allow || v.Category != CategoryURLRule || v.Rule != "no-admin" {
			t.Errorf("%s: %+v", p, v)
		}
	}
	for _, p := range []string{"/admin%2Fx", "/a%5Cadmin/", "/admin%252F"} {
		v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", p))
		if v.Allow || v.Category != CategoryPathAmbiguous {
			t.Errorf("%s: %+v", p, v)
		}
		// No path rule on this host: the path is not judged.
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "example.com", p)); !v.Allow {
			t.Errorf("%s on a host without path rules: %+v", p, v)
		}
	}
	// Segment boundary: /administrator is not under /admin/.
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/administrator")); !v.Allow {
		t.Errorf("/administrator: %+v", v)
	}
	// GAP-0046: '..;' is not read as '..' (refused as ambiguous, not
	// allowed as /public/x), and a deny rule ignores case.
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/admin/..;/public/x")); v.Allow || v.Category != CategoryPathAmbiguous {
		t.Errorf("/admin/..;/public/x: %+v", v)
	}
	for _, p := range []string{"/ADMIN/", "/Admin/x", "/%41DMIN/"} {
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", p)); v.Allow || v.Category != CategoryURLRule {
			t.Errorf("%s: %+v", p, v)
		}
	}
	// A method override header can't dodge a method rule.
	for _, hdr := range []string{"x-http-method-override", "x-http-method", "x-method-override"} {
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.github.com", "/admin/", hdr, "post")); v.Allow || v.Category != CategoryURLRule {
			t.Errorf("GET with %s POST: %+v", hdr, v)
		}
	}
	// A rule's own prefix is canonicalized at load; an ambiguous one fails.
	cfg, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles[0].URLRules = []URLRuleCfg{{Hosts: []string{"x.example"}, PathPrefix: "/a%2Fb", Action: "deny"}}
	if _, err := NewEngine(Options{Config: cfg}); err == nil {
		t.Error("ambiguous path_prefix accepted")
	}
}
