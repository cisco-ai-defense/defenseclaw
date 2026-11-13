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
	"strings"
	"testing"
)

// TestMethodOverrideClassGAP0046 (r3a): every override is each of its
// values; a form POST that a method-scoped rule would refuse under its
// body's _method is decided on the body, and where the body can't be read
// it follows the failure mode. Normal form POSTs pass.
func TestMethodOverrideClassGAP0046(t *testing.T) {
	ctx := context.Background()
	form := func(body string) (*Request, []byte) {
		r := req("eng-web", "POST", "api.github.com", "/repos/acme/web", "content-type", "application/x-www-form-urlencoded")
		r.ContentType, r.ContentLength, r.EndOfStream = "application/x-www-form-urlencoded", int64(len(body)), false
		return r, []byte(body)
	}
	h := newHarness(t, nil)
	for _, body := range []string{"_method=DELETE", "a=1&_method=delete", "_METHOD=DELETE", "%5Fmethod=DELETE", "_method=GET%2CDELETE", "x=%zz&_method=DELETE"} {
		r, b := form(body)
		v := h.eng.DecideHeaders(ctx, r)
		if !v.Allow || !v.WantBody {
			t.Fatalf("%s: headers %+v", body, v)
		}
		if v = h.eng.DecideBody(ctx, r, v, b); v.Allow || v.Category != CategoryURLRule {
			t.Errorf("%s: %+v", body, v)
		}
	}
	// A plain form POST, or one overriding to a method nothing refuses, passes.
	for _, body := range []string{"title=hello", "_method=PATCH"} {
		r, b := form(body)
		v := h.eng.DecideHeaders(ctx, r)
		if v = h.eng.DecideBody(ctx, r, v, b); !v.Allow {
			t.Errorf("%s refused: %+v", body, v)
		}
	}
	// No method-scoped rule could apply: the body is not asked for.
	r, _ := form("_method=DELETE")
	r.Host, r.Authority, r.Path = "example.com", "example.com", "/x"
	if v := h.eng.DecideHeaders(ctx, r); !v.Allow || v.WantBody {
		t.Errorf("unrelated host: %+v", v)
	}
	// A form body the callout can't read: closed refuses, open alerts.
	for _, mode := range []string{FailureClosed, FailureOpen} {
		hm := newHarness(t, func(c *Config, _ *Options) { c.FailureMode = mode; c.BodyInspection = BodyOff })
		r, _ := form("_method=DELETE")
		v := hm.eng.DecideHeaders(ctx, r)
		switch mode {
		case FailureClosed:
			if v.Allow || v.Category != CategoryBodyUninspected || v.Rule != "method_override" {
				t.Errorf("closed, body off: %+v", v)
			}
		case FailureOpen:
			if !v.Allow || !v.Alert || !strings.Contains(strings.Join(v.Findings, ","), "method_override_unchecked") {
				t.Errorf("open, body off: %+v", v)
			}
		}
	}
	// multipart is never buffered (D9): the failure mode decides.
	r = req("eng-web", "POST", "api.github.com", "/repos/acme/web", "content-type", "multipart/form-data; boundary=x")
	r.ContentType, r.EndOfStream = "multipart/form-data; boundary=x", false
	if v := h.eng.DecideHeaders(ctx, r); v.Allow {
		t.Errorf("multipart form, closed: %+v", v)
	}
	// Header and query lists count value by value.
	for _, hv := range []string{"GET, DELETE", "DELETE,GET"} {
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/repos/acme/web", "x-http-method-override", hv)); v.Allow {
			t.Errorf("override header %q: %+v", hv, v)
		}
	}
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.github.com", "/repos/acme/web?_method=GET,DELETE")); v.Allow {
		t.Errorf("_method list in the query: %+v", v)
	}
}

// TestURLRuleAskCarriesTheRuleGAP0177: an url rule ask names its rule and
// path on the AskSink, and a host ask its pattern; two unnamed rules on a
// host get different names.
func TestURLRuleAskCarriesTheRuleGAP0177(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = append(c.Profiles[0].URLRules,
			URLRuleCfg{Hosts: []string{"uploads.example.org"}, Methods: []string{"PUT"}, PathPrefix: "/a/", Action: "ask"},
			URLRuleCfg{Hosts: []string{"uploads.example.org"}, Methods: []string{"PUT"}, PathPrefix: "/b/", Action: "ask"})
	})
	h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/repos/acme/releases/1"))
	h.eng.DecideHeaders(ctx, req("eng-web", "PUT", "uploads.example.org", "/a/x"))
	h.eng.DecideHeaders(ctx, req("eng-web", "PUT", "uploads.example.org", "/b/x"))
	h.eng.DecideHeaders(ctx, req("eng-web", "GET", "files.example.io", "/"))
	if len(h.asks.got) != 4 {
		t.Fatalf("asks %+v", h.asks.got)
	}
	if g := h.asks.got[0]; g.Rule != "url_rules:ask-release" || g.Path != "/repos/acme/releases" {
		t.Errorf("url rule ask %+v", g)
	}
	if h.asks.got[1].Rule == h.asks.got[2].Rule || h.asks.got[1].Path != "/a/" {
		t.Errorf("unnamed rules share a name: %+v %+v", h.asks.got[1], h.asks.got[2])
	}
	if g := h.asks.got[3]; g.Rule != "ask_hosts:files.example.io" || g.Path != "" {
		t.Errorf("host ask %+v", g)
	}
}
