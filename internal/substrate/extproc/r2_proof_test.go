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

// Lane R2 proof tests: bypass variants found after the first F5 fixes, kept
// as regression tests (GAP-0044, GAP-0046, GAP-0156).

import (
	"context"
	"testing"
)

// GAP-0044 variant: the callout matches JSON-RPC keys exactly, while an MCP
// server that decodes with Go encoding/json (mark3labs/mcp-go and others)
// matches struct fields case-insensitively, last key winning.
func TestR2CaseVariantKeys(t *testing.T) {
	ctx := context.Background()
	bodies := map[string]string{
		"Method":             `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"drop_tables","arguments":{}}}`,
		"method then METHOD": `{"jsonrpc":"2.0","id":1,"method":"ping","METHOD":"tools/call","params":{"name":"drop_tables","arguments":{}}}`,
		"name then Name":     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list","Name":"drop_tables","arguments":{}}}`,
	}
	for name, b := range bodies {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = FailureClosed })
			h.judge.block = true
			r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
			r.ContentType = "application/json"
			v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, []byte(b))
			judgedDrop := false
			for _, c := range h.judge.calls {
				if c.Tool == "drop_tables" {
					judgedDrop = true
				}
			}
			if v.Allow && !judgedDrop {
				t.Errorf("allowed without judging drop_tables (judge calls %d): %+v", len(h.judge.calls), v)
			}
		})
	}
}

// GAP-0044 variant: two Content-Encoding header lines; the callout reads the
// first only, an origin that joins them (Node) decodes the gzip body.
func TestR2DuplicateContentEncoding(t *testing.T) {
	ctx := context.Background()
	secret := []byte(`{"k":"` + fakeAWSKey + `"}`)
	h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = FailureClosed })
	r := req("eng-web", "POST", "upload.example.org", "/up", "content-type", "application/octet-stream")
	r.ContentType = "application/octet-stream"
	r.Headers = append(r.Headers, Header{"content-encoding", "identity"}, Header{"content-encoding", "gzip"})
	v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, gz(t, secret))
	if v.Allow && !v.Alert {
		t.Errorf("gzip secret behind a duplicate Content-Encoding allowed silently: %+v", v)
	}
}

// GAP-0046 variant: dot segments are resolved before the deny rule, but
// raw-path origins (Node/Express routers, proxies that forward the raw
// path) route /admin/../public/x under /admin.
func TestR2DotSegmentPopsDenyPrefix(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = append([]URLRuleCfg{
			{Name: "no-admin", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "deny"},
		}, c.Profiles[0].URLRules...)
	})
	ctx := context.Background()
	for _, p := range []string{"/admin/../public/x", "/admin/%2e%2e/public/x", "/admin/.%2E/public/x"} {
		if v := h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", p)); v.Allow {
			t.Errorf("%s allowed: %+v", p, v)
		}
	}
	// _method query override (Laravel, Express method-override getter).
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.github.com", "/admin/x?_method=POST")); v.Allow {
		t.Errorf("_method=POST allowed: %+v", v)
	}
}
