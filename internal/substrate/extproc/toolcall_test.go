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

// TestToolCallContextGAP0015: the verdict route gets the URL (no query),
// the MCP session and the request id, so URL-keyed MCP asset rules match
// and the verdict ties to the callout's event.
func TestToolCallContextGAP0015(t *testing.T) {
	h := newHarness(t, nil)
	r := req("eng-web", "POST", "mcp.example.com", "/mcp?token=x", "content-type", "application/json", "mcp-session-id", "sess-42")
	r.Scheme = "https"
	r.ID = "req-1"
	v := h.eng.DecideBody(context.Background(), r, Verdict{Allow: true, Profile: "eng"}, mcpCall("list"))
	if !v.Allow || len(h.judge.calls) != 1 {
		t.Fatalf("verdict %+v, calls %d", v, len(h.judge.calls))
	}
	c := h.judge.calls[0]
	if c.URL != "https://mcp.example.com/mcp" || c.SessionID != "sess-42" || c.RequestID != "req-1" || c.Server != "tickets" {
		t.Fatalf("tool call %+v", c)
	}
	if id := newRequestID(); len(id) != 16 || id == newRequestID() {
		t.Fatalf("request id %q", id)
	}
}

// TestToolCallNoRulePathGAP0015: with the verdict route turned off a
// tools/call is never a silent allow: an alert on OSS, refused on a
// managed install.
func TestToolCallNoRulePathGAP0015(t *testing.T) {
	ctx := context.Background()
	r := req("eng-web", "POST", "mcp.example.com", "/mcp", "content-type", "application/json")
	h := newHarness(t, func(_ *Config, o *Options) { o.Judge = nil })
	if v := h.eng.DecideBody(ctx, r, Verdict{Allow: true}, mcpCall("list")); !v.Allow || !v.Alert || len(v.Findings) != 1 || v.Findings[0] != "tool_rules_not_configured" {
		t.Fatalf("oss: %+v", v)
	}
	hm := newHarness(t, func(c *Config, o *Options) { c.Managed = true; o.Judge = nil })
	if v := hm.eng.DecideBody(ctx, r, Verdict{Allow: true}, mcpCall("list")); v.Allow || v.Category != CategoryMCPToolBlocked || v.Rule != "tool_rules_not_configured" {
		t.Fatalf("managed: %+v", v)
	}
	// A body with no tools/call needs no rules.
	if v := hm.eng.DecideBody(ctx, r, Verdict{Allow: true}, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); !v.Allow || v.Alert {
		t.Fatalf("tools/list: %+v", v)
	}
}
