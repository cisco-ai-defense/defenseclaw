// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-0998: an administrator allow by name and URL is already a decision. The
// first call of the server, while its scan has not finished, is not told to
// wait for the scan, in every tier; a wrong endpoint, another name and an
// explicit deny keep the wait or the block.
func TestAdminAllowedServerIsAdmittedWhileItsScanIsPending(t *testing.T) {
	const loopback = "http://127.0.0.1:18795/mcp"
	pending := watcher.MCPAdmissionStatus{Name: "gas", Pending: true, RetryAfter: 300 * time.Second}
	probe := mcpRuntimeProbe{ServerName: "gas", ToolName: "mcp__gas__ping", URL: loopback, Surface: "hook", Matched: true}
	for _, tc := range mcpTierCases {
		for _, rc := range []struct {
			name      string
			allowed   []config.AssetPolicyRule
			wantAllow bool
		}{
			{"name and url", []config.AssetPolicyRule{{Name: "gas", URL: loopback}}, true},
			{"name", []config.AssetPolicyRule{{Name: "gas"}}, true},
			{"no rule", nil, false},
			{"another endpoint", []config.AssetPolicyRule{{Name: "gas", URL: "http://127.0.0.1:9999/mcp"}}, false},
			{"another server", []config.AssetPolicyRule{{Name: "other", URL: loopback}}, false},
		} {
			t.Run(tc.name+"/"+rc.name, func(t *testing.T) {
				api := tc.api(rc.allowed...)
				decision, refused := api.mcpAdmissionStatusDecision(context.Background(), api.scannerCfg,
					"claudecode", "PreToolUse", probe, pending)
				if rc.wantAllow {
					if refused {
						t.Fatalf("an administrator-allowed server still got an admission decision: %+v", decision)
					}
					return
				}
				if !refused || decision.Source != "mcp-admission-pending" || decision.RetryAfterSeconds != 300 {
					t.Fatalf("decision %+v (admission decision %v), want the pending wait of the scan", decision, refused)
				}
				if want := map[bool]string{true: "block", false: "allow"}[tc.failsClosed]; decision.Action != want {
					t.Fatalf("action %q, want %q", decision.Action, want)
				}
			})
		}
	}
}

// The same through the managed hook: the first call of an allowed loopback
// server, before the scan lands, is allowed; with a rule for another endpoint
// the call is still told to wait.
func TestManagedUnixHookReportedMCPFirstCallOfAnAllowedServerDoesNotWaitForTheScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	gas := assetfacts.MCPServer{Name: "gas", URL: "http://127.0.0.1:18795/mcp"}
	pendingScan := func(h *reportedMCPHarness) {
		h.api.SetMCPAdmissionStatus(func(connector, server, home, _ string) watcher.MCPAdmissionStatus {
			if servers, _ := h.reported.list(); len(servers) > 0 {
				return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 300 * time.Second}
			}
			return watcher.MCPAdmissionStatus{}
		})
	}
	h := newReportedMCPHarness()
	pendingScan(h)
	h.allowOnly(gas)
	wantMCPAllow(t, "first call, allow by name and URL", h.callInSession(t, "s1", gas))

	h = newReportedMCPHarness()
	pendingScan(h)
	h.allowOnly(assetfacts.MCPServer{Name: "gas", URL: "http://127.0.0.1:9999/mcp"})
	resp := h.callInSession(t, "s1", gas)
	if resp.Action != "block" || !strings.Contains(resp.SourceReason, "mcp-admission-pending") {
		t.Fatalf("first call with a rule for another endpoint: action=%q reason=%q, want the pending block", resp.Action, resp.SourceReason)
	}
}
