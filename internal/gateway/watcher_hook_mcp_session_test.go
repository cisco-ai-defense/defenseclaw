// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

const sessionTestHome = "/home/eng1"

func sessionTestContext(t *testing.T, server assetfacts.MCPServer) context.Context {
	t.Helper()
	facts, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{MCP: &server}))
	if !ok || facts.MCP == nil {
		t.Fatal("the hook facts lost the server")
	}
	return context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: sessionTestHome}),
		claimedAssetFactsContextKey{}, facts)
}

// callInSession is a tool call of the server in one agent session, with the
// definition the hook of that call read, as the standalone hook sends it.
func (h *reportedMCPHarness) callInSession(t *testing.T, session string, server assetfacts.MCPServer) claudeCodeHookResponse {
	t.Helper()
	return h.api.evaluateClaudeCodeHook(sessionTestContext(t, server), claudeCodeHookRequest{
		SessionID: session, HookEventName: "PreToolUse", ToolName: "mcp__" + server.Name + "__ping",
		ToolInput: map[string]interface{}{}, CWD: sessionTestHome + "/proj",
	})
}

func (h *reportedMCPHarness) startSession(t *testing.T, session string) {
	t.Helper()
	h.api.mcpSessionStarted(sessionTestContext(t, assetfacts.MCPServer{Name: "none", Command: "npx", Args: []string{"-y", "pkg"}}), "claudecode", session, "SessionStart", "startup")
}

func paddedArgs(head []string, n int, pad string) []string {
	args := append([]string(nil), head...)
	for len(args) < n {
		args = append(args, pad)
	}
	return args
}

// A definition the scanner refuses stays refused for the agent session that
// met it. The agent keeps its connection after the config is edited, so the
// edited definition (the prefix of a longer refused one, which an
// administrator may have allowed exactly, or an ordinary package) does not
// release the later calls of that session. A session that starts again
// connects to what the config lists now, and another session never held the
// refused definition.
func TestManagedUnixHookReportedMCPRefusedDefinitionStaysRefusedForTheRunningSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	longRefused := func(head []string) assetfacts.MCPServer {
		args := paddedArgs(head, 32, "--quiet")
		return assetfacts.MCPServer{Name: "review", Command: "npx", Args: append(args, "--eval=different")}
	}
	prefix := func(head []string) assetfacts.MCPServer {
		return assetfacts.MCPServer{Name: "review", Command: "npx", Args: paddedArgs(head, 32, "--quiet")}
	}
	cases := []struct {
		name  string
		head  []string
		allow bool
	}{
		{"prefix an administrator allowed exactly", []string{"-c", "approved"}, true},
		{"ordinary package prefix", []string{"-y", "pkg"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.issue = watcher.MCPScanIssueArguments
			if tc.allow {
				h.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{
					Name: "review", Command: "npx", ArgsPrefix: paddedArgs(tc.head, 32, "--quiet"),
				}}
			}
			if got := h.callInSession(t, "s1", longRefused(tc.head)); got.Action != "block" {
				t.Fatalf("the refused 33-argument definition: action=%q, want block", got.Action)
			}
			if got := h.callInSession(t, "s1", prefix(tc.head)); got.Action != "block" {
				t.Errorf("the edited prefix in the session that met the refused definition: action=%q, want block", got.Action)
			}
			if got := h.callInSession(t, "s1", prefix(tc.head)); got.Action != "block" {
				t.Errorf("a later call in the same session: action=%q, want block", got.Action)
			}
			// Benign twin: another session never held the refused definition.
			if got := h.callInSession(t, "s2", prefix(tc.head)); got.Action != "allow" {
				t.Errorf("another session with the ordinary definition: action=%q, want allow", got.Action)
			}
			// The agent of the first session starts again: it connects to the
			// definition the config lists now.
			h.startSession(t, "s1")
			if got := h.callInSession(t, "s1", prefix(tc.head)); got.Action != "allow" {
				t.Errorf("after the session restarted: action=%q, want allow", got.Action)
			}
		})
	}
}

// An administrator who allowed every refused definition a session met does
// not have its calls held by the earlier one.
func TestManagedUnixHookReportedMCPAllowedRefusedDefinitionsStayAllowedAfterAnEdit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	h.issue = watcher.MCPScanIssueLauncher
	h.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "py", Command: "python3", ArgsPrefix: []string{"/opt/a.py"}},
		{Name: "py", Command: "python3", ArgsPrefix: []string{"/opt/b.py"}}}
	for _, script := range []string{"/opt/a.py", "/opt/b.py", "/opt/a.py"} {
		server := assetfacts.MCPServer{Name: "py", Command: "python3", Args: []string{script}}
		if got := h.callInSession(t, "s1", server); got.Action != "allow" {
			t.Fatalf("allowed refused definition %s: action=%q, want allow", script, got.Action)
		}
	}
	// A refused definition the administrator did not allow joins the session.
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "py", Command: "python3", Args: []string{"/opt/c.py"}}); got.Action != "block" {
		t.Fatalf("refused definition without an allow: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "py", Command: "python3", Args: []string{"/opt/a.py"}}); got.Action != "block" {
		t.Errorf("the allowed definition after the session met one without an allow: action=%q, want block", got.Action)
	}
}

// A session that met more refused definitions of one name than it can keep is
// not released by an allow either.
func TestManagedUnixHookReportedMCPSessionThatMetTooManyRefusedDefinitionsStaysHeld(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	h.issue = watcher.MCPScanIssueLauncher
	h.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "py", Command: "python3", ArgsPrefix: []string{"/opt/a.py"}}}
	for i := 0; i <= hookRefusedPerName; i++ {
		h.callInSession(t, "s1", assetfacts.MCPServer{Name: "py", Command: "python3", Args: []string{fmt.Sprintf("/opt/other%d.py", i)}})
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "py", Command: "python3", Args: []string{"/opt/a.py"}}); got.Action != "block" {
		t.Errorf("allowed definition after the session met too many refused ones: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("an ordinary server of the same session: action=%q, want allow", got.Action)
	}
}
