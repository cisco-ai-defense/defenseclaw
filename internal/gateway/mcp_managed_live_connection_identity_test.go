// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// The agent keeps the connection to a refused definition for as long as its
// process lives, and the hook names the server, not the connection. On a
// managed Linux or macOS gateway the connection is therefore held by the
// session and the server name, whatever directory a later hook reports or
// leaves out: the allow of a replacement never speaks for the revoked live
// definition (GAP-0925, GAP-0998).

func skipManagedWindowsMCPHold(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows keeps its own admission path")
	}
}

func managedHoldCall(t *testing.T, h *reportedMCPHarness, session, cwd string, server assetfacts.MCPServer) claudeCodeHookResponse {
	t.Helper()
	return h.api.evaluateClaudeCodeHook(sessionTestContext(t, server), claudeCodeHookRequest{
		SessionID: session, HookEventName: "PreToolUse", ToolName: "mcp__" + server.Name + "__ping",
		ToolInput: map[string]interface{}{}, CWD: cwd,
	})
}

func TestManagedLiveConnectionIsHeldWhateverDirectoryALaterHookReports(t *testing.T) {
	skipManagedWindowsMCPHold(t)
	a := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py"}}
	b := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py", "--v2"}}
	other := assetfacts.MCPServer{Name: "wiki", Command: "python3", Args: []string{"/opt/wiki.py"}}
	for _, laterCWD := range []string{sessionTestHome + "/proj", sessionTestHome + "/other", sessionTestHome + "/proj/sub", "/", ""} {
		t.Run("later CWD="+laterCWD, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.watcherLikeStatus()
			h.allowOnly(a, other)
			wantMCPAllow(t, "A allowed in the first directory", managedHoldCall(t, h, "s1", sessionTestHome+"/proj", a))
			h.allowOnly(b, other)
			wantMCPBlock(t, "the live connection is the revoked A", managedHoldCall(t, h, "s1", laterCWD, b))
			// Benign twins: another session and another server are their own.
			wantMCPAllow(t, "a separate session runs B", managedHoldCall(t, h, "s2", laterCWD, b))
			wantMCPAllow(t, "another server of the session is not held", managedHoldCall(t, h, "s1", laterCWD, other))
			// The agent starting again ends the hold.
			h.startSession(t, "s1")
			wantMCPAllow(t, "B after the agent started again", managedHoldCall(t, h, "s1", laterCWD, b))
		})
	}
}

func TestManagedLiveConnectionOfAScannerRefusedURLIsHeld(t *testing.T) {
	skipManagedWindowsMCPHold(t)
	b := assetfacts.MCPServer{Name: "vgr", URL: "http://127.0.0.1:18796/mcp"}
	for _, urlA := range []string{
		"http://127.0.0.1:18795/mcp",
		"http://ip6-localhost:18795/mcp",
		"http://ip6-loopback:18795/mcp",
		"http://LocalHost:18795/mcp",
		"http://tools.localhost:18795/mcp",
		"http://metadata.google.internal/mcp",
		"http://169.254.169.254/mcp",
		"https://user:pass@mcp.example.test/mcp",
		"https://user@mcp.example.test/mcp",
	} {
		t.Run(urlA, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.watcherLikeStatus()
			a := assetfacts.MCPServer{Name: "vgr", URL: urlA}
			h.allowOnly(a)
			wantMCPAllow(t, "A allowed", h.callInSession(t, "s1", a))
			h.allowOnly(b)
			wantMCPBlock(t, "the live connection is the revoked A", h.callInSession(t, "s1", b))
			wantMCPAllow(t, "a separate session runs B", h.callInSession(t, "s2", b))
		})
	}
}

func TestManagedLiveConnectionOfAnOrdinaryURLIsNotHeld(t *testing.T) {
	skipManagedWindowsMCPHold(t)
	a := assetfacts.MCPServer{Name: "vgr", URL: "https://mcp.example.test/a"}
	b := assetfacts.MCPServer{Name: "vgr", URL: "https://mcp.example.test/b"}
	h := newReportedMCPHarness()
	h.watcherLikeStatus()
	h.allowOnly(a)
	wantMCPAllow(t, "A allowed", h.callInSession(t, "s1", a))
	h.allowOnly(b)
	wantMCPAllow(t, "B allowed, A was never refused", h.callInSession(t, "s1", b))
}

func TestManagedPendingExactAllowHonoursTheHeldDefinitionInEveryDirectory(t *testing.T) {
	skipManagedWindowsMCPHold(t)
	a := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py"}}
	b := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py", "--v2"}}
	pendingB := func(h *reportedMCPHarness) {
		h.api.SetMCPAdmissionStatus(func(connector, server, home, _ string) watcher.MCPAdmissionStatus {
			entries, _ := h.reported.list()
			for _, entry := range entries {
				if entry.Connector != connector || entry.Name != server || entry.Home != home {
					continue
				}
				if len(entry.Args) == len(a.Args) {
					return watcher.MCPAdmissionStatus{Name: server}
				}
				return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 300 * time.Second}
			}
			return watcher.MCPAdmissionStatus{}
		})
	}
	for _, laterCWD := range []string{sessionTestHome + "/proj", sessionTestHome + "/other", ""} {
		t.Run("later CWD="+laterCWD, func(t *testing.T) {
			h := newReportedMCPHarness()
			pendingB(h)
			h.allowOnly(a)
			if got := managedHoldCall(t, h, "s1", sessionTestHome+"/proj", a); got.Action != "allow" {
				t.Fatalf("A allowed: %+v", got)
			}
			h.allowOnly(b)
			if got := managedHoldCall(t, h, "s1", laterCWD, b); got.Action != "block" {
				t.Fatalf("pending B allowed while the live connection is the revoked A: action=%q reason=%q", got.Action, got.SourceReason)
			}
		})
	}
	// Benign twin: with nothing held, the exact allow decides a pending
	// definition at its first call.
	h := newReportedMCPHarness()
	pendingB(h)
	h.allowOnly(b)
	if got := managedHoldCall(t, h, "s1", sessionTestHome+"/other", b); got.Action != "allow" {
		t.Fatalf("pending B with an exact allow and nothing held: action=%q reason=%q", got.Action, got.SourceReason)
	}
}
