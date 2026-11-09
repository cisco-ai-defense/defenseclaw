// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func fillReportedMCPList(t *testing.T, h *reportedMCPHarness) {
	t.Helper()
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		if !h.reported.note(config.MCPServerEntry{
			Name: fmt.Sprintf("prior-%d", i), Command: "python3", Args: []string{"/opt/old.py"},
			Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher",
		}) {
			t.Fatalf("setup: report slot %d not filled", i)
		}
	}
}

// A full store is not a verdict: when the account has used its share of the
// session store, a refused definition the next session meets is still refused
// after its config is edited to an ordinary one, and an ordinary server of
// the same account and another account are not held.
func TestManagedUnixHookReportedMCPRefusalSurvivesEditWhenSessionStoreIsFull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	entry := config.MCPServerEntry{Name: "review", Command: "python3", Args: []string{"/opt/old.py"},
		Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		if !h.reported.retainRefused("claudecode", sessionTestHome, fmt.Sprintf("prior-%d", i), sessionTestHome+"/proj", "review", entry, time.Now()) {
			t.Fatalf("setup: session slot %d not filled", i)
		}
	}
	refused := assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/old.py"}}
	ordinary := assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "s1", refused); got.Action != "block" {
		t.Fatalf("first refused call at capacity: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "s1", ordinary); got.Action != "block" {
		t.Fatalf("same name after an edit at capacity: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("another server of the account: action=%q, want allow", got.Action)
	}
	if got := h.call("/home/eng2", &ordinary); got.Action != "allow" {
		t.Errorf("the same name for another account: action=%q, want allow", got.Action)
	}
}

// The same holds when the report list of the account is full: the first call
// of the next refused server and every later one are refused, with the cause
// and the administrator step, and an administrator allow written for the
// definition does not release a name whose report could not be kept.
func TestManagedUnixHookReportedMCPFirstCallWhenReportListIsFullIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillReportedMCPList(t, h)
	server := assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/new.py"}}
	got := h.callInSession(t, "s1", server)
	if got.Action != "block" {
		t.Fatalf("first refused call with a full report list: action=%q, want block", got.Action)
	}
	if want := "asset_policy.mcp.allowed"; !strings.Contains(got.Reason, want) {
		t.Errorf("reason %q does not name the administrator step %q", got.Reason, want)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "block" {
		t.Errorf("the name after an edit with a full report list: action=%q, want block", got.Action)
	}
	h.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "review", Command: "python3", ArgsPrefix: []string{"/opt/new.py"}}}
	if got := h.callInSession(t, "s1", server); got.Action != "block" {
		t.Errorf("an allow for a definition whose report was not kept: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("an ordinary server with a full report list: action=%q, want allow", got.Action)
	}
	if got := h.call("/home/eng2", &assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/home/eng2/server.py"}}); got.Action != "block" {
		t.Errorf("another account, whose list has room, must still be refused and listed: action=%q, want block", got.Action)
	}
}

// A URL server the full report list cannot keep is not admitted by omission.
func TestManagedUnixHookReportedMCPURLServerWhenReportListIsFullIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillReportedMCPList(t, h)
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "remote", URL: "https://mcp.example.com/mcp"}); got.Action != "block" {
		t.Fatalf("URL server with a full report list: action=%q, want block", got.Action)
	}
}

// Names no store can keep are held per account in a bounded set. Past the
// bound the account is held whole, and other accounts are not.
func TestManagedUnixHookReportedMCPAccountIsHeldWhenUnkeptNamesPassTheBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillReportedMCPList(t, h)
	for i := 0; i <= hookUnkeptPerAccount; i++ {
		h.callInSession(t, "s1", assetfacts.MCPServer{Name: fmt.Sprintf("over-%d", i), Command: "python3", Args: []string{"/opt/new.py"}})
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "block" {
		t.Errorf("an unknown server of an account held whole: action=%q, want block", got.Action)
	}
	if got := h.call("/home/eng2", &assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("another account: action=%q, want allow", got.Action)
	}
}

// What was held ends with the memory time limit, and the end of the agent
// session clears the session store only.
func TestHookReportedMCPUnkeptNameExpires(t *testing.T) {
	var h hookReportedMCPServers
	now := time.Now()
	entry := config.MCPServerEntry{Name: "review", Command: "python3", Args: []string{"/opt/old.py"}, LocalRefusal: "launcher"}
	h.holdUnkept("claudecode", "/home/eng1", "review", entry, now)
	if _, ok := h.unkeptFor("claudecode", "/home/eng1", "review", now.Add(time.Minute)); !ok {
		t.Fatal("a held name was not held")
	}
	if _, ok := h.unkeptFor("claudecode", "/home/eng1", "other", now.Add(time.Minute)); ok {
		t.Error("a name nobody reported was held")
	}
	if _, ok := h.unkeptFor("claudecode", "/home/eng1", "review", now.Add(mcpResolvedTTL+time.Minute)); ok {
		t.Error("a held name outlived the memory time limit")
	}
}
