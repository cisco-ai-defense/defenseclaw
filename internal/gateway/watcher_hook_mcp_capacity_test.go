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

// With both stores full of live listed servers, the next refused definition of
// the account is refused on its own calls, with the cause, and the session
// that met it keeps it after the config is edited; no other server of the
// account, and no other account, is held for it.
func TestManagedUnixHookReportedMCPRefusalWhenEveryStoredSessionIsListed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	now := time.Now()
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		entry := config.MCPServerEntry{Name: fmt.Sprintf("srv-%d", i), Command: "python3", Args: []string{"/opt/old.py"},
			Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
		if !h.reported.note(entry) || !h.reported.retainRefused("claudecode", sessionTestHome, fmt.Sprintf("prior-%d", i), sessionTestHome+"/proj", entry.Name, entry, now) {
			t.Fatalf("setup: slot %d not filled", i)
		}
	}
	refused := assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/new.py"}}
	for call := 0; call < 2; call++ {
		got := h.callInSession(t, "s1", refused)
		if got.Action != "block" || !strings.Contains(got.Reason, "launcher") || !strings.Contains(got.Reason, "asset_policy.mcp.allowed") {
			t.Fatalf("call %d of a refused definition with both stores full of listed servers: action=%q reason=%q, want a launcher block with the administrator step", call, got.Action, got.Reason)
		}
	}
	first := h.callInSession(t, "s1", refused)
	edited := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}})
	if edited.Action != "block" || edited.Reason != first.Reason {
		t.Errorf("the same session after an edit: action=%q reason=%q, want the first cause %q", edited.Action, edited.Reason, first.Reason)
	}
	if got := h.callInSession(t, "s2", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("an ordinary server of the same name in another session: action=%q, want allow", got.Action)
	}
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("another server of the account: action=%q, want allow", got.Action)
	}
	if got := h.call("/home/eng2", &assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("another account: action=%q, want allow", got.Action)
	}
	// The agent starting again ends what the session held.
	h.startSession(t, "s1")
	if got := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("after the agent started again: action=%q, want allow", got.Action)
	}
}

// With both stores full of definitions nothing lists, the connection a session
// keeps to a refused definition keeps its cause after the server is edited
// to a URL: the edit is a new definition and decided on its own, and the old
// one is not replaced by it.
func TestManagedUnixHookReportedMCPRefusalCauseSurvivesURLEditWhenBothStoresAreFull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillReportedMCPList(t, h)
	entry := config.MCPServerEntry{Name: "review", Command: "python3", Args: []string{"/opt/server.py"},
		Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		if !h.reported.retainRefused("claudecode", sessionTestHome, fmt.Sprintf("prior-%d", i), sessionTestHome+"/proj", "review", entry, time.Now()) {
			t.Fatalf("setup: session slot %d not filled", i)
		}
	}
	first := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/server.py"}})
	if first.Action != "block" || !strings.Contains(first.Reason, "launcher") {
		t.Fatalf("first refused call: action=%q reason=%q, want a launcher block", first.Action, first.Reason)
	}
	second := h.callInSession(t, "s1", assetfacts.MCPServer{Name: "review", URL: "https://mcp.example.com/mcp"})
	if second.Action != "block" || second.Reason != first.Reason {
		t.Fatalf("same connection after a URL edit: action=%q reason=%q, want the first cause %q", second.Action, second.Reason, first.Reason)
	}
}

// A name nobody reported lately holds nothing: sessions and listed servers the
// memory time limit has passed do not count for the account, and an ordinary
// server is allowed whatever refused names the account met, in this session
// or another.
func TestManagedUnixHookReportedMCPExpiredRecordsNeverBlockAnOrdinaryServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	now := time.Now()
	stale := now.Add(-mcpResolvedTTL - time.Hour)
	live := now.Add(-2 * time.Hour)
	for i := 0; i < 33; i++ {
		entry := config.MCPServerEntry{Name: fmt.Sprintf("old-%d", i), Command: "python3", Args: []string{"/opt/old.py"},
			Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
		h.reported.noteAt(entry, stale)
		h.reported.retainRefused("claudecode", sessionTestHome, "old-session", sessionTestHome+"/proj", entry.Name, entry, stale)
	}
	liveEntry := config.MCPServerEntry{Name: "old-0", Command: "python3", Args: []string{"/opt/old.py"},
		Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
	h.reported.retainRefused("claudecode", sessionTestHome, "other-session", sessionTestHome+"/proj", "old-0", liveEntry, live)
	h.reported.holdOverflow("claudecode", sessionTestHome, "old-session", sessionTestHome+"/proj", "old-3", liveEntry, stale)
	h.reported.holdOverflow("claudecode", sessionTestHome, "other-session", sessionTestHome+"/proj", "old-0", liveEntry, live)
	ordinary := assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "old-session", assetfacts.MCPServer{Name: "old-3", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action != "allow" {
		t.Errorf("a session whose overflow hold expired: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
	if got := h.callInSession(t, "s1", ordinary); got.Action != "allow" {
		t.Errorf("ordinary server after names that expired: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
	sameName := assetfacts.MCPServer{Name: "old-1", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "s1", sameName); got.Action != "allow" {
		t.Errorf("ordinary server named like an expired one: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
	sameLive := assetfacts.MCPServer{Name: "old-0", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "s1", sameLive); got.Action != "allow" {
		t.Errorf("ordinary server named like one another session holds: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
}

// A list that has used its share gives up the servers no hook reported within
// the memory time limit before it refuses to list a new one, so a refused
// server of the account is listed and shown to the watcher.
func TestHookReportedMCPFullListGivesUpExpiredServers(t *testing.T) {
	var h hookReportedMCPServers
	now := time.Now()
	stale := now.Add(-mcpResolvedTTL - time.Hour)
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		h.noteAt(config.MCPServerEntry{Name: fmt.Sprintf("old-%d", i), URL: "https://old.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}, stale)
	}
	fresh := config.MCPServerEntry{Name: "fresh", URL: "https://mcp.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}
	if !h.noteAt(fresh, now) || !h.listedAs(fresh) {
		t.Fatal("a full list of expired servers did not give way to a new server")
	}
	if got, _ := h.list(); len(got) != 1 {
		t.Errorf("list holds %d servers after the expired ones were given up, want 1", len(got))
	}
	// Live servers are not given up.
	for i := 0; i < hookReportedMCPPerHomeLimit-1; i++ {
		h.noteAt(config.MCPServerEntry{Name: fmt.Sprintf("live-%d", i), URL: "https://live.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}, now)
	}
	extra := config.MCPServerEntry{Name: "extra", URL: "https://mcp.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}
	if h.noteAt(extra, now) || h.listedAs(extra) {
		t.Error("a list of live servers listed a server beyond the share of the account")
	}
	if !h.listedAs(fresh) {
		t.Error("a live server was given up")
	}
}

func fillRefusedSessions(t *testing.T, h *reportedMCPHarness) {
	t.Helper()
	entry := config.MCPServerEntry{Name: "filler", Command: "python3", Args: []string{"/opt/old.py"},
		Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		if !h.reported.retainRefused("claudecode", sessionTestHome, fmt.Sprintf("prior-%d", i), sessionTestHome+"/proj", "filler", entry, time.Now()) {
			t.Fatalf("setup: session slot %d not filled", i)
		}
	}
}

// Once the session store is full, each session it could not track is held by
// its own identity: any number of other refused sessions, and the end of one of
// them, neither block an ordinary server of another session nor release the
// refusal an earlier session holds.
func TestManagedUnixHookReportedMCPOverflowHoldsAreKeptByFullIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillRefusedSessions(t, h)
	refused := assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/old.py"}}
	if got := h.callInSession(t, "held-session", refused); got.Action != "block" {
		t.Fatalf("first refused call at capacity: action=%q, want block", got.Action)
	}
	const peers = 3000
	for i := 0; i < peers; i++ {
		other := assetfacts.MCPServer{Name: fmt.Sprintf("other-%d", i), Command: "python3", Args: []string{"/opt/other.py"}}
		if got := h.callInSession(t, fmt.Sprintf("peer-%d", i), other); got.Action != "block" {
			t.Fatalf("refused call of peer %d: action=%q, want block", i, got.Action)
		}
	}
	ordinary := assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}
	for i := 0; i < peers; i++ {
		if got := h.callInSession(t, fmt.Sprintf("calm-%d", i), ordinary); got.Action != "allow" {
			t.Fatalf("ordinary server of session calm-%d beside %d held sessions: action=%q reason=%q, want allow", i, peers, got.Action, got.Reason)
		}
	}
	for i := 0; i < peers; i += 7 {
		h.startSession(t, fmt.Sprintf("peer-%d", i))
	}
	edited := assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "held-session", edited); got.Action != "block" {
		t.Errorf("the first session after other sessions started again: action=%q reason=%q, want its hold kept", got.Action, got.Reason)
	}
	h.startSession(t, "held-session")
	if got := h.callInSession(t, "held-session", edited); got.Action != "allow" {
		t.Errorf("after its own agent started again: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
}

// A session the session store was full for keeps the cause of the definition
// it met first when the same name is reported again with another refused
// definition: the edit is a new definition and does not replace the old one.
func TestManagedUnixHookReportedMCPOverflowKeepsFirstCauseAcrossRefusedEdit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillRefusedSessions(t, h)
	first := h.callInSession(t, "held-session", assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/old.py"}})
	if first.Action != "block" || !strings.Contains(first.Reason, "launcher") {
		t.Fatalf("first refused call: action=%q reason=%q, want a launcher block", first.Action, first.Reason)
	}
	second := h.callInSession(t, "held-session", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-c", "pwd"}})
	if second.Action != "block" || second.Reason != first.Reason {
		t.Fatalf("after a second refused definition: action=%q reason=%q, want the first cause %q", second.Action, second.Reason, first.Reason)
	}
	third := h.callInSession(t, "held-session", assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}})
	if third.Action != "block" || third.Reason != first.Reason {
		t.Errorf("after an ordinary edit: action=%q reason=%q, want the first cause %q", third.Action, third.Reason, first.Reason)
	}
}

// The overflow store is bounded per account. A store of live holds does not
// release any of them and does not hold the next session, whose own calls are
// decided as a failed admission; the holds that expired are given up first.
func TestManagedUnixHookReportedMCPOverflowStoreBoundGivesUpExpiredHoldsFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	fillRefusedSessions(t, h)
	entry := config.MCPServerEntry{Name: "review", Command: "python3", Args: []string{"/opt/old.py"},
		Connector: "claudecode", Home: sessionTestHome, LocalRefusal: "launcher"}
	now := time.Now()
	stale := now.Add(-mcpResolvedTTL - time.Hour)
	for i := 0; i < hookOverflowPerAccount; i++ {
		at := now
		if i%2 == 1 {
			at = stale
		}
		h.reported.holdOverflow("claudecode", sessionTestHome, fmt.Sprintf("bulk-%d", i), sessionTestHome+"/proj", "review", entry, at)
	}
	refused := assetfacts.MCPServer{Name: "review", Command: "python3", Args: []string{"/opt/new.py"}}
	edited := assetfacts.MCPServer{Name: "review", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "late", refused); got.Action != "block" {
		t.Fatalf("refused call beside a store with expired holds: action=%q, want block", got.Action)
	}
	if got := h.callInSession(t, "late", edited); got.Action != "block" {
		t.Errorf("the session after an edit, once the expired holds gave way: action=%q reason=%q, want its hold kept", got.Action, got.Reason)
	}
	if _, ok := h.reported.overflowHeld("claudecode", sessionTestHome, "bulk-0", sessionTestHome+"/proj", "review", now); !ok {
		t.Error("a live hold was given up")
	}
	for i := 0; i < hookOverflowPerAccount; i++ {
		h.reported.holdOverflow("claudecode", sessionTestHome, fmt.Sprintf("more-%d", i), sessionTestHome+"/proj", "review", entry, now)
	}
	if got := h.callInSession(t, "latest", refused); got.Action != "block" || !strings.Contains(got.Reason, "launcher") {
		t.Errorf("refused call beside a store of live holds: action=%q reason=%q, want a launcher block", got.Action, got.Reason)
	}
	ordinary := assetfacts.MCPServer{Name: "fine", Command: "npx", Args: []string{"-y", "pkg"}}
	if got := h.callInSession(t, "latest", ordinary); got.Action != "allow" {
		t.Errorf("ordinary server beside a store of live holds: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
	if got := h.call("/home/eng2", &ordinary); got.Action != "allow" {
		t.Errorf("another account: action=%q reason=%q, want allow", got.Action, got.Reason)
	}
}
