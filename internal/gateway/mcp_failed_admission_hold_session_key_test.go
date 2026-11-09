// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// callIn sends the hook of session for server with cwd as the working
// directory, which the hook protocol allows to be empty.
func (f *sessionHoldFixture) callIn(cwd, session, server string) claudeCodeHookResponse {
	f.t.Helper()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: f.home})
	return f.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		SessionID: session, HookEventName: "PreToolUse", ToolName: "mcp__" + server + "__count_words",
		ToolInput: map[string]interface{}{}, CWD: cwd,
	})
}

// The agent holds one connection per server name for the whole session, so
// the failed admission of a local-scope entry is found by every later hook of
// that session: one that leaves the working directory out, and one that
// reports another folder. Another session and another server are not held.
func TestFailedMCPAdmissionHoldOfALocalScopeIsFoundWhateverDirectoryALaterHookReports(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			f := newSessionHoldFixture(t, tc.pack)
			elsewhere := t.TempDir()
			f.list(sessionHoldListed)
			f.wantFailed("listed local", tc.action, f.call("s1", "wiki-ok"))
			f.list(sessionHoldRemoved)
			f.wantFailed("removed, no working directory", tc.action, f.callIn("", "s1", "wiki-ok"))
			f.wantFailed("removed, another folder", tc.action, f.callIn(elsewhere, "s1", "wiki-ok"))
			f.wantFailed("removed, its own folder", tc.action, f.callIn(f.project, "s1", "wiki-ok"))

			f.wantOrdinary("another session, no working directory", f.callIn("", "s2", "wiki-ok"))
			f.wantOrdinary("another server, no working directory", f.callIn("", "s1", "wiki-fine"))
			f.wantOrdinary("another account, no working directory", func() claudeCodeHookResponse {
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: t.TempDir()})
				return f.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					SessionID: "s1", HookEventName: "PreToolUse", ToolName: "mcp__wiki-ok__count_words",
					ToolInput: map[string]interface{}{},
				})
			}())
		})
	}
}

// The clean admission of the failed definition in its own scope still ends the
// hold, whatever directory the hook that sees it reports.
func TestFailedMCPAdmissionHoldOfALocalScopeIsReleasedByItsOwnCleanAdmission(t *testing.T) {
	f := newSessionHoldFixture(t, "strict")
	f.list(sessionHoldListed)
	f.wantFailed("listed local", "block", f.call("s1", "wiki-ok"))
	f.failed = false
	f.wantOrdinary("listed again, admitted", f.call("s1", "wiki-ok"))
	f.list(sessionHoldRemoved)
	f.wantOrdinary("removed after it was admitted, no working directory", f.callIn("", "s1", "wiki-ok"))
}

// overflowFixture is a strict per-user gateway whose watcher fails every
// definition of wiki-ok while failed is set; a definition is its URL.
func overflowFixture(t *testing.T, pack string) (f *scopeHoldFixture, failed *bool, url func(int) string) {
	f = newScopeHoldFixture(t, pack)
	failed = new(bool)
	*failed = true
	f.status = func(name string) watcher.MCPAdmissionStatus {
		if *failed && name == "wiki-ok" {
			return watcher.MCPAdmissionStatus{Name: name, Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
		}
		return watcher.MCPAdmissionStatus{}
	}
	return f, failed, func(i int) string { return fmt.Sprintf("http://localhost:27103/mcp?version=%d", i) }
}

// A session that met more failed definitions of a name than the hold keeps is
// marked, and the marker outlives the release of every definition it did keep:
// the strict tier blocks the name once the config no longer lists it, the
// default tier warns, and a definition listed and admitted clean in the
// session is allowed.
func TestFailedMCPAdmissionOverflowMarkerLastsAfterTheKeptDefinitionsAreReleased(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			f, failed, url := overflowFixture(t, tc.pack)
			for i := 0; i < hookRefusedPerName+1; i++ {
				f.listUser(scopeHoldServer(url(i), ""))
				wantHeldFailed(t, fmt.Sprintf("failed definition %d", i), tc.action, f.call(f.cwd, "s1", "wiki-ok"))
			}
			held, overflow := f.api.hookMCP.heldFailures("claudecode", f.home, "s1", "wiki-ok", heldScopes(f.cwd), time.Now())
			if len(held) != hookRefusedPerName || !overflow {
				t.Fatalf("held=%d overflow=%t, want %d and true", len(held), overflow, hookRefusedPerName)
			}
			*failed = false
			for i := 0; i < hookRefusedPerName; i++ {
				f.listUser(scopeHoldServer(url(i), ""))
				// Each call releases the definition it lists; the others stay held.
				f.call(f.cwd, "s1", "wiki-ok")
			}
			f.listUser(`{}`)
			wantHeldFailed(t, "removed, kept ones released", tc.action, f.call(f.cwd, "s1", "wiki-ok"))
			wantHeldFailed(t, "removed, no working directory", tc.action, f.call("", "s1", "wiki-ok"))
			wantHeldFailed(t, "removed, another folder", tc.action, f.call(t.TempDir(), "s1", "wiki-ok"))

			// Benign twins: a definition listed and admitted clean, another
			// session, another server.
			f.listUser(scopeHoldServer(scopeHoldCleanURL, ""))
			wantHeldOrdinary(t, "fresh clean definition listed", f.call(f.cwd, "s1", "wiki-ok"))
			f.listUser(`{}`)
			wantHeldOrdinary(t, "another session", f.call(f.cwd, "s2", "wiki-ok"))
			wantHeldOrdinary(t, "another server", f.call(f.cwd, "s1", "wiki-fine"))
		})
	}
}

// The same when the session store is full and the session is held in the
// overflow store, which keeps the first definition only: the admission of that
// definition does not release a session that met another one it could not keep.
func TestFailedMCPAdmissionOverflowStoreKeepsASessionThatMetAnotherDefinition(t *testing.T) {
	f, failed, url := overflowFixture(t, "strict")
	filler := config.MCPServerEntry{Name: "filler", URL: scopeHoldCleanURL}
	for i := 0; i < hookReportedMCPPerHomeLimit; i++ {
		if !f.api.hookMCP.retainRefused("claudecode", f.home, fmt.Sprintf("prior-%d", i), "", "filler", filler, time.Now()) {
			t.Fatalf("setup: session slot %d not filled", i)
		}
	}
	for i := 0; i < 2; i++ {
		f.listUser(scopeHoldServer(url(i), ""))
		wantHeldFailed(t, "failed definition", "block", f.call(f.cwd, "s1", "wiki-ok"))
	}
	*failed = false
	f.listUser(scopeHoldServer(url(0), ""))
	wantHeldOrdinary(t, "first definition listed clean", f.call(f.cwd, "s1", "wiki-ok"))
	f.listUser(`{}`)
	wantHeldFailed(t, "removed, the other definition was not kept", "block", f.call(f.cwd, "s1", "wiki-ok"))
	wantHeldOrdinary(t, "another session", f.call(f.cwd, "s2", "wiki-ok"))
}
