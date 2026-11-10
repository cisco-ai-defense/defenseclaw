// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

const (
	firstDefinitionURL       = "https://first.example.test/mcp"
	replacementDefinitionURL = "https://second.example.test/mcp"
)

func serverAt(url string) string {
	return `{"wiki":{"type":"http","url":"` + url + `"}}`
}

// An allow admitted definition A and a session called it. The entry is then
// replaced by B, which is refused, and an administrator allows exactly B. The
// session that called A keeps the connection to A, so its calls stay refused;
// a session that starts after the allow connects to B and is admitted by the
// allow at once, in every tier. Before the fix the earlier refusal stood for
// the new sessions of the folder until the gateway restarted (GAP-1016).
func TestExactAllowOfTheReplacementAdmitsNewSessionsButNotTheSessionThatCalledTheEarlierDefinition(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			f := newSessionHoldFixture(t, tc.pack)
			f.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "wiki", URL: firstDefinitionURL}}
			status := watcher.MCPAdmissionStatus{}
			f.api.SetMCPAdmissionStatus(func(_, _, _, _ string) watcher.MCPAdmissionStatus { return status })

			f.list(serverAt(firstDefinitionURL))
			f.wantOrdinary("A, called by the old session", f.call("old", "wiki"))

			// The entry is replaced by B, which the scanner refuses, and the
			// allow of A is replaced by none.
			f.list(serverAt(replacementDefinitionURL))
			f.api.scannerCfg.AssetPolicy.MCP.Allowed = nil
			departed := time.Now()
			refused := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
			status = watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, Revoked: true, ScanIssue: watcher.MCPScanIssueAddress,
				Departed: departed, Listed: &refused}
			f.wantFailed("B refused, old session", tc.action, f.call("old", "wiki"))
			f.wantFailed("B refused, new session (the refusal of B is its own)", tc.action, f.call("new0", "wiki"))

			// The exact allow of B.
			time.Sleep(20 * time.Millisecond)
			f.api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "wiki", URL: replacementDefinitionURL}}
			status = watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, Revoked: true, ScanIssue: watcher.MCPScanIssueAddress,
				Departed: departed, Listed: &watcher.MCPAdmissionStatus{}}
			f.wantFailed("B allowed, the session that called A", tc.action, f.call("old", "wiki"))
			f.wantOrdinary("B allowed, a new session", f.call("new1", "wiki"))
			f.wantOrdinary("B allowed, another new session", f.call("new2", "wiki"))
			f.wantFailed("B allowed, the session that called A, later", tc.action, f.call("old", "wiki"))
			// Benign twin: the session that started with B and called it is
			// not held for A.
			f.wantOrdinary("B allowed, the new session again", f.call("new1", "wiki"))
		})
	}
}

// A session is judged by the revoked status unless the gateway knows it
// started after the earlier definition left: a session it has not heard from,
// or one that started before, keeps it, and a start or a resume is a new
// process while a later hook of the same session is not.
func TestRevokedStatusNarrowsToTheSessionsThatStartedAfterTheDeparture(t *testing.T) {
	api := &APIServer{hookMCP: &hookReportedMCPServers{}}
	departed := time.Now()
	listed := watcher.MCPAdmissionStatus{Name: "wiki"}
	revoked := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, Revoked: true, Departed: departed, Listed: &listed}
	probe := func(session string) mcpRuntimeProbe {
		return mcpRuntimeProbe{ServerName: "wiki", SessionID: session, Surface: "hook", Matched: true}
	}
	ctx := context.Background()
	hook := time.Now().Add(time.Minute) // after the departure
	api.hookMCP.noteSession("claudecode", "", "late", false, hook)
	api.hookMCP.noteSession("claudecode", "", "early", false, departed.Add(-time.Hour))
	// A later hook of a known session does not move its start.
	api.hookMCP.noteSession("claudecode", "", "early", false, hook)
	api.hookMCP.noteSession("claudecode", "", "resumed", false, departed.Add(-time.Hour))
	api.hookMCP.noteSession("claudecode", "", "resumed", true, hook)

	for session, wantNarrowed := range map[string]bool{"late": true, "resumed": true, "early": false, "unknown": false, "": false} {
		got := api.statusForSession(ctx, "claudecode", probe(session), revoked)
		if narrowed := !got.Revoked; narrowed != wantNarrowed {
			t.Errorf("session %q: status %+v, narrowed to the listed definition = %v, want %v", session, got, narrowed, wantNarrowed)
		}
	}
	// Benign twin: the status of a listing that could not be read, and an
	// ordinary failed status, are never narrowed.
	unread := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, Revoked: true}
	if got := api.statusForSession(ctx, "claudecode", probe("late"), unread); !got.Revoked {
		t.Errorf("a revoked status with no departure time was narrowed: %+v", got)
	}
	plain := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true}
	if got := api.statusForSession(ctx, "claudecode", probe("late"), plain); got != plain {
		t.Errorf("an unrevoked status was changed: %+v", got)
	}
}

// The store that places sessions in time is bounded: past the bound a new
// session stays unknown, which the revoked status judges as the oldest.
func TestSessionStartStoreStaysBounded(t *testing.T) {
	h := &hookReportedMCPServers{}
	now := time.Now()
	for i := 0; i < hookReportedMCPLimit+10; i++ {
		h.noteSession("claudecode", "", "s"+strconv.Itoa(i), false, now)
	}
	if got := len(h.sessionStarts); got != hookReportedMCPLimit {
		t.Fatalf("%d sessions kept, want the bound %d", got, hookReportedMCPLimit)
	}
	if _, known := h.sessionStartedAt("claudecode", "", "s"+strconv.Itoa(hookReportedMCPLimit+5), now); known {
		t.Fatal("a session past the bound is known")
	}
	// Entries past the memory time limit make room.
	h.noteSession("claudecode", "", "fresh", false, now.Add(mcpResolvedTTL+time.Minute))
	if _, known := h.sessionStartedAt("claudecode", "", "fresh", now.Add(mcpResolvedTTL+time.Minute)); !known {
		t.Fatal("a new session is unknown although expired ones can make room")
	}
}
