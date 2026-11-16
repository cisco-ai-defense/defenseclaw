// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// perUserNodeRefusal is the error a per-user gateway reports when
// `defenseclaw mcp scan --json` refuses a bare node launcher: the refusal is
// the JSON error on stdout, and stderr is empty (rel-1-0-6:GAP-0258, sweep 9
// dc-mac).
const perUserNodeRefusal = "scanner mcp-scanner exited 1 (scan failed: refusing to scan local MCP server 'gb05-benign': " +
	"command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx): a scan starts only npm or PyPI packages " +
	"through npx or uvx, never another program; stderr=)"

// fakeClock is the retry clock of a test: it moves only when told to.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// rel-1-0-6:GAP-0258 sweep 9: on per-user macOS the refusal of a node
// launcher read "exited 1 (stderr=)" (the scanner's refusal was on stdout),
// so it was retried with backoff at +2.5 and +7 minutes, and the agent got
// only "scanner failure". With the refusal in the error, 35 minutes of 30 s
// discovery polls and 10-minute rescans on a fake clock scan it once per
// definition: once after the edit, once after a second edit, never between.
// The block and runtime disable stay. The error without the refusal text
// (the old one) is retried at 2, 6, 14 and 30 minutes on the same clock.
func TestPerUserLauncherRefusalIsScannedOncePerDefinitionOnAFakeClock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal string
		retries int
	}{
		{name: "refusal on stdout, read", refusal: perUserNodeRefusal},
		{name: "refusal lost, old error", refusal: "scanner mcp-scanner exited 1 (stderr=)", retries: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, scan := newScriptedMCPHarness(t)
			clock := &fakeClock{now: time.Date(2026, 11, 1, 7, 14, 5, 0, time.UTC)}
			h.w.state.now = clock.Now
			server := &h.servers[0]
			evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(*server), Connector: server.Connector}
			final := tc.retries == 0
			if !final {
				// The live scanner marked that error a refusal (its stdout
				// held one), so it blocked; this fake error does not carry
				// the mark, so the strict tier stands in for it.
				h.w.cfg.Scanners.MCPScanner.UnverifiedServer = "block"
			}
			edit := func(args ...string) {
				t.Helper()
				server.Command, server.Args = "node", args
				scan.fail = errors.New(tc.refusal)
				before := scan.count()
				got := h.poll()
				if len(got) != 1 || got[0].Verdict != VerdictBlocked || !strings.HasPrefix(got[0].Reason, scanFailureReason) || !strings.Contains(got[0].Reason, tc.refusal) {
					t.Fatalf("admission after the edit %+v, want one fail-closed block", got)
				}
				if n := scan.count() - before; n != 1 {
					t.Fatalf("the edit was scanned %d times, want once", n)
				}
				scans, retries := scan.count(), 0
				for i := 1; i <= 70; i++ { // 35 minutes of 30 s polls
					clock.advance(30 * time.Second)
					if h.pending(*server) {
						t.Fatalf("poll %d: the refused server is pending, so its calls get the still-scanning refusal", i)
					}
					retries += len(h.poll())
					if final && i%20 == 0 { // a rescan every 10 minutes
						if outcome := h.w.rescanTarget(context.Background(), evt, nil); outcome != rescanSkipped {
							t.Fatalf("rescan at poll %d = %v, want skipped", i, outcome)
						}
					}
					if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
						t.Fatalf("poll %d: journal %+v, want the server blocked and disabled", i, state)
					}
				}
				if retries != tc.retries || scan.count()-scans != tc.retries {
					t.Fatalf("in 35 minutes: %d admissions, %d scans; want %d", retries, scan.count()-scans, tc.retries)
				}
			}
			edit("/Users/u/proj/time-server.js")
			if !final {
				return
			}
			edit("/Users/u/proj/time-server.js", "--utc") // a new definition: scanned once more

			server.Command, server.Args = "npx", []string{"-y", "."}
			scan.fail = nil
			if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
				t.Fatalf("admission of the restored definition %+v, want clean", got)
			}
			if state := h.journal(*server); !state.IsEmpty() {
				t.Fatalf("the restored, clean server is still refused: %+v", state)
			}
		})
	}
}
