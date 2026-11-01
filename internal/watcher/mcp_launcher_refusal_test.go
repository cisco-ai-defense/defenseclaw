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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// nodeRefusal is the error the gateway reports when the Python scanner
// refuses a bare node launcher (rel-1-0-6:GAP-0258, dc-ent-win rc23).
const nodeRefusal = "scanner: mcp-scanner exited 1: ValueError: refusing to scan local MCP server 'gb05-benign': " +
	"command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx): a scan starts only npm or PyPI " +
	"packages through npx or uvx, never another program. Start the server with npx or uvx, serve it over HTTP " +
	"and use its URL, or review it and allow that definition with 'defenseclaw mcp allow <name> --command ... --args ...'"

// scriptedMCPScanner refuses a node launcher as the scanner does, fails
// with fail while it is set, and passes every other definition.
type scriptedMCPScanner struct {
	mu    sync.Mutex
	calls int
	fail  error
	h     *definitionChangeHarness
}

func (s *scriptedMCPScanner) Name() string               { return "mcp-scanner" }
func (s *scriptedMCPScanner) Version() string            { return "fake-1" }
func (s *scriptedMCPScanner) SupportedTargets() []string { return []string{"mcp"} }

func (s *scriptedMCPScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		return nil, s.fail
	}
	for _, server := range s.h.servers {
		if server.Command == "node" {
			return nil, errors.New(nodeRefusal)
		}
	}
	return &scanner.ScanResult{Scanner: "mcp-scanner", Target: target, Timestamp: time.Now().UTC()}, nil
}

func (s *scriptedMCPScanner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newScriptedMCPHarness(t *testing.T) (*definitionChangeHarness, *scriptedMCPScanner) {
	t.Helper()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	scan := &scriptedMCPScanner{h: h}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("first admission %+v, want clean", got)
	}
	return h, scan
}

// rel-1-0-6:GAP-0258: an admitted project server changed to a bare node
// launcher was scanned, blocked and reported as drift on every discovery
// poll (30 s) forever, and every tool call got the "still scanning" refusal
// instead of the launcher reason: a scan failure never replaced the old
// baseline, so the server stayed pending. The refusal of the launcher is now
// final for that definition: one admission, the block stays, nothing is
// pending, and no poll, pending check or rescan scans it again until the
// definition changes.
func TestChangedMCPServerLauncherRefusalIsFinal(t *testing.T) {
	h, scan := newScriptedMCPHarness(t)
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"/home/u/proj/time-server.js"}
	if !h.pending(*server) {
		t.Fatal("the changed definition kept the clean verdict of the old one")
	}
	got := h.poll()
	if len(got) != 1 || got[0].Verdict != VerdictBlocked || !strings.HasPrefix(got[0].Reason, scanFailureReason) ||
		!strings.Contains(got[0].Reason, "is not an allowlisted stdio launcher") {
		t.Fatalf("admission of the node definition %+v, want one fail-closed block naming the launcher", got)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal %+v, want the refused server blocked and disabled", state)
	}
	scans := scan.count()
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(*server), Connector: server.Connector}
	for i := range 5 {
		if h.pending(*server) {
			t.Fatalf("check %d: the refused server is still pending, so its calls get the still-scanning refusal", i)
		}
		if again := h.poll(); len(again) != 0 {
			t.Fatalf("poll %d admitted the unchanged refused server again: %+v", i, again)
		}
		if outcome := h.w.rescanTarget(context.Background(), evt, nil); outcome != rescanSkipped {
			t.Fatalf("rescan %d of the unchanged refused server = %v, want skipped", i, outcome)
		}
	}
	if n := scan.count(); n != scans {
		t.Fatalf("the unchanged refused server was scanned %d more times", n-scans)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal after the polls %+v, want still blocked and disabled", state)
	}

	// A new definition is admitted again; a scannable one is released.
	server.Command, server.Args = "npx", []string{"-y", "."}
	if !h.pending(*server) {
		t.Fatal("the restored definition is not pending before its own scan")
	}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("admission of the restored definition %+v, want clean", got)
	}
	if state := h.journal(*server); !state.IsEmpty() {
		t.Fatalf("the restored, clean server is still refused: %+v", state)
	}
}

// rel-1-0-6:GAP-0258: a scan that could not finish (not a refusal) is
// retried, with backoff: not on every poll, again when its delay has passed,
// with the delay doubled, and a scan that then finishes releases the block.
func TestChangedMCPServerScanFailureRetriesWithBackoff(t *testing.T) {
	h, scan := newScriptedMCPHarness(t)
	h.w.cfg.Scanners.MCPScanner.UnverifiedServer = "block" // the strict tier blocks a scan that did not finish
	server := &h.servers[0]
	path := MCPEventPath(*server)
	scan.fail = errors.New("scanner: mcp-scanner exited 1: TimeoutError: the server did not answer initialize")
	server.Args = []string{"-y", ".", "--quiet"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission of the changed definition %+v, want a fail-closed block", got)
	}
	if h.pending(*server) {
		t.Fatal("the blocked server is still pending")
	}
	scans := scan.count()
	for i := range 3 {
		if again := h.poll(); len(again) != 0 {
			t.Fatalf("poll %d retried before the retry was due: %+v", i, again)
		}
	}
	if n := scan.count(); n != scans {
		t.Fatalf("scanned %d more times before the retry was due", n-scans)
	}
	due := func() time.Duration {
		h.w.state.mu.Lock()
		defer h.w.state.mu.Unlock()
		retry := h.w.state.retry[path]
		retry.due = time.Now().Add(-time.Second)
		h.w.state.retry[path] = retry
		return retry.delay
	}
	if delay := due(); delay != admissionRetryFirst {
		t.Fatalf("first retry delay %v, want %v", delay, admissionRetryFirst)
	}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("due retry %+v, want one more fail-closed block", got)
	}
	if again := h.poll(); len(again) != 0 {
		t.Fatalf("retried again at once: %+v", again)
	}
	if delay := due(); delay != 2*admissionRetryFirst {
		t.Fatalf("second retry delay %v, want it doubled to %v", delay, 2*admissionRetryFirst)
	}
	scan.fail = nil
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("retry after the scanner recovered %+v, want clean", got)
	}
	if state := h.journal(*server); !state.IsEmpty() {
		t.Fatalf("the clean server is still refused: %+v", state)
	}
	if again := h.poll(); len(again) != 0 {
		t.Fatalf("the admitted server was admitted again: %+v", again)
	}
}

// The final state is only for a launcher refusal; a scanner that could not
// finish, a refused URL or folder is retried.
func TestMCPLauncherRefusalBaselineMark(t *testing.T) {
	for _, tc := range []struct {
		reason string
		mark   string
	}{
		{scanFailureReason + nodeRefusal, mcpLauncherRefusedMark},
		{scanFailureReason + `MCP server "x" is not started: command "C:\\tools\\npx.cmd" is a path; a scan starts only the bare names npx or uvx`, mcpLauncherRefusedMark},
		{scanFailureReason + "scanner: mcp-scanner exited 1: TimeoutError: no answer", mcpScanFailedMark},
		{scanFailureReason + "scanner: mcp-scanner exited 1: ValueError: refusing to scan MCP URL 'http://127.0.0.1': private address", mcpScanFailedMark},
		{scanFailureReason + `mcp-scan: MCP server "notes" is not started in server: the folder is not an absolute path`, mcpScanFailedMark},
	} {
		w := &InstallWatcher{cfg: &config.Config{}}
		res := AdmissionResult{Event: InstallEvent{Type: InstallMCP}, Verdict: VerdictBlocked, Reason: tc.reason}
		if got := w.admissionFingerprint(res, "fp"); got != "fp"+tc.mark {
			t.Errorf("fingerprint for %q = %q, want mark %q", tc.reason, got, tc.mark)
		}
	}
}
