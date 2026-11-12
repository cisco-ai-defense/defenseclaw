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
	// A refused definition blocks in the strict tier and managed profiles;
	// the default tier keeps it with a warning (GAP-0775,
	// TestRefusedMCPServerIsKeptWithAWarningInTheDefaultTier).
	h.w.cfg.Guardrail.RulePack = "strict"
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
		{scanFailureReason + `scanner: mcp-scanner exited 1: [npx stderr] mcp as-user scan: the hook enumerator did not start the server: MCP server "x" is not started: an npx argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd`, mcpLauncherRefusedMark},
		// From the host, not the definition: the npx.cmd the user's PATH
		// resolves, a launcher not on PATH or not trusted.
		{scanFailureReason + `mcp-scan: MCP server "x" is not started: the npx.cmd path contains a Windows command metacharacter`, mcpScanFailedMark},
		{scanFailureReason + `mcp-scan: MCP server "x" is not started: npx.cmd is not on the PATH the server starts with`, mcpScanFailedMark},
		{scanFailureReason + `mcp-scan: MCP server "x" is not started: launcher C:\Users\u\npx.cmd is not trusted (owner); on a managed computer a scan starts npx only when it is installed for all users under Program Files, in a folder only administrators can change`, mcpScanFailedMark},
		{scanFailureReason + "scanner: mcp-scanner exited 1: MCPStdioLaunchError: local MCP launcher 'npx' argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd", mcpScanFailedMark},
	} {
		w := &InstallWatcher{cfg: &config.Config{}}
		res := AdmissionResult{Event: InstallEvent{Type: InstallMCP}, Verdict: VerdictBlocked, Reason: tc.reason}
		if got := w.admissionFingerprint(res, "fp"); got != "fp"+tc.mark {
			t.Errorf("fingerprint for %q = %q, want mark %q", tc.reason, got, tc.mark)
		}
	}
}

// refusedNodeHarness is a harness whose server was admitted clean, then
// changed to a node launcher and refused (final).
func refusedNodeHarness(t *testing.T) (*definitionChangeHarness, *scriptedMCPScanner, InstallEvent) {
	t.Helper()
	h, scan := newScriptedMCPHarness(t)
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"/home/u/proj/time-server.js"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission of the node definition %+v, want a fail-closed block", got)
	}
	return h, scan, InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(*server), Connector: server.Connector}
}

// rel-1-0-6:GAP-0258 review: a final launcher refusal is final for one
// definition. An edit of only its env or only its cwd is another definition:
// it is pending, the poll admits it once, and the rescan scans it too.
func TestMarkedMCPRefusalEnvOrCWDEditIsAdmittedAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.MCPServerEntry)
	}{
		{"env", func(s *config.MCPServerEntry) { s.Env = map[string]string{"TZ": "UTC"} }},
		{"cwd", func(s *config.MCPServerEntry) { s.CWD = s.Project }},
	} {
		t.Run(tc.name+"/poll", func(t *testing.T) {
			h, scan, _ := refusedNodeHarness(t)
			tc.edit(&h.servers[0])
			if !h.pending(h.servers[0]) {
				t.Fatal("the edited definition is not pending before its own scan")
			}
			scans := scan.count()
			if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked || !strings.Contains(got[0].Reason, "allowlisted stdio launcher") {
				t.Fatalf("admission of the edited definition %+v, want one launcher refusal", got)
			}
			if scan.count() != scans+1 {
				t.Fatalf("the edited definition was scanned %d times, want once", scan.count()-scans)
			}
			if h.pending(h.servers[0]) || len(h.poll()) != 0 {
				t.Fatal("the edited definition is not final after its own refusal")
			}
		})
		t.Run(tc.name+"/rescan", func(t *testing.T) {
			h, scan, evt := refusedNodeHarness(t)
			tc.edit(&h.servers[0])
			scans := scan.count()
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned || scan.count() != scans+1 {
				t.Fatalf("rescan of the edited definition = %v with %d scans, want scanned once", got, scan.count()-scans)
			}
			if state := h.journal(h.servers[0]); state.Runtime != "disable" || state.Install != "block" {
				t.Fatalf("journal %+v, want the edited node server still blocked and disabled", state)
			}
		})
	}
}

// rel-1-0-6:GAP-0258 review: the refusal is final for one scanner and one
// admission policy. A change of either makes the rescan scan it again.
func TestMarkedMCPRefusalScannerOrPolicyChangeRescans(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config.Config)
	}{
		{"scanner", func(c *config.Config) { c.Scanners.MCPScanner.ScanPrompts = !c.Scanners.MCPScanner.ScanPrompts }},
		{"admission policy", func(c *config.Config) {
			c.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, scan, evt := refusedNodeHarness(t)
			scans := scan.count()
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanSkipped || scan.count() != scans {
				t.Fatalf("rescan before the change = %v with %d scans, want skipped", got, scan.count()-scans)
			}
			tc.change(h.w.cfg)
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned || scan.count() != scans+1 {
				t.Fatalf("rescan after the %s change = %v with %d scans, want scanned once", tc.name, got, scan.count()-scans)
			}
			if state := h.journal(h.servers[0]); state.Runtime != "disable" || state.Install != "block" {
				t.Fatalf("journal %+v, want still blocked: the launcher is refused again", state)
			}
			if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanSkipped || scan.count() != scans+1 {
				t.Fatalf("rescan after the new refusal = %v, want final again", got)
			}
		})
	}
}

// rel-1-0-6:GAP-0258 review: an asset_policy.mcp allow rule pinned to the
// refused definition admits it without a scan and releases the block; the
// mark does not hold a definition the admin reviewed and allowed.
func TestMarkedMCPRefusalIsReleasedByAnAllowRule(t *testing.T) {
	h, scan, evt := refusedNodeHarness(t)
	server := h.servers[0]
	h.w.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, Command: server.Command, ArgsPrefix: server.Args, Reason: "reviewed"}}
	scans, before := scan.count(), len(h.admitted)
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("rescan with the allow rule = %v, want admitted", got)
	}
	if scan.count() != scans {
		t.Fatalf("the allowed definition was scanned %d times", scan.count()-scans)
	}
	if got := h.admitted[before:]; len(got) != 1 || got[0].Verdict != VerdictAllowed {
		t.Fatalf("admission with the allow rule %+v, want allowed", got)
	}
	if state := h.journal(server); !state.IsEmpty() {
		t.Fatalf("the allowed definition is still refused: %+v", state)
	}
	if h.pending(server) || len(h.poll()) != 0 {
		t.Fatal("the allowed definition is pending or admitted again")
	}
}

// rel-1-0-6:GAP-0258 review: on managed Windows the npx.cmd path the user's
// PATH resolves can hold a cmd.exe metacharacter. That is the host, not the
// definition: the server stays blocked, and its scan is retried with backoff
// so a fixed PATH admits it without an edit.
func TestHostLauncherRefusalIsRetriedNotFinal(t *testing.T) {
	h, scan := newScriptedMCPHarness(t)
	server := &h.servers[0]
	path := MCPEventPath(*server)
	scan.fail = errors.New(`mcp-scan: MCP server "gb05-benign" is not started: the npx.cmd path contains a Windows command metacharacter`)
	server.Args = []string{"-y", ".", "--quiet"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission with the host refusal %+v, want a fail-closed block", got)
	}
	if h.pending(*server) || len(h.poll()) != 0 {
		t.Fatal("the blocked server is pending or retried before its delay")
	}
	h.w.state.mu.Lock()
	retry := h.w.state.retry[path]
	retry.due = time.Now().Add(-time.Second)
	h.w.state.retry[path] = retry
	h.w.state.mu.Unlock()
	scan.fail = nil // the PATH was fixed
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("due retry after the host was fixed %+v, want clean", got)
	}
	if state := h.journal(*server); !state.IsEmpty() {
		t.Fatalf("the clean server is still refused: %+v", state)
	}
}
