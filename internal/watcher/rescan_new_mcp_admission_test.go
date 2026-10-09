// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0132: on a managed gateway (an MCP server source is bound), a server
// that appears after the first rescan gets install admission, so
// admission.mcp.scan_on_install: false admits it without a scan, as `mcp
// set` does per user. A server present at start that scan_on_install
// false admits only gets a baseline.
func TestRescanAdmitsMCPServerAddedLaterWithoutScan(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	off := false
	cfg.Admission.MCP.ScanOnInstall = &off
	cfg.Watch.RescanContentGated = true // the unchanged server is not rescanned
	servers := []config.MCPServerEntry{{Name: "present", URL: "https://present.example.test/mcp", Connector: "codex"}}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })

	w.runRescanCycle(context.Background())
	if len(admitted) != 0 {
		t.Fatalf("first cycle admitted %#v, want baselines only", admitted)
	}
	servers = append(servers, config.MCPServerEntry{Name: "added", URL: "https://added.example.test/mcp", Connector: "codex"})
	before := scans.calls
	// GAP-0254: the enrolled-MCP poll admits it at once, not after the cycle.
	w.AdmitAddedMCPServers([]string{"added"})
	w.admitAddedMCPServers(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Name != "added" || admitted[0].Verdict != VerdictAllowed {
		t.Fatalf("poll admitted %#v, want added allowed", admitted)
	}
	if scans.calls != before {
		t.Fatalf("scan_on_install false still scanned the new server (%d scans)", scans.calls-before)
	}
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 {
		t.Fatalf("the next cycle admitted the server again: %#v", admitted)
	}
}

// GAP-1096: an MCP server already configured when the gateway starts is
// admitted in the first cycle, so its HIGH verdict blocks and disables it;
// it used to get a baseline scan whose rejected verdict nothing acted on.
func TestRescanFirstCycleAdmitsMCPServerPresentAtStart(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	servers := []config.MCPServerEntry{{Name: "usm-time", Command: "uvx", Args: []string{"mcp-server-time"}, Connector: "claudecode"}}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
			ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "lab marker",
		}}}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Name != "usm-time" || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("first cycle admitted %+v, want usm-time rejected", admitted)
	}
}

// auditRows records the audit rows logger emits; rows() returns them as JSON.
func auditRows(t *testing.T, logger *audit.Logger) (rows func() []string) {
	t.Helper()
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)
	return func() []string {
		logs, _ := runtime.snapshot()
		out := make([]string, 0, len(logs))
		for _, record := range logs {
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(raw))
		}
		return out
	}
}

// GAP-0424: with admission.mcp.scan_on_install false the rescan scanned a
// server whose baseline had no scan (its loopback scan had failed), every
// cycle, and no admission row was ever written for it. The rescan admits it
// without a scan, once.
func TestRescanAdmitsUnscannedMCPServerWithoutScanWhenScanOnInstallIsOff(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	off := false
	cfg.Admission.MCP.ScanOnInstall = &off
	cfg.Watch.RescanContentGated = true
	server := config.MCPServerEntry{Name: "epa-noscan", URL: "http://127.0.0.1:28571/mcp", Connector: "claudecode", Home: "/home/u1"}
	var admitted []AdmissionResult
	rows := auditRows(t, logger)
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
	snap, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	w.persistSnapshot(evt, snap, "", w.cachedFingerprint(evt, nil))

	w.runRescanCycle(context.Background())
	w.runRescanCycle(context.Background())
	if scans.calls != 0 || len(admitted) != 1 || admitted[0].Verdict != VerdictAllowed {
		t.Fatalf("%d scans, admitted %+v; want one admission without a scan", scans.calls, admitted)
	}
	if got := strings.Join(rows(), "\n"); !strings.Contains(got, "type=mcp reason=scan-disabled") {
		t.Fatalf("audit rows:\n%s\nwant install-allowed reason=scan-disabled", got)
	}
}

// GAP-0910: an MCP server the admin pinned in asset_policy.mcp.allowed after
// its scan failed was scanned again by the rescan (install-scan-error), and
// stayed blocked and reported as not scanned (asset_not_scanned). The rescan
// admits it without a scan, releases the block and forgets the issue.
func TestRescanAdmitsAllowPinnedMCPServerWhoseScanFailed(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true
	server := config.MCPServerEntry{Name: "w2bnotes", URL: "http://127.0.0.1:28561/mcp", Connector: "codex", Home: "/home/u1"}
	rows := auditRows(t, logger)
	w := New(cfg, nil, nil, store, logger, nil, nil)
	failing := &failingScanner{countingScanner{name: "mcp-scanner"}}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return failing }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.AdmitAddedMCPServers([]string{server.Name})
	w.admitAddedMCPServers(context.Background())
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 || issues[0].Kind != AdmissionUnscanned {
		t.Fatalf("issues after the failed scan: %+v", issues)
	}

	cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, URL: server.URL, Reason: "reviewed"}}
	before, rowsBefore := failing.calls, len(rows())
	w.runRescanCycle(context.Background())
	if failing.calls != before {
		t.Fatalf("the rescan scanned the pinned server %d times", failing.calls-before)
	}
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 0 {
		t.Fatalf("issues after the pinned server was admitted: %+v", issues)
	}
	if entry, err := store.GetActionForConnector("mcp", server.Name, "codex"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("journal %+v (err %v), want the scan failure block released", entry, err)
	}
	newRows := strings.Join(rows()[rowsBefore:], "\n")
	if strings.Contains(newRows, "install-scan-error") || !strings.Contains(newRows, "type=mcp reason=allow-listed") {
		t.Fatalf("rescan rows:\n%s\nwant install-allowed reason=allow-listed and no install-scan-error", newRows)
	}
}

// GAP-0405: servers added with 'claude mcp add' (local scope) or a project's
// .mcp.json were never scanned: the gateway read only the user scope and the
// rescan admitted nothing new. ReadWatchedMCPServers lists every project's
// servers and the discovery poll admits one within its interval.
func TestProjectMCPServerIsAdmittedOnDiscovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	state := `{"projects":{"` + filepath.ToSlash(project) + `":{"mcpServers":{"deepwiki":{"type":"http","url":"https://mcp.example.test/mcp"}}}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"team-sync":{"command":"python3","args":["sync.py"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return cfg.ReadWatchedMCPServers([]string{"claudecode"})
	})
	w.SetMCPDiscoveryPoll(true)
	w.firstCycleDone.Store(true)

	w.discoverAddedMCPServers()
	w.admitAddedMCPServers(context.Background())
	names := map[string]bool{}
	for _, r := range admitted {
		names[r.Event.Name] = true
	}
	if !names["deepwiki"] || !names["team-sync"] || scans.calls != 2 {
		t.Fatalf("admitted %v with %d scans, want deepwiki and team-sync scanned", names, scans.calls)
	}
}

// GAP-0371: an allow pinned to the server URL (the rule mcp allow writes)
// admits the added server without a scan; the watcher used to match the
// rule against the name alone, which never matches a pinned rule.
func TestAdmitAddedMCPServerMatchesAllowPinnedToItsURL(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "ctx7", URL: "https://ctx7.example.test/mcp"}}
	servers := []config.MCPServerEntry{}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	scans := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scans }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.runRescanCycle(context.Background())
	servers = append(servers, config.MCPServerEntry{Name: "ctx7", URL: "https://ctx7.example.test/mcp", Connector: "codex"})
	w.AdmitAddedMCPServers([]string{"ctx7"})
	w.admitAddedMCPServers(context.Background())
	if len(admitted) != 1 || admitted[0].Verdict != VerdictAllowed || scans.calls != 0 {
		t.Fatalf("admitted %#v after %d scans, want ctx7 allowed by its pinned rule without a scan", admitted, scans.calls)
	}
}

// heldScanner holds every scan until release closes.
type heldScanner struct {
	started, release chan struct{}
	once             sync.Once
}

func (s *heldScanner) Name() string               { return "mcp-scanner" }
func (s *heldScanner) Version() string            { return "fake-1" }
func (s *heldScanner) SupportedTargets() []string { return []string{"mcp"} }
func (s *heldScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return &scanner.ScanResult{Scanner: s.Name(), Target: target, Timestamp: time.Now().UTC()}, nil
}

// GAP-0254: a server added while the first rescan cycle after an upgrade is
// still scanning is admitted at once: discovery waited for the whole cycle
// (about 19 minutes on a managed host), and admission waited for the scan the
// cycle was running.
func TestMCPServerAddedDuringFirstCycleIsAdmittedAtOnce(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	off := false
	cfg.Admission.MCP.ScanOnInstall = &off
	cfg.Watch.RescanContentGated = true
	if err := os.MkdirAll(filepath.Join(skillDir, "slow"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "slow", "SKILL.md"), []byte("# slow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	servers := []config.MCPServerEntry{{Name: "present", URL: "https://present.example.test/mcp", Connector: "codex", Home: "/home/u1"}}
	var admitted []string
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		admitted = append(admitted, r.Event.Name)
		mu.Unlock()
	})
	slow := &heldScanner{started: make(chan struct{}), release: make(chan struct{})}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return slow }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]config.MCPServerEntry(nil), servers...), nil
	})
	cycle := make(chan struct{})
	go func() { defer close(cycle); w.runRescanCycle(context.Background()) }()
	select {
	case <-slow.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first cycle never scanned the existing skill")
	}
	mu.Lock()
	servers = append(servers, config.MCPServerEntry{Name: "added", URL: "https://added.example.test/mcp", Connector: "codex", Home: "/home/u2"})
	mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.discoverAddedMCPServers()
		w.admitAddedMCPServers(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("admission waited for the running cycle")
	}
	mu.Lock()
	got := append([]string(nil), admitted...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "added" {
		t.Fatalf("admitted %v while the cycle scanned a skill, want [added]", got)
	}
	close(slow.release)
	<-cycle
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 {
		t.Fatalf("admitted %v, want added once and present only baselined", admitted)
	}
}

// GAP-0623: a command server from a project .mcp.json was scanned by name
// from the gateway folder, where the CLI cannot find it, and every scan
// failed closed. It is scanned from its project, for its connector.
func TestProjectMCPServerIsScannedFromItsProject(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	project := t.TempDir()
	server := config.MCPServerEntry{Name: "timesrv", Command: "uvx", Args: []string{"mcp-server-time"}, Connector: "claudecode", Project: project, SourceScope: "project"}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: "claudecode"}
	ms, ok := w.scannerFor(evt).(*scanner.MCPScanner)
	if !ok || ms.Project != project || ms.Connector != "claudecode" {
		t.Fatalf("scanner %+v, want the scan run in %s for claudecode", ms, project)
	}
}
