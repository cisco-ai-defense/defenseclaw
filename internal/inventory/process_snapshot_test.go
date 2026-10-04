// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeWindowsSnapshotReader struct {
	entries    []windowsProcessEntry
	listErr    error
	details    map[int]windowsProcessDetails
	detailErrs map[int]error
}

func (f fakeWindowsSnapshotReader) List() ([]windowsProcessEntry, error) {
	return f.entries, f.listErr
}

func (f fakeWindowsSnapshotReader) Details(pid int) (windowsProcessDetails, error) {
	return f.details[pid], f.detailErrs[pid]
}

func windowsAgentCatalog() []AISignature {
	return []AISignature{
		{ID: "codex", Name: "Codex", Vendor: "OpenAI", SupportedConnector: "codex", Confidence: .98, ProcessNames: []string{"codex"}},
		{ID: "claudecode", Name: "Claude Code", Vendor: "Anthropic", SupportedConnector: "claudecode", Confidence: .98, ProcessNames: []string{"claude"}},
	}
}

func windowsProcessParityCatalog() []AISignature {
	return append(windowsAgentCatalog(),
		AISignature{ID: "ollama", Name: "Ollama", ProcessNames: []string{"ollama"}},
		AISignature{ID: "jan", Name: "Jan", ProcessNames: []string{"Jan", "jan.exe"}},
		AISignature{ID: "lmstudio", Name: "LM Studio", ProcessNames: []string{"LM Studio", "lms"}},
		AISignature{ID: "claude-desktop", Name: "Claude Desktop", ProcessNames: []string{"Claude"}},
		AISignature{ID: "first-collision", Name: "First collision", ProcessNames: []string{"shared-helper"}},
		AISignature{ID: "second-collision", Name: "Second collision", ProcessNames: []string{"SHARED-HELPER.EXE"}},
	)
}

func TestCollectWindowsSnapshotAndClassifyAgents(t *testing.T) {
	started := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	reader := fakeWindowsSnapshotReader{
		entries: []windowsProcessEntry{
			{PID: 10, PPID: 1, Comm: `C:\tools\CoDeX.ExE`, SessionOwnerID: "S-1-5-21-7-1001"},
			{PID: 16, PPID: 10, Comm: "cmd.exe"},
			{PID: 11, PPID: 16, Comm: "node.exe"},
			{PID: 12, PPID: 1, Comm: "CLAUDE.CMD"},
			{PID: 13, PPID: 1, Comm: "my-codex-helper.exe"},
			{PID: 14, PPID: 1, Comm: "notes-about-claude.exe"},
			{PID: 15, PPID: 99, Comm: "node.exe"},
		},
		details: map[int]windowsProcessDetails{
			10: {User: `WORKSTATION\kevin`, StartedAt: started},
			11: {User: `WORKSTATION\kevin`, StartedAt: started.Add(time.Second)},
			12: {User: `WORKSTATION\kevin`, StartedAt: started.Add(2 * time.Second)},
		},
	}
	procs, err := collectWindowsSnapshot(reader)
	if err != nil {
		t.Fatal(err)
	}
	classifyWindowsProcesses(procs, windowsAgentCatalog())
	got := map[int]string{}
	for _, proc := range procs {
		got[proc.PID] = proc.Connector
	}
	for pid, want := range map[int]string{10: "codex", 11: "codex", 12: "claudecode"} {
		if got[pid] != want {
			t.Errorf("PID %d connector = %q, want %q", pid, got[pid], want)
		}
	}
	for _, pid := range []int{13, 14, 15, 16} {
		if got[pid] != "" {
			t.Errorf("false positive PID %d classified as %q", pid, got[pid])
		}
	}
	if procs[0].User != `WORKSTATION\kevin` || !procs[0].StartedAt.Equal(started) || !procs[0].Windows || procs[0].SessionOwnerID != "S-1-5-21-7-1001" {
		t.Fatalf("metadata not preserved: %+v", procs[0])
	}
}

func TestClassifyWindowsProcessesMapsUniqueCatalogAliases(t *testing.T) {
	procs := []processInfo{
		{PID: 1, Comm: `C:\Program Files\Ollama\OLLAMA.EXE`, Windows: true},
		{PID: 2, Comm: "Jan.exe", Windows: true},
		{PID: 3, Comm: "LM Studio.exe", Windows: true},
		{PID: 4, Comm: "Claude.exe", Windows: true},
		{PID: 5, Comm: "shared-helper.exe", Windows: true},
		{PID: 6, Comm: "claude.exe", Image: `C:\Users\kevin\.local\bin\claude.exe`, Windows: true},
		{PID: 7, Comm: "claude.exe", Image: `C:\Users\kevin\AppData\Local\AnthropicClaude\app-1.0.0\claude.exe`, Windows: true},
	}
	classifyWindowsProcesses(procs, windowsProcessParityCatalog())

	want := map[int]string{
		1: "ollama",
		2: "jan",
		3: "lmstudio",
		// Claude Code and Claude Desktop both claim Claude.exe. Basename-only
		// process inventory cannot distinguish them, so it fails closed.
		4: "",
		// Every cross-signature collision fails closed.
		5: "",
		// Claude Code's native install path settles the shared basename
		// (GAP-1440); Claude Desktop's own folder stays unclassified.
		6: "claudecode",
		7: "",
	}
	for _, proc := range procs {
		if proc.Connector != want[proc.PID] {
			t.Errorf("PID %d connector = %q, want %q", proc.PID, proc.Connector, want[proc.PID])
		}
	}
}

func TestWindowsProcessAliasesIncludesReviewedLauncherAliases(t *testing.T) {
	aliases := windowsProcessAliases(windowsAgentCatalog())
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "codex-app-server.exe", want: "codex"},
		{name: "codex-exec.exe", want: "codex"},
		{name: "codex_exec.exe", want: "codex"},
		{name: "claude-code.exe", want: "claudecode"},
	} {
		if got := aliases[normalizedWindowsProcessName(test.name)]; got != test.want {
			t.Errorf("launcher alias %q = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestClassifyWindowsProcessesRestrictsNodeInheritanceToAgentCLIs(t *testing.T) {
	procs := []processInfo{
		{PID: 10, PPID: 1, Comm: "codex.exe", Windows: true},
		{PID: 11, PPID: 10, Comm: "cmd.exe", Windows: true},
		{PID: 12, PPID: 11, Comm: "node.exe", Windows: true},
		{PID: 20, PPID: 1, Comm: "ollama.exe", Windows: true},
		{PID: 21, PPID: 20, Comm: "cmd.exe", Windows: true},
		{PID: 22, PPID: 21, Comm: "node.exe", Windows: true},
	}
	classifyWindowsProcesses(procs, windowsProcessParityCatalog())

	want := map[int]string{
		10: "codex",
		11: "",
		12: "codex",
		20: "ollama",
		21: "",
		22: "",
	}
	for _, proc := range procs {
		if proc.Connector != want[proc.PID] {
			t.Errorf("PID %d connector = %q, want %q", proc.PID, proc.Connector, want[proc.PID])
		}
	}
}

func TestCollectWindowsSnapshotToleratesPerProcessFailures(t *testing.T) {
	reader := fakeWindowsSnapshotReader{
		entries:    []windowsProcessEntry{{PID: 20, PPID: 1, Comm: "codex.exe"}, {PID: 21, PPID: 1, Comm: "claude.exe"}},
		details:    map[int]windowsProcessDetails{21: {User: "kevin"}},
		detailErrs: map[int]error{20: errors.New("access denied"), 21: errors.New("process exited during creation-time read")},
	}
	procs, err := collectWindowsSnapshot(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 2 || procs[0].Comm != "codex.exe" || procs[1].User != "kevin" {
		t.Fatalf("readable base/partial records were lost: %+v", procs)
	}
}

func TestCollectWindowsSnapshotDistinguishesFailureFromZeroMatches(t *testing.T) {
	wantErr := errors.New("toolhelp unavailable")
	if procs, err := collectWindowsSnapshot(fakeWindowsSnapshotReader{listErr: wantErr}); !errors.Is(err, wantErr) || procs != nil {
		t.Fatalf("snapshot failure = (%v, %v), want nil and error", procs, err)
	}
	procs, err := collectWindowsSnapshot(fakeWindowsSnapshotReader{entries: []windowsProcessEntry{{PID: 30, Comm: "explorer.exe"}}})
	if err != nil || len(procs) != 1 {
		t.Fatalf("successful non-agent snapshot = (%v, %v)", procs, err)
	}
	classifyWindowsProcesses(procs, windowsAgentCatalog())
	if procs[0].Connector != "" {
		t.Fatalf("legitimate zero-match snapshot classified explorer: %+v", procs[0])
	}
}

func TestDetectProcessesEmitsEveryWindowsAgentProcess(t *testing.T) {
	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	started := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	processSnapshotSource = func() ([]processInfo, error) {
		return []processInfo{
			{PID: 40, PPID: 1, Comm: "codex.exe", User: "kevin", StartedAt: started, Windows: true},
			{PID: 41, PPID: 40, Comm: "node.exe", User: "kevin", StartedAt: started.Add(time.Second), Windows: true},
			{PID: 42, PPID: 1, Comm: "claude.exe", User: "kevin", StartedAt: started.Add(2 * time.Second), Windows: true},
			{PID: 43, PPID: 1, Comm: "claude.exe", Windows: true},
		}, nil
	}
	svc := &ContinuousDiscoveryService{catalog: windowsAgentCatalog()}
	signals, err := svc.detectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 4 {
		t.Fatalf("got %d process signals, want 4: %+v", len(signals), signals)
	}
	seen := map[int]bool{}
	for _, signal := range signals {
		seen[signal.Runtime.PID] = true
		if signal.Runtime.PID != 43 && (signal.Runtime.User != "kevin" || signal.Runtime.StartedAt == nil || signal.Runtime.UptimeSec < 0) {
			t.Errorf("incomplete runtime: %+v", signal.Runtime)
		}
		if signal.Runtime.PID == 43 {
			raw, marshalErr := json.Marshal(signal.Runtime)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var runtimeJSON map[string]any
			if err := json.Unmarshal(raw, &runtimeJSON); err != nil {
				t.Fatal(err)
			}
			if _, exists := runtimeJSON["started_at"]; exists {
				t.Errorf("unavailable started_at was fabricated: %s", raw)
			}
			if _, exists := runtimeJSON["uptime_sec"]; exists {
				t.Errorf("unavailable uptime_sec was fabricated: %s", raw)
			}
		}
	}
	for _, pid := range []int{40, 41, 42, 43} {
		if !seen[pid] {
			t.Errorf("missing PID %d", pid)
		}
	}
}

func TestDetectProcessesReturnsSnapshotFailure(t *testing.T) {
	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	processSnapshotSource = func() ([]processInfo, error) { return nil, errors.New("enumeration failed") }
	svc := &ContinuousDiscoveryService{catalog: windowsAgentCatalog()}
	if signals, err := svc.detectProcesses(); err == nil || signals != nil {
		t.Fatalf("detectProcesses = (%v, %v), want nil and error", signals, err)
	}
}

func TestProcessSnapshotFailureIsStructuredInScanSummary(t *testing.T) {
	svc := &ContinuousDiscoveryService{
		store: NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	report := svc.classifyAndPersist(
		"scan-1", "api", time.Now(), nil,
		scanStats{Errors: 1, DetectorErrors: map[string]string{"process": "process snapshot: enumeration failed"}},
		aiStateFile{}, true,
	)
	if report.Summary.Result != "partial" || report.Summary.Errors != 1 {
		t.Fatalf("unexpected failure summary: %+v", report.Summary)
	}
	if got := report.Summary.DetectorErrors["process"]; got != "process snapshot: enumeration failed" {
		t.Fatalf("structured process error = %q", got)
	}
}

func TestDetectProcessesClaimsEachPOSIXProcessOnce(t *testing.T) {
	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	started := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	cliOnly := []processInfo{{PID: 93283, PPID: 93242, Comm: "claude", User: "kevin", StartedAt: started}}
	processSnapshotSource = func() ([]processInfo, error) { return cliOnly, nil }
	catalog := []AISignature{
		{ID: "claudecode", Name: "Claude Code", ProcessNames: []string{"claude"}},
		{ID: "claude-desktop", Name: "Claude Desktop", ProcessNames: []string{"Claude"}},
	}
	svc := &ContinuousDiscoveryService{catalog: catalog}
	signals, err := svc.detectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].SignatureID != "claudecode" {
		t.Fatalf("claude CLI signals = %+v, want one Claude Code row", signals)
	}

	both := append(cliOnly, processInfo{PID: 500, PPID: 1, Comm: "Claude", User: "kevin", StartedAt: started.Add(-time.Hour)})
	processSnapshotSource = func() ([]processInfo, error) { return both, nil }
	signals, err = svc.detectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, signal := range signals {
		got[signal.SignatureID] = signal.Runtime.PID
	}
	if len(signals) != 2 || got["claudecode"] != 93283 || got["claude-desktop"] != 500 {
		t.Fatalf("CLI plus app signals = %v, want claudecode=93283 claude-desktop=500", got)
	}
}

// GAP-2633: two live Claude Code sessions of one user stay one signal, with
// the newest as the Runtime block and the older one in OtherInstances.
func TestDetectProcessesKeepsEveryPOSIXInstanceOfAProduct(t *testing.T) {
	old := processSnapshotSource
	t.Cleanup(func() { processSnapshotSource = old })
	now := time.Now().UTC().Truncate(time.Second)
	procs := []processInfo{
		{PID: 60371, PPID: 60300, Comm: "claude", User: "dcr-std1", StartedAt: now.Add(-8 * 24 * time.Hour)},
		{PID: 2425551, PPID: 2425500, Comm: "claude", User: "dcr-std1", StartedAt: now.Add(-time.Minute)},
		{PID: 500, PPID: 1, Comm: "Claude", User: "dcr-std1", StartedAt: now.Add(-time.Hour)},
	}
	processSnapshotSource = func() ([]processInfo, error) { return procs, nil }
	catalog := []AISignature{
		{ID: "claudecode", Name: "Claude Code", ProcessNames: []string{"claude"}},
		{ID: "claude-desktop", Name: "Claude Desktop", ProcessNames: []string{"Claude"}},
	}
	svc := &ContinuousDiscoveryService{catalog: catalog}
	signals, err := svc.detectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	bySig := map[string]AISignal{}
	for _, signal := range signals {
		bySig[signal.SignatureID] = signal
	}
	if len(signals) != 2 {
		t.Fatalf("signals = %d, want 2 (one per product)", len(signals))
	}
	code := bySig["claudecode"].Runtime
	if code == nil || code.PID != 2425551 {
		t.Fatalf("claudecode runtime = %+v, want newest PID 2425551", code)
	}
	if len(code.OtherInstances) != 1 || code.OtherInstances[0].PID != 60371 ||
		code.OtherInstances[0].UptimeSec < 8*24*3600 || len(code.OtherInstances[0].OtherInstances) != 0 {
		t.Fatalf("claudecode other instances = %+v, want PID 60371 only", code.OtherInstances)
	}
	desktop := bySig["claude-desktop"].Runtime
	if desktop == nil || desktop.PID != 500 || len(desktop.OtherInstances) != 0 {
		t.Fatalf("claude-desktop runtime = %+v, want PID 500 alone", desktop)
	}
}

// GAP-1738: cursor-agent runs as its own node.exe on Windows; that image is
// Cursor, any other node.exe is not.
func TestClassifyWindowsProcessesFindsCursorAgentNode(t *testing.T) {
	catalog := append(windowsAgentCatalog(), AISignature{ID: "cursor", Name: "Cursor", ProcessNames: []string{"cursor", "Cursor"}})
	procs := []processInfo{
		{PID: 1, Comm: "node.exe", Image: `C:\Users\kevin\AppData\Local\cursor-agent\versions\2026.10.01-14929f9\node.exe`, Windows: true},
		{PID: 2, Comm: "node.exe", Image: `C:\Program Files\nodejs\node.exe`, Windows: true},
		{PID: 3, Comm: "rg.exe", Image: `C:\Users\kevin\AppData\Local\cursor-agent\versions\2026.10.01-14929f9\rg.exe`, Windows: true},
	}
	classifyWindowsProcesses(procs, catalog)
	if procs[0].Connector != "cursor" || procs[1].Connector != "" || procs[2].Connector != "" {
		t.Fatalf("connectors = %q %q %q", procs[0].Connector, procs[1].Connector, procs[2].Connector)
	}
}

// GAP-1849: cursor-agent's worker-server node.exe child is folded into its
// parent, so one cursor-agent run is one Cursor process.
func TestClassifyWindowsProcessesFoldsCursorWorkerServer(t *testing.T) {
	catalog := append(windowsAgentCatalog(), AISignature{ID: "cursor", Name: "Cursor", ProcessNames: []string{"cursor", "Cursor"}})
	image := `C:\Users\kevin\AppData\Local\cursor-agent\versions\2026.10.01-14929f9\node.exe`
	procs := []processInfo{
		{PID: 2144, PPID: 900, Comm: "node.exe", Image: image, Windows: true},
		{PID: 15344, PPID: 2144, Comm: "node.exe", Image: image, Windows: true},
		{PID: 3000, PPID: 901, Comm: "node.exe", Image: image, Windows: true},
	}
	classifyWindowsProcesses(procs, catalog)
	if procs[0].Connector != "cursor" || procs[1].Connector != "" || procs[2].Connector != "cursor" {
		t.Fatalf("connectors = %q %q %q", procs[0].Connector, procs[1].Connector, procs[2].Connector)
	}
}

// GAP-2021: Codex's app-server daemon and its pid-update-loop helper share a
// launcher that has exited; they are one Codex process. A Codex run under a
// live shell, or one with a different exited parent, stays its own.
func TestClassifyWindowsProcessesFoldsOrphanedCodexDaemonHelpers(t *testing.T) {
	image := `C:\Users\kevin\AppData\Roaming\npm\node_modules\@openai\codex\vendor\codex.exe`
	started := time.Date(2026, 10, 2, 5, 33, 0, 0, time.UTC)
	procs := []processInfo{
		{PID: 452, PPID: 9220, Comm: "codex.exe", Image: image, StartedAt: started.Add(time.Second), Windows: true},
		{PID: 11104, PPID: 9220, Comm: "codex.exe", Image: image, StartedAt: started, Windows: true},
		{PID: 700, PPID: 0, Comm: "pwsh.exe", Windows: true},
		{PID: 701, PPID: 700, Comm: "codex.exe", Image: image, Windows: true},
		{PID: 702, PPID: 700, Comm: "codex.exe", Image: image, Windows: true},
		{PID: 800, PPID: 9300, Comm: "codex.exe", Image: image, Windows: true},
	}
	classifyWindowsProcesses(procs, windowsAgentCatalog())
	for i, want := range []string{"", "codex", "", "codex", "codex", "codex"} {
		if procs[i].Connector != want {
			t.Fatalf("pid %d: connector %q, want %q", procs[i].PID, procs[i].Connector, want)
		}
	}
}

// GAP-1965: Amp's plugin runtimes are amp.exe children of the amp.exe run;
// they are folded into it, so one Amp session is one Amp process.
func TestClassifyWindowsProcessesFoldsAmpPluginRuntimes(t *testing.T) {
	catalog := append(windowsAgentCatalog(), AISignature{ID: "amp", Name: "Amp", ProcessNames: []string{"amp"}})
	image := `C:\Users\kevin\AppData\Roaming\npm\node_modules\@ampcode\cli\bin\amp.exe`
	procs := []processInfo{
		{PID: 12196, PPID: 900, Comm: "amp.exe", Image: image, Windows: true},
		{PID: 3032, PPID: 12196, Comm: "amp.exe", Image: image, Windows: true},
		{PID: 13156, PPID: 12196, Comm: "amp.exe", Image: image, Windows: true},
		{PID: 4000, PPID: 901, Comm: "amp.exe", Image: image, Windows: true},
	}
	classifyWindowsProcesses(procs, catalog)
	if procs[0].Connector != "amp" || procs[1].Connector != "" || procs[2].Connector != "" || procs[3].Connector != "amp" {
		t.Fatalf("connectors = %q %q %q %q", procs[0].Connector, procs[1].Connector, procs[2].Connector, procs[3].Connector)
	}
}

// GAP-2043: VS Code Copilot Chat runs its agent host as copilot-runtime.exe
// (under Code.exe), which runs DefenseClaw's Copilot hooks: it is a Copilot
// process. The Copilot CLI's own copilot-runtime.exe engine child is folded
// into its run, so one CLI session stays one process.
func TestClassifyWindowsProcessesFindsTheVSCodeCopilotAgentHost(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	runtimeImage := `c:\Program Files\Microsoft VS Code\07f806f999\resources\app\node_modules.asar.unpacked\@github\copilot-sdk-win32-x64\prebuilds\win32-x64\copilot-runtime.exe`
	procs := []processInfo{
		{PID: 13728, PPID: 15252, Comm: "copilot-runtime.exe", Image: runtimeImage, Windows: true},
		{PID: 15252, PPID: 900, Comm: "Code.exe", Image: `c:\Program Files\Microsoft VS Code\Code.exe`, Windows: true},
		{PID: 5000, PPID: 901, Comm: "copilot.exe", Image: `C:\Users\u\AppData\Roaming\npm\copilot.exe`, Windows: true},
		{PID: 5001, PPID: 5000, Comm: "copilot-runtime.exe", Image: `C:\Users\u\AppData\Local\copilot\pkg\copilot-runtime.exe`, Windows: true},
	}
	classifyWindowsProcesses(procs, catalog)
	if procs[0].Connector != "copilot" || procs[1].Connector != "" || procs[2].Connector != "copilot" || procs[3].Connector != "" {
		t.Fatalf("connectors = %q %q %q %q", procs[0].Connector, procs[1].Connector, procs[2].Connector, procs[3].Connector)
	}
}

// GAP-2633: a spooled per-user scan binds every listed process to the
// account and refuses a negative PID in OtherInstances.
func TestUserScanBindsEveryProcessInstanceToTheAccount(t *testing.T) {
	catalog := []AISignature{{ID: "claudecode", Name: "Claude Code", ProcessNames: []string{"claude"}}}
	sig := AISignal{
		SignatureID: "claudecode", Name: "Claude Code", Product: "Claude Code", Category: "active_process",
		Detector: "process", State: "new", Fingerprint: hashValue("fp"),
		Runtime: &ProcessRuntime{PID: 2, User: "spoofed", Comm: "claude",
			OtherInstances: []ProcessRuntime{{PID: 1, User: "spoofed", Comm: "claude"}}},
	}
	svc := &ContinuousDiscoveryService{catalog: catalog}
	got := svc.attributeUserScanSignal(sig, "1001", "dcr-std1")
	if got.Runtime.User != "dcr-std1" || len(got.Runtime.OtherInstances) != 1 || got.Runtime.OtherInstances[0].User != "dcr-std1" {
		t.Fatalf("runtime = %+v, want every instance bound to dcr-std1", got.Runtime)
	}
	if sig.Runtime.OtherInstances[0].User != "spoofed" {
		t.Fatal("attributeUserScanSignal changed the caller's signal")
	}
	bad := sig
	bad.Runtime = &ProcessRuntime{PID: 2, Comm: "claude", OtherInstances: []ProcessRuntime{{PID: -1, Comm: "claude"}}}
	err := ValidateUserScanReport(AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "scan-1"}, Signals: []AISignal{bad}}, catalog)
	if err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("validate negative other PID = %v, want non-negative error", err)
	}
}
