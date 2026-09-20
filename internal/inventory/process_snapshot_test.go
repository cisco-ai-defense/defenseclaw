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
			{PID: 10, PPID: 1, Comm: `C:\tools\CoDeX.ExE`},
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
	if procs[0].User != `WORKSTATION\kevin` || !procs[0].StartedAt.Equal(started) || !procs[0].Windows {
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
