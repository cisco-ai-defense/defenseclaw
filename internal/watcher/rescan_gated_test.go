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

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// countingScanner is a scanner.Scanner test double that records how many times
// Scan was invoked so tests can assert the watcher only scans on real drift.
type countingScanner struct {
	mu       sync.Mutex
	name     string
	calls    int
	findings []scanner.Finding
}

func (s *countingScanner) Name() string               { return s.name }
func (s *countingScanner) Version() string            { return "fake-1" }
func (s *countingScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *countingScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return &scanner.ScanResult{
		Scanner:   s.name,
		Target:    target,
		Timestamp: time.Now().UTC(),
		Findings:  s.findings,
	}, nil
}

func TestShouldRescan(t *testing.T) {
	const fp = "fingerprint-A"
	snap := &TargetSnapshot{ContentHash: "hash-1"}

	tests := []struct {
		name     string
		baseline *audit.SnapshotRow
		snap     *TargetSnapshot
		fp       string
		gated    bool
		want     bool
	}{
		{
			name:     "gating disabled always scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    false,
			want:     true,
		},
		{
			name:     "nil baseline scans",
			baseline: nil,
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "baseline without scan recovers",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "content changed scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-OLD", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "empty baseline content hash scans",
			baseline: &audit.SnapshotRow{ContentHash: "", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "fingerprint changed scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: "fingerprint-OLD"},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "unchanged skips",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := shouldRescan(tt.baseline, tt.snap, tt.fp, tt.gated)
			if got != tt.want {
				t.Fatalf("shouldRescan() = %v (%s), want %v", got, reason, tt.want)
			}
			if reason == "" {
				t.Error("shouldRescan() returned empty reason")
			}
		})
	}
}

func TestScannerFingerprintStableAndChanges(t *testing.T) {
	// Empty PATH makes the best-effort `<binary> --version` probe fail
	// deterministically, so the fingerprint depends only on config + provenance.
	t.Setenv("PATH", "")

	cfg, _, _, _ := setupTestEnv(t)
	w := &InstallWatcher{cfg: cfg}
	evt := InstallEvent{Type: InstallSkill, Name: "demo", Path: "/skills/demo"}

	base := w.scannerFingerprint(evt)
	if base == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if again := w.scannerFingerprint(evt); again != base {
		t.Fatalf("fingerprint not stable for identical config: %q != %q", again, base)
	}

	// GAP-0415: a config reload (new whole-config hash, next generation) of
	// a key that does not change scan output must not rescan every skill.
	version.SetContentHash([]byte("watch:\n  rescan_interval_min: 1\n"))
	version.BumpGeneration()
	if again := w.scannerFingerprint(evt); again != base {
		t.Fatal("fingerprint changed with the config hash and generation alone")
	}

	// A scan-affecting config change must change the fingerprint.
	cfg.Scanners.SkillScanner.UseLLM = !cfg.Scanners.SkillScanner.UseLLM
	if changed := w.scannerFingerprint(evt); changed == base {
		t.Error("fingerprint did not change after toggling use_llm")
	}

	// A different target kind must produce a different fingerprint.
	mcpEvt := InstallEvent{Type: InstallMCP, Name: "demo", Path: "demo"}
	if w.scannerFingerprint(mcpEvt) == base {
		t.Error("expected distinct fingerprint for MCP scanner kind")
	}
}

func TestRescanCycleGatedSkipsUnchangedTargets(t *testing.T) {
	// Deterministic fingerprint probe (no real scanner binary on PATH).
	t.Setenv("PATH", "")

	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true

	// Pin MCP enumeration to an empty server set so only the skill target
	// drives the cycle.
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	skillPath := filepath.Join(skillDir, "demo-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("# demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(skillPath, "skill.py")
	if err := os.WriteFile(scriptPath, []byte("print('v1')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	fake := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	ctx := context.Background()

	// First cycle establishes the baseline -> exactly one scan.
	w.runRescanCycle(ctx)
	if fake.calls != 1 {
		t.Fatalf("after first cycle: scanner calls = %d, want 1", fake.calls)
	}

	// Repeated no-change cycles must not re-scan.
	for i := 0; i < 3; i++ {
		w.runRescanCycle(ctx)
	}
	if fake.calls != 1 {
		t.Fatalf("after no-change cycles: scanner calls = %d, want 1", fake.calls)
	}

	// A content change triggers exactly one more scan.
	if err := os.WriteFile(scriptPath, []byte("print('v2 changed contents')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.runRescanCycle(ctx)
	if fake.calls != 2 {
		t.Fatalf("after content change: scanner calls = %d, want 2", fake.calls)
	}

	// Stable again — no extra scan.
	w.runRescanCycle(ctx)
	if fake.calls != 2 {
		t.Fatalf("after stable cycle: scanner calls = %d, want 2", fake.calls)
	}

	// A scanner fingerprint change (config toggle) re-scans byte-identical
	// content so updated rules take effect.
	cfg.Scanners.SkillScanner.UseLLM = !cfg.Scanners.SkillScanner.UseLLM
	w.runRescanCycle(ctx)
	if fake.calls != 3 {
		t.Fatalf("after fingerprint change: scanner calls = %d, want 3", fake.calls)
	}
}

func TestRescanCycleUngatedScansEveryCycle(t *testing.T) {
	t.Setenv("PATH", "")

	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = false

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	skillPath := filepath.Join(skillDir, "demo-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("# demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "skill.py"), []byte("print('v1')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	fake := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		w.runRescanCycle(ctx)
	}
	if fake.calls != 3 {
		t.Fatalf("ungated: scanner calls = %d, want 3 (one per cycle)", fake.calls)
	}
}

func TestMCPFingerprintChangesWithRulePackFile(t *testing.T) {
	dir := t.TempDir()
	original, err := os.ReadFile(filepath.Join("..", "..", "policies", "guardrail", "default", "suppressions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "suppressions.yaml")
	if err := os.WriteFile(file, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "local"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"local": {Path: dir}}
	w := New(cfg, nil, nil, nil, nil, nil, nil)
	evt := InstallEvent{Type: InstallMCP, Connector: "codex"}
	before := w.scannerFingerprint(evt)
	if err := os.WriteFile(file, append(original, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if after := w.scannerFingerprint(evt); after == before {
		t.Fatal("MCP fingerprint did not change with the rule-pack file")
	}
}

func TestScannerVersionChangesAfterBinaryReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires Unix")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "scanner")
	write := func(version string) {
		t.Helper()
		next := binary + ".next"
		if err := os.WriteFile(next, []byte("#!/bin/sh\nprintf '"+version+"\n'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(next, binary); err != nil {
			t.Fatal(err)
		}
	}
	w := &InstallWatcher{}
	write("v1")
	if got := w.scannerBinaryVersion(binary); got != "v1" {
		t.Fatalf("first version = %q", got)
	}
	write("version-two")
	if got := w.scannerBinaryVersion(binary); !strings.EqualFold(got, "version-two") {
		t.Fatalf("replacement version = %q, want version-two", got)
	}
}

// GAP-0627: a skill installed before a denied entry names it is refused by
// the next rescan cycle, without a content change, and quarantined.
func TestRescanCycleRefusesInstalledSkillAddedToDeniedList(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath
	skillPath := filepath.Join(skillDir, "epa-notes")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("---\nname: epa-notes\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var verdicts []AdmissionResult
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) { verdicts = append(verdicts, r) })
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }

	ctx := context.Background()
	w.runRescanCycle(ctx)
	if len(verdicts) != 0 {
		t.Fatalf("baseline cycle verdicts = %+v", verdicts)
	}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "epa-notes"}}
	w.runRescanCycle(ctx)
	if len(verdicts) != 1 || verdicts[0].Verdict != VerdictBlocked || verdicts[0].Event.Name != "epa-notes" {
		t.Fatalf("verdicts after the deny = %+v, want epa-notes blocked", verdicts)
	}
	if _, err := os.Lstat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("denied skill still installed: %v", err)
	}
}
