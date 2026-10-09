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
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
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
	pack := &guardrail.RulePack{}
	w.SetRulePackSource(func(string) *guardrail.RulePack { return pack })

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

	// An asset-only reload changes the composed pack without changing cfg or
	// the installed skill's bytes.
	pack = loadRescanTestPack(t, "default")
	w.runRescanCycle(ctx)
	if fake.calls != 4 {
		t.Fatalf("after rule-pack change: scanner calls = %d, want 4", fake.calls)
	}

	// Fingerprints are cached within a cycle. A skill under another
	// connector must not inherit this connector's pack fingerprint.
	otherPack := loadRescanTestPack(t, "strict")
	w.SetRulePackSource(func(connector string) *guardrail.RulePack {
		if connector == "other" {
			return otherPack
		}
		return pack
	})
	cache := make(map[string]string)
	first := w.cachedFingerprint(InstallEvent{Type: InstallSkill, Connector: "codex"}, cache)
	second := w.cachedFingerprint(InstallEvent{Type: InstallSkill, Connector: "other"}, cache)
	if first == second {
		t.Fatal("connector-specific rule packs share one cached fingerprint")
	}
}

// loadRescanTestPack loads a shipped pack; its files digest is what the
// rescan fingerprint records (GAP-0415, GAP-0456).
func loadRescanTestPack(t *testing.T, name string) *guardrail.RulePack {
	t.Helper()
	pack, err := guardrail.LoadRulePack(filepath.Join("..", "..", "policies", "guardrail", name))
	if err != nil {
		t.Fatal(err)
	}
	return pack
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
// the next rescan cycle, without a content change, and quarantined. So is an
// MCP server a command rule pushed later denies (GAP-1211).
func TestRescanCycleRefusesInstalledSkillAddedToDeniedList(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	servers := `{"mcp":{"servers":{"think":{"command":"npx","args":["-y","@modelcontextprotocol/server-sequential-thinking"]}}}}`
	if err := os.WriteFile(ocPath, []byte(servers), 0o600); err != nil {
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
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{
		Command: "npx", ArgsPrefix: []string{"-y", "@modelcontextprotocol/server-sequential-thinking"},
	}}
	w.runRescanCycle(ctx)
	blocked := map[string]bool{}
	for _, v := range verdicts {
		blocked[string(v.Event.Type)+":"+v.Event.Name] = v.Verdict == VerdictBlocked
	}
	if len(verdicts) != 2 || !blocked["skill:epa-notes"] || !blocked["mcp:think"] {
		t.Fatalf("verdicts after the deny = %+v, want epa-notes and think blocked", verdicts)
	}
	if _, err := os.Lstat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("denied skill still installed: %v", err)
	}
}

// GAP-0993: removing an allow rule must readmit an unchanged plugin so its
// existing HIGH finding can block and quarantine it.
func TestRescanCycleReadmitsPluginAfterAllowRemoval(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true
	cfg.Gateway.Watcher.Plugin.TakeAction = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	pluginPath := filepath.Join(pluginDir, "reviewed")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginPath, "index.js"), []byte("// reviewed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.AssetPolicy.Plugin.Allowed = []config.AssetPolicyRule{{Name: "reviewed"}}
	high := &countingScanner{name: "plugin-scanner", findings: []scanner.Finding{{
		ID: "f1", RuleID: "PLUGIN-001", Severity: scanner.SeverityHigh, Title: "dynamic code",
	}}}
	var verdicts []AdmissionResult
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, func(r AdmissionResult) {
		verdicts = append(verdicts, r)
	})
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return high }
	ctx := context.Background()
	w.runRescanCycle(ctx)
	evt := InstallEvent{Type: InstallPlugin, Name: "reviewed", Path: pluginPath}
	if res := w.runAdmission(ctx, evt); res.Verdict != VerdictAllowed {
		t.Fatalf("initial allow verdict = %+v", res)
	}
	cfg.AssetPolicy.Plugin.Allowed = nil
	w.runRescanCycle(ctx)
	if len(verdicts) != 1 || verdicts[0].Verdict != VerdictRejected {
		t.Fatalf("after allow removal = %+v, want rejected", verdicts)
	}
	if _, err := os.Lstat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("plugin still installed after allow removal: %v", err)
	}
}

// runtimeScanner fails as a scan does while the managed scanner runtime is
// not ready, until ready is set.
type runtimeScanner struct {
	countingScanner
	ready bool
}

func (s *runtimeScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	if !s.ready {
		return nil, scanner.ErrScannerRuntimeUnavailable
	}
	return s.countingScanner.Scan(ctx, target)
}

// GAP-0975: Setup prepares the managed Windows scanner runtime after it
// starts the gateway, so the startup cycle could not scan the installed
// plugins and left them unscanned for a whole interval. A cycle whose scans
// found the runtime not ready is retried soon, backing off, and once the
// runtime is ready the plugin is scanned and the loop returns to the interval.
func TestRescanRetriesSoonWhileScannerRuntimeNotReady(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	plugin := filepath.Join(pluginDir, "web-search")
	if err := os.MkdirAll(plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "plugin.yaml"), []byte("name: web-search\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, nil)
	fake := &runtimeScanner{countingScanner: countingScanner{name: "plugin-scanner"}}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }
	ctx := context.Background()

	for _, want := range []time.Duration{scannerRuntimeRetry, 2 * scannerRuntimeRetry} {
		w.runRescanCycle(ctx)
		if got := w.nextRescanDelay(time.Hour); got != want {
			t.Fatalf("next rescan with the runtime not ready in %s, want %s", got, want)
		}
	}
	fake.ready = true
	w.runRescanCycle(ctx)
	if fake.calls != 1 {
		t.Fatalf("plugin scanned %d times once the runtime was ready, want 1", fake.calls)
	}
	if got := w.nextRescanDelay(time.Hour); got != time.Hour {
		t.Fatalf("next rescan after a ready cycle in %s, want the interval", got)
	}
}
