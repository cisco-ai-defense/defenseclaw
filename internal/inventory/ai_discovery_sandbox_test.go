// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// sandboxTestSignature names one product on every surface a sandbox scan
// reads.
func sandboxTestSignature() AISignature {
	return AISignature{
		ID: "dccert-agent", Name: "DC Cert Agent", Vendor: "DC", Category: SignalAICLI, Confidence: 0.9,
		ConfigPaths: []string{"~/.dccert", ".dccert-project"}, MCPPaths: []string{"~/.dccert/mcp.json"},
		SkillPaths: []string{"~/.dccert/skills", "$DCCERT_HOME/skills"}, BinaryNames: []string{"dccert"},
		ProcessNames: []string{"dccert"}, EnvVarNames: []string{"DCCERT_MARKER"},
		HistoryPatterns: []string{"dccert-block-marker"},
	}
}

// writeSandboxTree writes files into the collected tree at root, at the
// sandbox paths given.
func writeSandboxTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		host := filepath.Join(root, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(host, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(host), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(host, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func skipSandboxScansOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandboxes run on Linux and macOS only")
	}
}

func TestScanSandboxRootReportsTheSandboxsOwnSurfaces(t *testing.T) {
	skipSandboxScansOnWindows(t)
	root := t.TempDir()
	writeSandboxTree(t, root, map[string]string{
		"/sandbox/.dccert/mcp.json":             `{"mcpServers":{"dccert-marker":{"command":"true"}}}`,
		"/sandbox/.dccert/skills/dccert-skill/": "",
		"/sandbox/.local/bin/dccert":            "",
		"/sandbox/.bash_history":                "echo dccert-block-marker\n",
		"/sandbox/work/repo/.dccert-project":    "",
		"/sandbox/work/repo/package.json":       `{"dependencies":{"left-pad":"1.0.0"}}`,
		"/sandbox/.custom-home/skills/another/": "",
	})
	scan := SandboxScan{
		Root: root, Home: "/sandbox", Workspace: "/sandbox/work/repo",
		Processes:   []SandboxProcess{{PID: 42, PPID: 1, Comm: "dccert", StartedAt: time.Now().Add(-time.Minute)}},
		Executables: map[string]string{"dccert": "/sandbox/.local/bin/dccert"},
		EnvNames:    []string{"DCCERT_MARKER", "PATH"},
		Variables:   map[string]string{"DCCERT_HOME": "/sandbox/.custom-home"},
	}
	opts := SandboxScanOptions{Mode: "enhanced", IncludeShellHistory: true, IncludePackageManifests: true, IncludeEnvVarNames: true,
		MaxFilesPerScan: 100, MaxFileBytes: 64 << 10, StoreRawLocalPaths: true}
	report, err := ScanSandboxRoot(context.Background(), scan, opts, []AISignature{sandboxTestSignature()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Source != AISourceSandbox || report.Summary.Result != "ok" {
		t.Fatalf("summary = %+v, want an ok sandbox scan", report.Summary)
	}
	detectors := map[string]bool{}
	for _, sig := range report.Signals {
		detectors[sig.Detector] = true
		if sig.Source != AISourceSandbox || sig.UserID != "" {
			t.Fatalf("signal %+v, want a sandbox signal with no host account", sig)
		}
		for _, ev := range sig.Evidence {
			if ev.RawPath != "" && !strings.HasPrefix(ev.RawPath, "/sandbox/") {
				t.Fatalf("evidence path %q is not the sandbox's own", ev.RawPath)
			}
			if strings.Contains(ev.RawPath, root) {
				t.Fatalf("evidence path %q names the host tree", ev.RawPath)
			}
		}
		if sig.Detector == "mcp" && !slices.Contains(sig.Basenames, "dccert-marker") {
			t.Fatalf("mcp signal basenames = %v, want the configured server", sig.Basenames)
		}
		if sig.Detector == "process" && (sig.Runtime == nil || sig.Runtime.PID != 42) {
			t.Fatalf("process signal = %+v, want the sandbox's pid 42", sig)
		}
	}
	for _, want := range []string{"config", "mcp", "skill", "binary", "process", "env", "shell_history"} {
		if !detectors[want] {
			t.Fatalf("detectors = %v, want %s", detectors, want)
		}
	}
	// The $DCCERT_HOME skills folder resolves through the sandbox's variable.
	found := false
	for _, sig := range report.Signals {
		if sig.Detector == "skill" && slices.Contains(sig.Basenames, "another") {
			found = true
		}
	}
	if !found {
		t.Fatalf("signals = %+v, want the skill under the sandbox's $DCCERT_HOME", report.Signals)
	}
}

// Nothing of the host reaches a sandbox's report: its processes, PATH,
// environment, variables, working directory and machine-wide surfaces.
func TestScanSandboxRootReadsNoHostFacts(t *testing.T) {
	skipSandboxScansOnWindows(t)
	hostDir := t.TempDir()
	writeSandboxTree(t, hostDir, map[string]string{"/.dccert-project": "", "/marker/skills/x/": ""})
	t.Chdir(hostDir)
	t.Setenv("DCCERT_MARKER", "1")
	t.Setenv("DCCERT_HOME", filepath.Join(hostDir, "marker"))
	stubProcessSnapshotSource(t, func() ([]processInfo, error) {
		return []processInfo{{PID: os.Getpid(), Comm: "dccert"}}, nil
	})
	sig := sandboxTestSignature()
	sig.BinaryNames = []string{"sh"}
	sig.ApplicationNames = []string{"dccert"}
	report, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: t.TempDir(), Home: "/sandbox"},
		SandboxScanOptions{Mode: "enhanced", IncludeEnvVarNames: true, IncludeNetworkDomains: true, StoreRawLocalPaths: true},
		[]AISignature{sig})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Signals) != 0 {
		t.Fatalf("signals = %+v, want none: every fact here is the host's", report.Signals)
	}
	for name := range report.Summary.DetectorDurations {
		switch name {
		case "application", "editor_extension", "local_endpoint", "local_model_api", "model_file":
			t.Fatalf("detector %s ran in a sandbox scan", name)
		}
	}
}

func TestScanSandboxRootDropsRawPathsUnlessKept(t *testing.T) {
	skipSandboxScansOnWindows(t)
	root := t.TempDir()
	writeSandboxTree(t, root, map[string]string{"/sandbox/.dccert/": ""})
	report, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: root, Home: "/sandbox"},
		SandboxScanOptions{Mode: "enhanced"}, []AISignature{sandboxTestSignature()})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Signals) == 0 {
		t.Fatal("want the config signal")
	}
	for _, sig := range report.Signals {
		for _, ev := range sig.Evidence {
			if ev.RawPath != "" {
				t.Fatalf("evidence keeps raw path %q without store_raw_local_paths", ev.RawPath)
			}
		}
	}
}

func TestScanSandboxRootMarksACollectionShortfallPartial(t *testing.T) {
	skipSandboxScansOnWindows(t)
	report, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: t.TempDir(), Home: "/sandbox", Problems: []string{"the stream hit its 4 MiB bound"}},
		SandboxScanOptions{}, []AISignature{sandboxTestSignature()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Result != "partial" || !strings.Contains(report.Summary.DetectorErrors["sandbox_collect"], "4 MiB") {
		t.Fatalf("summary = %+v, want partial naming the collection's shortfall", report.Summary)
	}
	// However many shortfalls, the report stays within what a record may
	// carry: one the gateway refused would hide the sandbox's inventory.
	many := make([]string, 200)
	for i := range many {
		many[i] = fmt.Sprintf("dccert shortfall %03d", i)
	}
	report, err = ScanSandboxRoot(context.Background(), SandboxScan{Root: t.TempDir(), Home: "/sandbox", Problems: many},
		SandboxScanOptions{}, []AISignature{sandboxTestSignature()})
	if err != nil {
		t.Fatal(err)
	}
	if detail := report.Summary.DetectorErrors["sandbox_collect"]; len(detail) > 1024 || !strings.HasPrefix(detail, "dccert shortfall 000") {
		t.Fatalf("detail of %d bytes: %.80q", len(detail), detail)
	}
	if err := ValidateUserScanReport(report, []AISignature{sandboxTestSignature()}); err != nil {
		t.Fatalf("the report is refused: %v", err)
	}
}

func TestScanSandboxRootRefusesARelativeTree(t *testing.T) {
	if _, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: "relative", Home: "/sandbox"}, SandboxScanOptions{}, nil); err == nil {
		t.Fatal("want a relative tree refused")
	}
	if _, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: t.TempDir(), Home: "/sandbox/../etc"}, SandboxScanOptions{}, nil); err == nil {
		t.Fatal("want an unclean home refused")
	}
}

func TestPlanSandboxScanNamesTheSandboxsPaths(t *testing.T) {
	skipSandboxScansOnWindows(t)
	t.Setenv("DCCERT_HOME", "/host/only")
	sig := sandboxTestSignature()
	sig.ConfigPaths = append(sig.ConfigPaths, "$UNSET_DCCERT_VAR/config")
	sig.RulePaths = []string{"~/.dccert/rules"}
	plan, err := PlanSandboxScan(SandboxScan{Home: "/sandbox", Workspace: "/sandbox/work/repo",
		Variables: map[string]string{"DCCERT_HOME": "/sandbox/.custom-home"}},
		SandboxScanOptions{IncludeShellHistory: true, IncludePackageManifests: true}, []AISignature{sig})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/sandbox/.dccert", "/sandbox/work/repo/.dccert-project"} {
		if !slices.Contains(plan.Stat, want) {
			t.Fatalf("stat = %v, want %s", plan.Stat, want)
		}
	}
	for _, p := range plan.Stat {
		if strings.Contains(p, "UNSET_DCCERT_VAR") || strings.HasPrefix(p, "/host") {
			t.Fatalf("stat = %v, want no unset or host variable paths", plan.Stat)
		}
	}
	if !slices.Contains(plan.Read, "/sandbox/.dccert/mcp.json") {
		t.Fatalf("read = %v", plan.Read)
	}
	wantDirs := []SandboxDir{{"/sandbox/.custom-home/skills", 3}, {"/sandbox/.dccert/rules", 1}, {"/sandbox/.dccert/skills", 3}}
	if !slices.Equal(plan.Dirs, wantDirs) {
		t.Fatalf("dirs = %v, want %v", plan.Dirs, wantDirs)
	}
	if !slices.Contains(plan.History, "/sandbox/.bash_history") || !slices.Equal(plan.Walk, []string{"/sandbox/work/repo"}) {
		t.Fatalf("history = %v walk = %v", plan.History, plan.Walk)
	}
	if !slices.Contains(plan.Manifests, "package.json") || !slices.Equal(plan.Binaries, []string{"dccert"}) {
		t.Fatalf("manifests = %v binaries = %v", plan.Manifests, plan.Binaries)
	}
	if plan.EnvNames {
		t.Fatal("environment names asked for with include_env_var_names off")
	}
	// Without a project folder nothing is walked.
	plan, err = PlanSandboxScan(SandboxScan{Home: "/sandbox"}, SandboxScanOptions{IncludePackageManifests: true, IncludeEnvVarNames: true}, []AISignature{sig})
	if err != nil || len(plan.Walk) != 0 || !plan.EnvNames {
		t.Fatalf("plan = %+v, %v, want no walk without a project, and environment names", plan, err)
	}
}

func sandboxScanFixture(t *testing.T) AIDiscoveryReport {
	t.Helper()
	root := t.TempDir()
	writeSandboxTree(t, root, map[string]string{"/sandbox/.dccert/mcp.json": `{"mcpServers":{"dccert-marker":{"command":"true"}}}`})
	report, err := ScanSandboxRoot(context.Background(), SandboxScan{Root: root, Home: "/sandbox"},
		SandboxScanOptions{Mode: "enhanced"}, []AISignature{sandboxTestSignature()})
	if err != nil || len(report.Signals) == 0 {
		t.Fatalf("fixture scan = %+v, %v", report, err)
	}
	return report
}

func TestDetectSandboxScansAttributesEachRecordToItsSandbox(t *testing.T) {
	skipSandboxScansOnWindows(t)
	dir := t.TempDir()
	report := sandboxScanFixture(t)
	for _, name := range []string{"alpha-1", "beta-2"} {
		rec := SandboxScanRecord{SandboxID: "id-" + name, SandboxName: name, UpdatedAt: time.Now(), Report: report}
		if err := WriteSandboxScanRecord(SandboxScanRecordPath(dir, name), rec); err != nil {
			t.Fatal(err)
		}
	}
	// The manager's record directory is no sandbox; a record filed under
	// another name is refused.
	if err := os.MkdirAll(filepath.Join(dir, "manager"), 0o700); err != nil {
		t.Fatal(err)
	}
	misfiled := SandboxScanRecord{SandboxID: "id-x", SandboxName: "gamma-3", UpdatedAt: time.Now(), Report: report}
	if err := WriteSandboxScanRecord(SandboxScanRecordPath(dir, "delta-4"), misfiled); err != nil {
		t.Fatal(err)
	}
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{SandboxScanDir: dir}, catalog: []AISignature{sandboxTestSignature()}}
	signals, _, errs := svc.detectSandboxScans()
	if errs["sandbox_scan:delta-4"] == "" || len(errs) != 1 {
		t.Fatalf("errors = %v, want only the misfiled record refused", errs)
	}
	byName := map[string]AISignal{}
	for _, sig := range signals {
		if sig.Source != AISourceSandbox || sig.SandboxID != "id-"+sig.SandboxName {
			t.Fatalf("signal = %+v, want it attributed to its record's sandbox", sig)
		}
		byName[sig.SandboxName] = sig
	}
	a, b := byName["alpha-1"], byName["beta-2"]
	if a.Fingerprint == "" || a.Fingerprint == b.Fingerprint || a.Fingerprint == report.Signals[0].Fingerprint {
		t.Fatalf("fingerprints %q %q (scan %q), want each in its sandbox's namespace", a.Fingerprint, b.Fingerprint, report.Signals[0].Fingerprint)
	}
}

func TestDetectSandboxScansRefusesALinkedRecord(t *testing.T) {
	skipSandboxScansOnWindows(t)
	dir := t.TempDir()
	report := sandboxScanFixture(t)
	elsewhere := filepath.Join(t.TempDir(), "scan.json")
	if err := WriteSandboxScanRecord(elsewhere, SandboxScanRecord{SandboxName: "alpha-1", UpdatedAt: time.Now(), Report: report}); err != nil {
		t.Fatal(err)
	}
	link := SandboxScanRecordPath(dir, "alpha-1")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{SandboxScanDir: dir}, catalog: []AISignature{sandboxTestSignature()}}
	signals, _, errs := svc.detectSandboxScans()
	if len(signals) != 0 || errs["sandbox_scan:alpha-1"] == "" {
		t.Fatalf("signals = %v errors = %v, want the linked record refused", signals, errs)
	}
}

func TestIngestExternalReportDropsSandboxAttribution(t *testing.T) {
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: t.TempDir(), HomeDir: t.TempDir(),
	}, []AISignature{testAISignature()})
	cleanupPreparedDiscoveryService(t, svc)
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-1", Source: "cli"},
		Signals: []AISignal{{SignatureID: testAISignature().ID, Category: SignalAICLI, SandboxID: "id-x", SandboxName: "alpha-1"}},
	}
	if err := svc.IngestExternalReport(context.Background(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Signals[0].SandboxID != "" || report.Signals[0].SandboxName != "" {
		t.Fatalf("signal = %+v, want sandbox attribution dropped", report.Signals[0])
	}
}
