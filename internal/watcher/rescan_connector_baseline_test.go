// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type pluginBaselineScanner struct {
	findings map[string][]scanner.Finding
}

func (s *pluginBaselineScanner) Name() string               { return "plugin-scanner" }
func (s *pluginBaselineScanner) Version() string            { return "test-1" }
func (s *pluginBaselineScanner) SupportedTargets() []string { return []string{"plugin"} }
func (s *pluginBaselineScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{
		Scanner: "plugin-scanner", Target: target, TargetType: "plugin", Timestamp: time.Now().UTC(),
		Findings: append([]scanner.Finding(nil), s.findings[target]...),
	}, nil
}

func TestRescanAttributesBundledPluginFindingsAndKeepsFirstSightOutOfAlerts(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanContentGated = true
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)

	home := t.TempDir()
	bundledRoot := filepath.Join(home, ".hermes", "hermes-agent", "plugins")
	userRoot := filepath.Join(home, ".hermes", "plugins")
	makePlugin := func(root, name string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "plugin.yaml"), []byte("name: "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	bundled := makePlugin(bundledRoot, "web/ddgs")
	user := makePlugin(userRoot, "notes")
	thirdParty := makePlugin(userRoot, "review")
	findings := map[string][]scanner.Finding{
		bundled:    {{ID: "bundled", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review bundled source", Description: "first observation"}},
		thirdParty: {{ID: "third-party", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review third-party source", Description: "first observation"}},
	}
	scan := &pluginBaselineScanner{findings: findings}
	w := New(cfg, nil, []string{bundledRoot, userRoot}, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{bundledRoot: "hermes", userRoot: "hermes"})
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	w.runRescanCycle(context.Background())

	for _, tc := range []struct {
		path, connector string
		baseline        bool
	}{
		{bundled, "hermes", true},
		{user, "hermes", false},
		{thirdParty, "hermes", false},
	} {
		row, err := store.GetTargetSnapshot("plugin", tc.path)
		if err != nil || row.ScanID == "" {
			t.Fatalf("snapshot %s: %#v, %v", tc.path, row, err)
		}
		raw, err := store.GetScanRawJSON(row.ScanID)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(raw, scanner.FindingTagDetectionOnly); got != tc.baseline {
			t.Errorf("first scan %s detection-only=%t, want %t", tc.path, got, tc.baseline)
		}
	}
	logs, _ := runtime.snapshot()
	firstFindings := 0
	for _, record := range logs {
		if record.EventName() != observability.EventName(observability.TelemetryEventFindingObserved) {
			continue
		}
		firstFindings++
		if connector := record.Correlation().ConnectorID; connector != "hermes" {
			t.Errorf("first-sight finding connector = %q, want hermes", connector)
		}
	}
	if firstFindings != 2 {
		t.Errorf("first-sight finding logs = %d, want bundled and user plugin", firstFindings)
	}

	// A content change is active even when the scanner returns the same finding.
	// A clean user plugin remains allowed.
	if err := os.WriteFile(filepath.Join(bundled, "plugin.yaml"), []byte("name: web/ddgs\nversion: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.runRescanCycle(context.Background())
	row, err := store.GetTargetSnapshot("plugin", bundled)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.GetScanRawJSON(row.ScanID)
	if err != nil || strings.Contains(raw, scanner.FindingTagDetectionOnly) {
		t.Fatalf("changed bundled scan retained baseline tag: %v, %s", err, raw)
	}
	logs, _ = runtime.snapshot()
	changed := 0
	for _, record := range logs {
		if record.EventName() == observability.EventName(observability.TelemetryEventFindingObserved) {
			changed++
			if connector := record.Correlation().ConnectorID; connector != "hermes" {
				t.Errorf("changed finding connector = %q, want hermes", connector)
			}
		}
	}
	if changed <= firstFindings {
		t.Fatal("changed bundled plugin did not emit a Hermes finding")
	}
	w.runRescanCycle(context.Background())
	logs, _ = runtime.snapshot()
	unchanged := 0
	for _, record := range logs {
		if record.EventName() == observability.EventName(observability.TelemetryEventFindingObserved) {
			unchanged++
		}
	}
	if unchanged != changed {
		t.Errorf("unchanged bundled plugin emitted %d more findings", unchanged-changed)
	}

	// A plugin added to a previously covered bundle root is an installation,
	// not part of that root's initial baseline.
	added := makePlugin(bundledRoot, "web/new")
	findings[added] = []scanner.Finding{{ID: "new", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review new source"}}
	var admitted []AdmissionResult
	restarted := New(cfg, nil, []string{bundledRoot, userRoot}, store, logger, nil, func(result AdmissionResult) {
		admitted = append(admitted, result)
	})
	restarted.SetRootConnectors(map[string]string{bundledRoot: "hermes", userRoot: "hermes"})
	restarted.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	restarted.runRescanCycle(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Path != added || admitted[0].Event.Connector != "hermes" || admitted[0].ScanID == "" {
		t.Fatalf("new plugin admissions = %#v, want one Hermes scan", admitted)
	}
	raw, err = store.GetScanRawJSON(admitted[0].ScanID)
	if err != nil || strings.Contains(raw, scanner.FindingTagDetectionOnly) {
		t.Fatalf("new plugin scan has baseline tag: %v, %s", err, raw)
	}
	if result := w.runAdmission(context.Background(), InstallEvent{Type: InstallPlugin, Name: "notes", Path: user, Connector: "hermes"}); result.Verdict == VerdictBlocked || result.Verdict == VerdictRejected {
		t.Fatalf("clean user plugin admission = %s, want allowed", result.Verdict)
	}
}

func TestRescanBundledPluginBaselineRequiresPhysicalTree(t *testing.T) {
	for _, tc := range []struct {
		name, layout string
		baseline     bool
	}{
		{"shipped tree", "physical", true},
		{"linked bundle root", "linked-root", false},
		{"linked bundle parent", "linked-parent", false},
		{"custom shipped tree", "custom-physical", true},
		{"linked custom root", "custom-linked", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", "")
			t.Setenv("HERMES_BUNDLED_PLUGINS", "")
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = "claudecode"
			cfg.Watch.RescanContentGated = true
			logger.SetRuntimeV8Emitter(&watcherTestRuntime{})

			home := t.TempDir()
			root := filepath.Join(home, ".hermes", "hermes-agent", "plugins")
			if strings.HasPrefix(tc.layout, "custom-") {
				root = filepath.Join(home, "vendor", "shipped")
				t.Setenv("HERMES_BUNDLED_PLUGINS", root)
			}
			plugin := filepath.Join(root, "photon")
			actual := plugin
			switch tc.layout {
			case "linked-root", "custom-linked":
				actual = filepath.Join(home, "other-plugins", "photon")
			case "linked-parent":
				actual = filepath.Join(home, "other-agent", "plugins", "photon")
			}
			if err := os.MkdirAll(actual, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(actual, "plugin.yaml"), []byte("name: photon\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if actual != plugin {
				link := root
				target := filepath.Dir(actual)
				if tc.layout == "linked-parent" {
					link = filepath.Dir(root)
					target = filepath.Dir(target)
				}
				if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("create test link: %v", err)
				}
			}

			finding := scanner.Finding{ID: "review", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review source"}
			w := New(cfg, nil, []string{root}, store, logger, nil, nil)
			w.SetRootConnectors(map[string]string{root: "hermes"})
			w.scannerFactory = func(InstallEvent) scanner.Scanner {
				return &pluginBaselineScanner{findings: map[string][]scanner.Finding{plugin: {finding}}}
			}
			w.runRescanCycle(context.Background())
			row, err := store.GetTargetSnapshot("plugin", plugin)
			if err != nil || row.ScanID == "" {
				t.Fatalf("plugin snapshot = %#v, %v", row, err)
			}
			raw, err := store.GetScanRawJSON(row.ScanID)
			if err != nil {
				t.Fatal(err)
			}
			if tagged := strings.Contains(raw, scanner.FindingTagDetectionOnly); tagged != tc.baseline {
				t.Errorf("baseline tag = %t, want %t", tagged, tc.baseline)
			}
		})
	}
}

// pluginTreeSwitchScanner records a finding from the tree it read and can
// replace the registered root before returning the result.
type pluginTreeSwitchScanner struct {
	root, replacement, movedRoot string
}

func (s *pluginTreeSwitchScanner) Name() string               { return "plugin-scanner" }
func (s *pluginTreeSwitchScanner) Version() string            { return "test-1" }
func (s *pluginTreeSwitchScanner) SupportedTargets() []string { return []string{"plugin"} }
func (s *pluginTreeSwitchScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	if _, err := os.ReadFile(filepath.Join(target, "plugin.yaml")); err != nil {
		return nil, err
	}
	if s.replacement != "" {
		var err error
		if s.movedRoot != "" {
			err = os.Rename(s.root, s.movedRoot)
		} else {
			err = os.Remove(s.root)
		}
		if err != nil {
			return nil, err
		}
		if err := os.Rename(s.replacement, s.root); err != nil {
			return nil, err
		}
	}
	return &scanner.ScanResult{
		Scanner: "plugin-scanner", Target: target, TargetType: "plugin", Timestamp: time.Now().UTC(),
		Findings: []scanner.Finding{{ID: "review", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review source"}},
	}, nil
}

func TestRescanBundledPluginBaselineTracksScannedTree(t *testing.T) {
	for _, tc := range []struct {
		name, layout string
		baseline     bool
	}{
		{"stable shipped tree", "physical", true},
		{"linked tree replaced during scan", "linked-then-physical", false},
		{"physical tree replaced during scan", "physical-then-physical", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", "")
			t.Setenv("HERMES_BUNDLED_PLUGINS", "")
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = "claudecode"
			logger.SetRuntimeV8Emitter(&watcherTestRuntime{})
			home := t.TempDir()
			root := filepath.Join(home, ".hermes", "hermes-agent", "plugins")
			actual := root
			replacement := ""
			if tc.layout != "physical" {
				replacement = filepath.Join(home, "shipped-replacement")
				if tc.layout == "linked-then-physical" {
					actual = filepath.Join(home, "linked-source")
				}
			}
			for _, dir := range []string{actual, replacement} {
				if dir == "" {
					continue
				}
				plugin := filepath.Join(dir, "photon")
				if err := os.MkdirAll(plugin, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(plugin, "plugin.yaml"), []byte("name: photon\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.layout == "linked-then-physical" {
				if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(actual, root); err != nil {
					t.Skipf("create test link: %v", err)
				}
			}
			w := New(cfg, nil, []string{root}, store, logger, nil, nil)
			w.SetRootConnectors(map[string]string{root: "hermes"})
			w.scannerFactory = func(InstallEvent) scanner.Scanner {
				scan := &pluginTreeSwitchScanner{root: root, replacement: replacement}
				if tc.layout == "physical-then-physical" {
					scan.movedRoot = filepath.Join(home, "previous-root")
				}
				return scan
			}
			w.runRescanCycle(context.Background())
			row, err := store.GetTargetSnapshot("plugin", filepath.Join(root, "photon"))
			if err != nil || row.ScanID == "" {
				t.Fatalf("plugin snapshot = %#v, %v", row, err)
			}
			raw, err := store.GetScanRawJSON(row.ScanID)
			if err != nil {
				t.Fatal(err)
			}
			if tagged := strings.Contains(raw, scanner.FindingTagDetectionOnly); tagged != tc.baseline {
				t.Errorf("baseline tag = %t, want %t", tagged, tc.baseline)
			}
		})
	}
}
