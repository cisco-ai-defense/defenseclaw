// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// pluginBaselineScanner returns the findings fixed for each target and
// records the targets it was asked to read. onScan runs before it returns.
type pluginBaselineScanner struct {
	mu       sync.Mutex
	findings map[string][]scanner.Finding
	scanned  []string
	onScan   func(target string)
}

func (s *pluginBaselineScanner) Name() string               { return "plugin-scanner" }
func (s *pluginBaselineScanner) Version() string            { return "test-1" }
func (s *pluginBaselineScanner) SupportedTargets() []string { return []string{"plugin"} }
func (s *pluginBaselineScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.scanned = append(s.scanned, target)
	findings := append([]scanner.Finding(nil), s.findings[target]...)
	onScan := s.onScan
	s.mu.Unlock()
	if onScan != nil {
		onScan(target)
	}
	return &scanner.ScanResult{
		Scanner: "plugin-scanner", Target: target, TargetType: "plugin", Timestamp: time.Now().UTC(),
		Findings: findings,
	}, nil
}

func (s *pluginBaselineScanner) scans(target string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, scanned := range s.scanned {
		if scanned == target {
			n++
		}
	}
	return n
}

type hermesPluginFixture struct {
	t                     *testing.T
	cfg                   *config.Config
	store                 *audit.Store
	runtime               *watcherTestRuntime
	bundledRoot, userRoot string
	scan                  *pluginBaselineScanner
	w                     *InstallWatcher
}

func newHermesPluginFixture(t *testing.T) *hermesPluginFixture {
	t.Helper()
	t.Setenv("PATH", "")
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanContentGated = true
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)
	home := t.TempDir()
	f := &hermesPluginFixture{
		t: t, cfg: cfg, store: store, runtime: runtime,
		bundledRoot: filepath.Join(home, ".hermes", "hermes-agent", "plugins"),
		userRoot:    filepath.Join(home, ".hermes", "plugins"),
		scan:        &pluginBaselineScanner{findings: map[string][]scanner.Finding{}},
	}
	f.w = New(cfg, nil, []string{f.bundledRoot, f.userRoot}, store, logger, nil, nil)
	f.w.SetRootConnectors(map[string]string{f.bundledRoot: "hermes", f.userRoot: "hermes"})
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return f.scan }
	return f
}

func writePluginFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// plugin writes a plugin and gives it a HIGH finding whenever it is scanned.
func (f *hermesPluginFixture) plugin(root, name string) string {
	path := filepath.Join(root, name)
	writePluginFile(f.t, filepath.Join(path, "plugin.yaml"), "name: "+name+"\n")
	writePluginFile(f.t, filepath.Join(path, "provider.py"), "VENDOR = True\n")
	f.scan.findings[path] = []scanner.Finding{{
		ID: "review-" + strings.ReplaceAll(name, "/", "-"), RuleID: "PLUGIN-REVIEW",
		Severity: scanner.SeverityHigh, Title: "Review plugin source",
	}}
	return path
}

// pinVendor records the current bytes of a plugin as the vendor digest.
func (f *hermesPluginFixture) pinVendor(name, path string) {
	f.t.Helper()
	digest, err := hermesPluginTreeDigest(path)
	if err != nil {
		f.t.Fatal(err)
	}
	previous, existed := hermesPluginVendorDigests[name]
	hermesPluginVendorDigests[name] = digest
	f.t.Cleanup(func() {
		if existed {
			hermesPluginVendorDigests[name] = previous
		} else {
			delete(hermesPluginVendorDigests, name)
		}
	})
}

// findingConnectors lists the connector of every finding log so far.
func (f *hermesPluginFixture) findingConnectors() []string {
	logs, _ := f.runtime.snapshot()
	var connectors []string
	for _, record := range logs {
		if record.EventName() == observability.EventName(observability.TelemetryEventFindingObserved) {
			connectors = append(connectors, record.Correlation().ConnectorID)
		}
	}
	return connectors
}

// activeScan requires a stored scan of path whose findings are not marked
// detection-only.
func (f *hermesPluginFixture) activeScan(path string) {
	f.t.Helper()
	row, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil || row == nil || row.ScanID == "" {
		f.t.Fatalf("snapshot %s: %#v, %v", path, row, err)
	}
	raw, err := f.store.GetScanRawJSON(row.ScanID)
	if err != nil {
		f.t.Fatal(err)
	}
	if !strings.Contains(raw, "PLUGIN-REVIEW") || strings.Contains(raw, scanner.FindingTagDetectionOnly) {
		f.t.Fatalf("scan of %s is not an active finding: %s", path, raw)
	}
}

func onlyHermes(t *testing.T, connectors []string) {
	t.Helper()
	for _, connector := range connectors {
		if connector != "hermes" {
			t.Fatalf("finding connectors = %q, want hermes only", connectors)
		}
	}
}

// GAP-0645: a Hermes shipped plugin whose bytes match the pinned vendor
// digest is not scanned or alerted on a fresh account; every scanned Hermes
// plugin is attributed to hermes, and a changed shipped plugin is scanned
// and alerted as any other.
func TestRescanAttributesBundledPluginFindingsAndKeepsFirstSightOutOfAlerts(t *testing.T) {
	f := newHermesPluginFixture(t)
	vendor := f.plugin(f.bundledRoot, "web/ddgs")
	f.pinVendor("web/ddgs", vendor)
	platform := f.plugin(f.bundledRoot, "platforms/photon")
	f.pinVendor("platforms/photon", platform)
	edited := f.plugin(f.bundledRoot, "kanban")
	f.pinVendor("kanban", edited)
	writePluginFile(t, filepath.Join(edited, "provider.py"), "VENDOR = False\n")
	unknown := f.plugin(f.bundledRoot, "web/unlisted")
	user := f.plugin(f.userRoot, "notes")
	delete(f.scan.findings, user)
	thirdParty := f.plugin(f.userRoot, "review")

	f.w.runRescanCycle(context.Background())
	for _, path := range []string{vendor, platform} {
		if n := f.scan.scans(path); n != 0 {
			t.Errorf("vendor plugin %s scanned %d times", path, n)
		}
		if row, _ := f.store.GetTargetSnapshot("plugin", path); row != nil {
			t.Errorf("vendor plugin %s has a rescan baseline: %#v", path, row)
		}
	}
	for _, path := range []string{edited, unknown, thirdParty} {
		f.activeScan(path)
	}
	if f.scan.scans(user) != 1 {
		t.Errorf("user plugin scans = %d, want 1", f.scan.scans(user))
	}
	first := f.findingConnectors()
	onlyHermes(t, first)
	if len(first) != 3 {
		t.Fatalf("first-sight findings = %d, want edited, unlisted and third-party", len(first))
	}

	// A shipped plugin first seen after startup is vendor code as well.
	late := f.plugin(f.bundledRoot, "web/late")
	f.pinVendor("web/late", late)
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(late); n != 0 {
		t.Fatalf("vendor plugin seen after startup scanned %d times", n)
	}

	// A bytecode cache Hermes writes at run time leaves the plugin vendor code.
	writePluginFile(t, filepath.Join(vendor, "__pycache__", "provider.cpython-312.pyc"), "cache")
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(vendor); n != 0 {
		t.Fatalf("vendor plugin with a bytecode cache scanned %d times", n)
	}

	// A change to shipped bytes, an added file or a link is not vendor code.
	writePluginFile(t, filepath.Join(vendor, "provider.py"), "VENDOR = False\n")
	writePluginFile(t, filepath.Join(platform, "extra.py"), "EXTRA = True\n")
	f.w.runRescanCycle(context.Background())
	for _, path := range []string{vendor, platform} {
		if f.scan.scans(path) != 1 {
			t.Fatalf("changed shipped plugin %s scans = %d, want 1", path, f.scan.scans(path))
		}
		f.activeScan(path)
	}
	changed := f.findingConnectors()
	onlyHermes(t, changed)
	if len(changed) != len(first)+2 {
		t.Fatalf("changed shipped plugins logged %d findings, want 2", len(changed)-len(first))
	}

	// Unchanged plugins do not log again, and a clean user plugin is allowed.
	f.w.runRescanCycle(context.Background())
	if again := f.findingConnectors(); len(again) != len(changed) {
		t.Errorf("unchanged plugins logged %d more findings", len(again)-len(changed))
	}
	if result := f.w.runAdmission(context.Background(), InstallEvent{Type: InstallPlugin, Name: "notes", Path: user, Connector: "hermes"}); result.Verdict == VerdictBlocked || result.Verdict == VerdictRejected {
		t.Fatalf("clean user plugin admission = %s, want allowed", result.Verdict)
	}
}

// GAP-0645 review 4: the vendor decision is made from the bytes read once.
// A replacement present when the tree is read is scanned and alerted even
// when it is restored while the scanner runs; no rescan finding is ever
// marked detection-only.
func TestRescanHermesVendorPluginDecisionUsesBytesRead(t *testing.T) {
	f := newHermesPluginFixture(t)
	shipped := f.plugin(f.bundledRoot, "platforms/photon")
	f.pinVendor("platforms/photon", shipped)
	linked := f.plugin(f.bundledRoot, "platforms/telegram")
	f.pinVendor("platforms/telegram", linked)
	sibling := f.plugin(f.userRoot, "review")
	source := filepath.Join(shipped, "provider.py")

	// Replaced before the read and restored during the scan.
	writePluginFile(t, source, "VENDOR = False\n")
	f.scan.onScan = func(target string) {
		if target == shipped {
			writePluginFile(t, source, "VENDOR = True\n")
		}
	}
	// A link to identical bytes is never vendor code.
	outside := filepath.Join(t.TempDir(), "provider.py")
	writePluginFile(t, outside, "VENDOR = True\n")
	if err := os.Remove(filepath.Join(linked, "provider.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(linked, "provider.py")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	f.w.runRescanCycle(context.Background())
	f.activeScan(shipped)
	f.activeScan(linked)
	onlyHermes(t, f.findingConnectors())

	// Replaced after the read, while another plugin is scanned, and left in
	// place: the next cycle reads the new bytes and scans them.
	if err := os.Remove(filepath.Join(linked, "provider.py")); err != nil {
		t.Fatal(err)
	}
	writePluginFile(t, filepath.Join(linked, "provider.py"), "VENDOR = True\n")
	if err := f.store.DeleteTargetSnapshot("plugin", linked); err != nil {
		t.Fatal(err)
	}
	before := f.scan.scans(linked)
	f.scan.onScan = func(target string) {
		if target == sibling {
			writePluginFile(t, filepath.Join(linked, "provider.py"), "VENDOR = False\n")
		}
	}
	if err := f.store.DeleteTargetSnapshot("plugin", sibling); err != nil {
		t.Fatal(err)
	}
	f.w.runRescanCycle(context.Background())
	if f.scan.scans(linked) != before {
		t.Fatalf("restored vendor plugin scanned in the cycle that read vendor bytes")
	}
	f.scan.onScan = nil
	f.w.runRescanCycle(context.Background())
	if f.scan.scans(linked) != before+1 {
		t.Fatalf("plugin left changed after the read was not scanned next cycle")
	}
	f.activeScan(linked)
	onlyHermes(t, f.findingConnectors())
	for _, path := range []string{shipped, linked, sibling} {
		row, err := f.store.GetTargetSnapshot("plugin", path)
		if err != nil || row == nil {
			continue
		}
		raw, _ := f.store.GetScanRawJSON(row.ScanID)
		if strings.Contains(raw, scanner.FindingTagDetectionOnly) {
			t.Fatalf("rescan of %s marked detection-only: %s", path, raw)
		}
	}
}

func TestHermesPluginTreeDigestCoversEveryReadByte(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: a\n")
	writePluginFile(t, filepath.Join(dir, "lib", "a.py"), "A = 1\n")
	base, err := hermesPluginTreeDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := []string{base}
	for _, change := range []func(){
		func() { writePluginFile(t, filepath.Join(dir, "lib", "a.py"), "A = 2\n") },
		func() { writePluginFile(t, filepath.Join(dir, "lib", "b.py"), "") },
		func() { writePluginFile(t, filepath.Join(dir, ".hidden"), "") },
		func() { writePluginFile(t, filepath.Join(dir, "node_modules", "x.js"), "") },
	} {
		change()
		got, err := hermesPluginTreeDigest(dir)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(seen, got) {
			t.Fatalf("digest did not change: %s", got)
		}
		seen = append(seen, got)
	}
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "a.pyc"), "cache")
	if got, err := hermesPluginTreeDigest(dir); err != nil || got != seen[len(seen)-1] {
		t.Fatalf("bytecode cache changed the digest: %s, %v", got, err)
	}
	if err := os.Symlink(filepath.Join(dir, "plugin.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := hermesPluginTreeDigest(dir); err == nil {
		t.Fatal("a linked entry produced a vendor digest")
	}
}

// HERMES_BUNDLED_PLUGINS names the shipped root of a custom Hermes install;
// the same digest rule applies there and nowhere else.
func TestRescanHermesVendorPluginCustomBundledRoot(t *testing.T) {
	f := newHermesPluginFixture(t)
	custom := filepath.Join(t.TempDir(), "bundle")
	t.Setenv("HERMES_BUNDLED_PLUGINS", custom)
	f.w = New(f.cfg, nil, []string{custom, f.userRoot}, f.store, f.w.logger, nil, nil)
	f.w.SetRootConnectors(map[string]string{custom: "hermes", f.userRoot: "hermes"})
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return f.scan }
	shipped := f.plugin(custom, "photon")
	f.pinVendor("photon", shipped)
	copied := f.plugin(f.userRoot, "photon")
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(shipped); n != 0 {
		t.Fatalf("vendor plugin in custom root scanned %d times", n)
	}
	f.activeScan(copied)
	onlyHermes(t, f.findingConnectors())
}
