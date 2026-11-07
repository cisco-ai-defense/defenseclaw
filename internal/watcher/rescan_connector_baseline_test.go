// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
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
	admitMu               sync.Mutex
	admitted              map[string][]AdmissionResult
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
	f.watch(f.w)
	return f
}

// watch points w at the fixture scanner and records its admissions.
func (f *hermesPluginFixture) watch(w *InstallWatcher) {
	f.w = w
	w.hermesManifests = hermesScannerLoader(f.t)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return f.scan }
	w.onAdmit = func(res AdmissionResult) {
		f.admitMu.Lock()
		defer f.admitMu.Unlock()
		if f.admitted == nil {
			f.admitted = map[string][]AdmissionResult{}
		}
		f.admitted[res.Event.Path] = append(f.admitted[res.Event.Path], res)
	}
}

// lastAdmission returns the latest admission reported for path.
func (f *hermesPluginFixture) lastAdmission(path string) (AdmissionResult, bool) {
	f.admitMu.Lock()
	defer f.admitMu.Unlock()
	list := f.admitted[path]
	if len(list) == 0 {
		return AdmissionResult{}, false
	}
	return list[len(list)-1], true
}

// refused requires the latest admission of path to reject or block it.
func (f *hermesPluginFixture) refused(path string) {
	f.t.Helper()
	res, ok := f.lastAdmission(path)
	if !ok || res.Verdict != VerdictRejected && res.Verdict != VerdictBlocked {
		f.t.Fatalf("admission of %s = %#v (reported %v), want rejected or blocked", path, res, ok)
	}
}

// unscannedVendor requires a shipped plugin that was never scanned and has
// no stored scan: nothing about its vendor content is kept.
func (f *hermesPluginFixture) unscannedVendor(path string) {
	f.t.Helper()
	if n := f.scan.scans(path); n != 0 {
		f.t.Fatalf("vendor plugin %s scanned %d times", path, n)
	}
	if row, err := f.store.GetTargetSnapshot("plugin", path); err == nil && row != nil && row.ScanID != "" {
		f.t.Fatalf("vendor plugin %s has a stored scan: %#v", path, row)
	}
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
	digest, err := hermesPluginTreeDigest(path, hermesScannerLoader(f.t))
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
// digest is not scanned or alerted on a fresh account and keeps a baseline
// with no scan; every scanned Hermes plugin is attributed to hermes, and a
// change to the pristine bytes is admitted, so a HIGH edit is refused.
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
		f.unscannedVendor(path)
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
	f.unscannedVendor(late)

	// A bytecode cache Hermes writes at run time leaves the plugin vendor code.
	writePluginFile(t, filepath.Join(vendor, "__pycache__", "provider.cpython-312.pyc"), "cache")
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(vendor); n != 0 {
		t.Fatalf("vendor plugin with a bytecode cache scanned %d times", n)
	}

	// A change to shipped bytes or an added file is not vendor code: the
	// baseline of the pristine bytes makes it a change, so install admission
	// decides it and refuses it.
	writePluginFile(t, filepath.Join(vendor, "provider.py"), "VENDOR = False\n")
	writePluginFile(t, filepath.Join(platform, "extra.py"), "EXTRA = True\n")
	f.w.runRescanCycle(context.Background())
	for _, path := range []string{vendor, platform} {
		if f.scan.scans(path) != 1 {
			t.Fatalf("changed shipped plugin %s scans = %d, want 1", path, f.scan.scans(path))
		}
		f.refused(path)
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
	f.refused(linked)
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
	base, err := hermesPluginTreeDigest(dir, hermesScannerLoader(t))
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
		got, err := hermesPluginTreeDigest(dir, hermesScannerLoader(t))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(seen, got) {
			t.Fatalf("digest did not change: %s", got)
		}
		seen = append(seen, got)
	}
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "a.pyc"), "cache")
	if got, err := hermesPluginTreeDigest(dir, hermesScannerLoader(t)); err != nil || got != seen[len(seen)-1] {
		t.Fatalf("bytecode cache changed the digest: %s, %v", got, err)
	}
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "x.node"), "native")
	if _, err := hermesPluginTreeDigest(dir, hermesScannerLoader(t)); err == nil {
		t.Fatal("a native payload in a bytecode cache produced a vendor digest")
	}
	if err := os.Remove(filepath.Join(dir, "lib", "__pycache__", "x.node")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "plugin.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := hermesPluginTreeDigest(dir, hermesScannerLoader(t)); err == nil {
		t.Fatal("a linked entry produced a vendor digest")
	}
}

// The snapshot leaves out folders and links; the hash of what it leaves out
// changes with each of them, and not with a bytecode cache Hermes writes.
func TestSkippedTreeHashCoversWhatTheSnapshotLeavesOut(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: a\n")
	if got := skippedTreeHash(dir, hermesScannerLoader(t)); got != "" {
		t.Fatalf("plain plugin skipped-tree hash = %q, want empty", got)
	}
	writePluginFile(t, filepath.Join(dir, "__pycache__", "a.cpython-312.pyc"), "cache")
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "a.cpython-312.pyc"), "cache")
	if got := skippedTreeHash(dir, hermesScannerLoader(t)); got != "" {
		t.Fatalf("bytecode cache skipped-tree hash = %q, want empty", got)
	}
	var seen []string
	for _, change := range []func(){
		func() { writePluginFile(t, filepath.Join(dir, "node_modules", "x.js"), "1") },
		func() { writePluginFile(t, filepath.Join(dir, "node_modules", "x.js"), "2") },
		func() { writePluginFile(t, filepath.Join(dir, ".git", "HEAD"), "ref") },
		func() { writePluginFile(t, filepath.Join(dir, ".venv", "notes.txt"), "n") },
		func() { writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "x.dll"), "native") },
		func() { _ = os.Symlink(filepath.Join(dir, "plugin.yaml"), filepath.Join(dir, "link.yaml")) },
	} {
		change()
		got := skippedTreeHash(dir, hermesScannerLoader(t))
		if got == "" || slices.Contains(seen, got) {
			t.Fatalf("skipped-tree hash did not change: %q", got)
		}
		seen = append(seen, got)
	}
}

// HERMES_BUNDLED_PLUGINS names the shipped root of a custom Hermes install;
// the same digest rule applies there and nowhere else.
func TestRescanHermesVendorPluginCustomBundledRoot(t *testing.T) {
	f := newHermesPluginFixture(t)
	custom := filepath.Join(t.TempDir(), "bundle")
	t.Setenv("HERMES_BUNDLED_PLUGINS", custom)
	w := New(f.cfg, nil, []string{custom, f.userRoot}, f.store, f.w.logger, nil, nil)
	w.SetRootConnectors(map[string]string{custom: "hermes", f.userRoot: "hermes"})
	f.watch(w)
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

// GAP-0645 review 5: the shipped-plugin rule replaces only the scan. An
// operator deny still refuses a pinned shipped plugin; its undenied twin is
// recorded without a scan.
func TestHermesVendorPluginHonorsExplicitDeny(t *testing.T) {
	f := newHermesPluginFixture(t)
	f.cfg.AssetPolicy.Plugin.Denied = append(f.cfg.AssetPolicy.Plugin.Denied,
		config.AssetPolicyRule{Name: "web/ddgs", Connector: "hermes", Reason: "operator denied plugin"})
	denied := f.plugin(f.bundledRoot, "web/ddgs")
	f.pinVendor("web/ddgs", denied)
	twin := f.plugin(f.bundledRoot, "web/searx")
	f.pinVendor("web/searx", twin)
	f.w.runRescanCycle(context.Background())
	res, ok := f.lastAdmission(denied)
	if !ok || res.Verdict != VerdictBlocked {
		t.Fatalf("denied shipped plugin admission = %#v (reported %v), want blocked", res, ok)
	}
	if n := f.scan.scans(denied); n != 0 {
		t.Fatalf("denied shipped plugin scanned %d times", n)
	}
	if res, ok := f.lastAdmission(twin); ok {
		t.Fatalf("undenied shipped plugin admission = %#v, want none", res)
	}
	f.unscannedVendor(twin)
	if logs := f.findingConnectors(); len(logs) != 0 {
		t.Fatalf("shipped plugins raised findings: %q", logs)
	}
}

// GAP-0645 review 5: a shipped plugin installed while the watcher runs is
// admitted on the live path without a scan; an edited shipped plugin is
// scanned and refused there, and a later edit of the admitted one is refused.
func TestHermesVendorPluginLiveAdmission(t *testing.T) {
	for _, name := range []string{"security-guidance", "web/ddgs"} {
		t.Run(name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			f.cfg.Watch.RescanEnabled = true
			path := f.plugin(f.bundledRoot, name)
			f.pinVendor(name, path)
			edited := f.plugin(f.bundledRoot, name+"-edited")
			f.pinVendor(name+"-edited", edited)
			writePluginFile(t, filepath.Join(edited, "provider.py"), "VENDOR = False\n")
			live := func(path string) AdmissionResult {
				t.Helper()
				events := f.w.pendingInstallEvents(path)
				if len(events) != 1 || events[0].Type != InstallPlugin || events[0].Path != path {
					t.Fatalf("live events = %#v, want one plugin at %s", events, path)
				}
				snap := f.w.admissionSnapshot(events[0])
				res := f.w.runAdmission(context.Background(), events[0])
				f.w.recordAdmissionBaseline(events[0], snap, res)
				return res
			}
			if res := live(path); res.Verdict != VerdictAllowed || res.Reason != hermesVendorPluginReason {
				t.Fatalf("live shipped plugin admission = %#v", res)
			}
			f.unscannedVendor(path)
			if logs := f.findingConnectors(); len(logs) != 0 {
				t.Fatalf("live shipped plugin raised findings: %q", logs)
			}
			if res := live(edited); res.Verdict != VerdictRejected && res.Verdict != VerdictBlocked {
				t.Fatalf("live edited shipped plugin admission = %s, want rejected or blocked", res.Verdict)
			}
			if f.scan.scans(edited) != 1 {
				t.Fatalf("live edited shipped plugin scans = %d, want 1", f.scan.scans(edited))
			}
			onlyHermes(t, f.findingConnectors())

			writePluginFile(t, filepath.Join(path, "provider.py"), "VENDOR = False\n")
			f.w.runRescanCycle(context.Background())
			if f.scan.scans(path) != 1 {
				t.Fatalf("edited live shipped plugin scans = %d, want 1", f.scan.scans(path))
			}
			f.refused(path)
		})
	}
}

// GAP-0645 r9: a shipped plugin is decided from the bytes read in each scan,
// with scan gating on or off: pristine twice is not scanned, an edit is, and
// an edit that returns to the vendor bytes is vendor content again.
func TestRescanHermesVendorPluginIsDecidedOnEveryScan(t *testing.T) {
	for _, gated := range []bool{true, false} {
		t.Run(map[bool]string{true: "gating on", false: "gating off"}[gated], func(t *testing.T) {
			f := newHermesPluginFixture(t)
			f.cfg.Watch.RescanContentGated = gated
			path := f.plugin(f.bundledRoot, "kanban")
			f.pinVendor("kanban", path)
			source := filepath.Join(path, "provider.py")
			f.w.runRescanCycle(context.Background())
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			writePluginFile(t, source, "VENDOR = False\n")
			f.w.runRescanCycle(context.Background())
			if f.scan.scans(path) != 1 {
				t.Fatalf("edited plugin scans = %d, want 1", f.scan.scans(path))
			}
			f.refused(path)
			writePluginFile(t, source, "VENDOR = True\n")
			before := len(f.findingConnectors())
			f.w.runRescanCycle(context.Background())
			if n := f.scan.scans(path); n != 1 {
				t.Fatalf("plugin restored to vendor bytes scans = %d, want 1", n)
			}
			if got := len(f.findingConnectors()); got != before {
				t.Fatalf("plugin restored to vendor bytes logged %d findings", got-before)
			}
			onlyHermes(t, f.findingConnectors())
		})
	}
}

// GAP-0645 review 8: after an ordinary edit was admitted, a later change in a
// folder the snapshot leaves out reaches a scan, and is refused when HIGH:
// no earlier admission skips any folder. A bytecode cache without a native
// file stays no change.
func TestHermesShippedPluginChangeAfterEditIsScanned(t *testing.T) {
	cases := []struct{ dir, file string }{
		{"__pycache__", "payload.node"},
		{"node_modules", "payload.node"},
		{".git", "payload.dll"},
		{".venv", "payload.wasm"},
		{".venv", "notes.txt"},
		{"lib/node_modules", "index.js"},
	}
	for _, tc := range cases {
		t.Run(tc.dir+"/"+tc.file, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.plugin(f.bundledRoot, "web/ddgs")
			f.pinVendor("web/ddgs", path)
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			writePluginFile(t, filepath.Join(path, "provider.py"), "VENDOR = False\n")
			f.w.runRescanCycle(context.Background())
			if f.scan.scans(path) != 1 {
				t.Fatalf("edited plugin scans = %d, want 1", f.scan.scans(path))
			}
			f.refused(path)

			writePluginFile(t, filepath.Join(path, "__pycache__", "provider.cpython-312.pyc"), "cache")
			f.w.runRescanCycle(context.Background())
			if f.scan.scans(path) != 1 {
				t.Fatalf("bytecode cache after the edit scans = %d, want 1", f.scan.scans(path))
			}

			writePluginFile(t, filepath.Join(path, filepath.FromSlash(tc.dir), tc.file), "payload")
			f.w.runRescanCycle(context.Background())
			if f.scan.scans(path) != 2 {
				t.Fatalf("plugin scans after %s/%s = %d, want 2", tc.dir, tc.file, f.scan.scans(path))
			}
			f.refused(path)
			onlyHermes(t, f.findingConnectors())
		})
	}
}

// GAP-0645 r9: a pristine shipped plugin is reported once as informational
// vendor content, under no connector finding, and again after a restart.
func TestRescanReportsVendorPluginOnceAsInformational(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	f.pinVendor("web/ddgs", path)
	for range 3 {
		f.w.runRescanCycle(context.Background())
	}
	logs, _ := f.runtime.snapshot()
	reports := 0
	for _, record := range logs {
		if record.EventName() == "legacy.audit.install.allowed" {
			reports++
		}
	}
	if reports != 1 {
		t.Fatalf("vendor plugin reported %d times, want 1", reports)
	}
	f.unscannedVendor(path)
	if logs := f.findingConnectors(); len(logs) != 0 {
		t.Fatalf("vendor plugin raised findings: %q", logs)
	}
}

// GAP-0645 review 5: shipped plugins that appear while the gateway is
// stopped, under a root an earlier run covered, take startup admission; the
// pinned ones are allowed without a scan and an edited one is refused.
func TestHermesVendorPluginAddedWhileStoppedIsNotScanned(t *testing.T) {
	f := newHermesPluginFixture(t)
	f.w.runRescanCycle(context.Background())
	path := f.plugin(f.bundledRoot, "web/ddgs")
	f.pinVendor("web/ddgs", path)
	edited := f.plugin(f.bundledRoot, "kanban")
	f.pinVendor("kanban", edited)
	writePluginFile(t, filepath.Join(edited, "provider.py"), "VENDOR = False\n")
	w := New(f.cfg, nil, []string{f.bundledRoot, f.userRoot}, f.store, f.w.logger, nil, nil)
	w.SetRootConnectors(map[string]string{f.bundledRoot: "hermes", f.userRoot: "hermes"})
	f.watch(w)
	w.runRescanCycle(context.Background())
	res, ok := f.lastAdmission(path)
	if !ok || res.Verdict != VerdictAllowed || res.Reason != hermesVendorPluginReason {
		t.Fatalf("shipped plugin startup admission = %#v (reported %v)", res, ok)
	}
	f.unscannedVendor(path)
	if f.scan.scans(edited) != 1 {
		t.Fatalf("edited shipped plugin scans = %d, want 1", f.scan.scans(edited))
	}
	f.refused(edited)
	onlyHermes(t, f.findingConnectors())
}

// GAP-0645 review 6: the plugin scanner reports a native payload in a folder
// it otherwise skips, so a digest match must not vouch for one, and a
// pristine shipped plugin that gains one is scanned, whichever folder it
// hides in. Bytecode caches without a native payload stay out of the way.
func TestHermesVendorPluginNativePayloadInScannerSkippedDir(t *testing.T) {
	cases := []struct{ dir, file string }{
		{"__pycache__", "payload.node"},
		{"lib/__pycache__", "payload.SO"},
		{"node_modules", "payload.node"},
		{".git", "payload.dll"},
		{".venv", "payload.wasm"},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			t.Run("rescan", func(t *testing.T) {
				f := newHermesPluginFixture(t)
				path := f.plugin(f.bundledRoot, "web/ddgs")
				f.pinVendor("web/ddgs", path)
				f.w.runRescanCycle(context.Background())
				f.w.runRescanCycle(context.Background())
				f.unscannedVendor(path)
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(tc.dir), tc.file), "payload")
				f.w.runRescanCycle(context.Background())
				if f.scan.scans(path) != 1 {
					t.Fatalf("plugin scans = %d, want 1", f.scan.scans(path))
				}
				f.refused(path)
				onlyHermes(t, f.findingConnectors())
			})
			t.Run("live", func(t *testing.T) {
				f := newHermesPluginFixture(t)
				f.cfg.Watch.RescanEnabled = true
				path := f.plugin(f.bundledRoot, "web/ddgs")
				f.pinVendor("web/ddgs", path)
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(tc.dir), tc.file), "payload")
				events := f.w.pendingInstallEvents(path)
				if len(events) != 1 {
					t.Fatalf("live events = %#v", events)
				}
				res := f.w.runAdmission(context.Background(), events[0])
				if res.Verdict != VerdictRejected && res.Verdict != VerdictBlocked {
					t.Fatalf("live admission = %s (%s), want rejected or blocked", res.Verdict, res.Reason)
				}
				if f.scan.scans(path) != 1 {
					t.Fatalf("plugin scans = %d, want 1", f.scan.scans(path))
				}
			})
		})
	}
}

func TestHermesVendorPluginBytecodeCacheIsNotAChange(t *testing.T) {
	f := newHermesPluginFixture(t)
	f.cfg.Watch.RescanEnabled = true
	path := f.plugin(f.bundledRoot, "web/ddgs")
	f.pinVendor("web/ddgs", path)
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	writePluginFile(t, filepath.Join(path, "__pycache__", "provider.cpython-312.pyc"), "cache")
	writePluginFile(t, filepath.Join(path, "lib", "__pycache__", "a.cpython-312.opt-1.pyc"), "cache")
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	events := f.w.pendingInstallEvents(path)
	if len(events) != 1 {
		t.Fatalf("live events = %#v", events)
	}
	if res := f.w.runAdmission(context.Background(), events[0]); res.Verdict != VerdictAllowed || res.Reason != hermesVendorPluginReason {
		t.Fatalf("live admission = %#v", res)
	}
	f.unscannedVendor(path)
	if logs := f.findingConnectors(); len(logs) != 0 {
		t.Fatalf("bytecode cache raised findings: %q", logs)
	}
}

// The native extensions the digest walk refuses are the ones the plugin
// scanner reports.
func TestHermesNativeExtensionsMatchScanner(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "scanner", "plugin_scanner", "rules.py"))
	if err != nil {
		t.Skipf("plugin scanner rules: %v", err)
	}
	match := regexp.MustCompile(`(?m)^BINARY_EXTENSIONS:[^=]*=\s*\{([^}]*)\}`).FindSubmatch(src)
	if match == nil {
		t.Fatal("BINARY_EXTENSIONS not found in the plugin scanner rules")
	}
	var scanned []string
	for _, ext := range regexp.MustCompile(`"(\.[a-z0-9]+)"`).FindAllSubmatch(match[1], -1) {
		scanned = append(scanned, string(ext[1]))
	}
	var ours []string
	for ext := range hermesNativeExtensions {
		ours = append(ours, ext)
	}
	slices.Sort(scanned)
	slices.Sort(ours)
	if !slices.Equal(scanned, ours) {
		t.Fatalf("native extensions = %q, scanner reports %q", ours, scanned)
	}
}

// GAP-0645 review 9: the baseline recorded for vendor bytes vouches for
// nothing but vendor bytes. When the plugin stops matching its digest while
// the snapshot hash is unchanged (a snapshot taken from other bytes, or a
// digest that no longer matches), the next cycle admits it and refuses it
// when HIGH, rather than scanning it as a first sight.
func TestHermesVendorBaselineVouchesOnlyForVendorBytes(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "kanban")
	f.pinVendor("kanban", path)
	f.w.runRescanCycle(context.Background())
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	row, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil || row == nil || row.ScanID != "" || strings.Contains(row.ScannerFingerprint, "hermes-vendor") {
		t.Fatalf("vendor baseline = %#v, %v; want an unmarked baseline with no scan", row, err)
	}
	hermesPluginVendorDigests["kanban"] = "0000"
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("plugin that stopped matching its digest scans = %d, want 1", n)
	}
	f.refused(path)
	onlyHermes(t, f.findingConnectors())
}

// GAP-0645 review 9: a file the plugin scanner can read in a folder it skips
// is hashed however much skipped data precedes it. A 64 MiB file in .git
// used to spend the whole budget, so a same-size edit of the entrypoint under
// node_modules left the content hash unchanged and was never rescanned.
func TestHermesShippedPluginEntrypointEditAfterLargeSkippedFileIsRescanned(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	pack := filepath.Join(path, ".git", "000-pack")
	writePluginFile(t, pack, "")
	if err := os.Truncate(pack, hermesPluginMaxTreeBytes); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(path, "node_modules", "main.js")
	writePluginFile(t, main, "safe()\n")
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("first sight scans = %d, want 1", n)
	}
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("unchanged plugin scans = %d, want 1", n)
	}
	writePluginFile(t, main, "eval()\n")
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 2 {
		t.Fatalf("plugin scans after the same-size entrypoint edit = %d, want 2", n)
	}
	f.refused(path)
}

// GAP-0645 review 9: skippedTreeHash reads the files the scanner can read, in
// order, and not the larger ones; a tree past the read bound has no stable
// hash, so it is never reported unchanged.
func TestSkippedTreeHashBounds(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: a\n")
	pack := filepath.Join(dir, ".git", "000-pack")
	writePluginFile(t, pack, "")
	if err := os.Truncate(pack, hermesScannerReadBytes+1); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "node_modules", "main.js")
	writePluginFile(t, main, "safe()\n")
	before := skippedTreeHash(dir, hermesScannerLoader(t))
	writePluginFile(t, main, "eval()\n")
	if after := skippedTreeHash(dir, hermesScannerLoader(t)); after == before {
		t.Fatal("same-size entrypoint edit left the skipped-tree hash unchanged")
	}
	if again, same := skippedTreeHash(dir, hermesScannerLoader(t)), skippedTreeHash(dir, hermesScannerLoader(t)); again != same {
		t.Fatal("skipped-tree hash of an unchanged tree differs between reads")
	}
	limit := hermesSkippedTreeMaxBytes
	hermesSkippedTreeMaxBytes = 4
	t.Cleanup(func() { hermesSkippedTreeMaxBytes = limit })
	if first, second := skippedTreeHash(dir, hermesScannerLoader(t)), skippedTreeHash(dir, hermesScannerLoader(t)); first == second {
		t.Fatal("a tree past the read bound has a stable hash")
	}
}

// hermesDeclaredEntrypointForms is every way a manifest the plugin scanner
// reads declares a runtime entrypoint (top-level main, bin as a string or a
// map, entrypoint and entry, in each manifest file, in JSON and YAML). DIR
// stands for the folder the declared run.js is in; also is a second manifest
// that declares nothing, which must not shadow the first.
var hermesDeclaredEntrypointForms = map[string]struct{ file, body, alsoFile, alsoBody string }{
	"main":                                 {file: "package.json", body: `{"name":"p","version":"1.0.0","main":"DIR/run.js"}`},
	"main-dotdir":                          {file: "package.json", body: `{"name":"p","version":"1.0.0","main":"./DIR/run.js"}`},
	"main-lead":                            {file: "package.json", body: `{"name":"p","version":"1.0.0","main":"/DIR/run.js"}`},
	"main-dotdot":                          {file: "package.json", body: `{"name":"p","version":"1.0.0","main":"lib/../DIR/run.js"}`},
	"main-space":                           {file: "package.json", body: `{"name":"p","main":"  DIR/run.js "}`},
	"bin-string":                           {file: "package.json", body: `{"name":"p","version":"1.0.0","bin":"DIR/run.js"}`},
	"bin-map":                              {file: "package.json", body: `{"name":"p","version":"1.0.0","bin":{"p":"DIR/run.js"}}`},
	"bin-map-many":                         {file: "package.json", body: `{"name":"p","bin":{"a":"lib/a.js","p":"DIR/run.js"}}`},
	"entrypoint":                           {file: "package.json", body: `{"name":"p","entrypoint":"DIR/run.js"}`},
	"entry":                                {file: "plugin.json", body: `{"name":"p","entry":"DIR/run.js"}`},
	"manifest-json":                        {file: "manifest.json", body: `{"name":"p","main":"DIR/run.js"}`},
	"openclaw":                             {file: "openclaw.plugin.json", body: `{"id":"p","entrypoint":"DIR/run.js"}`},
	"claude-dir":                           {file: ".claude-plugin/plugin.json", body: `{"name":"p","entrypoint":"DIR/run.js"}`},
	"codex-dir":                            {file: ".codex-plugin/plugin.json", body: `{"name":"p","entry":"DIR/run.js"}`},
	"cursor-dir":                           {file: ".cursor-plugin/plugin.json", body: `{"name":"p","main":"DIR/run.js"}`},
	"yaml":                                 {file: "plugin.yaml", body: "name: p\nentrypoint: DIR/run.js\n"},
	"yaml-entry":                           {file: "plugin.yaml", body: "name: p\nentry: \"DIR/run.js\"\n"},
	"yaml-main":                            {file: "plugin.yml", body: "name: p\nmain: DIR/run.js\n"},
	"yaml-bin":                             {file: "plugin.yaml", body: "name: p\nbin:\n  p: DIR/run.js\n"},
	"yaml-merge-key":                       {file: "plugin.yaml", body: "name: p\nbase: &b\n  entrypoint: DIR/run.js\n<<: *b\n"},
	"yaml-bin-numeric-key":                 {file: "plugin.yaml", body: "name: p\nbin:\n  7: DIR/run.js\n"},
	"yaml-bin-bool-key":                    {file: "plugin.yaml", body: "name: p\nbin:\n  true: DIR/run.js\n"},
	"yaml-bin-null-key":                    {file: "plugin.yaml", body: "name: p\nbin:\n  null: DIR/run.js\n"},
	"yaml-bin-quoted-key":                  {file: "plugin.yaml", body: "name: p\nbin:\n  \"7\": DIR/run.js\n"},
	"yaml-bin-merge":                       {file: "plugin.yaml", body: "name: p\nshared: &s\n  tool: DIR/run.js\nbin:\n  <<: *s\n"},
	"yaml-duplicate-keys":                  {file: "plugin.yaml", body: "name: p\nname: q\nmain: lib/a.js\nmain: DIR/run.js\n"},
	"yaml-alias":                           {file: "plugin.yaml", body: "name: p\nsrc: &s DIR/run.js\nmain: *s\n"},
	"yaml-merge-sequence":                  {file: "plugin.yaml", body: "o: &o\n  name: p\nb: &b\n  bin:\n    7: DIR/run.js\n<<: [*o, *b]\n"},
	"yaml-bin-duplicate-key":               {file: "plugin.yaml", body: "name: p\nbin:\n  p: lib/a.js\n  p: DIR/run.js\n"},
	"yaml-bin-same-number-key":             {file: "plugin.yaml", body: "name: p\nbin:\n  1: lib/a.js\n  true: DIR/run.js\n"},
	"yaml-bin-merge-explicit":              {file: "plugin.yaml", body: "name: p\nbin:\n  <<: {p: lib/a.js}\n  p: DIR/run.js\n"},
	"yaml-merge-explicit-first":            {file: "plugin.yaml", body: "name: p\nmain: DIR/run.js\n<<: {main: lib/a.js}\n"},
	"yaml-merge-list-first":                {file: "plugin.yaml", body: "name: p\n<<: [{main: DIR/run.js}, {main: lib/a.js}]\n"},
	"yaml-merge-key-last":                  {file: "plugin.yaml", body: "name: p\n<<: {main: lib/a.js}\n<<: {main: DIR/run.js}\n"},
	"yaml-merge-nested":                    {file: "plugin.yaml", body: "i: &i\n  main: lib/a.js\nm: &m\n  <<: *i\n  main: DIR/run.js\n<<: *m\n"},
	"yaml-typed-int-key-wins":              {file: "plugin.yaml", body: "name: p\nbin:\n  1: lib/run.js\n  !!int 1: DIR/run.js\n"},
	"yaml-typed-bool-key-wins":             {file: "plugin.yaml", body: "name: p\nbin:\n  true: lib/run.js\n  !!bool true: DIR/run.js\n"},
	"yaml-typed-float-key-wins":            {file: "plugin.yaml", body: "name: p\nbin:\n  1.0: lib/run.js\n  !!float 1.0: DIR/run.js\n"},
	"yaml-typed-null-key-wins":             {file: "plugin.yaml", body: "name: p\nbin:\n  null: lib/run.js\n  !!null null: DIR/run.js\n"},
	"yaml-sexagesimal-key-wins":            {file: "plugin.yaml", body: "name: p\nbin:\n  1:00: lib/run.js\n  60: DIR/run.js\n"},
	"yaml-infinity-key-wins":               {file: "plugin.yaml", body: "name: p\nbin:\n  .inf: lib/run.js\n  +.Inf: DIR/run.js\n"},
	"yaml-date-key-wins":                   {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01: lib/run.js\n  !!timestamp 2001-1-1: DIR/run.js\n"},
	"yaml-datetime-z-offset-key-wins":      {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00Z: lib/run.js\n  2001-01-01T00:00:00+00:00: DIR/run.js\n"},
	"yaml-datetime-zone-shift-key-wins":    {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00Z: lib/run.js\n  2001-01-01T01:00:00+01:00: DIR/run.js\n"},
	"yaml-datetime-negative-zone-key-wins": {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00Z: lib/run.js\n  2000-12-31T23:00:00-01:00: DIR/run.js\n"},
	"yaml-datetime-fraction-key-wins":      {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00.1Z: lib/run.js\n  2001-01-01T00:00:00.100000+00:00: DIR/run.js\n"},
	"yaml-datetime-fraction-truncated-key-wins": {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00.1Z: lib/run.js\n  2001-01-01T00:00:00.1000009Z: DIR/run.js\n"},
	"yaml-datetime-spaced-key-wins":             {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01 00:00:00 Z: lib/run.js\n  2001-01-01t00:00:00z: DIR/run.js\n"},
	"yaml-datetime-minute-sixty-key-wins":       {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T01:00:00+01:00: lib/run.js\n  2001-01-01T00:00:00+00:60: DIR/run.js\n"},
	"yaml-datetime-naive-key-wins":              {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00: lib/run.js\n  2001-1-1 0:00:00: DIR/run.js\n"},
	"yaml-datetime-naive-vs-utc-keys-both":      {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00: DIR/run.js\n  2001-01-01T00:00:00Z: lib/run.js\n"},
	"yaml-datetime-date-vs-datetime-keys-both":  {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01: DIR/run.js\n  2001-01-01T00:00:00Z: lib/run.js\n"},
	"yaml-datetime-other-instant-keys-both":     {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00Z: DIR/run.js\n  2001-01-01T00:00:00+01:00: lib/run.js\n"},
	"yaml-datetime-fraction-digit-keys-both":    {file: "plugin.yaml", body: "name: p\nbin:\n  2001-01-01T00:00:00.1Z: DIR/run.js\n  2001-01-01T00:00:00.100001Z: lib/run.js\n"},
	"json-infinity":                             {file: "package.json", body: `{"name":"p","version":-Infinity,"main":"DIR/run.js"}`},
	"json-nan":                                  {file: "package.json", body: `{"name":"p","version":NaN,"main":"DIR/run.js"}`},
	"shadowed": {file: "plugin.yaml", body: "name: p\nentrypoint: DIR/run.js\n",
		alsoFile: "package.json", alsoBody: `{"name":"p","main":"lib/other.js"}`},
}

// GAP-0645 review 11: the plugin scanner reads a manifest-declared
// entrypoint whatever folder it is in, a bytecode cache included, so an
// edit to it must reach a scan; the cache Hermes writes stays unhashed.
func TestHermesDeclaredEntrypointInSkippedDirChangesRescan(t *testing.T) {
	for _, dir := range []string{"node_modules", "__pycache__", "lib/__pycache__"} {
		for name, manifest := range hermesDeclaredEntrypointForms {
			t.Run(dir+"/"+name, func(t *testing.T) {
				f := newHermesPluginFixture(t)
				path := f.plugin(f.bundledRoot, "web/ddgs")
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(manifest.file)),
					strings.ReplaceAll(manifest.body, "DIR", dir))
				if manifest.alsoFile != "" {
					writePluginFile(t, filepath.Join(path, filepath.FromSlash(manifest.alsoFile)), manifest.alsoBody)
				}
				entry := filepath.Join(path, filepath.FromSlash(dir), "run.js")
				writePluginFile(t, entry, "safe()\n")
				f.w.runRescanCycle(context.Background())
				f.w.runRescanCycle(context.Background())
				if got := f.scan.scans(path); got != 1 {
					t.Fatalf("scans before the edit = %d, want 1", got)
				}
				writePluginFile(t, entry, "eval()\n")
				f.w.runRescanCycle(context.Background())
				if got := f.scan.scans(path); got != 2 {
					t.Fatalf("same-size edit to a declared entrypoint scans = %d, want 2", got)
				}
			})
		}
	}
}

// A declared bytecode-cache entrypoint added after the vendor baseline is
// admitted once; a later same-size edit is not covered by that admission.
func TestHermesCacheEntrypointAfterBenignAdmissionIsRescanned(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.plugin(f.bundledRoot, "web/ddgs")
	high := f.scan.findings[path]
	f.pinVendor("web/ddgs", path)
	f.scan.findings[path] = nil
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)

	writePluginFile(t, filepath.Join(path, "package.json"),
		`{"name":"p","version":"1.0.0","main":"__pycache__/run.js"}`)
	entry := filepath.Join(path, "__pycache__", "run.js")
	writePluginFile(t, entry, "safe()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 1 {
		t.Fatalf("benign admission scans = %d, want 1", got)
	}
	f.scan.findings[path] = high
	writePluginFile(t, entry, "exec()\n")
	f.w.runRescanCycle(context.Background())
	if got := f.scan.scans(path); got != 2 {
		t.Fatalf("same-size entrypoint edit scans = %d, want 2", got)
	}
	f.refused(path)
}

// Benign twin: a manifest that does not declare the cache file leaves it
// unhashed, so the generated bytecode Hermes rewrites is not a change.
func TestHermesUndeclaredBytecodeCacheStaysUnhashedWithManifest(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "package.json"), `{"name":"p","main":"lib/run.js","bin":{"p":"bin/p.js"}}`)
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: p\nentrypoint: lib/run.js\n")
	writePluginFile(t, filepath.Join(dir, "lib", "run.js"), "safe()\n")
	writePluginFile(t, filepath.Join(dir, "__pycache__", "run.cpython-312.pyc"), "one")
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "run.js"), "not declared")
	if got := skippedTreeHash(dir, hermesScannerLoader(t)); got != "" {
		t.Fatalf("undeclared cache files hashed: %q", got)
	}
	writePluginFile(t, filepath.Join(dir, "__pycache__", "run.cpython-312.pyc"), "two")
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "run.js"), "still not declared")
	if got := skippedTreeHash(dir, hermesScannerLoader(t)); got != "" {
		t.Fatalf("rewritten undeclared cache files hashed: %q", got)
	}
}

// A manifest the plugin scanner cannot decide (bytes that are not UTF-8 make a
// scan raise) may still be read by it, so every cache file is then treated as
// declared. A manifest the scanner refuses (text its loader rejects) declares
// nothing, as in a scan: ordinary cache writes beside it are not hashed.
func TestHermesUnparsedManifestHashesBytecodeCache(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "package.json"), "{\"main\": \"\xff\"}")
	writePluginFile(t, filepath.Join(dir, "__pycache__", "a.cpython-312.pyc"), "one")
	first := skippedTreeHash(dir, hermesScannerLoader(t))
	if first == "" {
		t.Fatal("cache file not hashed beside a manifest the scanner cannot decode")
	}
	writePluginFile(t, filepath.Join(dir, "__pycache__", "a.cpython-312.pyc"), "two")
	if skippedTreeHash(dir, hermesScannerLoader(t)) == first {
		t.Fatal("cache edit not seen beside a manifest the scanner cannot decode")
	}
}

func TestHermesRefusedManifestDeclaresNothing(t *testing.T) {
	for name, body := range map[string]string{"package.json": "{\"main\": ", "plugin.yaml": "name: [unclosed\n", "plugin.yml": "main: [unclosed\n"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginFile(t, filepath.Join(dir, name), body)
			writePluginFile(t, filepath.Join(dir, "__pycache__", "a.cpython-312.pyc"), "one")
			if got := skippedTreeHash(dir, hermesScannerLoader(t)); got != "" {
				t.Fatalf("cache file hashed beside a manifest the scanner refuses: %q", got)
			}
		})
	}
}

// A manifest naming a cache file through a link still binds that file.
func TestHermesDeclaredCacheEntrypointThroughLinkIsHashed(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "package.json"), `{"name":"p","main":"alias/run.js"}`)
	writePluginFile(t, filepath.Join(dir, "__pycache__", "run.js"), "safe()\n")
	if err := os.Symlink(filepath.Join(dir, "__pycache__"), filepath.Join(dir, "alias")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	first := skippedTreeHash(dir, hermesScannerLoader(t))
	writePluginFile(t, filepath.Join(dir, "__pycache__", "run.js"), "exec()\n")
	if skippedTreeHash(dir, hermesScannerLoader(t)) == first {
		t.Fatal("edit of a cache entrypoint declared through a link was not seen")
	}
}

// hermesManifestFiles lists the manifests the plugin scanner reads.
func TestHermesManifestFilesMatchScanner(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "scanner", "plugin_scanner", "scanner.py"))
	if err != nil {
		t.Skipf("plugin scanner: %v", err)
	}
	block := regexp.MustCompile(`(?s)_MANIFEST_CANDIDATES[^=]*=\s*\((.*?)\n\)`).FindSubmatch(src)
	if block == nil {
		t.Fatal("_MANIFEST_CANDIDATES not found in the plugin scanner")
	}
	join := regexp.MustCompile(`^\(os\.path\.join\("([^"]+)", "([^"]+)"\),`)
	plain := regexp.MustCompile(`^\("([^"]+)",`)
	var scanned []string
	for _, line := range strings.Split(string(block[1]), "\n") {
		line = strings.TrimSpace(line)
		if m := join.FindStringSubmatch(line); m != nil {
			scanned = append(scanned, m[1]+"/"+m[2])
		} else if m := plain.FindStringSubmatch(line); m != nil {
			scanned = append(scanned, m[1])
		}
	}
	ours := slices.Clone(hermesManifestFiles)
	slices.Sort(scanned)
	slices.Sort(ours)
	if len(scanned) == 0 || !slices.Equal(scanned, ours) {
		t.Fatalf("manifest files = %q, scanner reads %q", ours, scanned)
	}
}

// A manifest-declared entrypoint inside a bytecode cache is vendor content
// only while its bytes are the pinned ones: the digest hashes it, so an edit
// reaches admission and is scanned instead of being allowed as vendor bytes.
func TestHermesDeclaredEntrypointIsBoundByVendorDigest(t *testing.T) {
	for _, dir := range []string{"node_modules", "__pycache__", "lib/__pycache__"} {
		for name, manifest := range hermesDeclaredEntrypointForms {
			t.Run(dir+"/"+name, func(t *testing.T) {
				f := newHermesPluginFixture(t)
				path := f.plugin(f.bundledRoot, "web/ddgs")
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(manifest.file)),
					strings.ReplaceAll(manifest.body, "DIR", dir))
				if manifest.alsoFile != "" {
					writePluginFile(t, filepath.Join(path, filepath.FromSlash(manifest.alsoFile)), manifest.alsoBody)
				}
				entry := filepath.Join(path, filepath.FromSlash(dir), "run.js")
				writePluginFile(t, entry, "safe()\n")
				f.pinVendor("web/ddgs", path)
				f.w.runRescanCycle(context.Background())
				f.unscannedVendor(path)

				writePluginFile(t, entry, "exec()\n")
				f.w.runRescanCycle(context.Background())
				if got := f.scan.scans(path); got != 1 {
					t.Fatalf("same-size edit to a declared entrypoint scans = %d, want 1", got)
				}
				f.refused(path)
				if f.w.hermesVendorPlugin(InstallEvent{Type: InstallPlugin, Path: path}) {
					t.Fatal("an edited declared entrypoint still matches the vendor digest")
				}
			})
		}
	}
}

// hermesShadowedEntrypointForms are YAML manifests that name a generated
// cache file as an entrypoint in a pair PyYAML replaces: a later duplicate
// key, an explicit pair over a merged one, a merge key beneath a later one.
// The plugin scanner reads only lib/run.js from each, so a write to the cache
// file is not a change (GAP-0645 review 14).
var hermesShadowedEntrypointForms = map[string]string{
	"duplicate-main":             "name: p\nmain: DIR/provider.cpython-312.pyc\nmain: lib/run.js\n",
	"typed-int-key":              "name: p\nbin:\n  1: DIR/provider.cpython-312.pyc\n  !!int 1: lib/run.js\n",
	"typed-bool-key":             "name: p\nbin:\n  true: DIR/provider.cpython-312.pyc\n  !!bool true: lib/run.js\n",
	"typed-float-key":            "name: p\nbin:\n  1.0: DIR/provider.cpython-312.pyc\n  !!float 1.0: lib/run.js\n",
	"typed-null-key":             "name: p\nbin:\n  null: DIR/provider.cpython-312.pyc\n  !!null null: lib/run.js\n",
	"sexagesimal-key":            "name: p\nbin:\n  1:00: DIR/provider.cpython-312.pyc\n  60: lib/run.js\n",
	"infinity-key":               "name: p\nbin:\n  .inf: DIR/provider.cpython-312.pyc\n  +.Inf: lib/run.js\n",
	"date-key":                   "name: p\nbin:\n  2001-01-01: DIR/provider.cpython-312.pyc\n  !!timestamp 2001-1-1: lib/run.js\n",
	"string-key":                 "name: p\nbin:\n  p: DIR/provider.cpython-312.pyc\n  !!str p: lib/run.js\n",
	"duplicate-bin-key":          "name: p\nbin:\n  p: DIR/provider.cpython-312.pyc\n  p: lib/run.js\n",
	"same-number-bin-key":        "name: p\nbin:\n  1: DIR/provider.cpython-312.pyc\n  true: lib/run.js\n",
	"merge-overridden-main":      "name: p\n<<: {main: DIR/provider.cpython-312.pyc}\nmain: lib/run.js\n",
	"merge-after-explicit":       "name: p\nmain: lib/run.js\n<<: {main: DIR/provider.cpython-312.pyc}\n",
	"merge-overridden-bin":       "name: p\nbin:\n  <<: {p: DIR/provider.cpython-312.pyc}\n  p: lib/run.js\n",
	"merge-list-later":           "name: p\n<<: [{main: lib/run.js}, {main: DIR/provider.cpython-312.pyc}]\n",
	"merge-key-earlier":          "name: p\n<<: {main: DIR/provider.cpython-312.pyc}\n<<: {main: lib/run.js}\n",
	"datetime-z-offset-key":      "name: p\nbin:\n  2001-01-01T00:00:00Z: DIR/provider.cpython-312.pyc\n  2001-01-01T00:00:00+00:00: lib/run.js\n",
	"datetime-zone-shift-key":    "name: p\nbin:\n  2001-01-01T00:00:00Z: DIR/provider.cpython-312.pyc\n  2001-01-01T01:00:00+01:00: lib/run.js\n",
	"datetime-negative-zone-key": "name: p\nbin:\n  2001-01-01T00:00:00Z: DIR/provider.cpython-312.pyc\n  2000-12-31T23:00:00-01:00: lib/run.js\n",
	"datetime-fraction-key":      "name: p\nbin:\n  2001-01-01T00:00:00.1Z: DIR/provider.cpython-312.pyc\n  2001-01-01T00:00:00.100000+00:00: lib/run.js\n",
	"datetime-naive-key":         "name: p\nbin:\n  2001-01-01T00:00:00: DIR/provider.cpython-312.pyc\n  2001-1-1 0:00:00: lib/run.js\n",
	"merge-nested-lost":          "name: p\ni: &i\n  main: DIR/provider.cpython-312.pyc\nm: &m\n  <<: *i\n  main: lib/run.js\n<<: *m\n",
	"alias-lost":                 "name: p\nold: &o DIR/provider.cpython-312.pyc\nmain: *o\nmain: lib/run.js\n",
}

// Benign twin: text in a manifest that is not an entrypoint field, such as a
// description that names a generated cache file, declares nothing, so the
// cache Hermes writes is neither hashed into the vendor digest nor a change.
func TestHermesManifestProseDeclaresNothing(t *testing.T) {
	prose := map[string]struct{ file, body string }{
		"yaml-description":                  {"plugin.yaml", "name: p\ndescription: caches itself in DIR/provider.cpython-312.pyc\n"},
		"json-description":                  {"package.json", `{"name":"p","description":"see DIR/provider.cpython-312.pyc"}`},
		"launcher":                          {"plugin.json", `{"name":"p","launcher":{"path":"DIR/provider.cpython-312.pyc"}}`},
		"runtime":                           {"plugin.yaml", "name: p\nruntime:\n  - path: DIR/provider.cpython-312.pyc\n"},
		"nested":                            {"package.json", `{"name":"p","defenseclaw":{"entrypoint":"DIR/provider.cpython-312.pyc"}}`},
		"scripts":                           {"package.json", `{"name":"p","scripts":{"start":"DIR/provider.cpython-312.pyc"}}`},
		"entrypoints-list":                  {"package.json", `{"name":"p","entrypoints":["DIR/provider.cpython-312.pyc"]}`},
		"main-list":                         {"package.json", `{"name":"p","main":["DIR/provider.cpython-312.pyc"]}`},
		"bin-list":                          {"package.json", `{"name":"p","bin":["DIR/provider.cpython-312.pyc"]}`},
		"yaml-duplicate-keys":               {"plugin.yaml", "name: p\nname: p\ndescription: ordinary\n"},
		"yaml-numeric-key":                  {"plugin.yaml", "name: p\nprovides:\n  7: DIR/provider.cpython-312.pyc\n"},
		"yaml-bin-other-file":               {"plugin.yaml", "name: p\nbin:\n  7: lib/other.js\n  true: lib/more.js\n"},
		"yaml-bin-merge-prose":              {"plugin.yaml", "name: p\nshared: &s\n  note: DIR/provider.cpython-312.pyc\nprovides:\n  <<: *s\n"},
		"json-nan":                          {"package.json", `{"name":"p","version":NaN}`},
		"json-trailing-comma":               {"package.json", `{"name":"p","main":"DIR/provider.cpython-312.pyc",}`},
		"json-single-quotes":                {"package.json", "{'name':'p','main':'DIR/provider.cpython-312.pyc'}"},
		"json-yaml-object":                  {"package.json", "name: p\nmain: DIR/provider.cpython-312.pyc\n"},
		"json-truncated":                    {"plugin.json", `{"name":"p","main":"DIR/provider.cpython-312.pyc"`},
		"json-comment":                      {"manifest.json", `{"name":"p","main":"DIR/provider.cpython-312.pyc"} // x`},
		"yaml-unhashable-key":               {"plugin.yaml", "name: p\nbin:\n  ? [a, b]\n  : DIR/provider.cpython-312.pyc\n"},
		"yaml-second-document":              {"plugin.yaml", "main: DIR/provider.cpython-312.pyc\n---\nname: p\n"},
		"yaml-unknown-tag":                  {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: !custom y\n"},
		"yaml-bad-merge":                    {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\n<<: 5\n"},
		"yaml-timestamp-offset-24":          {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: 2001-01-01T00:00:00+24:00\n"},
		"yaml-timestamp-offset-negative-24": {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: 2001-01-01T00:00:00-24:00\n"},
		"yaml-timestamp-offset-2360":        {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: 2001-01-01T00:00:00+23:60\n"},
		"yaml-timestamp-offset-9999":        {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: 2001-01-01T00:00:00+99:99\n"},
		"yaml-timestamp-hour-24":            {"plugin.yaml", "name: p\nmain: DIR/provider.cpython-312.pyc\nx: 2001-01-01T24:00:00Z\n"},
		"yaml-timestamp-key-offset-24":      {"plugin.yaml", "name: p\nbin:\n  2001-01-01T00:00:00+24:00: DIR/provider.cpython-312.pyc\n"},
		"yaml-nested-main":                  {"plugin.yaml", "name: p\nprovides:\n  main: DIR/provider.cpython-312.pyc\n"},
	}
	for name, body := range hermesShadowedEntrypointForms {
		prose["yaml-shadowed-"+name] = struct{ file, body string }{"plugin.yaml", body}
	}
	for _, dir := range []string{"__pycache__", "lib/__pycache__"} {
		for name, manifest := range prose {
			t.Run(dir+"/"+name, func(t *testing.T) {
				f := newHermesPluginFixture(t)
				path := f.plugin(f.bundledRoot, "web/ddgs")
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(manifest.file)),
					strings.ReplaceAll(manifest.body, "DIR", dir))
				before, err := hermesPluginTreeDigest(path, hermesScannerLoader(t))
				if err != nil {
					t.Fatal(err)
				}
				f.w.runRescanCycle(context.Background())
				f.w.runRescanCycle(context.Background())
				if got := f.scan.scans(path); got != 1 {
					t.Fatalf("first-sight scans = %d, want 1", got)
				}
				admissions := len(f.admitted[path])

				writePluginFile(t, filepath.Join(path, filepath.FromSlash(dir), "provider.cpython-312.pyc"), "cache one")
				f.w.runRescanCycle(context.Background())
				writePluginFile(t, filepath.Join(path, filepath.FromSlash(dir), "provider.cpython-312.pyc"), "cache two")
				f.w.runRescanCycle(context.Background())
				if got := f.scan.scans(path); got != 1 {
					t.Fatalf("generated cache file caused a scan: %d scans", got)
				}
				if got := len(f.admitted[path]); got != admissions {
					t.Fatalf("generated cache file caused %d admissions", got-admissions)
				}
				if after, err := hermesPluginTreeDigest(path, hermesScannerLoader(t)); err != nil || after != before {
					t.Fatalf("generated cache file changed the vendor digest: %v", err)
				}
				if extra := skippedTreeHash(path, hermesScannerLoader(t)); extra != "" {
					t.Fatalf("generated cache file hashed: %q", extra)
				}
			})
		}
	}
}
