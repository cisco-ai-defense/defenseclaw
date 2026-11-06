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

// unscannedVendor requires a never-scanned shipped plugin with a baseline.
func (f *hermesPluginFixture) unscannedVendor(path string) {
	f.t.Helper()
	if n := f.scan.scans(path); n != 0 {
		f.t.Fatalf("vendor plugin %s scanned %d times", path, n)
	}
	f.vendorBaseline(path)
}

// vendorBaseline requires a shipped-plugin baseline for path, marked with
// the content hash of its current bytes.
func (f *hermesPluginFixture) vendorBaseline(path string) {
	f.t.Helper()
	row, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil || row == nil {
		f.t.Fatalf("vendor plugin %s has no baseline: %v", path, err)
	}
	snap, err := SnapshotTarget(path)
	if err != nil {
		f.t.Fatal(err)
	}
	if row.ContentHash != snap.ContentHash || !strings.HasSuffix(row.ScannerFingerprint, hermesVendorMark+snap.ContentHash) {
		f.t.Fatalf("vendor plugin %s baseline = %#v, want content %s marked", path, row, snap.ContentHash)
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
	digest, _, err := hermesPluginTreeDigest(path)
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
// digest is not scanned or alerted on a fresh account but gets a baseline;
// every scanned Hermes plugin is attributed to hermes, and a changed shipped
// plugin is admitted as a changed plugin with a baseline is.
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
	// baseline makes it a change, so install admission decides it.
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
	// The baseline records the bytes that matched, not the later ones.
	if row, err := f.store.GetTargetSnapshot("plugin", linked); err != nil || row == nil ||
		!strings.HasSuffix(row.ScannerFingerprint, hermesVendorMark+row.ContentHash) {
		t.Fatalf("restored vendor plugin baseline = %#v, %v", row, err)
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
	sameContent := func(content string) {
		t.Helper()
		snap, err := SnapshotTarget(dir)
		if err != nil || snap.ContentHash != content {
			t.Fatalf("content hash %s, snapshot %#v, %v", content, snap, err)
		}
	}
	base, content, err := hermesPluginTreeDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	sameContent(content)
	seen := []string{base}
	for _, change := range []func(){
		func() { writePluginFile(t, filepath.Join(dir, "lib", "a.py"), "A = 2\n") },
		func() { writePluginFile(t, filepath.Join(dir, "lib", "b.py"), "") },
		func() { writePluginFile(t, filepath.Join(dir, ".hidden"), "") },
		func() { writePluginFile(t, filepath.Join(dir, "node_modules", "x.js"), "") },
	} {
		change()
		got, content, err := hermesPluginTreeDigest(dir)
		if err != nil {
			t.Fatal(err)
		}
		sameContent(content)
		if slices.Contains(seen, got) {
			t.Fatalf("digest did not change: %s", got)
		}
		seen = append(seen, got)
	}
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "a.pyc"), "cache")
	if got, _, err := hermesPluginTreeDigest(dir); err != nil || got != seen[len(seen)-1] {
		t.Fatalf("bytecode cache changed the digest: %s, %v", got, err)
	}
	writePluginFile(t, filepath.Join(dir, "lib", "__pycache__", "x.node"), "native")
	if _, _, err := hermesPluginTreeDigest(dir); err == nil {
		t.Fatal("a native payload in a bytecode cache produced a vendor digest")
	}
	if err := os.Remove(filepath.Join(dir, "lib", "__pycache__", "x.node")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "plugin.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, _, err := hermesPluginTreeDigest(dir); err == nil {
		t.Fatal("a linked entry produced a vendor digest")
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
// admitted on the live path without a scan, and its baseline makes a later
// edit an admission; an edited shipped plugin is scanned and refused there.
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

// GAP-0645 review 5: a shipped-plugin baseline never had a scan, so content
// other than the bytes that matched the digest is admitted. That holds when
// the snapshot stored with the mark describes other bytes than the ones
// that matched, and when scan gating is off.
func TestRescanHermesVendorBaselineAdmitsOtherContent(t *testing.T) {
	t.Run("mark of other bytes", func(t *testing.T) {
		f := newHermesPluginFixture(t)
		path := f.plugin(f.bundledRoot, "kanban")
		f.pinVendor("kanban", path)
		_, verified, err := hermesPluginTreeDigest(path)
		if err != nil {
			t.Fatal(err)
		}
		writePluginFile(t, filepath.Join(path, "provider.py"), "VENDOR = False\n")
		snap, err := SnapshotTarget(path)
		if err != nil {
			t.Fatal(err)
		}
		evt := InstallEvent{Type: InstallPlugin, Name: "kanban", Path: path, Connector: "hermes"}
		if err := f.store.SetTargetSnapshot("plugin", path, snap.ContentHash, "{}", "{}", "[]", "",
			f.w.scannerFingerprint(evt)+hermesVendorMark+verified); err != nil {
			t.Fatal(err)
		}
		f.w.startupRescanDone = true
		f.w.runRescanCycle(context.Background())
		if f.scan.scans(path) != 1 {
			t.Fatalf("plugin scans = %d, want 1", f.scan.scans(path))
		}
		f.refused(path)
	})
	t.Run("gating off", func(t *testing.T) {
		f := newHermesPluginFixture(t)
		f.cfg.Watch.RescanContentGated = false
		path := f.plugin(f.bundledRoot, "kanban")
		f.pinVendor("kanban", path)
		f.w.runRescanCycle(context.Background())
		f.w.runRescanCycle(context.Background())
		f.unscannedVendor(path)
		writePluginFile(t, filepath.Join(path, "provider.py"), "VENDOR = False\n")
		f.w.runRescanCycle(context.Background())
		if f.scan.scans(path) != 1 {
			t.Fatalf("plugin scans = %d, want 1", f.scan.scans(path))
		}
		f.refused(path)
	})
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
// pristine shipped plugin that gains one is admitted, whichever folder it
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
