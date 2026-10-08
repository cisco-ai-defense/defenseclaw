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

package manager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// In-sandbox AI discovery. While a sandbox is ready, what its agent installed
// and configured in it (MCP servers, skills, plugins, CLIs, packages, shell
// history mentions, running agents) is inventoried like a user's home: the
// collector (collector.go) reads it, ScanSandboxRoot scans the tree it
// answered (removed once scanned), and the scan record under
// <data_dir>/sandboxes/<name>/discovery joins the gateway's AI
// discovery on its next full scan, attributed to the sandbox. A scan runs once
// the sandbox is ready and checked, every ai_discovery.scan_interval_min while
// it stays ready, and on demand (Discover: `defenseclaw sandbox discover`).
// A stop keeps the record, so what was found stays seen, without its
// processes, which the stop ended; a delete removes it. ai_discovery.enabled
// false turns it off.

const (
	// discoveryTimeout bounds one collector exec; discoveryScanTimeout the
	// whole scan, the host side included.
	discoveryTimeout     = 30 * time.Second
	discoveryScanTimeout = 2 * time.Minute
	// observeFirstDelay is when the first scan of a sandbox found ready runs
	// on its own: a create or start asks for it at once once the sandbox
	// passed its check (observeNow), a daemon that restarts finds it ready.
	observeFirstDelay = time.Minute
	// discoverySlow is the scan time a log line reports.
	discoverySlow = 3 * time.Second
)

// observeRun is the running observer of a ready sandbox: its discovery
// cadence and, with the process tree on, its process samples.
type observeRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	// now asks for a discovery at once.
	now chan struct{}
}

// discoveryCatalog is the AI signature catalog the scans of a configuration
// use, loaded once per configuration snapshot.
type discoveryCatalog struct {
	mu      sync.Mutex
	cfg     *config.Config
	catalog []inventory.AISignature
	err     error
}

func (c *discoveryCatalog) get(cfg *config.Config) ([]inventory.AISignature, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg != cfg || (c.catalog == nil && c.err == nil) {
		c.cfg = cfg
		c.catalog, c.err = inventory.LoadAISignaturesForConfig(cfg)
	}
	return c.catalog, c.err
}

// syncObserve runs the sandbox's observer while it is ready and ends it
// otherwise. A stop drops the processes from its scan record: the stop
// ended them. A stop or a delete ends its process tree. Callers must not
// hold Manager.mu.
func (m *Manager) syncObserve(b *box, phase audit.SandboxPhase) {
	m.mu.Lock()
	want := phase == audit.SandboxPhaseReady && !b.deleted && !b.retained && !b.creating
	running := b.observe != nil
	name := b.rec.Name
	m.mu.Unlock()
	switch {
	case want && !running:
		m.startObserve(b)
	case !want && running:
		m.endObserve(b)
	}
	switch {
	case stoppedWorkload(phase):
		m.dropDiscoveredProcesses(name)
		m.endProcessTree(b)
	case phase == audit.SandboxPhaseDeleted:
		m.endProcessTree(b)
	}
}

func (m *Manager) startObserve(b *box) {
	runCtx := m.running()
	if runCtx == nil {
		return
	}
	m.mu.Lock()
	if b.observe != nil || b.deleted {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(runCtx)
	run := &observeRun{cancel: cancel, done: make(chan struct{}), now: make(chan struct{}, 1)}
	b.observe = run
	m.mu.Unlock()
	go func() {
		defer close(run.done)
		defer cancel()
		m.observeLoop(ctx, b, run)
	}()
}

// endObserve ends the observer without waiting for it.
func (m *Manager) endObserve(b *box) {
	m.mu.Lock()
	run := b.observe
	b.observe = nil
	m.mu.Unlock()
	if run != nil {
		run.cancel()
	}
}

// stopObserve ends the observer for good and waits for it.
func (m *Manager) stopObserve(b *box) {
	m.mu.Lock()
	run := b.observe
	b.observe = nil
	m.mu.Unlock()
	if run != nil {
		run.cancel()
		<-run.done
	}
}

// observeNow asks the sandbox's observer for a discovery at once: a create
// or start made it ready and its check passed.
func (m *Manager) observeNow(b *box) {
	m.mu.Lock()
	run := b.observe
	m.mu.Unlock()
	if run == nil {
		return
	}
	select {
	case run.now <- struct{}{}:
	default:
	}
}

func (m *Manager) observeLoop(ctx context.Context, b *box, run *observeRun) {
	next := time.NewTimer(observeFirstDelay)
	defer next.Stop()
	sample := time.NewTimer(processSampleInterval)
	defer sample.Stop()
	slow := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-run.now:
			m.scheduledDiscovery(ctx, b)
			next.Reset(m.discoveryInterval())
		case <-next.C:
			m.scheduledDiscovery(ctx, b)
			next.Reset(m.discoveryInterval())
		case <-sample.C:
			// One exec a sample, and none while the tree is off.
			took, sampled := m.sampleProcesses(ctx, b)
			var interval time.Duration
			interval, slow = m.paceSamples(b, took, sampled, slow, m.driverName())
			sample.Reset(interval)
		}
	}
}

// paceSamples is the interval to the next process sample after one that
// took took (sampled: it ran) on driver: processSampleInterval, and on the
// vm driver, where every exec crosses into a MicroVM, processSampleIntervalVM
// from the first slow sample on (slow) for the rest of the session. The
// process list reports the pace.
func (m *Manager) paceSamples(b *box, took time.Duration, sampled, slow bool, driver openshell.ComputeDriver) (time.Duration, bool) {
	if sampled && !slow && took > processSampleSlow && driver == openshell.DriverVM {
		slow = true
		m.logf("sandbox %s: a process sample took %s on the vm driver; its processes are sampled every %s instead of %s",
			b.name(m), took.Round(time.Millisecond), processSampleIntervalVM, processSampleInterval)
	}
	interval := processSampleInterval
	if slow {
		interval = processSampleIntervalVM
	}
	if sampled {
		m.setSampleInterval(b, interval)
	}
	return interval, slow
}

// driverName is the compute driver of the connected gateway, empty while
// none answered.
func (m *Manager) driverName() openshell.ComputeDriver {
	if d := m.gwDriver.Load(); d != nil {
		return d.Name
	}
	return ""
}

// name is the box's sandbox name.
func (b *box) name(m *Manager) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return b.rec.Name
}

// discoveryInterval is ai_discovery.scan_interval_min, at least a minute.
func (m *Manager) discoveryInterval() time.Duration {
	d := time.Duration(m.config().AIDiscovery.ScanIntervalMin) * time.Minute
	if d < time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// scheduledDiscovery runs a discovery the cadence asked for; failures are
// logged, and the last record stays.
func (m *Manager) scheduledDiscovery(ctx context.Context, b *box) {
	if !m.config().AIDiscovery.Enabled {
		return
	}
	res, err := m.discover(ctx, b)
	if err != nil {
		if ctx.Err() == nil {
			m.logf("sandbox %s: AI discovery: %v", b.name(m), err)
		}
		return
	}
	if res.DurationMs > discoverySlow.Milliseconds() {
		m.logf("sandbox %s: AI discovery took %dms", res.Name, res.DurationMs)
	}
}

// Discover runs the AI discovery of a ready sandbox now and returns what it
// found (POST /sandboxes/{name}/discover).
func (m *Manager) Discover(ctx context.Context, name string) (*sandboxapi.DiscoveryResult, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	if !m.config().AIDiscovery.Enabled {
		return nil, sandboxapi.Errorf(sandboxapi.CodeDisabled,
			"AI discovery is off (ai_discovery.enabled: false); turn it on with `defenseclaw agent discovery enable`")
	}
	return m.discover(ctx, b)
}

// discover runs one discovery of a ready sandbox: one collector exec, the
// tree it answered written under the sandbox's discovery folder, the scan of
// that tree, and the scan record. Discoveries of a sandbox never overlap,
// and a release of the sandbox (cleanup) waits for the one running: none
// writes after it.
func (m *Manager) discover(ctx context.Context, b *box) (*sandboxapi.DiscoveryResult, error) {
	b.discoverMu.Lock()
	defer b.discoverMu.Unlock()
	start := m.now()
	ctx, cancel := context.WithTimeout(ctx, discoveryScanTimeout)
	defer cancel()
	m.mu.Lock()
	rec := b.rec
	ready := b.phase == audit.SandboxPhaseReady && !b.creating && !b.deleted && !b.retained && !b.discoveryReleased
	id := b.sandboxID()
	m.mu.Unlock()
	if !ready {
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s is not running; start it first", rec.Name)
	}
	if !openshell.ValidSandboxName(rec.Name) || rec.Name == recordDirName {
		return nil, fmt.Errorf("%w: sandbox %q", openshell.ErrInvalidName, rec.Name)
	}
	cfg := m.config()
	catalog, err := m.signatures.get(cfg)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "load the AI signature catalog: %v", err)
	}
	opts := inventory.SandboxScanOptionsFromConfig(cfg)
	// A mounted project is the host's own folder, which the host's scan
	// reads; only a copy's manifests are the sandbox's.
	opts.IncludePackageManifests = opts.IncludePackageManifests && rec.WorkdirMode == config.OpenShellWorkdirCopy
	scan := inventory.SandboxScan{Home: connector.SandboxHomeDir, Variables: sandboxDiscoveryVariables()}
	if w := rec.Workdir; w != "" && path.IsAbs(w) && path.Clean(w) == w {
		scan.Workspace = w
	}
	plan, err := inventory.PlanSandboxScan(scan, opts, catalog)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "plan the discovery of sandbox %s: %v", rec.Name, err)
	}
	pairs, scope := collectPlan(plan, rec.Harness)
	scope.maxFiles = min(opts.MaxFilesPerScan, collectMaxEntries)
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	res, err := m.ownExec(ctx, gw, rec.Name, collectArgv("discover", opts.MaxFileBytes, pairs), openshell.ExecOptions{
		Timeout: discoveryTimeout, Idempotent: true, MaxOutputBytes: collectStreamBytes,
	})
	if err != nil {
		m.dropGateway(gw, err)
		return nil, upstream("read sandbox "+rec.Name+" for AI discovery", err)
	}
	col, err := parseCollection(res.Stdout, res.Truncated, scope, opts.MaxFileBytes)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeUpstream, "sandbox %s: %v (exit status %d)", rec.Name, err, res.ExitCode)
	}
	dir := m.discoveryDir(rec.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "sandbox %s: %v", rec.Name, err)
	}
	root := filepath.Join(dir, inventory.SandboxTreeDirName)
	// The tree holds copies of the sandbox's files (its MCP configurations,
	// its shell history's tail): it goes once scanned, and only the scan
	// record stays.
	defer func() {
		if err := removeTree(root); err != nil && !errors.Is(err, fs.ErrNotExist) {
			m.logf("sandbox %s: remove the discovery tree: %v", rec.Name, err)
		}
	}()
	if _, err := writeCollectedTree(root, col); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "sandbox %s: write the discovery tree: %v", rec.Name, err)
	}
	scan.Root = root
	scan.Problems = col.Problems
	scan.EnvNames = col.EnvNames
	scan.Executables = map[string]string{}
	for name, e := range col.Executables {
		scan.Executables[name] = e.Path
	}
	for _, p := range col.Processes {
		sp := inventory.SandboxProcess{PID: p.PID, PPID: p.PPID, Comm: p.Comm, Exe: p.Exe, Argv0Target: p.Argv0Target, StartedAt: col.started(p)}
		if len(p.Args) > 0 {
			sp.Argv0 = p.Args[0]
		}
		scan.Processes = append(scan.Processes, sp)
	}
	report, err := inventory.ScanSandboxRoot(ctx, scan, opts, catalog)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "scan sandbox %s: %v", rec.Name, err)
	}
	m.mu.Lock()
	stillReady := b.phase == audit.SandboxPhaseReady && !b.deleted
	m.mu.Unlock()
	if !stillReady {
		// The sandbox stopped while it was read: its processes ended with it
		// (dropDiscoveredProcesses ran already).
		report.Signals = slices.DeleteFunc(report.Signals, func(sig inventory.AISignal) bool { return sig.Detector == "process" })
	}
	record := inventory.SandboxScanRecord{SandboxID: id, SandboxName: rec.Name, UpdatedAt: m.now().UTC(), Report: report}
	if err := inventory.WriteSandboxScanRecord(m.scanRecordPath(rec.Name), record); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "sandbox %s: save the discovery record: %v", rec.Name, err)
	}
	return discoveryResult(rec.Name, report, len(col.Entries), m.now().Sub(start)), nil
}

// sandboxDiscoveryVariables are the sandbox's values of the catalog's $VAR
// paths. The collector reads environment variable names only, never values,
// so these are the folders the harness launchers use: HOME, CODEX_HOME's
// default and the HERMES_HOME the Hermes launcher pins.
func sandboxDiscoveryVariables() map[string]string {
	home := connector.SandboxHomeDir
	return map[string]string{"HOME": home, "CODEX_HOME": home + "/.codex", "HERMES_HOME": home + "/.hermes"}
}

// collectPlan turns a scan plan into the collector's KIND VALUE pairs and the
// scope its answer is checked against. Paths outside the collector's roots
// are left out: their records would be refused anyway.
func collectPlan(plan inventory.SandboxCandidates, harnessName string) ([]string, *collectScope) {
	scope := newCollectScope()
	var pairs []string
	keep := func(p string) bool { _, ok := cleanCollectPath(p); return ok && scope.inRoots(p) }
	for _, p := range plan.Stat {
		if keep(p) {
			scope.exact[p] = true
			pairs = append(pairs, "S", p)
		}
	}
	for _, d := range plan.Dirs {
		if keep(d.Path) {
			depth := min(max(d.Depth, 1), 3)
			scope.dirs[d.Path] = depth
			pairs = append(pairs, fmt.Sprintf("D%d", depth), d.Path)
		}
	}
	for _, p := range plan.Read {
		if keep(p) {
			scope.exact[p], scope.content[p] = true, true
			pairs = append(pairs, "C", p)
		}
	}
	for _, p := range plan.History {
		if keep(p) {
			scope.exact[p], scope.content[p] = true, true
			pairs = append(pairs, "H", p)
		}
	}
	for _, w := range plan.Walk {
		if keep(w) {
			scope.walks = append(scope.walks, w)
			pairs = append(pairs, "W", w)
		}
	}
	if len(scope.walks) > 0 {
		for _, m := range plan.Manifests {
			scope.manifests[m] = true
			pairs = append(pairs, "M", m)
		}
		for _, s := range plan.ManifestSuffixes {
			scope.suffixes = append(scope.suffixes, strings.ToLower(s))
			pairs = append(pairs, "U", s)
		}
		for _, s := range plan.SkipDirs {
			pairs = append(pairs, "K", s)
		}
	}
	dirs := append([]string(nil), sandboxExecutableDirs...)
	if spec, ok := harness.Get(harnessName); ok {
		dirs = append(dirs, path.Join(spec.InstallRoot(), "bin"))
	}
	for _, d := range dirs {
		scope.exeDirs[d] = true
		pairs = append(pairs, "R", d)
	}
	for _, name := range plan.Binaries {
		scope.binaries[name] = true
		pairs = append(pairs, "N", name)
	}
	if plan.EnvNames {
		scope.envNames = true
		pairs = append(pairs, "O", "env")
	}
	return pairs, scope
}

// discoveryNames splits a signal's evidence into the components it names
// (a skills folder's entries, an MCP config's servers) and the files and
// folders it was found in, which `sandbox discover` listed as names too
// (GAP-0116). A signal without evidence records keeps its basenames as
// evidence.
func discoveryNames(sig inventory.AISignal) (names, evidence []string) {
	if len(sig.Evidence) == 0 {
		return nil, sig.Basenames
	}
	for _, ev := range sig.Evidence {
		switch {
		case ev.Basename == "":
		case ev.Type == "mcp_server" || strings.HasSuffix(ev.Type, "_entry"):
			names = appendNew(names, ev.Basename)
		default:
			evidence = appendNew(evidence, ev.Basename)
		}
	}
	return names, evidence
}

func appendNew(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// discoveryResult is the API view of a sandbox scan's report.
func discoveryResult(name string, report inventory.AIDiscoveryReport, entries int, took time.Duration) *sandboxapi.DiscoveryResult {
	out := &sandboxapi.DiscoveryResult{
		Name: name, ScannedAt: report.Summary.ScannedAt, DurationMs: took.Milliseconds(), Result: report.Summary.Result,
		Entries: entries, Files: report.Summary.FilesScanned, Signals: []sandboxapi.DiscoverySignal{},
	}
	for detector, detail := range report.Summary.DetectorErrors {
		out.Problems = append(out.Problems, sandboxapi.DisplayText(detector+": "+detail))
	}
	sort.Strings(out.Problems)
	for _, sig := range report.Signals {
		names, evidence := discoveryNames(sig)
		out.Signals = append(out.Signals, sandboxapi.DiscoverySignal{
			Category: sig.Category, Product: sandboxapi.DisplayText(sig.Product), Vendor: sandboxapi.DisplayText(sig.Vendor),
			Detector: sig.Detector, Names: sandboxapi.DisplayTexts(names), Evidence: sandboxapi.DisplayTexts(evidence),
			Confidence: sig.Confidence,
		})
	}
	sort.SliceStable(out.Signals, func(i, j int) bool {
		a, b := out.Signals[i], out.Signals[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		return a.Detector < b.Detector
	})
	return out
}

// discoveryDir is <data_dir>/sandboxes/<name>/discovery.
func (m *Manager) discoveryDir(name string) string {
	return filepath.Join(m.opts.DataDir, "sandboxes", name, inventory.SandboxDiscoveryDirName)
}

func (m *Manager) scanRecordPath(name string) string {
	return inventory.SandboxScanRecordPath(filepath.Join(m.opts.DataDir, "sandboxes"), name)
}

// dropDiscoveredProcesses rewrites a stopped sandbox's scan record without
// its process signals: the stop ended those processes, and the rest of what
// was found stays seen.
func (m *Manager) dropDiscoveredProcesses(name string) {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return
	}
	p := m.scanRecordPath(name)
	record, err := inventory.ReadSandboxScanRecord(p)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.logf("sandbox %s: read its discovery record: %v", name, err)
		}
		return
	}
	kept := record.Report.Signals[:0]
	for _, sig := range record.Report.Signals {
		if sig.Detector != "process" {
			kept = append(kept, sig)
		}
	}
	if len(kept) == len(record.Report.Signals) {
		return
	}
	record.Report.Signals = kept
	record.Report.Summary.TotalSignals, record.Report.Summary.ActiveSignals = len(kept), len(kept)
	if err := inventory.WriteSandboxScanRecord(p, record); err != nil {
		m.logf("sandbox %s: drop the stopped processes from its discovery record: %v", name, err)
	}
}

// removeDiscovery removes a gone sandbox's discovery folder: its tree and
// scan record, whose signals then go (DiscoveryRemoved tells the AI
// inventory).
func (m *Manager) removeDiscovery(name string) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return nil
	}
	_, err := os.Lstat(m.scanRecordPath(name))
	recorded := err == nil
	if err := removeTree(m.discoveryDir(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the discovery record of %s: %w", name, err)
	}
	if recorded && m.opts.DiscoveryRemoved != nil {
		m.opts.DiscoveryRemoved(name)
	}
	return nil
}
