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

//go:build !windows

package manager

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const (
	testOwner       = "0123456789abcdef"
	testIngressPort = 18971
	testEgressPort  = 18972
	testClaudeBin   = "/opt/defenseclaw-harness/claudecode/bin/claude"
)

// TestMain pins this machine's interface addresses: the egress guard refuses
// ranges and literals that hold them, so verdicts must not depend on the
// machine. The public addresses' subnets are the "local network".
func TestMain(m *testing.M) {
	restore := egress.OverrideInterfaceAddrsForTest(func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
			&net.IPNet{IP: net.ParseIP("185.199.9.9"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2a00:1450:9::fe"), Mask: net.CIDRMask(64, 128)},
		}, nil
	})
	code := m.Run()
	restore()
	os.Exit(code)
}

func boolPtr(v bool) *bool { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// writeFile writes data to p, making its directories.
func writeFile(t *testing.T, p, data string) string {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(data), 0o644))
	return p
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func wantCode(t *testing.T, err error, code string) *sandboxapi.Error {
	t.Helper()
	var e *sandboxapi.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
	return e
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// where returns the elements of *list, read under mu, that match (all for nil).
func where[T any](mu *sync.Mutex, list *[]T, match func(T) bool) []T {
	mu.Lock()
	defer mu.Unlock()
	var out []T
	for _, v := range *list {
		if match == nil || match(v) {
			out = append(out, v)
		}
	}
	return out
}

// fakeImages hands out one verified record.
type fakeImages struct {
	mu  sync.Mutex
	rec image.Record
	err error
	// fixedUID keeps rec's UID/GID instead of the build spec's.
	fixedUID bool
}

func (f *fakeImages) Resolve(_ context.Context, spec image.BuildSpec, _ bool) (image.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return image.Record{}, f.err
	}
	rec := f.rec
	rec.Connector = spec.Harness.Name
	if !f.fixedUID {
		rec.UID, rec.GID = spec.UID, spec.GID
	}
	return rec, nil
}

// fakeWorkspace records workspace calls and plans a mount under /work.
type fakeWorkspace struct {
	mu                                 sync.Mutex
	planErr, snapErr                   error
	planned, released, deleted, undone []string
	snapshots                          map[string]*workspace.SnapshotRecord
	masked                             []workspace.MaskedPath
	lastSnapshot                       workspace.SnapshotOptions
	lastMount, lastScan                workspace.MountOptions
	lastUndo                           workspace.UndoOptions
	clean                              bool // Review reports a folder without changes
	onUndo, onDeleteSnapshot           func(ctx context.Context)
	scanned                            []workspace.MaskedPath // ScanSecrets' answer (default: masked)
	scanErr                            error
}

func (f *fakeWorkspace) PlanMount(_ context.Context, opts workspace.MountOptions) (*workspace.MountPlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.planErr != nil {
		return nil, f.planErr
	}
	f.planned = append(f.planned, opts.Name)
	f.lastMount = opts
	repo := workspace.RepoName(opts.Project)
	target := path.Join("/work", repo)
	return &workspace.MountPlan{
		Name: opts.Name, Project: opts.Project, RepoName: repo, Target: target,
		Mounts: []workspace.Mount{
			{Kind: workspace.MountProject, Source: opts.Project, Target: target},
			{Kind: workspace.MountProtect, Source: filepath.Join(opts.Project, ".git", "hooks"), Target: target + "/.git/hooks", ReadOnly: true},
		},
		Masked: f.masked, ReadWrite: []string{target}, Labels: map[string]string{},
	}, nil
}

func (f *fakeWorkspace) ScanSecrets(_ context.Context, opts workspace.MountOptions) ([]workspace.MaskedPath, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastScan = opts
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	if f.scanned != nil {
		return f.scanned, nil
	}
	return f.masked, nil
}

func (f *fakeWorkspace) ReleaseMount(_, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, name)
	return nil
}

func (f *fakeWorkspace) Snapshot(_ context.Context, opts workspace.SnapshotOptions) (*workspace.SnapshotRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	f.lastSnapshot = opts
	rec := &workspace.SnapshotRecord{Name: opts.Name, Project: opts.Project, Kind: workspace.SnapshotGit, CreatedAt: time.Now(),
		Git: &workspace.GitSnapshot{Ref: "refs/defenseclaw/pre/" + opts.Name}}
	f.snapshots[opts.Name] = rec
	return rec, nil
}

func (f *fakeWorkspace) LoadSnapshot(_, name string) (*workspace.SnapshotRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec, ok := f.snapshots[name]; ok {
		return rec, nil
	}
	return nil, workspace.ErrSnapshotNotFound
}

func (f *fakeWorkspace) DeleteSnapshot(ctx context.Context, _, name string) error {
	if f.onDeleteSnapshot != nil {
		f.onDeleteSnapshot(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	delete(f.snapshots, name)
	return nil
}

func (f *fakeWorkspace) Undo(ctx context.Context, opts workspace.UndoOptions) (*workspace.UndoResult, error) {
	if f.onUndo != nil {
		f.onUndo(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.undone = append(f.undone, opts.Name)
	f.lastUndo = opts
	if rec, ok := f.snapshots[opts.Name]; ok && !opts.Preview {
		undone := *rec
		at := time.Now().UTC()
		undone.UndoneAt = &at
		f.snapshots[opts.Name] = &undone
	}
	return &workspace.UndoResult{Name: opts.Name, Preview: opts.Preview, Changes: []workspace.TreeChange{{Path: "README.md"}}}, nil
}

func (f *fakeWorkspace) Review(_ context.Context, opts workspace.ReviewOptions) (*workspace.ReviewReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clean {
		return &workspace.ReviewReport{Name: opts.Name}, nil
	}
	return &workspace.ReviewReport{Name: opts.Name, FilesChanged: 2, Insertions: 5, Deletions: 1,
		Flags: []workspace.Flag{{Path: "package.json", Label: "package.json#scripts.postinstall", Severity: workspace.SeverityHigh}}}, nil
}

func (f *fakeWorkspace) ReviewDiff(context.Context, string, string) ([]byte, error) {
	return []byte("diff --git a/README.md b/README.md\n"), nil
}

func (f *fakeWorkspace) DeleteCopy(string, string) error { return nil }

// fakeImporter imports profiles into the fake gateway through the SDK.
type fakeImporter struct {
	c                 openshell.Client
	mu                sync.Mutex
	imported, updated []string
	err               error
	calls             int
	// before runs ahead of each import or update, without the lock (another
	// daemon changing the gateway under this one).
	before func(p profiles.Profile, resourceVersion uint64)
}

func (f *fakeImporter) Import(ctx context.Context, _ string, p profiles.Profile, resourceVersion uint64) error {
	f.mu.Lock()
	f.calls++
	before := f.before
	f.mu.Unlock()
	if before != nil {
		before(p, resourceVersion)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	item := openshell.ProfileImportItem{Profile: p.Spec, Source: "test"}
	if resourceVersion != 0 {
		f.updated = append(f.updated, p.ID)
		_, err := f.c.UpdateProfile(ctx, p.ID, resourceVersion, item)
		return err
	}
	f.imported = append(f.imported, p.ID)
	res, err := f.c.ImportProfiles(ctx, []openshell.ProfileImportItem{item})
	if err == nil && !res.Imported {
		err = errors.New("profile import rejected")
	}
	return err
}

func (f *fakeImporter) counts() (imported, updated int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.imported), len(f.updated)
}

// memTelemetry keeps every sandbox record the production recorder accepts.
// Each record first goes through a real audit.SandboxRecorder, whose runtime
// builds the generated family record: one the audit schema refuses is not
// kept and fails the test at cleanup (production drops the error).
type memTelemetry struct {
	mu        sync.Mutex
	check     *audit.SandboxRecorder
	refused   []string
	lifecycle []audit.SandboxLifecycleEvent
	egress    []audit.SandboxEgressEvent
	approvals []audit.SandboxApprovalEvent
	policy    []audit.SandboxPolicyEvent
	health    []audit.SandboxHealthEvent
	findings  []audit.SandboxFindingEvent
	workspace []audit.SandboxWorkspaceEvent
}

func newMemTelemetry() *memTelemetry {
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(buildingRuntime{})
	return &memTelemetry{check: audit.NewSandboxRecorder(logger)}
}

// keep runs the production recorder on e under t.mu (which also serializes
// its tracked phases) and appends e to list unless it was refused.
func keep[T any](t *memTelemetry, kind string, list *[]T, e T, record func() error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := record(); err != nil {
		t.refused = append(t.refused, kind+": "+err.Error())
		return err
	}
	*list = append(*list, e)
	return nil
}

func (t *memTelemetry) RecordSandboxLifecycle(ctx context.Context, e audit.SandboxLifecycleEvent) error {
	return keep(t, "lifecycle", &t.lifecycle, e, func() error { return t.check.RecordSandboxLifecycle(ctx, e) })
}

func (t *memTelemetry) RecordSandboxEgress(ctx context.Context, e audit.SandboxEgressEvent) error {
	return keep(t, "egress", &t.egress, e, func() error { return t.check.RecordSandboxEgress(ctx, e) })
}

func (t *memTelemetry) RecordSandboxApproval(ctx context.Context, e audit.SandboxApprovalEvent) error {
	return keep(t, "approval", &t.approvals, e, func() error { return t.check.RecordSandboxApproval(ctx, e) })
}

func (t *memTelemetry) RecordSandboxPolicy(ctx context.Context, e audit.SandboxPolicyEvent) error {
	return keep(t, "policy "+string(e.Operation)+" "+e.Target+" "+e.Reason, &t.policy, e, func() error { return t.check.RecordSandboxPolicy(ctx, e) })
}

func (t *memTelemetry) RecordSandboxHealth(ctx context.Context, e audit.SandboxHealthEvent) error {
	return keep(t, "health", &t.health, e, func() error { return t.check.RecordSandboxHealth(ctx, e) })
}

func (t *memTelemetry) RecordSandboxFinding(ctx context.Context, e audit.SandboxFindingEvent) error {
	return keep(t, "finding", &t.findings, e, func() error { return t.check.RecordSandboxFinding(ctx, e) })
}

func (t *memTelemetry) RecordSandboxWorkspace(ctx context.Context, e audit.SandboxWorkspaceEvent) error {
	return keep(t, "workspace", &t.workspace, e, func() error { return t.check.RecordSandboxWorkspace(ctx, e) })
}

func (t *memTelemetry) phases(name string) []audit.SandboxPhase {
	var out []audit.SandboxPhase
	for _, e := range where(&t.mu, &t.lifecycle, func(e audit.SandboxLifecycleEvent) bool { return e.Sandbox.Name == name }) {
		out = append(out, e.Sandbox.Phase)
	}
	return out
}

// removed reports a rule_remove record of target with reason.
func (t *memTelemetry) removed(target, reason string) bool {
	return len(where(&t.mu, &t.policy, func(p audit.SandboxPolicyEvent) bool {
		return p.Operation == audit.SandboxPolicyRuleRemove && p.Target == target && p.Reason == reason
	})) > 0
}

func (t *memTelemetry) findingsOf(kind audit.SandboxFindingKind) []audit.SandboxFindingEvent {
	return where(&t.mu, &t.findings, func(f audit.SandboxFindingEvent) bool { return f.Kind == kind })
}

// buildingRuntime admits every sandbox record and builds its generated
// family record, which runs the schema's field validation, without
// exporting anything.
type buildingRuntime struct{}

func buildingRuntimeContext() audit.RuntimeV8BuildContext {
	return audit.RuntimeV8BuildContext{ConfigGeneration: 1, ConfigDigest: strings.Repeat("ab", 32)}
}

func (buildingRuntime) EmitRuntimeV8(_ context.Context, _ router.Metadata, build audit.RuntimeV8Builder) (audit.RuntimeV8EmitOutcome, error) {
	if _, err := build(buildingRuntimeContext(), router.AdmissionOrdinary); err != nil {
		return audit.RuntimeV8EmitOutcome{}, err
	}
	return audit.RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary, LocalPersisted: true}, nil
}

func (buildingRuntime) RecordRuntimeV8GeneratedMetricBatch(_ context.Context, metrics []audit.RuntimeV8GeneratedMetric) error {
	for _, metric := range metrics {
		if _, err := metric.Build(buildingRuntimeContext()); err != nil {
			return err
		}
	}
	return nil
}

// fakePersister records always decisions and, like the daemon's persister,
// writes them into the configuration (config.yaml, then a synchronous reload).
type fakePersister struct {
	mu           sync.Mutex
	allow, block []string
	save         func(block bool, host string)
}

func (p *fakePersister) AllowAlways(_ context.Context, host string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allow = append(p.allow, host)
	p.save(false, host)
	return nil
}

func (p *fakePersister) BlockAlways(_ context.Context, host string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.block = append(p.block, host)
	p.save(true, host)
	return nil
}

func (p *fakePersister) allowed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.allow)
}

// fakeWatch lets tests push stream events to a sandbox's watcher.
type fakeWatch struct {
	mu       sync.Mutex
	handlers map[string]func(stream.Event)
	ends     map[string]chan error
	started  chan string
	gateways []*Gateway // the connections the watches ran on, in order
	// settle waits for what an event handed off (the draft poll of a draft
	// or connected event), so push returns once it is done.
	settle func(sandbox string)
}

func (w *fakeWatch) watch(ctx context.Context, gw *Gateway, sandbox, _ string, _ func(string) error, handle func(stream.Event)) error {
	end := make(chan error, 1)
	w.mu.Lock()
	w.handlers[sandbox] = handle
	w.ends[sandbox] = end
	w.gateways = append(w.gateways, gw)
	w.mu.Unlock()
	w.started <- sandbox
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-end:
		return err
	}
}

func (w *fakeWatch) handler(t *testing.T, sandbox string) func(stream.Event) {
	t.Helper()
	w.mu.Lock()
	h := w.handlers[sandbox]
	w.mu.Unlock()
	if h == nil {
		t.Fatalf("no watcher for %s", sandbox)
	}
	return h
}

func (w *fakeWatch) push(t *testing.T, sandbox string, ev stream.Event) {
	t.Helper()
	ev.Sandbox = sandbox
	w.handler(t, sandbox)(ev)
	if ev.Kind == stream.KindDraft || ev.Kind == stream.KindConnected {
		w.settle(sandbox)
	}
}

func (w *fakeWatch) end(sandbox string, err error) {
	w.mu.Lock()
	ch := w.ends[sandbox]
	w.mu.Unlock()
	if ch != nil {
		ch <- err
	}
}

func (w *fakeWatch) waitStarted(t *testing.T, sandbox string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case name := <-w.started:
			if name == sandbox {
				return
			}
		case <-deadline:
			t.Fatalf("watcher for %s did not start", sandbox)
		}
	}
}

// fakeDNS answers the names a test sets and a public address for every
// other name, so triage never depends on real DNS.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]string
	rebinds map[string]rebind // switch a name's answers after n lookups
	calls   map[string]int
	hang    map[string]bool  // lookups wait for their context
	errs    map[string]error // lookups fail with the error
}

type rebind struct {
	after int
	addrs []string
}

// set makes host resolve to addrs; none makes it fail to resolve.
func (d *fakeDNS) set(host string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.answers[host+"."] = addrs
}

// rebindAfter makes host resolve to addrs once it was looked up n times.
func (d *fakeDNS) rebindAfter(host string, n int, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rebinds[host+"."] = rebind{after: n, addrs: addrs}
}

// setErr makes lookups of host fail with err (nil: answer again).
func (d *fakeDNS) setErr(host string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errs[host+"."] = err
}

func (d *fakeDNS) setHang(host string, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hang[host+"."] = on
}

func (d *fakeDNS) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	d.mu.Lock()
	hang := d.hang[name]
	d.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls[name]++
	if err := d.errs[name]; err != nil {
		return nil, err
	}
	addrs, ok := d.answers[name]
	if !ok {
		addrs = []string{"93.184.216.34"}
	}
	if r, ok := d.rebinds[name]; ok && d.calls[name] > r.after {
		addrs = r.addrs
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// fakeGuard records guard runs; a running guard can be made to detect.
type fakeGuard struct {
	mu      sync.Mutex
	running map[string]nestguard.Options
	runs    []nestguard.Options
}

func (g *fakeGuard) run(ctx context.Context, opts nestguard.Options) error {
	g.mu.Lock()
	g.runs = append(g.runs, opts)
	if opts.Once { // the final pass: one sweep, no watch
		g.mu.Unlock()
		return nil
	}
	g.running[opts.Root] = opts
	g.mu.Unlock()
	<-ctx.Done()
	g.mu.Lock()
	delete(g.running, opts.Root)
	g.mu.Unlock()
	return nil
}

// finals are the final passes that ran over root.
func (g *fakeGuard) finals(root string) []nestguard.Options {
	return where(&g.mu, &g.runs, func(o nestguard.Options) bool { return o.Once && o.Root == root })
}

func (g *fakeGuard) active(root string) (nestguard.Options, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	o, ok := g.running[root]
	return o, ok
}

func (g *fakeGuard) waitActive(t *testing.T, root string, want bool) nestguard.Options {
	t.Helper()
	var o nestguard.Options
	eventually(t, fmt.Sprintf("guard active for %s = %t", root, want), func() bool {
		var ok bool
		o, ok = g.active(root)
		return ok == want
	})
	return o
}

// fakeProxy is a ProxyControl that records decider swaps and rechecks.
type fakeProxy struct {
	mu      sync.Mutex
	decider *egress.Decider
	sets    int
	counter *egress.Counter
}

func (p *fakeProxy) SetDecider(d *egress.Decider) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.decider, p.sets = d, p.sets+1
	return nil
}

func (p *fakeProxy) Recheck(string) int       { return 0 }
func (p *fakeProxy) Counter() *egress.Counter { return p.counter }

func (p *fakeProxy) swaps() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sets
}

// harnessEnv is a fixture tying a manager to the fake gateway.
type harnessEnv struct {
	t        *testing.T
	fake     *openshelltest.Fake
	client   openshell.Client
	cfg      *config.Config
	cfgMu    sync.Mutex
	dataDir  string
	project  string
	store    *sandboxauth.FileStore
	images   *fakeImages
	ws       *fakeWorkspace
	importer *fakeImporter
	tel      *memTelemetry
	persist  *fakePersister
	watch    *fakeWatch
	dns      *fakeDNS
	guard    *fakeGuard
	forgot   []string
	m        *Manager
	cancel   context.CancelFunc
	done     chan struct{}
	gw       *Gateway
	connErr  error
	// The daemon's identity: its data dir's owner and its listeners.
	owner                            string
	ingressPort, egressPort, apiPort int
}

// daemonOptions place a harnessEnv's manager on a gateway, as one
// DefenseClaw daemon (data dir) of several. Zero values take a new gateway,
// testOwner, testIngressPort, testEgressPort and 18970.
type daemonOptions struct {
	fake                             *openshelltest.Fake
	owner                            string
	ingressPort, egressPort, apiPort int
}

func claudeContract(t *testing.T) string {
	t.Helper()
	res := connector.ResolveSandboxHookContract("claudecode", "2.1.156")
	if res.Status != connector.HookCompatibilityKnown {
		t.Fatalf("claudecode 2.1.156 has no known contract: %+v", res)
	}
	return res.Contract.ContractID
}

func newEnv(t *testing.T, edit func(*config.Config)) *harnessEnv {
	t.Helper()
	return newDaemonEnv(t, daemonOptions{}, edit)
}

// newDaemonEnv is newEnv for one of several daemons sharing a gateway.
func newDaemonEnv(t *testing.T, d daemonOptions, edit func(*config.Config)) *harnessEnv {
	t.Helper()
	if d.fake == nil {
		d.fake = openshelltest.New()
	}
	e := &harnessEnv{t: t, fake: d.fake, dataDir: t.TempDir(), owner: orDefault(d.owner, testOwner),
		ingressPort: orDefault(d.ingressPort, testIngressPort), egressPort: orDefault(d.egressPort, testEgressPort), apiPort: orDefault(d.apiPort, 18970)}
	e.client = e.fake.Client(openshell.ClientOptions{PollInterval: time.Millisecond, ReadyTimeout: 5 * time.Second})
	e.project = e.otherProject("myapp")
	cfg := &config.Config{DataDir: e.dataDir}
	cfg.Gateway.APIPort = e.apiPort
	cfg.Guardrail.Port = 4000
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Approvals.DebounceMs = 10
	if edit != nil {
		edit(cfg)
	}
	e.cfg = cfg
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(e.dataDir), sandboxauth.WithRefreshInterval(0))
	must(t, err)
	e.store = store
	e.images = &fakeImages{rec: image.Record{
		Tag: "defenseclaw/sandbox-claudecode:test", ImageID: "sha256:" + strings.Repeat("a", 64),
		HarnessVersion: "2.1.156", HookContract: claudeContract(t), HookFireVerified: true,
		NetworkBinaries: []image.Binary{{Name: "claude", Realpath: testClaudeBin}},
	}}
	e.ws = &fakeWorkspace{snapshots: map[string]*workspace.SnapshotRecord{}}
	e.importer = &fakeImporter{c: e.client}
	e.tel = newMemTelemetry()
	t.Cleanup(func() {
		if refused := where(&e.tel.mu, &e.tel.refused, nil); len(refused) > 0 {
			t.Errorf("the audit recorder refused %d sandbox record(s):\n%s", len(refused), strings.Join(refused, "\n"))
		}
	})
	e.persist = &fakePersister{save: func(block bool, host string) {
		e.setConfig(func(c *config.Config) {
			if block {
				c.OpenShell.Egress.Block = append(slices.Clip(c.OpenShell.Egress.Block), host)
			} else {
				c.OpenShell.Egress.Unblocked = append(slices.Clip(c.OpenShell.Egress.Unblocked), host)
			}
		})
	}}
	e.watch = &fakeWatch{handlers: map[string]func(stream.Event){}, ends: map[string]chan error{}, started: make(chan string, 64), settle: e.waitTriage}
	e.dns = &fakeDNS{answers: map[string][]string{}, rebinds: map[string]rebind{}, calls: map[string]int{}, hang: map[string]bool{}, errs: map[string]error{}}
	e.guard = &fakeGuard{running: map[string]nestguard.Options{}}
	e.gw = &Gateway{Client: e.client, Name: "openshell", Endpoint: "https://127.0.0.1:17670", Port: 17670, Version: "0.1.1"}
	e.m = e.newManager()
	return e
}

// orDefault returns v, or def when v is its zero value.
func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// waitTriage waits until no draft poll of the sandbox runs (triageNow).
func (e *harnessEnv) waitTriage(sandbox string) {
	e.t.Helper()
	eventually(e.t, "the draft poll of "+sandbox, func() bool {
		e.m.mu.Lock()
		defer e.m.mu.Unlock()
		b := e.m.boxes[sandbox]
		return b == nil || !b.triageBusy
	})
}

func (e *harnessEnv) config() *config.Config {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	return e.cfg
}

func (e *harnessEnv) setConfig(edit func(*config.Config)) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	next := *e.cfg
	edit(&next)
	e.cfg = &next
}

func (e *harnessEnv) newManager() *Manager {
	e.t.Helper()
	m, err := New(Options{
		DataDir: e.dataDir, Owner: e.owner, Config: e.config,
		Connect: func(context.Context) (*Gateway, error) {
			if e.connErr != nil {
				return nil, e.connErr
			}
			return e.gw, nil
		},
		Bindings: e.store, Images: e.images, Workspace: e.ws, Profiles: e.importer, Telemetry: e.tel,
		Persist: e.persist, ForgetBinding: func(id string) { e.forgot = append(e.forgot, id) },
		IngressPort: e.ingressPort, EgressPort: e.egressPort, APIPort: e.apiPort,
		HostUser: &HostUser{UID: 1000, GID: 1000, Name: "dev"}, Watch: e.watch.watch, Resolver: e.dns,
		Guard: e.guard.run, GuardGitlinks: func(context.Context, string) ([]string, error) { return nil, nil },
		DefenseClawVersion: "1.2.3", SettleDelay: -1, HookSilence: 10 * time.Minute,
		Logf: func(format string, args ...any) { e.t.Logf("[manager] "+format, args...) },
	})
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	return m
}

// run starts the manager's Run loop.
func (e *harnessEnv) run() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	m := e.m
	go func() { _ = m.Run(ctx); close(e.done) }()
	e.t.Cleanup(e.stop)
	eventually(e.t, "the manager to start", func() bool { return m.running() != nil })
}

func (e *harnessEnv) stop() {
	if e.cancel != nil {
		e.cancel()
		<-e.done
		e.cancel = nil
	}
}

// restartDaemon replaces the manager with a new daemon process over the same
// data dir and gateway, and waits for its startup reconcile.
func (e *harnessEnv) restartDaemon() {
	e.t.Helper()
	e.stop()
	e.m = e.newManager()
	e.run()
	eventually(e.t, "startup reconcile", func() bool {
		st, _ := e.m.Status(context.Background())
		return !st.LastReconcile.IsZero()
	})
}

// fakeClock makes the manager's clock start and returns how to move it.
func (e *harnessEnv) fakeClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	var mu sync.Mutex
	now = func() time.Time { mu.Lock(); defer mu.Unlock(); return start }
	e.m.opts.Now, e.m.now = now, now
	return now, func(d time.Duration) { mu.Lock(); start = start.Add(d); mu.Unlock() }
}

// tryCreate is Create with the harness and project filled in.
func (e *harnessEnv) tryCreate(req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error) {
	req.Harness = orDefault(req.Harness, "claudecode")
	req.Project = orDefault(req.Project, e.project)
	return e.m.Create(context.Background(), req)
}

func (e *harnessEnv) create(req sandboxapi.CreateRequest) *sandboxapi.Sandbox {
	e.t.Helper()
	sb, err := e.tryCreate(req)
	if err != nil {
		e.t.Fatalf("Create: %v", err)
	}
	return sb
}

// otherProject makes another project folder (two sandboxes never mount one
// folder live).
func (e *harnessEnv) otherProject(name string) string {
	e.t.Helper()
	dir := filepath.Join(e.t.TempDir(), name)
	must(e.t, os.MkdirAll(dir, 0o755))
	real, err := filepath.EvalSymlinks(dir)
	must(e.t, err)
	return real
}

// live creates a sandbox on the running manager and waits for its watcher.
func (e *harnessEnv) live(req sandboxapi.CreateRequest) *sandboxapi.Sandbox {
	e.t.Helper()
	if e.cancel == nil {
		e.run()
	}
	sb := e.create(req)
	e.watch.waitStarted(e.t, sb.Name)
	return sb
}

// liveEnv is a running manager with one watched sandbox of the name.
func liveEnv(t *testing.T, name string, edit func(*config.Config)) *harnessEnv {
	t.Helper()
	e := newEnv(t, edit)
	e.live(sandboxapi.CreateRequest{Name: name})
	return e
}

func (e *harnessEnv) stopBox(name string) {
	e.t.Helper()
	if _, err := e.m.Stop(context.Background(), name); err != nil {
		e.t.Fatalf("Stop %s: %v", name, err)
	}
}

func (e *harnessEnv) startBox(name string, req sandboxapi.StartRequest) {
	e.t.Helper()
	if _, err := e.m.Start(context.Background(), name, req); err != nil {
		e.t.Fatalf("Start %s: %v", name, err)
	}
}

func (e *harnessEnv) deleteBox(name string, req sandboxapi.DeleteRequest) {
	e.t.Helper()
	if _, err := e.m.Delete(context.Background(), name, req); err != nil {
		e.t.Fatalf("Delete %s: %v", name, err)
	}
}

func (e *harnessEnv) get(name string) *sandboxapi.Sandbox {
	e.t.Helper()
	sb, err := e.m.Get(context.Background(), name)
	if err != nil {
		e.t.Fatalf("Get %s: %v", name, err)
	}
	return sb
}

// boxOf is the manager's box of the sandbox.
func (e *harnessEnv) boxOf(name string) *box {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return e.m.boxes[name]
}

func (e *harnessEnv) binding(name string) sandboxauth.Binding {
	e.t.Helper()
	b, err := e.store.Lookup(name)
	must(e.t, err)
	return b
}

// ingressToken is the binding token the sandbox's ingress provider carries.
func (e *harnessEnv) ingressToken(name string) string {
	p, _ := e.client.GetProvider(context.Background(), name+"-ingress")
	if p == nil {
		return ""
	}
	return p.Spec.Credentials[openshell.EnvSandboxToken]
}

func (e *harnessEnv) providers() []string {
	e.t.Helper()
	list, err := e.client.ListProviders(context.Background())
	must(e.t, err)
	var out []string
	for _, p := range list {
		out = append(out, p.Name)
	}
	return out
}

// events are the sandbox's feed events of kind with reason ("" matches any).
func (e *harnessEnv) events(sandbox, kind, reason string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sandbox) {
		if (kind == "" || ev.Kind == kind) && (reason == "" || ev.Reason == reason) {
			out = append(out, ev)
		}
	}
	return out
}

// ocsf hands the sandbox one OpenShell shorthand line recorded at.
func (e *harnessEnv) ocsf(sandbox, line string, at time.Time) {
	e.t.Helper()
	e.m.ocsfEvent(context.Background(), e.boxOf(sandbox), *parseOCSF(e.t, line), at)
}

func parseOCSF(t *testing.T, line string) *ocsf.Record {
	t.Helper()
	rec, err := ocsf.Parse(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return &rec
}

// approvedRules is a copy of the sandbox's recorded rule approvers.
func (e *harnessEnv) approvedRules(sandbox string) map[string]string {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return maps.Clone(e.m.boxes[sandbox].rec.ApprovedRules)
}

// draft notifies the sandbox's watcher of new draft chunks.
func (e *harnessEnv) draft(sandbox string) {
	e.watch.push(e.t, sandbox, stream.Event{Kind: stream.KindDraft})
}

// chunk is a draft chunk in the shape OpenShell 0.1.1 drafts for a denied
// direct connection (allow_<host>_<port>, no protocol, advisor provenance).
func chunk(rule, host string, port uint32) types.PolicyChunk {
	return types.PolicyChunk{
		RuleName: rule, ReviewToken: "rt-" + rule, Binary: "/usr/bin/curl",
		ProposedRule: &types.NetworkPolicyRule{
			Name:      rule,
			Endpoints: []types.PolicyNetworkEndpoint{{Host: host, Port: port, Ports: []uint32{port}, AdvisorProposed: true}},
			Binaries:  []types.PolicyNetworkBinary{{Path: "/usr/bin/curl"}},
		},
	}
}

// ruleFor is the rule OpenShell drafts for host:443.
func ruleFor(host string) string {
	return "allow_" + strings.NewReplacer(".", "_", "-", "_").Replace(host) + "_443"
}

// propose adds a draft chunk for host:443 and returns its id.
func (e *harnessEnv) propose(sandbox, host string) string {
	return e.addChunk(sandbox, chunk(ruleFor(host), host, 443))
}

func (e *harnessEnv) addChunk(sandbox string, c types.PolicyChunk) string {
	return e.fake.AddDraftChunk(openshell.DefaultWorkspace, sandbox, c)
}

func (e *harnessEnv) chunkStatus(sandbox, id string) string {
	c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, sandbox, id)
	return c.Status
}

func (e *harnessEnv) waitChunk(sandbox, id, status string) {
	e.t.Helper()
	eventually(e.t, "chunk "+id+" "+status, func() bool { return e.chunkStatus(sandbox, id) == status })
}

// approveRule has triage approve a rule to host:443 in the running sandbox.
func (e *harnessEnv) approveRule(sandbox, host string) string {
	e.t.Helper()
	id := e.propose(sandbox, host)
	e.draft(sandbox)
	e.waitChunk(sandbox, id, "approved")
	return ruleFor(host)
}

func (e *harnessEnv) waitAsks(sandbox string, n int) []sandboxapi.Approval {
	e.t.Helper()
	var asks []sandboxapi.Approval
	eventually(e.t, fmt.Sprintf("%d asks", n), func() bool {
		asks, _ = e.m.Approvals(context.Background(), sandbox)
		return len(asks) == n
	})
	return asks
}

func (e *harnessEnv) decide(id string, d sandboxapi.ApprovalDecision) error {
	_, err := e.m.DecideApproval(context.Background(), id, d)
	return err
}

func (e *harnessEnv) hasRule(sandbox, rule string) bool {
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sandbox)
	_, ok := pol.NetworkPolicies[rule]
	return ok
}

// decideEgress is the proxy's verdict for the sandbox's current principal,
// which carries the sandbox's own decider.
func (e *harnessEnv) decideEgress(name, host string) egress.Decision {
	e.t.Helper()
	p, ok := e.m.creds.Lookup(e.binding(name).ID)
	if !ok || p.Decider == nil {
		e.t.Fatalf("no principal with a decider for %s", name)
	}
	return p.Decider.Decide(p, host, 443)
}

// liveProxy is a real egress proxy serving the manager's sandbox
// credentials. Every allowed dial goes to a local listener that holds the
// connection.
type liveProxy struct {
	addr string
	e    *harnessEnv
}

func startLiveProxy(t *testing.T, e *harnessEnv) *liveProxy {
	t.Helper()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	d, err := e.m.Decider()
	must(t, err)
	var dialer net.Dialer
	p, err := egress.New(egress.Options{
		Auth: e.m.EgressAuthenticator(), Decider: d, Resolver: e.dns,
		Dialer: dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", upstream.Addr().String())
		}),
	})
	must(t, err)
	e.m.AttachProxy(p)
	ln, err := egress.Listen("127.0.0.1:0")
	must(t, err)
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return &liveProxy{addr: ln.Addr().String(), e: e}
}

type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// send sends a CONNECT for sandbox's credential and returns the connection
// (closed at cleanup), its reader and the response head.
func (lp *liveProxy) send(t *testing.T, sandbox, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	cred := lp.e.boxOf(sandbox).cred
	conn, err := net.DialTimeout("tcp", lp.addr, 5*time.Second)
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	_, err = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n")
	must(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	return conn, br, resp
}

// open establishes a CONNECT tunnel for sandbox's credential.
func (lp *liveProxy) open(t *testing.T, sandbox, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, br, resp := lp.send(t, sandbox, target)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s CONNECT %s = %d", sandbox, target, resp.StatusCode)
	}
	return conn, br
}

// tunnelOpen reports whether the proxy still holds a tunnel open: a read
// waits for bytes instead of ending.
func tunnelOpen(conn net.Conn, br *bufio.Reader) bool {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := br.ReadByte()
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// connect sends a CONNECT for sandbox's credential and returns the status
// and, for a refusal, the block body.
func (lp *liveProxy) connect(t *testing.T, sandbox, target string) (int, egress.BlockResponse) {
	t.Helper()
	conn, _, resp := lp.send(t, sandbox, target)
	defer conn.Close()
	defer resp.Body.Close()
	var body egress.BlockResponse
	if resp.StatusCode == http.StatusForbidden {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("CONNECT %s: block body: %v", target, err)
		}
	}
	return resp.StatusCode, body
}

// teamPack is a custom pack with its own block and allow lists and an extra
// port.
const teamPack = `version: 1
name: team
network: {mode: open}
approvals: {mode: auto}
egress:
  block: ["*.paste.example"]
  allow: [webhook.site]
  ports: [443, 8443]
workspace: {mode: mount}
harness: {yolo: true}
mcp: {import: true, host_ports: false}
hooks: {fail_mode: closed}
`

// writeTeamPack writes teamPack into a new pack directory.
func writeTeamPack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "team", "pack.yaml"), teamPack)
	return dir
}
