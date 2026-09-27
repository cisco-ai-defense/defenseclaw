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
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
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

// fakeImages hands out one verified record.
type fakeImages struct {
	mu    sync.Mutex
	rec   image.Record
	err   error
	calls int
	build []bool
}

func (f *fakeImages) Resolve(_ context.Context, spec image.BuildSpec, build bool) (image.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.build = append(f.build, build)
	if f.err != nil {
		return image.Record{}, f.err
	}
	rec := f.rec
	rec.Connector = spec.Harness.Name
	rec.UID, rec.GID = spec.UID, spec.GID
	return rec, nil
}

// fakeWorkspace records workspace calls and plans a mount under /work.
type fakeWorkspace struct {
	mu           sync.Mutex
	planErr      error
	snapErr      error
	undoErr      error
	planned      []string
	released     []string
	snapshots    map[string]*workspace.SnapshotRecord
	deleted      []string
	deletedCopy  []string
	undone       []string
	reviewed     []string
	masked       []workspace.MaskedPath
	lastSnapshot workspace.SnapshotOptions
	lastMount    workspace.MountOptions
}

func newFakeWorkspace() *fakeWorkspace {
	return &fakeWorkspace{snapshots: map[string]*workspace.SnapshotRecord{}}
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
	plan := &workspace.MountPlan{
		Name: opts.Name, Project: opts.Project, RepoName: repo, Target: target,
		Mounts: []workspace.Mount{
			{Kind: workspace.MountProject, Source: opts.Project, Target: target},
			{Kind: workspace.MountProtect, Source: filepath.Join(opts.Project, ".git", "hooks"), Target: target + "/.git/hooks", ReadOnly: true},
		},
		Masked:    f.masked,
		ReadWrite: []string{target},
		Labels:    map[string]string{},
	}
	return plan, nil
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

func (f *fakeWorkspace) DeleteSnapshot(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	delete(f.snapshots, name)
	return nil
}

func (f *fakeWorkspace) Undo(_ context.Context, opts workspace.UndoOptions) (*workspace.UndoResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.undoErr != nil {
		return nil, f.undoErr
	}
	f.undone = append(f.undone, opts.Name)
	return &workspace.UndoResult{Name: opts.Name, Preview: opts.Preview, Changes: []workspace.TreeChange{{Path: "README.md"}}}, nil
}

func (f *fakeWorkspace) Review(_ context.Context, opts workspace.ReviewOptions) (*workspace.ReviewReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reviewed = append(f.reviewed, opts.Name)
	return &workspace.ReviewReport{Name: opts.Name, FilesChanged: 2, Insertions: 5, Deletions: 1,
		Flags: []workspace.Flag{{Path: "package.json", Label: "package.json#scripts.postinstall", Severity: workspace.SeverityHigh}}}, nil
}

func (f *fakeWorkspace) ReviewDiff(context.Context, string, string) ([]byte, error) {
	return []byte("diff --git a/README.md b/README.md\n"), nil
}

func (f *fakeWorkspace) DeleteCopy(_, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedCopy = append(f.deletedCopy, name)
	return nil
}

// fakeImporter imports profiles into the fake gateway through the SDK.
type fakeImporter struct {
	c        openshell.Client
	mu       sync.Mutex
	imported []string
	updated  []string
	err      error
}

func (f *fakeImporter) Import(ctx context.Context, _ string, p profiles.Profile, replace bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	item := openshell.ProfileImportItem{Profile: p.Spec, Source: "test"}
	if replace {
		f.updated = append(f.updated, p.ID)
		_, err := f.c.UpdateProfile(ctx, p.ID, 0, item)
		return err
	}
	f.imported = append(f.imported, p.ID)
	_, err := f.c.ImportProfiles(ctx, []openshell.ProfileImportItem{item})
	return err
}

// memTelemetry keeps every sandbox record the production recorder
// accepts. Each record first goes through a real audit.SandboxRecorder,
// whose runtime builds the generated family record: one the audit schema
// refuses (a reason that is not a stable token, a target that is not a
// bounded reference) is not kept and is reported by the environment's
// cleanup, instead of vanishing as it does in production, where the manager
// drops the recorder's error.
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

// accepted runs the production recorder on a record and notes a refusal.
// Callers hold t.mu, which also serializes the recorder's tracked phases.
func (t *memTelemetry) accepted(kind string, err error) error {
	if err != nil {
		t.refused = append(t.refused, kind+": "+err.Error())
	}
	return err
}

// refusedRecords lists the records the production recorder refused.
func (t *memTelemetry) refusedRecords() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.refused...)
}

func (t *memTelemetry) RecordSandboxLifecycle(ctx context.Context, e audit.SandboxLifecycleEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("lifecycle", t.check.RecordSandboxLifecycle(ctx, e)); err != nil {
		return err
	}
	t.lifecycle = append(t.lifecycle, e)
	return nil
}

func (t *memTelemetry) RecordSandboxEgress(ctx context.Context, e audit.SandboxEgressEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("egress", t.check.RecordSandboxEgress(ctx, e)); err != nil {
		return err
	}
	t.egress = append(t.egress, e)
	return nil
}

func (t *memTelemetry) RecordSandboxApproval(ctx context.Context, e audit.SandboxApprovalEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("approval", t.check.RecordSandboxApproval(ctx, e)); err != nil {
		return err
	}
	t.approvals = append(t.approvals, e)
	return nil
}

func (t *memTelemetry) RecordSandboxPolicy(ctx context.Context, e audit.SandboxPolicyEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("policy "+string(e.Operation)+" "+e.Target+" "+e.Reason, t.check.RecordSandboxPolicy(ctx, e)); err != nil {
		return err
	}
	t.policy = append(t.policy, e)
	return nil
}

func (t *memTelemetry) RecordSandboxHealth(ctx context.Context, e audit.SandboxHealthEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("health", t.check.RecordSandboxHealth(ctx, e)); err != nil {
		return err
	}
	t.health = append(t.health, e)
	return nil
}

func (t *memTelemetry) RecordSandboxFinding(ctx context.Context, e audit.SandboxFindingEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("finding", t.check.RecordSandboxFinding(ctx, e)); err != nil {
		return err
	}
	t.findings = append(t.findings, e)
	return nil
}

func (t *memTelemetry) RecordSandboxWorkspace(ctx context.Context, e audit.SandboxWorkspaceEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.accepted("workspace", t.check.RecordSandboxWorkspace(ctx, e)); err != nil {
		return err
	}
	t.workspace = append(t.workspace, e)
	return nil
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

func (t *memTelemetry) phases(name string) []audit.SandboxPhase {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []audit.SandboxPhase
	for _, e := range t.lifecycle {
		if e.Sandbox.Name == name {
			out = append(out, e.Sandbox.Phase)
		}
	}
	return out
}

// fakePersister records always decisions.
type fakePersister struct {
	mu           sync.Mutex
	allow, block []string
	err          error
}

func (p *fakePersister) AllowAlways(_ context.Context, host string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.allow = append(p.allow, host)
	return nil
}

func (p *fakePersister) BlockAlways(_ context.Context, host string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.block = append(p.block, host)
	return nil
}

// fakeWatch lets tests push stream events to a sandbox's watcher.
type fakeWatch struct {
	mu       sync.Mutex
	handlers map[string]func(stream.Event)
	ends     map[string]chan error
	started  chan string
}

func newFakeWatch() *fakeWatch {
	return &fakeWatch{handlers: map[string]func(stream.Event){}, ends: map[string]chan error{}, started: make(chan string, 64)}
}

func (w *fakeWatch) watch(ctx context.Context, _ *Gateway, sandbox, _ string, _ func(string) error, handle func(stream.Event)) error {
	end := make(chan error, 1)
	w.mu.Lock()
	w.handlers[sandbox] = handle
	w.ends[sandbox] = end
	w.mu.Unlock()
	w.started <- sandbox
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-end:
		return err
	}
}

func (w *fakeWatch) push(t *testing.T, sandbox string, ev stream.Event) {
	t.Helper()
	w.mu.Lock()
	h := w.handlers[sandbox]
	w.mu.Unlock()
	if h == nil {
		t.Fatalf("no watcher for %s", sandbox)
	}
	ev.Sandbox = sandbox
	h(ev)
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
	// rebinds switch a name's answers once it was looked up so often.
	rebinds map[string]rebind
	calls   map[string]int
	// hang makes lookups of a name wait for their context.
	hang map[string]bool
	// errs makes lookups of a name fail with the error.
	errs map[string]error
}

// setErr makes lookups of host fail with err (nil: answer again).
func (d *fakeDNS) setErr(host string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.errs == nil {
		d.errs = map[string]error{}
	}
	if err == nil {
		delete(d.errs, host+".")
		return
	}
	d.errs[host+"."] = err
}

// setHang makes lookups of host wait until their context ends (on) or
// answer again (off).
func (d *fakeDNS) setHang(host string, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hang == nil {
		d.hang = map[string]bool{}
	}
	d.hang[host+"."] = on
}

type rebind struct {
	after int
	addrs []string
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{answers: map[string][]string{}, rebinds: map[string]rebind{}, calls: map[string]int{}}
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
	if err := d.errs[name]; err != nil {
		d.calls[name]++
		return nil, err
	}
	addrs, ok := d.answers[name]
	if !ok {
		addrs = []string{"93.184.216.34"}
	}
	if r, ok := d.rebinds[name]; ok && d.calls[name] >= r.after {
		addrs = r.addrs
	}
	d.calls[name]++
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
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
	e := &harnessEnv{t: t, fake: openshelltest.New(), dataDir: t.TempDir()}
	e.client = e.fake.Client(openshell.ClientOptions{PollInterval: time.Millisecond, ReadyTimeout: 5 * time.Second})
	project := filepath.Join(t.TempDir(), "myapp")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	e.project = real
	cfg := &config.Config{DataDir: e.dataDir}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Approvals.DebounceMs = 10
	if edit != nil {
		edit(cfg)
	}
	e.cfg = cfg
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(e.dataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	e.store = store
	e.images = &fakeImages{rec: image.Record{
		Tag: "defenseclaw/sandbox-claudecode:test", ImageID: "sha256:" + strings.Repeat("a", 64),
		HarnessVersion: "2.1.156", HookContract: claudeContract(t), HookFireVerified: true,
		NetworkBinaries: []image.Binary{{Name: "claude", Realpath: testClaudeBin}},
	}}
	e.ws = newFakeWorkspace()
	e.importer = &fakeImporter{c: e.client}
	e.tel = newMemTelemetry()
	t.Cleanup(func() {
		if refused := e.tel.refusedRecords(); len(refused) > 0 {
			t.Errorf("the audit recorder refused %d sandbox record(s):\n%s", len(refused), strings.Join(refused, "\n"))
		}
	})
	e.persist = &fakePersister{}
	e.watch = newFakeWatch()
	e.dns = newFakeDNS()
	e.guard = newFakeGuard()
	e.gw = &Gateway{Client: e.client, Name: "openshell", Endpoint: "https://127.0.0.1:17670", Port: 17670, Version: "0.1.1"}
	e.m = e.newManager()
	return e
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
		DataDir: e.dataDir, Owner: testOwner, Config: e.config,
		Connect: func(context.Context) (*Gateway, error) {
			if e.connErr != nil {
				return nil, e.connErr
			}
			return e.gw, nil
		},
		Bindings: e.store, Images: e.images, Workspace: e.ws, Profiles: e.importer, Telemetry: e.tel,
		Persist: e.persist, ForgetBinding: func(id string) { e.forgot = append(e.forgot, id) },
		IngressPort: testIngressPort, EgressPort: testEgressPort, APIPort: 18970,
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
	deadline := time.Now().Add(5 * time.Second)
	for m.running() == nil {
		if time.Now().After(deadline) {
			e.t.Fatal("manager did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *harnessEnv) stop() {
	if e.cancel != nil {
		e.cancel()
		<-e.done
		e.cancel = nil
	}
}

func (e *harnessEnv) create(req sandboxapi.CreateRequest) *sandboxapi.Sandbox {
	e.t.Helper()
	if req.Harness == "" {
		req.Harness = "claudecode"
	}
	if req.Project == "" {
		req.Project = e.project
	}
	sb, err := e.m.Create(context.Background(), req)
	if err != nil {
		e.t.Fatalf("Create: %v", err)
	}
	return sb
}

func (e *harnessEnv) providers() []string {
	e.t.Helper()
	list, err := e.client.ListProviders(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, p := range list {
		out = append(out, p.Name)
	}
	return out
}

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
