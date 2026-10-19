// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// All native execution/qualification below is synthetic. The existing generic
// backend contract is faked; no image, namespace, external reader or child runs.
type nativeTransactionBackend struct {
	mu                                          sync.Mutex
	info                                        sandboxruntime.RuntimeInfo
	identity                                    sandboxruntime.SessionIdentity
	launches, closes, stops, deletes, factories int
	closeErr                                    error
	stopErr                                     error
	phase                                       string
	deleted                                     bool
	prepareHook                                 func(context.Context) error
	beforeReturn                                func()
	inspectHook                                 func()
	deleteHook                                  func()
}

func (b *nativeTransactionBackend) Info(context.Context) (sandboxruntime.RuntimeInfo, error) {
	return b.info, nil
}
func (b *nativeTransactionBackend) Prepare(ctx context.Context, policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec) (sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error) {
	b.mu.Lock()
	b.identity = spec.Identity
	b.mu.Unlock()
	receipt := sandboxruntime.PolicyReceipt{Runtime: spec.Identity.Runtime, Harness: spec.HarnessIdentity, PolicyDigest: policy.Digest()}
	for _, component := range policy.Components() {
		receipt.Components = append(receipt.Components, sandboxruntime.PolicyComponentBinding{Name: component.Name, Digest: component.Digest})
	}
	if b.prepareHook != nil {
		return &nativeTransactionProcess{b: b}, receipt, b.prepareHook(ctx)
	}
	return &nativeTransactionProcess{b: b}, receipt, nil
}
func (b *nativeTransactionBackend) Inspect(context.Context, sandboxruntime.SessionIdentity) (sandboxruntime.Instance, error) {
	b.mu.Lock()
	instance := sandboxruntime.Instance{Identity: b.identity, Phase: b.phase}
	b.mu.Unlock()
	if b.inspectHook != nil {
		b.inspectHook()
	}
	return instance, nil
}
func (b *nativeTransactionBackend) Stop(_ context.Context, id sandboxruntime.SessionIdentity) (sandboxruntime.Instance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stops++
	if b.stopErr != nil {
		return sandboxruntime.Instance{}, b.stopErr
	}
	if err := sandboxruntime.ValidateOwnedSession(b.identity, id); err != nil {
		return sandboxruntime.Instance{}, err
	}
	b.phase = "closed"
	return sandboxruntime.Instance{Identity: id, Phase: "closed"}, nil
}
func (b *nativeTransactionBackend) Delete(_ context.Context, id sandboxruntime.SessionIdentity) error {
	b.mu.Lock()
	b.deletes++
	err := sandboxruntime.ValidateOwnedSession(b.identity, id)
	if b.deleted {
		err = errors.New("synthetic backend entry already deleted")
	}
	if err == nil {
		b.deleted = true
	}
	b.mu.Unlock()
	if b.deleteHook != nil {
		b.deleteHook()
	}
	return err
}
func (*nativeTransactionBackend) Exec(context.Context, sandboxruntime.SessionIdentity, sandboxruntime.Command, sandboxruntime.ProcessIO) (sandboxruntime.ExecResult, error) {
	return sandboxruntime.ExecResult{}, errors.New("synthetic exec is unavailable")
}

type nativeTransactionProcess struct{ b *nativeTransactionBackend }

func (p *nativeTransactionProcess) Launch(_ context.Context, spec sandboxruntime.Spec) (sandboxruntime.Instance, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	p.b.launches++
	p.b.phase = "started"
	return sandboxruntime.Instance{Identity: spec.Identity, Phase: "started", Workdir: "/work", CreatedAt: time.Now()}, nil
}
func (p *nativeTransactionProcess) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	p.b.closes++
	return p.b.closeErr
}

type nativeTransactionFixture struct {
	m         *Manager
	b         *nativeTransactionBackend
	gate      *sandboxruntime.LaunchGate
	authority atomic.Pointer[sandboxruntime.PolicyAuthorityBinding]
	request   sandboxapi.CreateRequest
}

func nativeTransaction(t *testing.T) *nativeTransactionFixture {
	t.Helper()
	artifact := sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64)}
	runtime := sandboxruntime.RuntimeIdentity{Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap", HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "synthetic-only", Artifact: artifact}
	harness := sandboxruntime.HarnessIdentity{Version: "synthetic-only", HookContract: "synthetic-hooks", Artifact: artifact}
	caps := []sandboxruntime.Capability{sandboxruntime.StrictFilesystem, sandboxruntime.ProcessTreeContainment, sandboxruntime.ManagedHooks,
		sandboxruntime.Headless, sandboxruntime.CopyWorkspace, sandboxruntime.OfflineNetwork}
	f := &nativeTransactionFixture{b: &nativeTransactionBackend{info: sandboxruntime.RuntimeInfo{Identity: runtime, Available: true,
		Posture: "synthetic-test-only", Supported: caps, Harnesses: map[string]sandboxruntime.HarnessVerification{"claudecode": {Identity: harness, Supported: slices.Clone(caps)}}}}}
	f.authority.Store(&sandboxruntime.PolicyAuthorityBinding{SnapshotID: "synthetic-owner-generation", Generation: 1})
	var err error
	f.gate, err = sandboxruntime.NewLaunchGate(func() sandboxruntime.PolicyAuthorityBinding { return *f.authority.Load() })
	nativeMust(t, err)
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	cfg := &config.Config{Sandbox: &config.SandboxConfig{Enabled: true, Runtime: "axis", LLM: config.OpenShellLLMNone,
		Runtimes: config.SandboxRuntimesConfig{AXIS: config.SandboxRuntimeConfig{Enabled: true}},
		Workdir:  config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}}}
	resolve := func(flags packs.Flags, options sandboxruntime.PolicyOptions) (*sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, []packs.Violation, error) {
		options.Authority = *f.authority.Load()
		run, violations, err := sandboxruntime.ResolveHostRun(cfg, flags, options)
		if err != nil {
			return nil, nil, violations, err
		}
		policy, violations, err := sandboxruntime.BindResolvedExecutionPolicy(run, options)
		return run, policy, violations, err
	}
	prepare := func(ctx context.Context, run *sandboxruntime.HostResolvedRun, policy *sandboxruntime.ExecutionPolicy, id sandboxruntime.SessionIdentity) (sandboxruntime.Spec, sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error) {
		if run == nil || policy == nil {
			t.Fatal("factory received no owned host resolution")
		}
		planning, _, err := run.PlanningPolicy()
		nativeMust(t, err)
		if planning.Harness != "claudecode" {
			t.Fatal("factory received a different planning resolution")
		}
		f.b.mu.Lock()
		f.b.factories++
		f.b.mu.Unlock()
		spec := sandboxruntime.Spec{Identity: id, Harness: "claudecode", HarnessIdentity: harness, Offline: true, GuestWorkspace: "/work", Command: []string{"/synthetic/held-agent", "literal data"}}
		process, receipt, err := f.b.Prepare(ctx, policy, spec)
		if f.b.beforeReturn != nil {
			f.b.beforeReturn()
		}
		return spec, process, receipt, err
	}
	native, err := NewNativeExecution(owner, f.b, f.gate, resolve, prepare)
	nativeMust(t, err)
	data := t.TempDir()
	f.m = &Manager{opts: Options{DataDir: data, Owner: "synthetic-owner", Native: native, Config: func() *config.Config { return cfg },
		Connect: func(context.Context) (*Gateway, error) {
			t.Fatal("native transaction dialed OpenShell")
			return nil, nil
		}},
		ws: DefaultWorkspace{}, boxes: map[string]*box{}, records: newRecordStore(data), now: time.Now, runCtx: owner, logf: func(string, ...any) {}}
	f.request = sandboxapi.CreateRequest{Runtime: "axis", Name: "native-transaction", Harness: "claudecode", Project: t.TempDir(), Copy: true, Safe: true, NoMCP: true}
	return f
}

func TestNativeCreateUsesOwnedPolicyGateAndLifecycle(t *testing.T) {
	f := nativeTransaction(t)
	view, err := f.m.Create(context.Background(), f.request)
	nativeMust(t, err)
	if view.ID == "" || view.Runtime != "axis" || view.Phase != "ready" || f.b.launches != 1 || f.b.factories != 1 {
		t.Fatalf("create = %+v; backend=%+v", view, f.b)
	}
	b := f.m.boxes[f.request.Name]
	if view.ID != b.native.identity.ID || b.native.identity.Owner != f.m.opts.Owner {
		t.Fatal("full owned identity lost")
	}
	if identity := b.identity(); identity.Runtime != "axis" || identity.Driver != "bubblewrap" || identity.ID != view.ID {
		t.Fatalf("native audit identity = %+v", identity)
	}
	if adopted := f.m.adopt(&openshell.Sandbox{Name: f.request.Name, ID: "different-openshell-object"}, openshell.Driver{}); adopted != nil {
		t.Fatal("OpenShell adoption replaced a native-owned reservation")
	}
	stopFailure := errors.New("synthetic native wait uncertainty")
	f.b.stopErr = stopFailure
	if _, err := f.m.Stop(context.Background(), f.request.Name); !errors.Is(err, stopFailure) || !b.native.cleanupPending || string(b.identity().Phase) != "error" {
		t.Fatalf("failed stop lost exact cleanup custody: %v", err)
	}
	f.b.stopErr = nil
	stopped, err := f.m.Stop(context.Background(), f.request.Name)
	nativeMust(t, err)
	if stopped.Phase != "stopped" || stopped.PhaseReason != "" || b.native.cleanupPending || f.b.stops != 2 {
		t.Fatalf("stop = %+v", stopped)
	}
	_, err = f.m.Start(context.Background(), f.request.Name, sandboxapi.StartRequest{})
	nativeWantCode(t, err, sandboxapi.CodeUnavailable)
	deleted, err := f.m.Delete(context.Background(), f.request.Name, sandboxapi.DeleteRequest{})
	nativeMust(t, err)
	if !deleted.Deleted || f.b.deletes != 1 || len(f.m.boxes) != 0 {
		t.Fatalf("delete = %+v", deleted)
	}
}

func TestNativeCreateRejectsUnqualifiedAndUnsupportedBeforeFactory(t *testing.T) {
	for _, missing := range []string{"catalog", "managed-hooks"} {
		t.Run(missing, func(t *testing.T) {
			f := nativeTransaction(t)
			if missing == "catalog" {
				f.b.info.Available = false
				f.request.Project = "must-not-be-read"
			} else {
				f.b.info.Supported = slices.DeleteFunc(f.b.info.Supported, func(c sandboxruntime.Capability) bool { return c == sandboxruntime.ManagedHooks })
				v := f.b.info.Harnesses["claudecode"]
				v.Supported = slices.Clone(f.b.info.Supported)
				f.b.info.Harnesses["claudecode"] = v
			}
			view, err := f.m.Create(context.Background(), f.request)
			if err == nil || view != nil || f.b.factories != 0 || f.b.launches != 0 || len(f.m.boxes) != 0 {
				t.Fatalf("unsupported create = %v, %v", view, err)
			}
		})
	}
}

func TestNativeReservationOwnsRouteBeforePreparation(t *testing.T) {
	f := nativeTransaction(t)
	id := sandboxruntime.SessionIdentity{Owner: "synthetic-owner", ID: "synthetic-reservation", Name: "native-reservation", Runtime: f.b.info.Identity}
	session := &nativeSession{runtime: f.m.opts.Native, identity: id, instance: sandboxruntime.Instance{Identity: id, Phase: "bound"}}
	b, err := f.m.reserveExecution(id.Name, f.request.Project, config.OpenShellWorkdirCopy, session)
	nativeMust(t, err)
	view, err := f.m.Get(context.Background(), id.Name)
	nativeMust(t, err)
	if view.ID != id.ID || view.Phase != "creating" || f.b.factories != 0 {
		t.Fatalf("unprepared native view = %+v", view)
	}
	if f.m.adopt(&openshell.Sandbox{Name: id.Name, ID: "unrelated-openshell-object"}, openshell.Driver{}) != nil {
		t.Fatal("reservation was adopted as OpenShell")
	}
	f.m.release(id.Name, b)
}

func TestNativeUnsupportedOperationsNeverSelectOpenShell(t *testing.T) {
	f := nativeTransaction(t)
	_, err := f.m.Create(context.Background(), f.request)
	nativeMust(t, err)
	name := f.request.Name
	// None of these operations may enter the legacy workspace, binding,
	// configuration synchronization or gateway paths, even for a ready box.
	f.m.ws, f.m.opts.Bindings = nil, nil
	f.m.opts.SyncConfig = func(context.Context) error {
		t.Fatal("native unsupported operation synchronized legacy configuration")
		return nil
	}
	f.m.approvals = map[string]*approval{"stale-legacy-approval": {sandbox: name, status: sandboxapi.ApprovalPending}}
	f.m.dests = map[string]*destTable{name: {rows: map[string]*destRow{"stale.example.invalid": {Host: "stale.example.invalid", Refused: 1}}}}
	ctx := context.Background()
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"undo", func() error { _, err := f.m.Undo(ctx, name, sandboxapi.UndoRequest{}); return err }},
		{"review", func() error { _, err := f.m.Review(ctx, name, sandboxapi.ReviewRequest{}); return err }},
		{"accept", func() error { _, err := f.m.Accept(ctx, name, sandboxapi.AcceptRequest{}); return err }},
		{"discover", func() error { _, err := f.m.Discover(ctx, name); return err }},
		{"processes", func() error { _, err := f.m.Processes(ctx, name); return err }},
		{"destinations", func() error { _, err := f.m.Destinations(ctx, name); return err }},
		{"run-log", func() error { _, err := f.m.RunLog(ctx, name, 1); return err }},
		{"workspace-report", func() error { return f.m.ReportWorkspace(ctx, name, sandboxapi.WorkspaceReport{}) }},
		{"policy-explain", func() error { _, err := f.m.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: name}); return err }},
		{"policy-test", func() error {
			_, err := f.m.PolicyTest(ctx, sandboxapi.PolicyTestRequest{Sandbox: name, Checks: []sandboxapi.PolicyCheck{{Host: "example.invalid"}}})
			return err
		}},
		{"unblock", func() error {
			_, err := f.m.Unblock(ctx, sandboxapi.UnblockRequest{Sandbox: name, Host: "example.invalid"})
			return err
		}},
		{"approvals", func() error { _, err := f.m.Approvals(ctx, name); return err }},
		{"approval-decision", func() error {
			_, err := f.m.DecideApproval(ctx, "stale-legacy-approval", sandboxapi.ApprovalDecision{})
			return err
		}},
	} {
		t.Run(operation.name, func(t *testing.T) { nativeWantCode(t, operation.run(), sandboxapi.CodeUnavailable) })
	}
	if boxes := f.m.liveBoxes(); len(boxes) != 0 {
		t.Fatal("legacy background operations selected a native session")
	}
	if f.m.boxes[name].processTreeOn() {
		t.Fatal("native session claimed legacy process observation")
	}
	approvals, err := f.m.Approvals(ctx, "")
	nativeMust(t, err)
	if len(approvals) != 0 {
		t.Fatal("global approvals exposed an unrelated legacy proposal for a native name")
	}
	// A delayed event from an old OpenShell session cannot acquire the native
	// record by its reused display name. No proxy/telemetry dependencies exist.
	f.m.egressEvent(ctx, egress.Event{Kind: egress.EventAllowed, SandboxName: name}, 0)
	view, err := f.m.Get(ctx, name)
	nativeMust(t, err)
	if view.PendingApprovals != 0 || view.Egress != (sandboxapi.EgressStats{}) {
		t.Fatal("native view inherited stale legacy observations")
	}
	beforeProfile, beforeWarnings := view.Profile, slices.Clone(view.Warnings)
	f.m.ConfirmingView(view, "legacy floor explanation")
	if view.Profile != beforeProfile || !slices.Equal(view.Warnings, beforeWarnings) {
		t.Fatal("legacy confirmation rewrote a native view")
	}
	if f.b.launches != 1 || f.b.stops != 0 || f.b.deletes != 0 {
		t.Fatal("unsupported operations changed native custody")
	}
}

func TestNativeCreateStaleGenerationCleansBeforeLaunch(t *testing.T) {
	f := nativeTransaction(t)
	f.b.beforeReturn = func() {
		next := sandboxruntime.PolicyAuthorityBinding{SnapshotID: "synthetic-next-generation", Generation: 2}
		nativeMust(t, f.gate.Rotate(context.Background(), next, func(context.Context) error { f.authority.Store(&next); return nil }))
	}
	view, err := f.m.Create(context.Background(), f.request)
	if view != nil || err == nil || f.b.launches != 0 || f.b.closes == 0 || f.b.deletes != 1 || len(f.m.boxes) != 0 {
		t.Fatalf("stale create = %v, %v; backend=%+v", view, err, f.b)
	}
}

func TestNativeCreatePartialCancellationRetainsFailedCleanup(t *testing.T) {
	f := nativeTransaction(t)
	ctx, cancel := context.WithCancel(context.Background())
	failure := errors.New("synthetic close uncertainty")
	f.b.closeErr = failure
	f.b.prepareHook = func(context.Context) error { cancel(); return context.Canceled }
	view, err := f.m.Create(ctx, f.request)
	if view != nil || !errors.Is(err, context.Canceled) || len(f.m.boxes) != 1 || f.b.launches != 0 || f.b.closes != 1 {
		t.Fatalf("partial create = %v, %v", view, err)
	}
	b := f.m.boxes[f.request.Name]
	if !b.native.cleanupPending {
		t.Fatal("uncertain cleanup reservation was released")
	}
	f.b.closeErr = nil
	deleted, err := f.m.Delete(context.Background(), f.request.Name, sandboxapi.DeleteRequest{})
	nativeMust(t, err)
	if !deleted.Deleted || f.b.closes != 2 || len(f.m.boxes) != 0 {
		t.Fatal("retained partial cleanup did not finish")
	}
}

func TestNativeCreateManagerShutdownDuringFactoryCannotLaunch(t *testing.T) {
	f := nativeTransaction(t)
	service, stop := context.WithCancel(context.Background())
	defer stop()
	f.m.runCtx = service
	f.b.prepareHook = func(context.Context) error { stop(); return nil }
	view, err := f.m.Create(context.Background(), f.request)
	if view != nil || !errors.Is(err, context.Canceled) || f.b.launches != 0 || f.b.closes != 1 || f.b.deletes != 1 || len(f.m.boxes) != 0 {
		t.Fatalf("shutdown create = %v, %v; backend=%+v", view, err, f.b)
	}
}

func TestNativeGetCannotRepublishAfterOwnedStop(t *testing.T) {
	for _, operation := range []string{"stop", "revoke", "shutdown"} {
		t.Run(operation, func(t *testing.T) {
			f := nativeTransaction(t)
			_, err := f.m.Create(context.Background(), f.request)
			nativeMust(t, err)
			b := f.m.boxes[f.request.Name]
			entered, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(proceed) }) }
			defer release()
			f.b.inspectHook = func() { close(entered); <-proceed }
			type reply struct {
				view *sandboxapi.Sandbox
				err  error
			}
			got := make(chan reply, 1)
			go func() {
				view, err := f.m.Get(context.Background(), f.request.Name)
				got <- reply{view, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("fake Inspect was not reached")
			}
			if operation == "stop" {
				if b.op.TryLock() {
					b.op.Unlock()
					release()
					<-got
					t.Fatal("native Inspect did not serialize with Stop/Delete")
				}
				stopped := make(chan reply, 1)
				go func() {
					view, err := f.m.Stop(context.Background(), f.request.Name)
					stopped <- reply{view, err}
				}()
				release()
				nativeMust(t, (<-got).err)
				result := <-stopped
				nativeMust(t, result.err)
				if result.view.Phase != "stopped" || b.native.instance.Phase != "closed" {
					t.Fatal("Inspect restored a live phase after Stop")
				}
				return
			}
			if operation == "revoke" {
				nativeMust(t, f.m.RevokeNative(context.Background()))
			} else {
				f.m.closeNativeSessions()
			}
			release()
			result := <-got
			if operation == "shutdown" {
				nativeWantCode(t, result.err, sandboxapi.CodeUnavailable)
			} else {
				nativeMust(t, result.err)
				if result.view.Phase != "stopped" || !result.view.StartedAt.IsZero() {
					t.Fatalf("stale Inspect view after revocation = %+v", result.view)
				}
			}
			if b.native.instance.Phase != "closed" || string(b.identity().Phase) != "stopped" || b.rec.PhaseReason != "" {
				t.Fatal("stale Inspect replaced native cleanup/audit state")
			}
		})
	}
}

func TestNativeDeleteRetainsRecordUntilCloseSucceeds(t *testing.T) {
	f := nativeTransaction(t)
	_, err := f.m.Create(context.Background(), f.request)
	nativeMust(t, err)
	failure := errors.New("synthetic completed-prepare close uncertainty")
	f.b.closeErr = failure
	_, err = f.m.Delete(context.Background(), f.request.Name, sandboxapi.DeleteRequest{})
	if !errors.Is(err, failure) || f.b.deletes != 0 || len(f.m.boxes) != 1 || !f.m.boxes[f.request.Name].native.cleanupPending {
		t.Fatal("failed Close deleted its backend record or released its name")
	}
	f.b.closeErr = nil
	deleted, err := f.m.Delete(context.Background(), f.request.Name, sandboxapi.DeleteRequest{})
	nativeMust(t, err)
	if !deleted.Deleted || f.b.deletes != 1 || f.b.closes != 2 || len(f.m.boxes) != 0 {
		t.Fatal("explicit successful cleanup retry did not release the exact name")
	}
}

func TestNativeDeleteSuccessRemainsCompleteAfterContextCancellation(t *testing.T) {
	f := nativeTransaction(t)
	_, err := f.m.Create(context.Background(), f.request)
	nativeMust(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.b.deleteHook = cancel // Exact backend entry is already gone at cancellation.
	b := f.m.boxes[f.request.Name]
	b.op.Lock()
	deleted, err := f.m.deleteNativeOwned(ctx, b)
	b.op.Unlock()
	nativeMust(t, err)
	if ctx.Err() == nil || !deleted.Deleted || f.b.deletes != 1 || len(f.m.boxes) != 0 || b.native.cleanupPending {
		t.Fatal("successful authoritative Delete retained an unrecoverable name")
	}
}

func TestNativeRevocationDoesNotTakeBoxOperationOrReenterGate(t *testing.T) {
	f := nativeTransaction(t)
	_, err := f.m.Create(context.Background(), f.request)
	nativeMust(t, err)
	b := f.m.boxes[f.request.Name]
	b.op.Lock()
	done := make(chan error, 1)
	go func() {
		next := sandboxruntime.PolicyAuthorityBinding{SnapshotID: "synthetic-next-generation", Generation: 2}
		done <- f.gate.Rotate(context.Background(), next, func(ctx context.Context) error {
			if err := f.m.RevokeNative(ctx); err != nil {
				return err
			}
			f.authority.Store(&next)
			return nil
		})
	}()
	select {
	case err := <-done:
		b.op.Unlock()
		nativeMust(t, err)
	case <-time.After(time.Second):
		b.op.Unlock()
		<-done
		t.Fatal("publication revoke waited for box.op or reentered gate")
	}
	if f.b.stops != 1 {
		t.Fatal("publication did not stop exact native custody")
	}
}

func nativeMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func nativeWantCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiError *sandboxapi.Error
	if !errors.As(err, &apiError) || apiError.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}
