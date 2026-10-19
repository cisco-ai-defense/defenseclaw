// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

func identities() (sandboxruntime.RuntimeIdentity, sandboxruntime.HarnessIdentity) {
	artifact := sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64)}
	return sandboxruntime.RuntimeIdentity{Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap", HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "inert-test", Artifact: artifact},
		sandboxruntime.HarnessIdentity{Version: "inert-test", HookContract: "inert-hooks", Artifact: artifact}
}

func resolved(t *testing.T, cpu string) (*sandboxruntime.ExecutionPolicy, sandboxruntime.Spec) {
	t.Helper()
	runtime, harness := identities()
	cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Resources: config.OpenShellResourcesConfig{CPU: cpu}, Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}}}
	policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, packs.Flags{Harness: "claudecode"}, sandboxruntime.PolicyOptions{Offline: true, Harness: harness,
		Authority: sandboxruntime.PolicyAuthorityBinding{SnapshotID: "inert-owner-snapshot", Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return policy, sandboxruntime.Spec{Identity: sandboxruntime.SessionIdentity{Owner: "inert-owner", ID: "inert-session", Name: "inert-name", Runtime: runtime},
		Harness: "claudecode", HarnessIdentity: harness, Offline: true, Command: []string{"/.defenseclaw/payload"}, GuestWorkspace: "/work", Env: map[string]string{"HOME": "/home", "TMPDIR": "/tmp"}}
}

func held(t *testing.T, identity sandboxruntime.SessionIdentity) *Assets {
	t.Helper()
	open := func(name string) *os.File {
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	// Empty Image objects are inert; no SealImage, launcher or namespace syscall
	// appears in this test suite. Only fake nativeCalls can consume these inputs.
	work := t.TempDir()
	a, err := NewAssets(identity, bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{},
		CWD: open(work), Read: []*os.File{open(t.TempDir())}, Write: []*os.File{open(work), open(t.TempDir()), open(t.TempDir())}}, []string{"/readonly"}, []string{"/work", "/home", "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.mu.Lock(); _ = a.closeLocked(); a.mu.Unlock() })
	return a
}

func host(t *testing.T, identity sandboxruntime.RuntimeIdentity) (*Backend, context.Context) {
	t.Helper()
	owner, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	b, err := New(owner, identity)
	if err != nil {
		t.Fatal(err)
	}
	return b, owner
}

func TestDefaultCatalogRefusesBeforeNativePreparation(t *testing.T) {
	policy, spec := resolved(t, "")
	b, _ := host(t, spec.Identity.Runtime)
	called := false
	b.calls.start = func(context.Context, bridgeproto.Binding, bridgeproto.Preparation, bridgeprocess.Inputs, bridgeowner.Limits) (*bridgeprocess.Session, error) {
		called = true
		t.Fatal("closed catalog reached native process creation")
		return nil, nil
	}
	info, err := b.Info(context.Background())
	if err != nil || info.Available || len(info.Supported) != 0 || len(info.Harnesses) != 0 {
		t.Fatalf("catalog: %+v, %v", info, err)
	}
	process, receipt, err := b.Prepare(context.Background(), policy, spec)
	if !errors.Is(err, ErrUnavailable) || process != nil || receipt.PolicyDigest != "" || called {
		t.Fatalf("closed catalog: %v", err)
	}
}

func TestUnsupportedPolicyEmitsNoReceiptOrPartialAcknowledgements(t *testing.T) {
	for _, cpu := range []string{"", "1"} {
		policy, spec := resolved(t, cpu)
		plan, receipt, err := compilePolicy(policy, spec, nil)
		var unsupported *UnsupportedPolicy
		if !errors.As(err, &unsupported) || len(plan.Argv) != 0 || !reflect.DeepEqual(receipt, sandboxruntime.PolicyReceipt{}) {
			t.Fatalf("policy was acknowledged: %+v %v", receipt, err)
		}
		want := []sandboxruntime.PolicyComponentName{sandboxruntime.PolicyCommon, sandboxruntime.PolicyAuthority, sandboxruntime.PolicyWorkspace, sandboxruntime.PolicyEgress, sandboxruntime.PolicyHarness, sandboxruntime.PolicyMCP}
		if cpu != "" {
			want = append(want, sandboxruntime.PolicyResources)
		}
		if !reflect.DeepEqual(unsupported.Components, want) {
			t.Fatalf("unsupported %v want %v", unsupported.Components, want)
		}
	}
}

func TestManagerLifetimeMustBeBoundedAndBackendExplicit(t *testing.T) {
	runtime, _ := identities()
	if _, err := New(context.Background(), runtime); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := New(nil, runtime); !errors.Is(err, ErrUnavailable) { //nolint:staticcheck // Exercise refusal of an absent owner lifetime.
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	runtime.Driver = "axis_native"
	if _, err := New(ctx, runtime); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestAssetsBindFullIdentityOnceWithoutOpeningSpecPaths(t *testing.T) {
	_, spec := resolved(t, "")
	b, _ := host(t, spec.Identity.Runtime)
	a := held(t, spec.Identity)
	other := spec.Identity
	other.Owner = "other-owner"
	if err := b.BindAssets(other, a); !errors.Is(err, ErrAssets) {
		t.Fatal(err)
	}
	if err := b.BindAssets(spec.Identity, a); err != nil {
		t.Fatal(err)
	}
	if err := b.BindAssets(spec.Identity, a); !errors.Is(err, ErrAssets) {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, ErrAssets) {
		t.Fatal("producer retained release authority")
	}
	if _, err := b.Inspect(context.Background(), other); !errors.Is(err, ErrSession) {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), other); !errors.Is(err, ErrSession) {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), spec.Identity); err != nil {
		t.Fatal(err)
	}
	if !a.closed {
		t.Fatal("unstarted owned assets not released")
	}
	// A stale full identity must never select a newly bound resource after
	// deletion, even when a producer supplies a fresh set of held objects.
	fresh := held(t, spec.Identity)
	if err := b.BindAssets(spec.Identity, fresh); !errors.Is(err, ErrAssets) || fresh.claimed {
		t.Fatal("deleted immutable session ID was reused")
	}
}

// All preparation/launch tests below use private fake function injection. They
// never call real bridgeprocess.Start, an image, clone, mount or a worker entry.
type fakePeer struct {
	binding                  bridgeproto.Binding
	request                  uint64
	kind                     bridgeproto.Kind
	starts, launches, closes int
	lifetime                 context.Context
	closeErr                 error
}

func fakeHost(t *testing.T) (*Backend, *fakePeer, *sandboxruntime.ExecutionPolicy, sandboxruntime.Spec, *Assets) {
	t.Helper()
	policy, spec := resolved(t, "")
	b, _ := host(t, spec.Identity.Runtime)
	// This synthetic qualification is private to tests and is never a runtime
	// registry entry or receipt from an external client.
	b.info.Available = true
	b.info.Supported = policy.RequiredCapabilities()
	b.info.Harnesses = map[string]sandboxruntime.HarnessVerification{spec.Harness: {Identity: spec.HarnessIdentity, Supported: policy.RequiredCapabilities()}}
	a := held(t, spec.Identity)
	if err := b.BindAssets(spec.Identity, a); err != nil {
		t.Fatal(err)
	}
	f := &fakePeer{}
	b.calls = nativeCalls{
		start: func(ctx context.Context, binding bridgeproto.Binding, _ bridgeproto.Preparation, _ bridgeprocess.Inputs, _ bridgeowner.Limits) (*bridgeprocess.Session, error) {
			f.starts++
			f.binding = binding
			f.lifetime = ctx
			return &bridgeprocess.Session{}, nil
		},
		send: func(_ context.Context, _ *bridgeprocess.Session, command bridgeowner.Command) (uint64, error) {
			f.request++
			f.kind = command.Kind
			if command.Kind == bridgeproto.Launch {
				f.launches++
			}
			return f.request, nil
		},
		receive: func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error) {
			kind := bridgeproto.Prepared
			if f.kind == bridgeproto.Launch {
				kind = bridgeproto.Started
			}
			return bridgeproto.Frame{Version: bridgeproto.Version, Sequence: f.request, Request: f.request, Binding: f.binding, Kind: kind}, nil
		},
		close: func(ctx context.Context, _ *bridgeprocess.Session) cleanupObservation {
			f.closes++
			if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
				t.Error("cleanup did not get a fresh bounded context")
			}
			return cleanupObservation{complete: f.closeErr == nil, err: f.closeErr}
		},
	}
	b.compile = func(p *sandboxruntime.ExecutionPolicy, s sandboxruntime.Spec, a *Assets) (bridgeproto.Preparation, sandboxruntime.PolicyReceipt, error) {
		receipt := sandboxruntime.PolicyReceipt{Runtime: s.Identity.Runtime, Harness: s.HarnessIdentity, PolicyDigest: p.Digest()}
		for _, component := range p.Components() {
			receipt.Components = append(receipt.Components, sandboxruntime.PolicyComponentBinding{Name: component.Name, Digest: component.Digest})
		}
		return bridgeproto.Preparation{Backend: "bubblewrap", Argv: append([]string{}, s.Command...), Environment: []bridgeproto.Variable{{Name: "HOME", Value: "/home"}, {Name: "TMPDIR", Value: "/tmp"}}, Workdir: "/work",
				Filesystem: bridgeproto.Filesystem{Read: append([]string{}, a.read...), Write: append([]string{}, a.write...), Deny: []string{}}, Offline: true, TimeoutMS: 5000, OutputLimit: 65536},
			receipt, nil
	}
	return b, f, policy, spec, a
}

func TestPreparedLaunchIsFrozenSingleUseAndNotRequestLifetime(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	process, _, err := b.Prepare(ctx, policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if f.lifetime.Err() != nil || f.starts != 1 || f.launches != 0 {
		t.Fatal("request owned the prepared lifetime or preparation launched payload")
	}
	changed := cloneSpec(spec)
	changed.Command = append(changed.Command, "different")
	if _, err := process.Launch(context.Background(), changed); !errors.Is(err, ErrSession) {
		t.Fatal(err)
	}
	if _, err := process.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if _, err := process.Launch(context.Background(), spec); !errors.Is(err, ErrSession) || f.launches != 1 {
		t.Fatalf("launch replay: %v", err)
	}
	if err := process.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.closed || f.closes != 1 || f.lifetime.Err() == nil {
		t.Fatal("exact native custody/assets not closed")
	}
}

func TestCancelledPreparationRetainsFailedCleanupForExactRetry(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	wait := make(chan struct{})
	b.calls.start = func(lifetime context.Context, _ bridgeproto.Binding, _ bridgeproto.Preparation, _ bridgeprocess.Inputs, _ bridgeowner.Limits) (*bridgeprocess.Session, error) {
		close(wait)
		<-lifetime.Done()
		return &bridgeprocess.Session{}, lifetime.Err()
	}
	f.closeErr = errors.New("synthetic unobserved native wait")
	done := make(chan error, 1)
	go func() { _, _, err := b.Prepare(ctx, policy, spec); done <- err }()
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("prepare did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("preparation cancellation leaked")
	}
	if a.closed || f.closes != 1 {
		t.Fatal("failed cleanup released assets")
	}
	observed, err := b.Inspect(context.Background(), spec.Identity)
	if err != nil || observed.Phase != "cleanup_pending" {
		t.Fatalf("lost pending custody: %+v %v", observed, err)
	}
	f.closeErr = nil
	if err := b.Delete(context.Background(), spec.Identity); err != nil {
		t.Fatal(err)
	}
	if !a.closed || f.closes != 2 {
		t.Fatal("retry did not observe same custody before release")
	}
}

func TestReplyMismatchCleansExactNativeAndReturnsNoPreparedHandle(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	b.calls.receive = func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error) {
		return bridgeproto.Frame{Version: 1, Sequence: 1, Request: f.request, Binding: f.binding, Kind: bridgeproto.Started}, nil
	}
	process, receipt, err := b.Prepare(context.Background(), policy, spec)
	if !errors.Is(err, bridgeproto.ErrProtocol) || process != nil || receipt.PolicyDigest != "" || !a.closed || f.closes != 1 {
		t.Fatalf("mismatch cleanup: %v", err)
	}
}

func TestCloseDeadlineRetainsBusyEntryInsteadOfBlockingOnOperation(t *testing.T) {
	b, _, _, spec, a := fakeHost(t)
	e, err := b.find(spec.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := b.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy cleanup: %v", err)
	}
	if a.closed {
		t.Fatal("busy resources were released")
	}
	e.release()
	if err := b.Close(context.Background()); err != nil || !a.closed {
		t.Fatalf("cleanup retry: %v", err)
	}
}

func TestManagerCloseCancelsInFlightNativePreparationBeforeOperationWait(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	started := make(chan struct{})
	b.calls.start = func(lifetime context.Context, _ bridgeproto.Binding, _ bridgeproto.Preparation, _ bridgeprocess.Inputs, _ bridgeowner.Limits) (*bridgeprocess.Session, error) {
		close(started)
		<-lifetime.Done()
		return &bridgeprocess.Session{}, lifetime.Err()
	}
	done := make(chan error, 1)
	go func() { _, _, err := b.Prepare(context.Background(), policy, spec); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native preparation not reached")
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager shutdown stranded preparation")
	}
	if !a.closed || f.closes != 1 {
		t.Fatal("manager did not retain and finish native ownership")
	}
}

func TestClosingEntryRefusesLateLifetimeRegistration(t *testing.T) {
	e := &entry{operation: make(chan struct{}, 1)}
	e.requestClose()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if e.attachLifetime(cancel) {
		t.Fatal("closed entry accepted late native lifetime")
	}
	if ctx.Err() != nil {
		t.Fatal("refused registration changed caller ownership")
	}
}

func TestCompilationBoundaryRefusesIncompleteReceiptOrCredentialEnvironmentBeforeStart(t *testing.T) {
	for _, mode := range []string{"missing-component", "changed-grant", "credential-environment"} {
		t.Run(mode, func(t *testing.T) {
			b, f, policy, spec, _ := fakeHost(t)
			original := b.compile
			b.compile = func(p *sandboxruntime.ExecutionPolicy, s sandboxruntime.Spec, a *Assets) (bridgeproto.Preparation, sandboxruntime.PolicyReceipt, error) {
				plan, receipt, err := original(p, s, a)
				switch mode {
				case "missing-component":
					receipt.Components = receipt.Components[1:]
				case "changed-grant":
					plan.Filesystem.Write = append(plan.Filesystem.Write, "/host-root")
				case "credential-environment":
					plan.Environment = append(plan.Environment, bridgeproto.Variable{Name: "ANTHROPIC_API_KEY", Value: "fixed-public-inert-canary"})
				}
				return plan, receipt, err
			}
			process, receipt, err := b.Prepare(context.Background(), policy, spec)
			if !errors.Is(err, ErrPolicy) || process != nil || receipt.PolicyDigest != "" || f.starts != 0 {
				t.Fatalf("incomplete compilation reached native: %v", err)
			}
		})
	}
}

func TestPrepareUsesHeldObjectsAndNeverSpecHostWorkspaceAsAuthority(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	spec.HostWorkspace = "inert-unopenable-metadata://not-a-host-source"
	original := b.calls.start
	b.calls.start = func(ctx context.Context, binding bridgeproto.Binding, plan bridgeproto.Preparation, inputs bridgeprocess.Inputs, limits bridgeowner.Limits) (*bridgeprocess.Session, error) {
		if inputs.CWD != a.inputs.CWD || inputs.Payload != a.inputs.Payload {
			t.Fatal("held capabilities were replaced")
		}
		return original(ctx, binding, plan, inputs, limits)
	}
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil || f.starts != 1 {
		t.Fatal(err)
	}
	if err := process.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStickyProtocolFailureDoesNotHoldVerifiedCleanNativeAssets(t *testing.T) {
	b, _, policy, spec, a := fakeHost(t)
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	sticky := errors.New("synthetic sticky protocol cause")
	waitObserved := false
	b.calls.close = func(ctx context.Context, _ *bridgeprocess.Session) cleanupObservation {
		return observeCleanup(ctx,
			func(context.Context) error { return sticky },
			func(context.Context) error { waitObserved = true; return nil })
	}
	if err := process.Close(context.Background()); !errors.Is(err, sticky) {
		t.Fatal("protocol failure was laundered", err)
	}
	observed, err := b.Inspect(context.Background(), spec.Identity)
	if err != nil || !waitObserved || !a.closed || observed.Phase != "failed_closed" {
		t.Fatalf("verified cleanup leaked assets: %+v %v", observed, err)
	}
}

func TestCleanupObservationRefusesExpiredContextOrUnobservedNativeWait(t *testing.T) {
	for _, expire := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		failure := errors.New("synthetic native wait pending")
		observation := observeCleanup(ctx,
			func(context.Context) error {
				if expire {
					cancel()
				}
				return nil
			},
			func(context.Context) error {
				if !expire {
					return failure
				}
				return nil
			})
		cancel()
		if observation.complete {
			t.Fatal("cleanup uncertainty became complete")
		}
	}
}

func TestAssetCloseFailureRemainsFailureOnRetry(t *testing.T) {
	b, _, policy, spec, a := fakeHost(t)
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Inert fault injection: violate exclusive ownership of one test descriptor
	// to force a real Close error. No native runtime or image is executed.
	if err := a.inputs.Read[0].Close(); err != nil {
		t.Fatal(err)
	}
	first := process.Close(context.Background())
	second := process.Close(context.Background())
	if first == nil || second == nil || a.closeErr == nil {
		t.Fatal("asset close failure was cleared on retry")
	}
}

func TestConcurrentStopPreventsLatePreparedReplyFromReportingSuccess(t *testing.T) {
	b, f, policy, spec, a := fakeHost(t)
	receiving, release := make(chan struct{}), make(chan struct{})
	original := b.calls.receive
	b.calls.receive = func(ctx context.Context, s *bridgeprocess.Session) (bridgeproto.Frame, error) {
		close(receiving)
		<-release
		return original(ctx, s)
	}
	preparedResult := make(chan error, 1)
	go func() {
		process, receipt, err := b.Prepare(context.Background(), policy, spec)
		if process != nil || receipt.PolicyDigest != "" {
			preparedResult <- errors.New("closed preparation reported success")
			return
		}
		preparedResult <- err
	}()
	select {
	case <-receiving:
	case <-time.After(time.Second):
		t.Fatal("prepare never reached reply barrier")
	}
	stopped := make(chan error, 1)
	go func() { _, err := b.Stop(context.Background(), spec.Identity); stopped <- err }()
	select {
	case <-f.lifetime.Done():
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel preparation")
	}
	close(release)
	select {
	case err := <-preparedResult:
		if !errors.Is(err, ErrSession) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late preparation hung")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete")
	}
	if !a.closed {
		t.Fatal("stopped preparation retained clean assets")
	}
}
