// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package backend connects the existing runtime contract to actual private
// bridgeprocess ownership. Installation and full policy qualification remain
// closed; constructing this backend starts no process, worker or listener.
package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

var (
	ErrUnavailable = errors.New("AXIS native customer runtime is not qualified")
	ErrAssets      = errors.New("AXIS requires exclusive held assets bound to the complete session identity")
	ErrPolicy      = errors.New("AXIS requires a complete translated host execution policy")
	ErrSession     = errors.New("AXIS session is absent, mismatched, consumed or closing")
)

const cleanupTimeout = 10 * time.Second

// nativeCalls is private test injection over the existing concrete session,
// not another controller/custody abstraction or caller-supplied launcher.
type cleanupObservation struct {
	complete bool
	err      error
}

type nativeCalls struct {
	start   func(context.Context, bridgeproto.Binding, bridgeproto.Preparation, bridgeprocess.Inputs, bridgeowner.Limits) (*bridgeprocess.Session, error)
	send    func(context.Context, *bridgeprocess.Session, bridgeowner.Command) (uint64, error)
	receive func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error)
	close   func(context.Context, *bridgeprocess.Session) cleanupObservation
}

func actualCalls() nativeCalls {
	return nativeCalls{start: bridgeprocess.Start,
		send: func(ctx context.Context, s *bridgeprocess.Session, c bridgeowner.Command) (uint64, error) {
			return s.Protocol.Send(ctx, c)
		},
		receive: func(ctx context.Context, s *bridgeprocess.Session) (bridgeproto.Frame, error) {
			return s.Protocol.Receive(ctx)
		},
		close: func(ctx context.Context, s *bridgeprocess.Session) cleanupObservation {
			if s == nil || s.Protocol == nil {
				return cleanupObservation{err: ErrSession}
			}
			return observeCleanup(ctx, s.Protocol.Close, s.StopAndWait)
		},
	}
}

func observeCleanup(ctx context.Context, closeProtocol, waitNative func(context.Context) error) cleanupObservation {
	protocolErr := closeProtocol(ctx)
	nativeErr := waitNative(ctx)
	// Start returns a nonnil Session only with an initialized Owner.
	// Close returns through Owner.done when this fresh context remains
	// live: its workers have joined even if its protocol cause is sticky.
	// Independent native wait, never that protocol cause, proves custody.
	return cleanupObservation{complete: ctx.Err() == nil && nativeErr == nil, err: errors.Join(protocolErr, nativeErr, ctx.Err())}
}

type entry struct {
	operation         chan struct{} // one bounded, context-aware lifecycle operation
	assets            *Assets
	spec              sandboxruntime.Spec
	binding           bridgeproto.Binding
	native            *bridgeprocess.Session
	cancelMu          sync.Mutex
	cancel            context.CancelFunc
	closing           bool
	phase             string
	consumed          bool
	created           time.Time
	launchRequest     uint64
	executionTimeout  time.Duration
	executionDeadline time.Time
	outputLimit       uint32
	attached          bool
}

type Backend struct {
	mu      sync.Mutex
	owner   context.Context
	info    sandboxruntime.RuntimeInfo
	entries map[string]*entry
	usedIDs map[string]struct{}
	closed  bool
	calls   nativeCalls
	compile func(*sandboxruntime.ExecutionPolicy, sandboxruntime.Spec, *Assets) (bridgeproto.Preparation, sandboxruntime.PolicyReceipt, error)
}

var _ sandboxruntime.Backend = (*Backend)(nil)

// New takes the trusted manager's session-lifetime context, never an HTTP/create
// request context. It requires an absolute bounded deadline. Identity is host
// metadata, not artifact admission; this constructor's catalog stays unavailable
// and advertises no capabilities or harness qualification. No public option can
// promote fixed test evidence into a customer capability.
func New(owner context.Context, identity sandboxruntime.RuntimeIdentity) (*Backend, error) {
	if owner == nil {
		return nil, ErrUnavailable
	}
	deadline, bounded := owner.Deadline()
	if owner.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour ||
		identity.Validate() != nil || identity.Runtime != sandboxruntime.Axis || identity.Backend != "mxc" ||
		identity.Driver != "bubblewrap" || identity.HostOS != "linux" || identity.ExecutionOS != "linux" || identity.Architecture != "amd64" {
		return nil, ErrUnavailable
	}
	return &Backend{owner: owner, info: sandboxruntime.RuntimeInfo{Identity: identity,
		Reason:  "native lifecycle, full policy, hooks, transport and credential qualification is incomplete",
		Posture: "unqualified"}, entries: map[string]*entry{}, usedIDs: map[string]struct{}{}, calls: actualCalls(), compile: compilePolicy}, nil
}

func (b *Backend) Info(ctx context.Context) (sandboxruntime.RuntimeInfo, error) {
	if err := ctx.Err(); err != nil {
		return sandboxruntime.RuntimeInfo{}, err
	}
	// No mutable caller-owned maps/slices are retained by the public catalog.
	info := b.info
	info.Supported = slices.Clone(info.Supported)
	info.Unavailable = make(map[sandboxruntime.Capability]string, len(b.info.Unavailable))
	for capability, reason := range b.info.Unavailable {
		info.Unavailable[capability] = reason
	}
	info.Harnesses = make(map[string]sandboxruntime.HarnessVerification, len(b.info.Harnesses))
	for name, verification := range b.info.Harnesses {
		verification.Supported = slices.Clone(verification.Supported)
		info.Harnesses[name] = verification
	}
	return info, nil
}

// BindAssets reserves one complete identity and transfers held asset custody.
// This is a trusted manager operation, not an API/guest path or hash admission.
// Repeating a name, changing an owner or reusing Assets never replaces a record.
func (b *Backend) BindAssets(identity sandboxruntime.SessionIdentity, assets *Assets) error {
	if assets == nil || identity.Validate() != nil || identity.Runtime != b.info.Identity {
		return ErrAssets
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	assets.mu.Lock()
	defer assets.mu.Unlock()
	_, used := b.usedIDs[identity.ID]
	if b.closed || b.owner.Err() != nil || len(b.entries) >= 64 || len(b.usedIDs) >= 4096 || used || assets.cleanupOnly || assets.claimed || assets.closed || assets.identity != identity {
		return ErrAssets
	}
	assets.claimed = true
	b.usedIDs[identity.ID] = struct{}{}
	b.entries[identity.ID] = &entry{assets: assets, phase: "bound", operation: make(chan struct{}, 1)}
	return nil
}

func (b *Backend) find(identity sandboxruntime.SessionIdentity) (*entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[identity.ID]
	if e == nil || sandboxruntime.ValidateOwnedSession(e.assets.identity, identity) != nil {
		return nil, ErrSession
	}
	return e, nil
}

func cloneSpec(spec sandboxruntime.Spec) sandboxruntime.Spec {
	spec.Command = slices.Clone(spec.Command)
	if spec.Env != nil {
		env := make(map[string]string, len(spec.Env))
		for key, value := range spec.Env {
			env[key] = value
		}
		spec.Env = env
	}
	return spec
}

func localDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func makeBinding(policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, plan bridgeproto.Preparation) (bridgeproto.Binding, error) {
	preparation, err := bridgeproto.PreparationDigest(plan)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	session, err := localDigest(spec.Identity)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	runtime, err := localDigest(spec.Identity.Runtime)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	harness, err := localDigest(spec.HarnessIdentity)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	binding := bridgeproto.Binding{SessionID: spec.Identity.ID, SessionDigest: session, PolicyDigest: policy.Digest(), RuntimeDigest: runtime, HarnessDigest: harness, PreparationHash: preparation}
	return binding, binding.Validate()
}

func (b *Backend) Prepare(ctx context.Context, policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec) (sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	if policy.Digest() == "" || spec.Identity.Validate() != nil || spec.Identity.Runtime != b.info.Identity {
		return nil, sandboxruntime.PolicyReceipt{}, ErrPolicy
	}
	// Only a future reviewed source registry may enable this private path.
	// RuntimeInfo supplied by an API, the peer or a fixed test is never used.
	if !b.info.Available {
		return nil, sandboxruntime.PolicyReceipt{}, ErrUnavailable
	}
	if err := b.info.RequireHarness(spec.Harness, spec.HarnessIdentity, policy.RequiredCapabilities()...); err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	e, err := b.find(spec.Identity)
	if err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	if err := e.acquire(ctx); err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	defer e.release()
	if e.phase != "bound" || !b.active() {
		return nil, sandboxruntime.PolicyReceipt{}, ErrSession
	}
	spec = cloneSpec(spec)
	plan, receipt, err := b.compile(policy, spec, e.assets)
	if err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	if err := validateCompilation(policy, spec, e.assets, plan, receipt); err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	binding, err := makeBinding(policy, spec, plan)
	if err != nil {
		return nil, sandboxruntime.PolicyReceipt{}, err
	}
	e.phase, e.spec, e.binding = "preparing", spec, binding
	e.executionTimeout = time.Duration(plan.TimeoutMS) * time.Millisecond
	e.outputLimit = plan.OutputLimit
	lifetime, cancel := context.WithCancel(b.owner)
	if !e.attachLifetime(cancel) {
		cancel()
		return nil, sandboxruntime.PolicyReceipt{}, ErrSession
	}
	// Request cancellation affects preparation, while successful return detaches
	// that callback. The native owner's deadline always remains manager-owned.
	stopRequest := context.AfterFunc(ctx, cancel)
	e.native, err = b.calls.start(lifetime, binding, plan, e.assets.inputs, bridgeowner.Limits{WriteTimeout: 5 * time.Second, CleanupTimeout: cleanupTimeout})
	if err == nil && e.native == nil {
		err = ErrSession
	}
	if err == nil {
		var request uint64
		request, err = b.calls.send(ctx, e.native, bridgeowner.Command{Kind: bridgeproto.Prepare, Plan: &plan})
		if err == nil {
			err = b.reply(ctx, e, request, bridgeproto.Prepared)
		}
	}
	if !stopRequest() && ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (!b.active() || e.isClosing() || lifetime.Err() != nil) {
		err = errors.Join(ErrSession, lifetime.Err())
	}
	if err != nil {
		cancel()
		cleanupCtx, done := context.WithTimeout(context.WithoutCancel(b.owner), cleanupTimeout)
		defer done()
		return nil, sandboxruntime.PolicyReceipt{}, errors.Join(err, b.closeEntry(cleanupCtx, e))
	}
	e.phase, e.created = "prepared", time.Now()
	return &prepared{backend: b, entry: e}, receipt, nil
}

func (b *Backend) reply(ctx context.Context, e *entry, request uint64, kind bridgeproto.Kind) error {
	frame, err := b.calls.receive(ctx, e.native)
	if err != nil {
		return err
	}
	if frame.Validate() != nil || frame.Binding != e.binding || frame.Request != request || frame.Kind != kind {
		return bridgeproto.ErrProtocol
	}
	return nil
}

// closeEntry runs under the entry operation token. Native success, independently of protocol replies,
// is required before releasing assets. Errors leave the same exact entry and
// concrete session reachable for Stop/Delete/Close retry; no PID adoption occurs.
func (b *Backend) closeEntry(ctx context.Context, e *entry) error {
	if e.phase == "closed" || e.phase == "failed_closed" {
		return nil
	}
	e.phase = "cleanup_pending"
	e.cancelMu.Lock()
	e.closing = true
	cancel := e.cancel
	e.cancelMu.Unlock()
	if cancel != nil {
		defer cancel()
	}
	var protocolErr error
	if e.native != nil {
		observation := b.calls.close(ctx, e.native)
		if !observation.complete {
			if observation.err != nil {
				return observation.err
			}
			return ErrSession
		}
		protocolErr = observation.err
	}
	e.assets.mu.Lock()
	err := e.assets.closeLocked()
	e.assets.mu.Unlock()
	if err != nil {
		return errors.Join(protocolErr, err)
	}
	e.phase = "closed"
	if protocolErr != nil {
		e.phase = "failed_closed"
	}
	return protocolErr
}

func instance(e *entry) sandboxruntime.Instance {
	return sandboxruntime.Instance{Identity: e.assets.identity, Phase: e.phase, Workdir: e.spec.GuestWorkspace, CreatedAt: e.created}
}

func (b *Backend) Inspect(ctx context.Context, identity sandboxruntime.SessionIdentity) (sandboxruntime.Instance, error) {
	if err := ctx.Err(); err != nil {
		return sandboxruntime.Instance{}, err
	}
	e, err := b.find(identity)
	if err != nil {
		return sandboxruntime.Instance{}, err
	}
	if err := e.acquire(ctx); err != nil {
		return sandboxruntime.Instance{}, err
	}
	defer e.release()
	return instance(e), nil
}

func (b *Backend) Stop(ctx context.Context, identity sandboxruntime.SessionIdentity) (sandboxruntime.Instance, error) {
	e, err := b.find(identity)
	if err != nil {
		return sandboxruntime.Instance{}, err
	}
	e.requestClose()
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()
	if err := e.acquire(cleanup); err != nil {
		return sandboxruntime.Instance{}, err
	}
	defer e.release()
	err = b.closeEntry(cleanup, e)
	return instance(e), err
}

func (b *Backend) Delete(ctx context.Context, identity sandboxruntime.SessionIdentity) error {
	if _, err := b.Stop(ctx, identity); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, identity.ID)
	return nil
}

// Exec never starts a second process or uncancellable generic stream worker.
// Production streaming/re-exec needs a separately admitted bounded transport.
func (b *Backend) Exec(context.Context, sandboxruntime.SessionIdentity, sandboxruntime.Command, sandboxruntime.ProcessIO) (sandboxruntime.ExecResult, error) {
	return sandboxruntime.ExecResult{}, ErrUnavailable
}

// Close is called by the manager on shutdown. One shared cleanup deadline bounds
// all retained entries. A failure retains custody in b for another explicit call.
func (b *Backend) Close(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	entries := make([]*entry, 0, len(b.entries))
	for _, e := range b.entries {
		entries = append(entries, e)
	}
	b.mu.Unlock()
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()
	var errs []error
	for _, e := range entries {
		e.requestClose()
		if err := e.acquire(cleanup); err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, b.closeEntry(cleanup, e))
		e.release()
	}
	return errors.Join(errs...)
}

type prepared struct {
	backend *Backend
	entry   *entry
}

func (p *prepared) Launch(ctx context.Context, spec sandboxruntime.Spec) (sandboxruntime.Instance, error) {
	e, b := p.entry, p.backend
	if err := e.acquire(ctx); err != nil {
		return sandboxruntime.Instance{}, err
	}
	defer e.release()
	if e.phase != "prepared" || e.consumed || !b.active() || e.isClosing() || !reflect.DeepEqual(spec, e.spec) {
		return sandboxruntime.Instance{}, ErrSession
	}
	e.consumed = true
	deadline := time.Now().Add(e.executionTimeout)
	if parent, ok := b.owner.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	request, err := b.calls.send(ctx, e.native, bridgeowner.Command{Kind: bridgeproto.Launch})
	if err == nil {
		err = b.reply(ctx, e, request, bridgeproto.Started)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (!b.active() || e.isClosing()) {
		err = ErrSession
	}
	if err != nil {
		cleanup, cancel := cleanupContext(ctx)
		defer cancel()
		return sandboxruntime.Instance{}, errors.Join(err, b.closeEntry(cleanup, e))
	}
	e.phase = "started"
	e.launchRequest, e.executionDeadline = request, deadline
	return instance(e), nil
}

func (p *prepared) Close(ctx context.Context) error {
	e := p.entry
	e.requestClose()
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()
	if err := e.acquire(cleanup); err != nil {
		return err
	}
	defer e.release()
	return p.backend.closeEntry(cleanup, e)
}

func (e *entry) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case e.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (e *entry) release() { <-e.operation }

func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	duration := cleanupTimeout
	if ctx.Err() == nil {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < duration {
			duration = time.Until(deadline)
		}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), duration)
}

func (b *Backend) active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed && b.owner.Err() == nil
}
func (e *entry) attachLifetime(cancel context.CancelFunc) bool {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	if e.closing {
		return false
	}
	e.cancel = cancel
	return true
}
func (e *entry) requestClose() {
	e.cancelMu.Lock()
	e.closing = true
	cancel := e.cancel
	busy := len(e.operation) != 0
	e.cancelMu.Unlock()
	// Interrupt an in-flight operation before waiting for its token. An idle
	// session closes the protocol first, so normal teardown is not relabeled
	// as a request-cancellation failure by the owner's sticky error record.
	if busy && cancel != nil {
		cancel()
	}
}
func (e *entry) isClosing() bool {
	e.cancelMu.Lock()
	defer e.cancelMu.Unlock()
	return e.closing
}
