// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// NativeExecution is the existing manager's optional native dependency, not a
// second controller or a source of qualification. Only the trusted host owner
// constructs it. The backend must report independently qualified production capabilities.
// Resolution must be the owner's real publication transaction; the producer
// must choose admitted immutable command/image objects and derive capture from
// that same HostResolvedRun/ExecutionPolicy. No request digest or receipt enters
// this dependency. It supports one headless offline launch, not restart/export.
type NativeExecution struct {
	owner   context.Context
	backend sandboxruntime.Backend
	gate    *sandboxruntime.LaunchGate
	resolve func(packs.Flags, sandboxruntime.PolicyOptions) (*sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, []packs.Violation, error)
	prepare func(context.Context, *sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, sandboxruntime.SessionIdentity) (sandboxruntime.Spec, sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error)
}

// NewNativeExecution takes host-owned dependencies. The factory performs the
// provider-specific held-asset admission/binding and Backend.Prepare. Every
// nonnil PreparedProcess, including on error, transfers cleanup to the manager.
// A nil process on error requires completed factory cleanup; uncertain partial
// custody must return a nonnil cleanup-only process. No wire receipt is accepted.
func NewNativeExecution(owner context.Context, backend sandboxruntime.Backend, gate *sandboxruntime.LaunchGate,
	resolve func(packs.Flags, sandboxruntime.PolicyOptions) (*sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, []packs.Violation, error),
	prepare func(context.Context, *sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, sandboxruntime.SessionIdentity) (sandboxruntime.Spec, sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error),
) (*NativeExecution, error) {
	if owner == nil || backend == nil || gate == nil || resolve == nil || prepare == nil {
		return nil, nativeUnavailable()
	}
	if value := reflect.ValueOf(backend); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, nativeUnavailable()
	}
	deadline, bounded := owner.Deadline()
	if owner.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return nil, nativeUnavailable()
	}
	return &NativeExecution{owner: owner, backend: backend, gate: gate, resolve: resolve, prepare: prepare}, nil
}

func nativeUnavailable() error {
	return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "AXIS sandbox execution is not available: native policy enforcement and harness integration are still being qualified")
}

func nativeUnsupported() error {
	return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "this operation is not qualified for the owned native session")
}

type nativeSession struct {
	runtime          *NativeExecution
	identity         sandboxruntime.SessionIdentity
	prepared         sandboxruntime.PreparedProcess
	registered       *sandboxruntime.PreparedLaunch
	preparedComplete bool
	launchAttempted  bool
	instance         sandboxruntime.Instance
	cleanupPending   bool
	// revision invalidates in-flight observations when revocation bypasses
	// box.op. It and instance/cleanupPending are guarded by Manager.mu.
	revision uint64
}

func (m *Manager) createNative(ctx context.Context, req sandboxapi.CreateRequest) (_ *sandboxapi.Sandbox, result error) {
	n := m.opts.Native
	if n == nil || n.owner == nil || n.owner.Err() != nil || n.backend == nil || n.gate == nil || n.resolve == nil || n.prepare == nil {
		return nil, nativeUnavailable()
	}
	lifetime := m.running()
	m.mu.Lock()
	closed := m.nativeClosed
	m.mu.Unlock()
	if closed || lifetime == nil || lifetime.Err() != nil {
		return nil, nativeUnavailable()
	}
	deadline := time.Now().Add(defaultCreateTimeout)
	for _, source := range []context.Context{n.owner, lifetime} {
		if end, bounded := source.Deadline(); bounded && end.Before(deadline) {
			deadline = end
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stopOwner, stopManager := context.AfterFunc(n.owner, cancel), context.AfterFunc(lifetime, cancel)
	defer func() { stopOwner(); stopManager(); cancel() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := n.backend.Info(ctx)
	if err != nil {
		return nil, err
	}
	if info.Identity.Runtime != sandboxruntime.Axis {
		return nil, nativeUnavailable()
	}
	if err := info.Require(); err != nil {
		return nil, err
	}
	if !m.config().SandboxRuntimeEnabled(string(sandboxruntime.Axis)) {
		return nil, sandboxapi.Errorf(sandboxapi.CodeDisabled, sandboxapi.DisabledMessage)
	}
	name := config.NormalizeConnectorName(req.Harness)
	if _, ok := harness.Get(name); !ok {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown harness %q", req.Harness)
	}
	verified, ok := info.Harnesses[name]
	if !ok || verified.Identity.Validate() != nil {
		return nil, nativeUnavailable()
	}
	if err := info.RequireHarness(name, verified.Identity); err != nil {
		return nil, err
	}
	// The current native mechanism is offline. Do not accept secrets or options
	// whose required broker/additional-root/environment translation is absent.
	if req.LLM != nil || len(req.Credentials) != 0 || len(req.Context) != 0 || len(req.Env) != 0 || req.TimeZone != "" {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "native offline preparation does not admit credentials, context roots or environment overrides")
	}
	if err := m.listenersReady(); err != nil {
		return nil, err
	}
	project, err := realProject(req.Project)
	if err != nil {
		return nil, err
	}
	repo, err := m.repoPolicy(project, req.RepoPolicyDigest)
	if err != nil {
		return nil, err
	}
	flags := runFlags{Pack: req.Pack, Profile: req.Profile, Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo,
		Unmask: slices.Clone(req.Unmask), HostPorts: slices.Clone(req.HostPorts), NoMCP: req.NoMCP, Learn: req.Learn,
		CPU: req.CPU, Memory: req.Memory, ProcessTree: req.ProcessTree, RepoPolicy: repo}
	resolvedFlags := flags.packs(name, project, gatewayFacts{})
	resolvedFlags.MountUnsupported = "native live workspace execution is not qualified"
	run, policy, violations, err := n.resolve(resolvedFlags, sandboxruntime.PolicyOptions{Harness: verified.Identity, Offline: true})
	if err != nil {
		return nil, err
	}
	if run == nil || policy == nil {
		return nil, nativeUnavailable()
	}
	effective, _, err := run.PlanningPolicy()
	if err != nil {
		return nil, err
	}
	if fatal := packs.FirstFatal(violations); fatal != nil {
		return nil, m.violationError(ctx, fatal, req.Name)
	}
	if effective.Workspace.Mode != config.OpenShellWorkdirCopy || effective.Harness != name {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "native preparation requires its admitted copied workspace and harness")
	}
	if err := info.RequireHarness(name, verified.Identity, policy.RequiredCapabilities()...); err != nil {
		return nil, err
	}
	if err := m.checkPolicySources(effective.Workspace.Mode, project, effective); err != nil {
		return nil, err
	}
	sandboxName := strings.TrimSpace(req.Name)
	if sandboxName == "" {
		sandboxName, err = GenerateName(project)
		if err != nil {
			return nil, err
		}
	}
	if !openshell.ValidNewSandboxName(sandboxName) || workspace.ValidateName(sandboxName) != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "invalid sandbox name")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	identity := sandboxruntime.SessionIdentity{Owner: m.opts.Owner, ID: hex.EncodeToString(nonce[:]), Name: sandboxName, Runtime: info.Identity}
	session := &nativeSession{runtime: n, identity: identity, instance: sandboxruntime.Instance{Identity: identity, Phase: "bound"}}
	b, err := m.reserveExecution(sandboxName, project, effective.Workspace.Mode, session)
	if err != nil {
		return nil, err
	}
	b.op.Lock()
	defer b.op.Unlock()
	m.mu.Lock()
	b.rec.Owner, b.rec.ID, b.rec.Harness, b.rec.Flags = identity.Owner, identity.ID, name, flags
	b.rec.Profile, b.rec.NetworkMode, b.rec.Approvals, b.rec.Yolo = effective.Profile, effective.NetworkMode, effective.Approvals, effective.Yolo
	if effective.Pack != nil {
		b.rec.Pack, b.rec.PackDigest = effective.Pack.Name, effective.Pack.Digest
	}
	b.eff, b.violations = effective, slices.Clone(violations)
	m.mu.Unlock()
	committed, cleaned := false, false
	rb := &rollback{}
	rb.add("native execution", func(cleanup context.Context) error {
		err := m.cleanupNative(cleanup, b)
		cleaned = err == nil
		return err
	})
	defer func() {
		if committed {
			return
		}
		rb.run(m, sandboxName)
		if cleaned {
			m.release(sandboxName, b)
			return
		}
		m.mu.Lock()
		b.creating = false
		b.phase = audit.SandboxPhaseError
		session.cleanupPending = true
		b.rec.PhaseReason = "native cleanup remains owned and pending"
		m.mu.Unlock()
		result = errors.Join(result, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "native cleanup remains pending; delete the retained sandbox to retry"))
	}()
	spec, prepared, receipt, err := n.prepare(ctx, run, policy, identity)
	session.prepared = prepared
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	session.preparedComplete = true
	m.mu.Unlock()
	if sandboxruntime.ValidateOwnedSession(identity, spec.Identity) != nil || spec.Harness != name || spec.HarnessIdentity != verified.Identity || !spec.Offline {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "native producer returned a different execution identity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := n.owner.Err(); err != nil {
		return nil, err
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	registered, err := n.gate.RegisterPrepared(policy, info, receipt, spec, prepared)
	if err != nil {
		return nil, err
	}
	session.registered = registered
	// Launch consumes the gate handle even on refusal. Cleanup afterward uses
	// the retained concrete backend identity, never replays Abort or a PID.
	session.launchAttempted = true
	instance, err := n.gate.Launch(ctx, registered)
	if err != nil {
		return nil, err
	}
	if err := n.owner.Err(); err != nil {
		return nil, err
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	session.instance = instance
	b.creating, b.phase, b.started = false, audit.SandboxPhaseReady, m.now()
	b.rec.CreatedAt, b.rec.Workdir = instance.CreatedAt, instance.Workdir
	b.rec.HarnessVersion, b.rec.HookContract = spec.HarnessIdentity.Version, spec.HarnessIdentity.HookContract
	m.mu.Unlock()
	// Native sessions are process-owned, not restart-adoptable OpenShell
	// records. No persistence or restart capability is advertised by this slice.
	committed = true
	rb.commit()
	view := m.viewOf(b)
	return &view, nil
}

// Callers hold box.op. Known cleanup success alone permits name release; any
// uncertain process/asset cleanup retains this exact box for explicit retry.
func (m *Manager) cleanupNative(ctx context.Context, b *box) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	session := b.native
	if session == nil {
		return nil
	}
	var err error
	if session.registered != nil && !session.launchAttempted {
		err = session.runtime.gate.Abort(ctx, session.registered)
		session.launchAttempted = true
	} else if session.prepared != nil {
		err = session.prepared.Close(ctx)
	}
	if err == nil && session.preparedComplete {
		if err = ctx.Err(); err == nil {
			err = session.runtime.backend.Delete(ctx, session.identity)
		}
	}
	// Close/Abort and Delete report actual owned cleanup completion. In
	// particular, a successful Delete removed the exact backend record; a
	// deadline observed afterward must not retain an unrecoverable name.
	m.mu.Lock()
	session.cleanupPending = err != nil
	if err == nil {
		session.instance.Phase, b.phase = "closed", audit.SandboxPhaseStopped
		b.rec.PhaseReason = ""
	} else {
		b.phase, b.rec.PhaseReason = audit.SandboxPhaseError, "native cleanup remains owned and pending"
	}
	m.mu.Unlock()
	return err
}

func nativeSessionView(b *box) sandboxapi.Sandbox {
	n := b.native
	phase := "creating"
	switch n.instance.Phase {
	case "started":
		phase = "ready"
	case "closed":
		phase = "stopped"
	case "failed_closed", "cleanup_pending":
		phase = "error"
	}
	if n.cleanupPending {
		phase = "error"
	}
	return sandboxapi.Sandbox{Name: n.identity.Name, ID: n.identity.ID, Runtime: string(n.identity.Runtime.Runtime), Harness: b.rec.Harness,
		HarnessVersion: b.rec.HarnessVersion, HookContract: b.rec.HookContract, Phase: phase,
		PhaseReason: b.rec.PhaseReason, Project: b.rec.Project, Workdir: n.instance.Workdir,
		WorkdirMode: b.rec.WorkdirMode, Driver: n.identity.Runtime.Driver, CreatedAt: n.instance.CreatedAt}
}

func (m *Manager) getNative(ctx context.Context, b *box) (*sandboxapi.Sandbox, error) {
	lifetime := m.running()
	m.mu.Lock()
	n := b.native
	live := n != nil && !m.nativeClosed && n.runtime.owner.Err() == nil && lifetime != nil && lifetime.Err() == nil
	ready := live && n.preparedComplete && !n.cleanupPending && !b.creating && n.instance.Phase == "started"
	m.mu.Unlock()
	if !live {
		return nil, nativeUnavailable()
	}
	if ready {
		// A creation is reported immediately above. Once prepared, serialize
		// Inspect with explicit Stop/Delete without holding Manager.mu over I/O.
		b.op.Lock()
		defer b.op.Unlock()
		m.mu.Lock()
		current := m.boxes[n.identity.Name] == b && !b.deleted
		revision := n.revision
		live = !m.nativeClosed && n.runtime.owner.Err() == nil && lifetime.Err() == nil
		ready = current && live && !n.cleanupPending && n.instance.Phase == "started"
		m.mu.Unlock()
		if !current {
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "native session was deleted")
		}
		if !live {
			return nil, nativeUnavailable()
		}
		if !ready {
			view := m.viewOf(b)
			return &view, nil
		}
		instance, err := n.runtime.backend.Inspect(ctx, n.identity)
		if err != nil {
			return nil, err
		}
		if err := sandboxruntime.ValidateOwnedSession(n.identity, instance.Identity); err != nil {
			return nil, err
		}
		m.mu.Lock()
		live = !m.nativeClosed && n.runtime.owner.Err() == nil && lifetime.Err() == nil
		if m.boxes[n.identity.Name] == b && !b.deleted && !b.creating &&
			n.revision == revision && !n.cleanupPending && n.instance.Phase == "started" && live {
			n.instance = instance
			switch instance.Phase {
			case "closed":
				b.phase = audit.SandboxPhaseStopped
			case "failed_closed", "cleanup_pending":
				b.phase = audit.SandboxPhaseError
			}
		}
		m.mu.Unlock()
		if !live {
			return nil, nativeUnavailable()
		}
	}
	view := m.viewOf(b)
	return &view, nil
}

func (m *Manager) stopNative(ctx context.Context, b *box) (*sandboxapi.Sandbox, error) {
	n := b.native
	if !n.preparedComplete {
		cleanup, cancel := detached(ctx, 10*time.Second)
		defer cancel()
		if err := m.cleanupNative(cleanup, b); err != nil {
			return nil, err
		}
	} else {
		instance, err := n.runtime.backend.Stop(ctx, n.identity)
		if err == nil {
			err = sandboxruntime.ValidateOwnedSession(n.identity, instance.Identity)
		}
		m.mu.Lock()
		n.cleanupPending = err != nil
		if err == nil {
			n.instance, b.phase, b.rec.PhaseReason = instance, audit.SandboxPhaseStopped, ""
		} else {
			b.phase = audit.SandboxPhaseError
			b.rec.PhaseReason = "native cleanup remains owned and pending"
		}
		m.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	view := m.viewOf(b)
	return &view, nil
}

func (m *Manager) deleteNative(ctx context.Context, b *box, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	if req.KeepSnapshot {
		return nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "native snapshot retention is not qualified")
	}
	cleanup, cancel := detached(ctx, 10*time.Second)
	defer cancel()
	return m.deleteNativeOwned(cleanup, b)
}

// The caller holds box.op and supplies its bounded owned cleanup context.
func (m *Manager) deleteNativeOwned(cleanup context.Context, b *box) (*sandboxapi.DeleteResponse, error) {
	if err := m.cleanupNative(cleanup, b); err != nil {
		return nil, err
	}
	name := b.native.identity.Name
	m.mu.Lock()
	b.deleted = true
	m.mu.Unlock()
	m.release(name, b)
	return &sandboxapi.DeleteResponse{Name: name, Deleted: true}, nil
}

// RevokeNative stops exact owned backend records without taking box.op or
// reentering LaunchGate. A publication owner may call it while holding the gate;
// a create can hold box.op while waiting to Launch under that same gate.
// Backend.Stop must cancel pending Prepare and independently wait native custody.
// Unpublished factory resources remain bounded by its admission/owner contexts.
func (m *Manager) RevokeNative(ctx context.Context) error {
	m.mu.Lock()
	var boxes []*box
	for _, b := range m.boxes {
		if b.native != nil && b.native.preparedComplete {
			b.native.revision++
			b.native.cleanupPending = true
			b.rec.PhaseReason = "native cleanup remains owned and pending"
			boxes = append(boxes, b)
		}
	}
	m.mu.Unlock()
	var errs []error
	for _, b := range boxes {
		n := b.native
		instance, err := n.runtime.backend.Stop(ctx, n.identity)
		if err == nil {
			err = sandboxruntime.ValidateOwnedSession(n.identity, instance.Identity)
		}
		m.mu.Lock()
		n.cleanupPending = err != nil
		if err == nil {
			n.instance = instance
			b.phase, b.rec.PhaseReason = audit.SandboxPhaseStopped, ""
		} else {
			b.phase = audit.SandboxPhaseError
		}
		m.mu.Unlock()
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) closeNativeSessions() {
	m.mu.Lock()
	m.nativeClosed = true
	m.mu.Unlock()
	cleanup, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := m.RevokeNative(cleanup); err != nil {
		m.logf("native shutdown: %v", err)
	}
	m.mu.Lock()
	var boxes []*box
	for _, b := range m.boxes {
		if b.native != nil {
			boxes = append(boxes, b)
		}
	}
	m.mu.Unlock()
	for _, b := range boxes {
		if !b.op.TryLock() {
			continue
		}
		if err := m.cleanupNative(cleanup, b); err != nil {
			m.logf("native shutdown cleanup: %v", err)
		}
		b.op.Unlock()
	}
}
