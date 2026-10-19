// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// PreparedProcess is a trusted adapter's already prepared resource handle.
// Preparation must not start untrusted code or grant credentials. Launch starts
// only that prepared execution; Close revokes its grants, kills and waits its
// owned workload, and releases preparation resources. Both must honor ctx.
// Implementations must not call back into their LaunchGate.
type PreparedProcess interface {
	Launch(context.Context, Spec) (Instance, error)
	Close(context.Context) error
}

// LaunchGate serializes admission and process creation with the host owner's
// policy changes. Its binding comes from the existing trusted authority; this
// gate does not resolve policy, mint generations or qualify an adapter. Create
// one per execution owner, then use Rotate for every relevant authority change.
// current must read that owner's actual synchronized authority source, remain
// bounded and never reenter the gate. It is read again at dispatch; a cached
// constructor binding would not detect a previously changed authority source.
// A zero gate refuses execution. No goroutine or listener is started.
type LaunchGate struct {
	mu      sync.Mutex
	current func() PolicyAuthorityBinding
	last    PolicyAuthorityBinding
	closed  bool
}

type preparedLaunchState struct {
	gate     *LaunchGate
	policy   *ExecutionPolicy
	info     RuntimeInfo
	receipt  PolicyReceipt
	spec     Spec
	process  PreparedProcess
	consumed bool
}

// PreparedLaunch is a one-use, host-private handle, not wire authorization.
// Copying the value shares its consumption state. Its owner must Launch or
// Abort it; retaining it does not survive an authority change.
type PreparedLaunch struct{ state *preparedLaunchState }

func (PreparedLaunch) MarshalJSON() ([]byte, error) {
	return nil, errors.New("prepared sandbox launch authority cannot be serialized")
}

func (*PreparedLaunch) UnmarshalJSON([]byte) error {
	return errors.New("prepared sandbox launch authority cannot be deserialized")
}

func validAuthority(binding PolicyAuthorityBinding) bool {
	return sessionID.MatchString(binding.SnapshotID) && binding.Generation > 0
}

func NewLaunchGate(current func() PolicyAuthorityBinding) (*LaunchGate, error) {
	if current == nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox launch gate requires a trusted host authority binding")
	}
	initial := current()
	if !validAuthority(initial) {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox launch gate requires a trusted host authority binding")
	}
	return &LaunchGate{current: current, last: initial}, nil
}

func (g *LaunchGate) ready() (PolicyAuthorityBinding, error) {
	if g.closed || g.current == nil {
		return PolicyAuthorityBinding{}, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox launch authority is closed")
	}
	current := g.current()
	if !validAuthority(current) || current != g.last {
		g.closed = true
		return PolicyAuthorityBinding{}, sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox host authority changed outside its launch transaction; launch gate closed")
	}
	return current, nil
}

// RegisterPrepared accepts only stable host-owned evidence and resources. The
// caller retains cleanup responsibility on refusal; ownership transfers to the
// returned handle on success. Registration starts no agent. Each launch checks
// the frozen evidence again under the authority lock immediately before calling
// the adapter. Client/workload supplied receipts must never reach this method.
// The host controller/adapter registry must first reserve the complete session
// identity uniquely and retain that reservation until its workload is stopped.
// This gate's replay protection applies to handles; it is not a session store.
func (g *LaunchGate) RegisterPrepared(policy *ExecutionPolicy, info RuntimeInfo, receipt PolicyReceipt, spec Spec, process PreparedProcess) (*PreparedLaunch, error) {
	if g == nil || absentPreparedProcess(process) {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox preparation requires an owned gate and resource handle")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current, err := g.ready()
	if err != nil {
		return nil, err
	}
	if spec.Identity.Validate() != nil || spec.Identity.Runtime != info.Identity || policy == nil || policy.effective == nil || spec.Harness != policy.effective.Harness || spec.HarnessIdentity != policy.options.Harness || spec.Offline != policy.options.Offline {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox preparation identity differs from its admitted runtime")
	}
	if err := policy.AdmitPolicy(info, receipt, current); err != nil {
		return nil, err
	}
	if (spec.CPU != "" && spec.CPU != policy.effective.Resources.CPU) || (spec.Memory != "" && spec.Memory != policy.effective.Resources.Memory) {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox preparation resources differ from the resolved policy")
	}
	spec.CPU, spec.Memory = policy.effective.Resources.CPU, policy.effective.Resources.Memory
	info.Supported = slices.Clone(info.Supported)
	unsupported := make(map[Capability]string, len(info.Unavailable))
	for capability, reason := range info.Unavailable {
		unsupported[capability] = reason
	}
	info.Unavailable = unsupported
	harnesses := make(map[string]HarnessVerification, len(info.Harnesses))
	for name, verification := range info.Harnesses {
		verification.Supported = slices.Clone(verification.Supported)
		harnesses[name] = verification
	}
	info.Harnesses = harnesses
	receipt.Components = slices.Clone(receipt.Components)
	return &PreparedLaunch{state: &preparedLaunchState{
		gate: g, policy: policy, info: info, receipt: receipt,
		spec: cloneLaunchSpec(spec), process: process,
	}}, nil
}

func absentPreparedProcess(process PreparedProcess) bool {
	if process == nil {
		return true
	}
	switch value := reflect.ValueOf(process); value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

func (g *LaunchGate) claim(prepared *PreparedLaunch) (*preparedLaunchState, error) {
	if prepared == nil || prepared.state == nil || prepared.state.gate != g || prepared.state.consumed {
		return nil, sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox preparation is absent, foreign or already consumed")
	}
	prepared.state.consumed = true
	return prepared.state, nil
}

// cleanup uses a fresh bounded context even after request cancellation. Failure
// closes the gate: the host owner must repair resource custody before it creates
// a new gate. Adapter Close must contain and wait its exact owned resources.
func (g *LaunchGate) cleanup(ctx context.Context, process PreparedProcess) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := process.Close(cleanupCtx); err != nil {
		g.closed = true
		return fmt.Errorf("sandbox preparation cleanup failed: %w", err)
	}
	return nil
}

// Launch consumes the handle even when admission or process creation fails. It
// holds the same lock as Rotate through the adapter's bounded process creation.
// After success the host controller owns the returned workload and must enforce
// revocation/lifecycle policy; this gate alone is not that lifecycle owner.
func (g *LaunchGate) Launch(ctx context.Context, prepared *PreparedLaunch) (Instance, error) {
	if g == nil {
		return Instance{}, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox launch authority is absent")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.claim(prepared)
	if err != nil {
		return Instance{}, err
	}
	refuse := func(err error) (Instance, error) {
		return Instance{}, errors.Join(err, g.cleanup(ctx, state.process))
	}
	current, err := g.ready()
	if err != nil {
		return refuse(err)
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if err := state.policy.AdmitPolicy(state.info, state.receipt, current); err != nil {
		return refuse(err)
	}
	instance, err := state.process.Launch(ctx, cloneLaunchSpec(state.spec))
	if err != nil {
		return refuse(err)
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if err := ValidateOwnedSession(state.spec.Identity, instance.Identity); err != nil {
		return refuse(err)
	}
	return instance, nil
}

// Abort releases one owned, unused preparation, including one made stale by a
// rotation or closed gate. It cannot stop a successfully launched instance;
// that resource belongs to the host controller's recorded lifecycle owner.
func (g *LaunchGate) Abort(ctx context.Context, prepared *PreparedLaunch) error {
	if g == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox launch authority is absent")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.claim(prepared)
	if err != nil {
		return err
	}
	return g.cleanup(ctx, state.process)
}

// Rotate runs the host owner's revocation/configuration transaction under the
// launch lock, then publishes its new trusted binding. The transaction must
// revoke old live grants/workloads as required before returning success, and
// must not reenter this gate. Failure closes the gate even if the transaction
// partially changed host state; continuing under the old binding is unsafe.
// The owner supplies the new generation, strictly greater than the previous one.
// A successful transaction must actually publish next in current's source.
func (g *LaunchGate) Rotate(ctx context.Context, next PolicyAuthorityBinding, transition func(context.Context) error) error {
	if g == nil || transition == nil {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox authority rotation requires an owned transition")
	}
	return g.rotate(ctx, &next, func(ctx context.Context) (PolicyAuthorityBinding, error) {
		return next, transition(ctx)
	})
}

// RotatePublished serializes revocation and publication when the existing host
// publisher assigns its generation during the transaction. transition must
// revoke affected old grants/workloads before publishing, then return the exact
// binding actually published in current's source. Never predict a host counter.
// Every relevant writer must use this same gate, and must not reenter it.
// Decide no-op updates before calling: once transition begins, a non-advancing
// generation, cancellation or any incomplete publication closes the gate.
func (g *LaunchGate) RotatePublished(ctx context.Context, transition func(context.Context) (PolicyAuthorityBinding, error)) error {
	if g == nil || transition == nil {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "sandbox authority rotation requires an owned transition")
	}
	return g.rotate(ctx, nil, transition)
}

func (g *LaunchGate) rotate(ctx context.Context, planned *PolicyAuthorityBinding, transition func(context.Context) (PolicyAuthorityBinding, error)) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	current, err := g.ready()
	if err != nil {
		return err
	}
	if planned != nil && (!validAuthority(*planned) || planned.Generation <= current.Generation) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox authority generation must advance")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := transition(ctx)
	if err = errors.Join(err, ctx.Err()); err != nil {
		g.closed = true
		return fmt.Errorf("sandbox authority transition failed; launch gate closed: %w", err)
	}
	observed := g.current()
	if err := ctx.Err(); err != nil {
		g.closed = true
		return fmt.Errorf("sandbox authority transition failed; launch gate closed: %w", err)
	}
	if !validAuthority(next) || next.Generation <= current.Generation || observed != next || (planned != nil && *planned != next) {
		g.closed = true
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox authority transition did not publish its expected binding; launch gate closed")
	}
	g.last = next
	return nil
}

// cloneLaunchSpec binds every launch field, including argv, environment,
// workspace and broker binding. The adapter receives a fresh copy at dispatch.
func cloneLaunchSpec(spec Spec) Spec {
	spec.Command = slices.Clone(spec.Command)
	environment := make(map[string]string, len(spec.Env))
	for key, value := range spec.Env {
		environment[key] = value
	}
	spec.Env = environment
	return spec
}
