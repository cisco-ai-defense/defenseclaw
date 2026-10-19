// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// These are synthetic custody/admission tests. No provider or workload runs.
type syntheticPreparedProcess struct {
	launches int
	closes   int
	launch   func(context.Context, Spec) (Instance, error)
	close    func(context.Context) error
}

func (p *syntheticPreparedProcess) Launch(ctx context.Context, spec Spec) (Instance, error) {
	p.launches++
	if p.launch != nil {
		return p.launch(ctx, spec)
	}
	return Instance{Identity: spec.Identity}, nil
}

func (p *syntheticPreparedProcess) Close(ctx context.Context) error {
	p.closes++
	if p.close != nil {
		return p.close(ctx)
	}
	return nil
}

func launchTestInput(t *testing.T) (*LaunchGate, *atomic.Pointer[PolicyAuthorityBinding], *ExecutionPolicy, RuntimeInfo, PolicyReceipt, Spec) {
	t.Helper()
	cfg, flags, options := policyTestInput()
	policy := mustPolicy(t, cfg, flags, options)
	info, receipt := policyEvidence(policy)
	var source atomic.Pointer[PolicyAuthorityBinding]
	source.Store(&options.Authority)
	gate, err := NewLaunchGate(func() PolicyAuthorityBinding { return *source.Load() })
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{
		Identity: SessionIdentity{Owner: "synthetic-owner", ID: "synthetic-session", Name: "synthetic-session", Runtime: info.Identity},
		Harness:  "claudecode", HarnessIdentity: options.Harness,
		HostWorkspace: "/synthetic/private-stage", GuestWorkspace: "/synthetic/workspace",
		Command: []string{"/synthetic/agent", "", "literal;data"}, Env: map[string]string{"PUBLIC": "synthetic"},
		BindingID: "synthetic-host-broker-binding",
		CPU:       policy.effective.Resources.CPU, Memory: policy.effective.Resources.Memory,
	}
	return gate, &source, policy, info, receipt, spec
}

func registerLaunch(t *testing.T, gate *LaunchGate, policy *ExecutionPolicy, info RuntimeInfo, receipt PolicyReceipt, spec Spec, process PreparedProcess) *PreparedLaunch {
	t.Helper()
	prepared, err := gate.RegisterPrepared(policy, info, receipt, spec, process)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestLaunchGateBindsPrivateSpecAndCopiesEvidence(t *testing.T) {
	gate, _, policy, info, receipt, spec := launchTestInput(t)
	want := cloneLaunchSpec(spec)
	process := &syntheticPreparedProcess{launch: func(_ context.Context, got Spec) (Instance, error) {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("launch input changed: %+v", got)
		}
		return Instance{Identity: got.Identity}, nil
	}}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	spec.Command[0], spec.Env["PUBLIC"] = "/synthetic/replacement", "changed"
	info.Supported[0] = "unknown"
	for name := range info.Harnesses {
		info.Harnesses[name].Supported[0] = "unknown"
		delete(info.Harnesses, name)
	}
	receipt.Components[0].Digest = "changed"
	if _, err := json.Marshal(prepared); err == nil {
		t.Fatal("prepared authority was serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), prepared); err == nil {
		t.Fatal("prepared authority was deserialized")
	}
	if _, err := gate.Launch(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	copyHandle := *prepared
	if _, err := gate.Launch(context.Background(), &copyHandle); err == nil || process.launches != 1 || process.closes != 0 {
		t.Fatal("copied handle replayed or stopped an already transferred instance")
	}
}

func TestLaunchGateRefusesStaleCurrentSourceAndForeignGate(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	process := &syntheticPreparedProcess{}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	foreign, err := NewLaunchGate(func() PolicyAuthorityBinding { return *source.Load() })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Launch(context.Background(), prepared); err == nil || process.closes != 0 {
		t.Fatal("foreign gate used or closed another owner's handle")
	}
	// Reading the real host source at dispatch also detects an already published
	// external change. Production writers must still use Rotate to close the
	// interval between this check and actual launch.
	next := *source.Load()
	next.Generation++
	source.Store(&next)
	if _, err := gate.Launch(context.Background(), prepared); err == nil || process.launches != 0 || process.closes != 1 {
		t.Fatal("stale policy launched or its preparation was not released")
	}
	if err := gate.Abort(context.Background(), prepared); err == nil || process.closes != 1 {
		t.Fatal("consumed stale preparation was closed twice")
	}
}

func TestLaunchGateSerializesRotationWithProcessCreation(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	entered, release := make(chan struct{}), make(chan struct{})
	process := &syntheticPreparedProcess{launch: func(_ context.Context, frozen Spec) (Instance, error) {
		close(entered)
		<-release
		return Instance{Identity: frozen.Identity}, nil
	}}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	launchDone, rotateDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := gate.Launch(context.Background(), prepared); launchDone <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("synthetic launch did not enter")
	}
	rotationStarted := make(chan struct{})
	next := *source.Load()
	next.Generation++
	go func() {
		close(rotationStarted)
		rotateDone <- gate.Rotate(context.Background(), next, func(context.Context) error {
			source.Store(&next)
			return nil
		})
	}()
	<-rotationStarted
	if *source.Load() == next {
		t.Fatal("authority changed during the owned launch")
	}
	close(release)
	if err := <-launchDone; err != nil {
		t.Fatal(err)
	}
	if err := <-rotateDone; err != nil || *source.Load() != next {
		t.Fatalf("rotation did not publish: %v", err)
	}
	if _, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{}); err == nil {
		t.Fatal("old policy prepared after rotation")
	}
}

func TestLaunchGateCleansPartialFailureAndLatchesCleanupFailure(t *testing.T) {
	for _, failure := range []string{"cancelled-before", "cancelled-after", "wrong-identity", "adapter-error", "cleanup-error"} {
		t.Run(failure, func(t *testing.T) {
			gate, _, policy, info, receipt, spec := launchTestInput(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			process := &syntheticPreparedProcess{}
			process.launch = func(_ context.Context, frozen Spec) (Instance, error) {
				if failure == "cancelled-after" {
					cancel()
				}
				if failure == "wrong-identity" {
					frozen.Identity.Owner = "another-owner"
				}
				if failure == "adapter-error" || failure == "cleanup-error" {
					return Instance{}, errors.New("synthetic partial launch failure")
				}
				return Instance{Identity: frozen.Identity}, nil
			}
			process.close = func(cleanupCtx context.Context) error {
				if cleanupCtx.Err() != nil {
					t.Fatal("cancelled request prevented cleanup")
				}
				if _, bounded := cleanupCtx.Deadline(); !bounded {
					t.Fatal("cleanup has no deadline")
				}
				if failure == "cleanup-error" {
					return errors.New("synthetic custody not established")
				}
				return nil
			}
			prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
			if failure == "cancelled-before" {
				cancel()
			}
			if _, err := gate.Launch(ctx, prepared); err == nil || process.closes != 1 {
				t.Fatal("failed launch escaped owned cleanup")
			}
			_, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{})
			if (err != nil) != (failure == "cleanup-error") {
				t.Fatalf("unexpected gate state after %s: %v", failure, err)
			}
		})
	}
}

func TestLaunchGateRotationFailureClosesAdmission(t *testing.T) {
	for _, failure := range []string{"transaction-error", "not-published"} {
		t.Run(failure, func(t *testing.T) {
			gate, source, policy, info, receipt, spec := launchTestInput(t)
			process := &syntheticPreparedProcess{}
			prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
			next := *source.Load()
			next.Generation++
			err := gate.Rotate(context.Background(), next, func(context.Context) error {
				if failure == "transaction-error" {
					return errors.New("synthetic incomplete revocation")
				}
				return nil
			})
			if err == nil {
				t.Fatal("incomplete rotation accepted")
			}
			if _, err := gate.Launch(context.Background(), prepared); err == nil || process.launches != 0 || process.closes != 1 {
				t.Fatal("closed gate launched a pending preparation")
			}
		})
	}
}

func TestLaunchGateCannotResurrectPreparationAfterAuthorityRollback(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	process := &syntheticPreparedProcess{}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	old := *source.Load()
	next := old
	next.Generation++
	if err := gate.Rotate(context.Background(), next, func(context.Context) error {
		source.Store(&next)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Rolling back external configuration cannot roll back the gate's history
	// and resurrect a handle issued before a successful policy transition.
	source.Store(&old)
	if _, err := gate.Launch(context.Background(), prepared); err == nil || process.launches != 0 || process.closes != 1 {
		t.Fatal("authority rollback resurrected stale preparation")
	}
	source.Store(&next)
	if _, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{}); err == nil || !gate.closed {
		t.Fatal("authority divergence did not latch the gate closed")
	}
}

func TestLaunchGatePreparationCannotOverrideResourcePolicy(t *testing.T) {
	for _, field := range []string{"cpu", "memory"} {
		t.Run(field, func(t *testing.T) {
			gate, _, policy, info, receipt, spec := launchTestInput(t)
			if field == "cpu" {
				spec.CPU = "999999"
			} else {
				spec.Memory = "999999Gi"
			}
			process := &syntheticPreparedProcess{}
			if _, err := gate.RegisterPrepared(policy, info, receipt, spec, process); err == nil || process.launches != 0 || process.closes != 0 {
				t.Fatal("resource override accepted, or caller's refused resource ownership was changed")
			}
		})
	}
}

func TestLaunchGateInvalidInputsAndAbortDoNotLaunch(t *testing.T) {
	gate, _, policy, info, receipt, spec := launchTestInput(t)
	var typedNil *syntheticPreparedProcess
	for _, process := range []PreparedProcess{nil, typedNil} {
		if _, err := gate.RegisterPrepared(policy, info, receipt, spec, process); err == nil {
			t.Fatal("missing preparation resource accepted")
		}
	}
	process := &syntheticPreparedProcess{}
	for _, invalid := range []*ExecutionPolicy{nil, {}} {
		if _, err := gate.RegisterPrepared(invalid, info, receipt, spec, process); err == nil {
			t.Fatal("unresolved policy accepted")
		}
	}
	var zero LaunchGate
	if _, err := zero.RegisterPrepared(policy, info, receipt, spec, process); err == nil {
		t.Fatal("zero launch gate accepted resources")
	}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	if err := gate.Abort(context.Background(), prepared); err != nil || process.closes != 1 || process.launches != 0 {
		t.Fatal("abort did not release unused preparation")
	}
	if _, err := gate.Launch(context.Background(), prepared); err == nil || process.closes != 1 || process.launches != 0 {
		t.Fatal("aborted handle launched or was closed twice")
	}
}
