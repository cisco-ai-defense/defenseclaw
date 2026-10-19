// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// These tests exercise only the existing synthetic gate and process handles.
// No gateway generation, native process or provider is created.
func TestRotatePublishedUsesActualPublisherGenerationAndRetiresOldPolicy(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	process := &syntheticPreparedProcess{}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	next := *source.Load()
	// Other host publications can advance a shared sequence. The gate must
	// accept the actual assigned generation rather than guessing current+1.
	next.Generation += 73
	calls := 0
	if err := gate.RotatePublished(context.Background(), func(context.Context) (PolicyAuthorityBinding, error) {
		calls++
		source.Store(&next)
		return next, nil
	}); err != nil || calls != 1 {
		t.Fatalf("actual publication was not adopted exactly once: %v", err)
	}
	if _, err := gate.Launch(context.Background(), prepared); err == nil || process.launches != 0 || process.closes != 1 {
		t.Fatal("old policy launched after actual publication or lost cleanup")
	}
	cfg, flags, options := policyTestInput()
	options.Authority = next
	currentPolicy := mustPolicy(t, cfg, flags, options)
	currentInfo, currentReceipt := policyEvidence(currentPolicy)
	current := registerLaunch(t, gate, currentPolicy, currentInfo, currentReceipt, spec, &syntheticPreparedProcess{})
	if _, err := gate.Launch(context.Background(), current); err != nil {
		t.Fatalf("valid new publication left the gate closed: %v", err)
	}
}

func TestRotatePublishedIncompleteTransitionClosesAdmission(t *testing.T) {
	for _, mode := range []string{"error-before", "error-after", "invalid", "same", "backward", "mismatch", "cancel-after"} {
		t.Run(mode, func(t *testing.T) {
			gate, source, policy, info, receipt, spec := launchTestInput(t)
			previous := *source.Load()
			next := previous
			next.Generation += 73
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("fixed incomplete publication")
			calls := 0
			err := gate.RotatePublished(ctx, func(context.Context) (PolicyAuthorityBinding, error) {
				calls++
				if mode == "error-before" {
					return PolicyAuthorityBinding{}, failure
				}
				switch mode {
				case "invalid":
					next.SnapshotID = ""
				case "same":
					next.Generation = previous.Generation
				case "backward":
					next.Generation = previous.Generation - 1
				}
				source.Store(&next)
				if mode == "error-after" {
					return next, failure
				}
				if mode == "cancel-after" {
					cancel()
				}
				returned := next
				if mode == "mismatch" {
					returned.Generation++
				}
				return returned, nil
			})
			if err == nil || calls != 1 {
				t.Fatal("incomplete transition succeeded or repeated its callback")
			}
			if mode == "cancel-after" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation after publication was lost")
			}
			// Even restoring the old source cannot resurrect admission after a
			// callback that may have partially revoked or published host state.
			source.Store(&previous)
			if _, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{}); err == nil {
				t.Fatal("failed publication reopened old authority")
			}
			if err := gate.RotatePublished(context.Background(), func(context.Context) (PolicyAuthorityBinding, error) {
				calls++
				return next, nil
			}); err == nil || calls != 1 {
				t.Fatal("closed gate ran another publication callback")
			}
		})
	}
}

func TestRotatePublishedSerializesPublicationBeforeWaitingLaunch(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	process := &syntheticPreparedProcess{}
	prepared := registerLaunch(t, gate, policy, info, receipt, spec, process)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	rotated, launched := make(chan error, 1), make(chan error, 1)
	next := *source.Load()
	next.Generation += 73
	go func() {
		rotated <- gate.RotatePublished(context.Background(), func(context.Context) (PolicyAuthorityBinding, error) {
			close(entered)
			<-release
			source.Store(&next)
			return next, nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not enter the synthetic barrier")
	}
	if gate.mu.TryLock() {
		gate.mu.Unlock()
		t.Fatal("publication callback ran outside the launch mutex")
	}
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := gate.Launch(context.Background(), prepared)
		launched <- err
	}()
	<-started
	releaseOnce()
	select {
	case err := <-rotated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not finish")
	}
	select {
	case err := <-launched:
		if err == nil || process.launches != 0 || process.closes != 1 {
			t.Fatal("waiting launch bypassed publication or lost exact cleanup")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting launch did not finish")
	}
}

func TestPlannedRotationCancellationAfterPublicationClosesAdmission(t *testing.T) {
	gate, source, policy, info, receipt, spec := launchTestInput(t)
	previous := *source.Load()
	next := previous
	next.Generation++
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := gate.Rotate(ctx, next, func(context.Context) error {
		source.Store(&next)
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("planned rotation erased cancellation during publication")
	}
	source.Store(&previous)
	if _, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{}); err == nil {
		t.Fatal("canceled planned rotation resurrected old admission")
	}
}

func TestRotationCancellationDuringPublishedSourceReadClosesAdmission(t *testing.T) {
	for _, publishedAPI := range []bool{false, true} {
		t.Run(map[bool]string{false: "planned", true: "published"}[publishedAPI], func(t *testing.T) {
			gate, source, policy, info, receipt, spec := launchTestInput(t)
			previous := *source.Load()
			next := previous
			next.Generation++
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			published := false
			gate.current = func() PolicyAuthorityBinding {
				if published {
					cancel()
				}
				return *source.Load()
			}
			transition := func(context.Context) (PolicyAuthorityBinding, error) {
				source.Store(&next)
				published = true
				return next, nil
			}
			var err error
			if publishedAPI {
				err = gate.RotatePublished(ctx, transition)
			} else {
				err = gate.Rotate(ctx, next, func(ctx context.Context) error { _, err := transition(ctx); return err })
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("source-read cancellation became a successful rotation")
			}
			published = false
			source.Store(&previous)
			if _, err := gate.RegisterPrepared(policy, info, receipt, spec, &syntheticPreparedProcess{}); err == nil {
				t.Fatal("source-read cancellation left admission open")
			}
		})
	}
}

func TestRotationPreflightRefusalDoesNotRunTransitionOrCloseGate(t *testing.T) {
	for _, mode := range []string{"cancel-published", "cancel-planned", "invalid-planned"} {
		t.Run(mode, func(t *testing.T) {
			gate, source, policy, info, receipt, spec := launchTestInput(t)
			prepared := registerLaunch(t, gate, policy, info, receipt, spec, &syntheticPreparedProcess{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			next := *source.Load()
			if mode != "invalid-planned" {
				next.Generation++
				cancel()
			}
			called := false
			var err error
			if mode == "cancel-published" {
				err = gate.RotatePublished(ctx, func(context.Context) (PolicyAuthorityBinding, error) {
					called = true
					return next, nil
				})
			} else {
				err = gate.Rotate(ctx, next, func(context.Context) error { called = true; return nil })
			}
			if err == nil || called {
				t.Fatal("preflight refusal invoked its transition")
			}
			if _, err := gate.Launch(context.Background(), prepared); err != nil {
				t.Fatalf("preflight refusal unnecessarily closed the unchanged gate: %v", err)
			}
		})
	}
	gate, _, _, _, _, _ := launchTestInput(t)
	if err := gate.RotatePublished(context.Background(), nil); err == nil {
		t.Fatal("nil publication callback was admitted")
	}
	if err := (*LaunchGate)(nil).RotatePublished(context.Background(), func(context.Context) (PolicyAuthorityBinding, error) {
		t.Fatal("absent gate invoked its callback")
		return PolicyAuthorityBinding{}, nil
	}); err == nil {
		t.Fatal("nil gate was admitted")
	}
}
