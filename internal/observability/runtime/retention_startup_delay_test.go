// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"
)

// #1384, GAP-1790: the first run after readiness waits the startup delay,
// so it does not read old pages under the first hook calls of a start.
func TestRetentionControllerFirstRunWaitsTheStartupDelay(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	finished := make(chan struct{})
	close(finished)
	reaper.stop = finished
	scheduler := newScriptedRetentionScheduler()
	const delay = 300 * time.Millisecond
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, StartupDelay: delay,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(delay / 3)
	if runs, _, _, _ := reaper.snapshot(); runs != 0 {
		t.Fatalf("reaper ran %d times inside the startup delay", runs)
	}
	receiveRetentionTest(t, reaper.started)
	if waited := time.Since(started); waited < delay {
		t.Fatalf("first run after %s, want at least %s", waited, delay)
	}
	if interval := receiveRetentionTest(t, scheduler.waits); interval == 0 {
		t.Fatal("no cadence after the first run")
	}
	stopRetentionControllerTest(t, controller)
}

// A stop during the startup delay returns at once, with no run.
func TestRetentionControllerStopDuringStartupDelay(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: newScriptedRetentionScheduler(), StartupDelay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopped := time.Now()
	stopRetentionControllerTest(t, controller)
	if took := time.Since(stopped); took > 5*time.Second {
		t.Fatalf("stop took %s inside the startup delay", took)
	}
	if runs, _, _, _ := reaper.snapshot(); runs != 0 {
		t.Fatalf("reaper ran %d times, want none", runs)
	}
}

// Without a delay (Secure Client, tests) the first run starts at once.
func TestRetentionControllerNoStartupDelayRunsAtOnce(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: newScriptedRetentionScheduler(), SecureClient: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	stopRetentionControllerTest(t, controller)
}

func stopRetentionControllerTest(t *testing.T, controller *RetentionController) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := controller.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
