// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
)

// cappedFakeRetentionReaper is a fake reaper with the opt-in size cap.
type cappedFakeRetentionReaper struct {
	*fakeRetentionReaper
	maxStoreMB atomic.Int64
}

func (reaper *cappedFakeRetentionReaper) MaxStoreMB() int64 { return reaper.maxStoreMB.Load() }

func (reaper *cappedFakeRetentionReaper) UpdateMaxStoreMB(mb int64) error {
	if mb < 0 {
		return errors.New("invalid fake size cap")
	}
	reaper.maxStoreMB.Store(mb)
	return nil
}

// #1384: a size cap alone (retention_days 0) keeps the reaper running; with
// neither the controller reports retention disabled, as before.
func TestRetentionControllerRunsForASizeCapAlone(t *testing.T) {
	reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(0)}
	scheduler := newScriptedRetentionScheduler()
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler})
	if err != nil {
		t.Fatal(err)
	}
	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(0, 2048)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !controller.enabled() || reaper.MaxStoreMB() != 2048 {
		t.Fatalf("enabled %t, cap %d; want a run for the size cap", controller.enabled(), reaper.MaxStoreMB())
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if interval := receiveRetentionTest(t, scheduler.waits); interval == 0 {
		t.Fatal("no cadence for a size cap alone")
	}
	stopRetentionControllerTest(t, controller)

	off := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(0)}
	controller, err = newRetentionController(off, RetentionControllerOptions{Scheduler: newScriptedRetentionScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	if controller.enabled() {
		t.Fatal("retention enabled with no age and no size cap")
	}
	// A reaper without the size cap refuses one.
	plain, err := newRetentionController(newFakeRetentionReaper(7), RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plain.lifecycleMu.Lock()
	err = plain.applyPolicyLocked(7, 2048)
	plain.lifecycleMu.Unlock()
	if err == nil {
		t.Fatal("a reaper without a size cap accepted one")
	}
}
