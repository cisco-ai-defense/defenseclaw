// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0402: retention ran every six hours, and a size cap was only checked
// then; under about 15 actors audit.db and its WAL filled the gateway's
// volume well before that, and every hook failed closed. With a cap the
// controller checks the store every ten minutes; without one it keeps the
// six-hour cadence.
func TestRetentionControllerChecksASizeCapEveryTenMinutes(t *testing.T) {
	for _, c := range []struct {
		capMB int64
		want  time.Duration
	}{
		{capMB: 1024, want: 10 * time.Minute},
		{capMB: 0, want: audit.RetentionScheduleInterval},
	} {
		reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(7)}
		scheduler := newScriptedRetentionScheduler()
		controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler})
		if err != nil {
			t.Fatal(err)
		}
		controller.lifecycleMu.Lock()
		err = controller.applyPolicyLocked(7, c.capMB)
		controller.lifecycleMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := controller.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		receiveRetentionTest(t, reaper.started)
		reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
		if wait := receiveRetentionTest(t, scheduler.waits); wait != c.want {
			t.Fatalf("cap %d MiB: wait after a run = %s, want %s", c.capMB, wait, c.want)
		}
		stopRetentionControllerTest(t, controller)
	}
}
