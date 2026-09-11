// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package agentchain

import (
	"testing"
	"time"
)

// TestExitedCounterTracksTheTable pins the invariant the eviction shortcut
// rests on.
//
// evictOldestExitedLocked returns immediately when the counter says there is
// nothing to reclaim. If the counter ever drifts above the truth the scan is
// merely wasted; if it drifts below, a full table stops accepting new pids
// and the tracker silently stops learning ancestry -- which attributes new
// work to stale lineage, the failure this table exists to prevent.
func TestExitedCounterTracksTheTable(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	tracker := newTracker(time.Minute, clock)

	countExited := func() int {
		exited := 0
		for _, record := range tracker.records {
			if !record.exitedAt.IsZero() {
				exited++
			}
		}
		return exited
	}
	check := func(step string) {
		t.Helper()
		if got, want := tracker.exited, countExited(); got != want {
			t.Fatalf("after %s: counter = %d, table holds %d exited", step, got, want)
		}
	}

	tracker.ObserveExec(10, 1, 0, "claude", "claude")
	tracker.ObserveExec(11, 10, 0, "bash", "bash -c id")
	check("two execs")

	tracker.ObserveExit(11)
	check("one exit")
	if tracker.exited != 1 {
		t.Fatalf("exited = %d, want 1", tracker.exited)
	}

	// Exiting the same pid twice must not double-count.
	tracker.ObserveExit(11)
	check("repeated exit")
	if tracker.exited != 1 {
		t.Fatalf("exited = %d after a repeated exit, want 1", tracker.exited)
	}

	// The kernel recycles the number: the record comes back to life.
	tracker.ObserveExec(11, 10, 0, "curl", "curl https://example.invalid")
	check("recycled pid")
	if tracker.exited != 0 {
		t.Fatalf("exited = %d after the pid was reused, want 0", tracker.exited)
	}

	tracker.ObserveExit(11)
	now = now.Add(2 * time.Minute)
	if removed := tracker.Reap(); removed != 1 {
		t.Fatalf("Reap removed %d, want 1", removed)
	}
	check("reap")
	if tracker.exited != 0 {
		t.Fatalf("exited = %d after reaping the only dead record, want 0", tracker.exited)
	}
}
