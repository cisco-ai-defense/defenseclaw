//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"sort"
	"testing"
	"time"
)

// GAP-1833: the guardian runs PublishWindowsClaudeVersionFloor on every
// reconcile, and it reads and writes managed-settings.d while it holds the
// Claude Code managed policy lock (the fourth lock user next to the standalone
// ensure, the drift restore and the managed_hooks_only apply). This times the
// body it runs under the lock on an unchanged pass. The lock's own open,
// harden and verify steps are timed against the real lock in
// internal/enterprisehooks (the "version floor lock" row of
// TestGAP1833UnchangedPassesHoldTheClaudePolicyLockUnderTheSmokeBar); a hold is
// that overhead plus this body.
const gap1833FloorSmokeBar = 200 * time.Millisecond

func TestGAP1833UnchangedVersionFloorReconcileHoldsTheLockUnderTheSmokeBar(t *testing.T) {
	opts, locked := windowsFloorOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	stub := windowsClaudeFloorTransaction
	var holds []time.Duration
	windowsClaudeFloorTransaction = func(fn func(string) error) error {
		start := time.Now()
		defer func() { holds = append(holds, time.Since(start)) }()
		return stub(fn)
	}
	t.Cleanup(func() { windowsClaudeFloorTransaction = stub })
	before := *locked
	const passes = 20
	for i := 0; i < passes; i++ {
		state, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"})
		if err != nil {
			t.Fatal(err)
		}
		if state.Changed {
			t.Fatalf("pass %d changed the floor: the passes are not unchanged passes", i)
		}
	}
	// A pass that takes no lock proves nothing: the floor must be written
	// under the lock on every reconcile, so every pass has one hold.
	if got := *locked - before; got != passes || len(holds) != passes {
		t.Fatalf("version floor reconcile took the lock %d times (%d holds) in %d unchanged passes, want one each", got, len(holds), passes)
	}
	sort.Slice(holds, func(i, j int) bool { return holds[i] < holds[j] })
	t.Logf("GAP1833 version floor body (under lock) p50 %8s max %8s (n=%d)", holds[len(holds)/2], holds[len(holds)-1], len(holds))
	if worst := holds[len(holds)-1]; worst >= gap1833FloorSmokeBar {
		t.Errorf("the version floor reconcile held the Claude managed policy lock %s on an unchanged pass, at or above the %s smoke bar", worst, gap1833FloorSmokeBar)
	}
}
