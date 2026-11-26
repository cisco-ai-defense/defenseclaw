//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1833: the guardian runs PublishWindowsClaudeVersionFloor on every
// reconcile, the fourth user of the Claude Code managed policy lock next to
// the standalone ensure, the drift restore and the managed_hooks_only apply.
// Its body under the lock took 243 ms on an unchanged pass: one read of the
// absent managed-settings.json (readPolicyFile's transient-name retries) and
// a record save. The reads now run before the lock and an unchanged pass
// saves nothing, so a hold is the lock's own steps (timed against the real
// lock in internal/enterprisehooks) plus a check that every file the plan was
// made from is unchanged.
const (
	// gap1833FloorHoldBar is the lead bar for one hold on an unchanged pass.
	gap1833FloorHoldBar = 10 * time.Millisecond
	// gap1833FloorSmokeBar is the live smoke bar for one hold of a pass that
	// writes the floor. A pass whose snapshot goes stale falls back to the
	// full read under the lock (about 230 ms of transient-name retries on the
	// absent managed-settings.json), and a scanner holding the just-written
	// file adds a write retry, so one hold of twenty can be slow on a shared
	// box (GAP-2252: 602 ms, p50 19 ms). The bar is judged by
	// testenv.HoldsUnderBar: the median must stay under it, the worst under it
	// stretched by the host slowdown, re-measured up to three times.
	gap1833FloorSmokeBar = 200 * time.Millisecond
)

func requireGAP1833Elevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: the floor tree is owned by Administrators, as under the guardian")
	}
}

// gap1833TimedFloorPasses runs passes floor passes, calling before ahead of
// each (outside the lock), and returns each hold of the lock, sorted, and
// each whole pass.
func gap1833TimedFloorPasses(t *testing.T, opts Options, locked *int, passes int, before func(), wantChanged bool) (holds, whole []time.Duration) {
	t.Helper()
	stub := windowsClaudeFloorTransaction
	windowsClaudeFloorTransaction = func(fn func(string) error) error {
		start := time.Now()
		defer func() { holds = append(holds, time.Since(start)) }()
		return stub(fn)
	}
	defer func() { windowsClaudeFloorTransaction = stub }()
	taken := *locked
	for i := 0; i < passes; i++ {
		if before != nil {
			before()
		}
		start := time.Now()
		state, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"})
		whole = append(whole, time.Since(start))
		if err != nil {
			t.Fatal(err)
		}
		if state.Changed != wantChanged {
			t.Fatalf("pass %d changed=%v, want %v", i, state.Changed, wantChanged)
		}
	}
	// A pass that takes no lock proves nothing: every pass writes or checks
	// the floor under the lock.
	if got := *locked - taken; got != passes || len(holds) != passes {
		t.Fatalf("the version floor reconcile took the lock %d times (%d holds) in %d passes, want one each", got, len(holds), passes)
	}
	sort.Slice(holds, func(i, j int) bool { return holds[i] < holds[j] })
	sort.Slice(whole, func(i, j int) bool { return whole[i] < whole[j] })
	return holds, whole
}

func TestGAP1833UnchangedVersionFloorReconcileHoldsTheLockUnderTheSmokeBar(t *testing.T) {
	requireGAP1833Elevated(t)
	opts, locked := windowsFloorOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	const passes = 20
	holds, whole := gap1833TimedFloorPasses(t, opts, locked, passes, nil, false)
	t.Logf("GAP1833 version floor unchanged: hold (under lock) p50 %8s max %8s | whole pass p50 %8s max %8s (n=%d)",
		holds[len(holds)/2], holds[len(holds)-1], whole[len(whole)/2], whole[len(whole)-1], len(holds))
	if worst := holds[len(holds)-1]; worst >= gap1833FloorHoldBar {
		t.Errorf("the version floor reconcile held the Claude managed policy lock %s on an unchanged pass, at or above the %s bar", worst, gap1833FloorHoldBar)
	}
	// Most of a whole pass is the transient-name retry wait of the absent
	// managed-settings.json read (about 230 ms of timer-rounded sleeps,
	// before or under the lock). The same passes with those sleeps stubbed
	// out compare the rest of the work across builds.
	restoreSleep := safefile.SetTransientRetrySleepForTest(func(time.Duration) {})
	_, whole = gap1833TimedFloorPasses(t, opts, locked, 50, nil, false)
	restoreSleep()
	t.Logf("GAP1833 version floor unchanged, retry sleeps stubbed: whole pass p50 %8s max %8s (n=%d)", whole[len(whole)/2], whole[len(whole)-1], len(whole))

	// The changed-floor path: the drop-in is gone before each pass (drift),
	// so every pass writes the floor and saves its record under the lock.
	path := claudeFloorFile(t, opts)
	holds, ok, report := testenv.HoldsUnderBar(gap1833FloorSmokeBar, func() []time.Duration {
		holds, whole = gap1833TimedFloorPasses(t, opts, locked, passes, func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, true)
		t.Logf("GAP1833 version floor written: hold (under lock) p50 %8s max %8s | whole pass p50 %8s max %8s (n=%d)",
			holds[len(holds)/2], holds[len(holds)-1], whole[len(whole)/2], whole[len(whole)-1], len(holds))
		return holds
	})
	t.Logf("GAP1833 version floor written, against the %s smoke bar:\n%s", gap1833FloorSmokeBar, report)
	if got := readFile(t, path); got != wantClaudeFloorBytes {
		t.Fatalf("floor = %q", got)
	}
	if !ok {
		t.Errorf("the version floor reconcile held the Claude managed policy lock %s at worst writing the floor, over the %s smoke bar:\n%s", holds[len(holds)-1], gap1833FloorSmokeBar, report)
	}
}

// The race rows of TestGAP1833FloorChangedBetweenTheReadAndTheLockIsReadAgain
// on the Windows tree, with the Windows reads (identity-pinned stats,
// transient-name retries) and administrator-owned files.
func TestGAP1833WindowsFloorChangedBetweenTheReadAndTheLockIsReadAgain(t *testing.T) {
	requireGAP1833Elevated(t)
	runGAP1833FloorRaces(t, func(t *testing.T) gap1833FloorEnv {
		opts, _ := windowsFloorOptions(t)
		return gap1833FloorEnv{opts: opts, write: func(t *testing.T, path, content string) {
			writeFile(t, path, content)
			ownAs(t, path, wellKnownSID(t, windows.WinBuiltinAdministratorsSid))
		}}
	})
}
