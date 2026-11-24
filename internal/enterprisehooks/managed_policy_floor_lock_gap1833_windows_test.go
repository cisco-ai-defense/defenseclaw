//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// GAP-1833: the fourth guardian-pass user of the Claude Code managed policy
// lock, the version floor reconcile (enterprisepolicy
// PublishWindowsClaudeVersionFloor), timed through the real lock: the hold
// from the acquire through the floor body. The other three users are timed in
// TestGAP1833UnchangedPassesHoldTheClaudePolicyLockUnderTheSmokeBar.
const gap1833FloorRealLockBar = 10 * time.Millisecond

func TestGAP1833VersionFloorPassHoldsTheRealClaudePolicyLockUnderTheBar(t *testing.T) {
	programFiles, holds := enterprisehooks.GAP1833RealLockFixtureForTest(t)
	root := t.TempDir()
	opts := enterprisepolicy.Options{
		GOOS:                "windows",
		HookBinary:          `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		WindowsProgramFiles: programFiles,
		WindowsProgramData:  filepath.Join(root, "ProgramData"),
		StateDir:            filepath.Join(root, "state", "machine-policy"),
		// The test tree sits in the test account's profile, which the
		// machine policy trust rules refuse; the real lock still runs its own
		// trust checks on its lock file.
		SkipTrustChecks: true,
	}
	connectors := []string{"claudecode"}
	if state, err := enterprisepolicy.PublishWindowsClaudeVersionFloor(opts, connectors); err != nil || !state.Changed {
		t.Fatalf("first pass must write the floor: changed=%v %v", state.Changed, err)
	}
	floor, err := enterprisepolicy.ClaudeVersionFloorPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(floor); err != nil {
		t.Fatalf("floor drop-in: %v", err)
	}
	holds()
	const passes = 20
	run := func(name string, before func(), wantChanged bool) []time.Duration {
		t.Helper()
		for i := 0; i < passes; i++ {
			if before != nil {
				before()
			}
			state, err := enterprisepolicy.PublishWindowsClaudeVersionFloor(opts, connectors)
			if err != nil {
				t.Fatal(err)
			}
			if state.Changed != wantChanged {
				t.Fatalf("%s pass %d changed=%v, want %v", name, i, state.Changed, wantChanged)
			}
		}
		got := holds()
		// A pass that takes no lock proves nothing; one whose sources
		// changed after its unlocked read takes it again.
		if len(got) < passes {
			t.Fatalf("%s took the real Claude policy lock %d times in %d passes, want at least one each", name, len(got), passes)
		}
		t.Logf("GAP1833 %-32s real lock-held p50 %8s max %8s (n=%d)", name, got[len(got)/2], got[len(got)-1], len(got))
		return got
	}
	unchanged := run("version floor unchanged", nil, false)
	if worst := unchanged[len(unchanged)-1]; worst >= gap1833FloorRealLockBar {
		t.Errorf("the version floor reconcile held the real Claude managed policy lock %s on an unchanged pass, at or above the %s bar", worst, gap1833FloorRealLockBar)
	}
	written := run("version floor written", func() {
		if err := os.Remove(floor); err != nil {
			t.Fatal(err)
		}
	}, true)
	if worst := written[len(written)-1]; worst >= 200*time.Millisecond {
		t.Errorf("the version floor reconcile held the real Claude managed policy lock %s writing the floor, at or above the 200ms smoke bar", worst)
	}
}
