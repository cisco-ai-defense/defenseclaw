// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGAP1789UnansweredStateReadIsNotProved pins rel-1-0-10:GAP-1789: a
// write through a hard link to a state file in a part of the state whose read
// did not answer is not proved free of the state, and is refused as an
// unfinished walk refuses a patch target. Before, the identity index left the
// file out and the write read as no state write (an allow). On Windows a
// local folder read that the share-link walk waits for past
// networkShareAnswerWait reads this way (GAP-1787); here a share that never
// answers makes the same read on every host. Only multiply linked targets
// reach the index: a single-link write is judged as before, and once the
// state answers again an ordinary hard link is allowed again (the unanswered
// index is not kept).
func TestGAP1789UnansweredStateReadIsNotProved(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 0)
	slow := filepath.Join(home, ".defenseclaw", "cache", "slow")
	if err := os.Mkdir(slow, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(slow, "entry")
	alias := filepath.Join(cwd, "slow-alias")
	twin, twinLink := filepath.Join(cwd, "own.txt"), filepath.Join(cwd, "own-twin.txt")
	plain := filepath.Join(cwd, "plain.txt")
	for _, file := range []string{entry, twin, plain} {
		if err := os.WriteFile(file, []byte("data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(entry, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(twin, twinLink); err != nil {
		t.Fatal(err)
	}
	state := func(path string) bool {
		resetActiveStateIndex(t)
		return actionProtectedStatePath(path, &actionStateHome{home: home})
	}
	idle := func(when string) {
		t.Helper()
		if !state(alias) {
			t.Fatalf("%s: the hard link to a state file was not found", when)
		}
		if state(twin) || state(plain) {
			t.Fatalf("%s: an ordinary project write (a hard link pair of its own, a single-link file) read as a state write", when)
		}
	}
	idle("idle box")

	slowRoot := mustResolve(t, slow)
	hold := make(chan struct{})
	wait := networkShareAnswerWait
	networkShareAnswerWait = 20 * time.Millisecond
	restore := OverrideNetworkSharesForTest(func(path string) string {
		if path == slowRoot || strings.HasPrefix(path, slowRoot+string(filepath.Separator)) {
			return slowRoot
		}
		return ""
	}, func(string) { <-hold })
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
			restore()
			networkShareAnswerWait = wait
		}
	}
	t.Cleanup(release)

	if !state(alias) {
		t.Fatal("a hard link to a state file in a part of the state whose read did not answer read as no state write (fail open)")
	}
	if !state(twinLink) {
		t.Fatal("a multiply linked target was taken as proved free of the state while a read of the state did not answer")
	}
	if state(plain) {
		t.Fatal("a single-link project write was refused because a read of the state did not answer")
	}
	release()
	idle("after the state answers again")
}
