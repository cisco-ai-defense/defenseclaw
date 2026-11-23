// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// DET111 step 2 (no wall clock in the readers): the identity index of the
// active state was kept for 2 s whatever changed in it, so a hard link to a
// state file written in that time was not mapped to it (the write through the
// link was judged an ordinary file) until the index aged out. The index is
// kept while its folders keep their fingerprints now: a change is seen at
// once, and an unchanged state is still walked once.
func TestActiveStateIndexFollowsTheStateNotTheClock(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 10)
	// Let the fixture's folders settle, so the index is kept across calls.
	time.Sleep(200 * time.Millisecond)
	plain := filepath.Join(cwd, "plain")
	if err := os.WriteFile(plain, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(plain, plain+".link"); err != nil {
		t.Fatal(err)
	}
	before := activeStateIndexWalks.Load()
	for range 3 {
		if _, same, _ := ResolveActiveStateHardlinkTarget(plain+".link", home); same {
			t.Fatal("an ordinary hard link mapped to the state")
		}
	}
	if walks := activeStateIndexWalks.Load() - before; walks != 1 {
		t.Fatalf("an unchanged state walked %d times, want 1", walks)
	}
	// A new state file and a hard link to it, inside the old 2 s window.
	state := filepath.Join(home, ".defenseclaw", "hooks", "new-hook.sh")
	if err := os.WriteFile(state, []byte("state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(cwd, "hook-alias")
	if err := os.Link(state, alias); err != nil {
		t.Fatal(err)
	}
	if mapped, same, _ := ResolveActiveStateHardlinkTarget(alias, home); !same || mapped != state {
		t.Fatalf("a hard link to a state file written after the index was built: mapped=%q same=%v, want %q", mapped, same, state)
	}
}
