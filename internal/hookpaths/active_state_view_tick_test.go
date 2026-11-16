// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0488, GAP-0073: a view of the active state kept after one read serves
// the next read of the same call only while nothing in the state changed. A
// hard link to the patch target made right after a kept read, in the same
// clock tick as the read or the next one, is always found by the next read.
func TestActiveStateViewSeesALinkMadeRightAfterAKeptRead(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, ".defenseclaw", "hooks")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{state, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "other"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(project, "twin.txt")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		// Long enough for the last change of the state to be in an earlier
		// tick, so the first read keeps its view.
		time.Sleep(12 * time.Millisecond)
		if _, same, complete := ResolveActiveStateIdentity(target, home); same || !complete {
			t.Fatalf("round %d: a target outside the state read as state=%v complete=%v", i, same, complete)
		}
		linked := filepath.Join(state, fmt.Sprintf("alias-%d", i))
		if err := os.Link(target, linked); err != nil {
			t.Fatal(err)
		}
		if _, same, complete := ResolveActiveStateIdentity(target, home); !same || !complete {
			t.Fatalf("round %d: a link made right after the read was missed (state=%v complete=%v)", i, same, complete)
		}
		if err := os.Remove(linked); err != nil {
			t.Fatal(err)
		}
	}
}
