// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-0476: an undo lists the files it removed (added since the
// checkpoint) and put back (changed or deleted since), as paths in the
// actor, so the launcher can report them; ignored files are not touched
// and not listed, and a file name cannot pass for a key of the answer.
func TestGAP0476UndoListsTheFilesItReverted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	a := newActor(t)
	c := a.client()
	ctx := context.Background()
	proj := filepath.Join(a.workdir, "proj")
	write(t, proj, "f.txt", "one", 0o644)
	write(t, proj, "gone.txt", "kept", 0o644)
	write(t, proj, ".gitignore", "*.log\n", 0o644)
	cp, err := Checkpoint(ctx, CheckpointOptions{Exec: c, Dir: proj})
	if err != nil {
		t.Fatal(err)
	}
	write(t, proj, "f.txt", "two", 0o644)
	write(t, proj, "sub/new.sh", "new", 0o755)
	write(t, proj, "x\nrestored=9\ncommit=0", "odd", 0o644)
	write(t, proj, "build.log", "ignored", 0o644)
	if err := os.Remove(filepath.Join(proj, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	u, err := Undo(ctx, UndoOptions{Exec: c, Dir: proj})
	if err != nil || u.ID != "1" || u.Commit != cp.Commit {
		t.Fatalf("%+v %v (checkpoint %+v)", u, err, cp)
	}
	slices.Sort(u.Removed)
	slices.Sort(u.Restored)
	wantRemoved := []string{filepath.Join(proj, "sub/new.sh"), filepath.Join(proj, "x\nrestored=9\ncommit=0")}
	slices.Sort(wantRemoved)
	if !slices.Equal(u.Removed, wantRemoved) {
		t.Fatalf("removed %q, want %q", u.Removed, wantRemoved)
	}
	if want := []string{filepath.Join(proj, "f.txt"), filepath.Join(proj, "gone.txt")}; !slices.Equal(u.Restored, want) {
		t.Fatalf("restored %q, want %q", u.Restored, want)
	}
	// Nothing changed since: nothing listed.
	if u, err = Undo(ctx, UndoOptions{Exec: c, Dir: proj}); err != nil || len(u.Removed)+len(u.Restored) != 0 {
		t.Fatalf("second undo %+v %v", u, err)
	}
}

// An actor whose answer has no lists (an older script) lists nothing.
func TestGAP0476UndoAnswerWithoutLists(t *testing.T) {
	head, rest := undoAnswer([]byte("restored=1\ncommit=abc\n"))
	if string(head) != "restored=1\ncommit=abc\n" || rest != nil {
		t.Fatalf("%q %q", head, rest)
	}
	removed, restored := undoChanges("/w", "", nil)
	if removed != nil || restored != nil {
		t.Fatal("lists from nothing")
	}
	// A name cut off at the bound is dropped.
	removed, restored = undoChanges("/w", "8,7", []byte("M\x00a.txt\x00b.sh\x00cut"))
	if !slices.Equal(restored, []string{"/w/a.txt"}) || !slices.Equal(removed, []string{"/w/b.sh"}) {
		t.Fatalf("removed %q restored %q", removed, restored)
	}
}
