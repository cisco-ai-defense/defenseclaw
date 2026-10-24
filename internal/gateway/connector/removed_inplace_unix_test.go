// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type removedFakeInfo struct{ stat any }

func (removedFakeInfo) Name() string       { return "f" }
func (removedFakeInfo) Size() int64        { return 0 }
func (removedFakeInfo) Mode() fs.FileMode  { return 0o600 }
func (removedFakeInfo) ModTime() time.Time { return time.Time{} }
func (removedFakeInfo) IsDir() bool        { return false }
func (i removedFakeInfo) Sys() any         { return i.stat }

// until 1.1: the stub is written into a script file only when it and its
// hooks folder have one owner, so a name that leads to another account's
// marked file (a root-owned managed hook) is never written by a privileged
// teardown.
func TestRemovedInPlaceOnlyForTheFolderOwnersFile(t *testing.T) {
	user := removedFakeInfo{&syscall.Stat_t{Uid: 1001}}
	root := removedFakeInfo{&syscall.Stat_t{Uid: 0}}
	if err := removedInPlaceRefusal(user, user); err != nil {
		t.Fatalf("the folder owner's own file is refused: %v", err)
	}
	if removedInPlaceRefusal(root, user) == nil || removedInPlaceRefusal(user, root) == nil {
		t.Fatal("a file of another owner than its folder's is written in place")
	}
	if removedInPlaceRefusal(removedFakeInfo{}, user) == nil || removedInPlaceRefusal(user, removedFakeInfo{}) == nil {
		t.Fatal("an owner that cannot be read allows an in-place write")
	}
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := removedInPlaceRefusal(info, info); err != nil {
		t.Fatalf("a real file of this account is refused: %v", err)
	}
}

// Safety net: a shell that is already running the old OpenHands script
// reads on from where it was in the file after the stub is written into it.
// The stub's tail (blanks out to the old end, then exit 2) makes that run
// block; a file cut after the stub would end the run with the status of its
// last command (0, an allow), and a rename alone would let it run the old
// script to its end.
func TestRemovedStubInPlaceBlocksARunThatIsAlreadyGoing(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	c := removedOpenHands
	h := newRemovedHost(t)
	h.stage(t, c)
	fifo := filepath.Join(h.home, "release")
	started := filepath.Join(h.home, "started")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	old := "#!" + bash + "\n# defenseclaw-managed-hook v6\nset -euo pipefail\n" +
		strings.Repeat("# the 1.0.3 hook goes on before it calls the gateway\n", 40) +
		": > '" + started + "'\n" +
		"cat '" + fifo + "' >/dev/null\n" +
		"exit 0\n"
	writeRemovedFile(t, h.script(c), old, c.mode)
	run := exec.Command(h.script(c))
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run.Process.Kill() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the old hook never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	release, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = release.Close()
	err = run.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("the run that was already going ended with %v; want exit 2", err)
	}
	h.requireStub(t, c)
}
