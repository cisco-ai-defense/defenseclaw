// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The scans of one hook call stat, lstat and resolve the same operand again
// and again, and on Windows each read cost the walk of its folders (about
// 100 us, so 5000 operands of a Codex or Claude Code call passed the hook
// answer budget). The walk is now made once for a path in a call, and what
// the last name needs of it is read alone (rel-1-0-9:GAP-0943).
func TestHookCallWalksAnOperandOncePerCall(t *testing.T) {
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	project := filepath.Join(t.TempDir(), "work", "team", "service", "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	folders := len(strings.Split(strings.Trim(filepath.ToSlash(project), "/"), "/"))
	reads := countWalkReads(t)
	const operands = 5000
	end := HookCall()
	for i := range operands {
		name := filepath.Join(project, fmt.Sprintf("f%d", i))
		// The scans of a call: an lstat, then stats.
		if _, err := pathLstat(name); err == nil {
			t.Fatal("the operand exists")
		}
		for range 4 {
			if _, err := pathStat(name); err == nil {
				t.Fatal("the operand exists")
			}
		}
	}
	end()
	// One read of the folder and one of the last name for the lstat, then
	// the last name alone for the first stat; the rest are answered.
	if want := folders + 2*operands; *reads > want {
		t.Fatalf("%d operands read five times in one hook call made %d walk reads, want at most %d", operands, *reads, want)
	}
}

// Outside a call, and in a second call, a path is walked again: the file
// system changes between calls, and a link made by one call is met by the
// next.
func TestHookCallMemoryEndsWithTheCall(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	readOperands(t, fx.slot, 20)
	end()
	if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.share, fx.slot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, inCall := range []bool{false, true} {
		if inCall {
			defer HookCall()()
		}
		if _, err := pathLstat(filepath.Join(fx.slot, "f0")); !errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("in a call = %v: read of a name the earlier call read = %v, want the share error", inCall, err)
		}
	}
}

// With several calls in progress the reads of a goroutine cannot be told
// from another call without a stack walk that costs more than a read, so
// nothing is remembered: every read is walked as it was.
func TestHookCallMemoryIsOffWhileSeveralCallsRun(t *testing.T) {
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	folder := t.TempDir()
	reads := countWalkReads(t)
	open, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		defer HookCall()()
		close(open)
		<-release
	}()
	<-open
	end := HookCall()
	name := filepath.Join(folder, "f0")
	for range 3 {
		if _, err := pathLstat(name); err == nil {
			t.Fatal("the operand exists")
		}
	}
	end()
	close(release)
	<-stopped
	if *reads < 3 {
		t.Fatalf("three reads of one name made %d walk reads with two calls open, want each walked", *reads)
	}
}

// What a call stat-ed it is told again, and a name it did not stat is read
// when it is first asked (every reader of one evaluation sees the same
// files); the next call sees the file system as it is then.
func TestHookCallStatAnswersAreKeptForTheCall(t *testing.T) {
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	folder := t.TempDir()
	seen, later := filepath.Join(folder, "seen"), filepath.Join(folder, "later")
	end := HookCall()
	if _, err := pathStat(seen); !os.IsNotExist(err) {
		t.Fatalf("missing name = %v", err)
	}
	for _, name := range []string{seen, later} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pathStat(seen); !os.IsNotExist(err) {
		t.Fatalf("name stat-ed earlier in the call = %v, want the answer of the call", err)
	}
	if _, err := pathStat(later); err != nil {
		t.Fatalf("name not stat-ed before = %v, want it read", err)
	}
	end()
	if _, err := pathStat(seen); err != nil {
		t.Fatalf("name in the next call = %v, want it read", err)
	}
}

// Windows names a file by spellings that differ in the case of a letter,
// and the scans of one call spell an operand both ways; two names the
// system tells apart are never one key.
func TestClearedKeyFoldsOnlyWhatWindowsFolds(t *testing.T) {
	same := clearedKey(`C:\Users\Dev\proj\F1`, true) == clearedKey(`c:\users\dev\proj\f1`, true)
	if want := runtime.GOOS == "windows"; same != want {
		t.Fatalf("ASCII case spellings share a key = %v, want %v on %s", same, want, runtime.GOOS)
	}
	if clearedKey("proj\\k", true) == clearedKey("proj\\\u212a", true) {
		t.Fatal("a Kelvin sign shares a key with k")
	}
	if clearedKey("proj\\f1", true) == clearedKey("proj\\f1", false) {
		t.Fatal("a read that opens the last link shares a key with one that does not")
	}
}
