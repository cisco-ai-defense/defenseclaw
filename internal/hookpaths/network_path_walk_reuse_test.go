// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countWalkReads counts the component reads of the share walk until the
// test ends.
func countWalkReads(t *testing.T) *int {
	t.Helper()
	var reads int
	old := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		reads++
		return os.Lstat(name)
	}
	t.Cleanup(func() { walkLstat = old })
	return &reads
}

// An ordinary command names thousands of operands below one folder. On
// Windows every operand cost a read of each folder on the way to it (about
// 1 ms an operand, so 3000 operands of a Codex call passed the 4 s answer
// budget); a hook call now reads each folder once and the deepest folder of
// an operand once more to see it is the same (rel-1-0-9:GAP-0943).
func TestShareWalkReadsEachFolderOnceAndTheDeepestAgainPerHookCall(t *testing.T) {
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	defer restore()
	project := filepath.Join(t.TempDir(), "work", "team", "service", "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	folders := len(strings.Split(strings.Trim(filepath.ToSlash(project), "/"), "/"))
	reads := countWalkReads(t)
	const operands = 3000
	end := HookCall()
	for i := range operands {
		if _, err := pathLstat(filepath.Join(project, fmt.Sprintf("f%d", i))); err == nil {
			t.Fatal("the operand exists")
		}
	}
	end()
	if want := folders + operands - 1; *reads > want {
		t.Fatalf("%d operands in one hook call made %d folder reads, want at most %d (%d folders and one more read per operand)", operands, *reads, want, folders)
	}
	// A read outside a hook call keeps no memory of an earlier one.
	before := *reads
	if _, err := pathLstat(filepath.Join(project, "again")); err == nil {
		t.Fatal("the operand exists")
	}
	if *reads-before != folders {
		t.Fatalf("a read outside a hook call made %d folder reads, want %d", *reads-before, folders)
	}
}

// The folders a call has found plain are the only ones it skips: a link to a
// share that is named after thousands of ordinary operands is still asked,
// and so is a link met again after a plain one.
func TestShareLinkAfterManyOrdinaryOperandsIsStillAsked(t *testing.T) {
	fx := newLinkedShareFixture(t)
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
	end := HookCall()
	defer end()
	for i := range 3000 {
		name := filepath.Join(fx.project, fmt.Sprintf("f%d", i))
		if _, err := pathLstat(name); errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("an ordinary operand %d is read as a share: %v", i, err)
		}
	}
	if probes.Load() != 0 {
		t.Fatalf("%d probes for ordinary operands, want none", probes.Load())
	}
	if _, err := pathLstat(fx.viaLink); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("operand below the link to the share = %v, want the share error", err)
	}
	if probes.Load() != 1 {
		t.Fatalf("%d probes, want one", probes.Load())
	}
}

// walkReuseFixture is a project below a deeper folder, a folder to swap, and
// a share that does not answer.
type walkReuseFixture struct {
	top, project, slot, share string
	probes                    func() int64
}

func newWalkReuseFixture(t *testing.T) walkReuseFixture {
	t.Helper()
	top := t.TempDir()
	project := filepath.Join(top, "team", "project")
	slot := filepath.Join(project, "slot")
	share := t.TempDir()
	for _, dir := range []string{slot, filepath.Join(share, "skills"), filepath.Join(share, "project", "slot")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	probes := fakeNetworkShare(t, share, 20*time.Millisecond, time.Second, func(string) { <-release })
	return walkReuseFixture{top: top, project: project, slot: slot, share: share, probes: probes.Load}
}

// readOperands reads n ordinary operands below dir in the call.
func readOperands(t *testing.T, dir string, n int) {
	t.Helper()
	for i := range n {
		if _, err := pathLstat(filepath.Join(dir, fmt.Sprintf("f%d", i))); errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("ordinary operand %d is read as a share: %v", i, err)
		}
	}
}

// A folder the call found plain can become a link to a share while the
// call runs; its next read must ask the share before it opens it.
func TestShareFolderThatBecomesALinkInTheCallIsAsked(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	readOperands(t, fx.slot, 3000)
	if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fx.share, fx.slot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := pathLstat(filepath.Join(fx.slot, "skills")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read below the swapped folder = %v, want the share error", err)
	}
	if got := fx.probes(); got != 1 {
		t.Fatalf("%d probes, want one", got)
	}
}

// The same when a folder above the one the operands are in becomes the link.
func TestShareAncestorThatBecomesALinkInTheCallIsAsked(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	readOperands(t, fx.slot, 3000)
	if err := os.Rename(fx.project, fx.project+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fx.share, "project"), fx.project); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := pathLstat(filepath.Join(fx.slot, "f0")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read below the swapped ancestor = %v, want the share error", err)
	}
	if got := fx.probes(); got != 1 {
		t.Fatalf("%d probes, want one", got)
	}
}

// A folder replaced by another plain folder is read on, with no probe: the
// call does not turn an ordinary change into a block.
func TestShareFolderReplacedByAnotherFolderStaysReadable(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	readOperands(t, fx.slot, 3000)
	if err := os.Rename(fx.slot, fx.slot+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fx.slot, 0o700); err != nil {
		t.Fatal(err)
	}
	readOperands(t, fx.slot, 3000)
	if got := fx.probes(); got != 0 {
		t.Fatalf("%d probes for a plain folder, want none", got)
	}
}

// A read of a known folder that the system holds (a folder above it became a
// link to a share that does not answer) is bounded by the answer wait and
// reported unanswered, once; the call keeps no folders after it.
func TestShareKnownFolderReadThatDoesNotReturnIsBounded(t *testing.T) {
	fx := newWalkReuseFixture(t)
	end := HookCall()
	defer end()
	readOperands(t, fx.slot, 10)
	release := make(chan struct{})
	defer close(release)
	old := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if name == fx.slot {
			<-release
		}
		return os.Lstat(name)
	}
	t.Cleanup(func() { walkLstat = old })
	start := time.Now()
	if _, err := pathLstat(filepath.Join(fx.slot, "f0")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("held read = %v, want the share error", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("held read took %v, want about the answer wait", took)
	}
	if call := currentHookCall(); len(call.plainFolders) != 0 || !call.noPlain {
		t.Fatalf("the call keeps %d folders after a held read (noPlain %v), want none", len(call.plainFolders), call.noPlain)
	}
}
