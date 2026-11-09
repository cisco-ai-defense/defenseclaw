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
// budget); a hook call now reads a folder once (rel-1-0-9:GAP-0943).
func TestShareWalkReadsEachFolderOncePerHookCall(t *testing.T) {
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
	if *reads > folders {
		t.Fatalf("%d operands in one hook call made %d folder reads, want at most one per folder (%d)", operands, *reads, folders)
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
