// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A walk that stops at the link bound has not shown that no unasked share is
// left: it is reported as not proven (the share error), never as a completed
// check, and the read that follows it cannot open a share the walk did not
// ask (rel-1-0-9:GAP-0621).

// localLinkChain makes n links, the first named by the returned path, each
// pointing at the next and the last at target. The links are made from the
// last to the first so each target exists when its link is made: Windows
// makes a link to a folder a folder link only if the folder is there, and a
// file link to a folder cannot be opened as one, so a chain made from the
// first to the last is a chain no read can go through.
func localLinkChain(t *testing.T, dir string, n int, target string) string {
	t.Helper()
	name := func(i int) string { return filepath.Join(dir, fmt.Sprintf("hop%03d", i)) }
	for i := n; i >= 1; i-- {
		to := target
		if i < n {
			to = name(i + 1)
		}
		if err := os.Symlink(to, name(i)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	return name(1)
}

// More local links than the bound, the last into a share that does not
// answer: every reader asks that share and ends with the share error.
func TestLocalLinkChainLongerThanTheBoundIntoASilentShareIsAsked(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := localLinkChain(t, t.TempDir(), networkLinkHopLimit+1, share)
	through := filepath.Join(first, "leaf")
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, share, 20*time.Millisecond, time.Second, func(string) { <-release })
			start := time.Now()
			if err := tc.read(through); !errors.Is(err, errNetworkShareUnanswered) || probes.Load() != 1 {
				t.Fatalf("%s through %d links into a silent share = %v with %d probes, want the share error after one probe", tc.name, networkLinkHopLimit+1, err, probes.Load())
			}
			if took := time.Since(start); took > time.Second {
				t.Fatalf("read held the call %v", took)
			}
		})
	}
}

// The same chain into a share that answers is read, and so is a short one.
func TestLocalLinkChainIntoAShareThatAnswersIsRead(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{3, networkLinkHopLimit + 1} {
		t.Run(fmt.Sprint(n, " links"), func(t *testing.T) {
			first := localLinkChain(t, t.TempDir(), n, share)
			probes := fakeNetworkShare(t, share, 100*time.Millisecond, time.Second, func(string) {})
			if _, err := pathEvalSymlinks(filepath.Join(first, "leaf")); err != nil || probes.Load() != 1 {
				t.Fatalf("evalsymlinks through %d links into a share that answers = %v with %d probes", n, err, probes.Load())
			}
		})
	}
}

// A chain of local links longer than the bound that reaches no share is not
// proven free of one: the walk ends with the share error and asks nothing.
func TestLocalLinkChainBeyondTheBoundThatEndsNowhereIsNotProven(t *testing.T) {
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := localLinkChain(t, t.TempDir(), networkLinkHopLimit+2, local)
	probes := fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
	for _, tc := range linkedShareReads {
		if err := tc.read(filepath.Join(first, "leaf")); !errors.Is(err, errNetworkShareUnanswered) {
			t.Fatalf("%s through %d local links = %v, want the share error of a walk that did not finish", tc.name, networkLinkHopLimit+2, err)
		}
	}
	if probes.Load() != 0 {
		t.Fatalf("%d probes for a chain that reaches no share", probes.Load())
	}
}

// More share-to-share links than the walk follows: the walk ends with the
// share error, and a read of the last share is never opened unasked.
func TestShareLinkChainLongerThanTheBoundIsNotACompletedCheck(t *testing.T) {
	count := networkLinkHopLimit + 2
	shares := make([]string, count)
	for i := range shares {
		shares[i] = t.TempDir()
	}
	for i := 0; i+1 < count; i++ {
		if err := os.Symlink(shares[i+1], filepath.Join(shares[i], "next")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(shares[count-1], "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	link := filepath.Join(project, ".claude")
	if err := os.Symlink(shares[0], link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	through := link
	for range count - 1 {
		through = filepath.Join(through, "next")
	}
	through = filepath.Join(through, "leaf")
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			probes := fakeNetworkShares(t, shares, 100*time.Millisecond, func(string) {})
			if err := tc.read(through); !errors.Is(err, errNetworkShareUnanswered) {
				t.Fatalf("%s through %d shares = %v, want the share error of a walk that did not finish", tc.name, count, err)
			}
			if last := probes(shares[count-1]); last != 0 {
				t.Fatalf("last share asked %d times; the walk was to end before it", last)
			}
		})
	}
}

// Benign twin: a chain of shares that answer, within the bound, is read.
func TestShareLinkChainWithinTheBoundIsRead(t *testing.T) {
	const count = 5
	shares := make([]string, count)
	for i := range shares {
		shares[i] = t.TempDir()
	}
	for i := 0; i+1 < count; i++ {
		if err := os.Symlink(shares[i+1], filepath.Join(shares[i], "next")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(shares[count-1], "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), ".claude")
	if err := os.Symlink(shares[0], link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	through := link
	for range count - 1 {
		through = filepath.Join(through, "next")
	}
	probes := fakeNetworkShares(t, shares, 100*time.Millisecond, func(string) {})
	if _, err := pathStat(filepath.Join(through, "leaf")); err != nil {
		t.Fatalf("stat through %d answering shares = %v", count, err)
	}
	for i, share := range shares {
		if n := probes(share); n != 1 {
			t.Fatalf("share %d asked %d times, want once", i, n)
		}
	}
}
