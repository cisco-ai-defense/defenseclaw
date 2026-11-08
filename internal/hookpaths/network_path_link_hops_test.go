// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A read that goes through several links, each into another share, opens
// every share on the way: asking the first share does not answer for the
// second (rel-1-0-9:GAP-0621).

// fakeNetworkShares makes each of roots a network share, asked through ask,
// and returns the number of probes of each root.
func fakeNetworkShares(t *testing.T, roots []string, wait time.Duration, ask func(root string)) func(root string) int {
	t.Helper()
	oldRoot, oldProbe, oldWalk := networkShareRootOf, probeNetworkShare, networkShareLinkWalk
	oldWait := networkShareAnswerWait
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	var mu sync.Mutex
	probes := map[string]int{}
	slashed := func(path string) string { return "/" + strings.TrimLeft(filepath.ToSlash(path), "/") }
	networkShareRootOf = func(path string) string {
		path = slashed(path)
		for _, root := range roots {
			if share := slashed(root); path == share || strings.HasPrefix(path, share+"/") {
				return root
			}
		}
		return ""
	}
	probeNetworkShare = func(root string) {
		root = strings.TrimRight(root, "/\\")
		mu.Lock()
		probes[root]++
		mu.Unlock()
		ask(root)
	}
	networkShareLinkWalk = true
	networkShareAnswerWait = wait
	t.Cleanup(func() {
		networkShareRootOf, probeNetworkShare, networkShareLinkWalk = oldRoot, oldProbe, oldWalk
		networkShareAnswerWait = oldWait
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	})
	return func(root string) int {
		mu.Lock()
		defer mu.Unlock()
		return probes[root]
	}
}

type twoShareFixture struct {
	project, shareA, shareB string
	// link reaches shareA; hop is the link inside shareA that reaches shareB.
	link, hop string
}

func newTwoShareFixture(t *testing.T) twoShareFixture {
	t.Helper()
	fx := twoShareFixture{project: filepath.Join(t.TempDir(), "project"), shareA: t.TempDir(), shareB: t.TempDir()}
	if err := os.MkdirAll(fx.project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.shareB, "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.link = filepath.Join(fx.project, ".claude")
	fx.hop = filepath.Join(fx.shareA, "skills")
	if err := os.Symlink(fx.shareA, fx.link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(fx.shareB, fx.hop); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	return fx
}

func TestEveryLinkHopIntoAShareIsAskedBeforeTheRead(t *testing.T) {
	fx := newTwoShareFixture(t)
	through := filepath.Join(fx.link, "skills", "leaf")
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShares(t, []string{fx.shareA, fx.shareB}, 100*time.Millisecond, func(root string) {
				if root == fx.shareB {
					<-release
				}
			})
			start := time.Now()
			err := tc.read(through)
			if took := time.Since(start); took > time.Second {
				t.Fatalf("read held the call %v", took)
			}
			if !errors.Is(err, errNetworkShareUnanswered) {
				t.Fatalf("read through two shares = %v, want the share error of the second", err)
			}
			if a, b := probes(fx.shareA), probes(fx.shareB); a != 1 || b != 1 {
				t.Fatalf("probes A=%d B=%d, want one each", a, b)
			}
		})
	}
}

// The first share is asked first: a first share that does not answer ends the
// read before the second share is asked.
func TestFirstSilentShareOnTheWayEndsTheReadBeforeTheNext(t *testing.T) {
	fx := newTwoShareFixture(t)
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShares(t, []string{fx.shareA, fx.shareB}, 20*time.Millisecond, func(root string) {
		if root == fx.shareA {
			<-release
		}
	})
	if _, err := pathStat(filepath.Join(fx.link, "skills", "leaf")); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("stat = %v, want the share error", err)
	}
	if a, b := probes(fx.shareA), probes(fx.shareB); a != 1 || b != 0 {
		t.Fatalf("probes A=%d B=%d, want A asked and B not", a, b)
	}
}

// A final link is followed only by the reads that open it; the second link
// is the final component here.
func TestFinalLinkIntoSecondShareIsAskedOnlyByTheReadsThatFollowIt(t *testing.T) {
	fx := newTwoShareFixture(t)
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShares(t, []string{fx.shareA, fx.shareB}, 100*time.Millisecond, func(root string) {
				if root == fx.shareB {
					<-release
				}
			})
			err := tc.read(filepath.Join(fx.link, "skills"))
			follows := tc.name != "lstat" && tc.name != "readlink" && tc.name != "walkdir"
			if follows != errors.Is(err, errNetworkShareUnanswered) || follows != (probes(fx.shareB) == 1) {
				t.Fatalf("final link read = %v with %d probes of B; follows the link: %v", err, probes(fx.shareB), follows)
			}
			if probes(fx.shareA) != 1 {
				t.Fatalf("%d probes of A, want one", probes(fx.shareA))
			}
		})
	}
}

// Benign twins: both shares answer, or the link inside the first share leads
// to a local folder, and the read is made as before.
func TestLinksThroughSharesThatAnswerOrLeadLocallyAreRead(t *testing.T) {
	fx := newTwoShareFixture(t)
	probes := fakeNetworkShares(t, []string{fx.shareA, fx.shareB}, 200*time.Millisecond, func(string) {})
	for _, tc := range linkedShareReads {
		if tc.name == "readlink" {
			continue
		}
		if err := tc.read(filepath.Join(fx.link, "skills", "leaf")); err != nil && tc.name != "readdir" && tc.name != "walkdir" {
			t.Fatalf("%s through two shares that answer = %v", tc.name, err)
		}
	}
	if a, b := probes(fx.shareA), probes(fx.shareB); a != 1 || b != 1 {
		t.Fatalf("probes A=%d B=%d, want one each", a, b)
	}

	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "leaf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := newTwoShareFixture(t)
	if err := os.Remove(other.hop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(local, other.hop); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	probes = fakeNetworkShares(t, []string{other.shareA, other.shareB}, 200*time.Millisecond, func(string) {})
	if _, err := pathStat(filepath.Join(other.link, "skills", "leaf")); err != nil {
		t.Fatalf("stat through a share and a local link = %v", err)
	}
	if a, b := probes(other.shareA), probes(other.shareB); a != 1 || b != 0 {
		t.Fatalf("probes A=%d B=%d, want only A asked", a, b)
	}
}

// A link inside a share that points at itself ends the walk, not the call.
func TestLinkLoopInsideAShareEndsTheWalk(t *testing.T) {
	fx := newTwoShareFixture(t)
	loop := filepath.Join(fx.shareA, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	fakeNetworkShares(t, []string{fx.shareA, fx.shareB}, 100*time.Millisecond, func(string) {})
	start := time.Now()
	if _, err := pathStat(filepath.Join(fx.link, "loop")); errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("stat of a link loop = %v, want the system error", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("link loop held the call %v", took)
	}
}

// A name that ends in a separator opens its last link, as os.Lstat follows
// it, so lstat and a directory walk of link/ read the share.
func TestTrailingSeparatorOpensTheFinalLinkIntoAShare(t *testing.T) {
	fx := newLinkedShareFixture(t)
	sep := string(filepath.Separator)
	for _, tc := range linkedShareReads {
		if tc.name != "lstat" && tc.name != "walkdir" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
			if err := tc.read(fx.link + sep); !errors.Is(err, errNetworkShareUnanswered) || probes.Load() != 1 {
				t.Fatalf("%s of the link with a trailing separator = %v with %d probes, want the share error after one probe", tc.name, err, probes.Load())
			}
		})
		t.Run(tc.name+" without separator", func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
			if err := tc.read(fx.link); errors.Is(err, errNetworkShareUnanswered) || probes.Load() != 0 {
				t.Fatalf("%s of the link itself = %v with %d probes, want no probe", tc.name, err, probes.Load())
			}
		})
	}
	// A local folder with a trailing separator costs no probe.
	probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) {})
	if _, err := pathLstat(fx.project + sep); err != nil || probes.Load() != 0 {
		t.Fatalf("lstat of a local folder with a trailing separator = %v with %d probes", err, probes.Load())
	}
}
