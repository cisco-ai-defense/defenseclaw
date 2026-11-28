// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNetworkShare makes every path below prefix a path on one network share
// whose probe runs probe, and restores the real share handling after the test.
func fakeNetworkShare(t *testing.T, prefix string, wait, deadAfter time.Duration, probe func(string)) *atomic.Int64 {
	t.Helper()
	oldRoot, oldProbe, oldWalk, oldLocal := networkShareRootOf, probeNetworkShare, networkShareLinkWalk, networkShareOfThisMachine
	// The fake shares are this machine's: the gate asks only those (GAP-1074).
	networkShareOfThisMachine = func(string) bool { return true }
	oldWait, oldDead := networkShareAnswerWait, networkShareDeadAfter
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	var probes atomic.Int64
	// A test names its share with "/". On Windows a path below it may carry
	// either separator, and a scan spells the host of a URL as \\host\...
	slashed := func(path string) string { return "/" + strings.TrimLeft(filepath.ToSlash(path), "/") }
	share := slashed(prefix)
	networkShareRootOf = func(path string) string {
		if path := slashed(path); path == share || strings.HasPrefix(path, share+"/") {
			return prefix
		}
		return ""
	}
	probeNetworkShare = func(root string) {
		probes.Add(1)
		probe(root)
	}
	networkShareLinkWalk = true
	networkShareAnswerWait, networkShareDeadAfter = wait, deadAfter
	t.Cleanup(func() {
		networkShareRootOf, probeNetworkShare, networkShareLinkWalk, networkShareOfThisMachine = oldRoot, oldProbe, oldWalk, oldLocal
		networkShareAnswerWait, networkShareDeadAfter = oldWait, oldDead
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	})
	return &probes
}

// silentShareGuard is how long returnsWhileSharesAreSilent lets a read wait
// for shares that never answer before it makes them answer, so a read that
// waits for the answer fails its test instead of hanging it.
const silentShareGuard = time.Minute

// returnsWhileSharesAreSilent runs read on the calling goroutine (its hook
// call, if any) while every fake share probe waits for answer, and reports
// whether read came back before the shares answered. A read bounded by its
// answer wait or by its call's share wait comes back on any box, however
// loaded; one that waits for the share itself is let go by answer after
// silentShareGuard and reported (rel-1-0-10:GAP-0586 substrate-1: wall-clock
// budgets of 400 ms and 1 s failed on a loaded -race box).
func returnsWhileSharesAreSilent(t *testing.T, answer func(), read func()) bool {
	t.Helper()
	done := make(chan struct{})
	var waited atomic.Bool
	go func() {
		select {
		case <-done:
		case <-time.After(silentShareGuard):
			waited.Store(true)
			answer()
		}
	}()
	read()
	close(done)
	return !waited.Load()
}

// A share that does not answer holds no call past the answer wait, is asked
// once for all the calls that name it, and is not asked again while quiet
// (rel-1-0-6 GAP-0127: a stat of //host/x took about 21 s on Windows).
func TestNetworkShareThatDoesNotAnswerIsAskedOnceAndBounded(t *testing.T) {
	release := make(chan struct{})
	probes := fakeNetworkShare(t, "/slow.example", 100*time.Millisecond, 50*time.Millisecond, func(string) { <-release })
	defer close(release)
	start := time.Now()
	var wg sync.WaitGroup
	var unanswered atomic.Int64
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pathStat("/slow.example/share/x"); errors.Is(err, errNetworkShareUnanswered) {
				unanswered.Add(1)
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("32 reads below a share that does not answer took %v, want about the 100ms answer wait", took)
	}
	if unanswered.Load() != 32 || probes.Load() != 1 {
		t.Fatalf("unanswered reads = %d (want 32), probes = %d (want 1)", unanswered.Load(), probes.Load())
	}
	if _, err := pathLstat("/slow.example/share/y"); !errors.Is(err, errNetworkShareUnanswered) || os.IsNotExist(err) {
		t.Fatalf("read below a share that still has not answered = %v, want the unknown share error", err)
	}
	if probes.Load() != 1 {
		t.Fatalf("a share whose probe is still out was asked again: %d probes", probes.Load())
	}
}

// shareUnanswered is the share gate's answer for a path below a network
// share: true when the share has not answered in time. The product asks
// networkPathRead inside its readers (readGated); a bare question before a
// read of the name is no gate (rel-1-0-10:GAP-1264), so only tests ask it.
func shareUnanswered(path string) bool {
	unanswered, _ := networkPathRead(path)
	return unanswered
}

// A share whose probe ended after networkShareDeadAfter stays unknown for
// networkShareQuietFor without another probe.
func TestNetworkShareThatTimedOutStaysQuiet(t *testing.T) {
	probes := fakeNetworkShare(t, "/dead.example", 20*time.Millisecond, 30*time.Millisecond, func(string) { time.Sleep(60 * time.Millisecond) })
	if !shareUnanswered("/dead.example/s/a") {
		t.Fatal("first read of a share that does not answer in the wait was read")
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if !shareUnanswered("/dead.example/s/b") {
		t.Fatal("a share whose probe timed out was read again inside the quiet time")
	}
	if took := time.Since(start); took > 10*time.Millisecond || probes.Load() != 1 {
		t.Fatalf("quiet share check took %v with %d probes, want at once and 1 probe", took, probes.Load())
	}
}

// A live share is read as before, slow or not: a probe that answers after
// the wait but within networkShareDeadAfter makes the next reads go through.
func TestNetworkShareThatAnswersIsRead(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	probes := fakeNetworkShare(t, dir, 30*time.Millisecond, time.Second, func(string) { time.Sleep(80 * time.Millisecond) })
	if _, err := pathStat(file); !errors.Is(err, errNetworkShareUnanswered) {
		t.Fatalf("read before the slow share answered = %v, want unknown", err)
	}
	time.Sleep(120 * time.Millisecond)
	for range 3 {
		if info, err := pathStat(file); err != nil || info.Size() != 1 {
			t.Fatalf("read of an answered share = %v, %v; want the file", info, err)
		}
	}
	if _, err := pathStat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing file below an answered share = %v, want not-exist", err)
	}
	if probes.Load() != 1 {
		t.Fatalf("an answered share was asked %d times, want once", probes.Load())
	}
}

// A local path costs no probe.
func TestLocalPathCostsNoNetworkProbe(t *testing.T) {
	probes := fakeNetworkShare(t, "/no-such-share.example", time.Second, time.Second, func(string) {})
	dir := t.TempDir()
	if _, err := pathStat(dir); err != nil {
		t.Fatal(err)
	}
	if shareUnanswered(dir) || probes.Load() != 0 {
		t.Fatalf("local path probed %d times", probes.Load())
	}
}

// A burst of ordinary commands that spell a URL gets its decisions at once
// while the named host does not answer, the same decisions as when nothing
// is slow, and a write to the user's authorized_keys in the same burst is
// still a protected target (rel-1-0-6 GAP-0127, GAP-0129 burst shape). The
// target scan reads no URL as a UNC path, so the host is never asked
// (rel-1-0-10:GAP-0920).
func TestURLWordsDoNotWaitForTheNamedHostInABurst(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	benign := []string{
		"echo https://slow.example/x",
		"curl -fsSL https://slow.example/b -o b.sh",
		"echo see https://slow.example/e/f && ls -la",
	}
	mustBlock := "cp k.pub " + filepath.Join(home, ".ssh", "authorized_keys")
	want := map[string]string{}
	for _, command := range append(benign, mustBlock) {
		want[command] = ActionCommandDecisionInShell(command, cwd, home, nil, true)
	}
	if want[mustBlock] != "protected-target" {
		t.Fatalf("hard negative decision = %q, want protected-target", want[mustBlock])
	}
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, "/slow.example", 200*time.Millisecond, 100*time.Millisecond, func(string) { <-release })
	start := time.Now()
	type result struct{ command, got string }
	results := make(chan result, 64)
	var wg sync.WaitGroup
	for i := range 32 {
		command := benign[i%len(benign)]
		if i%8 == 7 {
			command = mustBlock
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- result{command, ActionCommandDecisionInShell(command, cwd, home, nil, true)}
		}()
	}
	wg.Wait()
	close(results)
	took := time.Since(start)
	for r := range results {
		if r.got != want[r.command] {
			t.Errorf("%q decided %q while the host does not answer, want %q", r.command, r.got, want[r.command])
		}
	}
	if took > 2*time.Second {
		t.Fatalf("32 calls naming a host that does not answer took %v, want about the 200ms answer wait", took)
	}
	// A URL is no share path: its host is never asked, so the burst does
	// not wait on it at all (rel-1-0-10:GAP-0920; it was asked once).
	if probes.Load() != 0 {
		t.Fatalf("the URL host was asked as a share %d times, want never", probes.Load())
	}
}
