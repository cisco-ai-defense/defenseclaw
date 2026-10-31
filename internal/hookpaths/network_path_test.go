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
	oldRoot, oldProbe := networkShareRootOf, probeNetworkShare
	oldWait, oldDead := networkShareAnswerWait, networkShareDeadAfter
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	var probes atomic.Int64
	networkShareRootOf = func(path string) string {
		if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			return prefix
		}
		return ""
	}
	probeNetworkShare = func(root string) {
		probes.Add(1)
		probe(root)
	}
	networkShareAnswerWait, networkShareDeadAfter = wait, deadAfter
	t.Cleanup(func() {
		networkShareRootOf, probeNetworkShare = oldRoot, oldProbe
		networkShareAnswerWait, networkShareDeadAfter = oldWait, oldDead
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	})
	return &probes
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

// A share whose probe ended after networkShareDeadAfter stays unknown for
// networkShareQuietFor without another probe.
func TestNetworkShareThatTimedOutStaysQuiet(t *testing.T) {
	probes := fakeNetworkShare(t, "/dead.example", 20*time.Millisecond, 30*time.Millisecond, func(string) { time.Sleep(60 * time.Millisecond) })
	if !networkPathUnanswered("/dead.example/s/a") {
		t.Fatal("first read of a share that does not answer in the wait was read")
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if !networkPathUnanswered("/dead.example/s/b") {
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
	if networkPathUnanswered(dir) || probes.Load() != 0 {
		t.Fatalf("local path probed %d times", probes.Load())
	}
}

// A burst of ordinary commands that spell a URL (read as a UNC path by the
// target scan) gets its decisions inside the answer wait while the named
// host does not answer, the same decisions as when nothing is slow, and a
// write to the user's authorized_keys in the same burst is still a
// protected target (rel-1-0-6 GAP-0127, GAP-0129 burst shape).
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
	if probes.Load() != 1 {
		t.Fatalf("the share was asked %d times, want once", probes.Load())
	}
}
