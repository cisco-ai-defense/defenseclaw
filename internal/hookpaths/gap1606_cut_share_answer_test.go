// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1606: a read below a share that the call's budget cut off
// is unknown at that moment, not the answer of the file system. The call's
// memory (callStat, the call memo every evaluation memo resolves its write
// targets in since GAP-0447) keeps no answer made then, so once the share
// has answered, a later read in the same call reads the link to the
// protected file. On Windows CI three shares that did not answer left the
// live share cut off for the first read of a call that names a protected
// link on it; the call memo kept that walk and every later evaluation
// allowed the write.
func TestGAP1606ACutShareAnswerIsNotKeptForTheCall(t *testing.T) {
	previous := memoReads
	memoReads = true
	t.Cleanup(func() { memoReads = previous })

	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.MkdirAll(share, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(keys, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(share, "alias")
	if err := os.Symlink(keys, link); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	release := make(chan struct{})
	var once sync.Once
	answer := func() { once.Do(func() { close(release) }) }
	restore := OverrideNetworkSharesForTest(func(path string) string {
		if path == share || strings.HasPrefix(path, share+string(filepath.Separator)) {
			return share
		}
		return ""
	}, func(string) { <-release })
	t.Cleanup(func() {
		answer()
		restore()
	})

	defer HookCall()()
	call := currentHookCall()
	if call == nil {
		t.Fatal("no hook call")
	}
	// The shares before it spent the call's budget: the wait for this share
	// is cut short at once, while the share would still answer.
	call.waitLeft = 0
	if resolved, ok := NewTargetMemo().ResolveWriteTarget(link); ok {
		t.Fatalf("a write below a share the budget cut off resolved to %s", resolved)
	}
	if _, err := callStat(link); err == nil {
		t.Fatal("a stat below a share the budget cut off answered")
	}

	answer()
	shareAnswered(t, share)

	want, err := os.Stat(keys)
	if err != nil {
		t.Fatal(err)
	}
	for name, resolve := range map[string]func(string) (string, bool){
		"evaluation memo": NewTargetMemo().ResolveWriteTarget,
		"call":            ResolveWriteTarget,
	} {
		resolved, ok := resolve(link)
		if !ok {
			t.Errorf("%s: the link on the share that has answered is unresolved: the cut answer was kept", name)
			continue
		}
		if got, err := os.Stat(resolved); err != nil || !os.SameFile(got, want) {
			t.Errorf("%s: the link resolved to %s (%v), want the protected file", name, resolved, err)
		}
	}
	if got, err := callStat(link); err != nil || !os.SameFile(got, want) {
		t.Errorf("a stat of the link after the share answered: %v; the cut answer was kept", err)
	}
}

// shareAnswered waits until the probe of share has returned.
func shareAnswered(t *testing.T, share string) {
	t.Helper()
	key := strings.ToLower(filepath.ToSlash(share))
	networkShares.mu.Lock()
	probe := networkShares.probes[key]
	networkShares.mu.Unlock()
	if probe == nil {
		t.Fatal("the share was never asked")
	}
	select {
	case <-probe.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the share did not answer")
	}
}
