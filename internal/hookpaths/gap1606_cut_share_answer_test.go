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

	// The walk reads the physical path: a temp folder below a link (macOS
	// /var) would never name the share the override matches.
	resetPlainFolders(t)
	dir := linkFreeTempDir(t)
	share := filepath.Join(dir, "share")
	if err := os.MkdirAll(filepath.Join(share, ".ssh"), 0o700); err != nil {
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
	// The share is also a home whose key file is a link off the share: the
	// protected key paths list the file it reaches only once it is read.
	testSymlink(t, keys, filepath.Join(share, ".ssh", "authorized_keys"))
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
	before := HookCallState()
	if resolved, ok := NewTargetMemo().ResolveWriteTarget(link); ok {
		t.Fatalf("a write below a share the budget cut off resolved to %s", resolved)
	}
	// A cut that spent no wait still changes the call's state, so the
	// gateway's dispatch memo (GAP-1472) keeps no dispatch that met it.
	if HookCallState() == before {
		t.Error("a share wait the budget cut short with no wait left leaves the call's state as it was")
	}
	if _, err := callStat(link); err == nil {
		t.Fatal("a stat below a share the budget cut off answered")
	}
	evaluation := NewTargetMemo()
	if offShare := keyPathsOffShare(evaluation.ProtectedAuthorizedKeysPaths(share), share, keys); offShare != "" {
		t.Fatalf("the key paths of a home the budget cut off list %s", offShare)
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
	if keyPathsOffShare(evaluation.ProtectedAuthorizedKeysPaths(share), share, keys) == "" {
		t.Error("the key paths of the home miss the file its key link reaches: the list made during the cut was kept")
	}
}

// keyPathsOffShare is the first of paths that is not below share and names
// the file keys ("" for none).
func keyPathsOffShare(paths []string, share, keys string) string {
	want, err := os.Stat(keys)
	if err != nil {
		return ""
	}
	for _, path := range paths {
		if pathAtOrUnder(path, share) {
			continue
		}
		if got, err := os.Stat(path); err == nil && os.SameFile(got, want) {
			return path
		}
	}
	return ""
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

// rel-1-0-10:GAP-1606 review P3-1: the read of a known folder is bounded by
// what the call has left of its share wait (stillPlain). When that wait, not
// the answer wait, ended it, the walk it failed is a budget cut like a share
// ask the budget cut short, and the call's memory keeps none of it: once the
// read is back, a later resolve in the same call walks again.
func TestGAP1606AKnownFolderReadTheBudgetCutIsNotKept(t *testing.T) {
	previous := memoReads
	memoReads = true
	t.Cleanup(func() { memoReads = previous })
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	t.Cleanup(restore)
	slot := filepath.Join(linkFreeTempDir(t), "team", "slot")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}

	defer HookCall()()
	call := currentHookCall()
	if call == nil {
		t.Fatal("no hook call")
	}
	// The walk now knows slot as a plain folder and reads it once more for
	// each name below it.
	readOperands(t, slot, 1)
	call.waitLeft, call.tail = 20*time.Millisecond, 0
	release := make(chan struct{})
	var once sync.Once
	answer := func() { once.Do(func() { close(release) }) }
	t.Cleanup(answer)
	old := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if name == slot {
			<-release
		}
		return os.Lstat(name)
	}
	t.Cleanup(func() { walkLstat = old })

	target := filepath.Join(slot, "f1")
	mark := call.cutMark()
	if resolved, ok := NewTargetMemo().ResolveWriteTarget(target); ok {
		t.Fatalf("a write below a folder whose read the budget cut off resolved to %s", resolved)
	}
	if call.cutMark() == mark {
		t.Error("the read of a known folder the call's share wait cut short is not counted as a budget cut")
	}

	answer()
	for name, resolve := range map[string]func(string) (string, bool){
		"evaluation memo": NewTargetMemo().ResolveWriteTarget,
		"call":            ResolveWriteTarget,
	} {
		if resolved, ok := resolve(target); !ok || filepath.Base(resolved) != "f1" {
			t.Errorf("%s: the write below the folder read again = %q, %v: the cut walk was kept", name, resolved, ok)
		}
	}
}

// rel-1-0-10:GAP-1606 review P3-2: protectedReach grades a write's parent
// against the protected names. Names made while the budget cut a share off
// are not kept, and neither is a parent grade made against them, even when
// the share has answered by the time the parent is read: a later reach in
// the same evaluation reads the parent again against the complete names.
func TestGAP1606AReachParentGradedAgainstCutNamesIsNotKept(t *testing.T) {
	previous := memoReads
	memoReads = true
	t.Cleanup(func() { memoReads = previous })
	resetPlainFolders(t)
	dir := linkFreeTempDir(t)
	share := filepath.Join(dir, "share")
	inShare := filepath.Join(share, "real")
	home := filepath.Join(dir, "home")
	for _, folder := range []string{inShare, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The home's key name is a link into the share; the write's parent is a
	// link to the same folder of the share.
	if err := os.Symlink(inShare, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	via := filepath.Join(dir, "via")
	testSymlink(t, inShare, via)
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
	// The budget is spent: the names are made while the share is cut off.
	// The share answers at the first read of the write's own path, after the
	// names and before the parent is read.
	call.waitLeft = 0
	old := walkLstat
	walkLstat = func(name string) (os.FileInfo, error) {
		if name == via {
			answer()
			shareAnswered(t, share)
		}
		return os.Lstat(name)
	}
	t.Cleanup(func() { walkLstat = old })

	evaluation := NewTargetMemo()
	target := filepath.Join(via, "new")
	evaluation.ProtectedReach(target, home)
	if grade := evaluation.ProtectedReach(target, home); grade != GradeNamed {
		t.Fatalf("a write through a link to the folder a protected key link reaches = %q, want Named: the parent graded against the cut names was kept", grade.String())
	}
}
