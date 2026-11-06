// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The gateway can establish a known file identity while a share root probe
// is pending. This keeps a protected hard-link destination named.
func TestG288ReachableShareIdentityWhileRootPending(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	alias := filepath.Join(root, "alias")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	fakeNetworkShare(t, root, 750*time.Millisecond, 5*time.Second, func(string) {
		time.Sleep(2 * time.Second)
	})
	start := time.Now()
	aliasInfo, aliasErr := PathLstat(alias)
	fileInfo, fileErr := PathStat(file)
	if aliasErr != nil || fileErr != nil || !os.SameFile(aliasInfo, fileInfo) {
		t.Fatalf("known file identity = %v, %v; errors %v, %v", aliasInfo, fileInfo, aliasErr, fileErr)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("known identity took %v, want within one second", elapsed)
	}
}

// A stalled read of one file cannot hide a reachable protected file identity
// elsewhere on the same share.
func TestG288PendingShareReadKeepsOtherIdentityVisible(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	alias := filepath.Join(root, "alias")
	stalled := filepath.Join(root, "stalled")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 50*time.Millisecond, time.Second, func(string) {})
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if name == stalled {
			time.Sleep(200 * time.Millisecond)
		}
		return oldRead(name, kind)
	}
	if _, err := PathStat(stalled); !ShareUnanswered(err) {
		t.Fatalf("stalled path = %v, want unknown share", err)
	}
	aliasInfo, aliasErr := PathLstat(alias)
	fileInfo, fileErr := PathStat(file)
	if aliasErr != nil || fileErr != nil || !os.SameFile(aliasInfo, fileInfo) {
		t.Fatalf("reachable identity = %v, %v; errors %v, %v", aliasInfo, fileInfo, aliasErr, fileErr)
	}
}

// Two unanswered identities on one share use one first-contact window.
// Another reached identity can still answer after either read times out.
func TestG288PendingShareReadsShareFirstContactBudget(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 80*time.Millisecond, time.Second, func(string) {})
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if name == first || name == second {
			time.Sleep(250 * time.Millisecond)
		}
		return oldRead(name, kind)
	}
	start := time.Now()
	for _, path := range []string{first, second} {
		if _, err := PathStat(path); !ShareUnanswered(err) {
			t.Fatalf("%s = %v, want unknown share", path, err)
		}
	}
	if elapsed := time.Since(start); elapsed >= 175*time.Millisecond {
		t.Errorf("two pending identities took %v, want one share window", elapsed)
	}
}

// After a root probe spends its bound, an identity read cannot spend another
// full bound on the same unanswered share.
func TestG288RootPendingDoesNotDoubleChargeIdentity(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 750*time.Millisecond, 5*time.Second, func(string) {
		time.Sleep(2 * time.Second)
	})
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if name == file {
			time.Sleep(2 * time.Second)
		}
		return oldRead(name, kind)
	}
	start := time.Now()
	if _, err := pathStat(file); !ShareUnanswered(err) {
		t.Fatalf("root-bound read = %v, want unknown share", err)
	}
	if _, err := PathStat(file); !ShareUnanswered(err) {
		t.Fatalf("identity read = %v, want unknown share", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("first contact took %v, want within one second", elapsed)
	}
}

// A share root and a file read consume one hook answer budget together.
func TestG288ShareRootAndFileUseOneDeadline(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "ordinary.txt")
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 750*time.Millisecond, 5*time.Second, func(string) {
		time.Sleep(450 * time.Millisecond)
	})
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if name == file {
			time.Sleep(2 * time.Second)
		}
		return oldRead(name, kind)
	}
	start := time.Now()
	_, err := pathLstat(file)
	if !ShareUnanswered(err) {
		t.Errorf("first read = %v, want unknown share", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("first contact took %v, want under one second", elapsed)
	}
}

// A read that finishes after its deadline cannot keep the next read unknown.
func TestG288ShareFileReadRecovers(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "ordinary.txt")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 50*time.Millisecond, time.Second, func(string) {})
	var reads atomic.Int32
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if name == file && reads.Add(1) == 1 {
			time.Sleep(200 * time.Millisecond)
		}
		return oldRead(name, kind)
	}
	if _, err := PathStat(file); !ShareUnanswered(err) {
		t.Fatalf("first read = %v, want unknown share", err)
	}
	time.Sleep(250 * time.Millisecond)
	if info, err := PathStat(file); err != nil || info.Size() != 2 {
		t.Fatalf("next read = %v, %v, want current file identity", info, err)
	}
}

// Every hook reader must use the same file bound after a share root answers.
func TestG288AllShareReadersAreBounded(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "ordinary.txt")
	if err := os.WriteFile(file, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	oldRead := readPath
	t.Cleanup(func() { readPath = oldRead })
	fakeNetworkShare(t, root, 30*time.Millisecond, time.Second, func(string) {})
	readPath = func(name string, kind pathReadKind) pathReadResult {
		if strings.HasPrefix(name, root) {
			time.Sleep(150 * time.Millisecond)
		}
		return oldRead(name, kind)
	}
	for _, row := range []struct {
		name string
		read func() error
	}{
		{"stat", func() error { _, err := pathStat(file); return err }},
		{"lstat", func() error { _, err := pathLstat(file); return err }},
		{"pinned stat", func() error { _, err := pathStatPinned(file); return err }},
		{"open", func() error { _, err := pathOpen(file); return err }},
		{"read directory", func() error { _, err := pathReadDir(root); return err }},
		{"read link", func() error { _, err := pathReadlink(link); return err }},
		{"resolve link", func() error { _, err := pathEvalSymlinks(link); return err }},
	} {
		t.Run(row.name, func(t *testing.T) {
			start := time.Now()
			if err := row.read(); !ShareUnanswered(err) {
				t.Errorf("read = %v, want unknown share", err)
			}
			if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
				t.Errorf("read took %v, want bounded result", elapsed)
			}
			// Let the prior operating-system read finish so each row
			// exercises its own reader instead of the pending-share cache.
			time.Sleep(170 * time.Millisecond)
		})
	}
}
