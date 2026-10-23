//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Review P1 (1.0.4 guard loop round 2): an allow passes an outage only
// while the gateway that wrote it could still revoke it. The folder of the
// account's revocation marks (the key folder) must be the record writer's,
// with write and search for its owner, carry no immutable or append-only
// flag or deny entry, and be on a writable volume; whatever of that cannot
// be read blocks too. A block still denies with its reason.
func TestPublishedSessionOutageAllowNeedsAMarkFolderItsWriterCanChange(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a fresh allow in folders the writer can change proves the session")
	}
	keyDir := filepath.Dir(root)
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o755) })
	for _, mode := range []os.FileMode{0o555, 0o455, 0o355, 0o055} {
		if err := os.Chmod(keyDir, mode); err != nil {
			t.Fatal(err)
		}
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("a key folder of mode %04o lets the allow prove the session", mode)
		}
	}
	if err := os.Chmod(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key folder its owner can change again proves the session")
	}

	previousLocked, previousVolume := publishedSessionFolderLocked, publishedSessionVolumeReadOnly
	t.Cleanup(func() { publishedSessionFolderLocked, publishedSessionVolumeReadOnly = previousLocked, previousVolume })
	for name, locked := range map[string]func(string) (bool, error){
		"immutable or a deny entry": func(path string) (bool, error) { return path == keyDir, nil },
		"flags unreadable":          func(string) (bool, error) { return false, errors.New("statx: function not implemented") },
	} {
		publishedSessionFolderLocked = locked
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%s: the allow must prove nothing", name)
		}
	}
	publishedSessionFolderLocked = previousLocked
	// The key folder can be a mount of its own: a read-only one takes no
	// mark although the record folder's volume is writable.
	publishedSessionVolumeReadOnly = func(path string) (bool, error) { return path == keyDir, nil }
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a key folder on a read-only volume lets the allow prove the session")
	}
	publishedSessionVolumeReadOnly = previousVolume

	if os.Geteuid() == 0 {
		// The records were written by root, which changes any folder.
		if !publishedSessionTestAllows(root, identity, key) {
			t.Fatal("root's records prove the session in a folder only root may change")
		}
		if err := os.Chown(keyDir, 65534, -1); err != nil {
			t.Fatal(err)
		}
		dir, _ := PublishedSessionIdentityDir(root, identity)
		if err := os.Chown(dir, 4242, -1); err != nil {
			t.Fatal(err)
		}
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatal("a key folder another account owns lets the allow prove the session")
		}
	}

	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true, Reason: foreignHookBlockedPrefix + " blocked"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	publishedSessionFolderLocked = func(string) (bool, error) { return true, nil }
	if got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a block still denies: %+v %v", got, err)
	}
}

// A plain folder has no flag that keeps its owner from changing it, and a
// folder that is gone cannot be checked.
func TestPublishedSessionFolderIsLockedReadsAPlainFolder(t *testing.T) {
	dir := t.TempDir()
	if locked, err := publishedSessionFolderIsLocked(dir); err != nil || locked {
		t.Fatalf("a temporary folder: %v %v", locked, err)
	}
	if _, err := publishedSessionFolderIsLocked(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a folder that is gone must be an error")
	}
}
