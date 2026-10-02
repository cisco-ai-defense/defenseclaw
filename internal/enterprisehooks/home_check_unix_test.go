//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stubHomeEnvironment replaces the mount table and session source.
func stubHomeEnvironment(t *testing.T, mounts map[string]unixMount, sessions map[int]bool) {
	t.Helper()
	origMount, origSession, origRoot, origOwner := unixMountAt, unixLiveSession, ecryptfsPrivateRoot, ecryptfsRootOwnerOK
	t.Cleanup(func() {
		unixMountAt, unixLiveSession, ecryptfsPrivateRoot, ecryptfsRootOwnerOK = origMount, origSession, origRoot, origOwner
	})
	unixMountAt = func(path string) (unixMount, bool, error) {
		mount, ok := mounts[filepath.Clean(path)]
		return mount, ok, nil
	}
	unixLiveSession = func(uid int) bool { return sessions[uid] }
}

func writeEcryptfsMarkers(t *testing.T, home, privateTarget string) {
	t.Helper()
	if err := os.Symlink(privateTarget, filepath.Join(home, ".Private")); err != nil {
		t.Fatal(err)
	}
	for _, marker := range ecryptfsLockedMarkers {
		if err := os.WriteFile(filepath.Join(home, marker), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A standard user can create every ecryptfs marker in their own home. The
// markers alone made the home "pending" forever, which stopped hook repair
// and foreign-hook cleanup for that user.
func TestCheckUnixTargetHomeIgnoresUserCreatedEcryptfsMarkers(t *testing.T) {
	stubHomeEnvironment(t, nil, nil)
	root := trustedTestDir(t)
	uid := os.Getuid()
	fake := makeHome(t, root, "faker")
	decoy := filepath.Join(root, "decoy", ".Private")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEcryptfsMarkers(t, fake, decoy)
	if check := CheckUnixTargetHome(fake, uid); check.State != HomeAvailable {
		t.Fatalf("user-created ecryptfs markers must not make a home pending: %+v", check)
	}
}

func TestCheckUnixTargetHomeRecognizesOnlyAVerifiedLockedEcryptfsHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ecryptfs private homes exist only on Linux")
	}
	mounts := map[string]unixMount{}
	sessions := map[int]bool{}
	stubHomeEnvironment(t, mounts, sessions)
	root := trustedTestDir(t)
	uid := os.Getuid()
	ecryptfsPrivateRoot = filepath.Join(root, ".ecryptfs")
	ecryptfsRootOwnerOK = func(owner uint32) bool { return int(owner) == uid }
	private := filepath.Join(ecryptfsPrivateRoot, "alice", ".Private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ecryptfsPrivateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	alice := makeHome(t, root, "alice")
	writeEcryptfsMarkers(t, alice, private)
	check := CheckUnixTargetHome(alice, uid)
	if check.State != HomePending || check.Inode == 0 {
		t.Fatalf("a verified locked ecryptfs home is pending: %+v", check)
	}
	// Unlocked: the ecryptfs mount covers the home, so markers seen there
	// are files inside the user's decrypted home.
	mounts[alice] = unixMount{FSType: "ecryptfs", Owner: -1}
	if check := CheckUnixTargetHome(alice, uid); check.State != HomeAvailable {
		t.Fatalf("a mounted home is not locked: %+v", check)
	}
	delete(mounts, alice)
	// A user with a live session has an unlocked home or runs agents from
	// the lower directory; either way it cannot be left unrepaired.
	sessions[uid] = true
	if check := CheckUnixTargetHome(alice, uid); check.State != HomeUntrusted || !strings.Contains(check.Reason, "live session") {
		t.Fatalf("a locked home with a live session must not be pending: %+v", check)
	}
	delete(sessions, uid)
	// An ecryptfs root that is not root-owned proves nothing.
	ecryptfsRootOwnerOK = func(uint32) bool { return false }
	if check := CheckUnixTargetHome(alice, uid); check.State != HomeAvailable {
		t.Fatalf("an ecryptfs root that is not root-owned proves nothing: %+v", check)
	}
}

// A filesystem the user mounted over their home (FUSE) answers the
// guardian's own stat calls: it could refuse (EACCES → pending) or hang
// them. It is untrusted before the home is inspected at all.
func TestCheckUnixTargetHomeRefusesUserMountedHomes(t *testing.T) {
	mounts := map[string]unixMount{}
	stubHomeEnvironment(t, mounts, nil)
	root := trustedTestDir(t)
	uid := os.Getuid()
	home := makeHome(t, root, "fuser")
	mounts[home] = unixMount{FSType: "fuse.sshfs", Owner: 1000}
	if check := CheckUnixTargetHome(home, uid); check.State != HomeUntrusted || !strings.Contains(check.Reason, "mounted by a user") {
		t.Fatalf("a user-mounted home must be untrusted: %+v", check)
	}
	gone := filepath.Join(root, "never-created")
	mounts[gone] = unixMount{FSType: "fuse", Owner: -1}
	if check := CheckUnixTargetHome(gone, uid); check.State != HomeUntrusted {
		t.Fatalf("the mount check must run before the home is stat'ed: %+v", check)
	}
	mounts[home] = unixMount{FSType: "fuse.gvfsd", Owner: 0}
	if check := CheckUnixTargetHome(home, uid); check.State != HomeAvailable {
		t.Fatalf("a root-mounted filesystem is inspected normally: %+v", check)
	}
	mounts[home] = unixMount{FSType: "nfs4", Owner: -1}
	if check := CheckUnixTargetHome(home, uid); check.State != HomeAvailable {
		t.Fatalf("an administrator's network home is inspected normally: %+v", check)
	}
}

func TestCheckUnixTargetHomeMarksAccessDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is never refused by permission bits")
	}
	stubHomeEnvironment(t, nil, nil)
	root := trustedTestDir(t)
	parent := filepath.Join(root, "sealed")
	home := filepath.Join(parent, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	check := CheckUnixTargetHome(home, os.Getuid())
	if check.State != HomePending || !check.AccessDenied {
		t.Fatalf("a refused home root is pending and marked access denied: %+v", check)
	}
}

func TestCheckUnixTargetHomeMarksOnlyAModeProblemAsLoose(t *testing.T) {
	stubHomeEnvironment(t, nil, nil)
	root := trustedTestDir(t)
	uid := os.Getuid()
	loose := makeHome(t, root, "loose")
	if err := os.Chmod(loose, 0o770); err != nil {
		t.Fatal(err)
	}
	if check := CheckUnixTargetHome(loose, uid); check.State != HomeUntrusted || !check.LooseMode || check.Inode == 0 {
		t.Fatalf("a group-writable home the user owns is untrusted and loose: %+v", check)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(loose, link); err != nil {
		t.Fatal(err)
	}
	if check := CheckUnixTargetHome(link, uid); check.State != HomeUntrusted || check.LooseMode {
		t.Fatalf("a symlinked home is not a mode problem: %+v", check)
	}
	if check := CheckUnixTargetHome(loose, uid+1); check.State != HomeUntrusted || check.LooseMode {
		t.Fatalf("another uid's home is not a mode problem: %+v", check)
	}
}
