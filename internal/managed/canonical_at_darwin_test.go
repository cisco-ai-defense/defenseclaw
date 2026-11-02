//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func userOwnedOptions(mode os.FileMode) CanonicalOptions {
	return CanonicalOptions{
		UnixOwner:                   &UnixOwnership{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())},
		UnixMode:                    mode,
		AllowUntrustedOwnerTransfer: true,
		Quiet:                       true,
	}
}

func openDirFD(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func aclLines(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("/bin/ls", "-led", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ls: %v %s", err, out)
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if len(lines) < 2 {
		return ""
	}
	return lines[1]
}

func TestEnsureCanonicalAtRepairsThroughDescriptors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", path).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v %s", err, out)
	}
	if err := unix.Chflags(path, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(path, 0) })

	result, err := EnsureCanonicalAt(openDirFD(t, dir), dir, "token", ObjectAdminFile, userOwnedOptions(0o600))
	if err != nil {
		t.Fatalf("EnsureCanonicalAt: %v", err)
	}
	if result.Outcome != CanonicalRepaired {
		t.Fatalf("outcome = %s (%v, %s)", result.Outcome, result.Drift, result.RepairError)
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o7777 != 0o600 || st.Flags&unix.UF_IMMUTABLE != 0 {
		t.Fatalf("mode %04o flags %#x", st.Mode&0o7777, st.Flags)
	}
	if acl := aclLines(t, path); acl != "" {
		t.Fatalf("ACL left: %s", acl)
	}
}

func TestEnsureCanonicalAtRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(dir, "hard")); err != nil {
		t.Fatal(err)
	}
	fd := openDirFD(t, dir)
	for _, name := range []string{"link", "hard"} {
		result, err := EnsureCanonicalAt(fd, dir, name, ObjectAdminFile, userOwnedOptions(0o600))
		if err == nil || result.Outcome != CanonicalStructural || !IsStructuralCanonicalError(err) {
			t.Fatalf("%s: outcome %s err %v", name, result.Outcome, err)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat(target, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o7777 != 0o666 {
		t.Fatalf("link target re-permissioned: %04o", st.Mode&0o7777)
	}
}

// A parent swapped for a symlink after the caller pinned it cannot redirect
// the repair: the object is opened relative to the pinned descriptor and the
// path re-check reports the swap instead of writing elsewhere.
func TestEnsureCanonicalAtIgnoresSwappedParentPath(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "hooks")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "script"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	fd := openDirFD(t, parent)

	decoy := filepath.Join(root, "decoy")
	if err := os.Mkdir(decoy, 0o755); err != nil {
		t.Fatal(err)
	}
	decoyFile := filepath.Join(decoy, "script")
	if err := os.WriteFile(decoyFile, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(decoyFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, parent); err != nil {
		t.Fatal(err)
	}
	_, _ = EnsureCanonicalAt(fd, parent, "script", ObjectAdminFile, userOwnedOptions(0o600))
	var st unix.Stat_t
	if err := unix.Stat(decoyFile, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o7777 != 0o666 {
		t.Fatalf("repair followed the swapped parent: %04o", st.Mode&0o7777)
	}
}
