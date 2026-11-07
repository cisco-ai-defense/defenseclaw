//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0714: the check a root run makes before its first write into a home is
// the one ReclaimToDirectoryOwner refuses on after it, so a refused start
// leaves nothing behind. The test stands in for the root run (it cannot be one).
func TestGAP0714PreflightRefusesWhatReclaimRefuses(t *testing.T) {
	old := effectiveUID
	t.Cleanup(func() { effectiveUID = old })
	effectiveUID = func() int { return 0 }
	t.Setenv("SUDO_UID", "")

	// Group- and other-writable: a directory a private file cannot be given to.
	open := filepath.Join(t.TempDir(), "open home")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(open, "gateway.log")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reclaimErr := ReclaimToDirectoryOwner(file)
	preflightErr := PreflightReclaimDirectory(open)
	if reclaimErr == nil || preflightErr == nil {
		t.Fatalf("an open home must be refused by both: reclaim %v, preflight %v", reclaimErr, preflightErr)
	}
	if reclaimErr.Error() != preflightErr.Error() {
		t.Fatalf("preflight refuses with %q, reclaim with %q", preflightErr, reclaimErr)
	}

	// A path that is a link is not followed.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(open, link); err != nil {
		t.Fatal(err)
	}
	if err := PreflightReclaimDirectory(link); err == nil {
		t.Fatal("a linked home was not refused")
	}
}

// Benign twins: a private home owned by this account, a home that does not
// exist yet and any non-root run pass the preflight.
func TestGAP0714PreflightLetsOrdinaryHomesThrough(t *testing.T) {
	old := effectiveUID
	t.Cleanup(func() { effectiveUID = old })
	effectiveUID = func() int { return 0 }
	t.Setenv("SUDO_UID", "")

	private := filepath.Join(t.TempDir(), "private home")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PreflightReclaimDirectory(private); err != nil {
		t.Fatalf("a private home owned by this account was refused: %v", err)
	}
	// A home that does not exist yet is created by root, so it is let through
	// only below a root-owned folder, inside root's own home (root is its owner
	// there; here the stand-in root home is the private folder).
	oldOwner := pathOwnerAndMode
	t.Cleanup(func() { pathOwnerAndMode = oldOwner })
	pathOwnerAndMode = ownedWhereItExists(0, 0o755)
	oldRoot := rootHomeDir
	t.Cleanup(func() { rootHomeDir = oldRoot })
	rootHomeDir = func() string { return private }
	if err := PreflightReclaimDirectory(filepath.Join(private, "not yet", "deeper")); err != nil {
		t.Fatalf("a home below a root-owned folder was refused: %v", err)
	}
	pathOwnerAndMode = oldOwner

	open := filepath.Join(t.TempDir(), "open home")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	effectiveUID = func() int { return 1000 }
	if err := PreflightReclaimDirectory(open); err != nil {
		t.Fatalf("a non-root run was refused: %v", err)
	}
}

// GAP-0714 (review 5): a root run would create a missing home, its log and its
// PID record owned by root, and a 0700 root-owned home strands the account the
// home is for. A missing home below a folder another account owns is refused
// before anything is created.
func TestGAP0714PreflightRefusesToCreateAHomeInsideAnotherAccountsFolder(t *testing.T) {
	old := effectiveUID
	t.Cleanup(func() { effectiveUID = old })
	effectiveUID = func() int { return 0 }

	account := t.TempDir() // owned by the account running the test, not root
	home := filepath.Join(account, ".defenseclaw")
	err := PreflightReclaimDirectory(home)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing home inside another account's folder was not refused: %v", err)
	}
	// Further levels of missing folders do not hide the owner.
	if err := PreflightReclaimDirectory(filepath.Join(account, "a", "b", ".defenseclaw")); err == nil {
		t.Fatal("a deeper missing home inside another account's folder was not refused")
	}
	if _, statErr := os.Lstat(home); !os.IsNotExist(statErr) {
		t.Fatalf("the preflight created the home: %v", statErr)
	}
	// Benign twins: the account's own start and the same path once it exists.
	effectiveUID = func() int { return 1000 }
	if err := PreflightReclaimDirectory(home); err != nil {
		t.Fatalf("a non-root run was refused: %v", err)
	}
	effectiveUID = func() int { return 0 }
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PreflightReclaimDirectory(home); err != nil {
		t.Fatalf("an existing private home owned by this account was refused: %v", err)
	}
}

// GAP-0714 (review 6): a root-owned folder that other accounts can write (/tmp,
// a group-writable shared folder) is no better than a folder owned by another
// account: root would create the home owned by root and the account it is for
// could not use it. Only a root-owned folder nobody else can write passes; the
// 0700 and 0755 rows are the benign twins.
func TestGAP0714PreflightRefusesToCreateAHomeInsideAFolderOtherAccountsCanWrite(t *testing.T) {
	old := effectiveUID
	t.Cleanup(func() { effectiveUID = old })
	effectiveUID = func() int { return 0 }
	t.Setenv("SUDO_UID", "")
	oldOwner := pathOwnerAndMode
	t.Cleanup(func() { pathOwnerAndMode = oldOwner })

	home := filepath.Join(t.TempDir(), ".defenseclaw")
	oldRoot := rootHomeDir
	t.Cleanup(func() { rootHomeDir = oldRoot })
	rootHomeDir = func() string { return filepath.Dir(home) } // the benign rows are root's own home
	for _, tc := range []struct {
		name    string
		uid     uint32
		perm    os.FileMode
		refused bool
	}{
		{"root-owned world-writable (like /tmp)", 0, 0o777, true},
		{"root-owned group-writable", 0, 0o775, true},
		{"root-owned other-writable only", 0, 0o757, true},
		{"root-owned private folder", 0, 0o700, false},
		{"root-owned ordinary folder", 0, 0o755, false},
		{"folder owned by another account", 1000, 0o755, true},
	} {
		pathOwnerAndMode = ownedWhereItExists(tc.uid, tc.perm)
		// A deeper missing path is judged by the nearest existing folder.
		for _, target := range []string{home, filepath.Join(home, "deeper", "still")} {
			err := PreflightReclaimDirectory(target)
			if tc.refused && (err == nil || !strings.Contains(err.Error(), "does not exist")) {
				t.Errorf("%s: %s was not refused: %v", tc.name, target, err)
			}
			if !tc.refused && err != nil {
				t.Errorf("%s: %s was refused: %v", tc.name, target, err)
			}
		}
	}
	// Nothing was created by any of the checks.
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("the preflight created the home: %v", err)
	}
	// The real /tmp (root-owned and open to everyone on Linux and macOS) is refused.
	pathOwnerAndMode = oldOwner
	if uid, perm, err := pathOwnerAndMode("/tmp"); err == nil && uid == 0 && perm&0o002 != 0 {
		if err := PreflightReclaimDirectory(filepath.Join("/tmp", "dc-g629m-preflight-not-created", ".defenseclaw")); err == nil {
			t.Fatal("a missing home directly below /tmp was not refused")
		}
	}
}

// GAP-0714 (review 7): a sudo start is for the account that ran sudo. A missing
// home below a root-owned folder nobody else can write (/home) would be created
// by root, owned by root and mode 0700, and the account could not enter it to
// start its own gateway. The root-owned folder alone is no proof the new home
// belongs to root: it is let through only inside root's own home, so a sudo
// start for a missing account home is refused before anything is created.
func TestGAP0714PreflightRefusesToCreateAnAccountHomeForTheSudoAccount(t *testing.T) {
	old := effectiveUID
	t.Cleanup(func() { effectiveUID = old })
	effectiveUID = func() int { return 0 }
	oldOwner := pathOwnerAndMode
	t.Cleanup(func() { pathOwnerAndMode = oldOwner })
	oldRoot := rootHomeDir
	t.Cleanup(func() { rootHomeDir = oldRoot })

	// A root-owned 0755 homes folder (/home) and a root home beside it.
	base := t.TempDir()
	homes := filepath.Join(base, "home")
	rootHome := filepath.Join(base, "rootuser")
	for _, dir := range []string{homes, rootHome} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pathOwnerAndMode = ownedWhereItExists(0, 0o755)
	rootHomeDir = func() string { return rootHome }

	missingAccountHome := filepath.Join(homes, "someone", ".defenseclaw")
	t.Setenv("SUDO_UID", "1000")
	for _, target := range []string{
		missingAccountHome,
		filepath.Join(homes, "someone"),
		filepath.Join(homes, "someone", "a", "b", ".defenseclaw"),
	} {
		err := PreflightReclaimDirectory(target)
		if err == nil || !strings.Contains(err.Error(), "account that ran sudo") {
			t.Errorf("%s: a sudo start was allowed to create a root-owned account home: %v", target, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(homes, "someone")); !os.IsNotExist(err) {
		t.Fatalf("the preflight created the home: %v", err)
	}

	// Benign twin: root's own home, under sudo and with no sudo account or one
	// that is root itself.
	rootOwn := filepath.Join(rootHome, ".defenseclaw")
	if err := PreflightReclaimDirectory(rootOwn); err != nil {
		t.Errorf("a sudo start in root's own home was refused: %v", err)
	}
	for _, raw := range []string{"", "0"} {
		t.Setenv("SUDO_UID", raw)
		if err := PreflightReclaimDirectory(rootOwn); err != nil {
			t.Errorf("SUDO_UID %q: a root run in root's own home was refused: %v", raw, err)
		}
		// An absent or root sudo account is no proof that root owns another
		// account's home: the target is outside root's home, so it is refused.
		err := PreflightReclaimDirectory(missingAccountHome)
		if err == nil || !strings.Contains(err.Error(), "root would create") {
			t.Errorf("SUDO_UID %q: a root run was allowed to create a root-owned account home: %v", raw, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(homes, "someone")); !os.IsNotExist(err) {
		t.Fatalf("the preflight created the home: %v", err)
	}
	// A root home reached through a link is still root's home.
	t.Setenv("SUDO_UID", "1000")
	linkedRoot := filepath.Join(base, "rootlink")
	if err := os.Symlink(rootHome, linkedRoot); err != nil {
		t.Fatal(err)
	}
	rootHomeDir = func() string { return linkedRoot }
	if err := PreflightReclaimDirectory(rootOwn); err != nil {
		t.Errorf("a sudo start in root's home reached through a link was refused: %v", err)
	}
}

// ownedWhereItExists stands in for a folder owned by uid with mode perm: a path
// that does not exist has no owner, as with the real call.
func ownedWhereItExists(uid uint32, perm os.FileMode) func(string) (uint32, os.FileMode, error) {
	return func(path string) (uint32, os.FileMode, error) {
		if _, err := os.Stat(path); err != nil {
			return 0, 0, err
		}
		return uid, perm, nil
	}
}

// GAP-0714 (review 8): SUDO_UID empty or 0 names no account, so it is no proof
// that root owns the home it is about to create. A root run aimed at another
// account's missing home below a root-owned 0755 folder is refused before
// anything is created; root's own home is the benign twin.
func TestGAP0714PreflightRefusesAForeignMissingHomeWithoutASudoAccount(t *testing.T) {
	oldUID, oldOwner, oldRoot := effectiveUID, pathOwnerAndMode, rootHomeDir
	t.Cleanup(func() { effectiveUID, pathOwnerAndMode, rootHomeDir = oldUID, oldOwner, oldRoot })
	effectiveUID = func() int { return 0 }
	pathOwnerAndMode = ownedWhereItExists(0, 0o755)
	base := t.TempDir()
	rootHome := filepath.Join(base, "root")
	homes := filepath.Join(base, "home")
	for _, dir := range []string{rootHome, homes} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rootHomeDir = func() string { return rootHome }
	foreign := filepath.Join(homes, "foreign", ".defenseclaw")
	t.Setenv("DEFENSECLAW_HOME", foreign)
	for _, raw := range []string{"", "0", " "} {
		t.Setenv("SUDO_UID", raw)
		if err := PreflightReclaimDirectory(foreign); err == nil || !strings.Contains(err.Error(), "root would create") {
			t.Errorf("SUDO_UID %q: a root run into a missing foreign home passed the preflight: %v", raw, err)
		}
		if err := PreflightReclaimDirectory(filepath.Join(rootHome, ".defenseclaw")); err != nil {
			t.Errorf("SUDO_UID %q: root's own home was refused: %v", raw, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(homes, "foreign")); !os.IsNotExist(err) {
		t.Fatalf("the preflight created the foreign home: %v", err)
	}
}
