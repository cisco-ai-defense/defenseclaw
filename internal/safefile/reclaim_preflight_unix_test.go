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

	private := filepath.Join(t.TempDir(), "private home")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PreflightReclaimDirectory(private); err != nil {
		t.Fatalf("a private home owned by this account was refused: %v", err)
	}
	// A home that does not exist yet is created by root, so it is let through
	// only below a root-owned folder (root is its owner there).
	oldOwner := pathOwnerUID
	t.Cleanup(func() { pathOwnerUID = oldOwner })
	pathOwnerUID = func(string) (uint32, error) { return 0, nil }
	if err := PreflightReclaimDirectory(filepath.Join(private, "not yet", "deeper")); err != nil {
		t.Fatalf("a home below a root-owned folder was refused: %v", err)
	}
	pathOwnerUID = oldOwner

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
