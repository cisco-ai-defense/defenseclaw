//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"path/filepath"
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
	if err := PreflightReclaimDirectory(filepath.Join(private, "not yet")); err != nil {
		t.Fatalf("a home that does not exist yet was refused: %v", err)
	}

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
