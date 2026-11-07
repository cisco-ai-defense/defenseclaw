// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const createCanonicalTestAccount = `NT SERVICE\DefenseClawGateway`

// onlyOwnerDrift reports a drift list that names nothing but the owner, which
// a non-elevated test token cannot assign at creation.
func onlyOwnerDrift(drift []string) bool {
	for _, entry := range drift {
		if !strings.HasPrefix(entry, "owner ") {
			return false
		}
	}
	return len(drift) > 0
}

// GAP-0762: a directory the product creates must already carry the canonical
// descriptor, so the Guardian has no repair to log on its first pass.
func TestCreateCanonicalDirectoryIsCanonicalFromCreation(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	path := filepath.Join(t.TempDir(), "hooks")
	if err := CreateCanonicalDirectory(path, ObjectRuntimeDirectory, opts); err != nil {
		t.Fatalf("CreateCanonicalDirectory: %v", err)
	}
	result, err := AssessCanonical(path, ObjectRuntimeDirectory, opts)
	if err != nil {
		t.Fatalf("AssessCanonical: %v", err)
	}
	if result.Outcome != CanonicalOK {
		if onlyOwnerDrift(result.Drift) {
			t.Skipf("the test token cannot own the directory as Administrators: %v", result.Drift)
		}
		t.Fatalf("a created directory must be canonical at once, got %s: %v", result.Outcome, result.Drift)
	}
}

// The base behaviour this replaces: a plain mkdir inherits its parent
// entries unprotected, which the canonical check calls drift.
func TestPlainMkdirIsDriftTheGuardianWouldRepair(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	path := filepath.Join(t.TempDir(), "hooks")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := AssessCanonical(path, ObjectRuntimeDirectory, opts)
	if err != nil {
		t.Fatalf("AssessCanonical: %v", err)
	}
	if result.Outcome == CanonicalOK || !strings.Contains(strings.Join(result.Drift, "; "), "inherits") {
		t.Fatalf("a plain directory should read as inheriting drift, got %s: %v", result.Outcome, result.Drift)
	}
}

func TestCreateCanonicalDirectoryRefusals(t *testing.T) {
	opts := CanonicalOptions{GatewayServiceAccount: createCanonicalTestAccount, Quiet: true}
	dir := t.TempDir()
	existing := filepath.Join(dir, "hooks")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CreateCanonicalDirectory(existing, ObjectRuntimeDirectory, opts); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing path must fail like os.Mkdir, got %v", err)
	}
	if err := CreateCanonicalDirectory(filepath.Join(dir, "file"), ObjectRuntimeFile, opts); err == nil {
		t.Fatal("a file kind must be refused")
	}
	t.Setenv(WindowsServiceAccountEnv, "")
	unpinned := filepath.Join(dir, "unpinned")
	err := CreateCanonicalDirectory(unpinned, ObjectRuntimeDirectory, CanonicalOptions{Quiet: true})
	if !errors.Is(err, ErrCanonicalIdentityUnavailable) {
		t.Fatalf("an unresolved gateway identity must be reported, got %v", err)
	}
	if _, statErr := os.Lstat(unpinned); !os.IsNotExist(statErr) {
		t.Fatalf("nothing may be created without the gateway identity: %v", statErr)
	}
}
