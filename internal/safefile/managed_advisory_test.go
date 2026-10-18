//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"testing"
)

func withManagedModeAdvisory(t *testing.T, hook func(path, reason string) bool) {
	t.Helper()
	previous := ManagedModeAdvisory
	ManagedModeAdvisory = hook
	t.Cleanup(func() { ManagedModeAdvisory = previous })
}

func groupReadableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestValidatePrivateDirectoryModeVerdictIsFatalWithoutAdvisory(t *testing.T) {
	withManagedModeAdvisory(t, nil)
	if err := ValidatePrivateDirectory(groupReadableDir(t)); err == nil {
		t.Fatal("ValidatePrivateDirectory(0750) = nil, want a too-broad error")
	}
}

func TestValidatePrivateDirectoryModeVerdictFollowsManagedAdvisory(t *testing.T) {
	dir := groupReadableDir(t)
	var reported string
	withManagedModeAdvisory(t, func(path, _ string) bool { reported = path; return true })
	if err := ValidatePrivateDirectory(dir); err != nil {
		t.Fatalf("ValidatePrivateDirectory(0750) with the advisory = %v, want nil", err)
	}
	if reported != dir {
		t.Fatalf("advisory reported %q, want %q", reported, dir)
	}

	withManagedModeAdvisory(t, func(string, string) bool { return false })
	if err := ValidatePrivateDirectory(dir); err == nil {
		t.Fatal("ValidatePrivateDirectory(0750) with a declining advisory = nil, want an error")
	}
}

func TestValidatePrivateTypeVerdictNeverFollowsManagedAdvisory(t *testing.T) {
	withManagedModeAdvisory(t, func(string, string) bool { return true })
	file := groupReadableDir(t) + "/not-a-directory"
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateDirectory(file); err == nil {
		t.Fatal("ValidatePrivateDirectory(regular file) = nil, want a type error")
	}
}
