//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1733PreflightRefusesOnlyWhenEveryTargetIsRefused: the standalone
// first-install preflight no longer fails every user for one user's per-user
// install folder; the install plan skips that user. It still refuses when
// it would enrol nobody, and on the first refusal in strict mode.
func TestGAP1733PreflightRefusesOnlyWhenEveryTargetIsRefused(t *testing.T) {
	bad := errors.New("enterprise hooks: reject noncanonical managed runtime baseline: C:\\Users\\u2\\.defenseclaw holds config.yaml")
	other := errors.New("enterprise hooks: reject noncanonical managed runtime baseline: C:\\Users\\u3\\.defenseclaw")
	for _, tc := range []struct {
		name     string
		refusals []error
		strict   bool
		want     error
	}{
		{"one user of two", []error{nil, bad}, false, nil},
		{"every user", []error{bad, other}, false, bad},
		{"the only user", []error{bad}, false, bad},
		{"nobody refused", []error{nil, nil}, false, nil},
		{"no targets", nil, false, nil},
		{"strict, one user of two", []error{nil, bad}, true, bad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsManagedRuntimePreflightVerdict(tc.refusals, tc.strict); got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGAP1733PreflightOfTheOnlyPerUserInstallUserStillRefuses: a machine
// whose only target holds a per-user install keeps the early refusal with
// the folder named (GAP-0741), on the standalone profile.
func TestGAP1733PreflightOfTheOnlyPerUserInstallUserStillRefuses(t *testing.T) {
	requireElevatedManagedWindows(t)
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	target := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, filepath.Join(dataDir, "hooks"), target); err != nil {
		t.Fatal(err)
	}
	manifest := windowsManagedRuntimeTestManifest(home, target)
	if err := PreflightWindowsManagedRuntimeRoots(manifest); err != nil {
		t.Fatalf("preflight of a canonical managed folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightWindowsManagedRuntimeRoots(manifest); err == nil || !strings.Contains(err.Error(), dataDir+" holds config.yaml") {
		t.Fatalf("preflight of the only target's per-user install folder = %v, want the refusal", err)
	}
}
