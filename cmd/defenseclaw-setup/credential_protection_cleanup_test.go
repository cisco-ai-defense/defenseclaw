// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCredentialCleanupRunsVerifiedMaintenanceRuntimeBeforeRelease(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	transaction := setupTransaction{ID: "cleanup-transaction", DataRoot: dataRoot}
	steps := []string{}
	err := cleanupCredentialProtectionWithMaintenance(
		transaction,
		func(got setupTransaction) (credentialCleanupRuntime, error) {
			if got.ID != transaction.ID {
				t.Fatalf("cleanup transaction = %q, want %q", got.ID, transaction.ID)
			}
			steps = append(steps, "provide")
			return credentialCleanupRuntime{
				root: filepath.Join(t.TempDir(), "verified-runtime"),
				cleanup: func() {
					steps = append(steps, "release")
				},
			}, nil
		},
		func(runtime credentialCleanupRuntime, got setupTransaction) error {
			if runtime.root == "" || got.ID != transaction.ID {
				t.Fatal("cleanup command did not receive the verified runtime and transaction")
			}
			steps = append(steps, "remove")
			return nil
		},
	)
	if err != nil {
		t.Fatalf("cleanup credential protection: %v", err)
	}
	if !slices.Equal(steps, []string{"provide", "remove", "release"}) {
		t.Fatalf("cleanup steps = %v", steps)
	}
}

func TestCredentialCleanupFailureStillReleasesMaintenanceRuntime(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	released := false
	want := errors.New("injected cleanup failure")
	err := cleanupCredentialProtectionWithMaintenance(
		setupTransaction{DataRoot: dataRoot},
		func(setupTransaction) (credentialCleanupRuntime, error) {
			return credentialCleanupRuntime{
				root: "verified-runtime",
				cleanup: func() {
					released = true
				},
			}, nil
		},
		func(credentialCleanupRuntime, setupTransaction) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("cleanup error = %v, want %v", err, want)
	}
	if !released {
		t.Fatal("maintenance runtime was not released after cleanup failure")
	}
}

func TestCredentialCleanupSkipsMissingDataRoot(t *testing.T) {
	called := false
	err := cleanupCredentialProtectionWithMaintenance(
		setupTransaction{DataRoot: filepath.Join(t.TempDir(), "missing")},
		func(setupTransaction) (credentialCleanupRuntime, error) {
			called = true
			return credentialCleanupRuntime{}, nil
		},
		func(credentialCleanupRuntime, setupTransaction) error {
			called = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("missing data root cleanup: %v", err)
	}
	if called {
		t.Fatal("missing data root prepared a maintenance runtime")
	}
}
