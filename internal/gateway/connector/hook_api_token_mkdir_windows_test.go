// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const mkdirTestAccount = `NT SERVICE\DefenseClawGateway`

func assessHooksDirectory(t *testing.T, path string) managed.CanonicalResult {
	t.Helper()
	result, err := managed.AssessCanonical(path, managed.ObjectRuntimeDirectory, managed.CanonicalOptions{
		GatewayServiceAccount: mkdirTestAccount,
		Quiet:                 true,
	})
	if err != nil {
		t.Fatalf("AssessCanonical: %v", err)
	}
	return result
}

// GAP-0762: under a managed deployment the hooks folder is created in the
// Guardian canonical protection, so a fresh install has nothing to repair.
func TestMkdirHookAPITokenDirManagedIsProtectedFromCreation(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
	t.Setenv(managed.WindowsServiceAccountEnv, mkdirTestAccount)
	path := filepath.Join(t.TempDir(), "hooks")
	if err := mkdirHookAPITokenDir(path); err != nil {
		t.Fatalf("mkdirHookAPITokenDir: %v", err)
	}
	result := assessHooksDirectory(t, path)
	if strings.Contains(strings.Join(result.Drift, "; "), "inherits") {
		t.Fatalf("the hooks folder must be created protected, got %s: %v", result.Outcome, result.Drift)
	}
	if result.GatewayAccessMissing {
		t.Fatalf("the gateway service must hold its write entry from creation: %v", result.Drift)
	}
}

// Benign twin: a per-user (unmanaged) install keeps an ordinary directory, so
// the owner of the home still reaches it.
func TestMkdirHookAPITokenDirUnmanagedStaysOrdinary(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.WindowsServiceAccountEnv, "")
	path := filepath.Join(t.TempDir(), "hooks")
	if err := mkdirHookAPITokenDir(path); err != nil {
		t.Fatalf("mkdirHookAPITokenDir: %v", err)
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		t.Fatalf("hooks folder missing: %v", err)
	}
	if !strings.Contains(strings.Join(assessHooksDirectory(t, path).Drift, "; "), "inherits") {
		t.Fatal("an unmanaged hooks folder must keep the owner inherited protection")
	}
}
