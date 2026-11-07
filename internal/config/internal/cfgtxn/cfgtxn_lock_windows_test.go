// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cfgtxn

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const lockTestAccount = `NT SERVICE\DefenseClawGateway`

// GAP-0766: the lock beside the managed config is created in the canonical
// protection, so no account but the administrators and the service can hold
// it, and the Guardian has nothing to repair.
func TestOpenLockFileInStandaloneManagedTreeIsCanonical(t *testing.T) {
	home := t.TempDir()
	etc := filepath.Join(home, "etc")
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv(managed.WindowsServiceAccountEnv, lockTestAccount)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(etc, "config.yaml"))
	lockPath := LockPath(filepath.Join(etc, "config.yaml"))
	f, err := openLockFile(lockPath)
	if errors.Is(err, managed.ErrCanonicalOwnerUnavailable) {
		t.Skipf("the test token cannot own the lock as Administrators: %v", err)
	}
	if err != nil {
		t.Fatalf("openLockFile: %v", err)
	}
	_ = f.Close()
	result, err := managed.AssessCanonical(lockPath, managed.ObjectConfigFile, managed.CanonicalOptions{GatewayServiceAccount: lockTestAccount, Quiet: true})
	if err != nil || result.Outcome != managed.CanonicalOK {
		t.Fatalf("the config lock must be canonical from creation, got %s %v: %v", result.Outcome, err, result.Drift)
	}
}

// Benign twin: outside a managed deployment the lock is the ordinary file the
// per-user CLI has always used.
func TestOpenLockFileUnmanagedStaysOrdinary(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	lockPath := LockPath(filepath.Join(t.TempDir(), "config.yaml"))
	f, err := openLockFile(lockPath)
	if err != nil {
		t.Fatalf("openLockFile: %v", err)
	}
	_ = f.Close()
}

// GAP-0766: the runtime directory's .env lock is created canonical as a
// runtime file, the kind the Guardian, Setup repair and verify judge it by,
// not as a config file.
func TestOpenLockFileForDotEnvIsCanonicalRuntimeFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	t.Setenv(managed.WindowsServiceAccountEnv, lockTestAccount)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(home, "etc", "config.yaml"))
	lockPath := LockPath(filepath.Join(home, ".env"))
	f, err := openLockFile(lockPath)
	if errors.Is(err, managed.ErrCanonicalOwnerUnavailable) {
		t.Skipf("the test token cannot own the lock as Administrators: %v", err)
	}
	if err != nil {
		t.Fatalf("openLockFile: %v", err)
	}
	_ = f.Close()
	result, err := managed.AssessCanonical(lockPath, managed.ObjectRuntimeFile, managed.CanonicalOptions{GatewayServiceAccount: lockTestAccount, Quiet: true})
	if err != nil || result.Outcome != managed.CanonicalOK {
		t.Fatalf("the .env lock must be a canonical runtime file from creation, got %s %v: %v", result.Outcome, err, result.Drift)
	}
}
