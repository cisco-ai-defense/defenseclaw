// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cfgtxn

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

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
	if refusedOwnerLeftNothing(t, lockPath, err) {
		return
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

// refusedOwnerLeftNothing reports a creation refused because the token cannot
// assign the Administrators owner, after checking the refusal kept its
// contract: only a standard user's (Limited) token is refused, and the lock
// file is removed again. Those runs used to skip, and a lock file the refusal
// left behind went unseen (GAP-2150).
func refusedOwnerLeftNothing(t *testing.T, lockPath string, err error) bool {
	t.Helper()
	if !errors.Is(err, managed.ErrCanonicalOwnerUnavailable) {
		return false
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("an elevated token must own the lock as Administrators: %v", err)
	}
	if _, statErr := os.Lstat(lockPath); !os.IsNotExist(statErr) {
		t.Fatalf("a refused owner must not leave the lock file behind: %v", statErr)
	}
	return true
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
	if refusedOwnerLeftNothing(t, lockPath, err) {
		return
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
