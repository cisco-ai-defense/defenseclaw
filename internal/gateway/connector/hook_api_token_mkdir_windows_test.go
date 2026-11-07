// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const mkdirTestAccount = `NT SERVICE\DefenseClawGateway`

// pinMkdirTest pins the process the way a managed service environment does
// and returns the data directory the hooks folder belongs in.
func pinMkdirTest(t *testing.T, profile string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, profile)
	t.Setenv(managed.WindowsServiceAccountEnv, mkdirTestAccount)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(home, "etc", "config.yaml"))
	return home
}

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

// requireCanonicalHooksDirectory skips when the test token cannot own the
// directory as Administrators (the creator then removes it and says so).
func requireCanonicalHooksDirectory(t *testing.T, path string, err error) {
	t.Helper()
	if errors.Is(err, managed.ErrCanonicalOwnerUnavailable) {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("a refused owner must not leave the folder behind: %v", statErr)
		}
		t.Skipf("the test token cannot own the folder as Administrators: %v", err)
	}
	if err != nil {
		t.Fatalf("create hooks folder: %v", err)
	}
	if result := assessHooksDirectory(t, path); result.Outcome != managed.CanonicalOK {
		t.Fatalf("the hooks folder must be canonical from creation, got %s: %v", result.Outcome, result.Drift)
	}
}

// GAP-0762: in a standalone managed deployment the hooks folder is created in
// the Guardian canonical protection, so a fresh install has nothing to repair.
func TestMkdirHookAPITokenDirStandaloneIsCanonicalFromCreation(t *testing.T) {
	path := filepath.Join(pinMkdirTest(t, managed.ProfileStandalone), "hooks")
	requireCanonicalHooksDirectory(t, path, mkdirHookAPITokenDir(path))
}

// The OTLP token paths create the same folder through the same creator, in
// either order with the hook token.
func TestEnsureHookAPITokenDirIsCanonicalWhenOTLPRunsFirst(t *testing.T) {
	home := pinMkdirTest(t, managed.ProfileStandalone)
	path := filepath.Join(home, "hooks")
	requireCanonicalHooksDirectory(t, path, ensureHookAPITokenDir(path))
	if err := ensureHookAPITokenDir(path); err != nil {
		t.Fatalf("an existing folder is left for the trust check: %v", err)
	}
}

// Secure Client behaviour stays unchanged: its folder is the ordinary
// directory it always was.
func TestMkdirHookAPITokenDirSecureClientStaysOrdinary(t *testing.T) {
	path := filepath.Join(pinMkdirTest(t, managed.ProfileSecureClient), "hooks")
	if err := mkdirHookAPITokenDir(path); err != nil {
		t.Fatalf("mkdirHookAPITokenDir: %v", err)
	}
	if !strings.Contains(strings.Join(assessHooksDirectory(t, path).Drift, "; "), "inherits") {
		t.Fatal("a Secure Client hooks folder must keep the inherited protection")
	}
}

// Benign twin: a per-user hooks folder, in a managed process or not, stays an
// ordinary directory its owner can reach.
func TestMkdirHookAPITokenDirPerUserStaysOrdinary(t *testing.T) {
	pinMkdirTest(t, managed.ProfileStandalone)
	perUser := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
	if err := os.MkdirAll(filepath.Dir(perUser), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := mkdirHookAPITokenDir(perUser); err != nil {
		t.Fatalf("mkdirHookAPITokenDir: %v", err)
	}
	if !strings.Contains(strings.Join(assessHooksDirectory(t, perUser).Drift, "; "), "inherits") {
		t.Fatal("a per-user hooks folder must keep the owner inherited protection")
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	unmanaged := filepath.Join(t.TempDir(), "hooks")
	if err := mkdirHookAPITokenDir(unmanaged); err != nil {
		t.Fatalf("mkdirHookAPITokenDir: %v", err)
	}
}

// A managed standalone account that cannot be resolved fails the creation and
// leaves no inheriting folder behind.
func TestMkdirHookAPITokenDirUnresolvedAccountLeavesNothing(t *testing.T) {
	home := pinMkdirTest(t, managed.ProfileStandalone)
	t.Setenv(managed.WindowsServiceAccountEnv, `DOMAIN\not-a-service-account`)
	path := filepath.Join(home, "hooks")
	if err := mkdirHookAPITokenDir(path); err == nil {
		t.Fatal("an unresolvable gateway account must fail the creation")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("no folder may be left behind: %v", err)
	}
}

// GAP-0762: an OTLP-first start must not create the data directory above the
// hooks folder in a standalone managed tree; the Guardian keeps it canonical,
// and a plain mkdir would hand it the inherited protection to repair.
func TestEnsureHookAPITokenDirStandaloneCreatesNoParent(t *testing.T) {
	home := pinMkdirTest(t, managed.ProfileStandalone)
	parent := filepath.Join(home, "missing-runtime")
	err := ensureHookAPITokenDir(filepath.Join(parent, "hooks"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing managed parent must be reported, got %v", err)
	}
	if _, statErr := os.Lstat(parent); !os.IsNotExist(statErr) {
		t.Fatalf("no parent may be created: %v", statErr)
	}
}

// Benign twin: the Secure Client and per-user paths keep the ordinary
// MkdirAll of the parent.
func TestEnsureHookAPITokenDirOrdinaryPathsStillMakeTheParent(t *testing.T) {
	home := pinMkdirTest(t, managed.ProfileSecureClient)
	path := filepath.Join(home, "missing-runtime", "hooks")
	if err := ensureHookAPITokenDir(path); err != nil {
		t.Fatalf("Secure Client: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	perUser := filepath.Join(t.TempDir(), "a", "b", "hooks")
	if err := ensureHookAPITokenDir(perUser); err != nil {
		t.Fatalf("per-user: %v", err)
	}
}
