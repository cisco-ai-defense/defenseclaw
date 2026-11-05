//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func pinSecureClientTokenTest(t *testing.T) {
	t.Helper()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileSecureClient)
}

func writeHookTokenForTest(t *testing.T, mode os.FileMode) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := HookAPITokenFilePath(dir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func TestDarwinTokenAcceptsTighterMode(t *testing.T) {
	dir, _ := writeHookTokenForTest(t, 0o400)
	token, err := LoadHookAPIToken(dir, "codex")
	if err != nil || token != strings.Repeat("a", 64) {
		t.Fatalf("a 0400 token was refused: %q %v", token, err)
	}
}

// A looser token is refused, but as permission drift, so the gateway keeps
// its cached token instead of rejecting every hook request.
func TestDarwinTokenModeDriftIsManagedPermissionDrift(t *testing.T) {
	pinSecureClientTokenTest(t)
	for _, mode := range []os.FileMode{0o640, 0o644, 0o660} {
		dir, _ := writeHookTokenForTest(t, mode)
		_, err := LoadHookAPIToken(dir, "codex")
		if err == nil {
			t.Fatalf("mode %04o accepted", mode)
		}
		if !IsManagedPermissionDrift(err) {
			t.Fatalf("mode %04o error is not drift: %v", mode, err)
		}
	}
}

func TestDarwinTokenFolderModeDriftIsManagedPermissionDrift(t *testing.T) {
	pinSecureClientTokenTest(t)
	dir, _ := writeHookTokenForTest(t, 0o600)
	if err := os.Chmod(filepath.Join(dir, "hooks"), 0o770); err != nil {
		t.Fatal(err)
	}
	_, err := LoadHookAPIToken(dir, "codex")
	if err == nil || !IsManagedPermissionDrift(err) {
		t.Fatalf("hooks folder drift error = %v, want permission drift", err)
	}
}

func TestDarwinTokenStructureIsNeverDrift(t *testing.T) {
	dir, path := writeHookTokenForTest(t, 0o600)
	target := path + ".target"
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	_, err := LoadHookAPIToken(dir, "codex")
	if err == nil || IsManagedPermissionDrift(err) {
		t.Fatalf("symlinked token error = %v, want a structural failure", err)
	}
}

func TestDarwinTokenOwnerVerdictIsDrift(t *testing.T) {
	pinSecureClientTokenTest(t)
	if err := tokenPermissionVerdict(os.ErrPermission); !IsManagedPermissionDrift(err) {
		t.Fatalf("owner verdict not marked as drift: %v", err)
	}
	if tokenPermissionVerdict(nil) != nil {
		t.Fatal("nil verdict became an error")
	}
}

func TestR108MAINREVP3PerUserTokenPermissionRefused(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	dir, path := writeHookTokenForTest(t, 0o640)
	if _, err := LoadHookAPIToken(dir, "codex"); err == nil || IsManagedPermissionDrift(err) {
		t.Fatalf("per-user hook token mode verdict = %v, want plain refusal", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "hooks"), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHookAPIToken(dir, "codex"); err == nil || IsManagedPermissionDrift(err) {
		t.Fatalf("per-user hook folder verdict = %v, want plain refusal", err)
	}
	if err := tokenPermissionVerdict(os.ErrPermission); IsManagedPermissionDrift(err) {
		t.Fatalf("per-user owner verdict = %v, want plain refusal", err)
	}
}

func TestR108MAINREVP3PerUserOTLPTokenPermissionRefused(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	dir := t.TempDir()
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err == nil || IsManagedPermissionDrift(err) {
		t.Fatalf("per-user OTLP token verdict = %v, want plain refusal", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err != nil || token != strings.Repeat("a", 64) {
		t.Fatalf("per-user private OTLP token = %q, %v", token, err)
	}
}

func TestR108MAINREVP3SecureClientTokenDriftTwin(t *testing.T) {
	pinSecureClientTokenTest(t)
	dir, _ := writeHookTokenForTest(t, 0o640)
	if _, err := LoadHookAPIToken(dir, "codex"); err == nil || !IsManagedPermissionDrift(err) {
		t.Fatalf("Secure Client hook token verdict = %v, want managed drift", err)
	}
}

func TestR108MAINREVP3SecureClientDefaultProfileTokenDrift(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, "")
	dir, _ := writeHookTokenForTest(t, 0o640)
	if _, err := LoadHookAPIToken(dir, "codex"); err == nil || !IsManagedPermissionDrift(err) {
		t.Fatalf("default Secure Client token verdict = %v, want managed drift", err)
	}
}

func TestR108MAINREVP3StandaloneTokenPermissionRefused(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	dir, _ := writeHookTokenForTest(t, 0o640)
	if _, err := LoadHookAPIToken(dir, "codex"); err == nil || IsManagedPermissionDrift(err) {
		t.Fatalf("standalone token verdict = %v, want plain refusal", err)
	}
}
