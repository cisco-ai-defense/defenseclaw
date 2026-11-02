// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestResolveDefaultEnvConfigPathUsesTrustedProgramData(t *testing.T) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatalf("resolve trusted ProgramData: %v", err)
	}
	got, err := ResolveDefaultEnvConfigPath()
	if err != nil {
		t.Fatalf("resolve managed env_config path: %v", err)
	}
	want := filepath.Join(
		programData,
		"Cisco",
		"Cisco Secure Client",
		"DefenseClaw",
		"env_config.json",
	)
	if got != want {
		t.Fatalf("managed env_config path = %q, want %q", got, want)
	}
}

// AVC owns env_config.json; permission drift on it (here: a test user owns
// the file) is accepted and logged so a region change still takes effect.
// Structure and strict mode stay fatal.
func TestOpenEnvConfigAcceptsPermissionDrift(t *testing.T) {
	t.Setenv("DEFENSECLAW_ENV_CONFIG_SKIP_TRUST", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "env_config.json")
	if err := os.WriteFile(path, []byte(`{"endpoint":"https://example.invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if managed.ValidateTrustedFilePath(path, "env_config") == nil {
		t.Skip("temp file already passes the strict check; no drift to accept")
	}
	file, err := openEnvConfig(path)
	if err != nil {
		t.Fatalf("drifted env_config was refused: %v", err)
	}
	_ = file.Close()

	if _, err := openEnvConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing env_config was accepted")
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if file, err := openEnvConfig(path); err == nil {
		_ = file.Close()
		t.Fatal("strict pin accepted a drifted env_config")
	}
}

func TestManagedEnvConfigTrustDoesNotDependOnElevation(t *testing.T) {
	t.Setenv("DEFENSECLAW_ENV_CONFIG_SKIP_TRUST", "")
	if !shouldEnforceEnvConfigTrust() {
		t.Fatal("managed env_config trust was disabled for a production caller")
	}
	t.Setenv("DEFENSECLAW_ENV_CONFIG_SKIP_TRUST", "1")
	if shouldEnforceEnvConfigTrust() {
		t.Fatal("parser-test trust waiver was ignored")
	}
}
