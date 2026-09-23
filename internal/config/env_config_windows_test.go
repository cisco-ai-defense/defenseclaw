// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"path/filepath"
	"testing"

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
