// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1733 review (live k2c, TST-11933): without the service pins, the
// protection ledger of the Windows standalone layout resolved to
// <DataDir>-hook-guardian, a folder the guardian never writes, instead of
// ProgramData\Cisco\DefenseClaw\hook-guardian-state. Every ledger reader
// resolves it here, with no stub of the layout.
func TestGAP1733HookGuardianLedgerOfTheWindowsLayoutDataDirIsTheLayoutFolder(t *testing.T) {
	t.Setenv(HookGuardianAuthorizationDirEnv, "")
	layout, err := StandaloneWindowsLayout()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(layout.GuardianAuthDir, HookGuardianAuthorizationFile)
	for _, dataDir := range []string{layout.DataDir, strings.ToUpper(layout.DataDir), layout.DataDir + `\`} {
		if got := HookGuardianAuthorizationPath(dataDir); !strings.EqualFold(got, want) {
			t.Fatalf("ledger of %s = %s, want %s", dataDir, got, want)
		}
	}
	other := filepath.Join(t.TempDir(), "runtime")
	if got := HookGuardianAuthorizationDir(other); got != other+"-hook-guardian" {
		t.Fatalf("authorization folder of a non-layout data folder = %s, want %s-hook-guardian", got, other)
	}
	override := filepath.Join(t.TempDir(), "authorization")
	t.Setenv(HookGuardianAuthorizationDirEnv, override)
	if got := HookGuardianAuthorizationDir(layout.DataDir); got != override {
		t.Fatalf("with the override set, authorization folder = %s, want %s", got, override)
	}
}
