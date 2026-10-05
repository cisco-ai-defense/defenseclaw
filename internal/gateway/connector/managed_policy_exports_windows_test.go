// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"slices"
	"testing"
)

// A Devin hook process runs the administrator's launcher, not the installed
// gateway, so it cannot resolve that launcher for itself. The foreign-hook
// guard must still own the per-user command the guardian registered for it,
// or every Devin prompt is blocked by DefenseClaw's own hook.
func TestPerUserOwnedHookCommandsOwnTheAdministratorLauncherForDevin(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	admin := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	registered := windowsDevinBashHookCommand(admin)
	if slices.Contains(PerUserOwnedHookCommands("devin", dataDir), registered) {
		t.Fatalf("precondition: the test process must not resolve the administrator launcher")
	}
	if owned := PerUserOwnedHookCommandsForBinary("devin", dataDir, admin); !slices.Contains(owned, registered) {
		t.Fatalf("registered Devin command %q is not owned; owned = %q", registered, owned)
	}
}
