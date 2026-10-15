// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The hook process resolves the standalone binding from the protected
// Program Files root, not its environment.
func TestWindowsCodexStandaloneHookContractResolvesTheProtectedLayout(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		t.Skipf("no trusted Program Files root: %v", err)
	}
	t.Setenv("ProgramFiles", `D:\Elsewhere`)
	t.Setenv(managed.EnterpriseProfileEnv, "")
	want := ResolveHookContract("codex", "").Contract.ContractID
	if got := WindowsCodexStandaloneHookContract(filepath.Join(layout.BinDir, "defenseclaw-hook.exe")); got != want {
		t.Fatalf("standalone launcher contract = %q, want %q", got, want)
	}
	secureClient := filepath.Join(filepath.Dir(filepath.Dir(layout.InstallRoot)), "Cisco", "Cisco Secure Client", "DefenseClaw", "bin", "defenseclaw-hook.exe")
	if got := WindowsCodexStandaloneHookContract(secureClient); got != "" {
		t.Fatalf("Secure Client launcher selected contract %q", got)
	}
	// Both profiles' requirements bind a contract, so every published Codex
	// command names its event and waits for the launcher.
	if got := WindowsCodexManagedHookContract(secureClient); got != want {
		t.Fatalf("Secure Client managed contract = %q, want %q", got, want)
	}
	if got := WindowsCodexManagedHookContract(filepath.Join(layout.BinDir, "defenseclaw-hook.exe")); got != want {
		t.Fatalf("standalone managed contract = %q, want %q", got, want)
	}
}
