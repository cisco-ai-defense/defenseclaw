// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0344: the Windows installer pins the guardian, the
// enumerator and the gateway services to <state root>\hook-guardian-state
// (DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR), the standalone layout's
// GuardianAuthDir, which the account join keys read from an elevated shell.
func TestWindowsInstallerPinsTheLayoutGuardianFolder(t *testing.T) {
	layout, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(layout.GuardianAuthDir, `\hook-guardian-state`) {
		t.Fatalf("layout guardian folder %s", layout.GuardianAuthDir)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		`"DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$AuthorizationDirectory"`,
		`AuthorizationDirectory = (Microsoft.PowerShell.Management\Join-Path $StateRoot 'hook-guardian-state')`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the installer no longer has %s", want)
		}
	}
}
