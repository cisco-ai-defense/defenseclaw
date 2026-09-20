// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexGenericWindowsShellStaticReaderScope(t *testing.T) {
	repoRoot := t.TempDir()
	fixturePath := filepath.Join(repoRoot, "tests", "fixture.ps1")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, command := range []string{
		`Get-Content -LiteralPath .\tests\fixture.ps1`,
		`gc .\tests\fixture.ps1`,
		`type .\tests\fixture.ps1`,
		`Select-String -Pattern fixture -Path .\tests\fixture.ps1`,
	} {
		t.Run(command, func(t *testing.T) {
			got := codexToolResultContentScope(codexHookRequest{
				ToolName:  "exec_command",
				ToolInput: map[string]interface{}{"command": command},
				CWD:       repoRoot,
			})
			if got != ruleContentScopeSource {
				t.Fatalf("scope = %v, want source for %q", got, command)
			}
		})
	}

	for _, command := range []string{
		`Get-Content .\tests\fixture.ps1; Write-Output synthetic-secret`,
		`type .\tests\fixture.ps1 & echo synthetic-secret`,
		`Get-Content $fixturePath`,
		`Get-Content .\tests\fixture.ps1 > .\tests\copy.ps1`,
	} {
		t.Run("untrusted "+command, func(t *testing.T) {
			got := codexToolResultContentScope(codexHookRequest{
				ToolName:  "exec_command",
				ToolInput: map[string]interface{}{"command": command},
				CWD:       repoRoot,
			})
			if got != ruleContentScopeUntrusted {
				t.Fatalf("scope = %v, want untrusted for %q", got, command)
			}
		})
	}
}
