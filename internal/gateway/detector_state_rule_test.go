// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104DetectorStateWriteRequiresResolvedTarget(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	stateDir := filepath.Join(home, ".defenseclaw")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(stateDir, "config.yaml")
	if err := os.WriteFile(state, []byte("guardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	tests := []struct {
		name, command string
		block         bool
	}{
		{"active state", `printf marker >> ` + state, true},
		{"project file", `printf marker >> report.txt`, false},
		{"state path as data", `printf '%s\n' '` + state + `' > report.txt`, false},
	}
	dialect := actionfacts.DialectPOSIX
	if runtime.GOOS == "windows" {
		dialect = actionfacts.DialectPowerShell
		tests = []struct {
			name, command string
			block         bool
		}{
			{"active state", `Add-Content -LiteralPath '` + state + `' -Value marker`, true},
			{"project file", `Add-Content -LiteralPath report.txt -Value marker`, false},
			{"state path as data", `Set-Content -LiteralPath report.txt -Value '` + state + `'`, false},
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home,
				DialectHint: dialect}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: true,
			})
			finding := findingWithID(findings, "tamper.detector_state_write")
			if got := finding != nil && finding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("tamper enforcement=%t, want %t; finding=%+v", got, tc.block, finding)
			}
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tc.block {
				t.Fatalf("tamper verdict block=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
		})
	}
}
