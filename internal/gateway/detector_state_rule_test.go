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
		// The action target-mention ruling classifies a named active target
		// independently of this command's output operand.
		{"state path as data", `printf '%s\n' '` + state + `' > report.txt`, true},
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
			{"state path as data", `Set-Content -LiteralPath report.txt -Value '` + state + `'`, true},
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

func TestR104ActiveStateMentionUsesStateFinding(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	installDefaultProfileConnector(t, "claudecode")
	dialect := actionfacts.DialectPOSIX
	active := "echo " + state
	readOnly := "cat " + state
	project := "echo " + filepath.Join(cwd, ".defenseclaw", "config.yaml")
	if runtime.GOOS == "windows" {
		dialect = actionfacts.DialectPowerShell
		active = "Write-Output " + state
		readOnly = "Get-Content " + state
		project = "Write-Output " + filepath.Join(cwd, ".defenseclaw", "config.yaml")
	}
	for _, tc := range []struct {
		name, command string
		enforce       bool
		block         bool
	}{
		{"action active", active, true, true},
		{"observe active", active, false, false},
		{"action read only", readOnly, true, false},
		{"action project state", project, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd,
				ActiveHome: home, DialectHint: dialect}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: tc.enforce,
			})
			stateFinding := findingWithID(findings, "tamper.detector_state_write")
			if got := stateFinding != nil && stateFinding.contributesToEnforcement(); got != tc.block {
				t.Fatalf("state enforcement=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
			sshFinding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if sshFinding != nil && sshFinding.contributesToEnforcement() {
				t.Fatalf("state command received SSH enforcement: %v", FindingStrings(findings))
			}
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tc.block {
				t.Fatalf("block=%t, want %t; findings=%v", got, tc.block, FindingStrings(findings))
			}
		})
	}
}
