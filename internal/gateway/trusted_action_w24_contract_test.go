// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A parse gap cannot decide an action. The original action remains in the
// ordinary policy and protected-write passes; each proved child adds findings.
func TestTrustedActionW24AdditiveContract(t *testing.T) {
	const connector = "w24-additive-contract-test"
	installDefaultProfileConnector(t, connector)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(cwd, "build"), filepath.Join(cwd, "out"),
		filepath.Join(cwd, "logs"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "report.txt"), []byte("sample.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "race.txt"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, command, rule string
		dialect             actionfacts.Dialect
		block               bool
	}{
		{"login shell benign", `bash -lc 'printf ok > logs/bash-child.log'`, "", actionfacts.DialectPOSIX, false},
		{"login shell inner rule", `bash -lc 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"login shell single inner rule", `bash -lc 'rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"env reset benign", `env -i PATH=/usr/bin:/bin sh -c 'printf ok > out/clean.txt'`, "", actionfacts.DialectPOSIX, false},
		{"env reset inner rule", `env -i PATH=/usr/bin:/bin sh -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"env chdir benign", `env --chdir=. sh -c 'printf ok > out/child.txt'`, "", actionfacts.DialectPOSIX, false},
		{"full path env inner rule", `/usr/bin/env sh -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"full path sudo inner rule", `/usr/bin/sudo sh -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"full path shell inner rule", `/bin/bash -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"named shell option", `bash -o pipefail -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"dash inner rule", `dash -c 'true; rm -rf /'`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"trap ordinary write", `trap 'printf done >> logs/cleanup.log' EXIT; cp payload out/job-input`, "", actionfacts.DialectPOSIX, false},
		{"trap dangerous body", `trap 'true; rm -rf /' EXIT; echo done`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"export function", `f() { rm -rf /; }; export -f f; bash -c f`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"declare export function", `f() { rm -rf /; }; declare -fx f; bash -c f`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"typeset export function", `f() { rm -rf /; }; typeset -fx f; bash -c f`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"declare trap function", `f() { rm -rf /; }; declare -fx f; trap f EXIT`, "CMD-RM-RF", actionfacts.DialectPOSIX, true},
		{"builtin directory inner rule", `builtin cd ` + home + `; cat .ssh/id_rsa`, "PATH-SSH-KEY", actionfacts.DialectPOSIX, true},
		{"command directory inner rule", `command cd ` + home + `; cat .ssh/id_rsa`, "PATH-SSH-KEY", actionfacts.DialectPOSIX, true},
		{"loop bound destination", `for f in build/item.txt; do echo ok >> "$f"; done`, "", actionfacts.DialectPOSIX, false},
		{"assignment bound destination", `out="$(mktemp -d)"; printf ok > "$out/probe.txt"`, "", actionfacts.DialectPOSIX, false},
		{"export bound destination", `export OUTPUT_DIR=out; printf ready > "$OUTPUT_DIR/status.txt"`, "", actionfacts.DialectPOSIX, false},
		{"printf bound destination", `printf -v f '%s' out/report.txt; echo ok >> "$f"`, "", actionfacts.DialectPOSIX, false},
		{"read bound destination", `read f < report.txt; printf ok > "out/$f"`, "", actionfacts.DialectPOSIX, false},
		{"function bound destination", `stage_file() { cp "$1" "build/$2"; }; stage_file payload staged.bin`, "", actionfacts.DialectPOSIX, false},
		{name: "conditional ordinary patch", dialect: actionfacts.DialectPOSIX,
			command: "if [ -f race.txt ]; then apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: race.txt\n@@\n+new\n*** End Patch\nPATCH\nelse\napply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: race.txt\n+new\n*** End Patch\nPATCH\nfi\nrg -n new race.txt"},
		{"PowerShell multiline inner rule", "Get-ChildItem |\n Remove-Item -Recurse -Force C:\\", "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"PowerShell group inner rule", `if ($true) { Write-Output a; Remove-Item -Recurse -Force C:\ }`, "CMD-RM-RF", actionfacts.DialectPowerShell, true},
		{"cmd group inner rule", `if exist x (echo a & rmdir /s /q C:\)`, "CMD-RM-RF", actionfacts.DialectCMD, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: tt.command, CWD: cwd,
				ActiveHome: home, DialectHint: tt.dialect}
			if tt.dialect != actionfacts.DialectPOSIX {
				input.CWD, input.ActiveHome = `C:\Users\alice\project`, `C:\Users\alice`
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tt.block {
				t.Errorf("block=%v, want %v: %v", got, tt.block, FindingStrings(findings))
			}
			if finding := findingWithID(findings, "ACTION-COMPOUND-UNPROVEN"); finding != nil &&
				finding.contributesToEnforcement() {
				t.Errorf("parse uncertainty refused action: %v", FindingStrings(findings))
			}
			if tt.rule != "" {
				finding := findingWithID(findings, tt.rule)
				if finding == nil || !finding.contributesToEnforcement() {
					t.Errorf("missing enforced %s: %v", tt.rule, FindingStrings(findings))
				}
			}
		})
	}
}

func TestTrustedActionW24StartupDirectoryAndBoundVariableLimits(t *testing.T) {
	const connector = "w24-startup-directory-test"
	installDefaultProfileConnector(t, connector)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, command, rule string
		block               bool
	}{
		{"login body relative private key read", `bash -lc 'cat .ssh/id_rsa'`, "PATH-SSH-KEY", true},
		{"login body home path", `bash -lc 'cat ~/.ssh/id_rsa'`, "PATH-SSH-KEY", true},
		{"use before later binding", `printf ok > "$f"; f=out/report.txt`, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: tt.command, CWD: home,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      input,
				LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			if got := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; got != tt.block {
				t.Errorf("block=%v, want %v: %v", got, tt.block, FindingStrings(findings))
			}
			if tt.rule != "" {
				finding := findingWithID(findings, tt.rule)
				if finding == nil || !finding.contributesToEnforcement() {
					t.Errorf("missing enforced %s: %v", tt.rule, FindingStrings(findings))
				}
			}
		})
	}
}

func TestTrustedActionW24ZshHistoryDoesNotInheritBashClearGrammar(t *testing.T) {
	const connector = "w24-zsh-history-test"
	installDefaultProfileConnector(t, connector)
	for _, tt := range []struct {
		name, command string
		wantFinding   bool
	}{
		{"zsh", `zsh -c 'history -c'`, false},
		{"full path zsh", `/bin/zsh -c 'history -c'`, false},
		{"wrapped zsh", `env zsh -c 'history -c'`, false},
		{"bash", `bash -c 'history -c'`, true},
		{"zsh unset HISTFILE", `zsh -c 'unset HISTFILE'`, true},
		{"nested bash in zsh", `zsh -c "bash -c 'history -c'"`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: tt.command,
				CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			got := findingWithID(findings, "integrity.history_tamper") != nil
			if got != tt.wantFinding {
				t.Errorf("history finding=%v, want %v: %v", got, tt.wantFinding, FindingStrings(findings))
			}
		})
	}
}
