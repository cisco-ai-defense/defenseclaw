// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func requireNativePOSIXArtifactHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("native Windows paths do not have one authoritative POSIX shell mapping")
	}
}

func TestPromotedArtifactFindingsBlocksOnlyAuthoritativeFinalBytes(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-promotion-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	tests := []struct {
		name        string
		body        string
		wantRule    string
		enforceable bool
	}{
		{name: "destructive", body: "#!/bin/sh\nrm -rf /\n", wantRule: "CMD-RM-RF", enforceable: true},
		{name: "benign", body: "#!/bin/sh\nprintf '%s\\n' build-complete\n"},
		{
			// A list or subshell in the script is judged as the same
			// commands in the tool call would be.
			name: "list is enforced",
			body: "#!/bin/sh\nfalse && rm -rf /\n", wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			name: "subshell is enforced",
			body: "#!/bin/sh\n(rm -rf /)\n", wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			name: "redirected group is enforced",
			body: "#!/bin/sh\n{ rm -rf /; } 2>/dev/null\n", wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			// An exit in a subshell ends only the subshell.
			name: "exit in a subshell leaves later command reachable",
			body: "#!/bin/sh\n(exit 0)\nrm -rf /\n", wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			name: "exit makes later command unreachable",
			body: "#!/bin/sh\nexit 0\nrm -rf /\n", wantRule: "CMD-RM-RF",
		},
		{
			name: "exec makes later command unreachable",
			body: "#!/bin/sh\nexec true\nrm -rf /\n", wantRule: "CMD-RM-RF",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".sh")
			if err := os.WriteFile(path, []byte(test.body), 0o700); err != nil {
				t.Fatal(err)
			}
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true, nil)
			var matched *RuleFinding
			for index := range findings {
				if findings[index].RuleID == test.wantRule {
					matched = &findings[index]
					break
				}
			}
			if test.wantRule == "" {
				if len(findings) != 0 {
					t.Fatalf("benign final bytes produced findings: %v", FindingStrings(findings))
				}
				return
			}
			if matched == nil {
				t.Fatalf("missing %s: %v facts=%+v", test.wantRule, FindingStrings(findings), facts)
			}
			if got := matched.contributesToEnforcement(); got != test.enforceable {
				t.Fatalf(
					"enforceable=%t want %t: %+v outer=%+v projected=%+v",
					got,
					test.enforceable,
					*matched,
					facts,
					facts.EnforcementProjection(),
				)
			}
		})
	}

	t.Run("parser uncertainty telemetry", func(t *testing.T) {
		path := filepath.Join(dir, "parser-uncertainty.sh")
		body := []byte("#!/bin/sh\n\"$RUNNER\" -c 'rm -rf /'\n")
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
		})
		var telemetry trustedActionTelemetry
		promotedArtifactFindings(t.Context(), agentHookRequest{
			ConnectorName: connectorName,
		}, facts, true, func(observation trustedActionTelemetry) {
			telemetry.merge(observation)
		})
		if telemetry.ParserUncertaintyCount == 0 {
			t.Fatalf("artifact parser uncertainty telemetry = %+v", telemetry)
		}
	})
}

// GAP-1513: a migrated 0.8.x literal rule blocks a script the call runs only
// when an executed command of the script carries the literal; the literal in
// a comment of the script does not block it.
// installMigratedLiteralConnector gives connectorName a rule pack with one
// migrated 0.8.x literal rule, ACME-OWN-MARKER (acme.own-7f3c).
func installMigratedLiteralConnector(t *testing.T, connectorName string) {
	t.Helper()
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	own := "version: 1\ncategory: acme-markers\nrules:\n" +
		"  - id: ACME-OWN-MARKER\n    pattern: 'acme\\.own-7f3c'\n    title: \"Own marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "acme.yaml"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil || len(plan.Expressed) != 1 {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConnectorRulePackOverrides(connectorName, pack); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connectorName) })
}

func TestPromotedArtifactMigratedLiteralNeedsAnExecutedCommand(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-migrated-literal"
	installMigratedLiteralConnector(t, connectorName)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/stdin", filepath.Join(dir, "stdin-alias")); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		body string
		want bool
	}{
		{"#!/bin/sh\n# see acme.own-7f3c in the runbook\nprintf '%s\\n' done\n", false},
		{"#!/bin/sh\necho acme.own-7f3c > /tmp/acme-marker.txt\n", true},
		// A quoted heredoc is data the command that reads it acts on.
		{"#!/bin/sh\ncat > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat - > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ntee /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat -n -- - > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		// The command a heredoc is fed to may read it whatever its name: the
		// shell that runs the script may bind true, mkdir, cat or /bin/cat to a
		// function that reads stdin (TestInheritedShellFunctionReadsAHeredoc).
		// So the literal counts beside any command, file operands or not.
		{"#!/bin/sh\ntrue <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\nprintf '%s\\n' done\n", true},
		{"#!/bin/sh\nmkdir -p /tmp/acme <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\ncat /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\ngrep acme /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\ngrep -n -e acme /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\nhead -n 1 /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\ngrep -e - /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		// A program the parse does not model (cut) leaves the script
		// detection-only, heredoc or not.
		{"#!/bin/sh\ncut -d - -f 1 /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", false},
		{"#!/bin/sh\ngrep -f - /dev/null > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ngrep -e - /dev/null - > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ngrep acme > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ngrep acme /dev/stdin > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat /dev/stdin > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\nhead -n 1 > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat /dev/./stdin > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat /dev//stdin > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ngrep acme stdin-alias > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncp notes.txt copy.txt\ncat notes.txt > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ncat missing.txt > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n", true},
		{"#!/bin/sh\ngrep acme notes.txt <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\n/bin/cat /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		{"#!/bin/sh\necho done <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n", true},
		// A ':' heredoc comment block leaves the parse partial: never enforced.
		{"#!/bin/sh\n: <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\nprintf '%s\\n' done\n", false},
	} {
		body, want := tc.body, tc.want
		path := filepath.Join(dir, fmt.Sprintf("script-%d.sh", i))
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir})
		findings := promotedArtifactFindings(t.Context(), agentHookRequest{ConnectorName: connectorName}, facts, true, nil)
		enforced := false
		for _, finding := range findings {
			if finding.RuleID == "ACME-OWN-MARKER" && finding.contributesToEnforcement() {
				enforced = true
			}
		}
		if enforced != want {
			t.Errorf("%q: enforced=%t, want %t (%v)", body, enforced, want, FindingStrings(findings))
		}
	}
}

// Bash binds a command name to a function before it looks for a builtin or a
// file, for any name, an absolute path included: a function the shell
// inherits (export -f) or one BASH_ENV defines. That function reads the
// heredoc a script feeds true, grep with a file operand or /bin/cat
// /dev/null, so the migrated literal in it counts: the gateway does not see
// the shell that will run the script.
func TestInheritedShellFunctionReadsAHeredoc(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-inherited-function"
	installMigratedLiteralConnector(t, connectorName)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	consumed := filepath.Join(dir, "consumed.txt")
	bashEnv := filepath.Join(dir, "bash_env")
	if err := os.WriteFile(bashEnv, []byte("function /bin/cat { command cat > '"+consumed+"'; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bash, bashErr := exec.LookPath("bash")
	for i, tc := range []struct {
		name, body string
		run        []string // how bash runs the script (SCRIPT is its path)
	}{
		{"exported true", "#!/bin/sh\ntrue <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n",
			[]string{"-c", "true() { command cat > '" + consumed + "'; }; export -f true; exec bash \"$1\"", "_", "SCRIPT"}},
		{"exported grep", "#!/bin/sh\ngrep acme notes.txt <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n",
			[]string{"-c", "grep() { command cat > '" + consumed + "'; }; export -f grep; exec bash \"$1\"", "_", "SCRIPT"}},
		{"BASH_ENV absolute path", "#!/bin/sh\n/bin/cat /dev/null <<'EOF'\nsee acme.own-7f3c in the runbook\nEOF\n",
			[]string{"-c", `BASH_ENV="$1" exec bash "$2"`, "_", bashEnv, "SCRIPT"}},
	} {
		path := filepath.Join(dir, fmt.Sprintf("inherited-%d.sh", i))
		if err := os.WriteFile(path, []byte(tc.body), 0o700); err != nil {
			t.Fatal(err)
		}
		if bashErr == nil {
			_ = os.Remove(consumed)
			args := slices.Clone(tc.run)
			args[len(args)-1] = path
			cmd := exec.Command(bash, args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			data, _ := os.ReadFile(consumed)
			if err != nil || !strings.Contains(string(data), "acme.own-7f3c") {
				// The premise: the function read the heredoc. Linux CI runs bash 5.
				if runtime.GOOS == "linux" {
					t.Errorf("%s: bash did not feed the heredoc to the function: %v %s (read %q)", tc.name, err, out, data)
				} else {
					t.Logf("%s: bash here did not run the function: %v %s", tc.name, err, out)
				}
			}
		}
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir})
		findings := promotedArtifactFindings(t.Context(), agentHookRequest{ConnectorName: connectorName}, facts, true, nil)
		enforced := false
		for _, finding := range findings {
			if finding.RuleID == "ACME-OWN-MARKER" && finding.contributesToEnforcement() {
				enforced = true
			}
		}
		if !enforced {
			t.Errorf("%s: the heredoc literal did not enforce (%v)", tc.name, FindingStrings(findings))
		}
	}
}

func TestR104GAP0463HeredocDecisionDoesNotDependOnLaterCommand(t *testing.T) {
	const connectorName = "r104-heredoc-migrated-literal"
	installMigratedLiteralConnector(t, connectorName)
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "notes.txt"), []byte("ordinary notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "cat notes.txt <<'EOF'\nacme.own-7f3c\nEOF\n"
	for _, command := range []string{base, base + "date\n"} {
		input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd,
			ActiveHome: t.TempDir(), DialectHint: actionfacts.DialectPOSIX}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, Connector: connectorName, EnforcementCapable: true,
		})
		finding := findingWithID(findings, "ACME-OWN-MARKER")
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("heredoc with later command %v was not conservatively blocked: %v",
				command != base, FindingStrings(findings))
		}
	}
}

func TestPromotedArtifactPreservesActiveAgentInstructionContext(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-active-agent-context-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()

	for _, test := range []struct {
		name     string
		fileName string
		ruleID   string
		lost     bool
	}{
		{
			name:     "cached case-insensitive AGENTS.md",
			fileName: "AGENTS.md",
			ruleID:   "COG-AGENTS-MD",
		},
		{
			name:     "lost case-insensitive MEMORY.md",
			fileName: "MEMORY.md",
			ruleID:   "COG-MEMORY",
			lost:     true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			activePath := filepath.Join(dir, test.fileName)
			mutatedPath := filepath.Join(dir, strings.ToLower(test.fileName))
			scriptPath := filepath.Join(dir, test.fileName+"-mutator.sh")
			body := fmt.Sprintf("#!/bin/sh\nprintf updated > %q\n", mutatedPath)
			if err := os.WriteFile(scriptPath, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{
				Tool:    "shell",
				Command: fmt.Sprintf("bash %q", scriptPath),
				CWD:     dir,
			}
			if test.lost {
				input.ActiveAgentFilesCaseInsensitiveUncertain = true
				input.ActiveAgentFilesUncertain = true
			} else {
				input.ActiveAgentFiles = []string{activePath}
				input.ActiveAgentFilesCaseInsensitive = []string{activePath}
			}
			outer := actionfacts.Analyze(input)

			for _, preExecution := range []bool{true, false} {
				t.Run(fmt.Sprintf("pre-execution=%t", preExecution), func(t *testing.T) {
					findings := promotedArtifactFindings(
						t.Context(),
						agentHookRequest{ConnectorName: connectorName},
						outer,
						preExecution,
						nil,
					)
					matched := findingWithID(findings, test.ruleID)
					if matched == nil {
						t.Fatalf("executed script lost %s: %v outer=%+v", test.ruleID, FindingStrings(findings), outer)
					}
					if got := matched.contributesToEnforcement(); got != preExecution {
						t.Fatalf("enforceable=%t want %t: %+v", got, preExecution, *matched)
					}
				})
			}
		})
	}
}

func TestPromotedArtifactHonorsPOSIXNoExecScriptMode(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-script-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "runner-cleanup.sh")
	statePath := filepath.Join(
		home,
		".defenseclaw",
		"quarantine",
		"skills",
		"e2e-stale",
	)
	body := fmt.Sprintf("#!/bin/sh\nrm -rf -- %q\n", statePath)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		invocation  string
		wantFinding bool
		enforceable bool
	}{
		{name: "bash short noexec", invocation: "bash -n"},
		{name: "bash named noexec", invocation: "bash -o noexec"},
		{name: "lowercase absolute bash", invocation: "/usr/bin/bash -n"},
		{name: "sh noexec", invocation: "sh -n"},
		{name: "dash noexec", invocation: "dash -n"},
		{name: "lowercase env wrapper", invocation: "env bash -n"},
		{name: "lowercase command wrapper", invocation: "command -- sh -n"},
		{name: "lowercase exec wrapper", invocation: "exec dash -n"},
		{name: "bash verbose noexec", invocation: "bash -nv"},
		{name: "bash final verbose noexec", invocation: "bash +v -nv"},
		{name: "bash named verbose noexec", invocation: "bash -o noexec -o verbose"},
		{name: "bash long verbose noexec", invocation: "bash --verbose -n"},
		{name: "sh verbose noexec", invocation: "sh -nv"},
		{name: "dash verbose noexec", invocation: "dash -nv"},
		{name: "bash verbose disabled", invocation: "bash -nv +v"},
		{name: "bash named verbose disabled", invocation: "bash -o noexec -o verbose +o verbose"},
		{name: "sh verbose disabled", invocation: "sh -nv +v"},
		{name: "dash verbose disabled", invocation: "dash -nv +v"},
		{
			name: "bash short noexec re-enabled", invocation: "bash -n +n",
			wantFinding: true, enforceable: true,
		},
		{
			name: "bash named noexec re-enabled", invocation: "bash -o noexec +o noexec",
			wantFinding: true, enforceable: true,
		},
		{
			name: "sh noexec re-enabled", invocation: "sh -n +n",
			wantFinding: true, enforceable: true,
		},
		{
			name: "dash noexec re-enabled", invocation: "dash -n +n",
			wantFinding: true, enforceable: true,
		},
		// For identity failures below, direct shell artifact candidates remain
		// enforceable because the promoted script is analyzed separately and must
		// be authoritative. Wrapper/nested candidates remain detection-only because
		// promotedArtifactCandidateEnforcementEligible rejects them.
		{
			name: "mixed case bash", invocation: "Bash -n",
			wantFinding: true, enforceable: true,
		},
		{
			name: "mixed case basename", invocation: "/usr/bin/Bash -n",
			wantFinding: true, enforceable: true,
		},
		{
			name: "mixed case directory", invocation: "/USR/bin/bash -n",
			wantFinding: true, enforceable: true,
		},
		{name: "mixed case env wrapper", invocation: "Env bash -n", wantFinding: true},
		{name: "mixed case env child", invocation: "env Bash -n", wantFinding: true},
		{
			name: "mixed case command wrapper", invocation: "Command -- sh -n",
			wantFinding: true,
		},
		{name: "mixed case command child", invocation: "command -- Sh -n", wantFinding: true},
		{name: "mixed case exec wrapper", invocation: "Exec dash -n", wantFinding: true},
		{name: "mixed case exec child", invocation: "exec Dash -n", wantFinding: true},
		{
			name: "nested shell path", invocation: "/usr/bin/fake/bash -n",
			wantFinding: true, enforceable: true,
		},
		{name: "nested env path", invocation: "/usr/bin/fake/env bash -n", wantFinding: true},
		{
			name: "nested command path", invocation: "/usr/bin/fake/command -- sh -n",
			wantFinding: true,
		},
		{name: "nested exec path", invocation: "/usr/bin/fake/exec dash -n", wantFinding: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: fmt.Sprintf("%s %q", test.invocation, path),
				CWD:     dir,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true, nil)
			matched := findingWithID(findings, "tamper.detector_state_write")
			if !test.wantFinding {
				if len(findings) != 0 {
					t.Fatalf(
						"no-exec script produced findings: %v facts=%+v",
						FindingStrings(findings),
						facts,
					)
				}
				return
			}
			if matched == nil || matched.contributesToEnforcement() != test.enforceable {
				t.Fatalf(
					"executing script finding enforcement=%t want %t: %v facts=%+v",
					matched != nil && matched.contributesToEnforcement(),
					test.enforceable,
					FindingStrings(findings),
					facts,
				)
			}
		})
	}
}

func TestPromotedArtifactRevokesNoExecPreviewAfterConflictingSources(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-conflict-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "runner-cleanup.sh")
	statePath := filepath.Join(
		home, ".defenseclaw", "quarantine", "skills", "source-conflict",
	)
	if err := os.WriteFile(
		script,
		[]byte(fmt.Sprintf("#!/bin/sh\nrm -rf -- %q\n", statePath)),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		command string
		argv    []string
	}{
		{
			name:    "raw executes structured noexec",
			command: fmt.Sprintf("bash %q", script),
			argv:    []string{"bash", "-n", script},
		},
		{
			name:    "raw noexec structured executes",
			command: fmt.Sprintf("bash -n %q", script),
			argv:    []string{"bash", script},
		},
		{
			name:    "raw noexec redirect structured executes",
			command: fmt.Sprintf("bash -n %q > /dev/null", script),
			argv:    []string{"bash", script},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: test.command, Argv: test.argv,
				CWD: dir, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			})
			if facts.Parse.Status == actionfacts.StatusComplete || facts.Authoritative() {
				t.Fatalf("conflicting sources stayed authoritative: %+v", facts)
			}
			for _, command := range facts.Commands {
				if command.Effect == actionfacts.EffectPreview {
					t.Fatalf("conflicting sources retained preview: %+v", facts)
				}
			}
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true, nil)
			matched := findingWithID(findings, "tamper.detector_state_write")
			if matched == nil {
				t.Fatalf("source conflict lost tamper finding: %v facts=%+v", FindingStrings(findings), facts)
			}
			if matched.contributesToEnforcement() {
				t.Fatalf("source-conflict artifact unexpectedly enforceable: %+v parse=%+v commands=%+v", *matched, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestPOSIXNoExecArtifactPipelineRetainsFinding(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-pipeline-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bad\nprintf SAFE_FILENAME_MARKER\n#")
	statePath := filepath.Join(
		home, ".defenseclaw", "quarantine", "skills", "e2e-stale",
	)
	if err := os.WriteFile(
		path,
		[]byte(fmt.Sprintf("#!/bin/sh\nrm -rf -- %q\n(\n", statePath)),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		format string
	}{
		{name: "bash", format: "bash -n '%s' 2>/dev/stdout | bash"},
		{name: "bash verbose", format: "bash -nv '%s' 2>/dev/stdout | bash"},
		{name: "sh", format: "sh -n '%s' 2>/dev/stdout | bash"},
		{name: "dash verbose", format: "dash -nv '%s' 2>/dev/stdout | bash"},
		{name: "env bash", format: "env bash -n '%s' 2>/dev/stdout | bash"},
		{name: "command sh", format: "command -- sh -n '%s' 2>/dev/stdout | bash"},
		{name: "exec dash", format: "exec dash -n '%s' 2>/dev/stdout | bash"},
		{name: "subshell", format: "(bash -n '%s') 2>/dev/stdout | bash"},
		{name: "block", format: "{ bash -n '%s'; } 2>/dev/stdout | bash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := fmt.Sprintf(test.format, path)
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: command, CWD: dir, ActiveHome: home,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true, nil)
			matched := findingWithID(findings, "tamper.detector_state_write")
			if matched == nil {
				t.Fatalf("no-exec pipeline lost tamper finding: %v facts=%+v", FindingStrings(findings), facts)
			}
			if matched.contributesToEnforcement() {
				t.Fatalf("pipeline artifact unexpectedly became enforceable: %+v", *matched)
			}
		})
	}
}

func TestPOSIXNoExecCommandPipelineRetainsFinding(t *testing.T) {
	const connectorName = "noexec-command-pipeline-test"
	installDefaultProfileConnector(t, connectorName)
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "bash", command: `bash -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "bash verbose", command: `bash -nv -c 'rm -rf /' 2>&1 | bash`},
		{name: "env bash", command: `env bash -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "command sh", command: `command -- sh -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "exec dash", command: `exec dash -n -c 'rm -rf /' 2>&1 | bash`},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []actionfacts.Input{
				{Tool: "shell", Command: test.command, CWD: "/repo"},
				{Tool: "Bash", Args: args, CWD: "/repo"},
			} {
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connectorName,
					EnforcementCapable: true,
				})
				if findingWithID(findings, "CMD-RM-RF") == nil {
					t.Fatalf("no-exec command pipeline lost finding: %v", FindingStrings(findings))
				}
			}
		})
	}
}

func TestPOSIXNoExecScriptRedirectRetainsStateMutationDetection(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-redirect-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "runner-cleanup.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf safe\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(
		home,
		".defenseclaw",
		"quarantine",
		"skills",
		"redirected-output",
	)
	command := fmt.Sprintf("bash -n %q > %q", script, target)
	input := actionfacts.Input{
		Tool: "shell", Command: command, CWD: dir, ActiveHome: home,
	}
	facts := actionfacts.Analyze(input)
	sawScriptExecute := false
	sawTargetWrite := false
	for _, path := range facts.Paths {
		sawScriptExecute = sawScriptExecute || path.Access == actionfacts.PathAccessExecute &&
			semanticPathValue(path) == canonicalSemanticPath(script)
		sawTargetWrite = sawTargetWrite || path.Access == actionfacts.PathAccessWrite &&
			semanticPathValue(path) == canonicalSemanticPath(target)
	}
	if facts.Parse.Status != actionfacts.StatusPartial || facts.Authoritative() ||
		!sawScriptExecute || !sawTargetWrite {
		t.Fatalf("no-exec redirect facts=%+v", facts)
	}
	if findings := promotedArtifactFindings(
		t.Context(),
		agentHookRequest{ConnectorName: connectorName},
		facts,
		true,
		nil,
	); len(findings) != 0 {
		t.Fatalf("safe redirected script produced artifact findings: %v", FindingStrings(findings))
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: command, Connector: connectorName,
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "tamper.detector_state_write")
	// The independent target proof resolves the active quarantine redirect
	// even though unrelated script analysis leaves ActionFacts partial.
	if matched == nil || !matched.contributesToEnforcement() {
		t.Fatalf("redirect lost protected-state enforcement: %v", FindingStrings(findings))
	}
}

func TestReadPromotedArtifactRejectsPathIndirection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary users cannot reliably create a Windows symlink fixture")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.sh")
	link := filepath.Join(dir, "link.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if body, _, ok := readPromotedArtifact(link, actionfacts.DialectPOSIX); ok || len(body) != 0 {
		t.Fatal("symlinked artifact became enforcement input")
	}
}

func TestReadPromotedArtifactRequiresExecuteBitOnlyForDirectPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use POSIX execute permission bits")
	}
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readPromotedArtifact(path, actionfacts.DialectNone); ok {
		t.Fatal("non-executable direct path was promoted")
	}
	if _, dialect, ok := readPromotedArtifact(
		path,
		actionfacts.DialectPOSIX,
	); !ok || dialect != actionfacts.DialectPOSIX {
		t.Fatal("explicit interpreter lost readable non-executable script")
	}
}

func TestPromotedArtifactUsesInvocationWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX working-directory semantics")
	}
	const connectorName = "artifact-cwd-test"
	installDefaultProfileConnector(t, connectorName)
	file, err := os.CreateTemp("/tmp", "defenseclaw-artifact-cwd-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if _, err := file.WriteString("#!/bin/sh\nrm -rf ..\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		cwd         string
		enforceable bool
	}{
		{name: "caller in tmp", cwd: "/tmp", enforceable: true},
		{name: "caller in project", cwd: "/tmp/project", enforceable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: test.cwd,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true, nil)
			got := false
			for _, finding := range findings {
				got = got || finding.RuleID == "CMD-RM-RF" && finding.contributesToEnforcement()
			}
			if got != test.enforceable {
				t.Fatalf("enforceable=%t want %t findings=%v", got, test.enforceable, FindingStrings(findings))
			}
		})
	}
}

func TestPromotedArtifactShebangDialectRequiresExactInterpreter(t *testing.T) {
	tests := []struct {
		line string
		want actionfacts.Dialect
	}{
		{line: "#!/bin/sh", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/bin/bash", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/bin/env bash", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/local/bin/pwsh", want: actionfacts.DialectPowerShell},
		{line: "#!/usr/bin/env pwsh", want: actionfacts.DialectPowerShell},
		{line: "#!/usr/bin/shadow", want: actionfacts.DialectNone},
		{line: "#!/usr/bin/env bashful", want: actionfacts.DialectNone},
		{line: "#!/opt/notpowershell", want: actionfacts.DialectNone},
		{line: "#!/usr/bin/env -S bash", want: actionfacts.DialectNone},
		{line: "#!/bin/sh -e", want: actionfacts.DialectNone},
		{line: "#!sh", want: actionfacts.DialectNone},
		{line: "  #!/bin/sh", want: actionfacts.DialectNone},
		{line: "#!/bin/sh\r", want: actionfacts.DialectNone},
	}
	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			if got := promotedArtifactShebangDialect([]byte(test.line + "\n")); got != test.want {
				t.Fatalf("dialect=%q want %q", got, test.want)
			}
		})
	}
}

func TestExperimentalArtifactPromotionRequiresReviewedStructuredRoute(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	installDefaultProfileConnector(t, "claudecode")
	path := filepath.Join(t.TempDir(), "assembled.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: filepath.Dir(path),
	})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(facts, nil)
	req := agentHookRequest{
		ConnectorName:           "claudecode",
		HookEventName:           "PreToolUse",
		SuppressCorrelationEmit: true,
		toolChain:               capture,
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector("claudecode")
	original := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}

	got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), profile, req, original, 0,
	)
	if got.Action != guardrailActionBlock {
		t.Fatalf("reviewed pre-tool route action=%q findings=%v", got.Action, got.RuleIDs)
	}

	unknown := req
	unknown.HookEventName = "pretooluse"
	if got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), profile, unknown, original, 0,
	); got.Action != original.Action || len(got.RuleIDs) != 0 {
		t.Fatalf("undeclared event entered artifact path: %+v", got)
	}

	unreviewed := profile
	unreviewed.ToolCallLifecycle = connector.ToolCallLifecycleContract{}
	if got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), unreviewed, req, original, 0,
	); got.Action != original.Action || len(got.RuleIDs) != 0 {
		t.Fatalf("unreviewed contract entered artifact path: %+v", got)
	}
}

func TestExperimentalArtifactPromotionPanicUsesFailMode(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	dir := t.TempDir()
	name, body := "assembled.sh", "#!/bin/sh\nrm -rf /\n"
	if runtime.GOOS == "windows" {
		name, body = "assembled.ps1", "Remove-Item -Recurse -Force C:\\\r\n"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{
		Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: filepath.Dir(path),
	}
	if runtime.GOOS == "windows" {
		quotedPath := strings.ReplaceAll(path, "'", "''")
		input = actionfacts.Input{
			Tool: "powershell", Command: "powershell -NoProfile -File '" + quotedPath + "'",
			CWD: dir, DialectHint: actionfacts.DialectPowerShell,
		}
	}
	facts := actionfacts.Analyze(input)
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(facts, nil)
	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", toolChain: capture,
	}
	original := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action"}
	for _, tc := range []struct {
		name, failMode, wantAction string
		wantWouldBlock             bool
		perUser                    bool
	}{
		{name: "closed", failMode: "closed", wantAction: "block"},
		// A per-user install is always closed (sa-port-peer).
		{name: "per-user explicit open", failMode: "open", perUser: true, wantAction: "block"},
		{name: "explicit open", failMode: "open", wantAction: "allow", wantWouldBlock: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			if !tc.perUser {
				// An administrator's explicit open covers a panic on a managed host.
				cfg.DeploymentMode = "managed_enterprise"
			}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.HookFailMode = tc.failMode
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
			api := &APIServer{scannerCfg: cfg}
			profile := api.hookProfileForConnector("claudecode")
			panicked := false
			profile.Respond = func(connector.HookRespondInput) connector.HookRespondOutput {
				panicked = true
				panic("artifact response shaper panic")
			}
			got := api.safeApplyExperimentalArtifactPromotion(t.Context(), profile, req, original, 0)
			if !panicked || got.Action != tc.wantAction || got.Mode != "action" || got.WouldBlock != tc.wantWouldBlock {
				t.Fatalf("panicked=%t response=%+v, want %s", panicked, got, tc.wantAction)
			}
		})
	}
}

// GAP-0616: a script call inside a compound command is judged as if it ran
// alone, so a migrated 0.8.x literal rule that blocks `bash heredoc.sh` also
// blocks it in a list, a sequence, a pipeline, a subshell or the background.
func TestPromotedArtifactInCompoundCommandIsEnforced(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	own := "version: 1\ncategory: acme-markers\nrules:\n" +
		"  - id: ACME-OWN-MARKER\n    pattern: 'acme\\.own-7f3c'\n    title: \"Own marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "acme.yaml"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil || len(plan.Expressed) != 1 {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	const connectorName = "artifact-compound-command-test"
	if err := ApplyConnectorRulePackOverrides(connectorName, pack); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connectorName) })
	dir := t.TempDir()
	path := filepath.Join(dir, "heredoc.sh")
	body := "#!/bin/sh\ncat > /tmp/acme-marker.txt <<'EOF'\nacme.own-7f3c\nEOF\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		want    bool
	}{
		{"bash heredoc.sh", true},
		{"bash heredoc.sh && cat /tmp/acme-marker.txt", true},
		{"bash heredoc.sh; echo done", true},
		{"bash heredoc.sh || echo failed", true},
		{"bash heredoc.sh | cat", true},
		{"bash heredoc.sh > /dev/null", true},
		{"bash heredoc.sh 2>&1 | tail -5", true},
		{"X=1 bash heredoc.sh", true},
		{"X=1 bash heredoc.sh > /dev/null", true},
		{"(X=1 bash heredoc.sh) 2>&1", true},
		{"(bash heredoc.sh)", true},
		{"{ bash heredoc.sh; }", true},
		{"{ bash heredoc.sh; } > /dev/null", true},
		{"(bash heredoc.sh) 2>&1", true},
		{"if true; then bash heredoc.sh; fi", true},
		{"case x in x) bash heredoc.sh;; esac", true},
		{"while true; do bash heredoc.sh; done", true},
		{"for i in 1; do bash heredoc.sh; done", true},
		{"! bash heredoc.sh", true},
		{"bash heredoc.sh; echo $HOME", true},
		{"bash heredoc.sh &", true},
		{"echo start; bash heredoc.sh", true},
		{fmt.Sprintf("false && bash %q", path), true},
		{fmt.Sprintf("true || bash %q", path), true},
		{fmt.Sprintf("cd /tmp && bash %q", path), true},
		// After a cd the relative name may be another file.
		{"cd /tmp && bash heredoc.sh", false},
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: test.command, CWD: dir})
		findings := promotedArtifactFindings(t.Context(), agentHookRequest{
			ConnectorName: connectorName,
		}, facts, true, nil)
		matched := findingWithID(findings, "ACME-OWN-MARKER")
		if matched == nil {
			t.Errorf("%q lost detection: %v", test.command, FindingStrings(findings))
			continue
		}
		if got := matched.contributesToEnforcement(); got != test.want {
			t.Errorf("%q: enforced=%t, want %t", test.command, got, test.want)
		}
	}
}

func TestPromotedArtifactFactsParticipateInToolChains(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-chain-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	for _, test := range []struct {
		name string
		body string
		step int
	}{
		{name: "predecessor", body: "#!/bin/sh\nsudo -l\n", step: 1},
		{name: "terminal", body: "#!/bin/sh\nsudo -u root /bin/sh\n", step: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".sh")
			if err := os.WriteFile(path, []byte(test.body), 0o700); err != nil {
				t.Fatal(err)
			}
			outer := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
			})
			capture := &toolChainHookCapture{}
			capture.recordTrustedAction(outer, nil)
			req := agentHookRequest{
				ConnectorName: connectorName,
				toolChain:     capture,
			}
			_ = promotedArtifactFindings(t.Context(), req, outer, true, nil)
			projection, _ := projectAgentHookToolChains(
				req,
				connector.ToolCallLifecycleContract{},
			)
			assertToolChainStep(
				t,
				projection,
				guardrail.ToolChainPrivilegeDiscoveryThenElevation,
				test.step,
				true,
			)
		})
	}
}

func TestPromotedArtifactObserverFindingDoesNotEnterEnforcingChain(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	keyPath := filepath.Join(home, ".ssh", "id_rsa")
	readCommand := "cat " + keyPath
	a := config.GuardrailProfile{Mode: "action"}
	b := config.GuardrailProfile{Mode: "observe", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"observer.example"}}}
	_, ctx := meetVerdictFixture(t, a, b,
		meetVerdictRule("A-OTHER", "absent-marker", "HIGH"),
		meetVerdictRule("PATH-SSH-KEY", keyPath, "HIGH"))
	dir := t.TempDir()
	path := filepath.Join(dir, "read.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+readCommand+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	outer := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(outer, nil)
	req := agentHookRequest{ConnectorName: "codex", toolChain: capture}
	findings := promotedArtifactFindings(ctx, req, outer, true, nil)
	if found := findingWithID(findings, "PATH-SSH-KEY"); found == nil || found.profile != "b" {
		t.Fatalf("observer finding missing from artifact audit: %+v", findings)
	}
	step, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	for _, projection := range capture.artifactProjections {
		if projection.DetectionStepMask&step != 0 || projection.EnforcementStepMask&step != 0 {
			t.Fatalf("observer's PATH-SSH-KEY entered an enforcing chain: %+v", projection)
		}
	}
}

func TestPromotedWindowsArtifactFactsParticipateInToolChains(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "windows-artifact-chain-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("Windows home directory unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-read.ps1")
	credentialPath := filepath.Join(home, ".aws", "credentials")
	body := "Get-Content '" + strings.ReplaceAll(credentialPath, "'", "''") + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	quotedPath := strings.ReplaceAll(path, "'", "''")
	outer := actionfacts.Analyze(actionfacts.Input{
		Tool:        "powershell",
		Command:     "& '" + quotedPath + "'",
		CWD:         dir,
		DialectHint: actionfacts.DialectPowerShell,
	})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(outer, nil)
	req := agentHookRequest{
		ConnectorName: connectorName,
		toolChain:     capture,
	}
	_ = promotedArtifactFindings(t.Context(), req, outer, true, nil)
	projection, _ := projectAgentHookToolChains(
		req,
		connector.ToolCallLifecycleContract{},
	)
	// The only outer uncertainty is the statically named script body. Artifact
	// promotion resolves those bytes, and the exact credential path is therefore
	// eligible to join a later same-path external egress proof.
	assertToolChainStep(
		t,
		projection,
		guardrail.ToolChainSecretReadThenEgress,
		1,
		true,
	)
}

func TestPromotedWindowsArtifactTrailingLineEndingEnforcement(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "windows-artifact-enforcement-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	for _, test := range []struct {
		name        string
		body        string
		wantRule    string
		enforceable bool
	}{
		{
			name: "destructive CRLF", body: "Remove-Item -Recurse -Force C:\\\r\n",
			wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			name:     "runtime bypass CRLF",
			body:     "codex exec --dangerously-bypass-approvals-and-sandbox\r\n",
			wantRule: "exec.agent_runtime_bypass_flags", enforceable: true,
		},
		{
			name:     "straight-line interior CRLF is enforceable",
			body:     "Write-Output ready\r\nRemove-Item -Recurse -Force C:\\\r\n",
			wantRule: "CMD-RM-RF", enforceable: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".ps1")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			quotedPath := strings.ReplaceAll(path, "'", "''")
			outer := actionfacts.Analyze(actionfacts.Input{
				Tool: "powershell", Command: "powershell -NoProfile -File '" + quotedPath + "'",
				CWD: dir, DialectHint: actionfacts.DialectPowerShell,
			})
			findings := promotedArtifactFindings(
				t.Context(),
				agentHookRequest{ConnectorName: connectorName},
				outer,
				true,
				nil,
			)
			var matched *RuleFinding
			for index := range findings {
				if findings[index].RuleID == test.wantRule {
					matched = &findings[index]
					break
				}
			}
			if matched == nil {
				t.Fatalf("missing %s: %v outer=%+v", test.wantRule, FindingStrings(findings), outer)
			}
			if got := matched.contributesToEnforcement(); got != test.enforceable {
				t.Fatalf("enforceable=%t want %t: %+v", got, test.enforceable, *matched)
			}
		})
	}
}

func TestPromotedWindowsCMDAndBATFinalBytes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "claudecode"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector(connectorName)
	original := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}

	for _, extension := range []string{".cmd", ".bat"} {
		t.Run(strings.TrimPrefix(extension, "."), func(t *testing.T) {
			for _, test := range []struct {
				name      string
				body      string
				wantBlock bool
			}{
				{
					name: "destructive", body: "rmdir /s /q C:\\\r\n",
					wantBlock: true,
				},
				{
					name: "quoted benign control",
					body: "echo \"rmdir /s /q C:\\\"\r\n",
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					path := filepath.Join(dir, test.name+extension)
					if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
						t.Fatal(err)
					}
					outer := actionfacts.Analyze(actionfacts.Input{
						Tool: "cmd", Command: `"` + path + `"`, CWD: dir,
						DialectHint: actionfacts.DialectCMD,
					})
					findings := promotedArtifactFindings(
						t.Context(),
						agentHookRequest{ConnectorName: connectorName},
						outer,
						true,
						nil,
					)
					if test.wantBlock {
						if len(findings) != 1 || findings[0].RuleID != "CMD-RM-RF" ||
							!findings[0].contributesToEnforcement() {
							t.Fatalf("destructive final bytes findings=%+v outer=%+v", findings, outer)
						}
					} else if len(findings) != 0 {
						t.Fatalf("quoted final bytes produced findings: %v", FindingStrings(findings))
					}

					capture := &toolChainHookCapture{}
					capture.recordTrustedAction(outer, nil)
					req := agentHookRequest{
						ConnectorName:           connectorName,
						HookEventName:           "PreToolUse",
						SuppressCorrelationEmit: true,
						toolChain:               capture,
					}
					got := api.safeApplyExperimentalArtifactPromotion(
						t.Context(), profile, req, original, 0,
					)
					wantAction, wantRawAction := original.Action, original.RawAction
					if test.wantBlock {
						wantAction, wantRawAction = guardrailActionBlock, guardrailActionBlock
					}
					if got.Action != wantAction || got.RawAction != wantRawAction {
						t.Fatalf(
							"action/raw=%q/%q want %q/%q findings=%v outer=%+v",
							got.Action, got.RawAction, wantAction, wantRawAction,
							got.Findings, outer,
						)
					}
				})
			}
		})
	}
}

func TestPromotedArtifactDirectSuffixDoesNotInventInterpreter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-directly-executable.ps1")
	if err := os.WriteFile(
		path,
		[]byte(`Remove-Item -Recurse -Force C:\`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Facts{
		Parse: actionfacts.ParseResult{
			Status:  actionfacts.StatusComplete,
			Dialect: actionfacts.DialectPOSIX,
		},
		Commands: []actionfacts.CommandFact{{
			ID: 1, Kind: actionfacts.CommandKindProcess,
			Dialect: actionfacts.DialectPOSIX, Effect: actionfacts.EffectExecute,
			Program: path, Executable: path, Argv: []string{path}, ArgvComplete: true,
		}},
		Paths: []actionfacts.PathFact{{
			CommandID: 1, Access: actionfacts.PathAccessExecute,
			Flavor: actionfacts.PathFlavorPOSIX, Value: path,
			Normalized: path, Resolved: path, Absolute: true,
		}},
	}
	if findings := promotedArtifactFindings(
		t.Context(),
		agentHookRequest{ConnectorName: "artifact-direct-suffix-test"},
		facts,
		true,
		nil,
	); len(findings) != 0 {
		t.Fatalf("suffix-only direct path produced findings: %v", FindingStrings(findings))
	}
}

func TestPromotedArtifactDialectRequiresAmbientWindowsShellAuthority(t *testing.T) {
	tests := []struct {
		name    string
		command actionfacts.CommandFact
		path    actionfacts.PathFact
		want    actionfacts.Dialect
		ok      bool
	}{
		{
			name: "PowerShell dot source",
			command: actionfacts.CommandFact{
				Program: ".", Dialect: actionfacts.DialectPowerShell,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessRead, Normalized: `C:\work\task.ps1`,
			},
			want: actionfacts.DialectPowerShell, ok: true,
		},
		{
			name: "POSIX dot source",
			command: actionfacts.CommandFact{
				Program: ".", Dialect: actionfacts.DialectPOSIX,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessRead, Normalized: "/tmp/task.sh",
			},
			want: actionfacts.DialectPOSIX, ok: true,
		},
		{
			name: "PowerShell direct script",
			command: actionfacts.CommandFact{
				Program: `C:\work\task.ps1`, Dialect: actionfacts.DialectPowerShell,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: `C:\work\task.ps1`,
			},
			want: actionfacts.DialectPowerShell, ok: true,
		},
		{
			name: "CMD direct script",
			command: actionfacts.CommandFact{
				Program: `C:\work\task.cmd`, Dialect: actionfacts.DialectCMD,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: `C:\work\task.cmd`,
			},
			want: actionfacts.DialectCMD, ok: true,
		},
		{
			name: "POSIX suffix alone",
			command: actionfacts.CommandFact{
				Program: "/tmp/task.ps1", Dialect: actionfacts.DialectPOSIX,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: "/tmp/task.ps1",
			},
			want: actionfacts.DialectNone, ok: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := promotedArtifactDialect(test.command, test.path)
			if got != test.want || ok != test.ok {
				t.Fatalf("dialect/ok=%q/%t want %q/%t", got, ok, test.want, test.ok)
			}
		})
	}
}
