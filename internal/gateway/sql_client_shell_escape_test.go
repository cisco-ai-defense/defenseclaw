// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

func TestSQLClientShellEscapeSemanticOwnersAndCEL(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		expression string
		command    string
		client     actionfacts.SQLClientShellEscapeClient
	}{
		{
			name: "SQLite", ruleID: "exec.sqlite_client_shell_escape",
			expression: semanticSQLiteClientShellEscapeExpression,
			command:    `sqlite3 app.db '.shell /bin/sh'`, client: actionfacts.SQLClientShellEscapeSQLite,
		},
		{
			name: "MySQL", ruleID: "exec.mysql_client_shell_escape",
			expression: semanticMySQLClientShellEscapeExpression,
			command:    `mysql --database=app --execute='\! /bin/bash'`, client: actionfacts.SQLClientShellEscapeMySQL,
		},
	}
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, code := compiler.Compile(test.expression); code != semantic.CompileOK {
				t.Fatalf("compile code=%s", code)
			}
			owner, ok := semanticOwners[test.ruleID]
			if !ok || owner.prerequisite == nil || !owner.alertOnly || owner.detectionOnly {
				t.Fatalf("owner=%+v exists=%t", owner, ok)
			}
			input := actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"}
			facts := actionfacts.Analyze(input)
			if !owner.eligible(facts) || !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("exact escape not owned/enforceable: %+v", facts)
			}
			escapes := actionfacts.ExactSQLClientShellEscapes(facts)
			if len(escapes) != 1 || escapes[0].Client != test.client {
				t.Fatalf("escapes=%+v", escapes)
			}
			proof, owned := trustedSemanticOwnerFindingProof(test.ruleID, input, facts)
			if !owned || !proof.authorizes(test.ruleID) {
				t.Fatalf("semantic proof=%+v owned=%t", proof, owned)
			}
			if findingWithID(scanTrustedRulesForProfile(t, "strict", test.command, "shell"), test.ruleID) != nil {
				t.Fatalf("raw text scanner authorized %s", test.ruleID)
			}
		})
	}
}

func TestSQLClientShellEscapeProfilePosture(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		command string
	}{
		{"SQLite", "exec.sqlite_client_shell_escape", `sqlite3 app.db '.shell /bin/sh'`},
		{"MySQL", "exec.mysql_client_shell_escape", `mariadb -D app -e '\! /bin/bash'`},
	}
	profiles := []struct {
		name, severity, action string
	}{
		{"default", "HIGH", guardrailActionAlert},
		{"permissive", "HIGH", guardrailActionAlert},
		{"strict", "CRITICAL", guardrailActionAlert},
	}
	for _, profile := range profiles {
		profile := profile
		for _, test := range tests {
			test := test
			t.Run(profile.name+"/"+test.name, func(t *testing.T) {
				const connector = "codex"
				installToolCallCorpusProfileConnector(t, connector, profile.name)
				input := actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connector, EnforcementCapable: true,
				})
				finding := findingWithID(findings, test.ruleID)
				if finding == nil || finding.Severity != profile.severity ||
					finding.contributesToEnforcement() || !finding.contributesToAlertOnly() {
					t.Fatalf("profile=%s finding=%+v all=%v", profile.name, finding, FindingStrings(findings))
				}

				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
				response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "execute_command",
					CWD:           "/repo",
					ToolInput:     map[string]interface{}{"command": test.command},
				})
				if response.Action != profile.action || response.RawAction != profile.action ||
					response.Severity != profile.severity ||
					response.WouldBlock ||
					!findingStringHasRuleID(response.Findings, test.ruleID) {
					t.Fatalf("profile=%s response=%+v", profile.name, response)
				}
			})
		}
	}
}

func TestSQLClientShellEscapeHardNegativesStayQuiet(t *testing.T) {
	const connector = "sql-client-shell-escape-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	ruleIDs := []string{"exec.sqlite_client_shell_escape", "exec.mysql_client_shell_escape"}
	commands := []string{
		`sqlite3 app.db '.help'`,
		`sqlite3 app.db ".shell $SHELL"`,
		`sqlite3 app.db '.tables' '.shell /bin/sh'`,
		`sqlite3 app.db '.shell /bin/sh -c id'`,
		`sqlite3 -readonly app.db '.shell /bin/sh'`,
		`printf '%s\n' '.shell /bin/sh'`,
		`sqlite3 app.db '.shell /bin/sh'; echo done`,
		`sudo sqlite3 app.db '.shell /bin/sh'`,
		`mysql -e '\h'`,
		`mysql -e "\! $SHELL"`,
		`mysql -e '\! /bin/sh; SELECT 1'`,
		`mysql --raw -e '\! /bin/sh'`,
		`mysql -e '\! /bin/sh' || true`,
		`psql -c '\! /bin/sh'`,
	}
	for _, command := range commands {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		for _, ruleID := range ruleIDs {
			if finding := findingWithID(findings, ruleID); finding != nil {
				t.Fatalf("near-negative %q matched %s: %+v; all=%v", command, ruleID, *finding, FindingStrings(findings))
			}
		}
	}
}
