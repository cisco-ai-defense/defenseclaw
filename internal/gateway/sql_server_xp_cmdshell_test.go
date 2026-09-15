// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const sqlServerXPCommandShellRuleID = "exec.sqlserver_xp_cmdshell_invoke"
const sqlServerXPCommandShellEnableRuleID = "exec.sqlserver_xp_cmdshell_enable"

func TestSQLServerXPCommandShellSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticSQLServerXPCommandShellExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[sqlServerXPCommandShellRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := sqlServerXPCommandShellInput(t, "EXEC xp_cmdshell 'whoami';")
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact invocation not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, EnforcementCapable: true,
	})
	matched := findingWithID(findings, sqlServerXPCommandShellRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestSQLServerXPCommandShellEnableIsSeparateAndAlertOnly(t *testing.T) {
	owner := semanticOwners[sqlServerXPCommandShellEnableRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := sqlServerXPCommandShellInput(t,
		"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
	)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact enable not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
	matched := findingWithID(findings, sqlServerXPCommandShellEnableRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() ||
		!matched.contributesToAlertOnly() || findingWithID(findings, sqlServerXPCommandShellRuleID) != nil {
		t.Fatalf("enable finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestSQLServerXPCommandShellAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "sql_query", CWD: "/repo",
					ToolInput: map[string]interface{}{
						"connection": "Server=db.invalid,1433;Database=master;User Id=fixture;Password=fixture-password;",
						"query":      "EXEC xp_cmdshell 'whoami';",
					},
				},
			)
			if response.Action != guardrailActionAlert || response.WouldBlock ||
				response.Severity != "HIGH" ||
				!findingStringHasRuleID(response.Findings, sqlServerXPCommandShellRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestSQLServerXPCommandShellSafeNegativesDoNotAlert(t *testing.T) {
	for _, query := range []string{
		"SELECT name FROM sys.configurations WHERE name = 'xp_cmdshell';",
		"EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
		"EXEC xp_cmdshell @command;",
		"SELECT 'EXEC xp_cmdshell ''whoami''';",
		"EXEC xp_cmdshell 'whoami'; SELECT 1;",
	} {
		input := sqlServerXPCommandShellInput(t, query)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: query, EnforcementCapable: true,
		})
		if findingWithID(findings, sqlServerXPCommandShellRuleID) != nil {
			t.Fatalf("query=%q produced owner finding: %v", query, FindingStrings(findings))
		}
		if findingWithID(findings, sqlServerXPCommandShellEnableRuleID) != nil {
			t.Fatalf("query=%q produced enable finding: %v", query, FindingStrings(findings))
		}
	}
}

func sqlServerXPCommandShellInput(t *testing.T, query string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"connection": "Server=db.invalid,1433;Database=master;User Id=fixture;Password=fixture-password;",
		"query":      query,
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "sql_query", Args: raw, CWD: "/repo"}
}
