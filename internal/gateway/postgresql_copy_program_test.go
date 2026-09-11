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

const postgreSQLCopyProgramRuleID = "exec.postgresql_copy_program"

func TestPostgreSQLCopyProgramSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticPostgreSQLCopyProgramExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[postgreSQLCopyProgramRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := postgreSQLCopyProgramInput(t, "COPY (SELECT 1) TO PROGRAM 'id';")
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact structured action not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, Connector: "", EnforcementCapable: true,
	})
	matched := findingWithID(findings, postgreSQLCopyProgramRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestPostgreSQLCopyProgramAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(),
				codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "sql_query",
					CWD:           "/repo",
					ToolInput: map[string]interface{}{
						"connection": "postgresql://db.invalid:5432/production",
						"database":   "production",
						"query":      "COPY (SELECT 1) TO PROGRAM 'id';",
					},
				},
			)
			if response.Action != guardrailActionAlert ||
				response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, postgreSQLCopyProgramRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestPostgreSQLCopyProgramSafeNegativesDoNotUseRegexFallback(t *testing.T) {
	for _, query := range []string{
		"COPY events TO STDOUT",
		"COPY events TO '/tmp/events.csv'",
		"SELECT 'COPY events TO PROGRAM ''id'''",
		"COPY events TO PROGRAM command_text",
		"COPY events TO PROGRAM 'id'; SELECT 1",
	} {
		input := postgreSQLCopyProgramInput(t, query)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: query, EnforcementCapable: true,
		})
		if findingWithID(findings, postgreSQLCopyProgramRuleID) != nil {
			t.Fatalf("query=%q produced owner finding: %v", query, FindingStrings(findings))
		}
	}
}

func postgreSQLCopyProgramInput(t *testing.T, query string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"connection": "postgresql://db.invalid:5432/production",
		"database":   "production",
		"query":      query,
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "sql_query", Args: raw, CWD: "/repo"}
}
