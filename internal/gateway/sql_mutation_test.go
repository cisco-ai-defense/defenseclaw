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

const sqlDestructiveMutationRuleID = "impact.sql_destructive_mutation"

func TestSQLDestructiveMutationSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticSQLDestructiveMutationExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[sqlDestructiveMutationRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := actionfacts.Input{Tool: "shell", Command: "psql -d production -c 'DELETE FROM customers;'"}
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact mutation not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: input.Command, EnforcementCapable: true,
	})
	matched := findingWithID(findings, sqlDestructiveMutationRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestSQLDestructiveMutationAlertsWithoutBlockingInEveryProfile(t *testing.T) {
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
						"connection": "postgresql://db.invalid/production",
						"database":   "production",
						"query":      "TRUNCATE TABLE scratch.events",
					},
				},
			)
			if response.Action != guardrailActionAlert || response.RawAction != guardrailActionAlert ||
				response.Severity != "HIGH" || response.WouldBlock ||
				!findingStringHasRuleID(response.Findings, sqlDestructiveMutationRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestSQLDestructiveMutationHardNegativesSuppressFallback(t *testing.T) {
	tests := []actionfacts.Input{
		{Tool: "shell", Command: "psql -c 'DELETE FROM customers WHERE id = 7'"},
		{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK'"},
		{Tool: "shell", Command: "psql --file migration.sql -c 'DELETE FROM customers'"},
		{Tool: "shell", Command: `printf '%s\n' "psql -c 'DELETE FROM customers'"`},
		structuredSQLMutationInput(t, "SELECT 'DROP DATABASE production'"),
		structuredSQLMutationInput(t, "EXPLAIN DELETE FROM customers"),
	}
	for _, input := range tests {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: input.Command, EnforcementCapable: true,
		})
		if findingWithID(findings, sqlDestructiveMutationRuleID) != nil {
			t.Fatalf("input=%+v produced owner finding: %v", input, FindingStrings(findings))
		}
	}
}

func TestStructuredDBExecutePolicyBoundaries(t *testing.T) {
	input := func(query string) actionfacts.Input {
		return actionfacts.Input{
			Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":` +
				string(mustJSON(t, query)) + `}`),
			ToolResourceIdentity: "mcp://database/synthetic-production",
		}
	}

	truncate := actionfacts.Analyze(input("TRUNCATE TABLE audit_log"))
	deleteAll := actionfacts.Analyze(input("DELETE FROM sessions"))
	dropTable := actionfacts.Analyze(input("DROP TABLE obsolete_records"))
	bounded := actionfacts.Analyze(input("DELETE FROM sessions WHERE id = 7"))
	if !sqlSchemaDestroyPrerequisite(truncate) || !sqlUnboundedDeletePrerequisite(deleteAll) {
		t.Fatalf("protected database operations were not recognized: truncate=%+v delete=%+v", truncate, deleteAll)
	}
	if sqlSchemaDestroyPrerequisite(dropTable) || sqlUnboundedDeletePrerequisite(dropTable) {
		t.Fatalf("standalone DROP TABLE must remain alert-only: %+v", dropTable)
	}
	if sqlDestructiveMutationPrerequisite(bounded) {
		t.Fatalf("bounded DELETE produced destructive mutation: %+v", bounded)
	}
}

func structuredSQLMutationInput(t *testing.T, query string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"connection": "postgresql://db.invalid/production",
		"database":   "production",
		"query":      query,
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "sql_query", Args: raw, CWD: "/repo"}
}
