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

const sqlSensitiveServerFileReadRuleID = "secrets.sql_sensitive_server_file_read"

func TestSQLSensitiveServerFileReadSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticSQLSensitiveServerFileReadExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[sqlSensitiveServerFileReadRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := gatewaySQLSensitiveServerFileReadInput(
		t,
		"mysql://analyst:placeholder@db.invalid:3306/app",
		"app",
		"SELECT LOAD_FILE('/etc/passwd');",
	)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact structured action not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, EnforcementCapable: true,
	})
	matched := findingWithID(findings, sqlSensitiveServerFileReadRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestSQLSensitiveServerFileReadAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		database   string
		query      string
	}{
		{
			name:       "mysql load file",
			connection: "mysql://analyst:placeholder@db.invalid:3306/app",
			database:   "app",
			query:      "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name:       "postgres binary read",
			connection: "postgresql://analyst:placeholder@db.invalid:5432/app",
			database:   "app",
			query:      "SELECT pg_read_binary_file('/etc/shadow');",
		},
		{
			name:       "mysql bare dsn alias",
			connection: "analyst:provided-by-secret-store@db.invalid:3306",
			query:      "SELECT LOAD_FILE('/etc/passwd') AS file_contents;",
		},
		{
			name:       "postgres space dsn copy select",
			connection: "host=db.invalid port=5432 dbname=app user=analyst",
			database:   "app",
			query:      "COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/server-copy';",
		},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		for _, test := range tests {
			test := test
			t.Run(profile+"/"+test.name, func(t *testing.T) {
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
							"connection": test.connection,
							"database":   test.database,
							"query":      test.query,
						},
					},
				)
				if response.Action != guardrailActionAlert ||
					response.RawAction != guardrailActionAlert ||
					response.Severity != "HIGH" || response.WouldBlock ||
					!findingStringHasRuleID(response.Findings, sqlSensitiveServerFileReadRuleID) {
					t.Fatalf("profile=%s response=%+v", profile, response)
				}
			})
		}
	}
}

func TestSQLSensitiveServerFileReadSourceTextMentionsDoNotCollide(t *testing.T) {
	mentions := []string{
		"Documentation example: SELECT LOAD_FILE('/etc/passwd');",
		"The string pg_read_file('/etc/shadow') appears in this source fixture.",
		"SELECT 'LOAD_FILE(''/etc/passwd'')';",
		"COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/server-copy';",
		"SELECT LOAD_FILE('/etc/passwd') AS file_contents;",
	}
	for _, mention := range mentions {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "shell", Command: "printf '%s' documentation", CWD: "/repo",
			},
			LegacyText: mention, EnforcementCapable: true,
		})
		if findingWithID(findings, sqlSensitiveServerFileReadRuleID) != nil {
			t.Fatalf("source-text mention produced finding: %v", FindingStrings(findings))
		}
	}
}

func TestSQLSensitiveServerFileReadNonSensitiveStructuredQueriesDoNotAlert(t *testing.T) {
	tests := []struct {
		connection string
		query      string
	}{
		{
			connection: "mysql://analyst@db.invalid:3306/app",
			query:      "SELECT LOAD_FILE('/tmp/test.txt');",
		},
		{
			connection: "host=db.invalid port=5432 dbname=app user=analyst",
			query:      "SELECT pg_read_file('/etc/hostname');",
		},
		{
			connection: "postgresql://analyst@db.invalid:5432/app",
			query:      "COPY (SELECT pg_read_file('/etc/hostname')) TO '/tmp/test.txt';",
		},
	}
	for _, test := range tests {
		input := gatewaySQLSensitiveServerFileReadInput(t, test.connection, "app", test.query)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: test.query, EnforcementCapable: true,
		})
		if findingWithID(findings, sqlSensitiveServerFileReadRuleID) != nil {
			t.Fatalf("non-sensitive structured query produced finding: %v", FindingStrings(findings))
		}
	}
}

func gatewaySQLSensitiveServerFileReadInput(
	t *testing.T,
	connection string,
	database string,
	query string,
) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{
		"connection": connection,
		"database":   database,
		"query":      query,
	})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "sql_query", Args: raw, CWD: "/repo"}
}
