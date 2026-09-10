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

const sqlCommandUDFCreateRuleID = "exec.sql_command_udf_create"

func TestSQLCommandUDFCreateSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticSQLCommandUDFCreateExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[sqlCommandUDFCreateRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}

	input := sqlCommandUDFPostgreSQLInput(t,
		"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;",
	)
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact create not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, Connector: "", EnforcementCapable: true,
	})
	matched := findingWithID(findings, sqlCommandUDFCreateRuleID)
	if matched == nil || matched.Severity != "HIGH" ||
		matched.contributesToEnforcement() || !matched.contributesToAlertOnly() ||
		matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestSQLCommandUDFCreateAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		toolInput map[string]interface{}
	}{
		{
			name: "postgresql structured",
			tool: "sql_query",
			toolInput: map[string]interface{}{
				"connection": "postgresql://db.invalid:5432/production",
				"database":   "production",
				"query":      "CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;",
			},
		},
		{
			name: "mysql source shell",
			tool: "execute_command",
			toolInput: map[string]interface{}{
				"command": "mysql -u root -p'fixture-password' -e \"CREATE FUNCTION sys_exec RETURNS INT SONAME '/tmp/lib_mysqludf_sys.so';\"",
			},
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
						ToolName:      test.tool,
						CWD:           "/repo",
						ToolInput:     test.toolInput,
					},
				)
				if response.Action != guardrailActionAlert ||
					response.RawAction != guardrailActionAlert ||
					response.Severity != "HIGH" || response.WouldBlock ||
					!findingStringHasRuleID(response.Findings, sqlCommandUDFCreateRuleID) {
					t.Fatalf("profile=%s response=%+v", profile, response)
				}
			})
		}
	}
}

func TestSQLCommandUDFInvocationAndSafeNegativesDoNotAlert(t *testing.T) {
	inputs := []actionfacts.Input{
		sqlCommandUDFPostgreSQLInput(t, "SELECT exec_cmd('id');"),
		sqlCommandUDFPostgreSQLInput(t,
			"CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ return value.upper() $$ LANGUAGE plpython3u;"),
		sqlCommandUDFPostgreSQLInput(t,
			"CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ # import os; os.system(value) $$ LANGUAGE plpython3u;"),
		sqlCommandUDFPostgreSQLInput(t,
			`CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ note = 'import os and os.system('; return note $$ LANGUAGE plpython3u;`),
		sqlCommandUDFPostgreSQLInput(t,
			`CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ """import os; os.system(value)"""; return value $$ LANGUAGE plpython3u;`),
		sqlCommandUDFPostgreSQLInput(t,
			"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu; SELECT exec_cmd('id');"),
	}
	for _, input := range inputs {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(input.Args), EnforcementCapable: true,
		})
		if findingWithID(findings, sqlCommandUDFCreateRuleID) != nil {
			t.Fatalf("safe/non-atomic input produced owner finding: %v", FindingStrings(findings))
		}
	}
}

func sqlCommandUDFPostgreSQLInput(t *testing.T, query string) actionfacts.Input {
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
