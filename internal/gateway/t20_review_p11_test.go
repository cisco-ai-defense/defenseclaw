// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestT20LongSQLIdentifierKeepsSemanticRules (DET111 T20 review P1-1): an
// over-size quoted SQL identifier no longer fails the projection for the
// whole call, so COPY ... TO PROGRAM keeps exec.postgresql_copy_program
// (alert HIGH in default, as at 17170c4ab4) through the structured sql_query
// tool (the reviewer's input). On the psql -c CLI path a word that long is
// past the shell analysis bound first (TRUNCATED). Red at 23ee0d55e2.
func TestT20LongSQLIdentifierKeepsSemanticRules(t *testing.T) {
	long := strings.Repeat("a", 5000)
	const connector = "codex"
	installToolCallCorpusProfileConnector(t, connector, "default")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	for _, query := range []string{
		`COPY "short" (c) TO PROGRAM 'id'`,
		`COPY "` + long + `" (c) TO PROGRAM 'id'`,
		`COPY "` + long + `" TO PROGRAM 'id'`,
	} {
		response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "sql_query", CWD: "/repo",
			ToolInput: map[string]interface{}{
				"connection": "postgresql://db.invalid:5432/production",
				"database":   "production", "query": query,
			},
		})
		if response.Action == "allow" || response.Severity != "HIGH" ||
			!findingStringHasRuleID(response.Findings, postgreSQLCopyProgramRuleID) {
			t.Errorf("len=%d: action=%s severity=%s findings=%v, want %s alert HIGH",
				len(query), response.Action, response.Severity, response.Findings, postgreSQLCopyProgramRuleID)
		}
	}
}
