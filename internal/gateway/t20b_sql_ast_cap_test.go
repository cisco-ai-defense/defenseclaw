// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestT20BSQLASTCapIsRecordedNotRaised (DET111 T20 review P3-1, DET111
// ruling): a SQL text past the SQL facts reader's bounds leaves a
// detection-only record in the decision and raises nothing by itself: a
// 300-statement benign query is allowed in default and strict, as at 1.0.10.
// At 06f1da5b94 the cap hit left no record. Red at 06f1da5b94.
func TestT20BSQLASTCapIsRecordedNotRaised(t *testing.T) {
	query := strings.Repeat("SELECT 1;", 300)
	const connector = "codex"
	for _, pack := range []string{"default", "strict"} {
		installToolCallCorpusProfileConnector(t, connector, pack)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
		r := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "sql_query", CWD: "/repo",
			ToolInput: map[string]interface{}{
				"connection": "postgresql://db.invalid:5432/production", "database": "production", "query": query,
			},
		})
		recorded := slices.ContainsFunc(r.Findings, func(f string) bool {
			return strings.Contains(f, "SQL text past the SQL facts bound")
		})
		if r.Action != "allow" || !recorded {
			t.Errorf("%s: action=%s severity=%s findings=%v, want allow with the SQL facts cap record", pack, r.Action, r.Severity, r.Findings)
		}
	}
}
