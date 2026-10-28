// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1771: the alert-only destructive SQL detection listed psql, mysql,
// mariadb and sqlcmd but not snowsql, so a destructive snowsql query was
// silent in the shipped profiles while the same psql query alerted. It now
// alerts the same way in every profile, and stays alert-only (no block).
func TestSnowSQLDestructiveMutationAlertsLikePsqlInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.BlockAt = "HIGH"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			for _, command := range []string{
				"psql -c 'DROP SCHEMA r25sa_fixture'",
				"snowsql -q 'DROP SCHEMA r25sa_fixture'",
				"snowsql -c prod -o friendly=false -q 'TRUNCATE TABLE events'",
			} {
				response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
					t.Context(),
					codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      "Bash",
						CWD:           "/repo",
						ToolInput:     map[string]interface{}{"command": command},
					},
				)
				if response.Action != guardrailActionAlert || response.WouldBlock ||
					!findingStringHasRuleID(response.Findings, sqlDestructiveMutationRuleID) {
					t.Fatalf("profile=%s command=%q response=%+v", profile, command, response)
				}
			}
		})
	}
}
