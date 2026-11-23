// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func t20bCodexBash(t *testing.T, pack, command string) codexHookResponse {
	t.Helper()
	const connector = "codex"
	installToolCallCorpusProfileConnector(t, connector, pack)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	return (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash", CWD: "/repo",
		ToolInput: map[string]interface{}{"command": command},
	})
}

// TestT20BSQLCLIServerRulesCoverMoreClients (DET111 T20 review P3-3): the
// COPY ... PROGRAM and sensitive server file read rules fire for a second
// -c, a second psql command and mysql or mariadb -e LOAD_FILE, not only one
// psql command. Red at 06f1da5b94.
func TestT20BSQLCLIServerRulesCoverMoreClients(t *testing.T) {
	for _, row := range []struct{ command, rule string }{
		{`psql -d production -c "SELECT 1" -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{`psql -d production -c "SELECT 1" && psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{`mysql -h db -e "SELECT LOAD_FILE('/etc/shadow')"`, "secrets.sql_sensitive_server_file_read"},
		{`mariadb -h db --execute="SELECT LOAD_FILE('/etc/passwd')"`, "secrets.sql_sensitive_server_file_read"},
	} {
		r := t20bCodexBash(t, "default", row.command)
		if r.Action == "allow" || !findingStringHasRuleID(r.Findings, row.rule) {
			t.Errorf("%q: action=%s findings=%v, want %s", row.command, r.Action, r.Findings, row.rule)
		}
	}
	for _, benign := range []string{
		`psql -d production -c "SELECT 1" -c "SELECT count(*) FROM t"`,
		`mysql -h db -e "SELECT 1"`,
	} {
		if r := t20bCodexBash(t, "default", benign); r.Action != "allow" {
			t.Errorf("benign %q: action=%s findings=%v, want allow", benign, r.Action, r.Findings)
		}
	}
}
