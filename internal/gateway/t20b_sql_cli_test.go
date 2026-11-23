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

// TestT20BPsqlLongQueryIsTruncated (DET111 T20 review, psql -c long
// identifier): psql -c with a COPY ... PROGRAM whose identifier is past the
// 4 KiB shell word bound was a clean allow with only the detection-only data
// word record at 1.0.10, 17170c4ab4 and 06f1da5b94. The query is code in the
// client's grammar, so the call is TRUNCATED: an alert in default, a block in
// strict. A short query keeps its exec.postgresql_copy_program HIGH finding.
// Red at 06f1da5b94.
func TestT20BPsqlLongQueryIsTruncated(t *testing.T) {
	long := strings.Repeat("a", 5000)
	for _, command := range []string{
		`psql -d production -c "COPY \"` + long + `\" (c) TO PROGRAM 'id'"`,
		`psql -d production -c "COPY \"` + long + `\" TO PROGRAM 'id'"`,
	} {
		for pack, want := range map[string]string{"default": "alert", "strict": "block"} {
			r := t20bCodexBash(t, pack, command)
			truncated := slices.ContainsFunc(r.Findings, func(f string) bool {
				return strings.Contains(f, "bounded_truncated") && !strings.Contains(f, posixDataWordTitle)
			})
			if r.Action != want || !truncated {
				t.Errorf("%s len=%d: action=%s findings=%v, want %s with a truncated finding",
					pack, len(command), r.Action, r.Findings, want)
			}
		}
	}
	r := t20bCodexBash(t, "default", `psql -d production -c "COPY \"short\" (c) TO PROGRAM 'id'"`)
	if r.Action != "alert" || r.Severity != "HIGH" || !findingStringHasRuleID(r.Findings, postgreSQLCopyProgramRuleID) {
		t.Errorf("short: action=%s severity=%s findings=%v, want %s alert HIGH", r.Action, r.Severity, r.Findings, postgreSQLCopyProgramRuleID)
	}
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
