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

func t20cCodexBash(t *testing.T, pack, command string) codexHookResponse {
	t.Helper()
	// A POSIX host's Codex Bash call (CWD /repo): on a Windows host Codex runs
	// its shell in PowerShell (codexShellRunsPowerShell) and the hook adds its
	// PowerShell and cmd readings, which keep their own bound rule
	// (posixInputLimitCommand).
	previousHost, previousShell := windowsHookHost, codexShellRunsPowerShell
	windowsHookHost, codexShellRunsPowerShell = func() bool { return false }, false
	t.Cleanup(func() { windowsHookHost, codexShellRunsPowerShell = previousHost, previousShell })
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

// TestT20CSQLClientLongQueryIsRecordedNotRaised (DET111 ruling on FIX-T20B):
// a SQL client's inline query past the 4 KiB shell word bound is code to the
// server, so the call is recorded truncated in the decision, but the cut by
// itself raises nothing: a long benign query stays allowed in default and in
// strict, as at 1.0.10. The call is judged on the statements within the bound
// with their long literals and comments shortened, so a rule that matches
// there fires (a COPY ... PROGRAM with a 5000-byte identifier or a long
// trailing comment, a LOAD_FILE after a long comment). Red at a64bfdb931: no
// record, and those were a clean allow.
func TestT20CSQLClientLongQueryIsRecordedNotRaised(t *testing.T) {
	big := strings.Repeat("a", 5000)
	recorded := func(r codexHookResponse) bool {
		return slices.ContainsFunc(r.Findings, func(f string) bool {
			return strings.Contains(f, "SQL client inline query past the shell word bound")
		})
	}
	for _, command := range []string{
		`psql -d production -c "SELECT '` + big + `' AS note"`,
		`mysql -h db -e "INSERT INTO notes (body) VALUES ('` + big + `')"`,
		`psql -d production -c "` + strings.Repeat("SELECT 1; ", 600) + `"`,
		`sqlcmd -S db -Q "SELECT '` + big + `'"`,
	} {
		for _, pack := range []string{"default", "strict"} {
			if r := t20cCodexBash(t, pack, command); r.Action != "allow" || !recorded(r) {
				t.Errorf("benign %s len=%d: action=%s findings=%v, want allow with the query cut record",
					pack, len(command), r.Action, r.Findings)
			}
		}
	}
	for _, row := range []struct{ command, rule string }{
		{`psql -d production -c "COPY \"` + big + `\" (c) TO PROGRAM 'id'"`, postgreSQLCopyProgramRuleID},
		{`psql -d production -c "COPY t (c) TO PROGRAM 'id' /* ` + big + ` */"`, postgreSQLCopyProgramRuleID},
		{"mysql -h db -e \"-- " + big + "\nSELECT LOAD_FILE('/etc/shadow') AS a\"", "secrets.sql_sensitive_server_file_read"},
	} {
		for _, pack := range []string{"default", "strict"} {
			r := t20cCodexBash(t, pack, row.command)
			if r.Action == "allow" || !findingStringHasRuleID(r.Findings, row.rule) {
				t.Errorf("%s %q: action=%s findings=%v, want %s", pack, row.command[:60], r.Action, r.Findings, row.rule)
			}
		}
	}
}
