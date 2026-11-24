// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-2175 (CHK-ENTWIN-R): the GAP-1801 (a) preflight deferred an HKLM hooks
// table to enrolment only when its text named "defenseclaw". Enrolment
// matches the handler's command by file identity (pathidentity.Same) and its
// arguments with hook --connector claudecode [--enterprise-managed], so a
// matrix that names the installed hook by an alias (an 8.3 short path, a hard
// link) was admitted by 1.0.10 and refused by the preflight, which stopped an
// upgrade, ensure or repair of that computer. The preflight now also defers a
// table with a handler whose arguments are DefenseClaw's hook arguments; a
// table with neither still is refused at once.
func TestGAP2175PreflightDefersAMatrixThatNamesTheHookByAnAlias(t *testing.T) {
	label := `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	handler := func(command, args string) string {
		return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + command + `","args":[` + args + `]}]}]}}`
	}
	for name, value := range map[string]string{
		"8.3 short path, managed": handler(`C:\\PROGRA~1\\Cisco\\DEFENS~1\\bin\\DEFENS~1.EXE`, `"hook","--connector","claudecode","--enterprise-managed"`),
		"8.3 short path":          handler(`C:\\PROGRA~1\\Cisco\\DEFENS~1\\bin\\DEFENS~1.EXE`, `"hook","--connector","claudecode"`),
		"hard link elsewhere":     handler(`C:\\Tools\\hk.exe`, `"hook","--connector","claudecode","--enterprise-managed"`),
	} {
		if err := ClaudeCodeOSAdminPolicyPreflight(value, label); err != nil {
			t.Errorf("%s: a matrix enrolment may admit was refused by the preflight: %v", name, err)
		}
	}
	for name, value := range map[string]string{
		"another connector": handler(`C:\\Tools\\hk.exe`, `"hook","--connector","codex"`),
		"an extra argument": handler(`C:\\Tools\\hk.exe`, `"hook","--connector","claudecode","--fail-open"`),
		"no arguments":      `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\Tools\\hk.exe hook --connector claudecode"}]}]}}`,
		"empty hooks table": `{"hooks":{"PreToolUse":[]}}`,
	} {
		if err := ClaudeCodeOSAdminPolicyPreflight(value, label); err == nil {
			t.Errorf("%s: a non-merging hooks table enrolment can never admit passed the preflight", name)
		}
	}
}
