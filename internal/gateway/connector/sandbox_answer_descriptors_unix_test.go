// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"regexp"
	"strings"
	"testing"
)

var traceFDWarning = regexp.MustCompile(`(?m)^\S*bash: BASH_XTRACEFD: [0-9]+: cannot open as FILE\n`)

// GAP-1769 (RV-OP2E): unsetting BASH_XTRACEFD closes the descriptor it names.
// _sandbox.sh dropped an exported BASH_XTRACEFD with the other inherited
// variables, so a workload that exported BASH_XTRACEFD=1 closed the hook's
// stdout (2: stderr, 0: stdin) before the hook answered: the Codex hook ended
// with exit 0 and nothing printed, which Codex reads as an allow, and a
// harness that answers its verdict on stdout lost it. The scrub now only drops
// the export bit, so the export changes no answer of any sandbox harness: an
// outage, a policy block and the harness's own block verdict.
func TestSandboxHooksAnswerWithAnExportedTraceDescriptor(t *testing.T) {
	const reason = "nope"
	verdicts := map[string]string{
		"claudecode":  `"claude_code_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`,
		"codex":       `"codex_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`,
		"copilot":     `"hook_output":{"permissionDecision":"deny","permissionDecisionReason":"nope"}`,
		"cursor":      `"hook_output":{"permission":"deny","user_message":"nope","agent_message":"nope"}`,
		"kiro":        `"hook_output":{"decision":"block","reason":"nope"}`,
		"devin":       `"hook_output":{"decision":"block","reason":"nope"}`,
		"hermes":      `"hook_output":{"decision":"block","reason":"nope"}`,
		"antigravity": `"hook_output":{"decision":"deny","reason":"nope"}`,
	}
	token := map[string]string{SandboxTokenEnv: "tok"}
	harnesses := 0
	for _, tc := range sandboxHookCases() {
		if !tc.lifecycle {
			continue
		}
		verdict, ok := verdicts[tc.connector]
		if !ok {
			t.Fatalf("no block verdict for sandbox harness %s", tc.connector)
		}
		harnesses++
		h := newSandboxHookHarness(t, tc.provider, tc.version)
		script := SandboxHookDir + "/" + tc.script
		for name, reply := range map[string][]string{
			"ingress-down":  {"exit:7", "exit:7"},
			"policy-block":  {`200|{"action":"block","reason":"` + reason + `"}`},
			"verdict-block": {`200|{"action":"block","reason":"` + reason + `",` + verdict + `}`},
		} {
			want := h.run(t, script, tc.args, tc.stdin, token, reply)
			// A block under the harness's contract, or its verdict on stdout
			// with exit 0 (Claude Code, Copilot, Antigravity, Codex).
			if !tc.blocked(want) && (want.exitCode != 0 || !strings.Contains(want.stdout, `"deny"`) && !strings.Contains(want.stdout, `"block"`)) {
				t.Fatalf("%s/%s: control run is no block: exit %d stdout %q stderr %q", tc.connector, name, want.exitCode, want.stdout, want.stderr)
			}
			for _, fd := range []string{"0", "1", "2"} {
				t.Run(tc.connector+"/"+name+"/BASH_XTRACEFD="+fd, func(t *testing.T) {
					env := map[string]string{SandboxTokenEnv: "tok", "BASH_XTRACEFD": fd}
					got := h.run(t, script, tc.args, tc.stdin, env, reply)
					// bash itself warns at startup when the descriptor is not
					// writable (stdin): that line is not the hook's.
					stderr := traceFDWarning.ReplaceAllString(got.stderr, "")
					if got.exitCode != want.exitCode || got.stdout != want.stdout || (stderr == "") != (want.stderr == "") || len(got.calls) != len(want.calls) {
						t.Fatalf("exit %d calls %d stdout %q stderr %q; without the export: exit %d calls %d stdout %q stderr %q",
							got.exitCode, len(got.calls), got.stdout, got.stderr, want.exitCode, len(want.calls), want.stdout, want.stderr)
					}
				})
			}
		}
	}
	if harnesses != len(sandboxHookScriptsByConnector) {
		t.Fatalf("checked %d sandbox harnesses, want all %d", harnesses, len(sandboxHookScriptsByConnector))
	}
}
