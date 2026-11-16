// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// TestCredentialOperandKeepsItsVerdictInEveryShellToolShape is GAP-1072: a
// managed Codex exec_command call (tool_input cmd and workdir) that named a
// credential file in a statement of more argv words than the analysis reads
// was allowed with no finding, while the same command in the Claude Code Bash
// shape was blocked. The workdir places the call in a folder of the home of
// the user, which a managed gateway cannot read, and the statement-bounded
// reading left out only the names a read showed to be no link, so it left
// out none and its statement stayed past the argv bound. The Codex shell
// tool shapes now get the short-list verdict, managed and per-user, past the
// argv bound and past the operand bound, as the Claude Code Bash shape does
// (TestCredentialOperandKeepsItsVerdictPastTheArgvBound); the ordinary twins
// keep theirs.
func TestCredentialOperandKeepsItsVerdictInEveryShellToolShape(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	type shape struct {
		name, connector string
		payload         func(command string) []byte
	}
	codex := func(tool, key string) func(string) []byte {
		return func(command string) []byte {
			return mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": f.project,
				"tool_name": tool, "tool_use_id": "call_b36", "tool_input": map[string]any{
					key: command, "workdir": f.project, "yield_time_ms": 10000, "max_output_tokens": 4000}})
		}
	}
	shapes := []shape{
		{"codex exec_command", "codex", codex("exec_command", "cmd")},
		{"codex shell", "codex", codex("shell", "command")},
	}
	rows := []struct{ name, command, want string }{
		{"touch 255 last", "touch " + gap0151Operands(255, "last", "~/.netrc"), "block"},
		{"touch 1025 last", "touch " + gap0151Operands(1025, "last", "~/.netrc"), "block"},
		{"touch 300 ordinary", "touch " + gap0151Operands(300, "none", ""), "allow"},
	}
	var payloads [][]byte
	var calls []*hookCall
	var wants []string
	for _, s := range shapes {
		for _, r := range rows {
			payload := s.payload(r.command)
			payloads = append(payloads, payload)
			for _, managed := range []bool{true, false} {
				calls = append(calls, &hookCall{name: fmt.Sprintf("%s %s managed=%v", s.name, r.name, managed),
					connector: s.connector, payload: payload, managed: managed})
				wants = append(wants, r.want)
			}
		}
	}
	headers := f.clientHeaders(t, payloads)
	for i, call := range calls {
		call.header = headers[i/2]
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		if call.verdict != wants[i] {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, wants[i])
		}
	}
}
