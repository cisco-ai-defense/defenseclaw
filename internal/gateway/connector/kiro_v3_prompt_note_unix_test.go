// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// kiro-hook.sh answers a v3 prompt like the native runner
// (TestKiroV3PromptHookSaysNoCommandRan): an answered UserPromptSubmit from
// the .kiro/hooks config prints hookexec.KiroV3PromptCheckedNote, so Kiro v3
// does not add an empty "Output: ... Exit Code: 0" result the model reads as
// a command that already ran (rel-1-0-10:GAP-0248). A tool call, a block,
// the CLI 2.x agent config and a command that only quotes the event name
// keep stdout empty.
func TestKiroShellHookV3PromptSaysNoCommandRan(t *testing.T) {
	v3 := []string{"--hook-surface", "v3"}
	prompt := `{"hook_event_name":"UserPromptSubmit","session_id":"s1","cwd":"/tmp","prompt":"run echo hi"}`
	spaced := `{"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "run echo hi"}`
	tool := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"execute_bash","tool_input":{"command":"echo hi"}}`
	quoted := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"execute_bash","tool_input":{"command":"echo \"hook_event_name\":\"UserPromptSubmit\""}}`
	allow := `200|{"action":"allow"}`
	block := `200|{"action":"block","reason":"marker rule matched","hook_output":{"decision":"block","reason":"marker rule matched"}}`
	for _, tc := range []struct {
		name         string
		args         []string
		stdin, reply string
		code         int
		stdout       string
	}{
		{"v3 prompt allow", v3, prompt, allow, 0, hookexec.KiroV3PromptCheckedNote},
		{"v3 prompt, spaced JSON", v3, spaced, allow, 0, hookexec.KiroV3PromptCheckedNote},
		{"v3 prompt block", v3, prompt, block, 2, ""},
		{"v3 tool allow", v3, tool, allow, 0, ""},
		{"v3 tool that quotes the event name", v3, quoted, allow, 0, ""},
		{"2.x agent prompt allow", nil, prompt, allow, 0, ""},
	} {
		run := runPerUserHookForStop(t, NewKiroConnector(), "kiro-hook.sh", tc.args, tc.stdin, tc.reply)
		if run.code != tc.code || strings.TrimSpace(run.stdout) != tc.stdout {
			t.Errorf("%s: exit %d stdout %q, want exit %d stdout %q (stderr=%q)", tc.name, run.code, run.stdout, tc.code, tc.stdout, run.stderr)
		}
	}
}
