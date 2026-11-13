// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// run --task printed Claude Code's raw stream-json events (seen live on the
// stk stack, TST-0335). A person sees the agent's text and its tool calls.
func TestTaskOutputShowsTheAgentsText(t *testing.T) {
	lines := []string{
		`{"type":"system","subtype":"init","cwd":"/work","session_id":"s1","tools":["Bash"]}`,
		`{"type":"system","subtype":"thinking_tokens","estimated_tokens":50,"session_id":"s1"}`,
		`{"type":"assistant","message":{"model":"claude-haiku-5-5","content":[{"type":"thinking","thinking":"","signature":"AAAA"}]},"session_id":"s1"}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"f7-task.txt"}}]},"session_id":"s1"}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"ok"}]},"session_id":"s1"}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"Created f7-task.txt.\n\nfinished\u001b]52;c;AAAA\u0007"}]},"session_id":"s1"}`,
		`{"type":"result","subtype":"success","is_error":false,"result":"Created f7-task.txt.\n\nfinished","session_id":"s1"}`,
		`plain output from another agent`,
		`{"not":"an agent event"}`,
	}
	var out, errw bytes.Buffer
	emit := TextEmitter(&out, &errw)
	for _, l := range lines {
		emit(relay.TaskEvent{Type: "stdout", Data: l})
	}
	got := out.String()
	want := "> Write\nCreated f7-task.txt.\n\nfinished\nplain output from another agent\n{\"not\":\"an agent event\"}\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "session_id") || strings.Contains(got, "\x1b") {
		t.Errorf("raw events or controls reached the terminal: %q", got)
	}
	out.Reset()
	emit(relay.TaskEvent{Type: "stdout", Data: `{"type":"result","subtype":"error_max_turns","is_error":true,"result":"","session_id":"s1"}`})
	if !strings.Contains(out.String(), "the agent stopped: error_max_turns") {
		t.Errorf("an error result must show: %q", out.String())
	}
}
