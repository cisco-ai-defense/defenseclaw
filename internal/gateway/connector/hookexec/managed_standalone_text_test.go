// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// A Unix standalone managed hook that fails closed says, in one line that
// starts with DefenseClaw, what it blocked (a prompt is not a tool call),
// why and what to do, with the internal reason code last in parentheses.
// Claude Code shows this stderr line as the block message; Codex, Devin and
// Cursor show the reason in their block body.
func TestManagedStandaloneFailClosedTextIsPlain(t *testing.T) {
	const unavailable = "the DefenseClaw gateway is not available. Try again in a moment; if this continues, contact your administrator."
	for _, tc := range []struct {
		name    string
		failure sessionStopCause
		ev      sessionStopEvent
		want    string
		body    bool
	}{
		{
			name:    "claude prompt, gateway unreachable",
			failure: sessionStopCauses[2],
			ev:      sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`},
			want:    "DefenseClaw blocked this prompt: " + unavailable + " (gateway unreachable)",
		},
		{
			name:    "codex prompt, gateway unreachable",
			failure: sessionStopCauses[2],
			ev:      sessionStopEvent{connector: "codex", event: "UserPromptSubmit"},
			want:    "DefenseClaw blocked this prompt: " + unavailable + " (gateway unreachable)",
			body:    true,
		},
	} {
		r, _ := runSessionStop(t, tc.failure, tc.ev, true)
		if got := strings.TrimSpace(r.stderr); got != tc.want {
			t.Fatalf("%s: stderr\n got %q\nwant %q", tc.name, got, tc.want)
		}
		if tc.body && !strings.Contains(r.stdout, mustJSONString(tc.want)) {
			t.Fatalf("%s: block body must carry the same text: %q", tc.name, r.stdout)
		}
		if strings.Contains(r.stderr, "claude-code tool") || strings.Contains(r.stderr, "token drift") {
			t.Fatalf("%s: internal wording leaked: %q", tc.name, r.stderr)
		}
	}
}

// Outside the standalone profile (Secure Client and every other managed
// hook) the fail-closed text is unchanged.
func TestManagedFailClosedTextOutsideStandaloneIsUnchanged(t *testing.T) {
	r, _ := runSessionStop(t, sessionStopCauses[0],
		sessionStopEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`}, false)
	if want := "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): enterprise_managed_hook_socket_missing"; strings.TrimSpace(r.stderr) != want {
		t.Fatalf("stderr = %q, want %q", r.stderr, want)
	}
	r, _ = runSessionStop(t, sessionStopCauses[0],
		sessionStopEvent{connector: "codex", event: "UserPromptSubmit"}, false)
	if want := `{"decision":"block","reason":"DefenseClaw hook failed closed"}`; strings.TrimSpace(r.stdout) != want {
		t.Fatalf("stdout = %q, want %q", r.stdout, want)
	}
}

func TestHookEventSubject(t *testing.T) {
	for event, want := range map[string]string{
		"beforeSubmitPrompt":  "prompt",
		"tool.execute.before": "tool call",
		"PostToolUse":         "tool result",
		"PreCompact":          "PreCompact event",
		"":                    "request",
	} {
		if got := hookEventSubject(event); got != want {
			t.Fatalf("hookEventSubject(%q) = %q, want %q", event, got, want)
		}
	}
}
