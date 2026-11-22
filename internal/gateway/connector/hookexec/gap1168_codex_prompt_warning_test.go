// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10 GAP-1168: a Codex session that was running when the gateway
// stopped, whose next turn is a prompt with no tool call, showed no
// DefenseClaw warning: the prompt hook printed no systemMessage (Codex shows
// one for UserPromptSubmit), and the turn then failed on the stopped route
// with only Codex's "Reconnecting". The prompt now carries the warning; the
// once-per-session marker keeps a session at one. The closed tier still
// blocks the prompt and prints no allow notice.
func TestGAP1168RunningCodexPromptShowsTheOutageWarning(t *testing.T) {
	const warning = "DefenseClaw is not checking this session"
	sp, ok := specFor("codex")
	if !ok {
		t.Fatal("codex spec missing")
	}
	run := func(home, session, event, tier string) (int, string) {
		var stdout, stderr bytes.Buffer
		opts := withPerUserOutage(Options{
			Connector: "codex", Event: event, Home: home,
			HookDir: filepath.Join(home, "hooks"), Stdout: &stdout, Stderr: &stderr,
			Now:               time.Now,
			OutageFailModeNow: func() string { return tier },
			failurePayload:    []byte(`{"session_id":"` + session + `"}`),
		})
		code := failUnreachable(opts, sp, "closed", "gateway unreachable")
		return code, stdout.String()
	}
	for _, tc := range []struct {
		name   string
		events []string
	}{
		{"prompt only", []string{"UserPromptSubmit"}},
		{"prompt, tool call, prompt", []string{"UserPromptSubmit", "PreToolUse", "UserPromptSubmit"}},
		{"new session", []string{"SessionStart", "UserPromptSubmit", "PreToolUse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			warnings := 0
			for i, event := range tc.events {
				code, out := run(home, "gap1168", event, "open")
				if code != 0 {
					t.Fatalf("call %d (%s) exit %d", i, event, code)
				}
				if i == 0 && !strings.Contains(out, `"systemMessage"`) {
					t.Fatalf("the first event (%s) of the outage shows no warning: %q", event, out)
				}
				warnings += strings.Count(out, warning)
			}
			if warnings != 1 {
				t.Fatalf("%d warnings over %v, want 1", warnings, tc.events)
			}
		})
	}
	t.Run("closed tier blocks the prompt", func(t *testing.T) {
		code, out := run(t.TempDir(), "gap1168-closed", "UserPromptSubmit", "closed")
		if code == 0 && !strings.Contains(out, `"decision":"block"`) {
			t.Fatalf("the closed tier let the prompt through: code=%d %q", code, out)
		}
		if strings.Contains(out, warning) {
			t.Fatalf("a blocked prompt carries the allow notice: %q", out)
		}
	})
}
