// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cowork-1-0-8 GAP-0040: only Claude Code's interactive terminal shows a
// SessionStart systemMessage; Claude Cowork, the IDE extensions and claude -p
// drop it. The native runner's per-user outage warning skips SessionStart and
// goes on the session's first prompt or tool call, once; every call allows.
func TestNativeClaudeOutageWarningSkipsSessionStart(t *testing.T) {
	sp, ok := specFor("claudecode")
	if !ok {
		t.Fatal("claudecode spec missing")
	}
	for _, events := range [][]string{
		{"SessionStart", "UserPromptSubmit", "PreToolUse", "PreToolUse"},
		{"SessionStart", "PreToolUse", "UserPromptSubmit"},
	} {
		t.Run(strings.Join(events, ","), func(t *testing.T) {
			home := t.TempDir()
			for i, event := range events {
				var stdout, stderr bytes.Buffer
				opts := withPerUserOutage(Options{
					Connector: "claudecode", Event: event, Home: home,
					HookDir: filepath.Join(home, "hooks"), Stdout: &stdout, Stderr: &stderr,
					Now:               time.Now,
					OutageFailModeNow: func() string { return "open" },
					failurePayload:    []byte(`{"session_id":"cowork-session"}`),
				})
				if code := failUnreachable(opts, sp, "closed", "gateway unreachable"); code != 0 {
					t.Fatalf("call %d (%s) exit %d, want a fail-open allow", i, event, code)
				}
				out := strings.TrimSpace(stdout.String())
				warned := strings.Contains(out, "DefenseClaw is not checking this session")
				if want := i == 1; warned != want {
					t.Fatalf("call %d (%s) warned=%v, want %v; stdout %q", i, event, warned, want, out)
				}
				if !warned {
					continue
				}
				var body map[string]any
				if err := json.Unmarshal([]byte(out), &body); err != nil || len(body) != 1 || body["systemMessage"] == nil {
					t.Fatalf("call %d (%s) stdout %q, want only a systemMessage (no decision)", i, event, out)
				}
			}
		})
	}
}
