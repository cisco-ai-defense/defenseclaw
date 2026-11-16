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

// GAP-1352: in a session that was running when the gateway stopped, the
// first outage event (a Codex prompt, a Claude Code PostToolUse or Stop)
// cannot show a systemMessage. It took the once-per-session marker anyway,
// so the session never saw a warning. Only an event that shows the warning
// takes the marker: exactly one warning, whichever event comes first.
func TestNativeOutageWarningWaitsForAnEventThatShowsIt(t *testing.T) {
	for _, tc := range []struct {
		connector string
		events    []string
	}{
		{"codex", []string{"UserPromptSubmit", "Stop", "PreToolUse", "PreToolUse"}},
		{"claudecode", []string{"PostToolUse", "Stop", "UserPromptSubmit", "PreToolUse"}},
		{"claudecode", []string{"PostToolUse", "PreToolUse", "PreToolUse"}},
	} {
		t.Run(tc.connector+"/"+strings.Join(tc.events, ","), func(t *testing.T) {
			sp, ok := specFor(tc.connector)
			if !ok {
				t.Fatalf("%s spec missing", tc.connector)
			}
			home := t.TempDir()
			warnings := 0
			for i, event := range tc.events {
				var stdout, stderr bytes.Buffer
				opts := withPerUserOutage(Options{
					Connector: tc.connector, Event: event, Home: home,
					HookDir: filepath.Join(home, "hooks"), Stdout: &stdout, Stderr: &stderr,
					Now:               time.Now,
					OutageFailModeNow: func() string { return "open" },
					failurePayload:    []byte(`{"session_id":"running-session"}`),
				})
				if code := failUnreachable(opts, sp, "closed", "gateway unreachable"); code != 0 {
					t.Fatalf("call %d (%s) exit %d", i, event, code)
				}
				// Claude Code and Codex show only the systemMessage on stdout of an
				// exit-0 allow; a stderr line is not a warning the user sees.
				warnings += strings.Count(stdout.String(), "DefenseClaw is not checking this session")
			}
			if warnings != 1 {
				t.Fatalf("%d outage warnings over %v, want exactly 1", warnings, tc.events)
			}
		})
	}
}
