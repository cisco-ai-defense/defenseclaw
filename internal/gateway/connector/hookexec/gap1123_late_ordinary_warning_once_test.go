// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10 GAP-1123: in a turn on a frozen gateway Claude Code showed the
// outage warning twice, at UserPromptSubmit and again at PreToolUse:Bash.
// The tool call's ordinary allow is the watchdog's answer at the deadline,
// rendered ahead of time without the once-per-session marker (GAP-1352), so
// it always carried the warning. It now takes the marker when it is given:
// one warning per session, whichever event shows it first. The decision is
// unchanged: an ordinary call in the open tier runs, a call that may reach a
// protected file and every call of the closed tier stay blocked.
func TestGAP1123LateOrdinaryAllowWarnsOncePerSession(t *testing.T) {
	const warning = "DefenseClaw is not checking this session"
	sp, _ := specFor("claudecode")
	home := t.TempDir()
	project := t.TempDir()
	call := func(t *testing.T, session, command, tier string) (int, string) {
		t.Helper()
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := perUserRestartOptions(home, tier, false, stdout, stderr, func(code int) { exited <- code })
		opts.lateOrdinary = func() bool { return true }
		payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "cwd": project,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		opts.failurePayload = payload
		ordinary := bothLateScansOrdinary(opts)
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		w.noDecisionPending()
		w.mu.Lock()
		w.lookGen++
		gen := w.lookGen
		w.mu.Unlock()
		w.startOrdinaryLook(gen, opts, sp, "open")
		if ordinary && tier == "open" {
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				w.mu.Lock()
				ready := w.ordinary != nil
				w.mu.Unlock()
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the ordinary answer was never prepared")
				}
			}
		}
		return fireAnswerDeadline(t, w, exited, stdout, stderr)
	}

	t.Run("prompt warned first", func(t *testing.T) {
		// The prompt hook of the turn showed the warning and took the marker.
		prompt := perUserRestartOptions(home, "open", false, newClaimedStopWriter(), newClaimedStopWriter(), func(int) {})
		prompt.failurePayload = []byte(`{"session_id":"gap1123-a"}`)
		if !firstOutageWarning(prompt) {
			t.Fatal("the prompt could not take the warning marker")
		}
		code, shown := call(t, "gap1123-a", "git status", "open")
		if nativeOutageBlocked(runResult{code: code, stdout: shown}) {
			t.Fatalf("an ordinary call was blocked in the open tier: code=%d %q", code, shown)
		}
		if strings.Contains(shown, warning) {
			t.Fatalf("the tool call warned again in a session that already saw the warning: %q", shown)
		}
	})
	t.Run("tool call warns once", func(t *testing.T) {
		warnings := 0
		for i := 0; i < 2; i++ {
			code, shown := call(t, "gap1123-b", "git status", "open")
			if nativeOutageBlocked(runResult{code: code, stdout: shown}) {
				t.Fatalf("call %d: an ordinary call was blocked in the open tier: code=%d %q", i, code, shown)
			}
			warnings += strings.Count(shown, warning)
		}
		if warnings != 1 {
			t.Fatalf("%d warnings over two calls of one session, want 1", warnings)
		}
	})
	for _, tc := range []struct {
		name, command, tier string
	}{
		{"keys file, open tier", "cat .ssh/authorized_keys", "open"},
		{"ordinary call, closed tier", "git status", "closed"},
	} {
		t.Run(tc.name+" stays blocked", func(t *testing.T) {
			code, shown := call(t, "gap1123-c", tc.command, tc.tier)
			if !nativeOutageBlocked(runResult{code: code, stdout: shown}) {
				t.Fatalf("not blocked: code=%d %q", code, shown)
			}
		})
	}
}
