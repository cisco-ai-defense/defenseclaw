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
//
// rel-1-0-10 GAP-1187: an install that holds the lock at the deadline closes
// that ordinary answer too, also for a call whose gateway took it and owes
// its decision (the install check needed !closedKnown, which such a call has
// set, while the ordinary answer still replaced the closed one).
func TestGAP1123LateOrdinaryAllowWarnsOncePerSession(t *testing.T) {
	const warning = "DefenseClaw is not checking this session"
	sp, _ := specFor("claudecode")
	home := t.TempDir()
	project := t.TempDir()
	call := func(t *testing.T, home, session, command, tier string, pending, install bool) (int, string) {
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
		if pending {
			// The gateway took the call and owes its decision.
			w.noDecisionPending()
		}
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
		if install {
			// This account's installer took the lock during the call.
			mkdirInstallLock(t, home)
		}
		return fireAnswerDeadline(t, w, exited, stdout, stderr)
	}

	for _, pending := range []bool{true, false} {
		name := map[bool]string{true: "pending decision/", false: "no decision pending/"}[pending]
		t.Run(name+"prompt warned first", func(t *testing.T) {
			// The prompt hook of the turn showed the warning and took the marker.
			session := "gap1123-a-" + name
			prompt := perUserRestartOptions(home, "open", false, newClaimedStopWriter(), newClaimedStopWriter(), func(int) {})
			prompt.failurePayload = []byte(`{"session_id":"` + session + `"}`)
			if !firstOutageWarning(prompt) {
				t.Fatal("the prompt could not take the warning marker")
			}
			code, shown := call(t, home, session, "git status", "open", pending, false)
			if nativeOutageBlocked(runResult{code: code, stdout: shown}) {
				t.Fatalf("an ordinary call was blocked in the open tier: code=%d %q", code, shown)
			}
			if strings.Contains(shown, warning) {
				t.Fatalf("the tool call warned again in a session that already saw the warning: %q", shown)
			}
		})
		t.Run(name+"tool call warns once", func(t *testing.T) {
			warnings := 0
			for i := 0; i < 2; i++ {
				code, shown := call(t, home, "gap1123-b-"+name, "git status", "open", pending, false)
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
			install             bool
		}{
			{"keys file, open tier", "cat .ssh/authorized_keys", "open", false},
			{"ordinary call, closed tier", "git status", "closed", false},
			// rel-1-0-10 GAP-1187: an install that took the lock during the
			// call closes the ordinary answer, also of a call whose gateway
			// owes its decision.
			{"ordinary call, install window", "git status", "open", true},
		} {
			t.Run(name+tc.name+" stays blocked", func(t *testing.T) {
				callHome := home
				if tc.install {
					callHome = t.TempDir()
				}
				code, shown := call(t, callHome, "gap1123-c-"+name, tc.command, tc.tier, pending, tc.install)
				if !nativeOutageBlocked(runResult{code: code, stdout: shown}) {
					t.Fatalf("not blocked: code=%d %q", code, shown)
				}
			})
		}
	}
}
