// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGAP0407OutageRecordMatchesDeliveredAnswer(t *testing.T) {
	for _, tc := range []struct {
		name              string
		stallOrdinary     bool
		installAtDeadline bool
		decisionPending   bool
	}{
		{name: "allowed outage first record"},
		{name: "allowed outage during ordinary log open", stallOrdinary: true},
		{name: "install window closes outage", installAtDeadline: true},
		{name: "pending retry restores no-answer record", decisionPending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
				t.Fatal(err)
			}
			var w *answerWatchdog
			if tc.stallOrdinary {
				stall := make(chan struct{})
				previous := openHookFailureLog
				openHookFailureLog = func(path string, flag int, perm os.FileMode) (*os.File, error) {
					if strings.HasSuffix(path, "hook-failures.jsonl") {
						<-stall
					}
					return previous(path, flag, perm)
				}
				defer func() {
					close(stall)
					select {
					case <-w.failureLog.done:
					case <-time.After(2 * time.Second):
						t.Error("failure log did not finish after the stall was released")
					}
					openHookFailureLog = previous
				}()
			}
			var output bytes.Buffer
			type result struct {
				code   int
				output string
				marker []byte
			}
			exited := make(chan result, 1)
			mode := "closed"
			opts := withDefaults(Options{
				Home: home, Event: "PreToolUse", FailMode: mode,
				Stdout: &output, Stderr: io.Discard,
				OutageFailModeNow: func() string { return "open" },
				Exit: func(code int) {
					marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
					exited <- result{code: code, output: output.String(), marker: marker}
				},
			})
			opts.failurePayload = []byte(`{"session_id":"review","tool_use_id":"outage-record"}`)
			sp := specs["claudecode"]
			deadline := time.Now().Add(450 * time.Millisecond)
			w = startAnswerWatchdog(&opts, sp, mode, deadline, deadline)
			w.perUserOutageSeen(opts, sp, mode, syscall.ECONNREFUSED)
			if tc.decisionPending {
				w.noDecisionPending()
			}
			if tc.installAtDeadline {
				w.mu.Lock()
				w.installCheck = func() bool { return true }
				w.mu.Unlock()
			}
			select {
			case got := <-exited:
				if blocked := claudeBlocked(runResult{code: got.code, stdout: got.output}); blocked != (tc.installAtDeadline || tc.decisionPending) {
					t.Fatalf("deadline answer disagrees with expected decision: blocked=%t code=%d", blocked, got.code)
				}
				reason, failMode, outcome := perUserGatewayRestartingReason, "open", "fail_open"
				if tc.installAtDeadline || tc.decisionPending {
					reason, failMode, outcome = perUserGatewayNoAnswerReason, "closed", "fail_closed"
				}
				if !bytes.Contains(got.marker, []byte(`"tool_id":"outage-record"`)) ||
					!bytes.Contains(got.marker, []byte(`"reason":"`+reason+`"`)) ||
					!bytes.Contains(got.marker, []byte(`"fail_mode":"`+failMode+`"`)) ||
					!bytes.Contains(got.marker, []byte(`"outcome":"`+outcome+`"`)) {
					t.Fatalf("outage answer has an incorrect record: %q", got.marker)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("watchdog did not exit at the answer deadline")
			}
		})
	}
}

func TestGAP0407BenignOnTimeAnswerStaysAllowed(t *testing.T) {
	home := t.TempDir()
	var output bytes.Buffer
	exited := make(chan struct{}, 1)
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "open",
		Stdout: &output, Stderr: io.Discard,
		Exit: func(int) { exited <- struct{}{} },
	})
	deadline := time.Now().Add(450 * time.Millisecond)
	w := startAnswerWatchdog(&opts, specs["claudecode"], "open", deadline, deadline)
	if code := w.Finish(0); claudeBlocked(runResult{code: code, stdout: output.String()}) {
		t.Fatalf("on-time answer was blocked: code=%d output=%q", code, output.String())
	}
	select {
	case <-exited:
		t.Fatal("watchdog answered after the on-time result")
	default:
	}
}
