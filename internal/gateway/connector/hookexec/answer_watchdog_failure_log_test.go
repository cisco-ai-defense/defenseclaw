// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGAP0407FailedOrdinaryAppendKeepsToolID(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(logDir, "hook-failures.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := withDefaults(Options{Home: home, Event: "PreToolUse", Stderr: io.Discard})
	opts.failurePayload = []byte(`{"session_id":"s","tool_call_id":"g407-recorded"}`)
	logHookFailure(opts, spec{connector: "claudecode", hookName: "claude-code-hook"},
		"gateway did not answer", "transport", "closed", true)
	data, err := os.ReadFile(filepath.Join(logDir, "hook-failures.dropped"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("DCID")) || !bytes.Contains(data, []byte(`"tool_id":"g407-recorded"`)) ||
		!bytes.Contains(data, []byte(`"outcome":"fail_closed"`)) {
		t.Fatalf("local record missing tool decision: %q", data)
	}
}

func TestGAP0407BenignOrdinaryAppendFailureHasNoBlockMarker(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(logDir, "hook-failures.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := withDefaults(Options{Home: home, Event: "PreToolUse", Stderr: io.Discard})
	opts.failurePayload = []byte(`{"session_id":"s","tool_call_id":"g407-benign"}`)
	logHookFailure(opts, spec{connector: "claudecode", hookName: "claude-code-hook"},
		"gateway did not answer", "transport", "open", false)
	if _, err := os.Stat(filepath.Join(logDir, "hook-failures.dropped")); !os.IsNotExist(err) {
		t.Fatalf("benign call wrote a block marker: %v", err)
	}
}

// rel-1-0-6 GAP-0407: under an overload where the call misses its budget,
// the watchdog denies it at the deadline and has answerWatchdogLogWait for
// the line of that deny. The line used to be written after the answer: the
// folder look and the open of hook-failures.jsonl (shared by every hook of
// the account) outlasted the wait on a saturated host, the process ended,
// and the denied call had no record. The log is now open before the
// deadline, so the deny still comes at the deadline and its line is there
// when the process ends, however long an open takes after the deadline.
func TestWatchdogDenyLeavesItsLineWhenTheLogOpensSlowlyAfterTheDeadline(t *testing.T) {
	const budget = 600 * time.Millisecond
	shortAnswerBudget(t, budget)
	shortAnswerFloor(t)
	stall := 4 * answerWatchdogLogWait
	start := time.Now()
	previousOpen := openHookFailureLog
	openHookFailureLog = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if time.Since(start) >= budget {
			time.Sleep(stall) // the saturated host: an open after the deny
		}
		return previousOpen(name, flag, perm)
	}
	t.Cleanup(func() { openHookFailureLog = previousOpen })

	var logPath string
	hung := make(chan struct{})
	type ending struct {
		code  int
		lines string
	}
	exited := make(chan ending, 1)
	stdout := &firstWriteRecorder{}
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		run(t, "claudecode", nil, func(o *Options) {
			o.FailMode = "closed"
			o.StartedAt = start
			o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
			o.Stdout = stdout
			// The log of a flood exists: every earlier deny appended to it.
			logPath = filepath.Join(o.Home, "logs", "hook-failures.jsonl")
			if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(logPath, nil, 0o600); err != nil {
				t.Error(err)
			}
			o.Exit = func(code int) {
				// What the account keeps when the process ends here.
				data, _ := os.ReadFile(logPath)
				exited <- ending{code, string(data)}
			}
		})
	}()
	t.Cleanup(func() { close(hung); <-returned })
	select {
	case end := <-exited:
		lines := end.lines
		if out, _ := stdout.read(); !claudeBlocked(runResult{code: end.code, stdout: out}) {
			t.Fatalf("the watchdog answered exit %d stdout %q, want its deny", end.code, out)
		}
		if elapsed := time.Since(start); elapsed > budget+stall {
			t.Fatalf("the deny ended the process %s after the start, want it at the %s deadline plus the log wait", elapsed, budget)
		}
		if !strings.Contains(lines, `"outcome":"fail_closed"`) || strings.Count(lines, "\n") != 1 {
			t.Fatalf("hook-failures.jsonl when the process ended = %q, want the one fail_closed line of the denied call", lines)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog did not answer a gateway that gave no answer")
	}
}

// A call answered before answerWatchdogLogPrepareLead opens no log: the
// prepared open costs nothing on the calls that are answered in time.
func TestWatchdogOpensNoLogForACallAnsweredInTime(t *testing.T) {
	const budget = 1500 * time.Millisecond
	shortAnswerBudget(t, budget)
	previousLead := answerWatchdogLogPrepareLead
	answerWatchdogLogPrepareLead = 500 * time.Millisecond
	t.Cleanup(func() { answerWatchdogLogPrepareLead = previousLead })
	var opens atomic.Int32
	previousOpen := openHookFailureLog
	openHookFailureLog = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		opens.Add(1)
		return previousOpen(name, flag, perm)
	}
	t.Cleanup(func() { openHookFailureLog = previousOpen })
	exited := make(chan int, 1)
	result := run(t, "claudecode", ok(`{"action":"allow"}`), func(o *Options) {
		o.FailMode = "closed"
		o.StartedAt = time.Now()
		o.Exit = func(code int) { exited <- code }
		if err := os.MkdirAll(filepath.Join(o.Home, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.Home, "logs", "hook-failures.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	time.Sleep(budget + 300*time.Millisecond)
	select {
	case code := <-exited:
		t.Fatalf("the watchdog ended the process (%d) after the call was answered", code)
	default:
	}
	if claudeBlocked(result) {
		t.Fatalf("code %d stdout %q, want the gateway's allow", result.code, result.stdout)
	}
	if n := opens.Load(); n != 0 {
		t.Fatalf("hook-failure log opened %d times for a call answered in time, want 0", n)
	}
}
