// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGAP0407StalledMarkerOpenKeepsWatchdogBound(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	stall := make(chan struct{})
	previous := openHookFailureLog
	openHookFailureLog = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasSuffix(name, "hook-failures.dropped") || strings.HasSuffix(name, "hook-failures.jsonl") {
			<-stall
		}
		return previous(name, flag, perm)
	}
	var output bytes.Buffer
	exited := make(chan time.Duration, 1)
	start := time.Now()
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "closed", Stdout: &output, Stderr: io.Discard,
		Exit: func(int) { exited <- time.Since(start) },
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"stalled-marker-open"}`)
	deadline := start.Add(450 * time.Millisecond)
	w := startAnswerWatchdog(&opts, specs["claudecode"], "closed", deadline, deadline)
	logged := make(chan struct{})
	w.mu.Lock()
	logFailure := w.fallback.logFailure
	w.fallback.logFailure = func() {
		defer close(logged)
		logFailure()
	}
	w.mu.Unlock()
	defer func() {
		close(stall)
		<-logged
		<-w.failureLog.done
		openHookFailureLog = previous
	}()
	// The stalled open never returns until the test ends, so the bound only
	// has to tell "the watchdog gave up on the log after its wait" from "the
	// watchdog hangs on the open". A hosted runner can add well over 200 ms of
	// scheduling delay (684.95 ms seen on a macOS runner against 650 ms), so it
	// gets 700 ms more; the watchdog still has to exit while the open is stuck.
	bound, giveUp := 650*time.Millisecond, 900*time.Millisecond
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		bound, giveUp = bound+700*time.Millisecond, giveUp+700*time.Millisecond
	}
	select {
	case elapsed := <-exited:
		if elapsed > bound {
			t.Fatalf("watchdog exit exceeded its log wait: %v", elapsed)
		}
	case <-time.After(giveUp):
		t.Fatal("watchdog did not exit within its log wait")
	}
}

func TestGAP0407ClaimedBlockKeepsPreparedToolID(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	loggerDone := make(chan struct{})
	defer func() {
		close(release)
		<-loggerDone
	}()
	type exitResult struct {
		code   int
		out    string
		marker []byte
	}
	exited := make(chan exitResult, 1)
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "closed", Stdout: &output,
		Stderr: io.Discard,
		Now: func() time.Time {
			enterOnce.Do(func() { close(entered) })
			<-release
			return time.Now()
		},
		Exit: func(code int) {
			marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
			exited <- exitResult{code: code, out: output.String(), marker: marker}
		},
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"claimed-block"}`)
	sp := specs["claudecode"]
	deadline := time.Now().Add(450 * time.Millisecond)
	_ = startAnswerWatchdog(&opts, sp, "closed", deadline, deadline)
	go func() {
		defer close(loggerDone)
		logHookFailure(opts, sp, "gateway did not answer", "transport", "closed", true)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("failure logger did not reach the clock")
	}
	select {
	case got := <-exited:
		if !claudeBlocked(runResult{code: got.code, stdout: got.out}) {
			t.Fatalf("watchdog did not deliver a block: code=%d", got.code)
		}
		if !bytes.Contains(got.marker, []byte(`"tool_id":"claimed-block"`)) ||
			!bytes.Contains(got.marker, []byte(`"outcome":"fail_closed"`)) {
			t.Fatalf("blocked call has no per-ID record: %q", got.marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not exit at its answer deadline")
	}
}

func TestGAP0407ClaimedOpenKeepsAllowedRecord(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	loggerDone := make(chan struct{})
	defer func() {
		close(release)
		<-loggerDone
	}()
	type exitResult struct {
		code   int
		out    string
		marker []byte
	}
	exited := make(chan exitResult, 1)
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "open", Stdout: &output,
		Stderr: io.Discard,
		Now: func() time.Time {
			enterOnce.Do(func() { close(entered) })
			<-release
			return time.Now()
		},
		Exit: func(code int) {
			marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
			exited <- exitResult{code: code, out: output.String(), marker: marker}
		},
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"claimed-open"}`)
	sp := specs["claudecode"]
	deadline := time.Now().Add(450 * time.Millisecond)
	_ = startAnswerWatchdog(&opts, sp, "closed", deadline, deadline)
	go func() {
		defer close(loggerDone)
		logUnreachableFailure(opts, sp, perUserGatewayRestartingReason, "open", false)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("failure logger did not reach the clock")
	}
	select {
	case got := <-exited:
		if claudeBlocked(runResult{code: got.code, stdout: got.out}) {
			t.Fatalf("watchdog changed the allowed answer: code=%d", got.code)
		}
		if !bytes.Contains(got.marker, []byte(`"tool_id":"claimed-open"`)) ||
			!bytes.Contains(got.marker, []byte(`"outcome":"fail_open"`)) ||
			bytes.Contains(got.marker, []byte(`"outcome":"fail_closed"`)) {
			t.Fatalf("allowed call has an incorrect local record: %q", got.marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not exit at its answer deadline")
	}
}
