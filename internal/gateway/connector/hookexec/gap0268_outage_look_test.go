// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// rel-1-0-10 GAP-0268: reading the account outage tier starts a gateway
// process (hook-user outageMode). A call its gateway answers must not read
// it; a call left unanswered reads it at its deadline and follows it.

const gap0268Ordinary = `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"git status"}}`

// tierReads counts the tier reads and keeps the stack of the first one.
type tierReads struct {
	n     atomic.Int32
	once  sync.Once
	stack string
	mode  string
}

func (r *tierReads) read() string {
	r.n.Add(1)
	r.once.Do(func() { r.stack = string(debug.Stack()) })
	return r.mode
}

func TestGAP0268AnsweredCallReadsNoOutageTier(t *testing.T) {
	reads := &tierReads{mode: "open"}
	rt := &stubRT{onRequest: func(_ *stubRT, req *http.Request) (*http.Response, error) {
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{})
		}
		// The gateway takes the call and answers a moment later.
		time.Sleep(60 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
	}}
	result := runWithContext(t, context.Background(), "claudecode", rt, func(opts *Options) {
		opts.StartedAt = time.Now()
		opts.Stdin = strings.NewReader(gap0268Ordinary)
		opts.OutageFailModeNow = reads.read
		opts.AnswerWatchdog = ArmAnswerWatchdog(Options{Connector: "claudecode", Home: opts.Home, StartedAt: opts.StartedAt,
			FailMode: "closed", Exit: func(int) {}, Stdout: io.Discard, Stderr: io.Discard}, []byte(gap0268Ordinary))
		if opts.AnswerWatchdog == nil {
			t.Fatal("no watchdog for a per-user PreToolUse")
		}
	})
	if result.code != 0 || claudeBlocked(result) {
		t.Fatalf("answered allow: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	time.Sleep(200 * time.Millisecond) // background work of the call
	if n := reads.n.Load(); n != 0 {
		t.Fatalf("an answered call read the outage tier %d times; first from:\n%s", n, reads.stack)
	}
}

// A late ordinary call on a gateway that took it and gave no decision reads
// the tier at its deadline, not when it connects, and follows it: open allows
// with the warning, closed and strict availability deny.
func TestGAP0268LateOrdinaryCallReadsTheTierAtTheDeadline(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	sp, _ := specFor("claudecode")
	for _, tc := range []struct {
		name   string
		mode   string
		strict bool
		blocks bool
		reads  int32
	}{
		{"open tier", "open", false, false, 1},
		{"closed tier", "closed", false, true, 1},
		{"strict availability", "open", true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
			exited := make(chan int, 1)
			opts := perUserRestartOptions(home, tc.mode, tc.strict, stdout, stderr, func(code int) { exited <- code })
			reads := &tierReads{mode: tc.mode}
			opts.OutageFailModeNow = reads.read
			opts.lateOrdinary = func() bool { return true }
			w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
			w.noDecisionPending()
			w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
			time.Sleep(100 * time.Millisecond)
			if n := reads.n.Load(); n != 0 {
				t.Fatalf("tier read %d times at contact, before any deadline; first from:\n%s", n, reads.stack)
			}
			code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
			if got := nativeAnswerBlocks(code, stdout.String()); got != tc.blocks {
				t.Fatalf("blocks=%v, want %v: exit %d answer %q", got, tc.blocks, code, shown)
			}
			if n := reads.n.Load(); n != tc.reads {
				t.Fatalf("%d tier reads at the deadline, want %d", n, tc.reads)
			}
		})
	}
}

// The restart answer of a call whose first try was refused (a transport
// failure) is still prepared when the failure is seen.
func TestGAP0268RefusedTryStillPreparesTheOutageAnswer(t *testing.T) {
	sp, _ := specFor("claudecode")
	home := t.TempDir()
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(int) {})
	reads := &tierReads{mode: "open"}
	opts.OutageFailModeNow = reads.read
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
	w.mu.Lock()
	ready := w.restart != nil
	w.mu.Unlock()
	if !ready || reads.n.Load() != 1 {
		t.Fatalf("refused try: restart answer ready=%v after %d tier reads, want ready after 1", ready, reads.n.Load())
	}
}
