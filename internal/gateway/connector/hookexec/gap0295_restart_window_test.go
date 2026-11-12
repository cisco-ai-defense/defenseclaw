// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// stubRestartWindowProof replaces the restart-window proof for one test.
func stubRestartWindowProof(t *testing.T, fresh bool) {
	t.Helper()
	previous := perUserRestartWindowProof
	perUserRestartWindowProof = func(string, *perUserPeerCheck) restartProofResult {
		return restartProofResult{ok: fresh, reason: "proof_rejected"}
	}
	t.Cleanup(func() { perUserRestartWindowProof = previous })
}

// downThenUp is a gateway restart: every connection is refused until down
// has passed, then the gateway that comes up takes the connection and gives
// no decision until the request ends.
func downThenUp(down time.Duration) *stubRT {
	var upAt atomic.Int64
	upAt.Store(time.Now().Add(down).UnixNano())
	return &stubRT{onRequest: func(_ *stubRT, req *http.Request) (*http.Response, error) {
		if time.Now().UnixNano() < upAt.Load() {
			return nil, syscall.ECONNREFUSED
		}
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{})
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
}

// TestGAP0295RestartWindowFollowsTheOutageMode pins rel-1-0-6 GAP-0295 on
// the native per-user Claude Code hook: the gateway is down for 300 ms, then
// the new gateway takes the retry and has not answered when the hook budget
// ends. When the connection is held by a gateway that only just started and
// has answered no call yet (the proof), the call gets the outage answer: the
// default and permissive tiers allow it with the restarting warning and a
// fail_open row; the strict tier and strict availability deny it. A gateway
// that already answered (no proof) took the call and gave no decision: closed
// in every tier.
func TestGAP0295RestartWindowFollowsTheOutageMode(t *testing.T) {
	fastRestartRetries(t)
	for _, tc := range []struct {
		name       string
		fresh      bool
		outageMode string
		strict     bool
		firstTry   bool
		blocks     bool
		text, row  string
		outcome    string
	}{
		{"fresh gateway, open tier", true, "open", false, false, false, "restarting or not running", perUserGatewayRestartingReason, "fail_open"},
		{"fresh gateway, strict tier", true, "closed", false, false, true, "restarting or not running", perUserGatewayRestartingReason, "fail_closed"},
		{"fresh gateway, strict availability", true, "open", true, false, true, "restarting or not running", perUserGatewayRestartingReason, "fail_closed"},
		{"fresh gateway first try, open tier", true, "open", false, true, false, "restarting or not running", perUserGatewayRestartingReason, "fail_open"},
		{"answered gateway, open tier", false, "open", false, false, true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
		{"answered gateway, strict tier", false, "closed", false, false, true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
		{"answered gateway first try, open tier", false, "open", false, true, true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.firstTry && tc.fresh && runtime.GOOS != "linux" {
				t.Skip("the fresh-start window is Linux only")
			}
			stubRestartWindowProof(t, tc.fresh)
			down := 300 * time.Millisecond
			if tc.firstTry {
				down = 0
			}
			var home string
			result := runWithContext(t, context.Background(), "claudecode", downThenUp(down), func(opts *Options) {
				home = opts.Home
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
				opts.OutageFailModeNow = func() string { return tc.outageMode }
				opts.StrictAvailability = tc.strict
				// The restart budget ends 500 ms from now and the answer
				// budget 1 s from now: shorter than the window plus the
				// new gateway's first answer.
				opts.StartedAt = time.Now().Add(-hookAnswerBudget + time.Second)
				if tc.firstTry {
					// This account's gateway record was just written.
					if err := os.WriteFile(filepath.Join(home, "gateway.pid"), []byte("{}"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			})
			if got := claudeBlocked(result); got != tc.blocks {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, tc.blocks, result.code, result.stdout, result.stderr)
			}
			if !strings.Contains(result.stdout+result.stderr, tc.text) {
				t.Fatalf("stdout=%q stderr=%q, want %q named", result.stdout, result.stderr, tc.text)
			}
			if !tc.blocks && strings.Contains(result.stdout+result.stderr, "fail mode closed") {
				t.Fatalf("stdout=%q stderr=%q: an allowed call names fail mode closed", result.stdout, result.stderr)
			}
			rows := claimedStopRows(t, home)
			if len(rows) != 1 || rows[0].Reason != tc.row || rows[0].Outcome != tc.outcome {
				t.Fatalf("rows %+v, want one %s %q row", rows, tc.outcome, tc.row)
			}
		})
	}
}

// TestGAP0295TookTheCallStaysClosed: a gateway that sent a status or a
// progress report took the call; the restart-window proof does not apply
// to it, whatever the account's outage mode.
func TestGAP0295TookTheCallStaysClosed(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	stubRestartWindowProof(t, true)
	sp, _ := specFor("claudecode")
	for _, tc := range []struct {
		name string
		took func(w *answerWatchdog, opts Options)
	}{
		{"progress report", func(w *answerWatchdog, _ Options) { w.progressed() }},
		{"error status", func(w *answerWatchdog, opts Options) { w.gatewayAnsweredError(opts, sp, http.StatusServiceUnavailable) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
			exited := make(chan int, 1)
			opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
			w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
			w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
			w.noDecisionPending()
			w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
			tc.took(w, opts)
			code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
			if !nativeAnswerBlocks(code, stdout.String()) || strings.Contains(shown, "restarting or not running") {
				t.Fatalf("exit %d answer %q, want the closed answer of a call the gateway took", code, shown)
			}
		})
	}
	t.Run("restart window", func(t *testing.T) {
		home := t.TempDir()
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
		w.noDecisionPending()
		w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
		code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
		if nativeAnswerBlocks(code, stdout.String()) || !strings.Contains(shown, "restarting or not running") {
			t.Fatalf("exit %d answer %q, want the fail-open restart answer", code, shown)
		}
	})
}
