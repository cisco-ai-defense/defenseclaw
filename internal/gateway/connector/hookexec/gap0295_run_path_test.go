// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

// restartWindowCall prepares a per-user call whose first try its gateway
// refused and whose retry then connected with no decision: the watchdog
// holds the restart answer and the proof, and is never started, so the
// call's own answer path (failPerUserRestartWindow) decides.
func restartWindowCall(t *testing.T, outageMode string, strict bool, mutate func(*Options)) (Options, spec, *answerWatchdog) {
	t.Helper()
	sp, _ := specFor("claudecode")
	home := t.TempDir()
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	opts := perUserRestartOptions(home, outageMode, strict, stdout, stderr, func(int) {})
	if mutate != nil {
		mutate(&opts)
	}
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
	w.noDecisionPending()
	w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
	return opts, sp, w
}

// answerDeadlineEnded is a request context the answer deadline ended.
func answerDeadlineEnded() context.Context {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errGatewayNoAnswer)
	return ctx
}

// TestGAP0295RunPathRestartWindow drives Run's own no-answer branch
// (failPerUserRestartWindow) with the watchdog not answering: the open tier
// allows with the restarting text and a fail_open row; the strict tier,
// strict availability and an install that started during the call deny.
func TestGAP0295RunPathRestartWindow(t *testing.T) {
	stubRestartWindowProof(t, true)
	for _, tc := range []struct {
		name       string
		outageMode string
		strict     bool
		install    bool
		blocks     bool
		outcome    string
	}{
		{"open tier", "open", false, false, false, "fail_open"},
		{"strict tier", "closed", false, false, true, "fail_closed"},
		{"strict availability", "open", true, false, true, "fail_closed"},
		{"install window", "open", false, true, true, "fail_closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, sp, w := restartWindowCall(t, tc.outageMode, tc.strict, nil)
			if tc.install {
				// The installer took the data directory after the outage
				// answer was prepared: the answer is closed at answer time.
				opts.installWindowSeen = true
			}
			code, ok := failPerUserRestartWindow(answerDeadlineEnded(), opts, sp, "open")
			if !ok {
				t.Fatal("Run's no-answer branch did not take the restart-window answer")
			}
			shown := w.err.String() + w.out.String()
			if got := nativeAnswerBlocks(code, w.out.String()); got != tc.blocks {
				t.Fatalf("exit %d answer %q blocks=%v, want %v", code, shown, got, tc.blocks)
			}
			if !tc.install && (!strings.Contains(shown, "restarting or not running") || strings.Contains(shown, "did not answer in time")) {
				t.Fatalf("answer %q, want the restarting text", shown)
			}
			rows := claimedStopRows(t, opts.Home)
			if len(rows) != 1 || rows[0].Outcome != tc.outcome {
				t.Fatalf("rows %+v, want one %s row", rows, tc.outcome)
			}
			if !tc.install && rows[0].Reason != perUserGatewayRestartingReason {
				t.Fatalf("rows %+v, want the %q reason", rows, perUserGatewayRestartingReason)
			}
		})
	}
}

// TestGAP0295RunPathKeepsTheNoAnswer: with no proof, after an error status or
// a progress report, or with no deadline and no pending decision, Run's
// branch gives no restart answer and the call keeps the closed no-answer.
func TestGAP0295RunPathKeepsTheNoAnswer(t *testing.T) {
	sp, _ := specFor("claudecode")
	for _, tc := range []struct {
		name  string
		fresh bool
		setup func(*Options, *answerWatchdog)
		ctx   func() context.Context
	}{
		{"no proof", false, nil, answerDeadlineEnded},
		{"error status", true, func(opts *Options, _ *answerWatchdog) { opts.answeredErrorStatus = http.StatusServiceUnavailable }, answerDeadlineEnded},
		{"status on the watchdog", true, func(opts *Options, w *answerWatchdog) { w.gatewayAnsweredError(*opts, sp, http.StatusOK) }, answerDeadlineEnded},
		{"progress report", true, func(_ *Options, w *answerWatchdog) { w.progressed() }, answerDeadlineEnded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRestartWindowProof(t, tc.fresh)
			opts, _, w := restartWindowCall(t, "open", false, nil)
			if tc.setup != nil {
				tc.setup(&opts, w)
			}
			if _, ok := failPerUserRestartWindow(tc.ctx(), opts, sp, "open"); ok {
				t.Fatal("a call the gateway took, or with no proof, took the restart-window answer")
			}
		})
	}
	t.Run("no deadline and no pending decision", func(t *testing.T) {
		stubRestartWindowProof(t, true)
		home := t.TempDir()
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(int) {})
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
		w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
		if _, ok := failPerUserRestartWindow(context.Background(), opts, sp, "open"); ok {
			t.Fatal("a call still waiting took the restart-window answer")
		}
	})
}

// TestGAP0295ManagedAndSecureClientNeverTakeTheRestartWindow: managed
// (administrator mode open or closed), managed-socket and Secure Client
// calls never arm the restart-window answer, on the watchdog or on Run's
// path, even with the proof true and a fresh gateway record.
func TestGAP0295ManagedAndSecureClientNeverTakeTheRestartWindow(t *testing.T) {
	stubRestartWindowProof(t, true)
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"managed, administrator open", func(o *Options) { o.ManagedEnterprise = true; o.FailMode = "open" }},
		{"managed, administrator closed", func(o *Options) { o.ManagedEnterprise = true; o.FailMode = "closed" }},
		{"managed socket", func(o *Options) { o.ManagedUnixSocket = "/run/defenseclaw/hook.sock" }},
		{"Secure Client", func(o *Options) { o.SecureClient = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, sp, w := restartWindowCall(t, "open", false, func(o *Options) {
				tc.mutate(o)
				writeFreshGatewayRecordStub(t, o.Home)
			})
			// The fresh-record render, when armed, runs in the background.
			time.Sleep(50 * time.Millisecond)
			w.mu.Lock()
			armed := w.restart != nil || w.restartChoice != nil || w.restartProof != nil
			w.mu.Unlock()
			if armed {
				t.Fatal("the restart-window answer was armed for a managed or Secure Client call")
			}
			if _, ok := failPerUserRestartWindow(answerDeadlineEnded(), opts, sp, "open"); ok {
				t.Fatal("Run's branch took the restart-window answer for a managed or Secure Client call")
			}
			if strings.Contains(string(w.fallback.out)+string(w.fallback.err), "restarting or not running") {
				t.Fatalf("watchdog answer %q names the per-user restart", string(w.fallback.out)+string(w.fallback.err))
			}
		})
	}
}
