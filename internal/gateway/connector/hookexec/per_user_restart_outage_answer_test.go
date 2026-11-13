// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"strings"
	"syscall"
	"testing"
	"time"
)

func perUserRestartOptions(home, outageMode string, strict bool, stdout, stderr *claimedStopWriter, exit func(int)) Options {
	return withDefaults(Options{
		Connector:          "claudecode",
		Event:              "PreToolUse",
		Home:               home,
		HookDir:            home + "/hooks",
		FailMode:           "open",
		StrictAvailability: strict,
		StartedAt:          time.Now(),
		Stdin:              strings.NewReader(""),
		Stdout:             stdout,
		Stderr:             stderr,
		Exit:               exit,
		OutageFailModeNow:  func() string { return outageMode },
	})
}

// fireAnswerDeadline drives the watchdog's deadline by hand and returns what
// the agent got.
func fireAnswerDeadline(t *testing.T, w *answerWatchdog, exited chan int, stdout, stderr *claimedStopWriter) (int, string) {
	t.Helper()
	go w.watch(time.Now())
	select {
	case code := <-exited:
		awaitAnswerWatchdogBackground(t, w)
		return code, stderr.String() + stdout.String()
	case <-time.After(time.Minute):
		t.Fatal("the watchdog never answered")
	}
	return 0, ""
}

// awaitAnswerWatchdogBackground waits, after a simulated exit, for the work a
// watchdog leaves running when its exit does not end the process: watch's
// deferred close of the prepared failure log, and the prepare goroutine that
// watch's own timer starts ahead of the deadline (at once for a deadline that
// has passed), which creates logs and hook-failures.dropped in the account's
// home. Production exits the process there. A test that returned at once had
// its TempDir removed under that goroutine (macOS CI run 43337422577:
// "TempDir RemoveAll cleanup: unlinkat .../logs: directory not empty").
// It also waits for the record writers watch started (w.records): watch exits
// once the marker or the ordinary line has recorded the answer, and the
// other one can still be writing the logs folder (macOS CI, PR #1456,
// TestPerUserNoAnswerStaysClosed/per-user_deadline_before_contact).
func awaitAnswerWatchdogBackground(t *testing.T, w *answerWatchdog) {
	t.Helper()
	records := make(chan struct{})
	go func() {
		w.records.Wait()
		close(records)
	}()
	for _, done := range []<-chan struct{}{w.watchDone, w.failureLog.done, records} {
		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Fatal("the watchdog's background work did not finish")
		}
	}
}

// TestPerUserRestartOutlastingTheBudgetFollowsTheOutageMode pins rel-1-0-6
// GAP-0295 on the native per-user hook: a call this account's gateway refused
// (it is restarting) whose budget then ends before the gateway that comes up
// answers gets the outage answer, from the same decision as its row. The
// default and permissive tiers let it run with the outage warning (fail_open
// row); the strict tier and strict availability block it with the restarting
// text (fail_closed row). The deadline is driven by hand; nothing sleeps.
func TestPerUserRestartOutlastingTheBudgetFollowsTheOutageMode(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute // a bound only
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	sp, _ := specFor("claudecode")
	for _, tc := range []struct {
		name       string
		outageMode string
		strict     bool
		blocks     bool
	}{
		{"default tier (outage mode open)", "open", false, false},
		{"strict tier (outage mode closed)", "closed", false, true},
		{"strict availability", "open", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
			exited := make(chan int, 1)
			opts := perUserRestartOptions(home, tc.outageMode, tc.strict, stdout, stderr, func(code int) { exited <- code })
			w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
			w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
			code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
			if got := nativeAnswerBlocks(code, stdout.String()); got != tc.blocks {
				t.Fatalf("exit %d answer %q blocks=%v, want %v", code, shown, got, tc.blocks)
			}
			if !strings.Contains(shown, "restarting or not running") || strings.Contains(shown, "did not answer in time") {
				t.Fatalf("answer %q, want the restarting text, not the did-not-answer one", shown)
			}
			rows := claimedStopRows(t, home)
			want := "fail_open"
			if tc.blocks {
				want = "fail_closed"
			}
			if len(rows) != 1 || rows[0].Reason != perUserGatewayRestartingReason || rows[0].Outcome != want {
				t.Fatalf("rows %+v, want one %s %q row", rows, want, perUserGatewayRestartingReason)
			}
		})
	}
}

// TestPerUserNoAnswerWithoutAnOutageStaysClosed is the other side: a call
// whose gateway took it and did not answer, with no refusal, is the hung
// gateway, closed in every fail mode (GAP-2279); and a managed call's answer
// does not change when the per-user outage is reported.
func TestPerUserNoAnswerStaysClosed(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	sp, _ := specFor("claudecode")
	t.Run("per-user hung gateway", func(t *testing.T) {
		home := t.TempDir()
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		if !nativeAnswerBlocks(w.fallback.code, string(w.fallback.out)) {
			t.Fatal("a deadline before verified gateway contact must stay closed")
		}
		code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
		if !nativeAnswerBlocks(code, stdout.String()) || !strings.Contains(shown, "did not answer in time") {
			t.Fatalf("exit %d answer %q, want the closed no-answer result", code, shown)
		}
		rows := claimedStopRows(t, home)
		if len(rows) != 1 || rows[0].Reason != perUserGatewayNoAnswerReason || rows[0].Outcome != "fail_closed" {
			t.Fatalf("rows %+v, want one fail_closed %q row", rows, perUserGatewayNoAnswerReason)
		}
	})
	t.Run("per-user deadline before contact", func(t *testing.T) {
		home := t.TempDir()
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
		w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
		code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
		if !nativeAnswerBlocks(code, shown) {
			t.Fatalf("exit %d answer %q, want the closed pre-contact deadline", code, shown)
		}
	})
	t.Run("managed", func(t *testing.T) {
		stubManagedLifecycle(t, func() bool { return false })
		stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
		exited := make(chan int, 1)
		opts := managedStoppedOptions(t, "claudecode", managedStoppedForms[0].shape, stdout, stderr, func(code int) { exited <- code })
		opts.OutageFailModeNow = func() string { return "open" }
		w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
		w.perUserOutageSeen(opts, sp, "open", syscall.ECONNREFUSED)
		code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
		if !nativeAnswerBlocks(code, stdout.String()) || !strings.Contains(shown, managedGatewayNoAnswerReason) {
			t.Fatalf("exit %d answer %q, want the managed no-answer refusal", code, shown)
		}
	})
}

func TestPerUserRestartUnansweredNeedsAnOutageAndNoAnswer(t *testing.T) {
	ctx := context.Background()
	opts := Options{Connector: "claudecode"}
	answered := opts
	answered.answeredErrorStatus = 503
	for _, tc := range []struct {
		name string
		opts Options
		wait perUserGatewayWait
		want bool
	}{
		{"refused, then the budget ended at the next try", opts, perUserGatewayWait{sawOutage: true, err: fmt.Errorf("post: %w", context.DeadlineExceeded)}, true},
		{"refused, then no connection in the budget", opts, perUserGatewayWait{sawOutage: true, err: errGatewayNotConnected}, true},
		{"refused, then the new gateway took it and stalled", opts, perUserGatewayWait{sawOutage: true, err: fmt.Errorf("%w: x", errGatewayTookCallNoAnswer)}, false},
		{"no refusal first (hung gateway)", opts, perUserGatewayWait{err: context.DeadlineExceeded}, false},
		{"refused, then a listener not proven ours", opts, perUserGatewayWait{sawOutage: true, err: errPerUserPeerCheckUnfinished}, false},
		{"refused, then a listener not proven ours at the deadline", opts, perUserGatewayWait{sawOutage: true, err: fmt.Errorf("%w: %w", errPerUserPeerUnverified, context.DeadlineExceeded)}, false},
		{"refused, then a cut-off answer", opts, perUserGatewayWait{sawOutage: true, err: fmt.Errorf("%w: %w", errPerUserAnswerIncomplete, context.DeadlineExceeded)}, false},
		{"an answered error first", answered, perUserGatewayWait{sawOutage: true, err: context.DeadlineExceeded}, false},
		{"refused, then answered", opts, perUserGatewayWait{sawOutage: true}, false},
	} {
		if got := perUserRestartUnanswered(ctx, tc.opts, tc.wait); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPerUserPostNoAnswerExitIsOnlyANoStatusDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"deadline with no status", fmt.Errorf("Post: %w", context.DeadlineExceeded), true},
		{"took the call, no answer", fmt.Errorf("%w: x", errGatewayTookCallNoAnswer), true},
		{"outage (no connection)", errGatewayNotConnected, false},
		{"listener not proven", fmt.Errorf("%w: %w", errPerUserPeerUnverified, context.DeadlineExceeded), false},
		{"cut-off answer", fmt.Errorf("%w: %w", errPerUserAnswerIncomplete, context.DeadlineExceeded), false},
		{"other", errors.New("boom"), false},
	} {
		if got := PerUserPostNoAnswer(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	seen := map[int]bool{1: true}
	for _, code := range []int{PerUserPostOutageExit, PerUserPostPeerUnverifiedExit, PerUserPostNoAnswerExit, PerUserPostRestartNoAnswerExit} {
		if seen[code] {
			t.Fatalf("hook-post exit %d is used twice", code)
		}
		seen[code] = true
	}
}

// A no-answer without a verified contact or a prior refusal stays closed.
func TestPerUserOutageSeenNeedsARefusedFirstTry(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	sp, _ := specFor("claudecode")
	for _, err := range []error{
		fmt.Errorf("post: %w", context.DeadlineExceeded),
		fmt.Errorf("%w: x", errGatewayTookCallNoAnswer),
		fmt.Errorf("%w: %w", errPerUserPeerUnverified, syscall.ECONNREFUSED),
	} {
		t.Run(err.Error(), func(t *testing.T) {
			home := t.TempDir()
			stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
			exited := make(chan int, 1)
			opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
			w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
			w.perUserOutageSeen(opts, sp, "open", err)
			code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
			if !nativeAnswerBlocks(code, stdout.String()) || !strings.Contains(shown, "did not answer in time") {
				t.Fatalf("exit %d answer %q, want the closed did-not-answer refusal", code, shown)
			}
		})
	}
}

// stalledAfterConnect answers each request as rt.answers says: "refused" is a
// refused connection; "stall" takes the connection (the try is connected) and
// never answers until the request ends.
func stalledAfterConnect(answers ...string) *stubRT {
	return &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
		answer := answers[len(answers)-1]
		if rt.requests <= len(answers) {
			answer = answers[rt.requests-1]
		}
		if answer == "refused" {
			return nil, syscall.ECONNREFUSED
		}
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{})
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
}

// TestPerUserRunRefusedThenStalledFollowsTheOutageMode drives the native
// per-user hook (Run, doRequest) with a fake transport (review M21, M26): the
// first try is refused, then the next is taken and never answered until the
// call's own time ends. Both tiers block a pending gateway decision; a
// stalled first try without a refusal blocks too.
func TestPerUserRunRefusedThenStalledFollowsTheOutageMode(t *testing.T) {
	fastRestartRetries(t)
	for _, tc := range []struct {
		name       string
		answers    []string
		outageMode string
		blocks     bool
		want, row  string
		outcome    string
	}{
		{"refused then stalled, open tier", []string{"refused", "stall"}, "open", true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
		{"refused then stalled, strict tier", []string{"refused", "stall"}, "closed", true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
		{"stalled with no refusal, open tier", []string{"stall"}, "open", true, "did not answer", perUserGatewayNoAnswerReason, "fail_closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The call's own time ends before its answer deadline, so the
			// call answers, not the watchdog.
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			var home string
			result := runWithContext(t, ctx, "claudecode", stalledAfterConnect(tc.answers...), func(opts *Options) {
				home = opts.Home
				opts.Event = "PreToolUse"
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
				opts.OutageFailModeNow = func() string { return tc.outageMode }
				// The restart budget is still open after the refusal; the
				// answer deadline is past the call's own time.
				opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 300*time.Millisecond)
			})
			if got := claudeBlocked(result); got != tc.blocks {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, tc.blocks, result.code, result.stdout, result.stderr)
			}
			if !strings.Contains(result.stdout+result.stderr, tc.want) {
				t.Fatalf("stdout=%q stderr=%q, want %q named", result.stdout, result.stderr, tc.want)
			}
			rows := claimedStopRows(t, home)
			if len(rows) != 1 || rows[0].Reason != tc.row || rows[0].Outcome != tc.outcome {
				t.Fatalf("rows %+v, want one %s %q row", rows, tc.outcome, tc.row)
			}
		})
	}
}
