// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-6 GAP-0648 (GAP-0167/GAP-0171 replay): a hook process the host
// held for more than 30 s keeps the start the system gave it. Before, such a
// start was taken for a clock problem and the call got a fresh budget from
// the package's initialization: a Claude Code call frozen for 73 s during
// Setup /repair asked its gateway again and reached the agent as a verdict.
func TestHookCallStartKeepsAStaleProcessStart(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name    string
		started time.Time
		ok      bool
		want    time.Time
	}{
		{"fresh", now.Add(-200 * time.Millisecond), true, now.Add(-200 * time.Millisecond)},
		{"held 39 s", now.Add(-39 * time.Second), true, now.Add(-39 * time.Second)},
		{"held 73 s", now.Add(-73 * time.Second), true, now.Add(-73 * time.Second)},
		{"in the future (clock stepped back)", now.Add(time.Minute), true, hookProcessInit},
		{"not known", time.Time{}, false, hookProcessInit},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hookCallStart(test.started, test.ok, now); !got.Equal(test.want) {
				t.Fatalf("call start %s, want %s", got, test.want)
			}
		})
	}
	// A call that starts that late has no budget left: it is closed at once.
	managed := Options{Connector: "claudecode", Event: "PreToolUse", ManagedEnterprise: true}
	if deadline := answerDeadline(managed, hookCallStart(now.Add(-73*time.Second), true, now)); deadline.After(now) {
		t.Fatalf("a call started 73 s ago has its deadline %s from now, want it passed", deadline.Sub(now))
	}
}

func stubManagedServiceRunning(t *testing.T, running func(string) (bool, bool)) {
	t.Helper()
	previous := managedGatewayServiceRunningNow
	managedGatewayServiceRunningNow = running
	t.Cleanup(func() { managedGatewayServiceRunningNow = previous })
}

// GAP-0648: the first managed Windows call into a gateway stop connected to
// the running gateway, which took the call as Setup stopped it and never
// answered. It waited for the 4 s process cap (4.5-7.3 s for the agent)
// while the next calls were blocked at the 3 s restart budget. A call whose
// gateway service is read as not running at the restart budget is blocked
// then, closed; a running gateway keeps the call's answer budget.
func TestManagedWindowsCallIntoAGatewayStopIsBlockedAtTheRestartBudget(t *testing.T) {
	stubManagedLifecycle(t, func() bool { return false })
	previousStopped := managedGatewayServiceStopped
	managedGatewayServiceStopped = func(string) bool { return false }
	t.Cleanup(func() { managedGatewayServiceStopped = previousStopped })
	for _, test := range []struct {
		name           string
		running        bool
		reason         string
		atLeast, below time.Duration
	}{
		{"service stopping", false, managedGatewayRestartingReason, gatewayRestartBudget - 100*time.Millisecond, hookAnswerBudget - 200*time.Millisecond},
		// A running gateway keeps its answer window (contact + hookAnswerBudget, within the process cap).
		{"service running", true, managedGatewayNoAnswerReason, hookAnswerBudget - 100*time.Millisecond, managedAnswerDeadlineCap + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubManagedServiceRunning(t, func(name string) (bool, bool) { return test.running, name == "DefenseClawGateway" })
			home := t.TempDir()
			result, elapsed := runAgainstGateway(t, "claudecode", hungGateway(t), func(opts *Options) {
				managedWindowsStandalone(opts)
				opts.ManagedGatewayServiceName = "DefenseClawGateway"
				opts.FailureLogHome = userLogHome(home)
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
			})
			if !blocked(result) {
				t.Fatalf("after %s code=%d stdout=%q stderr=%q, want a block", elapsed, result.code, result.stdout, result.stderr)
			}
			if elapsed < test.atLeast || elapsed >= test.below {
				t.Fatalf("blocked after %s, want in [%s, %s)", elapsed, test.atLeast, test.below)
			}
			entry := lastHookFailure(t, home)
			if entry["reason"] != test.reason || entry["outcome"] != "fail_closed" {
				t.Fatalf("failure row %v, want %s, fail_closed", entry, test.reason)
			}
		})
	}
}

// The watch proves a stop only from a state read in time, and only for a
// call still waiting: a running, unreadable or slow service, or a call that
// has its response, keeps the call's own deadline.
func TestManagedGatewayServiceWatchNeedsAProvenStop(t *testing.T) {
	previousWait := managedGatewayServiceStateWait
	managedGatewayServiceStateWait = 50 * time.Millisecond
	t.Cleanup(func() { managedGatewayServiceStateWait = previousWait })
	const interval = 20 * time.Millisecond
	slow := func() (bool, bool) { time.Sleep(time.Second); return false, true }
	for _, test := range []struct {
		name    string
		states  []bool // read in order; the last repeats
		known   bool
		read    func() (bool, bool)
		stopAt  time.Duration
		restart bool
	}{
		{name: "stopped at the budget", states: []bool{false}, known: true, restart: true},
		{name: "running, then stopped", states: []bool{true, true, false}, known: true, restart: true},
		{name: "running", states: []bool{true}, known: true},
		{name: "state not known", states: []bool{false}, known: false},
		{name: "state read too slow", read: slow},
		{name: "answered before the budget", states: []bool{false}, known: true, stopAt: 20 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A read past the bound keeps running while the next one starts.
			var reads atomic.Int32
			read := test.read
			if read == nil {
				read = func() (bool, bool) {
					state := test.states[min(int(reads.Add(1))-1, len(test.states)-1)]
					return state, test.known
				}
			}
			deadline := time.Now().Add(60 * time.Millisecond)
			ctx, stop, release := watchManagedGatewayService(context.Background(), read, deadline, interval)
			defer release()
			if test.stopAt > 0 {
				time.Sleep(test.stopAt)
				stop()
			}
			select {
			case <-ctx.Done():
				if !test.restart || !errors.Is(context.Cause(ctx), errGatewayRestarting) {
					t.Fatalf("watch ended the call with %v, want it waiting", context.Cause(ctx))
				}
				if time.Now().Before(deadline) {
					t.Fatal("the call was ended before the restart budget")
				}
			case <-time.After(400 * time.Millisecond):
				if test.restart {
					t.Fatal("the call into a stopped service was not ended")
				}
			}
		})
	}
}

// Only a managed Windows call outside Secure Client is watched; Secure
// Client and per-user calls keep their transport unchanged.
func TestManagedGatewayServiceWatchScope(t *testing.T) {
	stubManagedServiceRunning(t, func(string) (bool, bool) { return false, true })
	deadline := time.Now().Add(-time.Millisecond)
	for _, test := range []struct {
		name    string
		opts    Options
		watched bool
	}{
		{"managed Windows", Options{ManagedEnterprise: true, ManagedGatewayServiceName: "DefenseClawGateway"}, true},
		{"Secure Client", Options{ManagedEnterprise: true, SecureClient: true, ManagedGatewayServiceName: "DefenseClawGateway"}, false},
		{"per-user", Options{ManagedGatewayServiceName: "DefenseClawGateway"}, false},
		{"no service", Options{ManagedEnterprise: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, release := watchManagedGatewayStarts(context.Background(), test.opts, deadline)
			defer release()
			select {
			case <-ctx.Done():
				if !test.watched {
					t.Fatalf("call ended with %v, want no watch", context.Cause(ctx))
				}
			case <-time.After(300 * time.Millisecond):
				if test.watched {
					t.Fatal("the managed Windows call was not watched")
				}
			}
		})
	}
}

// GAP-0648: one deadline holds for the whole call. A managed verdict that
// is read after the deadline (the host held the process across it) does not
// stand the watchdog down: the agent gets the watchdog's closed answer, never
// the late verdict. A per-user call keeps its answer.
func TestAManagedVerdictReadAfterTheDeadlineGetsTheWatchdogsAnswer(t *testing.T) {
	const verdict = `{"systemMessage":"late gateway verdict"}`
	for _, managed := range []bool{true, false} {
		name := "per-user"
		if managed {
			name = "managed"
		}
		t.Run(name, func(t *testing.T) {
			sp, _ := specFor("claudecode")
			var stdout, stderr bytes.Buffer
			opts := Options{Connector: "claudecode", Event: "PreToolUse", ManagedEnterprise: managed, FailMode: "closed",
				Stdout: &stdout, Stderr: &stderr}
			w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
			passed := time.Now().Add(-time.Millisecond)
			w.waiter.extendTo(passed)
			// The verdict is read, then the watchdog's thread runs.
			_, _ = w.out.WriteString(verdict)
			w.answered()
			go w.watch(passed)
			code := w.finish(0)
			shown := stdout.String() + stderr.String()
			if managed {
				if code == 0 || strings.Contains(shown, "late gateway verdict") || !strings.Contains(shown, managedGatewayNoAnswerReason) {
					t.Fatalf("exit %d answer %q, want the watchdog's closed %s answer", code, shown, managedGatewayNoAnswerReason)
				}
				return
			}
			if code != 0 || shown != verdict {
				t.Fatalf("exit %d answer %q, want the per-user call's own answer", code, shown)
			}
		})
	}
}
