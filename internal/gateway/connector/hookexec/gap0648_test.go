// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"io"
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

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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

// gotConn tells the watch on ctx, if any, that the call has a connection to
// the gateway, as the HTTP transport does.
func gotConn(ctx context.Context) {
	if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{})
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
	// The call starts this long before its restart budget ends, as one the
	// agent launched late (the budgets are constants), so the test does not
	// wait them out. Both cases start alike.
	const lead = 300 * time.Millisecond
	// A running gateway keeps its answer window, cut by the process cap.
	capAt := managedAnswerDeadlineCap - gatewayRestartBudget + lead
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
		{"service stopping", false, managedGatewayRestartingReason, lead - 50*time.Millisecond, lead + 400*time.Millisecond},
		{"service running", true, managedGatewayNoAnswerReason, capAt - 100*time.Millisecond, capAt + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubManagedServiceRunning(t, func(name string) (bool, bool) { return test.running, name == "DefenseClawGateway" })
			home := t.TempDir()
			var result runResult
			var elapsed time.Duration
			reading := testenv.Measure(func() {
				result, elapsed = runAgainstGateway(t, "claudecode", hungGateway(t), func(opts *Options) {
					managedWindowsStandalone(opts)
					opts.ManagedGatewayServiceName = "DefenseClawGateway"
					opts.FailureLogHome = userLogHome(home)
					opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
					opts.StartedAt = opts.StartedAt.Add(-gatewayRestartBudget + lead)
				})
			})
			if !blocked(result) {
				t.Fatalf("after %s code=%d stdout=%q stderr=%q, want a block", elapsed, result.code, result.stdout, result.stderr)
			}
			// The upper bound is the wall time of the call. Only a call that
			// missed it is given the host (GAP-0889), and only the time the
			// thread that ran it was ready to run and had no CPU during that
			// call (testenv.Measure): a call that waited on anything else
			// keeps the miss, and the lower bound is not moved.
			if elapsed < test.atLeast || (elapsed >= test.below && !reading.Within(elapsed, test.below)) {
				t.Fatalf("blocked after %s, want in [%s, %s)", elapsed, test.atLeast, test.below)
			}
			entry := lastHookFailure(t, home)
			if entry["reason"] != test.reason || entry["outcome"] != "fail_closed" {
				t.Fatalf("failure row %v, want %s, fail_closed", entry, test.reason)
			}
		})
	}
}

// GAP-0648 review F3: the service watch ends a call that waits for an
// answer from the gateway, not the start of the installer-owned gateway. A
// managed Windows call refused until its restart budget starts the gateway
// then, while the service still reads stopped: the start and the call's one
// retry run to the gateway's verdict.
func TestManagedGatewayRecoveryRunsPastTheServiceWatch(t *testing.T) {
	fastRestartRetries(t)
	stubManagedLifecycle(t, func() bool { return false })
	stubManagedServiceRunning(t, func(string) (bool, bool) { return false, true })
	var started atomic.Bool
	rt := &stubRT{onRequest: func(*stubRT, *http.Request) (*http.Response, error) {
		if !started.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
	}}
	var recoveries atomic.Int64
	r := run(t, "codex", rt, func(opts *Options) {
		managedWindowsStandalone(opts)
		opts.ManagedGatewayServiceName = "DefenseClawGateway"
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 300*time.Millisecond)
		opts.GatewayRecovery = func(context.Context, error) error {
			recoveries.Add(1)
			// The service manager still reads the service stopped meanwhile.
			time.Sleep(200 * time.Millisecond)
			started.Store(true)
			return nil
		}
	})
	if r.code != 0 || blocked(r) || recoveries.Load() != 1 {
		t.Fatalf("code=%d recoveries=%d stdout=%q stderr=%q, want the started gateway's verdict", r.code, recoveries.Load(), r.stdout, r.stderr)
	}
}

// The watch proves a stop only from a state read in time, and only for a
// call connected to the gateway and still waiting: a running, unreadable or
// slow service, a call no gateway took, or a call that has its response,
// keeps the call's own deadline.
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
		refused bool // no connection to the gateway
		restart bool
	}{
		{name: "stopped at the budget", states: []bool{false}, known: true, restart: true},
		{name: "running, then stopped", states: []bool{true, true, false}, known: true, restart: true},
		{name: "running", states: []bool{true}, known: true},
		{name: "state not known", states: []bool{false}, known: false},
		{name: "state read too slow", read: slow},
		{name: "answered before the budget", states: []bool{false}, known: true, stopAt: 20 * time.Millisecond},
		{name: "stopped, no connection", states: []bool{false}, known: true, refused: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
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
			if !test.refused {
				gotConn(ctx)
			}
			if test.stopAt > 0 {
				time.Sleep(test.stopAt)
				stop()
			}
			// A call that must keep waiting is watched for 200 ms: the
			// deadline (60 ms) and 5 reads after it.
			wait := 400 * time.Millisecond
			if !test.restart {
				wait = 200 * time.Millisecond
			}
			select {
			case <-ctx.Done():
				if !test.restart || !errors.Is(context.Cause(ctx), errGatewayRestarting) {
					t.Fatalf("watch ended the call with %v, want it waiting", context.Cause(ctx))
				}
				if time.Now().Before(deadline) {
					t.Fatal("the call was ended before the restart budget")
				}
			case <-time.After(wait):
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
			t.Parallel()
			ctx, _, release := watchManagedGatewayStarts(context.Background(), test.opts, deadline)
			defer release()
			gotConn(ctx)
			wait := 300 * time.Millisecond
			if !test.watched {
				wait = 150 * time.Millisecond
			}
			select {
			case <-ctx.Done():
				if !test.watched {
					t.Fatalf("call ended with %v, want no watch", context.Cause(ctx))
				}
			case <-time.After(wait):
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

// GAP-0648 review R2-2: the service watch is stopped before the start of the
// installer-owned gateway also for a call a gateway took. The first try
// connects and the stopping gateway drops it; the next tries are refused
// until the restart budget; the service reads not running while the gateway
// starts. The watch, which a connection arms, would end that start.
func TestManagedGatewayRecoveryAfterAConnectionRunsPastTheServiceWatch(t *testing.T) {
	fastRestartRetries(t)
	stubManagedLifecycle(t, func() bool { return false })
	previousInterval := managedGatewayServiceWatchInterval
	managedGatewayServiceWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { managedGatewayServiceWatchInterval = previousInterval })
	var starting, started atomic.Bool
	stubManagedServiceRunning(t, func(string) (bool, bool) {
		// Not running only while the gateway starts: the watch cannot end
		// the call before the start begins.
		return !starting.Load() || started.Load(), true
	})
	rt := &stubRT{onRequest: func(s *stubRT, req *http.Request) (*http.Response, error) {
		switch {
		case started.Load():
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
		case s.requests == 1:
			// The stopping gateway takes the first try and drops it.
			gotConn(req.Context())
			return nil, syscall.ECONNRESET
		}
		return nil, syscall.ECONNREFUSED
	}}
	var recoveries atomic.Int64
	r := run(t, "codex", rt, func(opts *Options) {
		managedWindowsStandalone(opts)
		opts.ManagedGatewayServiceName = "DefenseClawGateway"
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 300*time.Millisecond)
		opts.GatewayRecovery = func(context.Context, error) error {
			recoveries.Add(1)
			starting.Store(true)
			// The watch reads the service about ten times meanwhile.
			time.Sleep(200 * time.Millisecond)
			started.Store(true)
			return nil
		}
	})
	if r.code != 0 || blocked(r) || recoveries.Load() != 1 || rt.requests < 3 {
		t.Fatalf("code=%d recoveries=%d requests=%d stdout=%q stderr=%q, want the started gateway's verdict",
			r.code, recoveries.Load(), rt.requests, r.stdout, r.stderr)
	}
}

// sleepClock is the sleep-counting clock of a computer that slept for slept
// after the test began: the awake clock and the timers did not see it.
type sleepClock struct{ slept atomic.Int64 }

func (c *sleepClock) now() (time.Duration, bool) {
	now, ok := platformSuspendClock()
	return now + time.Duration(c.slept.Load()), ok
}

// useSleepClock makes w's deadline read clock, when it counts sleep at all.
func useSleepClock(w *answerWatchdog, clock *sleepClock) {
	w.waiter.mu.Lock()
	defer w.waiter.mu.Unlock()
	if w.waiter.sleepClock != nil {
		w.waiter.sleepClock = clock.now
	}
}

// GAP-0648 review F4: a managed call's deadline counts the time the computer
// slept. A verdict read after a sleep that outlasted the budget gets the
// watchdog's closed answer, from a watchdog woken by the sleep-counting
// clock, not by its timer (2 s more of awake time). A per-user call keeps
// the verdict. EC2 test hosts cannot sleep: the sleep is the clock's.
func TestAManagedVerdictReadAfterASleepPastTheDeadlineGetsTheWatchdogsAnswer(t *testing.T) {
	if !hookClockAnchor.ok {
		t.Skip("no sleep-counting clock on this system")
	}
	const verdict = `{"systemMessage":"verdict after the sleep"}`
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
			clock := &sleepClock{}
			useSleepClock(w, clock)
			deadline := time.Now().Add(2 * time.Second)
			w.waiter.extendTo(deadline)
			go w.watch(deadline)
			// The watchdog waits on its timer.
			time.Sleep(20 * time.Millisecond)
			// A sleep shorter than the clock's steps moves nothing.
			clock.slept.Store(int64(suspendClockSlack / 2))
			if w.waiter.passed() {
				t.Fatal("the deadline passed with 2 s left")
			}
			// The computer sleeps 3 s; the verdict is read first after it.
			clock.slept.Store(int64(3 * time.Second))
			_, _ = w.out.WriteString(verdict)
			w.answered()
			began := time.Now()
			code := w.finish(0)
			took := time.Since(began)
			shown := stdout.String() + stderr.String()
			if !managed {
				if code != 0 || shown != verdict {
					t.Fatalf("exit %d answer %q, want the per-user call's own answer", code, shown)
				}
				return
			}
			if code == 0 || strings.Contains(shown, "verdict after the sleep") || !strings.Contains(shown, managedGatewayNoAnswerReason) {
				t.Fatalf("exit %d answer %q, want the watchdog's closed %s answer", code, shown, managedGatewayNoAnswerReason)
			}
			if took >= lateAnswerWait {
				t.Fatalf("answered after %s, want the watchdog woken by the sleep-counting clock", took)
			}
		})
	}
}

// GAP-0648 review F4: a late managed call whose watchdog does not answer
// within lateAnswerWait (its thread held) is answered for: the late verdict
// is never written.
func TestALateManagedVerdictIsNotWrittenWhileTheWatchdogIsHeld(t *testing.T) {
	previous := lateAnswerWait
	lateAnswerWait = 50 * time.Millisecond
	t.Cleanup(func() { lateAnswerWait = previous })
	sp, _ := specFor("claudecode")
	var stdout, stderr bytes.Buffer
	opts := Options{Connector: "claudecode", Event: "PreToolUse", ManagedEnterprise: true, FailMode: "closed",
		Stdout: &stdout, Stderr: &stderr}
	w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
	w.waiter.extendTo(time.Now().Add(-time.Millisecond))
	// The watchdog's thread never runs.
	_, _ = w.out.WriteString(`{"systemMessage":"late gateway verdict"}`)
	w.answered()
	code := w.finish(0)
	shown := stdout.String() + stderr.String()
	if code == 0 || strings.Contains(shown, "late gateway verdict") || !strings.Contains(shown, managedGatewayNoAnswerReason) {
		t.Fatalf("exit %d answer %q, want the watchdog's closed %s answer", code, shown, managedGatewayNoAnswerReason)
	}
}

// GAP-0648 review 3 S1: a managed verdict read before the deadline is the
// answer the agent gets, also when rendering it takes the call past the
// deadline: finish answers for the watchdog only when the watchdog is held
// (lateAnswerWait passed), never for one that stood down in time. The
// deadline passes on the injected sleep-counting clock, so the test does
// not sleep. Before, the agent got the closed no-answer reply.
func TestAManagedVerdictReadInTimeIsWrittenWhenItsCallFinishesPastTheDeadline(t *testing.T) {
	if !hookClockAnchor.ok {
		t.Skip("no sleep-counting clock on this system")
	}
	previous := lateAnswerWait
	lateAnswerWait = 5 * time.Second
	t.Cleanup(func() { lateAnswerWait = previous })
	const verdict = `{"systemMessage":"verdict read in time"}`
	for _, held := range []bool{false, true} {
		name := "the watchdog stands down"
		if held {
			name = "the watchdog's thread is held"
		}
		t.Run(name, func(t *testing.T) {
			sp, _ := specFor("claudecode")
			var stdout, stderr bytes.Buffer
			opts := Options{Connector: "claudecode", Event: "PreToolUse", ManagedEnterprise: true, FailMode: "closed",
				Stdout: &stdout, Stderr: &stderr}
			w := prepareAnswerWatchdog(&opts, sp, "closed", time.Time{})
			clock := &sleepClock{}
			useSleepClock(w, clock)
			deadline := time.Now().Add(time.Hour)
			w.waiter.extendTo(deadline)
			if !held {
				go w.watch(deadline)
			}
			// The verdict is read with an hour left.
			_, _ = w.out.WriteString(verdict)
			w.answered()
			// Rendering it takes the call past the deadline.
			clock.slept.Store(int64(2 * time.Hour))
			if !w.lateAnswerDue() {
				t.Fatal("the deadline has not passed")
			}
			began := time.Now()
			code := w.finish(0)
			took := time.Since(began)
			shown := stdout.String() + stderr.String()
			if code != 0 || shown != verdict {
				t.Fatalf("exit %d answer %q, want the verdict read in time", code, shown)
			}
			if took >= lateAnswerWait {
				t.Fatalf("finish waited %s for a watchdog that had stood down", took)
			}
		})
	}
}

// GAP-0648 review 3 L2: the answer finish gives for a held managed watchdog
// is the one watch would give: while the computer's lifecycle holds a call
// whose administrator chose open (an install or upgrade began during the
// call), the install answer and its closed hook-failures row (GAP-1074).
// Hermes shows the difference: its no-answer row is fail_open.
func TestALateManagedAnswerForAHeldWatchdogIsTheInstallAnswerDuringALifecycle(t *testing.T) {
	previousLate, previousLog := lateAnswerWait, answerWatchdogLogWait
	lateAnswerWait, answerWatchdogLogWait = 50*time.Millisecond, time.Minute
	t.Cleanup(func() { lateAnswerWait, answerWatchdogLogWait = previousLate, previousLog })
	var running atomic.Bool
	stubManagedLifecycle(t, running.Load)
	home := t.TempDir()
	sp, _ := specFor("hermes")
	var stdout, stderr bytes.Buffer
	opts := withDefaults(Options{Connector: "hermes", Event: "pre_tool_call", ManagedEnterprise: true, FailMode: "open",
		Stdout: &stdout, Stderr: &stderr, FailureLogHome: func() string { return home }})
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	if w.installCheck == nil {
		t.Fatal("no lifecycle look for the administrator's open")
	}
	install := string(w.install.out) + string(w.install.err)
	w.waiter.extendTo(time.Now().Add(-time.Millisecond))
	// The lifecycle starts; the watchdog's thread never runs.
	running.Store(true)
	_, _ = w.out.WriteString(`{"action":"allow"}`)
	w.answered()
	code := w.finish(0)
	shown := stdout.String() + stderr.String()
	if shown != install || code != w.install.code || strings.Contains(shown, `"allow"`) {
		t.Fatalf("exit %d answer %q, want the closed install answer %q", code, shown, install)
	}
	row, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil || !strings.Contains(string(row), `"outcome":"fail_closed"`) || strings.Contains(string(row), "fail_open") {
		t.Fatalf("hook-failures row %q (%v), want the install answer's fail_closed row", row, err)
	}
}

// The sleep-counting clock runs with the awake clock while the computer is
// awake (CLOCK_BOOTTIME, CLOCK_MONOTONIC_RAW, GetTickCount64 in 10-16 ms
// steps). Each reading of it is bracketed by two of the awake clock, so a
// test goroutine the host holds between two readings widens the bracket, not
// the error (GAP-0648 review 3 L3): the interval it measured lies within
// the bracket, to two steps of the coarsest clock (GetTickCount64, up to
// 15.6 ms each). Before, a fixed 40 ms around one reading failed on a
// loaded runner.
func TestTheSleepCountingClockRunsWithTheAwakeClock(t *testing.T) {
	const step = 32 * time.Millisecond
	before := time.Now()
	first, ok := platformSuspendClock()
	after := time.Now()
	if !ok {
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			t.Fatal("no sleep-counting clock")
		}
		t.Skip("no sleep-counting clock on this system")
	}
	time.Sleep(100 * time.Millisecond)
	beforeLast := time.Now()
	last, _ := platformSuspendClock()
	afterLast := time.Now()
	moved := last - first
	least, most := beforeLast.Sub(after), afterLast.Sub(before)
	if moved < least-step || moved > most+step {
		t.Fatalf("the sleep-counting clock moved %s while the awake clock moved between %s and %s", moved, least, most)
	}
}

// GAP-0648 re-check: Secure Client hooks are unchanged in 1.0.9. A Secure
// Client hook the computer held more than 30 s still gets a fresh budget and
// asks its gateway, as in 1.0.8. With the stale start it spent its request
// budget and got its Secure Client fail mode's answer without asking: an
// allow in fail mode open. Other managed hooks keep the stale start and are
// blocked without asking.
func TestASecureClientHookHeldPastItsBudgetStillAsksItsGateway(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name    string
		started time.Time
		ok      bool
		want    time.Time
	}{
		{"fresh", now.Add(-200 * time.Millisecond), true, now.Add(-200 * time.Millisecond)},
		{"held 30 s", now.Add(-30 * time.Second), true, now.Add(-30 * time.Second)},
		{"held 39 s", now.Add(-39 * time.Second), true, now},
		{"held 73 s", now.Add(-73 * time.Second), true, now},
		{"in the future (clock stepped back)", now.Add(time.Minute), true, now},
		{"not known", time.Time{}, false, now},
	} {
		if got := secureClientCallStart(test.started, test.ok, now, now); !got.Equal(test.want) {
			t.Errorf("%s: call start %s, want %s", test.name, got, test.want)
		}
	}
	stale := now.Add(-73 * time.Second)
	for _, secureClient := range []bool{true, false} {
		name := "managed"
		if secureClient {
			name = "Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			rt := ok(`{"action":"block"}`)
			r := run(t, "claudecode", rt, func(opts *Options) {
				opts.Event = "PreToolUse"
				if secureClient {
					opts.ManagedEnterprise, opts.SecureClient = true, true
					opts.StartedAt = secureClientCallStart(stale, true, now, time.Now())
				} else {
					managedWindowsStandalone(opts)
					opts.StartedAt = hookCallStart(stale, true, now)
				}
				opts.FailMode = "open"
			})
			wantRequests := 0
			if secureClient {
				wantRequests = 1
			}
			if rt.requests != wantRequests || !blocked(r) {
				t.Fatalf("%d gateway requests, code=%d stdout=%q stderr=%q; want %d and a block",
					rt.requests, r.code, r.stdout, r.stderr, wantRequests)
			}
		})
	}
}
