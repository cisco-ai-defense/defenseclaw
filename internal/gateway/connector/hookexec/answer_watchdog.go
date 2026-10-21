// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"time"
)

// answerWatchdogLogWait bounds the hook-failure log line the watchdog writes
// after its answer: a stalled disk must not hold the process past it.
var answerWatchdogLogWait = 100 * time.Millisecond

// answerWatchdog makes the answer budget of a tool call hold when the hook
// process itself runs late. On a host that lifecycle work saturates (the
// Windows attestation repair of GAP-0155 and GAP-0167) the call's own
// goroutines can be held past the budget in work that no context ends: a
// service-manager query, the account and session lookups, a file read, or
// simply no CPU. The deny of such a call came a second or more after the
// budget.
//
// The watchdog renders the call's fail-closed answer (failNoAnswer: closed
// for a managed hook, the account's fail mode for a per-user hook) when the
// call starts, and at the answer deadline writes it and ends the process
// (Options.Exit), unless the call's own result is out or the gateway's
// decision is in. A 102 report that the gateway waits on a remote scanner
// moves the deadline to the progress ceiling (hookProgressCeiling), never
// further. Until then the call's output is held in memory, so exactly one
// answer reaches the agent. On Windows the watchdog waits on its own thread
// at the highest priority of the process (answerDeadlineWaiter), so
// ordinary-priority work that fills the CPU does not delay it. It never
// allows a call: its answer is the one the call gives when its gateway does
// not answer in time.
type answerWatchdog struct {
	mu       sync.Mutex
	finished bool
	fired    bool

	stdout, stderr io.Writer
	out, err       bytes.Buffer

	fallbackOut, fallbackErr []byte
	fallbackCode             int
	logFailure               func()
	exit                     func(int)

	ceiling time.Time
	waiter  *answerDeadlineWaiter
}

// AnswerWatchdog is the answer watchdog of one tool call that the hook
// command arms (ArmAnswerWatchdog) before it resolves the hook's runtime, and
// that Run adopts (Options.AnswerWatchdog).
type AnswerWatchdog = answerWatchdog

// ArmAnswerWatchdog arms the answer watchdog of a tool call as soon as the
// hook process has read the call, before the work that comes before Run: the
// managed runtime descriptor, the account, the hook sidecar and the fail
// mode. That work counts against the call's budget too, and on a host that a
// login or an installer stalled it held managed macOS calls past the budget,
// some with no answer at all, because the watchdog was armed only inside Run
// (GAP-0155, BM-03, BM-05). opts carries what the command line says
// (Connector, Event, FailMode, HookSurface, ManagedEnterprise, SecureClient,
// StartedAt, Exit); the payload names the event when the command does not.
// Until Run adopts it the prepared answer is closed for a managed hook and
// for a per-user hook whose command line does not say open. It returns nil
// when the call has no answer deadline (not a tool call, a Secure Client
// hook, no start time).
func ArmAnswerWatchdog(opts Options, payload []byte) *AnswerWatchdog {
	sp, ok := specFor(opts.Connector)
	if !ok || opts.StartedAt.IsZero() {
		return nil
	}
	opts.Stdin = strings.NewReader("")
	opts = withDefaults(opts)
	if copilotVSCodeLocal(opts) {
		sp = copilotVSCodeLocalSpec
	}
	opts.Event = resolveHookEvent(opts.Event, payload)
	deadline := answerDeadline(opts, opts.StartedAt)
	if deadline.IsZero() {
		return nil
	}
	failMode := "closed"
	if opts.ManagedEnterprise {
		opts.FailMode = "closed"
		// A managed hook writes no failure log into the account's home.
		opts.Home = ""
	} else if strings.EqualFold(strings.TrimSpace(opts.FailMode), "open") {
		failMode = "open"
	}
	return startAnswerWatchdog(&opts, sp, failMode, deadline, progressCeiling(opts, opts.StartedAt))
}

// startAnswerWatchdog arms the watchdog of a tool call whose answer is due at
// deadline (at ceiling after a progress report). It points opts at the held
// output; Run returns through finish.
func startAnswerWatchdog(opts *Options, sp spec, failMode string, deadline, ceiling time.Time) *answerWatchdog {
	w := &answerWatchdog{stdout: opts.Stdout, stderr: opts.Stderr, exit: opts.Exit, ceiling: ceiling, waiter: newAnswerDeadlineWaiter()}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = renderNoAnswer(*opts, sp, failMode)
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
	go w.watch(deadline)
	return w
}

// renderNoAnswer renders the answer of a call whose gateway did not answer
// in time, and the failure log line it writes when it is given.
func renderNoAnswer(opts Options, sp spec, failMode string) (stdout, stderr []byte, code int, logFailure func()) {
	if opts.answerSpentLocally {
		// The answer is closed (failNoAnswer), and so is its log line.
		failMode = "closed"
	}
	var out, errb bytes.Buffer
	rendered := opts
	rendered.Stdout, rendered.Stderr = &out, &errb
	// Rendering only: the failure is logged when the watchdog answers.
	rendered.Home = ""
	code = failNoAnswer(rendered, sp, failMode)
	logged := opts
	// The rendered answer already carries any fail-open warning.
	logged.Stderr = io.Discard
	logFailure = func() {
		if logged.ManagedEnterprise {
			logHookFailure(logged, sp, managedGatewayNoAnswerReason, "transport", failMode,
				logged.StrictAvailability || failMode == "closed")
			return
		}
		logHookFailure(logged, sp, perUserGatewayNoAnswerReason, "transport", failMode,
			!sp.failOpenOnly && (logged.StrictAvailability || failMode == "closed"))
	}
	return out.Bytes(), errb.Bytes(), code, logFailure
}

// adopt renders the watchdog's answer again for the call Run resolved (its
// event, fail mode and runtime), unless it was already given.
func (w *answerWatchdog) adopt(opts Options, sp spec, failMode string) {
	stdout, stderr, code, logFailure := renderNoAnswer(opts, sp, failMode)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return
	}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = stdout, stderr, code, logFailure
}

// hold points opts at the watchdog's held output (Run of an adopted call).
func (w *answerWatchdog) hold(opts *Options) {
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
}

func (w *answerWatchdog) watch(deadline time.Time) {
	if !w.waiter.wait(deadline) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return
	}
	w.fired = true
	_, _ = w.stderr.Write(w.fallbackErr)
	_, _ = w.stdout.Write(w.fallbackOut)
	if w.exit == nil {
		w.logFailure()
		return
	}
	logged := make(chan struct{})
	logFailure := w.logFailure
	go func() {
		defer close(logged)
		logFailure()
	}()
	timer := time.NewTimer(answerWatchdogLogWait)
	select {
	case <-logged:
	case <-timer.C:
	}
	timer.Stop()
	// Production exits here; the lock is never released, so the call's own
	// output cannot follow the answer.
	w.exit(w.fallbackCode)
}

// answered stands the watchdog down: the gateway's decision is in. Safe on
// a nil watchdog.
func (w *answerWatchdog) answered() {
	if w != nil {
		w.waiter.cancel()
	}
}

// progressed moves the watchdog's deadline to the progress ceiling: the
// gateway reported that the decision waits on a remote scanner. Safe on a
// nil watchdog.
func (w *answerWatchdog) progressed() {
	if w != nil {
		w.waiter.extendTo(w.ceiling)
	}
}

// Finish ends a call that the hook command answers itself (or with nothing)
// before Run: it stands the watchdog down unless it already answered and
// returns the exit status of the answer the agent got. Safe on a nil
// watchdog.
func (w *AnswerWatchdog) Finish(code int) int {
	if w == nil {
		return code
	}
	return w.finish(code)
}

// finish writes the call's own result unless the watchdog already answered,
// and returns the exit status of the answer the agent got.
func (w *answerWatchdog) finish(code int) int {
	w.waiter.cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return w.fallbackCode
	}
	w.finished = true
	_, _ = w.stderr.Write(w.err.Bytes())
	_, _ = w.stdout.Write(w.out.Bytes())
	return code
}
