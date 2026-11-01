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
// after its answer: a stalled disk must not hold the process past it. The
// account lookup of a managed row is not inside it: that runs in the
// background from the moment the watchdog is armed (failureLogHomeLookup).
var answerWatchdogLogWait = 100 * time.Millisecond

// installLockCheckWait bounds the watchdog's look at the account's install
// lock before it gives an answer that is not closed (GAP-0862): a stalled
// disk must not hold the answer, and a lock it could not read in time counts
// as held, so the answer is closed.
var installLockCheckWait = 100 * time.Millisecond

// answerWatchdog makes the answer budget of a tool call hold when the hook
// process itself runs late. On a host that lifecycle work saturates (the
// Windows attestation repair of GAP-0155 and GAP-0167) the call's own
// goroutines can be held past the budget in work that no context ends: a
// service-manager query, the account and session lookups, a file read, or
// simply no CPU. The deny of such a call came a second or more after the
// budget.
//
// The watchdog renders the call's fail-closed answer (failNoAnswer) when the
// call starts, and at the answer deadline writes it and ends the process
// (Options.Exit), unless the call's own result is out or the gateway's
// decision is in. A 102 report that the gateway waits on a remote scanner
// moves the deadline to the progress ceiling (hookProgressCeiling), never
// further. Until then the call's output is held in memory, so exactly one
// answer reaches the agent. On Windows the watchdog waits on its own thread
// at the highest priority of the process (answerDeadlineWaiter), so
// ordinary-priority work that fills the CPU does not delay it. It never
// allows a call: its answer is the one the call gives when its gateway does
// not answer in time, and once the call logged a closed failure (an
// unverified gateway peer, an invalid runtime) it is that call's closed
// answer in every fail mode (claimFailureLog). While this account's
// installer holds its data directory (.install.lock) the answer is closed
// too: a per-user hook in fail mode open checks the lock when the watchdog
// is armed and again at the deadline, before it answers (GAP-0862). A
// managed hook whose administrator chose open checks its computer's
// lifecycle the same way at the deadline (managedLifecycleActive, GAP-1074).
type answerWatchdog struct {
	mu             sync.Mutex
	finished       bool
	fired          bool
	failureLogged  bool
	failureLogDone chan struct{}
	// closedKnown is set once the watchdog's answer is closed: the call
	// logged a failure that is closed, or the gateway answered an HTTP
	// error status (closeForAnsweredError, gatewayAnsweredError).
	closedKnown bool
	// failureClosed is set only when the call itself logged a closed
	// failure (claimFailureLog): the hook then blocks locally, and its
	// delivery receipt says so. A 429 or an error status that a later
	// answer replaced does not block the call, so it acknowledges.
	failureClosed bool
	// claimedAnswer is set once the prepared answer is the one of the
	// failure row this call claimed (claimFailureLog): the row is written
	// with that reason, so no later render replaces the answer, and the
	// answer the agent gets names what the row names (rel-1-0-6 GAP-0294).
	claimedAnswer bool
	// logHome is the background lookup of the invoking user's diagnostic
	// directory of a managed call (cacheFailureLogHome).
	logHome *failureLogHomeLookup

	stdout, stderr io.Writer
	out, err       bytes.Buffer

	fallbackOut, fallbackErr []byte
	fallbackCode             int
	logFailure               func()
	exit                     func(int)
	deliveryReceipt          func(bool, bool)

	// installCheck is the install look of a call whose fallback is not
	// closed: the .install.lock of a per-user call's data directory
	// (GAP-0862), the lifecycle of a managed call's computer (GAP-1074). At
	// the deadline the watchdog gives the install answer below instead when
	// it says held, or does not answer in time. Nil when the fallback is
	// closed already.
	installCheck           func() bool
	installOut, installErr []byte
	installCode            int
	installLogFailure      func()

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
// StartedAt, Exit) and, for a managed hook, the resolver of the invoking
// user's diagnostic directory (FailureLogHome); the payload names the event
// when the command does not. That lookup starts before the watchdog can
// fire, so a deadline that passes before Run adopts the watchdog still
// leaves the call its hook-failures row.
// Until Run adopts it the prepared answer is closed outside Secure Client.
// It returns nil
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
		// Not an enforcement home: a managed row goes only to the invoking
		// user's diagnostic directory (FailureLogHome). An armed watchdog
		// that dropped that resolver answered a deadline before Run with no
		// row at all (G-small loop 4).
		opts.Home = ""
	} else if !opts.SecureClient && opts.Home != "" && installLockHeldWithin(opts.Home, installLockCheckWait) {
		// Run would close this call (runHook): so does its early answer.
		// The look is bounded: arming must not wait on a stalled disk.
		opts.FailMode = "closed"
		opts.StrictAvailability = true
		opts.installWindowSeen = true
	} else if strings.EqualFold(strings.TrimSpace(opts.FailMode), "open") {
		failMode = "open"
	}
	return startAnswerWatchdog(&opts, sp, failMode, deadline, progressCeiling(opts, opts.StartedAt))
}

// startAnswerWatchdog arms the watchdog of a tool call whose answer is due at
// deadline (at ceiling after a progress report). It points opts at the held
// output; Run returns through finish.
func startAnswerWatchdog(opts *Options, sp spec, failMode string, deadline, ceiling time.Time) *answerWatchdog {
	w := prepareAnswerWatchdog(opts, sp, failMode, ceiling)
	go w.watch(deadline)
	return w
}

// prepareAnswerWatchdog is startAnswerWatchdog without the wait for the
// deadline: it renders the watchdog's answer and points opts at the held
// output.
func prepareAnswerWatchdog(opts *Options, sp spec, failMode string, ceiling time.Time) *answerWatchdog {
	w := &answerWatchdog{stdout: opts.Stdout, stderr: opts.Stderr, exit: opts.Exit, ceiling: ceiling, waiter: newAnswerDeadlineWaiter()}
	w.cacheFailureLogHome(opts)
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = renderNoAnswer(*opts, sp, failMode)
	w.installCheck, w.installOut, w.installErr, w.installCode, w.installLogFailure = renderInstallAnswer(*opts, sp, failMode)
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
	return w
}

// renderNoAnswer renders the answer of a call whose gateway did not answer
// in time, and the failure log line it writes when it is given.
func renderNoAnswer(opts Options, sp spec, failMode string) (stdout, stderr []byte, code int, logFailure func()) {
	// The row and the rendered decision must use the same effective mode.
	failMode = noAnswerFailMode(opts, failMode)
	if opts.ManagedEnterprise {
		opts.managedNoAnswerCode = managedNoAnswerReason(opts)
	}
	var out, errb bytes.Buffer
	rendered := opts
	rendered.Stdout, rendered.Stderr = &out, &errb
	// Rendering only: the failure is logged when the watchdog answers.
	rendered.Home = ""
	rendered.FailureLogHome = nil
	rendered.answerWatch = nil
	code = failNoAnswer(rendered, sp, failMode)
	logged := opts
	logged.answerWatch = nil
	// The rendered answer already carries any fail-open warning.
	logged.Stderr = io.Discard
	logFailure = func() {
		if managedNativeDecision(logged) && logged.answeredErrorStatus != 0 {
			logged.FailMode = "closed"
			logHookFailure(logged, sp, answeredErrorReason(logged), "response", "closed", true)
			return
		}
		if logged.ManagedEnterprise {
			logHookFailure(logged, sp, managedNoAnswerReason(logged), "transport", failMode,
				logged.StrictAvailability || failMode == "closed")
			return
		}
		logHookFailure(logged, sp, perUserGatewayNoAnswerReason, "transport", failMode,
			!sp.failOpenOnly && (logged.StrictAvailability || failMode == "closed"))
	}
	return out.Bytes(), errb.Bytes(), code, logFailure
}

// renderInstallAnswer renders the closed answer a call whose fallback is
// not closed gets when, at the deadline, an install holds it: the answer Run
// gives it then (closeDuringInstall closes the call and sets strict
// availability). The look is the per-user call's .install.lock, or the
// managed call's computer lifecycle (managedLifecycleActive). It returns no
// look, and nothing to give, when the fallback is closed already or the call
// is neither (a Secure Client hook, a per-user call with no home).
func renderInstallAnswer(opts Options, sp spec, failMode string) (check func() bool, stdout, stderr []byte, code int, logFailure func()) {
	if opts.answerSpentLocally || normalizeFailMode(failMode) == "closed" {
		return nil, nil, nil, 0, nil
	}
	switch {
	case managedNativeDecision(opts):
		managedOpts := opts
		check = func() bool { return managedLifecycleHeldWithin(managedOpts, installLockCheckWait) }
	case !opts.ManagedEnterprise && !opts.SecureClient && opts.Home != "":
		home := opts.Home
		check = func() bool { return installLockHeldWithin(home, installLockCheckWait) }
	default:
		return nil, nil, nil, 0, nil
	}
	closed := opts
	closed.FailMode = "closed"
	closed.StrictAvailability = true
	// Given only when the look at the deadline finds the install (watch).
	closed.installWindowSeen = true
	stdout, stderr, code, logFailure = renderNoAnswer(closed, sp, "closed")
	return check, stdout, stderr, code, logFailure
}

// adopt renders the watchdog's answer again for the call Run resolved (its
// event, fail mode and runtime), unless it was already given. A call that
// already logged a closed failure keeps a closed answer.
func (w *answerWatchdog) adopt(opts *Options, sp spec, failMode string) {
	w.mu.Lock()
	closed := w.closedKnown
	w.mu.Unlock()
	if closed {
		failMode = "closed"
	}
	stdout, stderr, code, logFailure := renderNoAnswer(*opts, sp, failMode)
	installCheck, installOut, installErr, installCode, installLogFailure := renderInstallAnswer(*opts, sp, failMode)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired || w.claimedAnswer || (w.closedKnown && !closed) {
		return
	}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = stdout, stderr, code, logFailure
	w.installCheck, w.installOut, w.installErr, w.installCode, w.installLogFailure =
		installCheck, installOut, installErr, installCode, installLogFailure
}

// closeForAnsweredError makes the watchdog's answer the closed response of a
// call the gateway already answered with an HTTP error. Safe on a nil watchdog.
func (w *answerWatchdog) closeForAnsweredError(opts Options, sp spec) {
	if w == nil {
		return
	}
	stdout, stderr, code, logFailure := renderNoAnswer(opts, sp, "closed")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return
	}
	w.closedKnown = true
	if w.claimedAnswer {
		// The call's row is written: its answer stays, and it is closed.
		return
	}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = stdout, stderr, code, logFailure
}

// claimFailureLog runs first in logHookFailure, before anything there can
// block (the account lookup of a managed row, a stalled disk). A failure
// that is closed makes the watchdog's answer closed: an administrator's
// fail mode open covers an outage only, and a known refusal (an unverified
// gateway peer, an invalid runtime, a missing token) that waited on its log
// line past the deadline got the watchdog's fail-open answer instead. It
// returns the channel to close once the row is written, and false when the
// watchdog already answered or the call's row is already claimed.
//
// The claim that writes the call's row also decides the watchdog's answer:
// for failUnreachable (unreachableAnswer) of a call outside Secure Client it
// is the answer failUnreachable gives for reason and failMode
// (renderClaimedFailure). Before,
// the watchdog kept its own no-answer text, so a call whose transport proved
// the gateway service stopped near the deadline (the Windows SCM read after
// the restart wait, on a loaded host) logged
// enterprise_managed_gateway_not_running and, when the deadline passed while
// the row was written, showed enterprise_managed_gateway_no_answer
// (rel-1-0-6 GAP-0294).
func (w *answerWatchdog) claimFailureLog(opts Options, sp spec, closed bool, reason, failMode string, unreachableAnswer bool) (chan struct{}, bool) {
	var out, errb []byte
	var code int
	var logFailure func()
	// Rendered outside the lock: a render can read the lifecycle marker.
	ownOut, ownErr, ownCode, own := renderClaimedFailure(opts, sp, reason, failMode, closed, unreachableAnswer)
	if closed {
		closedOpts := opts
		closedOpts.FailMode = "closed"
		out, errb, code, logFailure = renderNoAnswer(closedOpts, sp, "closed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return nil, false
	}
	if closed {
		w.closedKnown = true
		w.failureClosed = true
	}
	if w.failureLogged {
		// Another failure has the call's row. Its answer stays when it is
		// that row's (claimedAnswer, closed already); otherwise the answer
		// turns closed.
		if closed && !w.claimedAnswer {
			w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = out, errb, code, logFailure
		}
		return nil, false
	}
	w.failureLogged = true
	w.failureLogDone = make(chan struct{})
	switch {
	case own:
		w.claimedAnswer = true
		// This claim writes the row; the watchdog writes none of its own.
		w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = ownOut, ownErr, ownCode, func() {}
	case closed:
		w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = out, errb, code, logFailure
	}
	return w.failureLogDone, true
}

// renderClaimedFailure renders the answer of a transport failure that
// failUnreachable is about to log with reason and failMode, for a managed
// call outside Secure Client and for a per-user call: the answer
// failUnreachable gives for it (closed when the call is blocked; a per-user
// outage its open mode lets through keeps that allow and its warning). ok is
// false for every other failure (its own refusal text, a Secure Client
// hook, a connector with no fail-closed contract) and for a stop event: the
// watchdog keeps its answer for those.
func renderClaimedFailure(opts Options, sp spec, reason, failMode string, closed, unreachableAnswer bool) (stdout, stderr []byte, code int, ok bool) {
	if !unreachableAnswer || opts.SecureClient || strings.TrimSpace(reason) == "" || sp.failOpenOnly ||
		failClosedStopEvent(opts, sp) {
		return nil, nil, 0, false
	}
	if closed {
		failMode = "closed"
	}
	var out, errb bytes.Buffer
	rendered := opts
	rendered.Stdout, rendered.Stderr = &out, &errb
	// Rendering only: the claiming call writes the row, and the once-per-
	// session warning marker is left for it (HookDir).
	rendered.Home, rendered.FailureLogHome, rendered.answerWatch, rendered.HookDir = "", nil, nil, ""
	if closed {
		rendered.FailMode = "closed"
	}
	if mode := normalizeFailMode(failMode); rendered.OutageFailModeNow != nil {
		// The mode the caller already read; the render must not read it again.
		rendered.OutageFailModeNow = func() string { return mode }
	}
	code = failUnreachable(rendered, sp, failMode, reason)
	return out.Bytes(), errb.Bytes(), code, true
}

// perUserOutageSeen makes the watchdog's answer the outage answer of a
// per-user call whose first try err its gateway refused or dropped
// (perUserOutageError): the
// answer the call gives when the restart outlasts its budget
// (perUserGatewayRestartingReason, the outage mode of the config on disk),
// with its failure row from the same failUnreachable. Before, the deadline of
// such a call gave the did-not-answer refusal in every fail mode, so a
// default-tier account's benign calls were denied in its own gateway's
// restart window while the calls refused a moment earlier ran with the outage
// warning (rel-1-0-6 GAP-0295). A call that already logged a failure, an
// answered error and the watchdog's own answer keep theirs. Safe on a nil
// watchdog; managed, socket and Secure Client hooks are unchanged.
func (w *answerWatchdog) perUserOutageSeen(opts Options, sp spec, failMode string, err error) {
	// Only a refused or dropped call (perUserOutageError) met an outage: a
	// gateway that took the first try and did not answer keeps the closed
	// no-answer answer in every fail mode (GAP-2279).
	if w == nil || !perUserOutageError(opts, err) || opts.ManagedEnterprise || opts.ManagedUnixSocket != "" ||
		opts.SecureClient || sp.failOpenOnly {
		return
	}
	outage := withPerUserOutage(opts)
	outage.answerWatch = nil
	mode := perUserOutageMode(&outage, closeDuringInstall(&outage, failMode))
	outage.OutageFailModeNow = func() string { return mode }
	var out, errb bytes.Buffer
	rendered := outage
	rendered.Stdout, rendered.Stderr = &out, &errb
	rendered.Home, rendered.FailureLogHome, rendered.HookDir = "", nil, ""
	code := failUnreachable(rendered, sp, mode, perUserGatewayRestartingReason)
	logged := outage
	logged.Stdout, logged.Stderr = io.Discard, io.Discard
	logFailure := func() { _ = failUnreachable(logged, sp, mode, perUserGatewayRestartingReason) }
	installCheck, installOut, installErr, installCode, installLogFailure := renderInstallAnswer(outage, sp, mode)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired || w.claimedAnswer || w.closedKnown || w.failureLogged {
		return
	}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = out.Bytes(), errb.Bytes(), code, logFailure
	w.installCheck, w.installOut, w.installErr, w.installCode, w.installLogFailure =
		installCheck, installOut, installErr, installCode, installLogFailure
}

// failureLogHomeLookup resolves the invoking user's diagnostic directory of
// a managed call once, in the background. The account lookup behind it (NSS,
// Open Directory, a token Known Folder) can take longer than
// answerWatchdogLogWait; started when the watchdog is armed it is done long
// before the deadline, so the row of a call the watchdog answers is written
// before the process ends.
type failureLogHomeLookup struct {
	done chan struct{}
	home string
}

func startFailureLogHomeLookup(resolve func() string) *failureLogHomeLookup {
	l := &failureLogHomeLookup{done: make(chan struct{})}
	go func() {
		defer close(l.done)
		l.home = resolve()
	}()
	return l
}

// wait is the directory, once the lookup is done.
func (l *failureLogHomeLookup) wait() string {
	<-l.done
	return l.home
}

// cacheFailureLogHome points a managed call's FailureLogHome at the
// watchdog's lookup, and starts that lookup the first time: when the
// watchdog is armed (ArmAnswerWatchdog with the hook command's resolver, or
// Run), before its answer is rendered and before it can fire, and when Run
// takes over an armed watchdog (hold), before anything there can log. The
// call's rows, the watchdog's own included, use that one lookup. A call with no
// resolver writes no managed row.
func (w *answerWatchdog) cacheFailureLogHome(opts *Options) {
	if !opts.ManagedEnterprise || opts.FailureLogHome == nil {
		return
	}
	w.mu.Lock()
	if w.logHome == nil {
		w.logHome = startFailureLogHomeLookup(opts.FailureLogHome)
	}
	lookup := w.logHome
	w.mu.Unlock()
	opts.FailureLogHome = lookup.wait
}

// hold points opts at the watchdog's held output and at its lookup of the
// call's diagnostic directory (Run of a call the hook command armed). Run
// can fail and log before it adopts the watchdog (an invalid runtime, a
// missing home, a broken binding): that row must use the lookup the
// watchdog started when it was armed, not start a second one that can
// stall past the deadline while the watchdog waits on it (G-small loop
// round 3).
func (w *answerWatchdog) hold(opts *Options) {
	w.cacheFailureLogHome(opts)
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
}

func (w *answerWatchdog) watch(deadline time.Time) {
	if !w.waiter.wait(deadline) {
		return
	}
	w.mu.Lock()
	installCheck := w.installCheck
	w.mu.Unlock()
	// Outside the lock: Run must still be able to finish meanwhile.
	installing := installCheck != nil && installCheck()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return
	}
	if installing && !w.closedKnown && !w.claimedAnswer && w.installCheck != nil {
		w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure =
			w.installOut, w.installErr, w.installCode, w.installLogFailure
	}
	w.fired = true
	_, _ = w.stderr.Write(w.fallbackErr)
	_, _ = w.stdout.Write(w.fallbackOut)
	if w.exit == nil {
		if !w.failureLogged {
			w.logFailure()
		}
		return
	}
	if w.failureLogged {
		if w.failureLogDone != nil {
			timer := time.NewTimer(answerWatchdogLogWait)
			select {
			case <-w.failureLogDone:
			case <-timer.C:
			}
			timer.Stop()
		}
		w.exit(w.fallbackCode)
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

// gatewayAnsweredError makes the watchdog's answer closed after a gateway
// status has arrived. A 2xx answer whose body is still incomplete at the
// deadline is a response failure; an error status is no outage either.
// Safe on a nil watchdog.
func (w *answerWatchdog) gatewayAnsweredError(opts Options, sp spec, status int) {
	if w == nil {
		return
	}
	closedOpts := opts
	closedOpts.FailMode = "closed"
	out, errb, code, logFailure := renderNoAnswer(closedOpts, sp, "closed")
	if status >= 200 && status < 300 {
		// The watchdog may fire while the body read is still waiting. Use
		// the same response-layer reason the ordinary body-read path uses.
		var stdout, stderr bytes.Buffer
		rendered := closedOpts
		rendered.Stdout, rendered.Stderr = &stdout, &stderr
		rendered.Home, rendered.FailureLogHome, rendered.answerWatch = "", nil, nil
		code = failResponse(rendered, sp, "closed", "incomplete gateway response")
		out, errb = stdout.Bytes(), stderr.Bytes()
		logged := closedOpts
		logged.answerWatch = nil
		logged.Stderr = io.Discard
		logFailure = func() { logHookFailure(logged, sp, "incomplete gateway response", "response", "closed", true) }
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired || w.failureClosed || w.claimedAnswer || (w.closedKnown && (status < 200 || status >= 300)) {
		return
	}
	w.closedKnown = true
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = out, errb, code, logFailure
}

// installLockHeldWithin is installLockHeld bounded by wait: a look that
// takes longer counts as a held lock.
func installLockHeldWithin(home string, wait time.Duration) bool {
	// The read is taken now: a look still held on a stalled disk after the
	// answer touches nothing of the call's.
	lstat := installLockLstat
	return heldWithin(func() bool { return installLockHeldBy(lstat, home) }, wait)
}

// heldWithin runs the look check bounded by wait: a look that takes longer
// counts as held.
func heldWithin(check func() bool, wait time.Duration) bool {
	held := make(chan bool, 1)
	go func() { held <- check() }()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case h := <-held:
		return h
	case <-timer.C:
		return true
	}
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
		if w.deliveryReceipt != nil {
			w.deliveryReceipt(false, true)
		}
		return w.fallbackCode
	}
	w.finished = true
	_, _ = w.stderr.Write(w.err.Bytes())
	_, _ = w.stdout.Write(w.out.Bytes())
	if w.deliveryReceipt != nil {
		w.deliveryReceipt(true, w.failureClosed)
	}
	return code
}

func (w *answerWatchdog) setDeliveryReceipt(receipt func(bool, bool)) {
	w.mu.Lock()
	w.deliveryReceipt = receipt
	w.mu.Unlock()
}
