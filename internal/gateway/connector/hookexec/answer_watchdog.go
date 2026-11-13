// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock"
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

// watchdogAnswer keeps the native answer and its audit witness together.
// Every replacement of a pending answer replaces this whole value.
type watchdogAnswer struct {
	out, err         []byte
	code             int
	blocked          bool
	mode             string
	reason, category string
	logFailure       func()
	frame            []byte
}

// lateAnswerOutcome is the one policy input for a call with no usable gateway
// answer. The answer, receipt, and local record use the returned values.
// The balanced timeout policy can be changed here without adding a second
// decision path in the watchdog.
func lateAnswerOutcome(opts Options, sp spec, configured string) (mode, reason string, blocked bool) {
	mode = noAnswerFailMode(opts, configured)
	reason = perUserGatewayNoAnswerReason
	if opts.ManagedEnterprise {
		reason = managedNoAnswerReason(opts)
	}
	if sp.failOpenOnly {
		blocked = !opts.SecureClient && loggedFailMode(opts, sp, mode) == "closed"
	} else {
		blocked = mode == "closed" && !failClosedStopEvent(opts, sp)
	}
	return
}

// answerWatchdog makes the answer budget of a tool call hold when the hook
// process itself runs late. On a host that lifecycle work saturates (the
// Windows attestation repair of GAP-0155 and GAP-0167) the call's own
// goroutines can be held past the budget in work that no context ends: a
// service-manager query, the account and session lookups, a file read, or
// simply no CPU. The deny of such a call came a second or more after the
// budget.
//
// The watchdog renders the call's closed pre-contact answer when the
// call starts, and at the answer deadline writes it and ends the process
// (Options.Exit), unless the call's own result is out or the gateway's
// decision is in. A 102 report that the gateway waits on a remote scanner
// moves the deadline to the progress ceiling (hookProgressCeiling), never
// further. Until then the call's output is held in memory, so exactly one
// answer reaches the agent. On Windows the watchdog waits on its own thread
// at the highest priority of the process (answerDeadlineWaiter), so
// ordinary-priority work that fills the CPU does not delay it. Its result
// stays closed without a gateway decision. A proven outage may use the
// account's outage mode. Once the call logged a closed failure (an
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
	// managedOutagePrimed is an open answer backed by a stopped-service
	// proof. A later connection or a different failure withdraws it.
	managedOutagePrimed bool
	// logHome is the background lookup of the invoking user's diagnostic
	// directory of a managed call (cacheFailureLogHome).
	logHome *failureLogHomeLookup

	stdout, stderr io.Writer
	out, err       bytes.Buffer

	fallback         watchdogAnswer
	noDecision       watchdogAnswer
	secureClient     bool
	visibleOutage    func() ([]byte, []byte, int)
	exit             func(int)
	deliveryReceipt  func(bool, bool)
	deadlineDelivery *hookDeliveryRequest
	// revoke reads the call's patch targets once more after finish wrote an
	// allow, and replaces it with a block when one changed (hookexec,
	// GAP-0488, GAP-0073). It reports whether it did.
	revoke func(stdout, stderr io.Writer) (int, bool)

	// installCheck is the install look of a call whose fallback is not
	// closed: the .install.lock of a per-user call's data directory
	// (GAP-0862), the lifecycle of a managed call's computer (GAP-1074). At
	// the deadline the watchdog gives the install answer below instead when
	// it says held, or does not answer in time. Nil when the fallback is
	// closed already.
	installCheck func() bool
	install      watchdogAnswer
	// lookGen numbers the ordinary looks (startOrdinaryLook): only the look
	// of the latest rendering may open its answer.
	lookGen  int
	ordinary *ordinaryAnswer

	ceiling         time.Time
	waiter          *answerDeadlineWaiter
	decisionPending bool
	// answeredStatus is set once the gateway sent an HTTP status, and
	// progressSeen once it reported progress (102): it took the call, so
	// no restart-window proof applies.
	answeredStatus bool
	progressSeen   bool
	// restart is the outage answer of a per-user call that met its own
	// gateway's restart (perUserOutageSeen) or reached a gateway that only
	// just started (restartWindowContact). restartProof says, at the
	// deadline, whether the call's connection was held by a gateway that
	// started moments ago and had answered no call before it (GAP-0295).
	restart      *perUserRestartAnswer
	restartProof func() restartProofResult
	// failureLog is the call's hook-failure log, opened
	// answerWatchdogLogPrepareLead before the deadline (watch).
	failureLog     *preparedFailureLog
	failureLogHome func() string
	prepareLead    time.Duration

	// closeLateAnswer is set for a managed call outside Secure Client: once
	// its deadline has passed, the agent gets the watchdog's answer, never a
	// verdict that came late (lateAnswerDue). watchDone is closed when watch
	// returns.
	closeLateAnswer bool
	watchDone       chan struct{}
	watchDoneOnce   sync.Once
	// records counts the goroutines watch starts to write the record of its
	// answer (the ordinary failure line and the prepared marker). watch exits
	// once one of them has recorded the answer; the other may still be
	// writing in the account's logs folder. Production exits the process
	// there; a test that simulates the exit waits for them (records.Wait).
	records sync.WaitGroup
	// answeredInTime is set when answered stood a managed call's watchdog
	// down before its deadline: the call's own answer is then the one
	// written, also when the call finishes after the deadline (GAP-0648
	// review 3 S1). Atomic, not under mu: answered runs from the delivery
	// receipt that finish and answerLate send while they hold mu.
	answeredInTime atomic.Bool
}

// lateAnswerWait bounds how long a managed call's own answer, ready after
// its deadline, waits for the watchdog's answer (watch is bounded by its own
// waits: the restart proof, the install look and the log line). A watchdog
// that has not answered by then is answered for (answerLate).
var lateAnswerWait = time.Second

// lateAnswerDue reports a managed call whose deadline has passed while the
// watchdog still owns its answer: the gateway's verdict, or the call's own
// result, came too late, and the watchdog answers it. One deadline holds for
// the whole call: before, a verdict read in the moment the watchdog's
// thread woke at the deadline (the host had held the process) could stand
// the watchdog down and reach the agent past it (rel-1-0-6 GAP-0648). The
// deadline counts the time the computer slept (countSleep), so a verdict
// read after a sleep that outlasted the budget is late too.
// Per-user and Secure Client calls keep their answer.
func (w *answerWatchdog) lateAnswerDue() bool {
	return w.closeLateAnswer && w.waiter.passed()
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
	opts.failurePayload = payload
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
	// The deadline holds from now, also before the watch goroutine runs.
	w.waiter.extendTo(deadline)
	go w.watch(deadline)
	w.mu.Lock()
	w.lookGen++
	gen := w.lookGen
	w.mu.Unlock()
	w.startOrdinaryLook(gen, *opts, sp, failMode)
	return w
}

// ordinaryAnswer is the open no-answer answer of a per-user call whose
// payload the shared reader proved ordinary (startOrdinaryLook); it is
// given only if the account tier read at the deadline is open.
type ordinaryAnswer struct {
	answer       watchdogAnswer
	tier         func() string
	installCheck func() bool
	install      watchdogAnswer
}

// lateOrdinaryTierWait bounds the tier read at the deadline: a read that
// stalls past it leaves the closed answer.
var lateOrdinaryTierWait = 250 * time.Millisecond

// startOrdinaryLook reads the payload's protected reach once the deadline
// is armed and, for an ordinary call, renders its open answer. The account
// tier is read only when the watchdog answers (watch), never for a call the
// gateway answers. Until both prove the open tier the prepared closed answer
// stands, so a stalled read gives the closed answer at the deadline and
// never holds it (GAP-0641 review 7). Only the look of the latest rendering
// (gen) counts.
func (w *answerWatchdog) startOrdinaryLook(gen int, opts Options, sp spec, failMode string) {
	if !lateOrdinaryLookCall(opts) {
		return
	}
	go func() {
		if !bothLateScansOrdinary(opts) {
			return
		}
		opts.lateOrdinaryOpen = true
		answer := renderNoAnswer(opts, sp, failMode)
		if answer.mode != "open" {
			return
		}
		installCheck, install := renderInstallAnswer(opts, sp, answer.mode)
		w.mu.Lock()
		defer w.mu.Unlock()
		if gen == w.lookGen {
			w.ordinary = &ordinaryAnswer{answer: answer, tier: opts.OutageFailModeNow, installCheck: installCheck, install: install}
		}
	}()
}

// ordinaryOwedLocked reports a watchdog still due to give its prepared
// no-decision answer, which an ordinary open answer may then replace.
func (w *answerWatchdog) ordinaryOwedLocked() bool {
	return !w.fired && !w.finished && !w.answeredInTime.Load() && !w.claimedAnswer &&
		!w.failureClosed && !w.failureLogged && !w.answeredStatus && sameWatchdogAnswer(w.fallback, w.noDecision)
}

// useOrdinaryAtDeadline gives the ordinary open answer when the account
// tier, read now within lateOrdinaryTierWait, is open.
func (w *answerWatchdog) useOrdinaryAtDeadline() {
	w.mu.Lock()
	ordinary := w.ordinary
	owed := ordinary != nil && ordinary.tier != nil && w.ordinaryOwedLocked()
	w.mu.Unlock()
	if !owed {
		return
	}
	tier := make(chan string, 1)
	go func() { tier <- ordinary.tier() }()
	timer := time.NewTimer(lateOrdinaryTierWait)
	defer timer.Stop()
	select {
	case mode := <-tier:
		if normalizeFailMode(mode) != "open" {
			return
		}
	case <-timer.C:
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ordinary != ordinary || !w.ordinaryOwedLocked() {
		return
	}
	w.fallback, w.noDecision = ordinary.answer, ordinary.answer
	if w.failureLog.markerEnabled {
		w.failureLog.replaceFallbackFrame(ordinary.answer.frame)
	}
	w.installCheck, w.install = ordinary.installCheck, ordinary.install
}

// sameWatchdogAnswer reports whether a is the rendering b itself, not
// another answer: an assignment shares the rendered buffers.
func sameWatchdogAnswer(a, b watchdogAnswer) bool {
	same := func(x, y []byte) bool { return len(x) == len(y) && (len(x) == 0 || &x[0] == &y[0]) }
	return a.code == b.code && a.mode == b.mode && same(a.out, b.out) && same(a.err, b.err)
}

// prepareAnswerWatchdog is startAnswerWatchdog without the wait for the
// deadline: it renders the watchdog's answer and points opts at the held
// output.
func prepareAnswerWatchdog(opts *Options, sp spec, failMode string, ceiling time.Time) *answerWatchdog {
	w := &answerWatchdog{stdout: opts.Stdout, stderr: opts.Stderr, exit: opts.Exit, ceiling: ceiling, waiter: newAnswerDeadlineWaiter(), secureClient: opts.SecureClient,
		failureLog: newPreparedFailureLog(), prepareLead: answerWatchdogLogPrepareLead,
		closeLateAnswer: managedNativeDecision(*opts), watchDone: make(chan struct{})}
	if w.closeLateAnswer {
		// One deadline for the whole call, also across a sleep of the
		// computer (GAP-0648 review F4).
		w.waiter.countSleep(platformSuspendClock)
	}
	w.failureLog.markerEnabled = !opts.ManagedEnterprise && !opts.SecureClient
	w.cacheFailureLogHome(opts)
	opts.failureLog = w.failureLog
	w.failureLogHome = failureLogHomeOf(*opts)
	w.fallback = renderNoAnswer(*opts, sp, failMode)
	w.noDecision = w.fallback
	if w.failureLog.markerEnabled {
		w.failureLog.setFallbackFrame(w.noDecision.frame)
	}
	w.installCheck, w.install = renderInstallAnswer(*opts, sp, failMode)
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
	return w
}

// renderNoAnswer renders the answer of a call whose gateway did not answer
// in time, and the failure log line it writes when it is given.
func renderNoAnswer(opts Options, sp spec, failMode string) watchdogAnswer {
	// The row and the rendered decision must use the same effective mode.
	failMode, reason, blocked := lateAnswerOutcome(opts, sp, failMode)
	category := "transport"
	if managedNativeDecision(opts) && opts.answeredErrorStatus != 0 {
		reason, category = answeredErrorReason(opts), "response"
	}
	if opts.ManagedEnterprise {
		opts.managedNoAnswerCode = reason
	}
	var out, errb bytes.Buffer
	rendered := opts
	rendered.Stdout, rendered.Stderr = &out, &errb
	// Rendering only: the failure is logged when the watchdog answers.
	rendered.Home = ""
	rendered.FailureLogHome = nil
	rendered.answerWatch = nil
	// Preparing a fallback must not consume this session's warning marker:
	// the request may still receive a gateway answer before the deadline.
	rendered.HookDir = ""
	if !rendered.ManagedEnterprise && !rendered.SecureClient && rendered.ManagedUnixSocket == "" {
		rendered.OutageFailModeNow = func() string { return failMode }
	}
	code := failNoAnswerInMode(rendered, sp, failMode)
	logged := opts
	logged.answerWatch = nil
	// The rendered answer already carries any fail-open warning.
	logged.Stderr = io.Discard
	logBlocked := blocked
	if logged.SecureClient {
		// Preserve the Secure Client record contract while its native
		// answer path keeps the established policy.
		logBlocked = logged.StrictAvailability || failMode == "closed"
		if !logged.ManagedEnterprise {
			logBlocked = !sp.failOpenOnly && logBlocked
		}
	}
	logFailure := func() {
		if managedNativeDecision(logged) && logged.answeredErrorStatus != 0 {
			logged.FailMode = "closed"
			logHookFailure(logged, sp, reason, category, "closed", true)
			return
		}
		if logged.ManagedEnterprise {
			logHookFailure(logged, sp, reason, category, failMode, logBlocked)
			return
		}
		logHookFailure(logged, sp, reason, category, failMode, logBlocked)
	}
	return watchdogAnswer{
		out: out.Bytes(), err: errb.Bytes(), code: code, blocked: blocked,
		mode: failMode, reason: reason, category: category, logFailure: logFailure,
		frame: localFailureFallbackFrame(opts, sp, reason, category, failMode, blocked),
	}
}

// renderVisibleOutage reserves the session warning only when the watchdog
// actually answers. Its failure row is written separately by logFailure.
func renderVisibleOutage(opts Options, sp spec, mode, reason string) (stdout, stderr []byte, code int) {
	var out, errb bytes.Buffer
	rendered := opts
	rendered.Stdout, rendered.Stderr = &out, &errb
	rendered.Home, rendered.FailureLogHome, rendered.answerWatch = "", nil, nil
	rendered.OutageFailModeNow = func() string { return mode }
	code = failUnreachable(rendered, sp, mode, reason)
	return out.Bytes(), errb.Bytes(), code
}

// renderInstallAnswer renders the closed answer a call whose fallback is
// not closed gets when, at the deadline, an install holds it: the answer Run
// gives it then (closeDuringInstall closes the call and sets strict
// availability). The look is the per-user call's .install.lock, or the
// managed call's computer lifecycle (managedLifecycleActive). It returns no
// look, and nothing to give, when the fallback is closed already or the call
// is neither (a Secure Client hook, a per-user call with no home).
func renderInstallAnswer(opts Options, sp spec, failMode string) (check func() bool, answer watchdogAnswer) {
	if opts.answerSpentLocally || normalizeFailMode(failMode) == "closed" {
		return nil, watchdogAnswer{}
	}
	switch {
	case managedNativeDecision(opts):
		managedOpts := opts
		check = func() bool { return managedLifecycleHeldWithin(managedOpts, installLockCheckWait) }
	case !opts.ManagedEnterprise && !opts.SecureClient && opts.Home != "":
		home := opts.Home
		check = func() bool { return installLockHeldWithin(home, installLockCheckWait) }
	default:
		return nil, watchdogAnswer{}
	}
	closed := opts
	closed.FailMode = "closed"
	closed.StrictAvailability = true
	// Given only when the look at the deadline finds the install (watch).
	closed.installWindowSeen = true
	return check, renderNoAnswer(closed, sp, "closed")
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
	opts.failureLog = w.failureLog
	answer := renderNoAnswer(*opts, sp, failMode)
	installCheck, installAnswer := renderInstallAnswer(*opts, sp, failMode)
	w.mu.Lock()
	if w.fired || w.claimedAnswer || (w.closedKnown && !closed) {
		w.mu.Unlock()
		return
	}
	w.fallback, w.noDecision = answer, answer
	if w.failureLog.markerEnabled {
		w.failureLog.replaceFallbackFrame(answer.frame)
	}
	w.visibleOutage = nil
	w.installCheck, w.install = installCheck, installAnswer
	w.lookGen++
	w.ordinary = nil
	gen := w.lookGen
	w.mu.Unlock()
	w.startOrdinaryLook(gen, *opts, sp, failMode)
}

// closeForAnsweredError makes the watchdog's answer the closed response of a
// call the gateway already answered with an HTTP error. Safe on a nil watchdog.
func (w *answerWatchdog) closeForAnsweredError(opts Options, sp spec) {
	if w == nil {
		return
	}
	answer := renderNoAnswer(opts, sp, "closed")
	w.mu.Lock()
	defer w.mu.Unlock()
	w.answeredStatus = true
	if w.fired {
		return
	}
	w.closedKnown = true
	if w.claimedAnswer {
		// The call's row is written: its answer stays, and it is closed.
		return
	}
	w.fallback = answer
	w.visibleOutage = nil
	if len(answer.frame) != 0 {
		w.failureLog.replaceFallbackFrame(answer.frame)
	}
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
func (w *answerWatchdog) claimFailureLog(opts Options, sp spec, closed bool, reason, failMode string, unreachableAnswer bool, frame ...[]byte) (chan struct{}, bool) {
	var closedAnswer watchdogAnswer
	// Rendered outside the lock: a render can read the lifecycle marker.
	ownAnswer, own := renderClaimedFailure(opts, sp, reason, failMode, closed, unreachableAnswer)
	if closed {
		closedOpts := opts
		closedOpts.FailMode = "closed"
		closedAnswer = renderNoAnswer(closedOpts, sp, "closed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return nil, false
	}
	w.visibleOutage = nil
	if closed {
		w.closedKnown = true
		w.failureClosed = true
	}
	if w.failureLogged {
		// Another failure has the call's row. Its answer stays when it is
		// that row's (claimedAnswer, closed already); otherwise the answer
		// turns closed.
		if closed && !w.claimedAnswer {
			w.fallback = closedAnswer
		}
		return nil, false
	}
	if len(frame) > 0 && len(frame[0]) > 0 {
		if own {
			w.failureLog.replaceFallbackFrame(frame[0])
		} else {
			w.failureLog.setFallbackFrame(frame[0])
		}
	}
	w.failureLogged = true
	w.failureLogDone = make(chan struct{})
	switch {
	case own:
		w.claimedAnswer = true
		// This claim writes the row; the watchdog writes none of its own.
		w.fallback = ownAnswer
	case closed:
		w.fallback = closedAnswer
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
func renderClaimedFailure(opts Options, sp spec, reason, failMode string, closed, unreachableAnswer bool) (answer watchdogAnswer, ok bool) {
	if !unreachableAnswer || opts.SecureClient || strings.TrimSpace(reason) == "" || sp.failOpenOnly ||
		failClosedStopEvent(opts, sp) {
		return watchdogAnswer{}, false
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
	code := failUnreachable(rendered, sp, failMode, reason)
	answer = watchdogAnswer{out: out.Bytes(), err: errb.Bytes(), code: code,
		blocked: closed, mode: failMode, reason: reason, category: "transport",
		logFailure: func() {},
		frame:      localFailureFallbackFrame(opts, sp, reason, "transport", failMode, closed)}
	return answer, true
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
	if w == nil || !perUserOutageError(opts, err) || !perUserRestartWindowCall(opts, sp) {
		return
	}
	answer := renderPerUserRestartAnswer(opts, sp, failMode, perUserGatewayRestartingReason)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.restart == nil {
		w.restart = answer
	}
	if w.fired || w.claimedAnswer || w.closedKnown || w.failureLogged {
		return
	}
	w.useRestartAnswerLocked(answer)
}

// managedOutageSeen preserves the administrator's open answer when a managed
// hook has already proved that its gateway service is stopped. A later
// connected try or a different failure restores the closed no-decision
// answer; the stopped service alone cannot authorize a call the new gateway
// has accepted. The lifecycle is checked again at the answer deadline.
func (w *answerWatchdog) managedOutageSeen(opts Options, sp spec, failMode string, err error) {
	if w == nil || !opts.ManagedEnterprise || opts.SecureClient {
		return
	}
	if err == nil {
		// A response supersedes an earlier stopped-service proof even when
		// a test transport does not provide a GotConn trace.
		if w.managedOutagePending() {
			w.noDecisionPending()
		}
		return
	}
	outage := withManagedOutage(opts, err)
	if outage.managedOutageOpen && !OrdinaryNoAnswerPayload(opts.failurePayload) {
		outage.managedOutageOpen = false
	}
	if !outage.managedOutageOpen {
		// The request's own deadline is not a later peer observation. The
		// connect trace withdraws the proof if this retry reached a peer.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, errGatewayNoAnswer) || errors.Is(err, errGatewayNotConnected) {
			return
		}
		w.mu.Lock()
		primed := w.managedOutagePrimed
		w.mu.Unlock()
		if primed {
			w.noDecisionPending()
		}
		return
	}
	reason := managedPeerFailureReason(opts, err)
	var out, errb bytes.Buffer
	rendered := outage
	rendered.Stdout, rendered.Stderr = &out, &errb
	rendered.Home, rendered.FailureLogHome, rendered.HookDir, rendered.answerWatch = "", nil, "", nil
	code := failUnreachable(rendered, sp, failMode, reason)
	logged := outage
	logged.answerWatch = nil
	logged.Stderr = io.Discard
	answer := watchdogAnswer{out: out.Bytes(), err: errb.Bytes(), code: code,
		mode: failMode, reason: reason, category: "transport",
		logFailure: func() { _ = failUnreachable(logged, sp, failMode, reason) },
		frame:      localFailureFallbackFrame(outage, sp, reason, "transport", failMode, false)}
	installCheck, install := renderInstallAnswer(outage, sp, failMode)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired || w.claimedAnswer || w.closedKnown || w.failureLogged || w.decisionPending {
		return
	}
	w.fallback = answer
	w.managedOutagePrimed = true
	w.visibleOutage = func() ([]byte, []byte, int) {
		return renderVisibleOutage(outage, sp, failMode, reason)
	}
	w.installCheck, w.install = installCheck, install
}

// managedOutagePending is the proof the request path can use if its context
// ends just before the watchdog writes the same prepared answer.
func (w *answerWatchdog) managedOutagePending() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.managedOutagePrimed && !w.closedKnown && !w.decisionPending && !w.answeredStatus
}

// perUserRestartWindowCall reports a per-user call (not managed, socket or
// Secure Client, and not fail-open-only) whose deadline may follow the
// account's outage mode.
func perUserRestartWindowCall(opts Options, sp spec) bool {
	return !opts.ManagedEnterprise && opts.ManagedUnixSocket == "" && !opts.SecureClient && !sp.failOpenOnly
}

// perUserRestartAnswer is the rendered outage answer of a per-user call whose
// gateway is restarting (perUserGatewayRestartingReason), in the outage mode
// read for the call, with its failure row and install-window answer.
type perUserRestartAnswer struct {
	mode         string
	answer       watchdogAnswer
	visible      func() ([]byte, []byte, int)
	installCheck func() bool
	install      watchdogAnswer
}

func renderPerUserRestartAnswer(opts Options, sp spec, failMode, reason string) *perUserRestartAnswer {
	outage := withPerUserOutage(opts)
	outage.answerWatch = nil
	mode := perUserOutageMode(&outage, closeDuringInstall(&outage, failMode))
	outage.OutageFailModeNow = func() string { return mode }
	var out, errb bytes.Buffer
	rendered := outage
	rendered.Stdout, rendered.Stderr = &out, &errb
	rendered.Home, rendered.FailureLogHome, rendered.HookDir = "", nil, ""
	answer := &perUserRestartAnswer{mode: mode}
	code := failUnreachable(rendered, sp, mode, reason)
	logged := outage
	logged.Stdout, logged.Stderr = io.Discard, io.Discard
	logFailure := func() { _ = failUnreachable(logged, sp, mode, reason) }
	if mode == "open" {
		answer.visible = func() ([]byte, []byte, int) {
			return renderVisibleOutage(outage, sp, mode, reason)
		}
	}
	blocked := !sp.failOpenOnly && mode == "closed" && !failClosedStopEvent(outage, sp)
	answer.answer = watchdogAnswer{out: out.Bytes(), err: errb.Bytes(), code: code,
		blocked: blocked, mode: mode, reason: reason,
		category: "transport", logFailure: logFailure,
		frame: localFailureFallbackFrame(outage, sp, reason, "transport", mode, blocked)}
	answer.installCheck, answer.install = renderInstallAnswer(outage, sp, mode)
	return answer
}

// useRestartAnswerLocked makes answer the watchdog's answer. w.mu is held.
func (w *answerWatchdog) useRestartAnswerLocked(answer *perUserRestartAnswer) {
	w.fallback = answer.answer
	w.visibleOutage = answer.visible
	w.installCheck, w.install = answer.installCheck, answer.install
	if len(answer.answer.frame) != 0 {
		w.failureLog.replaceFallbackFrame(answer.answer.frame)
	}
}

// restartWindowContact notes the proven connection of a per-user try. When
// this account's gateway record is only seconds old, the outage answer is
// prepared in the background (it reads the outage mode), so the deadline
// can give it if the proof holds then. Safe on a nil watchdog.
func (w *answerWatchdog) restartWindowContact(opts Options, sp spec, failMode string, check *perUserPeerCheck) {
	if w == nil || check == nil || opts.Home == "" || !perUserRestartWindowCall(opts, sp) {
		return
	}
	home := opts.Home
	// Read now: the proof runs on a goroutine that a proof past
	// restartProofWait leaves running (provenWithin, GAP-0680).
	proof := perUserRestartWindowProof
	w.mu.Lock()
	w.restartProof = func() restartProofResult { return proof(home, check) }
	prepared := w.restart != nil
	w.mu.Unlock()
	fresh := perUserGatewayRecentlyStarted(home)
	if !fresh && opts.lateOrdinary == nil {
		return
	}
	if fresh {
		perUserCaptureFreshGatewayOwner(home, check)
	}
	if prepared {
		return
	}
	go func() {
		reason := perUserGatewayRestartingReason
		if !fresh {
			// A gateway that has been up for a while and took the call may
			// only be late (a burst, a long operand list). Its call follows
			// the outage mode at the deadline when the scan finds nothing a
			// protected file could be reached through (GAP-0518); the proof
			// is the verified connection itself, with no status or progress
			// from it (restartWindowCandidateLocked).
			if !opts.lateOrdinary() {
				return
			}
			reason = perUserGatewayNoAnswerReason
			w.mu.Lock()
			w.restartProof = func() restartProofResult { return restartProofResult{ok: true} }
			w.mu.Unlock()
		}
		answer := renderPerUserRestartAnswer(opts, sp, failMode, reason)
		w.mu.Lock()
		if w.restart == nil {
			w.restart = answer
		}
		w.mu.Unlock()
	}()
}

// perUserRestartWindowProof reports whether the connection of check is held
// by this account's gateway that started moments ago and had answered no
// hook call before the connection; tests replace it.
var perUserRestartWindowProof = perUserFreshGatewayProof

type restartProofResult struct {
	ok     bool
	reason string
}

// restartProofWait bounds the restart-window proof at the deadline: a proof
// not done by then is no proof, and the call stays closed.
var restartProofWait = 250 * time.Millisecond

// restartWindowCandidate is the proof to run when the call's answer could
// still be the restart outage: an outage answer is ready, and the gateway
// sent no status or progress and the call logged no failure. w.mu is held.
func (w *answerWatchdog) restartWindowCandidateLocked() func() restartProofResult {
	if w.secureClient || w.restart == nil || w.restartProof == nil || w.answeredStatus || w.progressSeen ||
		w.failureClosed || w.claimedAnswer || w.failureLogged || w.fired {
		return nil
	}
	return w.restartProof
}

func (w *answerWatchdog) restartWindowSkipReasonLocked() string {
	switch {
	case w.restartProof == nil:
		return "no_verified_connection"
	case w.restart == nil:
		return "outage_mode_not_ready"
	case w.answeredStatus || w.progressSeen:
		return "answer_started"
	default:
		return "proof_not_applicable"
	}
}

// restartWindowProven runs the restart-window proof for the call's own
// answer path (Run) and returns the outage mode it then follows. Safe on a
// nil watchdog.
func (w *answerWatchdog) restartWindowProven() (mode, reason string, ok bool) {
	if w == nil {
		return "", "", false
	}
	w.mu.Lock()
	proof := w.restartWindowCandidateLocked()
	skipReason := w.restartWindowSkipReasonLocked()
	w.mu.Unlock()
	if proof == nil {
		w.failureLog.setRestartReason(skipReason)
		return "", "", false
	}
	result := provenWithin(proof, restartProofWait)
	if !result.ok {
		w.failureLog.setRestartReason(result.reason)
		return "", "", false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.restartWindowCandidateLocked() == nil {
		w.failureLog.setRestartReason(w.restartWindowSkipReasonLocked())
		return "", "", false
	}
	return w.restart.mode, w.restart.answer.reason, true
}

// provenWithin runs proof bounded by wait: a proof that takes longer is none.
func provenWithin(proof func() restartProofResult, wait time.Duration) restartProofResult {
	proven := make(chan restartProofResult, 1)
	go func() { proven <- proof() }()
	expired, stop := proofclock.NewTimer(wait)
	defer stop()
	select {
	case ok := <-proven:
		if !ok.ok && ok.reason == "" {
			ok.reason = "proof_rejected"
		}
		return ok
	case <-expired:
		return restartProofResult{reason: "proof_timeout"}
	}
}

// failPerUserRestartWindow answers a per-user call with no decision at its
// deadline whose connection a gateway that only just started holds: the
// restart outage in the mode read for the call (GAP-0295). ok is false for
// every other call, which keeps the closed no-answer answer.
func failPerUserRestartWindow(ctx context.Context, opts Options, sp spec, failMode string) (int, bool) {
	if opts.answeredErrorStatus != 0 || !perUserRestartWindowCall(opts, sp) ||
		(!gatewayNoAnswer(ctx) && !opts.answerWatch.hasPendingDecision()) {
		return 0, false
	}
	mode, reason, ok := opts.answerWatch.restartWindowProven()
	if !ok {
		return 0, false
	}
	outage := withPerUserOutage(opts)
	outage.OutageFailModeNow = func() string { return mode }
	return failUnreachable(outage, sp, failMode, reason), true
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
	opts.failureLog = w.failureLog
}

func (w *answerWatchdog) watch(deadline time.Time) {
	if w.watchDone != nil {
		defer w.watchDoneOnce.Do(func() { close(w.watchDone) })
	}
	// A call still waiting answerWatchdogLogPrepareLead before its deadline
	// opens its log now, so the line of the answer below is one append.
	// Give quick answers a short window to finish without opening a log,
	// while leaving enough time to prepare the marker before the deadline.
	remaining := max(time.Until(deadline), 0)
	lead := min(w.prepareLead, remaining)
	if remaining > 100*time.Millisecond {
		lead = min(w.prepareLead, remaining-100*time.Millisecond)
	}
	prepare := time.AfterFunc(time.Until(deadline.Add(-lead)), func() {
		w.failureLog.prepare(w.failureLogHome)
	})
	if !w.waiter.wait(deadline) {
		prepare.Stop()
		w.failureLog.close()
		return
	}
	w.mu.Lock()
	proof := w.restartWindowCandidateLocked()
	skipReason := w.restartWindowSkipReasonLocked()
	w.mu.Unlock()
	// Outside the lock: Run must still be able to finish meanwhile. A call
	// whose connection a gateway that only just started holds, with no
	// answer from it yet, is in that gateway's restart window: it gets the
	// outage answer, not the closed no-decision one (GAP-0295).
	if proof == nil {
		w.failureLog.setRestartReason(skipReason)
	} else if result := provenWithin(proof, restartProofWait); result.ok {
		w.mu.Lock()
		if w.restartWindowCandidateLocked() != nil {
			w.closedKnown = false
			w.useRestartAnswerLocked(w.restart)
		} else {
			w.failureLog.setRestartReason(w.restartWindowSkipReasonLocked())
		}
		w.mu.Unlock()
	} else {
		w.failureLog.setRestartReason(result.reason)
	}
	w.useOrdinaryAtDeadline()
	w.mu.Lock()
	installCheck := w.installCheck
	w.mu.Unlock()
	installing := installCheck != nil && installCheck()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished || w.answeredInTime.Load() {
		return
	}
	if installing && !w.closedKnown && !w.claimedAnswer && w.installCheck != nil {
		w.fallback = w.install
		if len(w.install.frame) != 0 {
			w.failureLog.replaceFallbackFrame(w.install.frame)
		}
	} else if !w.closedKnown && !w.claimedAnswer && !w.failureLogged && w.visibleOutage != nil {
		w.fallback.out, w.fallback.err, w.fallback.code = w.visibleOutage()
	}
	w.fired = true
	// Whatever of the prepared failure log (the ordinary log, the marker) the
	// record of this answer did not take is closed when the answer is done,
	// as Run closes it for a call that was answered in time. A descriptor
	// left open would stop the account folder of a simulated exit from being
	// removed on Windows.
	defer w.failureLog.close()
	_, _ = w.stderr.Write(w.fallback.err)
	_, _ = w.stdout.Write(w.fallback.out)
	// The token and local record describe this same committed answer. Send
	// them concurrently; neither may add a second exit wait to the hook.
	receiptDone := make(chan struct{})
	if delivery := w.deadlineDelivery; delivery != nil && !w.secureClient {
		blocked := w.fallback.blocked
		done := receiptDone
		// The transport remains open for the token after the answer timer
		// ends. Close it at the same bounded exit window if the process is
		// simulated rather than exited (as in tests).
		time.AfterFunc(answerWatchdogLogWait, delivery.close)
		go func() {
			_ = delivery.deadline(blocked)
			close(done)
		}()
	} else {
		close(receiptDone)
	}
	if w.exit == nil {
		if !w.failureLogged {
			w.fallback.logFailure()
		}
		return
	}
	localDone := (<-chan struct{})(w.failureLogDone)
	var markerDone <-chan bool
	markerTried, ordinaryStarted := false, false
	startOrdinary := func() {
		if ordinaryStarted || w.failureLogged {
			return
		}
		ordinaryStarted = true
		done := make(chan struct{})
		localDone = done
		logFailure := w.fallback.logFailure
		w.records.Add(1)
		go func() {
			defer w.records.Done()
			defer close(done)
			logFailure()
		}()
	}
	startMarker := func() {
		if markerTried || !w.failureLog.markerEnabled {
			return
		}
		markerTried = true
		if w.fallback.blocked {
			w.failureLog.promoteFallbackClosed()
		}
		result := make(chan bool, 1)
		markerDone = result
		w.records.Add(1)
		go func() {
			defer w.records.Done()
			result <- w.failureLog.appendFallback()
		}()
	}
	// Prefer a prepared ordinary descriptor. If its open is still pending,
	// the prepared fallback can record the committed answer immediately.
	if !w.failureLogged {
		if remaining > answerWatchdogLogWait && w.failureLog.markerEnabled && !w.failureLog.ordinaryReady() {
			startMarker()
		} else {
			startOrdinary()
		}
	}
	recorded := false
	deadlineExpired, stopDeadline := proofclock.NewTimer(answerWatchdogLogWait)
	defer stopDeadline()
	fallbackExpired, stopFallback := proofclock.NewTimer(answerWatchdogLogWait / 2)
	defer stopFallback()
	for !recorded || receiptDone != nil {
		select {
		case <-localDone:
			localDone = nil
			recorded = true
		case <-receiptDone:
			receiptDone = nil
		case saved := <-markerDone:
			markerDone = nil
			if saved {
				recorded = true
			} else {
				startOrdinary()
			}
		case <-fallbackExpired:
			if !recorded {
				if markerTried {
					startOrdinary()
				} else {
					startMarker()
				}
			}
		case <-deadlineExpired:
			if !recorded {
				fmt.Fprintln(os.Stderr, "defenseclaw: local failure record could not be appended before exit")
			}
			recorded, receiptDone = true, nil
		}
	}
	// Production exits here; the lock is never released, so the call's own
	// output cannot follow the answer.
	w.exit(w.fallback.code)
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
	answer := renderNoAnswer(closedOpts, sp, "closed")
	if status >= 200 && status < 300 {
		// The watchdog may fire while the body read is still waiting. Use
		// the same response-layer reason the ordinary body-read path uses.
		var stdout, stderr bytes.Buffer
		rendered := closedOpts
		rendered.Stdout, rendered.Stderr = &stdout, &stderr
		rendered.Home, rendered.FailureLogHome, rendered.answerWatch = "", nil, nil
		answer.code = failResponse(rendered, sp, "closed", "incomplete gateway response")
		answer.out, answer.err = stdout.Bytes(), stderr.Bytes()
		logged := closedOpts
		logged.answerWatch = nil
		logged.Stderr = io.Discard
		answer.logFailure = func() { logHookFailure(logged, sp, "incomplete gateway response", "response", "closed", true) }
		answer.reason, answer.category = "incomplete gateway response", "response"
		answer.frame = localFailureFallbackFrame(closedOpts, sp, answer.reason, answer.category, "closed", true)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.answeredStatus = true
	if w.fired || w.failureClosed || w.claimedAnswer || (w.closedKnown && (status < 200 || status >= 300)) {
		return
	}
	w.closedKnown = true
	w.fallback = answer
	w.visibleOutage = nil
	if w.failureLog.markerEnabled {
		w.failureLog.replaceFallbackFrame(answer.frame)
	}
}

// waitForLog waits for the watchdog's hook-failures row (done) for at most
// answerWatchdogLogWait. The bound runs on the proof clock like the other
// post-deadline bounds of a call, so a test decides whether it is spent
// instead of racing the host for a file append (GAP-0859); a release build
// runs the system clock.
func waitForLog(done <-chan struct{}) {
	expired, stop := proofclock.NewTimer(answerWatchdogLogWait)
	defer stop()
	select {
	case <-done:
	case <-expired:
	}
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
	expired, stop := proofclock.NewTimer(wait)
	defer stop()
	select {
	case h := <-held:
		return h
	case <-expired:
		return true
	}
}

// answered stands the watchdog down: the gateway's decision is in. Safe on
// a nil watchdog. A managed call's decision read before its deadline is the
// answer the agent gets, also when rendering it takes the call past the
// deadline (answeredInTime); one read after it is late (lateAnswerDue) and
// leaves the watchdog's answer.
func (w *answerWatchdog) answered() {
	if w == nil || w.lateAnswerDue() {
		return
	}
	if w.closeLateAnswer {
		// Before the cancel: watch, answerLate and finish read it.
		w.answeredInTime.Store(true)
	}
	w.waiter.cancel()
}

// noDecisionPending restores the closed answer when a retry has connected
// or the gateway reported progress but has made no decision. A prior
// refusal does not turn that pending decision into an outage. Secure Client
// keeps its established answer mode.
func (w *answerWatchdog) noDecisionPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.secureClient {
		return
	}
	w.decisionPending = true
	w.managedOutagePrimed = false
	if !w.fired && !w.claimedAnswer && !w.failureClosed {
		w.closedKnown = true
		w.fallback = w.noDecision
		w.visibleOutage = nil
		if len(w.noDecision.frame) != 0 {
			w.failureLog.replaceFallbackFrame(w.noDecision.frame)
		}
	}
}

// progressed moves the watchdog's deadline to the progress ceiling. Safe on
// a nil watchdog.
func (w *answerWatchdog) progressed() {
	if w != nil {
		w.mu.Lock()
		w.progressSeen = true
		w.mu.Unlock()
		w.noDecisionPending()
		w.waiter.extendTo(w.ceiling)
	}
}

func (w *answerWatchdog) hasPendingDecision() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.decisionPending
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
	if w.lateAnswerDue() && w.watchDone != nil && !w.answeredInTime.Load() {
		timer := time.NewTimer(lateAnswerWait)
		held := false
		select {
		case <-w.watchDone:
			// The watch answered (it fired), or it stood down for a
			// decision read in time: nothing to answer for.
		case <-timer.C:
			held = true
		}
		timer.Stop()
		if held {
			if late, ok := w.answerLate(); ok {
				w.waiter.cancel()
				return late
			}
		}
	}
	w.waiter.cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.fired {
		w.failureLog.close()
	}
	if w.fired {
		if w.deliveryReceipt != nil {
			w.deliveryReceipt(false, true)
		}
		return w.fallback.code
	}
	w.finished = true
	_, _ = w.stderr.Write(w.err.Bytes())
	_, _ = w.stdout.Write(w.out.Bytes())
	closed := w.failureClosed
	if code == 0 && w.revoke != nil {
		// The agent reads the answer when this hook exits, so a target that
		// changed while the answer was written is still refused.
		if revoked, ok := w.revoke(w.stdout, w.stderr); ok {
			code, closed = revoked, true
		}
	}
	if w.deliveryReceipt != nil {
		w.deliveryReceipt(true, closed)
	}
	return code
}

// answerLate gives the watchdog's answer for it when a managed call's
// deadline has passed and its watchdog did not answer within lateAnswerWait
// (its thread was held, or still waits on a timer the computer's sleep
// stopped): the late verdict or result is never written (GAP-0648 review
// F4). It is the answer watch would give: while the computer's lifecycle
// holds a call whose fallback is not closed, the install answer (GAP-1074,
// review 3 L2). ok is false when the watchdog answered, the call's decision
// came in time (answeredInTime) or the call is not late.
func (w *answerWatchdog) answerLate() (code int, ok bool) {
	w.mu.Lock()
	if !w.lateAnswerOwedLocked() {
		w.mu.Unlock()
		return 0, false
	}
	installCheck := w.installCheck
	w.mu.Unlock()
	// Outside the lock, as in watch; the look is bounded (heldWithin).
	installing := installCheck != nil && installCheck()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.lateAnswerOwedLocked() {
		return 0, false
	}
	if installing && !w.closedKnown && !w.claimedAnswer && w.installCheck != nil {
		w.fallback = w.install
		if len(w.install.frame) != 0 {
			w.failureLog.replaceFallbackFrame(w.install.frame)
		}
	}
	// The watchdog's answer: watch finds the call finished and stays quiet.
	w.fired, w.finished = true, true
	// Whatever of the prepared failure log the record of this answer does not
	// take is closed with it, as watch does for the answer it gives: watch
	// finds the call finished and returns before its own close, and an open
	// still in flight closes the file it opens (GAP-1022).
	defer w.failureLog.close()
	_, _ = w.stderr.Write(w.fallback.err)
	_, _ = w.stdout.Write(w.fallback.out)
	logged := w.failureLogDone
	if !w.failureLogged {
		done := make(chan struct{})
		logFailure := w.fallback.logFailure
		go func() {
			defer close(done)
			logFailure()
		}()
		logged = done
	}
	if logged != nil {
		waitForLog(logged)
	}
	if w.deliveryReceipt != nil {
		w.deliveryReceipt(false, true)
	}
	return w.fallback.code, true
}

// lateAnswerOwedLocked reports a late managed call nobody answered yet.
// w.mu is held.
func (w *answerWatchdog) lateAnswerOwedLocked() bool {
	return !w.fired && !w.finished && !w.answeredInTime.Load() && w.lateAnswerDue()
}

// setRevoke registers the check finish runs after it writes an allow.
func (w *answerWatchdog) setRevoke(revoke func(stdout, stderr io.Writer) (int, bool)) {
	w.mu.Lock()
	w.revoke = revoke
	w.mu.Unlock()
}

func (w *answerWatchdog) setDeliveryReceipt(receipt func(bool, bool)) {
	w.mu.Lock()
	w.deliveryReceipt = receipt
	w.mu.Unlock()
}

func (w *answerWatchdog) setDeadlineDelivery(delivery *hookDeliveryRequest) {
	w.mu.Lock()
	if !w.fired {
		w.deadlineDelivery = delivery
	}
	w.mu.Unlock()
}
