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
// not answer in time, and once the call logged a closed failure (an
// unverified gateway peer, an invalid runtime) it is that call's closed
// answer in every fail mode (claimFailureLog). While this account's
// installer holds its data directory (.install.lock) the answer is closed
// too: a per-user hook in fail mode open checks the lock when the watchdog
// is armed and again at the deadline, before it answers (GAP-0862).
type answerWatchdog struct {
	mu             sync.Mutex
	finished       bool
	fired          bool
	failureLogged  bool
	failureLogDone chan struct{}
	// closedKnown is set once the call logged a failure that is closed:
	// the watchdog's answer is then closed too.
	closedKnown bool
	// logHome is the background lookup of the invoking user's diagnostic
	// directory of a managed call (cacheFailureLogHome).
	logHome *failureLogHomeLookup

	stdout, stderr io.Writer
	out, err       bytes.Buffer

	fallbackOut, fallbackErr []byte
	fallbackCode             int
	logFailure               func()
	exit                     func(int)

	// installHome is the data directory of a per-user call whose fallback
	// is not closed; at the deadline the watchdog gives the install answer
	// below instead when that directory's .install.lock is held or cannot
	// be read (GAP-0862). Empty when the fallback is closed already.
	installHome            string
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
	w.cacheFailureLogHome(opts)
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = renderNoAnswer(*opts, sp, failMode)
	w.installHome, w.installOut, w.installErr, w.installCode, w.installLogFailure = renderInstallAnswer(*opts, sp, failMode)
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
	rendered.FailureLogHome = nil
	rendered.answerWatch = nil
	code = failNoAnswer(rendered, sp, failMode)
	logged := opts
	logged.answerWatch = nil
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

// renderInstallAnswer renders the closed answer a per-user call whose
// fallback is not closed gets when, at the deadline, its installer holds the
// data directory: the answer Run gives it then (runHook closes the call and
// sets strict availability). It returns an empty home, and nothing to give,
// when the fallback is closed already or the call is not a per-user one.
func renderInstallAnswer(opts Options, sp spec, failMode string) (home string, stdout, stderr []byte, code int, logFailure func()) {
	if opts.ManagedEnterprise || opts.SecureClient || opts.Home == "" ||
		opts.answerSpentLocally || normalizeFailMode(failMode) == "closed" {
		return "", nil, nil, 0, nil
	}
	closed := opts
	closed.FailMode = "closed"
	closed.StrictAvailability = true
	stdout, stderr, code, logFailure = renderNoAnswer(closed, sp, "closed")
	return opts.Home, stdout, stderr, code, logFailure
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
	installHome, installOut, installErr, installCode, installLogFailure := renderInstallAnswer(*opts, sp, failMode)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired || (w.closedKnown && !closed) {
		return
	}
	w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = stdout, stderr, code, logFailure
	w.installHome, w.installOut, w.installErr, w.installCode, w.installLogFailure =
		installHome, installOut, installErr, installCode, installLogFailure
}

// claimFailureLog runs first in logHookFailure, before anything there can
// block (the account lookup of a managed row, a stalled disk). A failure
// that is closed makes the watchdog's answer closed: an administrator's
// fail mode open covers an outage only, and a known refusal (an unverified
// gateway peer, an invalid runtime, a missing token) that waited on its log
// line past the deadline got the watchdog's fail-open answer instead. It
// returns the channel to close once the row is written, and false when the
// watchdog already answered or the call's row is already claimed.
func (w *answerWatchdog) claimFailureLog(opts Options, sp spec, closed bool) (chan struct{}, bool) {
	var out, errb []byte
	var code int
	var logFailure func()
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
		w.fallbackOut, w.fallbackErr, w.fallbackCode, w.logFailure = out, errb, code, logFailure
	}
	if w.failureLogged {
		return nil, false
	}
	w.failureLogged = true
	w.failureLogDone = make(chan struct{})
	return w.failureLogDone, true
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
	installHome := w.installHome
	w.mu.Unlock()
	// Outside the lock: Run must still be able to finish meanwhile.
	installing := installHome != "" && installLockHeldWithin(installHome, installLockCheckWait)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return
	}
	if installing && !w.closedKnown && w.installHome != "" {
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

// installLockHeldWithin is installLockHeld bounded by wait: a look that
// takes longer counts as a held lock.
func installLockHeldWithin(home string, wait time.Duration) bool {
	held := make(chan bool, 1)
	// The read is taken now: a look still held on a stalled disk after the
	// answer touches nothing of the call's.
	lstat := installLockLstat
	go func() { held <- installLockHeldBy(lstat, home) }()
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
		return w.fallbackCode
	}
	w.finished = true
	_, _ = w.stderr.Write(w.err.Bytes())
	_, _ = w.stdout.Write(w.out.Bytes())
	return code
}
