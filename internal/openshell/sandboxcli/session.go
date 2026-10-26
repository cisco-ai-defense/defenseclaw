// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// killedByInterrupt reports an error of a command a Ctrl-C ended: the
// terminal sends SIGINT to its whole foreground group, the git that a pull
// runs included.
func killedByInterrupt(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return errors.Is(err, errInterrupted) || errors.Is(err, openshell.ErrInterrupted)
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGINT
}

// RunDir is where detached runs keep their output inside the sandbox.
const RunDir = harness.RunDir

// session is one harness session in a sandbox.
type session struct {
	app  *App
	api  API
	cli  openshell.CLI
	spec *harness.Spec
	sb   *sandboxapi.Sandbox
	rm   bool
	yes  bool
	// cliErr holds the OpenShell CLI's own standard error of the session's
	// interactive harness or shell (holdCLIErr).
	cliErr *heldOutput
	// autoRm marks an rm the run did not ask for: a headless run's sandbox,
	// which goes by the rules of --rm unless --keep or
	// openshell.keep_headless keeps it (App.headlessRm). The end of the
	// session says why it went, or why it stayed, without naming --rm.
	autoRm bool
	// keptWhy says why a sandbox the end of its session was to delete
	// (autoRm) is kept instead.
	keptWhy string
	// started is set when the session created or started the sandbox; one
	// that was already running (a detached run, another session) is left
	// running when the session ends.
	started bool
	// liveRun is set at the end of a session in a sandbox whose detached
	// run is still going: nothing may stop the sandbox under it.
	liveRun bool
	// others counts, at the end of the session, the other sessions whose
	// harness or shell still runs in the sandbox (attachedSessions):
	// nothing may stop the sandbox, or undo the folder, under them.
	others int
	// lost is set when the session's connection to the sandbox broke (the
	// OpenShell gateway restarted under it, for one) while the sandbox
	// went on running: it is left running for a reattach.
	lost bool
	// unanswered is set when the sandbox ran no command at the end of a
	// session whose harness failed, though OpenShell still read it ready
	// after settlePhaseWait (settledPhase): its runtime may have stopped,
	// so nothing may say it keeps running (GAP-0333).
	unanswered bool
	// placeholder is set when OpenShell refused a request of the session's
	// conversation that carried a credential placeholder
	// (sandboxapi.PlaceholderRefusal): the conversation cannot go on, so the
	// end offers a new one instead of --continue (GAP-0354).
	placeholder bool
	// diskFull is set when a copy's pull at the end of the session failed
	// on the sandbox's own full disk (App.ownDiskFull): a MicroVM stopped
	// like that cannot start again, so it is left running for a pull once
	// some space is freed (GAP-0339).
	diskFull bool
	// headless marks a one-prompt session (the resume hint says how to
	// run the next prompt).
	headless bool
	// keepSnapshot keeps the undo snapshot when --rm deletes the sandbox:
	// the session's changes could not be reviewed, or nobody accepted them.
	// keepWhy says which.
	keepSnapshot bool
	keepWhy      string

	// before is the sandbox as it was when the session started, for the
	// end-of-session deltas.
	before *sandboxapi.Sandbox
	// daemonStarted is when the daemon the session ends with started
	// (sandboxapi.Status.StartedAt; zero when it does not say): after the
	// session's start, the daemon restarted during it.
	daemonStarted time.Time

	// shell marks a `connect --shell` session: no harness, so no hooks to
	// expect.
	shell bool
	// passArgs is set when the command was given arguments for the harness
	// (after --), which it may answer without a session (--version).
	passArgs bool
	// continueAfterDetached marks a Claude Code --continue after a completed
	// detached run, whose conversation may not have been saved.
	continueAfterDetached bool
	// startedAt is when the harness (or shell) was attached; harnessCode
	// its exit status.
	startedAt   time.Time
	harnessCode int
	// harnessOutput is the end of what a headless harness printed; startWhy
	// and startDo say why a harness that failed at start did, and what to
	// do (diagnoseStart), when that is known.
	harnessOutput     string
	startWhy, startDo string
	// interrupted is set when the user pressed Ctrl-C at the end of the
	// session's keep/undo question; undoStopped when that session's undo
	// stopped a sandbox it had found running.
	interrupted bool
	undoStopped bool
	// notAccepted is set when the daemon did not record that the user kept
	// the session's changes (acceptChanges): another terminal may have
	// started the sandbox again meanwhile.
	notAccepted bool
	// unmasked are the files that look like secrets the session left in
	// the project and the sandbox does not mask: its next start refuses
	// while they stay there (the review's UnmaskedSecrets).
	unmasked []string
	// pulled is the result of the pull a copy-mode session's end took, and
	// handedOver is set once nothing of it is left to bring back: finish
	// records both for a sandbox it stops (markStoppedCopy), when nothing
	// could have changed the copy since pullBase was read.
	pulled     string
	handedOver bool
	pullBase   copyBase

	// hooksWarned is set once the live warning that the session's hooks do
	// not reach DefenseClaw went out (hooks.go); noHooks once the session
	// ended without one of them getting through. sawHooks is set when the
	// session saw one of its hooks reach DefenseClaw (a verdict on the feed,
	// a read of its counters), which a daemon restart cannot take back.
	hooksMu     sync.Mutex
	hooksWarned bool
	noHooks     bool
	// stopFailed marks a session whose sandbox the end of the session could
	// not stop; its exit status is not success.
	stopFailed bool
	// errorPhaseReason is OpenShell's reason when the sandbox entered its
	// error state during the session, for the recovery step in finish.
	errorPhaseReason string
	sawHooks         atomic.Bool
	// hooksUnknown is set once the summary said a daemon restart during
	// the session left it unable to tell whether a hook reached DefenseClaw
	// (hookReachUnknown).
	hooksUnknown bool
	// hadTurn is set by the summary when the session made a tool call:
	// the harness had a turn, so the resume line it prints as it exits is
	// on the screen (Copilot CLI prints none without a prompt).
	hadTurn bool

	// notices are what the session announced while the harness owned the
	// terminal (hooks.go), repeated in the summary.
	noticeMu   sync.Mutex
	notices    []sessionNotice
	noticeKeys map[string]bool
	titleSet   bool
	// blockedHosts are the destinations the session announced blocked
	// (blockNotice), which the summary counts; unblockedHosts those of them
	// unblocked since, whose summary line offers no unblock.
	blockedHosts   map[string]bool
	unblockedHosts map[string]bool
	// refused are the host:port destinations of OpenShell's own refusals
	// the session announced, with their host; otherBlocks the hosts blocked
	// another way too; approved the destinations an approval opened since
	// (GAP-0196): no longer blocked, and not counted as such.
	refused     map[string]string
	otherBlocks map[string]bool
	approved    map[string]bool
	// gatewayDown is set when the daemon, at the end of the session, could
	// not reach the OpenShell gateway; errored when the sandbox ended in
	// OpenShell's error phase.
	gatewayDown, errored bool
	// driver and otherGateways are the runtime facts reported at session
	// end. Another gateway of this account can take over its MicroVM state.
	driver        string
	otherGateways []string
	// policyStop is the notice for a sandbox the organization stopped under
	// the session on a managed computer (managedStopText), "" otherwise.
	policyStop string
}

// probe runs a trivial command in workdir until the sandbox answers; ""
// is the sandbox's default directory. The harness's workdir exists only
// once a copy-mode project is uploaded, so a probe there comes after the
// upload.
func (s *session) probe(ctx context.Context, workdir string) error {
	inv, err := s.cli.Exec(s.sb.Name, []string{"true"}, openshell.CLIExecOptions{WorkDir: workdir, Timeout: probeTimeout})
	if err != nil {
		return err
	}
	var last error
	for i := 0; i < probeAttempts; i++ {
		var out bytes.Buffer
		code, err := s.app.Streamer.Stream(ctx, inv, &out, &out)
		if err == nil && code == 0 {
			return nil
		}
		last = err
		if err == nil {
			last = fmt.Errorf("exit status %d: %s", code, truncate(out.String(), 200))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.app.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("sandbox %s does not answer: %w", s.sb.Name, last)
}

// attach runs the harness in the foreground: with the terminal, or
// headless with its output streamed.
func (s *session) attach(ctx context.Context, opts harness.LaunchOptions, headless bool) (int, error) {
	argv, err := s.spec.LaunchArgv(opts)
	if err != nil {
		return -1, err
	}
	// While the harness runs, other sessions' ends leave the sandbox alone,
	// and what its copy held as it last stopped is no longer known.
	release, err := s.app.holdSession(ctx, s.sb.Name, s.stillRunning)
	if err != nil {
		return -1, err
	}
	defer release()
	s.app.forgetStoppedCopy(s.sb.Name)
	stop := s.beginSession(ctx)
	defer stop()
	if headless || !s.app.IO.TTY {
		inv, err := s.cli.Exec(s.sb.Name, argv, openshell.CLIExecOptions{WorkDir: s.sb.Workdir})
		if err != nil {
			return -1, err
		}
		runCtx, interrupted, stopSignals := sessionContext(ctx)
		defer stopSignals()
		// What the agent answers cannot drive the user's terminal.
		out, flushOut := sandboxOutput(s.app.IO.Out, s.app.IO.OutTTY)
		errOut, flushErr := sandboxOutput(s.app.IO.Err, s.app.IO.ErrTTY)
		tail := &outputTail{}
		code, err := s.app.Streamer.Stream(runCtx, inv, io.MultiWriter(out, tail), io.MultiWriter(errOut, tail))
		_, _ = flushOut(), flushErr()
		s.harnessOutput = tail.String()
		if interrupted() && ctx.Err() == nil {
			// The harness was ended; the session ends as usual.
			s.app.warnErr("interrupted: ending the session")
			s.harnessCode = exitInterrupted
			return exitInterrupted, nil
		}
		s.harnessCode = code
		return code, err
	}
	inv, err := s.cli.Exec(s.sb.Name, argv, openshell.CLIExecOptions{TTY: true, WorkDir: s.sb.Workdir})
	if err != nil {
		return -1, err
	}
	code, err := s.app.Terminal.Run(ctx, s.holdCLIErr(inv))
	if err != nil {
		s.printCLIErr(false)
	}
	s.harnessCode = code
	return code, err
}

// maxHeldCLIErr bounds what holdCLIErr keeps of the OpenShell CLI's own
// standard error during a session.
const maxHeldCLIErr = 64 << 10

// heldOutput keeps what is written to it, up to maxHeldCLIErr bytes.
type heldOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (h *heldOutput) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if room := maxHeldCLIErr - h.b.Len(); room > 0 {
		h.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (h *heldOutput) take() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.b.String()
	h.b.Reset()
	return out
}

// holdCLIErr has the OpenShell CLI's own standard error of an interactive
// session held until the session ends (printCLIErr): written into the
// harness's screen it corrupts it, and its relay error when the gateway
// restarted ("Error: × code: The service is currently unavailable,
// message: exec relay closed before the command reported an exit status")
// came before DefenseClaw's account of what ended the session (GAP-0279).
func (s *session) holdCLIErr(inv openshell.Invocation) openshell.Invocation {
	s.cliErr = &heldOutput{}
	inv.Stderr = s.cliErr
	return inv
}

// printCLIErr prints what the OpenShell CLI wrote on its own standard
// error during the session, after DefenseClaw's lines. Its relay error is
// left out when explained: DefenseClaw said what ended the session.
func (s *session) printCLIErr(explained bool) {
	if s.cliErr == nil {
		return
	}
	text := strings.TrimRight(s.cliErr.take(), "\r\n")
	if text == "" || explained && relayClosed(text) {
		return
	}
	fmt.Fprintln(s.app.IO.Err, terminalText(text))
}

// relayClosed reports whether the OpenShell CLI's error is its exec relay
// that closed under the session (the gateway restarted or went away).
func relayClosed(text string) bool {
	return strings.Contains(text, "exec relay closed") || strings.Contains(text, "The service is currently unavailable") ||
		(strings.Contains(text, "h2 protocol error") && strings.Contains(text, "hyper::Error"))
}

// loginShell starts the sandbox user's login shell (bash where the image
// has it) in the exec's working directory, with the environment the
// profile gives the connect shell (the egress proxy, the harness shim).
var loginShell = []string{"sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash -l; fi; exec sh -l"}

// attachShell runs a login shell in the project folder with the terminal
// (`connect --shell`).
func (s *session) attachShell(ctx context.Context) (int, error) {
	// While the shell runs, other sessions' ends leave the sandbox alone,
	// and what its copy held as it last stopped is no longer known.
	release, err := s.app.holdSession(ctx, s.sb.Name, s.stillRunning)
	if err != nil {
		return -1, err
	}
	defer release()
	s.app.forgetStoppedCopy(s.sb.Name)
	stop := s.beginSession(ctx)
	defer stop()
	inv, err := s.cli.Exec(s.sb.Name, loginShell, openshell.CLIExecOptions{TTY: true, WorkDir: s.sb.Workdir})
	inv = s.holdCLIErr(inv)
	if err != nil {
		return -1, err
	}
	return s.app.Terminal.Run(ctx, inv)
}

// stillRunning is the check an attach makes under the sandbox's gate once
// its lease is recorded (holdSession): from then on no stop or delete
// DefenseClaw decides ends the sandbox under the session, but one decided
// before it (another terminal's session end that counted no session, a
// `sandbox stop`) may have ended it since the session read it ready. Only
// a sandbox OpenShell reports ready now takes the session.
func (s *session) stillRunning(ctx context.Context) error {
	name := s.sb.Name
	now, err := s.api.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("cannot confirm that %s still runs: %w; run `%s status %s`, then retry the connect", name, apiError(err), CommandName, name)
	}
	if now.Phase != "ready" {
		return fmt.Errorf("%s is %s now: it was stopped while this session attached (another terminal's session ended, or a stop ran) → start it again: %s connect %s",
			name, firstNonEmpty(now.Phase, "not ready"), CommandName, name)
	}
	return nil
}

// beginSession reads the sandbox as the session starts (for the
// end-of-session deltas) and follows it until the returned stop.
func (s *session) beginSession(ctx context.Context) func() {
	if before, err := s.api.Get(ctx, s.sb.Name); err == nil {
		s.before = before
	} else {
		s.before = s.sb
	}
	s.startedAt = s.app.Now()
	return s.watchNotices(ctx)
}

// promptFirst are the harnesses whose first hook comes only with the
// user's first prompt, which may be long after they start: an idle one
// is not overdue. (The Codex TUI too, but its OTLP export from the start
// proves the path; see telemetryReached.)
var promptFirst = map[string]bool{
	"kiro": true, "hermes": true, "antigravity": true, "copilot": true,
}

// watchNotices follows the sandbox during the session and announces what
// must not wait until the end: an ask waiting for the user, a blocked
// destination, a large upload, a finding (an alert, hook tamper), a
// quarantined nested repository, a DefenseClaw daemon that does not
// answer, and hooks that do not reach DefenseClaw (the daemon's verdict,
// or no hook by the end of the hook window).
func (s *session) watchNotices(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	var since uint64
	_ = s.api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: s.sb.Name}, func(ev sandboxapi.ActivityEvent) error {
		since = max(since, ev.Seq)
		return nil
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.followActivity(ctx, since)
	}()
	if !s.shell && !promptFirst[s.spec.Name] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.checkHooksAfter(ctx, s.app.hookWindow())
		}()
	}
	if s.sb.WorkdirMode == config.OpenShellWorkdirCopy && createdDriver(*s.sb) == string(openshell.DriverVM) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.watchOverlayDisk(ctx)
		}()
	}
	return func() {
		cancel()
		wg.Wait()
		s.restoreTitle()
	}
}

// reconnectDelay paces the activity stream's reconnects (a real timer: an
// App's Sleep may be instant).
var reconnectDelay = 2 * time.Second

// followActivity follows the session's activity until ctx ends. When the
// stream ends early the daemon went away (stopped, restarted, crashed):
// the session says so while it cannot reach it, and follows again once it
// answers. A restarted daemon numbers its events from the start, so a
// reconnect reads them all and skips the ones seen or from before the
// session.
func (s *session) followActivity(ctx context.Context, since uint64) {
	var down time.Time
	for {
		if down.IsZero() {
			_ = s.api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: s.sb.Name, Since: since, Follow: true}, func(ev sandboxapi.ActivityEvent) error {
				s.onActivity(ctx, ev)
				return nil
			})
			if ctx.Err() != nil {
				return
			}
			since = 0
			if _, err := s.api.Status(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				down = s.app.Now()
				s.daemonDown()
			}
		} else if _, err := s.api.Status(ctx); err == nil {
			// Back: follow again at once.
			s.daemonBack(down)
			down = time.Time{}
			continue
		} else if ctx.Err() != nil {
			return
		}
		t := time.NewTimer(reconnectDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// onActivity handles one event of the session's feed.
func (s *session) onActivity(ctx context.Context, ev sandboxapi.ActivityEvent) {
	if !ev.Time.IsZero() && !s.startedAt.IsZero() && ev.Time.Before(s.startedAt.Add(-time.Minute)) {
		// From before the session (a reconnect reads the daemon's
		// buffer from the start).
		return
	}
	if !s.firstSight(ev) {
		return
	}
	switch ev.Kind {
	case sandboxapi.ActivityApprovalRequested:
		s.askNotice(ctx, ev)
	case sandboxapi.ActivityEgressBlocked:
		s.blockNotice(ev)
	case sandboxapi.ActivityEgressUnblocked:
		s.onUnblock(ev.Host)
	case sandboxapi.ActivityApprovalResolved:
		if sandboxapi.ApprovalApplied(ev) {
			s.onApproved(ev)
		}
	case sandboxapi.ActivityEgressLargeUpload:
		s.largeUploadNotice(ev)
	case sandboxapi.ActivityToolBlocked, sandboxapi.ActivityToolAsked, sandboxapi.ActivityHookBlocked, sandboxapi.ActivityHookFailed:
		// A hook of the session reached DefenseClaw.
		s.sawHooks.Store(true)
	case sandboxapi.ActivityFinding:
		switch ev.Reason {
		case sandboxapi.ReasonNestedRepo:
			// The summary lists the quarantined repositories itself.
			s.notice("", strings.TrimPrefix(ev.Message, "⚠ "), "")
		case sandboxapi.ReasonHooksUnreachable:
			s.warnHooksOnce(ev.Message)
		case sandboxapi.ReasonHooksRestored:
			s.sawHooks.Store(true)
		default:
			if ev.Reason == reasonHookTamper {
				// Its post-tool hook reached DefenseClaw.
				s.sawHooks.Store(true)
			}
			s.findingNotice(ev)
		}
	}
}

// askDestination is where an ask would open: its host and port.
func askDestination(ev sandboxapi.ActivityEvent) string {
	if ev.Host == "" {
		return ""
	}
	if ev.Port != 0 {
		// An ask is for one host and port, 443 included; an IPv6 literal
		// is bracketed, or its port reads as part of the address.
		return net.JoinHostPort(strings.Trim(ev.Host, "[]"), strconv.Itoa(ev.Port))
	}
	return ev.Host
}

// portBlock reports a block of one port rather than of the host, named
// with its port (443 too): a port the egress proxy or triage does not
// carry, a port on this machine the sandbox may not reach
// (host.openshell.internal, whose hook ingress and approved ports stay
// open), and OpenShell's own direct denials (no category), which its rules
// make per host and port. DefenseClaw's triage rejections of OpenShell's
// proposals carry the proxy's host-wide category (blocklisted, ip_literal).
func portBlock(ev sandboxapi.ActivityEvent) bool {
	return ev.Category == string(egress.CategoryPortNotAllowed) || ev.Reason == sandboxapi.ReasonHostPortClosed ||
		ev.Source == sandboxapi.SourceOpenShell && ev.Category == ""
}

// askText is an ask of sandbox name for the live notice: the destination
// (and the binary asking, when known), why it is an ask, and where it is
// answered (the harness owns this terminal).
func askText(name string, ev sandboxapi.ActivityEvent, binary string, tui bool) string {
	what := firstNonEmpty(askDestination(ev), "a new destination")
	if binary != "" {
		what += " (" + path.Base(binary) + ")"
	}
	id := ""
	if ev.ApprovalID != "" {
		id = " " + ev.ApprovalID
	}
	msg := "? ask" + id + ": " + what + " is waiting for you"
	if why := strings.TrimSpace(ev.Message); why != "" && why != ev.Host {
		msg += " (" + truncate(why, 120) + ")"
	}
	msg += " → in another terminal: " + CommandName + " approve " + name + id + " (or reject)"
	if tui {
		msg += ", or in `defenseclaw tui`: 7 Sandboxes, then t for Asks"
	}
	return msg
}

// askNotice announces an ask, with the binary the daemon's list names.
func (s *session) askNotice(ctx context.Context, ev sandboxapi.ActivityEvent) {
	binary := ""
	if ev.ApprovalID != "" {
		if list, err := s.api.Approvals(ctx, s.sb.Name); err == nil {
			for _, ap := range list {
				if ap.ID == ev.ApprovalID {
					binary = ap.Binary
				}
			}
		}
	}
	what := firstNonEmpty(askDestination(ev), "a new destination")
	if binary != "" {
		what += " (" + path.Base(binary) + ")"
	}
	s.notice("ask "+ev.ApprovalID, askText(s.sb.Name, ev, binary, s.app.tuiOffered()), "? asked to reach "+what)
}

// blockNotice announces a destination DefenseClaw blocked, once per host,
// with the command that lifts the block when one does. What the harness
// fetches on its own and does without (a startup tip) is not announced.
//
// A block of the egress proxy holds the host on every port, so the notice
// names the host alone: the port of whichever request came first
// ("webhook.site:80") would say the block stops there, though HTTPS is
// blocked too. The feed keeps the port, which tells its request lines
// apart. Where the port is what is blocked (portBlock), it shows, once per
// port.
func (s *session) blockNotice(ev sandboxapi.ActivityEvent) {
	// A refusal of a request that carried a credential placeholder blocks no
	// site: its finding says what it is (GAP-0354).
	if ev.Host == "" || ev.Reason == harnessFetchReason || sandboxapi.PlaceholderRefusal(ev.Reason) {
		return
	}
	where, key := ev.Host, "block "+ev.Host
	if portBlock(ev) {
		where = askDestination(ev)
		key = "block " + where
	}
	text := "✗ DefenseClaw blocked " + where
	// OpenShell refuses a connection no rule allows yet; under network.mode
	// deny no rule ever will, so the refusal is the policy's, and an approval
	// that was applied since opens nothing (GAP-0635).
	direct := ev.Source == sandboxapi.SourceOpenShell && ev.Category == ""
	networkOff := s.networkOff()
	switch why := firstNonEmpty(ev.Category, ev.Reason); {
	case direct && networkOff:
		text += ": " + s.networkOffText()
	case sshPort(ev):
		text += " (" + sandboxapi.SSHBlockedText(ev.Host) + ")"
	case ev.Category == sandboxapi.CategoryLargeUpload:
		// The large-upload block (egress.block_large_uploads) cut an
		// upload there (its event counts what went up), or refused a
		// request after the cut, which its reason explains.
		if ev.BytesUp > 0 {
			text = "✗ DefenseClaw blocked a large upload to " + where
		}
		if clause := sandboxapi.LargeUploadReason(ev.Reason); clause != "" {
			text += " (" + clause + ")"
		}
	case hostPortClosedWhy(ev) != "":
		text += ": " + hostPortClosedWhy(ev)
	case why != "":
		text += " (" + sandboxapi.BlockedText(why, ev.Host) + ")"
	}
	host := strings.ToLower(ev.Host)
	n := sessionNotice{summary: text}
	if ev.Unblockable && !sshPort(ev) {
		// Once the host is unblocked the summary gives the block without
		// the command (onUnblock).
		n.host, n.unblocked = host, text+"; unblocked since"
		text += " → unblock: " + CommandName + " unblock " + ev.Host + " --sandbox " + s.sb.Name
		n.summary = text
	}
	// An approval (triage's own, under the open profile) opens a connection
	// OpenShell refused before a rule allowed it: its line then says so
	// instead of a block (onApproved).
	if direct {
		n.dest = strings.ToLower(where)
		if !networkOff {
			n.approved = "⚠ " + where + ": a connection was refused before a rule allowed it; approved since"
		}
	}
	s.noticeMu.Lock()
	if s.blockedHosts == nil {
		s.blockedHosts, s.refused, s.otherBlocks = map[string]bool{}, map[string]string{}, map[string]bool{}
	}
	if len(s.blockedHosts) < maxSeenEvents {
		s.blockedHosts[host] = true
		if direct {
			s.refused[n.dest] = host
		} else {
			s.otherBlocks[host] = true
		}
	}
	// Blocked again after an unblock or approval: the block applies again.
	delete(s.unblockedHosts, host)
	delete(s.approved, n.dest)
	s.noticeMu.Unlock()
	s.noticeWith(key, text, n)
}

// networkOff reports a sandbox whose policy denies all network access
// (network.mode deny): no approval opens a destination there.
func (s *session) networkOff() bool {
	return s.sb != nil && s.sb.NetworkMode == string(packs.NetworkDeny)
}

// networkOffText says why every destination is refused under network.mode
// deny, and where the policy came from when the project's own policy tightened
// the run to it.
func (s *session) networkOffText() string {
	text := "the network is off for this sandbox (network.mode deny"
	if s.sb.RepoPolicy != nil && slices.Contains(s.sb.RepoPolicy.Tightened, "network.mode") {
		text += ", set by the project's " + path.Base(s.sb.RepoPolicy.Path)
	}
	return text + ")"
}

// onApproved records that an approval opened a destination during the
// session.
func (s *session) onApproved(ev sandboxapi.ActivityEvent) {
	dest := strings.ToLower(askDestination(ev))
	if dest == "" || s.networkOff() {
		return
	}
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	if s.approved == nil {
		s.approved = map[string]bool{}
	}
	if len(s.approved) < maxSeenEvents {
		s.approved[dest] = true
	}
}

// liftedBlocks counts the hosts the session announced blocked only by
// OpenShell refusals of destinations an approval opened since. Under
// noticeMu.
func (s *session) liftedBlocks() int {
	open := map[string]bool{}
	for dest, host := range s.refused {
		if _, seen := open[host]; !seen || !s.approved[dest] {
			open[host] = s.approved[dest] && !s.otherBlocks[host]
		}
	}
	n := 0
	for _, lifted := range open {
		if lifted {
			n++
		}
	}
	return n
}

// largeUploadNotice announces a large upload only the report saw (the
// large-upload block was off, or the destination is exempt from it), once
// per host, as the feed words it but for the port, which is the first
// request's: "⚠ large upload to files.example.net (more than 25 MiB)".
func (s *session) largeUploadNotice(ev sandboxapi.ActivityEvent) {
	if ev.Host == "" {
		return
	}
	text := "⚠ " + largeUploadText(ev.Host, ev)
	s.notice("large upload "+strings.ToLower(ev.Host), text, text)
}

// onUnblock records that host was unblocked for this sandbox (or for every
// sandbox) during the session.
func (s *session) onUnblock(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	if s.unblockedHosts == nil {
		s.unblockedHosts = map[string]bool{}
	}
	if len(s.unblockedHosts) < maxSeenEvents {
		s.unblockedHosts[host] = true
	}
}

// harnessFetchReason is triage's reason for a denied request the harness
// makes around the egress proxy and does without; reasonHookTamper the
// daemon's for a tool call that ran without a verdict
// (audit.SandboxFindingHookTamper).
const (
	harnessFetchReason = "harness_background_fetch"
	reasonHookTamper   = "hook_tamper"
)

// findingNotice announces a finding of the session: an alert on a tool
// call, hook tamper, silent hooks, an OpenShell security finding.
func (s *session) findingNotice(ev sandboxapi.ActivityEvent) {
	if strings.EqualFold(ev.Severity, "info") {
		return
	}
	msg := strings.TrimSpace(strings.TrimPrefix(firstNonEmpty(ev.Message, ev.Reason), "⚠ "))
	if msg == "" {
		return
	}
	if ev.Host != "" && !strings.Contains(msg, ev.Host) {
		msg = ev.Host + ": " + msg
	}
	s.notice("finding "+msg, "⚠ "+msg, "⚠ "+msg)
}

// daemonDown announces that the DefenseClaw daemon does not answer: the
// sandbox's hooks fail closed meanwhile.
func (s *session) daemonDown() {
	s.notice("", "⚠ the DefenseClaw daemon is not reachable, so the hooks fail closed: "+s.harnessName()+
		" can't use its tools until it is back (start it with `defenseclaw-gateway start`)", "")
}

// daemonBack announces the daemon's return and keeps the outage for the
// summary.
func (s *session) daemonBack(since time.Time) {
	s.notice("", "✓ the DefenseClaw daemon is reachable again", "")
	s.noticeMu.Lock()
	s.notices = append(s.notices, sessionNotice{summary: "⚠ the DefenseClaw daemon was not reachable from " + since.Local().Format("15:04:05") +
		" to " + s.app.Now().Local().Format("15:04:05") + "; the hooks failed closed meanwhile"})
	s.noticeMu.Unlock()
}

func (s *session) harnessName() string {
	if s.shell || s.spec == nil {
		return "the sandbox"
	}
	return s.spec.DisplayName
}

// detachScript starts argv ${2...} in the background, in a session of its
// own, as the latest detached run in the run directory $1 (see runs.go).
// Its runner records the harness's exit status in latest.exit unless a
// stop marked the run interrupted there meanwhile: a stop lets the harness
// exit (SIGTERM) before the sandbox goes, and that status is not the run's
// own ending.
// Without setsid the runner ignores SIGHUP itself: nohup refuses to start
// it where it cannot detach from a console (macOS outside a login session).
const detachScript = `set -eu
d=$1
shift
mkdir -p "$d"
log="$d/$(date -u +%Y%m%dT%H%M%SZ).log"
ln -sfn "$log" "$d/latest.log"
rm -f "$d/latest.exit"
date +%s > "$d/latest.started"
runner='f=$1; shift; rc=0; "$@" || rc=$?; [ -s "$f" ] || printf "%s\n" "$rc" > "$f"'
if command -v setsid >/dev/null 2>&1; then
  setsid nohup sh -c "$runner" sh "$d/latest.exit" "$@" >"$log" 2>&1 </dev/null &
else
  (trap '' HUP; exec sh -c "$runner" sh "$d/latest.exit" "$@") >"$log" 2>&1 </dev/null &
fi
printf '%s\n' "$!" > "$d/latest.pid"
`

// detach starts the harness in the background inside the sandbox; its
// output goes to RunDir/latest.log (see runs.go).
func (s *session) detach(ctx context.Context, opts harness.LaunchOptions) error {
	opts.Args = streamingArgs(s.spec, opts.Args)
	argv, err := s.spec.LaunchArgv(opts)
	if err != nil {
		return err
	}
	inv, err := s.cli.Exec(s.sb.Name, append([]string{"sh", "-c", detachScript, "sh", RunDir}, argv...),
		openshell.CLIExecOptions{WorkDir: s.sb.Workdir, Timeout: time.Minute})
	if err != nil {
		return err
	}
	var out bytes.Buffer
	code, err := s.app.Streamer.Stream(ctx, inv, &out, &out)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("start %s in the background: exit status %d: %s", s.spec.DisplayName, code, truncate(out.String(), 300))
	}
	a := s.app
	a.ok(s.spec.DisplayName + " is running in the background in " + s.sb.Name)
	a.line("follow:  " + CommandName + " logs " + s.sb.Name + " -f")
	a.line("watch:   " + CommandName + " activity -f --sandbox " + s.sb.Name)
	if s.sb.WorkdirMode == config.OpenShellWorkdirCopy {
		a.line("results: " + CommandName + " pull " + s.sb.Name + " --apply|--branch|--patch-out FILE")
	} else {
		a.line("review:  " + CommandName + " review " + s.sb.Name + "   undo: " + CommandName + " undo " + s.sb.Name)
	}
	a.line("stop:    " + CommandName + " stop " + s.sb.Name)
	if s.spec.Name == harness.ClaudeCode.Name {
		a.note("A completed detached Claude Code run may leave no saved conversation. If connect -- --continue cannot find one, connect without --continue to start a new conversation.")
	}
	return nil
}

// uploadCopy sends the staged copy and records its baseline. It runs
// before any exec in the workdir, which the upload creates.
func (s *session) uploadCopy(ctx context.Context, rec *workspace.CopyRecord) error {
	a := s.app
	t := a.transport(s.cli)
	report := func(result string, rec *workspace.CopyRecord, failure string) {
		r := sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUpload, Result: result, FailureClass: failure}
		if rec != nil {
			files, bytes := int64(rec.Files), rec.Bytes
			r.FileCount, r.ByteCount = &files, &bytes
		}
		if err := s.api.ReportWorkspace(context.WithoutCancel(ctx), s.sb.Name, r); err != nil {
			a.warn("could not record the upload with the daemon: " + err.Error())
		}
	}
	a.note(fmt.Sprintf("Uploading the copy (%s, %s)…", plural(int64(rec.Files), "file", "files"), humanBytes(rec.Bytes)))
	// The upload goes over the OpenShell CLI's ssh session; t's exec, over
	// the gateway API in this sandbox, confirms it arrived here.
	up, err := a.Workspace.Upload(ctx, a.dataDir(), s.sb.Name, t, t)
	if err != nil {
		report("failed", rec, "upload_failed")
		hint := a.sandboxDiskHint(ctx, s.api, err)
		if errors.Is(err, workspace.ErrUploadNotArrived) {
			hint = strayUploadHint
		}
		if outage := a.accountOutage(ctx, err); outage != err {
			return outage
		}
		return workspaceFailure("upload the project copy", err, hint)
	}
	if _, err := a.Workspace.Baseline(ctx, a.dataDir(), s.sb.Name, t); err != nil {
		report("failed", up, "baseline_failed")
		return workspaceFailure("record the copy's baseline", err, "")
	}
	report("completed", up, "")
	a.copyWarnings(up)
	return nil
}

// copyWarnings prints what an upload or a refresh of a copy left out: the
// secret files it held back (one line, however many) and the record's
// other warnings.
func (a *App) copyWarnings(rec *workspace.CopyRecord) {
	if n := len(rec.HeldBack); n > 0 {
		a.warn(plural(int64(n), "secret file", "secret files") + " held back from the copy: " + strings.Join(firstN(rec.HeldBack, 8), ", "))
	}
	if n := len(rec.Unmasked); n > 0 {
		a.warn(plural(int64(n), "file that looks like a secret is", "files that look like secrets are") + " in the copy (--unmask), so the agent can read " +
			itThem(rec.Unmasked) + ": " + strings.Join(firstN(rec.Unmasked, 8), ", "))
	}
	for _, w := range rec.Warnings {
		a.warn(w)
	}
}

// strayUploadHint follows an upload that did not arrive in the sandbox it
// named (workspace.ErrUploadNotArrived).
const strayUploadHint = "`" + CommandName + " doctor` checks the ssh connection sharing that can carry an upload into another sandbox"

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string(nil), list[:n]...), fmt.Sprintf("(+%d more)", len(list)-n))
}

// end runs the end-of-session summary, review and keep/undo decision.
func (s *session) end(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	a := s.app
	deleted := func() error {
		a.println()
		a.warn(s.sb.Name + " was deleted from outside this session, which ended " + s.harnessName() +
			"; there is nothing left to review, and its undo point went with it")
		s.printCLIErr(true)
		return nil
	}
	after, err := s.settled(ctx)
	if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return deleted()
	}
	if daemonUnreachable(err) {
		// The session's end needs the daemon: say what did not run and the
		// way to it, where it said only that the daemon was down (GAP-0336).
		a.println()
		later := "`" + CommandName + " review " + s.sb.Name + "` shows its changes and `" + CommandName + " undo " + s.sb.Name +
			"` reverts them; " + s.sb.Name + " and its undo point are kept"
		if s.sb.WorkdirMode == config.OpenShellWorkdirCopy {
			later = "`" + CommandName + " pull " + s.sb.Name + "` brings its work back; " + s.sb.Name + " keeps it"
		}
		a.warn("the DefenseClaw daemon is not running, so this session's review and its question about the changes did not run: start it with " +
			"`defenseclaw-gateway start`, then " + later)
		return &ExitError{Code: 1, Err: &Silent{Err: errors.New("the DefenseClaw daemon is not running")}}
	}
	if err != nil {
		return apiError(err)
	}
	// A delete from another terminal stops the sandbox first: it reads as
	// deleting, then is gone (GAP-0170).
	if after, err = s.settledPhase(ctx, after); sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return deleted()
	}
	a.println()
	s.driver = firstNonEmpty(after.Driver, s.sb.Driver)
	if st, err := s.api.Status(ctx); err == nil {
		s.daemonStarted = st.StartedAt
		s.gatewayDown = st.Enabled && !st.Available
		if st.Managed != nil {
			s.driver = firstNonEmpty(s.driver, st.Managed.Driver)
			s.otherGateways = slices.Clone(st.Managed.OtherGateways)
			if after.Phase != "ready" {
				// The managed gateway's words for the stop that revoked the
				// sandbox's registration (a re-match: a host port, settings
				// or a harness the profile no longer allows), else what the
				// caller's policy says now (#1199, GAP-0486).
				s.policyStop = after.StopReason
				if s.policyStop == "" {
					s.policyStop = s.managedStopText(ctx)
				}
			}
		}
		if st.Gateway != nil {
			s.driver = firstNonEmpty(s.driver, st.Gateway.Driver)
		}
	}
	elsewhere := s.endedElsewhere(after)
	if elsewhere != "" {
		a.warn(elsewhere)
	}
	if at := after.Hooks.PlaceholderRefusedAt; !at.IsZero() && !s.startedAt.IsZero() && !at.Before(s.startedAt) {
		s.placeholder = true
	}
	s.printCLIErr(elsewhere != "")
	// While the sandbox still runs: the review may stop it.
	s.diagnoseStart(ctx, after, elsewhere != "")
	if !s.started && after.Phase == "ready" {
		// The sandbox was running before the session: a detached run may
		// still be going in it.
		if run, err := a.detachedRun(ctx, s.cli, after); err == nil && run.State == sandboxapi.RunRunning {
			s.liveRun = true
		}
	}
	// Another session's harness or shell still running in the sandbox keeps
	// it running (this session's lease went with its harness). A mounted
	// sandbox this session would stop before its review is counted and
	// stopped under the sandbox's exclusive gate (lockForStop), so a session
	// that attaches after the count waits for the stop and then finds the
	// sandbox stopped, rather than being stopped under its harness.
	release := func() {}
	if after.WorkdirMode != config.OpenShellWorkdirCopy && after.Phase == "ready" && !s.lost && s.started && !s.liveRun {
		s.others, release, err = a.lockForStop(ctx, s.sb.Name)
	} else {
		// A copy's pull below covers what changed it only if no session
		// is attached now and none attaches before its stop (pullBase,
		// read before this count).
		s.pullBase = a.copyBaseOf(after)
		s.others, err = a.attachedSessions(s.sb.Name)
		s.pullBase.ok = s.pullBase.ok && s.others == 0
	}
	if err != nil {
		return attachedUnknown(s.sb.Name, err)
	}
	if after.WorkdirMode == config.OpenShellWorkdirCopy {
		return s.endCopy(ctx, after, elsewhere != "")
	}
	// What the agent left running keeps writing to the mounted folder: a
	// sandbox the session owns stops before the review, so the review, the
	// keep/undo answer and the undo point cover everything it changed.
	stopped, stopFailed := false, false
	switch {
	case after.Phase != "ready":
		// Stopped from elsewhere: nothing runs in it any more.
		stopped = true
	case s.others > 0:
		a.note(s.sb.Name + " keeps running: " + s.othersText() + ", so what changes after this review is not in it")
	case s.lost:
		a.note(s.sb.Name + " keeps running for a reattach, so what changes after this review is not in it")
	case s.started && !s.liveRun:
		if sb, err := s.api.Stop(ctx, s.sb.Name); err != nil {
			if now, gerr := s.api.Get(ctx, s.sb.Name); gerr == nil && now.Phase == "error" {
				// The runtime stopped as the session ended: the stop
				// met that, in whatever words; the line says what happened,
				// and nothing runs in it any more (GAP-0337).
				after, stopped = now, true
				if text := s.endedElsewhere(after); text != "" {
					a.warn(text)
				}
			} else {
				stopFailed = true
				a.warn("could not stop " + s.sb.Name + " before reviewing its changes (" + apiError(err).Error() +
					"); what still runs in it can change the folder after this review")
			}
		} else {
			stopped = true
			if sb != nil {
				after = sb
			}
		}
	case s.unanswered:
		runtime, why := s.runtimeStopCause(after)
		a.warn(s.sb.Name + " does not answer, though OpenShell still reads it as running: its " + runtime + " may have stopped under the session " +
			"(" + why + "); `" + CommandName + " status " + s.sb.Name + "` shows its state")
	case !s.liveRun:
		a.note(s.sb.Name + " is still running (it was running when you connected); changes it makes after this point are not in this review")
	}
	release()
	rev, err := s.api.Review(ctx, s.sb.Name, sandboxapi.ReviewRequest{})
	if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		return deleted()
	}
	reviewed := err == nil
	if !reviewed {
		a.warn("could not review the session's changes: " + apiError(err).Error())
	}
	a.println(s.summaryLine(after, rev))
	s.printHookReach(after, elsewhere != "")
	s.printNotices()
	// A session whose review failed may have changed anything: the
	// keep/undo question still comes, and the undo point stays.
	changed := !reviewed || (rev != nil && rev.Report != nil && (rev.Report.FilesChanged > 0 || len(rev.Report.Flags) > 0 ||
		rev.Report.HeadBefore != rev.Report.HeadAfter || rev.Report.BranchBefore != rev.Report.BranchAfter))
	if !reviewed {
		s.keepSnapshot, s.keepWhy = true, "the changes were not reviewed"
		if after.Snapshot != nil {
			a.note("undo still restores the folder to its undo point: `" + CommandName + " undo " + s.sb.Name + "`")
		}
	}
	if rev != nil && rev.Report != nil {
		a.printCommits(rev.Report)
		if line := riskLine(rev.Report); line != "" {
			a.println(a.style(line, ansiYellow))
		}
	} else if rev != nil && rev.RiskLine != "" {
		a.println(a.style(rev.RiskLine, ansiYellow))
	}
	s.printNested(after)
	s.printAsks(after)
	if (s.liveRun || s.others > 0) && changed {
		// Undo stops the sandbox, which would end the run or the other
		// sessions (and revert their work too).
		what := "the detached run in " + s.sb.Name + " is still going; review or undo once it ends"
		if !s.liveRun {
			what = s.othersText() + "; review or undo once they end"
		}
		a.note(what + ": `" + CommandName + " review " + s.sb.Name + "`, `" + CommandName + " undo " + s.sb.Name + "`")
		return s.finish(ctx, false)
	}
	if rev != nil && len(rev.UnmaskedSecrets) > 0 {
		s.unmasked = rev.UnmaskedSecrets
		a.warn(unmaskedText(s.unmasked) + ", and " + s.sb.Name + " does not mask " + itThem(s.unmasked) +
			" (its masks are fixed when it is created): keeping " + itThem(s.unmasked) + " in the project means " + s.sb.Name +
			" cannot be resumed → undo the session, or move " + itThem(s.unmasked) + " out of the project")
	}
	decision, accepted := s.onExit(changed)
	for decision == "d" {
		diff, err := s.api.Review(ctx, s.sb.Name, sandboxapi.ReviewRequest{Diff: true})
		if err != nil {
			a.warn("diff: " + apiError(err).Error())
		} else {
			a.page(diff.Diff)
		}
		decision, accepted = s.onExit(changed)
	}
	if changed && (decision == "u" || accepted) {
		// The question may have waited while the sandbox was deleted, or a
		// new sandbox took its name: the answer is not for that one
		// (GAP-0170).
		now, err := s.api.Get(ctx, s.sb.Name)
		if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			return deleted()
		}
		if err == nil && s.sb.ID != "" && now.ID != "" && now.ID != s.sb.ID {
			a.warn(s.sb.Name + " was deleted while this question waited, and a new sandbox took its name; the answer does not apply to it")
			return nil
		}
	}
	switch {
	case decision == "u":
		// Undo stops the sandbox and puts the folder back: a session that
		// attached while the question was open would be ended and lose its
		// work. It is counted, and the undo made, under the sandbox's
		// exclusive gate; one attached keeps the sandbox and the changes.
		others, unlock, err := a.lockForStop(ctx, s.sb.Name)
		if err != nil {
			return attachedUnknown(s.sb.Name, err)
		}
		if others > 0 {
			unlock()
			s.others = others
			a.warn("not undone: " + s.othersText() + " now (undo stops " + s.sb.Name + ", which ends " + them(others) + ") → undo once " +
				map[bool]string{true: "it ends", false: "they end"}[others == 1] + ": `" + CommandName + " undo " + s.sb.Name + "`")
			s.keepSnapshot, s.keepWhy = true, "it was not undone: "+s.othersText()
			return s.finish(ctx, false)
		}
		wasRunning := after.Phase == "ready"
		res, err := s.api.Undo(ctx, s.sb.Name, sandboxapi.UndoRequest{Stop: true})
		unlock()
		if err != nil {
			return fmt.Errorf("undo: %w", apiError(err))
		}
		a.ok("undone: " + undoDone(res, "see below"))
		if res.Result != nil {
			for _, w := range res.Result.Warnings {
				a.warn(w)
			}
			a.printUnrestored(res.Result.Unrestored())
		}
		// The folder is back at its undo point; undo stopped the sandbox.
		s.keepSnapshot, s.unmasked = false, nil
		s.undoStopped = wasRunning && !s.started
		return s.finish(ctx, true)
	case decision == "i":
		// Ctrl-C at the question: nothing was decided.
		s.interrupted, s.keepSnapshot, s.keepWhy = true, true, "nothing was decided"
		a.warn("interrupted: nothing was decided, so the changes stay in the folder and the undo point is kept (`" + CommandName + " undo " +
			s.sb.Name + "` still reverts them; `" + CommandName + " review " + s.sb.Name + "` shows them)")
	case !changed:
	case accepted && reviewed && stopped:
		// The next session starts from here: its undo point replaces this
		// one, whoever starts it. Changes nobody could review never become
		// the base.
		if a.acceptChanges(ctx, s.api, after) {
			a.ok("kept: the changes stay in the folder, and the next session takes a new undo point")
		} else {
			// The warning said the undo point stays.
			a.ok("kept: the changes stay in the folder")
			s.notAccepted = true
		}
	case accepted && reviewed && s.unanswered:
		a.ok("kept: the changes stay in the folder")
		a.note("the undo point stays, since " + s.sb.Name + " does not answer: `" + CommandName + " undo " + s.sb.Name +
			"` still reverts this session's changes")
	case accepted && reviewed && stopFailed:
		// Not running, but not stopped either (OpenShell's error state after
		// a runtime restart): "keeps running" was false there (GAP-0333).
		a.ok("kept: the changes stay in the folder")
		a.note("the undo point stays, since " + s.sb.Name + " could not be stopped: `" + CommandName + " undo " + s.sb.Name +
			"` still reverts this session's changes")
	case accepted && reviewed:
		// The sandbox keeps running: what it changes after this review was
		// not reviewed, so it must not become the base either.
		a.ok("kept: the changes stay in the folder")
		a.note("the undo point stays, since " + s.sb.Name + " keeps running: `" + CommandName + " undo " + s.sb.Name +
			"` still reverts this session's changes with whatever it changes next")
	case accepted:
		a.ok("kept: the changes stay in the folder, and the undo point stays, since they could not be reviewed")
	case after.Snapshot != nil:
		a.note("the changes stay in the folder; `" + CommandName + " undo " + s.sb.Name + "` still reverts them")
	}
	if changed && !accepted && !s.keepSnapshot && after.Snapshot != nil {
		// Nobody kept the changes (no terminal and no --yes, or no answer):
		// they stay undoable, so --rm keeps the undo snapshot.
		s.keepSnapshot, s.keepWhy = true, "nobody accepted the changes (--yes accepts them when no terminal can)"
	}
	return s.finish(ctx, stopped)
}

// endedElsewhere says what ended the session from outside it, when
// something did: the sandbox was undone or stopped (another terminal, the
// TUI), which ended the harness under the user.
func (s *session) endedElsewhere(after *sandboxapi.Sandbox) string {
	if s.startedAt.IsZero() || s.before == nil || s.before.Phase != "ready" {
		return ""
	}
	name := s.sb.Name
	if snap := after.Snapshot; snap != nil && !snap.UndoneAt.IsZero() && snap.UndoneAt.After(s.startedAt) &&
		(s.before.Snapshot == nil || !snap.UndoneAt.Equal(s.before.Snapshot.UndoneAt)) {
		return name + " was undone from outside this session (`" + CommandName + " undo` or the TUI): the folder is back at its undo point, " +
			"and that stopped " + s.harnessName()
	}
	if after.Phase == "error" {
		// Not a stop of anyone's: OpenShell lost the sandbox (GAP-0278).
		s.errored = true
		s.errorPhaseReason = after.PhaseReason
		runtime, why := s.runtimeStopCause(after)
		text := name + "'s " + runtime + " stopped under the session (" + why + "), which ended " + s.harnessName() +
			"; OpenShell now holds it in its error state"
		if runtime == "MicroVM" && len(s.otherGateways) > 0 {
			text += ". " + otherGatewaysText(s.otherGateways) + ". Stop that process (`kill PID` with the number above) once your sandboxes are saved"
		}
		return text
	}
	if after.Phase != "ready" {
		if h := after.Hooks; h.Silent && h.OnSilence == packs.OnSilenceStop {
			// DefenseClaw's own stop (raiseSilence), not someone else's.
			return "DefenseClaw stopped " + name + ": " + s.harnessName() + " worked for " + firstNonEmpty(h.SilenceAfter, "a while") +
				" without a hook reaching DefenseClaw (hooks.on_silence: stop). Check its hook configuration in the sandbox before you start it again"
		}
		if s.policyStop != "" {
			// The organization's stop, not someone else's (GAP-0486).
			return s.policyStop
		}
		if s.gatewayDown {
			// Not a stop of DefenseClaw's (GAP-0202): the gateway that runs
			// the sandbox went away under it.
			return "the OpenShell gateway is not available (it was stopped, or another account's gateway took its port; `" + CommandName +
				" doctor` says which), which ended " + s.harnessName()
		}
		return name + " was stopped from outside this session (`" + CommandName + " stop` or the TUI), which ended " + s.harnessName()
	}
	if s.lost {
		return "the connection to " + name + " was lost (the OpenShell gateway restarted, for one), which ended " + s.harnessName() +
			"; " + name + " is still running → reattach: " + CommandName + " connect " + name
	}
	return ""
}

// runtimeStopCause describes a runtime failure using the sandbox's driver,
// falling back to the gateway's when the sandbox predates that field.
func (s *session) runtimeStopCause(after *sandboxapi.Sandbox) (runtime, why string) {
	if firstNonEmpty(after.Driver, s.sb.Driver, s.driver) == string(openshell.DriverVM) {
		if len(s.otherGateways) > 0 {
			return "MicroVM", "another OpenShell gateway in your account likely took over its state"
		}
		return "MicroVM", "its gateway restarted, or its workload failed"
	}
	return "container", "Docker restarted, or its workload failed"
}

// managedStopText is the notice for a sandbox stopped under the session on
// a managed computer when the caller's policy no longer allows it: the
// profile allows no sandboxes now, or not this agent in one. It is the
// text the managed gateway gives that stop (sandboxapi.ProfileStop), which
// reaches the daemon but not the session; "" when the policy still allows
// the run, which then was stopped by someone else (GAP-0486).
func (s *session) managedStopText(ctx context.Context) string {
	name := s.sb.Harness
	if s.spec != nil {
		name = s.spec.Name
	}
	ex, err := s.api.Explain(ctx, sandboxapi.ExplainRequest{Harness: name})
	if err != nil || ex.Managed == nil {
		return ""
	}
	switch m := ex.Managed; {
	case !m.Allowed:
		return sandboxapi.ProfileStop("sandboxes", name, m.RequestAccess)
	case len(m.AllowedHarnesses) > 0 && !slices.ContainsFunc(m.AllowedHarnesses, func(h string) bool {
		return config.NormalizeConnectorName(h) == name
	}):
		return sandboxapi.ProfileStop("this agent in a sandbox", name, m.RequestAccess)
	}
	return ""
}

// settledPhase waits, at most settlePhaseWait, while the sandbox's phase
// is passing (the OpenShell gateway restarting under it reads as unknown
// or provisioning), and returns it as it then is. A session whose harness
// failed while the sandbox passed through such a phase and came back
// ready lost its connection to the sandbox, not the sandbox (lost).
//
// A sandbox being deleted (from another terminal or the TUI) is passing
// too: once it is gone, settledPhase returns the not-found error.
func (s *session) settledPhase(ctx context.Context, after *sandboxapi.Sandbox) (*sandboxapi.Sandbox, error) {
	passing := passingPhase
	if !passing(after.Phase) {
		// A harness that failed while its sandbox still reads ready may
		// have lost the sandbox a moment ago (a runtime restart stops it,
		// and OpenShell says so a few seconds later): look
		// again shortly before calling it running (GAP-0278).
		if after.Phase != "ready" || s.harnessCode == 0 || s.before == nil || s.before.Phase != "ready" {
			return after, nil
		}
		for range 2 {
			if s.app.Sleep(ctx, settlePhaseInterval) != nil {
				break
			}
			next, err := s.api.Get(ctx, s.sb.Name)
			if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
				return nil, err
			}
			if err != nil {
				break
			}
			if after = next; after.Phase != "ready" {
				break
			}
		}
		if after.Phase == "ready" && !s.answers(ctx) {
			// Still read ready, but it runs no command: its runtime is
			// gone, and OpenShell says so once the gateway is back, which can take
			// longer than the look above (GAP-0333, GAP-0337).
			after, err := s.waitPhase(ctx, after, func(phase string) bool { return phase == "ready" || passing(phase) })
			if err == nil && after.Phase == "ready" {
				s.unanswered = true
			}
			return after, err
		}
		if !passing(after.Phase) {
			return after, nil
		}
	}
	after, err := s.waitPhase(ctx, after, passing)
	if err != nil {
		return nil, err
	}
	s.lost = after.Phase == "ready" && s.harnessCode != 0 && s.before != nil && s.before.Phase == "ready"
	return after, nil
}

// passingPhase reports a phase a sandbox passes through: being created,
// started or deleted, or unknown while the OpenShell gateway restarts.
func passingPhase(phase string) bool {
	switch phase {
	case "unknown", "provisioning", "starting", "creating", "deleting":
		return true
	}
	return false
}

// waitPhase reads the sandbox every settlePhaseInterval, for at most
// settlePhaseWait, while wait holds for its phase, and returns it as it then
// is; the not-found error once it is gone.
func (s *session) waitPhase(ctx context.Context, after *sandboxapi.Sandbox, wait func(string) bool) (*sandboxapi.Sandbox, error) {
	for range int(settlePhaseWait / settlePhaseInterval) {
		if !wait(after.Phase) || s.app.Sleep(ctx, settlePhaseInterval) != nil {
			break
		}
		next, err := s.api.Get(ctx, s.sb.Name)
		if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			return nil, err
		}
		if err != nil {
			break
		}
		after = next
	}
	return after, nil
}

// answers reports whether the sandbox runs a trivial command now (one try,
// within answerTimeout); a command that cannot be prepared counts as an
// answer, which leaves the phase as OpenShell reports it.
func (s *session) answers(ctx context.Context) bool {
	inv, err := s.cli.Exec(s.sb.Name, []string{"true"}, openshell.CLIExecOptions{Timeout: answerTimeout})
	if err != nil {
		return true
	}
	var out bytes.Buffer
	code, err := s.app.Streamer.Stream(ctx, inv, &out, &out)
	return err == nil && code == 0
}

// answerTimeout bounds answers.
const answerTimeout = 10 * time.Second

// settlePhaseWait and settlePhaseInterval pace settledPhase.
const (
	settlePhaseWait     = 20 * time.Second
	settlePhaseInterval = 2 * time.Second
)

// onExit returns k (keep), u (undo), d (diff) or i (the user pressed
// Ctrl-C), and whether keeping was the user's choice (an answer, --yes,
// or on_exit: keep) rather than the default without a terminal.
func (s *session) onExit(changed bool) (string, bool) {
	a := s.app
	if !changed {
		return "k", false
	}
	policy := config.OpenShellOnExitAsk
	if a.Cfg != nil && a.Cfg.OpenShell.Workdir.OnExit != "" {
		policy = a.Cfg.OpenShell.Workdir.OnExit
	}
	switch policy {
	case config.OpenShellOnExitKeep:
		return "k", true
	case config.OpenShellOnExitUndo:
		return "u", false
	}
	if s.sb.Snapshot == nil {
		return "k", false
	}
	if !a.IO.TTY || s.yes {
		return "k", s.yes
	}
	ans, err := a.choose("Keep changes?", []choice{{"y", "keep"}, {"u", "undo everything"}, {"d", "show diff"}}, "y")
	if errors.Is(err, errInterrupted) {
		return "i", false
	}
	if err != nil {
		return "k", false
	}
	if ans == "y" {
		return "k", true
	}
	return ans, false
}

// othersText is "1 other session is attached to it".
func (s *session) othersText() string {
	return plural(int64(s.others), "other session is", "other sessions are") + " attached to it"
}

// sessionDeleteError preserves the API error while giving the session's
// cleanup failure a recovery step. A failed wait does not tell whether the
// sandbox is gone, stopped or still deleting.
type sessionDeleteError struct {
	name         string
	keepSnapshot bool
	err          error
}

func (e *sessionDeleteError) Error() string {
	why := gatewayTransportText(apiError(e.err).Error())
	retry := CommandName + " delete " + e.name
	if e.keepSnapshot {
		retry += " --keep-snapshot"
	}
	return "could not confirm deletion of " + e.name + " (" + why + "). Check the gateway with `" + CommandName +
		" doctor`, then retry `" + retry + "`; `" + CommandName + " list` confirms whether it is gone"
}

func (e *sessionDeleteError) Unwrap() error { return e.err }

// finish stops (or with --rm deletes) the sandbox after a session. A
// sandbox the session did not start, whose detached run is still going, or
// that other sessions are attached to keeps running.
func (s *session) finish(ctx context.Context, stopped bool) error {
	a := s.app
	name := s.sb.Name
	// A reconnect may have recorded its lease while the copy's final
	// apply/branch/patch question was open: count again, under the
	// sandbox's exclusive gate, held through the Stop or the Delete below,
	// so no session attaches between this count and that call.
	others, unlock, err := a.lockForStop(ctx, name)
	if err != nil {
		return attachedUnknown(name, err)
	}
	defer unlock()
	s.others = others
	switch {
	case s.rm && s.liveRun:
		s.notDeleted("its detached run is still going", "the run ends")
	case s.rm && s.others > 0:
		s.notDeleted(s.othersText(), "they end")
	}
	if s.rm {
		if _, err := s.api.Delete(ctx, name, sandboxapi.DeleteRequest{KeepSnapshot: s.keepSnapshot}); err != nil {
			failure := &sessionDeleteError{name: name, keepSnapshot: s.keepSnapshot, err: err}
			if !s.autoRm {
				return failure
			}
			// Nobody asked for this delete: the run still succeeded, and
			// cleanup is unconfirmed. Do not stop it or offer a resume while
			// deletion may still be in progress.
			a.warn(failure.Error())
			return nil
		}
	}
	if s.rm {
		a.forgetCLIState(name)
		why := " (--rm)"
		if s.autoRm {
			why = " (" + autoRmKeep + ")"
		}
		if s.keepSnapshot {
			a.ok("sandbox " + name + " deleted" + why + "; its undo point is kept because " + s.keepWhy + " → review: " +
				CommandName + " review " + name + "   undo: " + CommandName + " undo " + name + "   drop it: " + CommandName + " delete " + name)
			return nil
		}
		if s.autoRm {
			why = ": nothing is left in it to bring back or undo (" + autoRmKeep + ")"
		}
		a.ok("sandbox " + name + " deleted" + why)
		return nil
	}
	if !stopped {
		switch {
		case s.diskFull:
			a.note(fullDiskKeepText(name))
			return nil
		case s.liveRun:
			a.note("Sandbox " + name + " keeps running: its detached run is still going → follow: " + CommandName + " logs " + name + " -f   stop: " +
				CommandName + " stop " + name)
			return nil
		case s.others > 0:
			a.note("Sandbox " + name + " keeps running: " + s.othersText() + " → stop it once they end: " + CommandName + " stop " + name)
			return nil
		case s.lost:
			a.note("Sandbox " + name + " keeps running → reattach: " + CommandName + " connect " + name + "   stop: " + CommandName + " stop " + name)
			return nil
		case s.unanswered:
			a.note("Sandbox " + name + " does not answer → `" + CommandName + " status " + name +
				"` shows its state; if it enters OpenShell's error state, `" + CommandName + " doctor` shows its recovery steps")
			return nil
		case !s.started:
			if now, err := s.api.Get(ctx, name); err == nil && now.Phase != "ready" {
				// Stopped while the session ended (another terminal, the
				// TUI): the line read "keeps running → stop" (GAP-0366).
				a.note("Sandbox " + name + " is " + now.Phase + " now (stopped from outside this session) → resume: " + CommandName + " connect " + name)
				return nil
			}
			a.note("Sandbox " + name + " keeps running (it was running when you connected) → stop: " + CommandName + " stop " + name)
			s.continueHint()
			return nil
		}
		sb, err := s.api.Stop(ctx, name)
		if err != nil {
			if sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
				// OpenShell's error state: nothing runs in it (GAP-0333).
				a.warn("could not stop " + name + ": " + apiError(err).Error())
				return nil
			}
			s.stopFailed = true
			// No raw gRPC transport text (#1202): the steps after it work.
			a.warn("could not stop " + name + ": " + gatewayTransportText(apiError(err).Error()) + " → it may still be running: `" +
				CommandName + " status " + name + "` shows where it stands, `" + CommandName + " stop " + name + "` stops it")
			return nil
		}
		s.markStopped(sb)
	}
	if s.errored {
		// A failed MicroVM's main process can leave its VM running. Its
		// stop is refused; only an explicit end with the loss explained by
		// StopWayOn, or deletion, lets OpenShell release it.
		if runtime, _ := s.runtimeStopCause(s.sb); runtime == "MicroVM" {
			if openshell.LingeringVM(openshell.PhaseError, s.errorPhaseReason, false) {
				way := openshell.StopWayOn(name, openshell.PhaseError, s.errorPhaseReason, openshell.SupportedMin)
				if !openshell.MainProcessFailed(s.errorPhaseReason) {
					way += "; its MicroVM work is kept only through the last successful disk sync"
				}
				a.note("Sandbox " + name + " is in OpenShell's error state → " +
					way)
				return nil
			}
			a.note("Sandbox " + name + " is in OpenShell's error state → fix why its MicroVM failed, then `" + CommandName + " stop " + name +
				"` and `" + CommandName + " start " + name + "`; the sandbox remains, but its MicroVM work is kept only through the last successful disk sync")
			return nil
		}
		a.note("Sandbox " + name + " is in OpenShell's error state → fix what stopped it, then `" + CommandName + " stop " + name +
			"` and `" + CommandName + " start " + name + "`, which keep the sandbox and its work")
		return nil
	}
	if s.policyStop != "" {
		// A policy stop revoked this run's registration. The stop notice
		// gives the permitted next step; this sandbox cannot be resumed.
		a.note("Sandbox kept (stopped) → delete: " + CommandName + " delete " + name)
		return nil
	}
	next := "resume: " + CommandName + " connect " + name
	if s.headless {
		next += " --prompt TEXT"
	}
	if len(s.unmasked) > 0 {
		// connect refuses while they are in the project.
		next = "to resume, first move " + strings.Join(shownFiles(s.unmasked), ", ") + " out of the project, then: " +
			strings.TrimPrefix(next, "resume: ")
	}
	if s.notAccepted {
		if now, err := s.api.Get(ctx, name); err == nil && now.Phase == "ready" {
			// Started again from outside this session while its question was
			// open (another terminal, the TUI): "kept (stopped)" was false
			// (GAP-0389).
			a.note("Sandbox " + name + " is running again (started from outside this session) → reattach: " + CommandName + " connect " + name +
				"   stop: " + CommandName + " stop " + name)
			return nil
		}
	}
	kept := "Sandbox kept (stopped)"
	if s.undoStopped {
		kept = "Sandbox " + name + " is stopped now (undo stops it) and kept"
	}
	if s.keptWhy != "" {
		kept += ": " + s.keptWhy
	}
	a.note(kept + " → " + next + "   delete: " + CommandName + " delete " + name)
	s.continueHint()
	return nil
}

// shownFiles names at most five files, then how many more there are.
func shownFiles(files []string) []string {
	if len(files) <= 5 {
		return files
	}
	return append(slices.Clip(files[:5]), fmt.Sprintf("and %d more", len(files)-5))
}

// unmaskedText is "blk2.txt looks like a secret".
func unmaskedText(files []string) string {
	verb := " looks like a secret"
	if len(files) > 1 {
		verb = " look like secrets"
	}
	return strings.Join(shownFiles(files), ", ") + verb
}

// itThem is "it" for one file, else "them".
func itThem(files []string) string {
	if len(files) == 1 {
		return "it"
	}
	return "them"
}

// continueArgs are the harness arguments that continue its latest
// conversation in the project folder (all of them take the folder's most
// recent one, which a sandbox's own folder makes this session's).
var continueArgs = map[string]string{
	"claudecode": "--continue",
	"codex":      "resume --last",
	"opencode":   "--continue",
	"copilot":    "--continue",
	"kiro":       "--resume",
	"hermes":     "--continue",
	// agy's -c (a Go flag) reopens the folder's latest conversation, as
	// its own "Resume with -c" says.
	"antigravity": "-c",
}

// ownResumeHint is how the resume command a harness prints as it exits
// starts ("copilot --resume=<id>", "kiro-cli --resume-id <id>"). Its
// conversation is in the sandbox, so typed on this machine it does not
// reach it (the harness starts here, outside the sandbox, if it is
// installed at all), unless the shell wrapper sends that command into the
// sandbox. It cannot be kept off the screen: the harness prints it.
var ownResumeHint = map[string]string{
	"claudecode": "claude --resume",
	"codex":      "codex resume",
	// OpenCode's exit screen: "Continue  opencode -s ses_<id>".
	"opencode": "opencode -s",
	"copilot":  "copilot --resume",
	"kiro":     "kiro-cli --resume-id",
	"hermes":   "hermes --resume",
	// agy: "Resume with -c (or command below): agy --conversation=<id>".
	"antigravity": "agy --conversation",
}

// continueHint names, last and not dimmed, the command that continues this
// conversation inside the sandbox (a plain connect starts a new one), and
// what the harness's own resume hint does: the one it printed above after
// a session with a turn, else one it may print.
func (s *session) continueHint() {
	if s.headless || s.shell || s.spec == nil || (!s.sawHooks.Load() && !s.hooksUnknown) {
		// No conversation to continue: no hook of the session reached
		// DefenseClaw (a harness that failed to start, one nobody
		// prompted). After a daemon restart that cannot be told, and the
		// conversation may be there.
		return
	}
	a := s.app
	if s.placeholder {
		// --continue would resume the conversation OpenShell refuses.
		a.line(a.style("→", ansiCyan, ansiBold) + " start a new conversation: " + CommandName + " connect " + s.sb.Name +
			" (this one holds a sandbox credential placeholder, so OpenShell refuses its requests; --continue would resume it)")
		return
	}
	args, ok := continueArgs[s.spec.Name]
	if !ok {
		return
	}
	line := "continue this conversation: " + CommandName + " connect " + s.sb.Name + " -- " + args
	if own, ok := ownResumeHint[s.spec.Name]; ok {
		wrapped := strings.Fields(own)[0] == s.spec.Command && a.Cfg != nil && slices.Contains(a.Cfg.OpenShell.Wrappers, s.spec.Name)
		switch {
		case wrapped && s.hadTurn:
			line += " (the `" + own + " …` " + s.spec.DisplayName + " printed resumes it in this sandbox too: the shell wrapper is on)"
		case wrapped:
			line += " (a `" + own + " …` line of " + s.spec.DisplayName + " resumes it in this sandbox too: the shell wrapper is on)"
		case s.hadTurn:
			line += " (the `" + own + " …` " + s.spec.DisplayName + " printed above works only inside the sandbox)"
		default:
			line += " (a `" + own + " …` line of " + s.spec.DisplayName + " works only inside the sandbox)"
		}
	}
	a.line(a.style("→", ansiCyan, ansiBold) + " " + line)
}

// settled reads the sandbox for the session summary once its counts stop
// changing: OpenShell reports the session's last denials on its event
// stream a moment after they happen, so a read right as the session ends
// would miss them and disagree with a later status. It reads at most
// settleReads more times, settleInterval apart, and takes the last read
// when the counts keep moving.
func (s *session) settled(ctx context.Context) (*sandboxapi.Sandbox, error) {
	after, err := s.api.Get(ctx, s.sb.Name)
	if err != nil {
		return nil, err
	}
	for range settleReads {
		if s.app.Sleep(ctx, settleInterval) != nil {
			break
		}
		next, err := s.api.Get(ctx, s.sb.Name)
		if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			// Deleted while the session ended (GAP-0170).
			return nil, err
		}
		if err != nil {
			break
		}
		same := next.Egress.Destinations == after.Egress.Destinations && next.Egress.Blocked == after.Egress.Blocked &&
			next.Egress.BlockedRequests == after.Egress.BlockedRequests &&
			next.Hooks.ToolCalls == after.Hooks.ToolCalls && next.Hooks.ToolBlocked == after.Hooks.ToolBlocked &&
			next.Hooks.PromptBlocked == after.Hooks.PromptBlocked && next.Hooks.HookFailed == after.Hooks.HookFailed
		after = next
		if same {
			break
		}
	}
	return after, nil
}

// settleReads and settleInterval pace settled.
const (
	settleReads    = 3
	settleInterval = time.Second
)

// summaryLine is "Session ended · 57 tool calls (1 blocked: <rule title>
// (RULE-ID)) · 23 new sites contacted · 2 sites blocked · 8 files changed
// (+212 −37)". Both counts are destinations: the sites contacted are those
// the sandbox reached for the first time, and the sites blocked those the
// session announced blocked (its ✗ lines, which the summary repeats), or
// the daemon's count of newly blocked ones when that is higher (a late
// denial, or a flood the feed paced). A daemon restart keeps the hook
// counts and the destinations (GAP-0156), up to the last minute's when the
// daemon did not stop cleanly: counters below the session's start mean
// they started again, and the line says they cover only the time since the
// restart.
func (s *session) summaryLine(after *sandboxapi.Sandbox, rev *sandboxapi.ReviewResponse) string {
	before := s.before
	if before == nil {
		before = &sandboxapi.Sandbox{}
	}
	hooksBefore, egressBefore := before.Hooks, before.Egress
	// since qualifies the hook counts a daemon restart started again;
	// sitesReset marks the egress counts that started again.
	restarted := "since the daemon restarted"
	if s.restartedDuring() {
		restarted += " at " + s.app.clock(s.daemonStarted)
	}
	since, sitesReset := "", false
	if after.Hooks.HookRequests < hooksBefore.HookRequests || after.Hooks.ToolCalls < hooksBefore.ToolCalls {
		hooksBefore, since = sandboxapi.HookCoverage{}, restarted
	}
	if after.Egress.Destinations < egressBefore.Destinations || after.Egress.Blocked < egressBefore.Blocked ||
		after.Egress.BlockedRequests < egressBefore.BlockedRequests {
		egressBefore, sitesReset = sandboxapi.EgressStats{}, true
	}
	calls := after.Hooks.ToolCalls - hooksBefore.ToolCalls
	blocked := after.Hooks.ToolBlocked - hooksBefore.ToolBlocked
	asked := after.Hooks.ToolAsked - hooksBefore.ToolAsked
	s.hadTurn = calls > 0
	parts := []string{"Session ended"}
	tools := plural(max(calls, 0), "tool call", "tool calls")
	if since != "" {
		tools += " " + since
	}
	switch {
	case blocked > 0:
		tools += fmt.Sprintf(" (%d blocked", blocked)
		if after.Hooks.LastBlocked != "" {
			tools += ": " + blockedReason(after.Hooks.LastBlocked)
		}
		if asked > 0 {
			tools += fmt.Sprintf("; %d asked", asked)
		}
		tools += ")"
	case asked > 0:
		tools += fmt.Sprintf(" (%d asked)", asked)
	}
	parts = append(parts, tools)
	if prompts := after.Hooks.PromptBlocked - hooksBefore.PromptBlocked; prompts > 0 {
		parts = append(parts, plural(prompts, "prompt", "prompts")+" blocked")
	}
	// A hook call DefenseClaw answered with an error failed closed: the
	// harness's action was blocked without a verdict.
	if failed := after.Hooks.HookFailed - hooksBefore.HookFailed; failed > 0 {
		parts = append(parts, plural(failed, "hook call", "hook calls")+" failed (blocked)")
	}
	sites := after.Egress.Destinations - egressBefore.Destinations
	contacted := plural(int64(max(sites, 0)), "new site contacted", "new sites contacted")
	switch {
	case sitesReset && since != "":
		contacted += " since then"
	case sitesReset:
		contacted += " " + restarted
	}
	parts = append(parts, contacted)
	s.noticeMu.Lock()
	lifted := s.liftedBlocks()
	sitesBlocked := max(len(s.blockedHosts), after.Egress.Blocked-egressBefore.Blocked) - lifted
	s.noticeMu.Unlock()
	if sitesBlocked > 0 {
		parts = append(parts, plural(int64(sitesBlocked), "site blocked", "sites blocked"))
	}
	switch {
	case rev != nil && rev.Summary != "":
		parts = append(parts, rev.Summary)
	case rev != nil && rev.Report != nil:
		parts = append(parts, rev.Report.SummaryLine())
	}
	if rev != nil && rev.Report != nil {
		if moved := headMoved(rev.Report.BranchBefore, rev.Report.BranchAfter, rev.Report.HeadBefore, rev.Report.HeadAfter); moved != "" {
			parts = append(parts, moved)
		}
	}
	return strings.Join(parts, " · ")
}

// restartedDuring reports that the daemon the session ended with started
// after the session did: it restarted during the session, and a restart that
// was not clean may have lost its last minute of hook counts
// (hookReachUnknown).
func (s *session) restartedDuring() bool {
	return s.startedBefore(s.daemonStarted)
}

// startedBefore reports that the session started before a daemon that
// started at daemonStarted (zero: it does not say).
func (s *session) startedBefore(daemonStarted time.Time) bool {
	return !daemonStarted.IsZero() && !s.startedAt.IsZero() && daemonStarted.After(s.startedAt)
}

// blockedReason is a blocked tool call's reason as the summary names it:
// the deciding rule's title and ID ("E2E sandbox marker command
// (E2E-SANDBOX-MARKER)"), taken from the reason DefenseClaw gave the
// harness ("DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER:
// E2E sandbox marker command). Do not retry it in another form."), or the
// reason cut short.
func blockedReason(reason string) string {
	id, title, ok := sandboxapi.VerdictRule(reason)
	switch {
	case !ok:
		return truncate(strings.TrimSpace(reason), 60)
	case id == "":
		return "DefenseClaw policy"
	case title == "":
		return truncate(id, 60)
	}
	return truncate(title, 60) + " (" + id + ")"
}

// headMoved describes what a session did to HEAD: "switched main → fix",
// "HEAD moved on main (1a2b3c4 → 5d6e7f8)", or "" when it stayed.
func headMoved(branchBefore, branchAfter, headBefore, headAfter string) string {
	switch {
	case branchBefore != branchAfter:
		return "switched " + firstNonEmpty(branchBefore, "a detached HEAD") + " → " + firstNonEmpty(branchAfter, "a detached HEAD")
	case headBefore != headAfter:
		on := ""
		if branchAfter != "" {
			on = " on " + branchAfter
		}
		return "HEAD moved" + on + " (" + firstNonEmpty(shortCommit(headBefore), "none") + " → " + firstNonEmpty(shortCommit(headAfter), "none") + ")"
	}
	return ""
}

func shortCommit(oid string) string {
	if len(oid) > 7 {
		return oid[:7]
	}
	return oid
}

// printNested lists what the nested-repository guard found.
func (s *session) printNested(sb *sandboxapi.Sandbox) {
	a := s.app
	for _, n := range sb.NestedRepos {
		switch {
		case n.Kind == "gitlink":
			a.println(a.style("⚠ A submodule entry was added to the index: "+n.Path+"  → check .gitmodules before `git submodule update`", ansiYellow))
		case n.Error != "":
			a.println(a.style("✗ A new git repository at "+n.Path+" could not be quarantined ("+n.Error+"); do not run git there", ansiRed))
		default:
			a.println(a.style("⚠ A new git repository at "+n.Path+" was quarantined as "+n.Quarantined+"  → inspect it before renaming it back", ansiYellow))
		}
	}
}

// printAsks says where the asks the session left waiting are answered.
func (s *session) printAsks(sb *sandboxapi.Sandbox) {
	if sb.PendingApprovals <= 0 {
		return
	}
	a := s.app
	a.println(a.style("? "+plural(int64(sb.PendingApprovals), "ask is", "asks are")+" still waiting for you → "+
		CommandName+" approvals --sandbox "+sb.Name, ansiYellow))
}

// fullDiskKeepText is why the copy-mode MicroVM name keeps running, at the
// end of a session and at `sandbox stop`, while its own disk is full, and
// what to do first.
func fullDiskKeepText(name string) string {
	return "Sandbox " + name + " keeps running: a MicroVM stopped with its disk full cannot start again, and its work that was not pulled would be lost → " +
		"free some space in it (`" + CommandName + " exec " + name + " -- df -h /` shows it; `" + CommandName + " connect " + name +
		" --shell` to remove what it does not need), then `" + CommandName + " pull " + name + "`; stop it after that: `" + CommandName + " stop " + name + "`"
}

// overlayDiskEvery paces the session's look at its MicroVM's own disk
// (watchOverlayDisk) when it is larger than smallOverlayBytes, and
// smallOverlayDiskEvery when it is not, and the first look; tests shorten
// them.
var (
	overlayDiskEvery      = 2 * time.Minute
	smallOverlayDiskEvery = 15 * time.Second
)

// smallOverlayBytes is the size up to which a MicroVM's own disk is looked at
// every smallOverlayDiskEvery: an agent writing 50 MiB a second filled a
// 2 GiB one between two looks two minutes apart (GAP-1140).
const smallOverlayBytes = 4 << 30

// watchOverlayDisk looks at the own disk of the session's copy-mode
// MicroVM and says once, while the session runs, that it is full or
// filling: a write that fails there said nothing before the end of the
// session (#1148). It looks soon after the start, then every
// smallOverlayDiskEvery on a disk of up to smallOverlayBytes and every
// overlayDiskEvery on a larger one, and warns before the 90% mark too when,
// at the rate it filled since the last look, it would be full before the
// look after next (GAP-1140). A look that does not answer is tried again
// at the next tick.
func (s *session) watchOverlayDisk(ctx context.Context) {
	wait := smallOverlayDiskEvery
	var last overlayDisk
	var lastAt time.Time
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		disk := s.app.overlayDiskOf(ctx, s.cli, s.sb.Name)
		now := time.Now()
		if disk.known {
			wait = overlayDiskEvery
			if disk.size <= smallOverlayBytes {
				wait = smallOverlayDiskEvery
			}
		}
		if disk.filling() || disk.fillsWithin(last, now.Sub(lastAt), 2*wait) {
			text := "⚠ " + overlayDiskFillingText(s.sb.Name, disk, true)
			s.notice("overlay disk", text, text)
			return
		}
		if disk.known {
			last, lastAt = disk, now
		}
	}
}

// endCopy pulls a copy-mode sandbox's work and asks where it goes.
func (s *session) endCopy(ctx context.Context, after *sandboxapi.Sandbox, endedElsewhere bool) error {
	a := s.app
	if after.Phase != "ready" {
		// Stopped from elsewhere: its work stays in it until a pull, which
		// starts it to read it.
		a.println(s.summaryLine(after, nil))
		s.printHookReach(after, endedElsewhere)
		s.printNotices()
		a.note("its work stays in the sandbox: `" + CommandName + " pull " + after.Name + "` reads it")
		s.keepUnpulled()
		return s.finish(ctx, true)
	}
	// A harness that failed at start did no work, but it may have written
	// before it failed and an earlier session may have left work unpulled:
	// the pull still runs, without its progress line, which would stand
	// between the harness's output and the summary that points at it.
	pull, err := a.pull(ctx, s.api, s.cli, after, !s.failedAtStart(after, endedElsewhere))
	if err != nil {
		a.println(s.summaryLine(after, nil))
		s.printHookReach(after, endedElsewhere)
		s.printNotices()
		if killedByInterrupt(err) {
			// The Ctrl-C reached the git the pull runs (GAP-0221): not a
			// bundle that does not apply.
			s.interrupted = true
			a.warn("interrupted: nothing was brought back, and the work is still in the sandbox")
		} else {
			a.warn("could not pull the sandbox's changes: " + err.Error())
			s.diskFull = a.ownDiskFull(ctx, s.api, err) != ""
		}
		if !s.diskFull {
			a.note("retry with `" + CommandName + " pull " + after.Name + "`; the sandbox is kept")
		}
		s.keepUnpulled()
		return s.finish(ctx, false)
	}
	s.pulled, s.handedOver = pull.Result, pull.HandedOver()
	rev := &sandboxapi.ReviewResponse{Summary: pullSummary(pull), RiskLine: riskLine(&pull.Review)}
	a.println(s.summaryLine(after, rev))
	s.printHookReach(after, endedElsewhere)
	s.printNotices()
	if rev.RiskLine != "" {
		a.println(a.style(rev.RiskLine, ansiYellow))
	}
	s.printAsks(after)
	a.printReviewDetail(&pull.Review)
	for _, b := range pull.Blocking {
		a.warn(b)
	}
	if pull.Empty() {
		if pull.Since != "" {
			a.note("nothing new since the last apply to " + a.tildePath(after.Project))
		} else {
			a.note("the sandbox changed nothing")
		}
		s.handedOver = true
		return s.finish(ctx, false)
	}
	mode := ""
	if a.IO.TTY && !s.yes {
		choices := []choice{{"a", "apply (3-way)"}}
		if pull.Kind != workspace.CopyPlain {
			// A plain folder has no branches to put the work on.
			choices = append(choices, choice{"b", "branch dc/" + after.Name})
		}
		choices = append(choices, choice{"p", "patch file"}, choice{"s", "skip"}, choice{"d", "show diff"})
		ans, err := a.choose("Bring the changes back?", choices, "a")
		for err == nil && ans == "d" {
			// Read the work before choosing, as a mounted project's end
			// offers (GAP-0207).
			if diff, derr := a.Workspace.Diff(ctx, a.dataDir(), after.Name); derr != nil {
				a.warn("diff: " + derr.Error())
			} else {
				a.page(diff)
			}
			ans, err = a.choose("Bring the changes back?", choices, "a")
		}
		switch {
		case errors.Is(err, errInterrupted):
			// Ctrl-C: nothing comes back; the changes wait in the sandbox.
			s.interrupted = true
			a.warn("interrupted: nothing was brought back")
		case err != nil:
			// No answer (an interrupt, the end of input): the changes stay
			// in the sandbox, which ends as a skip does.
			return errors.Join(err, s.keepInSandbox(ctx, after, pull))
		}
		mode = map[string]string{"a": "apply", "b": "branch", "p": "patch"}[ans]
	}
	if mode == "" {
		return s.keepInSandbox(ctx, after, pull)
	}
	// The same gate as `pull --apply`: changes that can run code on this
	// machine, or a critical secret the agent wrote (which no risk line
	// names), are brought back only when the user says so.
	sensitive := rev.RiskLine != "" || pull.Review.Sensitive()
	opts := PullOptions{Name: after.Name, AcceptSensitive: !sensitive}
	switch mode {
	case "apply":
		opts.Apply = true
	case "branch":
		opts.Branch = true
	case "patch":
		opts.PatchOut = after.Name + ".patch"
	}
	// A branch that holds this work already takes nothing new: nothing to
	// confirm; nor does a branch or a patch file, which change nothing that
	// runs until merged or applied (GAP-0262, GAP-0267).
	if sensitive && writesElsewhere(opts.applyMode(), &pull.Review) {
		a.note(elsewhereNote(opts.applyMode()))
		opts.AcceptSensitive, sensitive = true, false
	}
	if sensitive && !a.branchHolds(ctx, after, opts) {
		yes, err := a.ask(a.bringBackQuestion(&pull.Review), false, false)
		if err != nil {
			return errors.Join(err, s.keepInSandbox(ctx, after, pull))
		}
		opts.AcceptSensitive = yes
		if !yes {
			a.note(notBroughtBack(after.Name, pull.Kind))
			s.keepUnpulled()
			return s.finish(ctx, false)
		}
	} else if sensitive {
		opts.AcceptSensitive = true
	}
	if _, err := a.applyPull(ctx, s.api, after, pull, opts); err != nil {
		a.warn(err.Error())
		s.keepUnpulled()
	} else {
		s.handedOver = true
	}
	return s.finish(ctx, false)
}

// markStopped records, for a copy-mode sandbox this session's end stopped
// after its pull, what its copy held (markStoppedCopy): nothing left to
// bring back when the pull found nothing new or went to the folder, a
// branch or a patch, so `delete` of it stopped need not warn about work it
// cannot check; and that pull, which the next pull is made from. A sandbox
// that keeps running can still change, so it is not marked; nor is one
// another session may have changed since the pull (it attached while the
// apply question was open and has ended, or a hook came: pullBase), which
// a delete must still warn about and the next pull must read. It runs
// under the sandbox's exclusive gate (finish), stopped being what
// OpenShell's stop returned.
func (s *session) markStopped(stopped *sandboxapi.Sandbox) {
	if (s.pulled != "" || s.handedOver) && s.pullBase.unchanged(s.app, s.sb.Name, stopped) {
		s.app.markStoppedCopy(s.sb, s.handedOver, s.pulled)
	}
}

// pullSummary is a pull's "N files changed (+a −d)", said to start from
// the last apply when an earlier apply brought the rest back already.
func pullSummary(pull *workspace.PullResult) string {
	if pull.Since != "" {
		return pull.Review.SummaryLine() + " since the last apply"
	}
	return pull.Review.SummaryLine()
}

// keepInSandbox ends a copy-mode session whose changes stay in the sandbox
// for `pull` (a skip, no terminal to ask on, --yes, no answer): it says how
// many files changed and that nothing was applied, and the sandbox is
// stopped (a session that started it) and kept, --rm or not.
func (s *session) keepInSandbox(ctx context.Context, after *sandboxapi.Sandbox, pull *workspace.PullResult) error {
	n := 0
	if pull != nil {
		n = len(pull.Changes)
	}
	s.app.note(plural(int64(n), "file", "files") + " changed; nothing was applied: the changes are kept in the sandbox for `" +
		CommandName + " pull " + after.Name + " --apply` (or --branch or --patch-out FILE)")
	s.keepUnpulled()
	return s.finish(ctx, false)
}

// keepUnpulled keeps a copy-mode sandbox whose work was not brought back:
// with --rm, deleting it would delete that work too, so --rm is dropped,
// and said.
func (s *session) keepUnpulled() {
	if s.rm {
		s.notDeleted("its work was not brought back", "it is")
	}
	s.rm = false
}

// autoRmKeep is what keeps the sandbox of a headless run (App.headlessRm).
const autoRmKeep = "a one-prompt run's sandbox; --keep or openshell.keep_headless keeps it"

// notDeleted drops the session's rm, saying why the sandbox stays: a
// warning for --rm, which asked for the delete; for a headless run's
// sandbox (autoRm) the reason goes on the line that says it was kept.
func (s *session) notDeleted(why, until string) {
	if s.autoRm {
		s.keptWhy = why
	} else {
		s.app.warn(s.sb.Name + " is not deleted (--rm): " + why + "; delete it once " + until + ": `" + CommandName + " delete " + s.sb.Name + "`")
	}
	s.rm = false
}

// transport is copy mode's openshell CLI transport.
func (a *App) transport(cli openshell.CLI) *workspace.CLI {
	return &workspace.CLI{Binary: cli.Binary, Gateway: cli.Gateway, Workspace: cli.Workspace}
}
