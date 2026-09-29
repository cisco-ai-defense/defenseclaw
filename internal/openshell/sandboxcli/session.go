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
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

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

	// shell marks a `connect --shell` session: no harness, so no hooks to
	// expect.
	shell bool
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
	// pulled is the result of the pull a copy-mode session's end took, and
	// handedOver is set once nothing of it is left to bring back: finish
	// records both for a sandbox it stops (markStoppedCopy).
	pulled     string
	handedOver bool

	// hooksWarned is set once the live warning that the session's hooks do
	// not reach DefenseClaw went out (hooks.go); noHooks once the session
	// ended without one of them getting through. sawHooks is set when the
	// session saw one of its hooks reach DefenseClaw (a verdict on the feed,
	// a read of its counters), which a daemon restart cannot take back.
	hooksMu     sync.Mutex
	hooksWarned bool
	noHooks     bool
	sawHooks    atomic.Bool
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
	// (blockNotice), which the summary counts.
	blockedHosts map[string]bool
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
	release := s.app.holdSession(s.sb.Name)
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
	code, err := s.app.Terminal.Run(ctx, inv)
	s.harnessCode = code
	return code, err
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
	release := s.app.holdSession(s.sb.Name)
	defer release()
	s.app.forgetStoppedCopy(s.sb.Name)
	stop := s.beginSession(ctx)
	defer stop()
	inv, err := s.cli.Exec(s.sb.Name, loginShell, openshell.CLIExecOptions{TTY: true, WorkDir: s.sb.Workdir})
	if err != nil {
		return -1, err
	}
	return s.app.Terminal.Run(ctx, inv)
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
	"kiro": true, "hermes": true, "antigravity": true, "openhands": true, "omnigent": true, "copilot": true,
}

// watchNotices follows the sandbox during the session and announces what
// must not wait until the end: an ask waiting for the user, a blocked
// destination, a finding (an alert, hook tamper), a quarantined nested
// repository, a DefenseClaw daemon that does not answer, and hooks that
// do not reach DefenseClaw (the daemon's verdict, or no hook by the end of
// the hook window).
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
	case sandboxapi.ActivityToolBlocked, sandboxapi.ActivityHookFailed:
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
		return ev.Host + ":" + strconv.Itoa(ev.Port)
	}
	return ev.Host
}

// askText is an ask of sandbox name for the live notice: the destination
// (and the binary asking, when known), why it is an ask, and where it is
// answered (the harness owns this terminal).
func askText(name string, ev sandboxapi.ActivityEvent, binary string) string {
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
	return msg + " → in another terminal: " + CommandName + " approve " + name + id + " (or reject), or in `defenseclaw tui`: 7 Sandboxes, then t for Asks"
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
	s.notice("ask "+ev.ApprovalID, askText(s.sb.Name, ev, binary), "? asked to reach "+what)
}

// blockNotice announces a destination DefenseClaw blocked, once per host,
// with the command that lifts the block when one does. What the harness
// fetches on its own and does without (a startup tip) is not announced.
func (s *session) blockNotice(ev sandboxapi.ActivityEvent) {
	if ev.Host == "" || ev.Reason == harnessFetchReason {
		return
	}
	text := "✗ DefenseClaw blocked " + hostPort(ev)
	if why := firstNonEmpty(ev.Category, ev.Reason); why != "" {
		text += " (" + reasonText(why) + ")"
	}
	if ev.Unblockable {
		text += " → unblock: " + CommandName + " unblock " + ev.Host + " --sandbox " + s.sb.Name
	}
	s.noticeMu.Lock()
	if s.blockedHosts == nil {
		s.blockedHosts = map[string]bool{}
	}
	if len(s.blockedHosts) < maxSeenEvents {
		s.blockedHosts[strings.ToLower(ev.Host)] = true
	}
	s.noticeMu.Unlock()
	s.notice("block "+ev.Host, text, text)
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
  nohup sh -c "$runner" sh "$d/latest.exit" "$@" >"$log" 2>&1 </dev/null &
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
	after, err := s.settled(ctx)
	if sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		a.println()
		a.warn(s.sb.Name + " was deleted from outside this session, which ended " + s.harnessName() + "; there is nothing left to review")
		return nil
	}
	if err != nil {
		return apiError(err)
	}
	a.println()
	elsewhere := s.endedElsewhere(after)
	if elsewhere != "" {
		a.warn(elsewhere)
	}
	// While the sandbox still runs: the review may stop it.
	s.diagnoseStart(ctx, after, elsewhere != "")
	if !s.started && after.Phase == "ready" {
		// The sandbox was running before the session: a detached run may
		// still be going in it.
		if run, err := a.detachedRun(ctx, s.cli, after); err == nil && run.State == runRunning {
			s.liveRun = true
		}
	}
	// Another session's harness or shell still running in the sandbox keeps
	// it running (this session's lease went with its harness).
	s.others = a.attachedSessions(s.sb.Name)
	if after.WorkdirMode == config.OpenShellWorkdirCopy {
		return s.endCopy(ctx, after, elsewhere != "")
	}
	// What the agent left running keeps writing to the mounted folder: a
	// sandbox the session owns stops before the review, so the review, the
	// keep/undo answer and the undo point cover everything it changed.
	stopped := false
	switch {
	case after.Phase != "ready":
		// Stopped from elsewhere: nothing runs in it any more.
		stopped = true
	case s.others > 0:
		a.note(s.sb.Name + " keeps running: " + s.othersText() + ", so what changes after this review is not in it")
	case s.started && !s.liveRun:
		if sb, err := s.api.Stop(ctx, s.sb.Name); err != nil {
			a.warn("could not stop " + s.sb.Name + " before reviewing its changes (" + apiError(err).Error() +
				"); what still runs in it can change the folder after this review")
		} else {
			stopped = true
			if sb != nil {
				after = sb
			}
		}
	case !s.liveRun:
		a.note(s.sb.Name + " is still running (it was running when you connected); changes it makes after this point are not in this review")
	}
	rev, err := s.api.Review(ctx, s.sb.Name, sandboxapi.ReviewRequest{})
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
	switch {
	case decision == "u":
		wasRunning := after.Phase == "ready"
		res, err := s.api.Undo(ctx, s.sb.Name, sandboxapi.UndoRequest{Stop: true})
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
		s.keepSnapshot = false
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
		// one. Changes nobody could review never become the base.
		a.acceptUndoPoint(after)
		a.ok("kept: the changes stay in the folder, and the next session takes a new undo point")
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
	if after.Phase != "ready" {
		return name + " was stopped from outside this session (`" + CommandName + " stop` or the TUI), which ended " + s.harnessName()
	}
	return ""
}

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

// finish stops (or with --rm deletes) the sandbox after a session. A
// sandbox the session did not start, whose detached run is still going, or
// that other sessions are attached to keeps running.
func (s *session) finish(ctx context.Context, stopped bool) error {
	a := s.app
	name := s.sb.Name
	switch {
	case s.rm && s.liveRun:
		s.notDeleted("its detached run is still going", "the run ends")
	case s.rm && s.others > 0:
		s.notDeleted(s.othersText(), "they end")
	}
	if s.rm {
		if _, err := s.api.Delete(ctx, name, sandboxapi.DeleteRequest{KeepSnapshot: s.keepSnapshot}); err != nil {
			if !s.autoRm {
				return fmt.Errorf("delete %s: %w", name, apiError(err))
			}
			// Nobody asked for this delete: the run still succeeded, and
			// the sandbox is kept as without it.
			s.rm, s.keptWhy = false, "it could not be deleted ("+apiError(err).Error()+")"
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
		case s.liveRun:
			a.note("Sandbox " + name + " keeps running: its detached run is still going → follow: " + CommandName + " logs " + name + " -f   stop: " +
				CommandName + " stop " + name)
			return nil
		case s.others > 0:
			a.note("Sandbox " + name + " keeps running: " + s.othersText() + " → stop it once they end: " + CommandName + " stop " + name)
			return nil
		case !s.started:
			a.note("Sandbox " + name + " keeps running (it was running when you connected) → stop: " + CommandName + " stop " + name)
			s.continueHint()
			return nil
		}
		if _, err := s.api.Stop(ctx, name); err != nil {
			a.warn("could not stop " + name + ": " + apiError(err).Error())
			return nil
		}
		s.markStopped()
	}
	next := "resume: " + CommandName + " connect " + name
	if s.headless {
		next += " --prompt TEXT"
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
	"openhands":  "--resume --last",
	// OmniGent's run --continue picks the sandbox agent's latest
	// conversation.
	"omnigent": "--continue",
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
	"copilot":    "copilot --resume",
	"kiro":       "kiro-cli --resume-id",
	"hermes":     "hermes --resume",
	"openhands":  "openhands --resume",
	"omnigent":   "omnigent run",
	// agy: "Resume with -c (or command below): agy --conversation=<id>".
	"antigravity": "agy --conversation",
}

// continueHint names, last and not dimmed, the command that continues this
// conversation inside the sandbox (a plain connect starts a new one), and
// what the harness's own resume hint does: the one it printed above after
// a session with a turn, else one it may print.
func (s *session) continueHint() {
	if s.headless || s.shell || s.spec == nil || !s.sawHooks.Load() {
		// No conversation to continue: no hook of the session reached
		// DefenseClaw (a harness that failed to start, one nobody
		// prompted).
		return
	}
	args, ok := continueArgs[s.spec.Name]
	if !ok {
		return
	}
	a := s.app
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
		if err != nil {
			break
		}
		same := next.Egress.Destinations == after.Egress.Destinations && next.Egress.Blocked == after.Egress.Blocked &&
			next.Egress.BlockedRequests == after.Egress.BlockedRequests &&
			next.Hooks.ToolCalls == after.Hooks.ToolCalls && next.Hooks.ToolBlocked == after.Hooks.ToolBlocked &&
			next.Hooks.HookFailed == after.Hooks.HookFailed
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
// denial, or a flood the feed paced). A daemon restart during the session
// starts its counters from zero: the session's then count from zero too.
func (s *session) summaryLine(after *sandboxapi.Sandbox, rev *sandboxapi.ReviewResponse) string {
	before := s.before
	if before == nil {
		before = &sandboxapi.Sandbox{}
	}
	hooksBefore, egressBefore := before.Hooks, before.Egress
	restarted := false
	if after.Hooks.HookRequests < hooksBefore.HookRequests || after.Hooks.ToolCalls < hooksBefore.ToolCalls {
		hooksBefore, restarted = sandboxapi.HookCoverage{}, true
	}
	if after.Egress.Destinations < egressBefore.Destinations || after.Egress.Blocked < egressBefore.Blocked ||
		after.Egress.BlockedRequests < egressBefore.BlockedRequests {
		egressBefore = sandboxapi.EgressStats{}
	}
	calls := after.Hooks.ToolCalls - hooksBefore.ToolCalls
	blocked := after.Hooks.ToolBlocked - hooksBefore.ToolBlocked
	s.hadTurn = calls > 0
	parts := []string{"Session ended"}
	tools := plural(max(calls, 0), "tool call", "tool calls")
	if restarted {
		tools += " since the daemon restarted"
	}
	if blocked > 0 {
		tools += fmt.Sprintf(" (%d blocked", blocked)
		if after.Hooks.LastBlocked != "" {
			tools += ": " + blockedReason(after.Hooks.LastBlocked)
		}
		tools += ")"
	}
	parts = append(parts, tools)
	// A hook call DefenseClaw answered with an error failed closed: the
	// harness's action was blocked without a verdict.
	if failed := after.Hooks.HookFailed - hooksBefore.HookFailed; failed > 0 {
		parts = append(parts, plural(failed, "hook call", "hook calls")+" failed (blocked)")
	}
	sites := after.Egress.Destinations - egressBefore.Destinations
	parts = append(parts, plural(int64(max(sites, 0)), "new site contacted", "new sites contacted"))
	s.noticeMu.Lock()
	sitesBlocked := max(len(s.blockedHosts), after.Egress.Blocked-egressBefore.Blocked)
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

// blockedReason is a blocked tool call's reason as the summary names it:
// the deciding rule's title and ID ("E2E sandbox marker command
// (E2E-SANDBOX-MARKER)"), taken from the reason DefenseClaw gave the
// harness ("Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox
// marker command. Try another approach…"), or the reason cut short.
func blockedReason(reason string) string {
	r := strings.TrimSpace(reason)
	for _, verb := range []string{"Blocked by ", "Held for approval by ", "Flagged by "} {
		rest, ok := strings.CutPrefix(r, verb+"DefenseClaw rule ")
		if !ok {
			if strings.HasPrefix(r, verb+"DefenseClaw policy.") {
				return "DefenseClaw policy"
			}
			continue
		}
		end := len(rest)
		for _, sep := range []string{":", " (", ". "} {
			if i := strings.Index(rest, sep); i >= 0 && i < end {
				end = i
			}
		}
		id := strings.TrimSuffix(rest[:end], ".")
		title := ""
		if strings.HasPrefix(rest[end:], ":") {
			title = strings.TrimSpace(rest[end+1:])
			for _, sep := range []string{" (also ", ". "} {
				if i := strings.Index(title, sep); i >= 0 {
					title = title[:i]
				}
			}
			title = strings.TrimSuffix(title, ".")
		}
		if title == "" {
			return truncate(id, 60)
		}
		return truncate(title, 60) + " (" + id + ")"
	}
	return truncate(r, 60)
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
		a.warn("could not pull the sandbox's changes: " + err.Error())
		a.note("retry with `" + CommandName + " pull " + after.Name + "`; the sandbox is kept")
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
		choices = append(choices, choice{"p", "patch file"}, choice{"s", "skip"})
		ans, err := a.choose("Bring the changes back?", choices, "a")
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
	// confirm.
	if sensitive && !a.branchHolds(ctx, after, opts) {
		yes, err := a.ask(a.bringBackQuestion(&pull.Review), false, false)
		if err != nil {
			return errors.Join(err, s.keepInSandbox(ctx, after, pull))
		}
		opts.AcceptSensitive = yes
		if !yes {
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
// that keeps running can still change, so it is not marked.
func (s *session) markStopped() {
	if s.pulled != "" || s.handedOver {
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
