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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Hook reachability of a session. Sandbox hooks fail closed, so a session
// whose hooks never reach DefenseClaw blocks every tool call while the
// harness itself may exit cleanly. The run says so three times: live, as
// soon as the daemon flags the session or the session's first hook is
// overdue (HookWindow); in the end-of-session summary; and through its exit
// status (ExitHooksUnreachable) when not one hook got through.

// DefaultHookWindow is how long a session may run before its first hook is
// overdue. Claude Code posts SessionStart as it starts; the Codex TUI posts
// it only with the first prompt, but exports OTLP from its start, which
// proves the path (telemetryReached).
const DefaultHookWindow = 45 * time.Second

// runHookSlack absorbs the difference between the sandbox's clock, which
// stamps a detached run's start, and the daemon's, which stamps hooks.
const runHookSlack = 2 * time.Second

func (a *App) hookWindow() time.Duration {
	if a.HookWindow > 0 {
		return a.HookWindow
	}
	return DefaultHookWindow
}

// hooksWarningText is the warning about hooks that do not reach
// DefenseClaw, with the likely cause and the doctor hint.
func hooksWarningText(reason string) string {
	msg := sandboxapi.HooksUnreachableWarning
	if reason = strings.TrimSpace(reason); reason != "" {
		msg += " (" + reason + ")"
	}
	return msg + ". " + sandboxapi.HooksDoctorHint
}

// errNoHooks is the exit of a session none of whose hooks reached
// DefenseClaw; the warning was printed already.
func errNoHooks() error {
	return &ExitError{Code: ExitHooksUnreachable, Err: &Silent{Err: errors.New("no DefenseClaw hook of the session reached the daemon")}}
}

// sessionNotice is one thing the session announced, as its line in the
// end-of-session summary.
type sessionNotice struct {
	summary string
	// host is the destination of a block the user can lift, and
	// unblocked its line once the session saw host unblocked
	// (session.unblockedHosts): the block, without the unblock command.
	host, unblocked string
}

// notice announces msg while the harness owns the terminal, once per key
// (an empty key: every time), and keeps summary ("" keeps nothing) for the
// end-of-session summary. A line written into a harness's TUI would
// corrupt it (it lands on the input box and stays after the redraw), so an
// interactive session shows the notice in the terminal's title and as a
// desktop notification (OSC 9, where the terminal has them) and rings the
// bell (a harness may take the title back at once), and the summary
// repeats it; a headless session prints a line on stderr.
func (s *session) notice(key, msg, summary string) {
	s.noticeWith(key, msg, sessionNotice{summary: summary})
}

// noticeWith is notice with the summary line n.
func (s *session) noticeWith(key, msg string, n sessionNotice) {
	summary := n.summary
	msg = sandboxapi.DisplayText(msg)
	tui := s.app.IO.TTY && !s.headless
	s.noticeMu.Lock()
	if key != "" {
		if s.noticeKeys == nil {
			s.noticeKeys = map[string]bool{}
		}
		if s.noticeKeys[key] {
			s.noticeMu.Unlock()
			return
		}
		s.noticeKeys[key] = true
	}
	if summary != "" {
		s.notices = append(s.notices, n)
	}
	push := tui && !s.titleSet
	s.titleSet = s.titleSet || tui
	s.noticeMu.Unlock()
	if !tui {
		fmt.Fprintf(s.app.IO.Err, "\r\n[defenseclaw] %s\r\n", msg)
		return
	}
	var b strings.Builder
	if push {
		// Keep the title to restore at the end of the session.
		b.WriteString("\x1b[22;0t")
	}
	b.WriteString("\x1b]2;[defenseclaw] " + truncate(msg, 160) + "\a")
	b.WriteString("\x1b]9;DefenseClaw: " + msg + "\a")
	b.WriteString("\a")
	fmt.Fprint(s.app.IO.Err, b.String())
}

// restoreTitle puts back the terminal title the session's notices
// replaced.
func (s *session) restoreTitle() {
	s.noticeMu.Lock()
	set := s.titleSet
	s.titleSet = false
	s.noticeMu.Unlock()
	if set {
		fmt.Fprint(s.app.IO.Err, "\x1b[23;0t")
	}
}

// firstSight reports whether the session sees ev for the first time: a
// reconnect of the activity stream reads the daemon's buffer again (and a
// restarted daemon's feed reuses the numbers under another epoch).
func (s *session) firstSight(ev sandboxapi.ActivityEvent) bool {
	key := fmt.Sprintf("event %s %d %d %s %s %s %s %s", ev.Epoch, ev.Seq, ev.Time.UnixNano(), ev.Kind, ev.ApprovalID, ev.Host, ev.Reason, ev.Message)
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	if s.noticeKeys == nil {
		s.noticeKeys = map[string]bool{}
	}
	if s.noticeKeys[key] {
		return false
	}
	if len(s.noticeKeys) < maxSeenEvents {
		s.noticeKeys[key] = true
	}
	return true
}

// maxSeenEvents bounds what firstSight remembers.
const maxSeenEvents = 4096

// maxSummaryNotices is how many of the session's notices the summary
// repeats; the feed has them all.
const maxSummaryNotices = 6

// printNotices repeats, after the summary line, what the session announced
// while the harness owned the terminal.
func (s *session) printNotices() {
	s.noticeMu.Lock()
	list := make([]string, 0, len(s.notices))
	for _, n := range s.notices {
		line := n.summary
		if n.host != "" && s.unblockedHosts[n.host] {
			// Unblocked since: no command to offer (RT U6).
			line = n.unblocked
		}
		list = append(list, line)
	}
	s.noticeMu.Unlock()
	a := s.app
	for i, line := range list {
		if i == maxSummaryNotices {
			a.note(fmt.Sprintf("… %d more: %s activity --sandbox %s", len(list)-i, CommandName, s.sb.Name))
			break
		}
		style := ansiYellow
		if strings.HasPrefix(line, "✗") {
			style = ansiRed
		}
		a.line(a.style(line, style))
	}
}

// warnHooksOnce prints the session's first live warning about its hooks:
// the daemon's feed line, or the run's own once the first hook is overdue.
func (s *session) warnHooksOnce(msg string) {
	s.hooksMu.Lock()
	warned := s.hooksWarned
	s.hooksWarned = true
	s.hooksMu.Unlock()
	if !warned {
		s.notice("", msg, "")
	}
}

// checkHooksAfter warns when not one hook of the session reached
// DefenseClaw by the end of window (unless ctx ends first).
func (s *session) checkHooksAfter(ctx context.Context, window time.Duration) {
	t := time.NewTimer(window)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
	}
	sb, err := s.api.Get(ctx, s.sb.Name)
	if err != nil || s.hooksReached(sb) || s.telemetryReached(sb) {
		// A daemon that does not answer is announced by the activity
		// watch.
		return
	}
	if !sb.Hooks.Unreachable {
		// A daemon that restarted during the window and did not stop
		// cleanly lost its last minute of hook counts: no hook since then
		// says nothing of the hooks before (the summary says it cannot
		// tell).
		if st, err := s.api.Status(ctx); err == nil && s.startedBefore(st.StartedAt) {
			return
		}
	}
	s.warnHooksOnce("⚠ " + hooksWarningText(firstNonEmpty(sb.Hooks.UnreachableReason,
		"not one hook request reached DefenseClaw in the session's first "+window.Round(time.Second).String())))
}

// hooksReached reports whether at least one hook of the session reached
// DefenseClaw by the time after was read. A daemon that did not stop
// cleanly loses its last minute of hook counts, so the time of the last
// hook decides too, and what the session saw on its way.
func (s *session) hooksReached(after *sandboxapi.Sandbox) bool {
	if s.sawHooks.Load() {
		return true
	}
	before := s.before
	if before == nil {
		before = s.sb
	}
	reached := after.Hooks.HookRequests > before.Hooks.HookRequests || after.Hooks.LastHookAt.After(before.Hooks.LastHookAt)
	if reached {
		s.sawHooks.Store(true)
	}
	return reached
}

// hookReachUnknown reports that the daemon restarted during the session and
// has no verdict of its own on the session's hooks: a restart that was not
// clean loses the hook counts of its last minute, so a hook that reached
// the daemon before it may have left no trace, and DefenseClaw cannot tell
// whether one did (PR 1022, when no restart kept the counts: a
// Copilot CLI session of 7 allowed tool calls and a restart ended with "no
// hook of this session reached DefenseClaw"). A daemon that does not say
// when it started gives its restart away by hook counters below the
// session's start.
func (s *session) hookReachUnknown(after *sandboxapi.Sandbox) bool {
	if after.Hooks.Unreachable {
		return false
	}
	before := s.before
	if before == nil {
		before = s.sb
	}
	return s.restartedDuring() || after.Hooks.HookRequests < before.Hooks.HookRequests
}

// telemetryReached reports whether an authenticated OTLP request of the
// session reached DefenseClaw by the time after was read: the ingress
// answers and the sandbox token arrives, so a harness that fires its first
// hook only with the first prompt (the Codex TUI) is not overdue. The
// daemon still flags a session that works without hooks, and the run shows
// its feed line.
func (s *session) telemetryReached(after *sandboxapi.Sandbox) bool {
	before := s.before
	if before == nil {
		before = s.sb
	}
	return after.Hooks.LastOTLPAt.After(before.Hooks.LastOTLPAt)
}

// printHookReach ends the summary of a session none of whose hooks reached
// DefenseClaw with the warning, and marks the session for its exit status.
// A harness that failed before it fired one (it exited with an error, and
// the daemon saw nothing wrong with its hooks) is said to have failed; a
// shell fires none. A session whose authenticated telemetry got through
// proved the path, as the live check counts it, unless the daemon says
// otherwise.
//
// After a daemon restart during the session, with no verdict of the new
// daemon's, whether a hook reached DefenseClaw is unknown (hookReachUnknown):
// the session says so, and neither says its hooks did not reach it nor
// ends with ExitHooksUnreachable.
func (s *session) printHookReach(after *sandboxapi.Sandbox, endedElsewhere bool) {
	if s.shell || s.hooksReached(after) || (s.telemetryReached(after) && !after.Hooks.Unreachable) {
		return
	}
	a := s.app
	if s.hookReachUnknown(after) {
		s.hooksUnknown = true
		at := ""
		if s.restartedDuring() {
			at = " (at " + a.clock(s.daemonStarted) + ")"
		}
		a.note("the DefenseClaw daemon restarted during the session" + at + " and has counted no hook of it since, " +
			"so DefenseClaw cannot tell whether this session's hooks reached it")
		return
	}
	if code := s.harnessCode; code != 0 && !after.Hooks.Unreachable {
		if !endedElsewhere && code != exitInterrupted {
			why := "the harness itself failed (its output is above)"
			if s.startWhy != "" {
				why = s.startWhy
			}
			a.println(a.style(fmt.Sprintf("✗ %s exited with status %d before any of its hooks reached DefenseClaw: %s",
				s.harnessName(), code, why), ansiRed, ansiBold))
			if s.startDo != "" {
				a.line("→ " + s.startDo)
			}
		}
		return
	}
	if s.spec != nil && promptFirst[s.spec.Name] && !after.Hooks.Unreachable {
		// Its first hook comes with the first prompt, and the daemon saw
		// the harness do no work without one: a session nobody prompted.
		a.note("no hook of this session reached DefenseClaw: " + s.harnessName() + " sends its first one with your first prompt")
		return
	}
	s.noHooks = true
	reason := firstNonEmpty(after.Hooks.UnreachableReason, "not one hook request of this session reached DefenseClaw")
	a.println(a.style("✗ "+hooksWarningText(reason), ansiRed, ansiBold))
}

// exit is the status of a finished session: the harness's own, else
// ExitHooksUnreachable when its hooks never reached DefenseClaw, or the
// interrupt that ended its keep/undo question.
func (s *session) exit(code int) error {
	switch {
	case code != 0:
		return &ExitError{Code: code}
	case s.noHooks:
		return errNoHooks()
	case s.interrupted:
		return &ExitError{Code: exitInterrupted}
	}
	return nil
}

// runReachedHooks reports whether a hook reached DefenseClaw during a
// detached run that started at the epoch second started (0: unknown, when
// any hook of the sandbox counts).
func runReachedHooks(sb *sandboxapi.Sandbox, started int64) bool {
	if started <= 0 {
		return sb.Hooks.HookRequests > 0
	}
	at := sb.Hooks.LastHookAt
	return !at.IsZero() && !at.Before(time.Unix(started, 0).Add(-runHookSlack))
}
