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
// overdue. Both harnesses post SessionStart as they start and
// UserPromptSubmit before their first model turn.
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

// notice prints one line while the harness owns the terminal: on stderr,
// in column 0, is all that is safe.
func (s *session) notice(msg string) {
	fmt.Fprintf(s.app.IO.Err, "\r\n[defenseclaw] %s\r\n", msg)
}

// warnHooksOnce prints the session's first live warning about its hooks:
// the daemon's feed line, or the run's own once the first hook is overdue.
func (s *session) warnHooksOnce(msg string) {
	s.hooksMu.Lock()
	warned := s.hooksWarned
	s.hooksWarned = true
	s.hooksMu.Unlock()
	if !warned {
		s.notice(msg)
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
	if err != nil || s.hooksReached(sb) {
		return
	}
	s.warnHooksOnce("⚠ " + hooksWarningText(firstNonEmpty(sb.Hooks.UnreachableReason,
		"not one hook request reached DefenseClaw in the session's first "+window.Round(time.Second).String())))
}

// hooksReached reports whether at least one hook of the session reached
// DefenseClaw by the time after was read.
func (s *session) hooksReached(after *sandboxapi.Sandbox) bool {
	before := s.before
	if before == nil {
		before = s.sb
	}
	return after.Hooks.HookRequests > before.Hooks.HookRequests
}

// printHookReach ends the summary of a session none of whose hooks reached
// DefenseClaw with the warning, and marks the session for its exit status.
func (s *session) printHookReach(after *sandboxapi.Sandbox) {
	if s.hooksReached(after) {
		return
	}
	s.noHooks = true
	a := s.app
	reason := firstNonEmpty(after.Hooks.UnreachableReason, "not one hook request of this session reached DefenseClaw")
	a.println(a.style("✗ "+hooksWarningText(reason), ansiRed, ansiBold))
}

// exit is the status of a finished session: the harness's own, else
// ExitHooksUnreachable when its hooks never reached DefenseClaw.
func (s *session) exit(code int) error {
	switch {
	case code != 0:
		return &ExitError{Code: code}
	case s.noHooks:
		return errNoHooks()
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
