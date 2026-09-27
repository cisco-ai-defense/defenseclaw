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

package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Hook reachability. Sandbox hooks fail closed: a session whose hooks never
// reach the ingress can do nothing, yet from the outside it looks like a
// quiet, healthy run. The manager watches each session (the time since the
// sandbox last became ready) for the signs of it:
//
//   - OpenShell refused a connection or request to the ingress: the
//     sandbox's policy does not allow DefenseClaw's port, as when another
//     daemon replaced the ingress provider profile. This is reported at
//     once, also after hooks that did get through.
//   - OpenShell let a hook connect to the ingress, but no authenticated
//     request (hook, OTLP or notify) followed within hookAttemptGrace: the
//     ingress does not answer, or the sandbox token never reached the hook.
//     A connection OpenShell closed on a policy reload counts as an attempt.
//   - The harness worked (a model call, egress) for HookReachWindow
//     without a single authenticated hook. OTLP is no sign of work: the
//     Codex TUI exports it from its start and fires its hooks only with the
//     first prompt.
//
// A session is flagged once; an authenticated hook clears the flag.

const (
	// DefaultHookReachWindow is how long a session's harness may work
	// before its first authenticated hook is overdue. Both harnesses post
	// SessionStart and UserPromptSubmit before their first model turn, so
	// the window only absorbs slow starts.
	DefaultHookReachWindow = 30 * time.Second
	// hookAttemptGrace is how long an ingress connection OpenShell reported
	// may go without an authenticated request.
	hookAttemptGrace = 15 * time.Second
	// hookReachInterval paces the reachability check.
	hookReachInterval = 5 * time.Second
)

// hookReach is one session's reachability state. Times are the manager's
// clock when it observed the event, so they compare with hooks.lastHook.
// Guarded by Manager.mu.
type hookReach struct {
	// firstWork is the session's first sign of harness work; firstAttempt
	// the first hook connection OpenShell reported.
	firstWork    time.Time
	firstAttempt time.Time
	// since and reason are set while the hooks do not reach DefenseClaw.
	since  time.Time
	reason string
	// warned is set once the session's warning went out.
	warned bool
}

// sessionOn reports whether b is in a session the reachability check
// covers. Callers hold Manager.mu.
func (b *box) sessionOn() bool {
	return !b.deleted && !b.creating && b.phase == audit.SandboxPhaseReady && !b.started.IsZero()
}

// noteWorkLocked records a sign of harness work at the manager's clock.
// Callers hold Manager.mu.
func (m *Manager) noteWorkLocked(b *box) {
	if b.sessionOn() && b.reach.firstWork.IsZero() {
		b.reach.firstWork = m.now()
	}
}

// observeHookConnection records OpenShell's view of one connection or
// request from the sandbox to the ingress, made at at; refused ones are
// reported at once. A record from before the session (replayed after a
// watch resumed) only counts.
func (m *Manager) observeHookConnection(ctx context.Context, b *box, refused bool, at time.Time) {
	now := m.now()
	m.mu.Lock()
	current := b.sessionOn() && !at.Before(b.started)
	if current && b.reach.firstAttempt.IsZero() {
		b.reach.firstAttempt = now
	}
	if refused {
		b.hooks.ingressRefused++
		if current {
			b.hooks.lastIngressRefused = now
		}
	}
	m.mu.Unlock()
	if refused && current {
		m.checkReach(ctx, b)
	}
}

// unreachableLocked returns why b's session hooks do not reach DefenseClaw,
// or "" when they do or nothing shows otherwise. Callers hold Manager.mu.
func (m *Manager) unreachableLocked(b *box, now time.Time) string {
	inSession := func(t time.Time) bool { return !t.IsZero() && !t.Before(b.started) }
	reached := inSession(b.hooks.lastHook)
	refused := inSession(b.hooks.lastIngressRefused) && (!reached || b.hooks.lastIngressRefused.After(b.hooks.lastHook))
	// An authenticated OTLP or notify request proves the ingress answers
	// and the sandbox token arrives: the connections OpenShell reported may
	// be the harness's telemetry (the Codex TUI exports from its start and
	// fires its first hooks only with the first prompt).
	authenticated := inSession(b.hooks.lastOTLP) || inSession(b.hooks.lastNotify)
	switch {
	case refused:
		return fmt.Sprintf("OpenShell refused the hooks' connections to the DefenseClaw ingress (%s:%d): the sandbox's network policy "+
			"does not allow it, as when another DefenseClaw daemon on this machine replaced the ingress provider profile",
			openshellHostAlias, m.opts.IngressPort)
	case reached:
		return ""
	case !authenticated && !b.reach.firstAttempt.IsZero() && now.Sub(b.reach.firstAttempt) >= hookAttemptGrace:
		return fmt.Sprintf("the hooks connect to the DefenseClaw ingress (port %d), but not one request authenticated: "+
			"the ingress does not answer, or the sandbox token did not reach the hook", m.opts.IngressPort)
	case !b.reach.firstWork.IsZero() && now.Sub(b.reach.firstWork) >= m.opts.HookReachWindow:
		return fmt.Sprintf("the harness has been working for %s without a single hook request reaching DefenseClaw",
			now.Sub(b.reach.firstWork).Round(time.Second))
	}
	return ""
}

// checkHookReach runs the reachability check of every session.
func (m *Manager) checkHookReach(ctx context.Context) {
	m.mu.Lock()
	boxes := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		boxes = append(boxes, b)
	}
	m.mu.Unlock()
	for _, b := range boxes {
		m.checkReach(ctx, b)
	}
}

// checkReach flags b's session when its hooks do not reach DefenseClaw
// and warns once: on the activity feed and as a HIGH hook_silence
// finding.
func (m *Manager) checkReach(ctx context.Context, b *box) {
	now := m.now()
	m.mu.Lock()
	if !b.sessionOn() || !b.reach.since.IsZero() {
		m.mu.Unlock()
		return
	}
	reason := m.unreachableLocked(b, now)
	if reason == "" {
		m.mu.Unlock()
		return
	}
	b.reach.since, b.reach.reason = now, reason
	warn := !b.reach.warned
	b.reach.warned = true
	id, name := b.identity(), b.rec.Name
	m.mu.Unlock()
	if !warn {
		return
	}
	m.logf("%s: %s (%s)", name, sandboxapi.HooksUnreachableWarning, reason)
	if err := m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
		Sandbox: id, Kind: audit.SandboxFindingHookSilence, Severity: "HIGH",
		Title:       "Sandbox hooks are not reaching DefenseClaw",
		Description: truncate(name+": "+reason+". The hooks fail closed, so every tool call of the session is blocked.", 1024),
		Remediation: "Run `defenseclaw sandbox doctor`, fix what it reports, then start the session again.",
		TargetRef:   name, Timestamp: now,
	}); err != nil {
		m.logf("hook reachability: record the finding for %s: %v", name, err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: "HIGH",
		Reason: sandboxapi.ReasonHooksUnreachable, Message: hooksUnreachableMessage(reason)})
}

// hooksUnreachableMessage is the feed line of an unreachable session.
func hooksUnreachableMessage(reason string) string {
	return "⚠ " + sandboxapi.HooksUnreachableWarning + " (" + reason + "). " + sandboxapi.HooksDoctorHint
}

// hookReachedLocked clears b's unreachable flag after an authenticated
// hook and reports whether it was set. Callers hold Manager.mu.
func (b *box) hookReachedLocked() bool {
	if b.reach.since.IsZero() {
		return false
	}
	b.reach.since, b.reach.reason = time.Time{}, ""
	return true
}

// publishHooksRestored tells the feed that a flagged session's hooks reach
// DefenseClaw after all.
func (m *Manager) publishHooksRestored(name string) {
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: "INFO",
		Reason: sandboxapi.ReasonHooksRestored, Message: "DefenseClaw hooks reach the daemon again"})
}
