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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// HookDecision is one hook verdict the gateway reached for a sandbox
// binding.
type HookDecision struct {
	BindingID   string
	SandboxName string
	// Event is the harness hook event (PreToolUse, ...).
	Event string
	Tool  string
	// Action is the verdict (allow, block, alert, confirm).
	Action     string
	WouldBlock bool
	Severity   string
	Reason     string
}

// ObserveIngress records an authenticated ingress request, the hook-coverage
// signal. The gateway calls it on every admitted sandbox request.
func (m *Manager) ObserveIngress(b sandboxauth.Binding, route sandboxauth.Route) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	box := m.boxes[b.SandboxName]
	if box == nil || box.rec.BindingID != b.ID {
		return
	}
	switch route {
	case sandboxauth.RouteHook:
		box.hooks.lastHook = now
		box.hooks.requests++
		box.silentSince, box.silenceSent = time.Time{}, false
	case sandboxauth.RouteNotify:
		box.hooks.lastNotify = now
	case sandboxauth.RouteOTLP:
		box.hooks.lastOTLP = now
		box.activeAt = now
	}
}

// ObserveHookDecision counts tool calls and blocked tool calls for the
// session summary and puts blocks on the activity feed.
func (m *Manager) ObserveHookDecision(d HookDecision) {
	if !isToolEvent(d.Event) {
		return
	}
	blocked := isBlockAction(d.Action)
	m.mu.Lock()
	b := m.boxes[d.SandboxName]
	if b == nil || b.rec.BindingID != d.BindingID {
		m.mu.Unlock()
		return
	}
	reason := displayReason(d.Reason)
	b.hooks.toolCalls++
	if blocked {
		b.hooks.toolBlocked++
		b.hooks.lastBlocked = truncate(firstNonEmpty(reason, d.Tool), 200)
	}
	m.mu.Unlock()
	if blocked {
		msg := "✗ tool call blocked by DefenseClaw"
		if d.Tool != "" {
			msg = "✗ " + d.Tool + " blocked by DefenseClaw"
		}
		if reason != "" {
			msg += ": " + truncate(reason, 200)
		}
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityToolBlocked, Sandbox: d.SandboxName, Tool: d.Tool,
			Event: d.Event, Severity: d.Severity, Reason: truncate(reason, 300), Message: msg})
	}
}

// displayReason drops a verdict reason the gateway already redacted (it
// only carries a length and digest).
func displayReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if strings.HasPrefix(reason, "<redacted") {
		return ""
	}
	return reason
}

func isToolEvent(event string) bool {
	e := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(event))
	return e == "pretooluse" || e == "beforetooluse" || e == "pretoolcall"
}

func isBlockAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny", "denied":
		return true
	}
	return false
}

// checkHookSilence raises a hook_silence finding for a ready sandbox whose
// harness was active (OCSF process or network events, egress, native OTLP)
// more than HookSilence after its last hook request, or after it became
// ready when no hook ever arrived. A tampered or disabled hook
// registration looks exactly like that; user-tier connectors, whose hook
// config the agent can edit, rely on it.
func (m *Manager) checkHookSilence(ctx context.Context) {
	threshold := m.opts.HookSilence
	now := m.now()
	type finding struct {
		id    audit.SandboxIdentity
		name  string
		since time.Time
	}
	var out []finding
	m.mu.Lock()
	for _, b := range m.boxes {
		if b.deleted || b.creating || b.phase != audit.SandboxPhaseReady {
			continue
		}
		ref := b.started
		if b.hooks.lastHook.After(ref) {
			ref = b.hooks.lastHook
		}
		if ref.IsZero() || !b.activeAt.After(ref.Add(threshold)) {
			continue
		}
		if b.silentSince.IsZero() {
			b.silentSince = ref
		}
		if b.silenceSent {
			continue
		}
		b.silenceSent = true
		out = append(out, finding{id: b.identity(), name: b.rec.Name, since: ref})
	}
	m.mu.Unlock()
	for _, f := range out {
		quiet := now.Sub(f.since).Round(time.Minute)
		_ = m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
			Sandbox: f.id, Kind: audit.SandboxFindingHookSilence, Severity: "HIGH",
			Title:       "Sandboxed harness is active without DefenseClaw hook traffic",
			Description: fmt.Sprintf("%s has been doing work for %s without a single hook request reaching DefenseClaw.", f.name, quiet),
			Remediation: "Check the harness's hook configuration inside the sandbox; stop the sandbox if hooks were disabled.",
			TargetRef:   f.name, Timestamp: now,
		})
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: f.name, Severity: "HIGH",
			Reason: string(audit.SandboxFindingHookSilence), Message: "⚠ the harness is active but its hooks are silent"})
	}
}
