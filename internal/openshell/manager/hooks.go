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
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// HookDecision is one hook verdict the gateway reached for a sandbox
// binding.
type HookDecision struct {
	BindingID   string
	SandboxName string
	// Connector is the binding's connector. It selects the harness's
	// tool-call hook events and how they pair (toolCallHooksByConnector);
	// empty means Claude Code's.
	Connector string
	// Event is the harness hook event (PreToolUse, ...).
	Event string
	Tool  string
	// ToolUseID is the harness's per-call ID (tool_use_id), which pairs a
	// call's pre-tool event with its post-tool event.
	ToolUseID string
	// SessionID and ToolInput are the call's session and tool input. They
	// name a call whose harness sends no per-call ID (Kiro CLI); ToolInput
	// is empty when the event carries no tool input.
	SessionID string
	ToolInput json.RawMessage
	// ResultStatus is the status a post-tool event reports (Amp's
	// tool.result: done, error or cancelled).
	ResultStatus string
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
	box := m.boxes[b.SandboxName]
	if box == nil || box.rec.BindingID != b.ID {
		m.mu.Unlock()
		return
	}
	restored := false
	switch route {
	case sandboxauth.RouteHook:
		box.hooks.lastHook = now
		box.hooks.requests++
		box.silentSince, box.silenceSent = time.Time{}, false
		restored = box.hookReachedLocked()
	case sandboxauth.RouteNotify:
		box.hooks.lastNotify = now
	case sandboxauth.RouteOTLP:
		// Not a sign of work for the reachability check: the Codex TUI
		// exports OTLP from its start, before the first prompt that fires
		// its hooks. A model call is (watch.go).
		box.hooks.lastOTLP = now
		box.activeAt = now
	}
	name := box.rec.Name
	m.mu.Unlock()
	if restored {
		m.publishHooksRestored(name)
	}
}

// ObserveHookDecision counts tool calls and blocked tool calls for the
// session summary, puts blocks on the activity feed, and correlates each
// tool call's pre-tool and post-tool events to detect hook tamper.
func (m *Manager) ObserveHookDecision(d HookDecision) {
	hooks := toolCallHooksFor(d.Connector)
	pre, result := hooks.classify(d.Event, d.ResultStatus)
	counted := isToolEvent(d.Event)
	if !pre && result == toolResultNone && !counted {
		return
	}
	var call toolCallRef
	if pre || result != toolResultNone {
		call = hooks.ref(d)
	}
	blocked := isBlockAction(d.Action)
	reason := displayReason(d.Reason)
	m.mu.Lock()
	b := m.boxes[d.SandboxName]
	if b == nil || b.rec.BindingID != d.BindingID {
		m.mu.Unlock()
		return
	}
	tamper := tamperNone
	switch {
	case pre:
		m.toolCalls.ObservePre(d.BindingID, call, blocked)
	case result != toolResultNone:
		tamper = m.toolCalls.ObserveResult(d.BindingID, call, result)
	}
	if counted {
		b.hooks.toolCalls++
		if blocked {
			b.hooks.toolBlocked++
			b.hooks.lastBlocked = truncate(firstNonEmpty(reason, d.Tool), 200)
		}
	}
	var alarm *tamperAlarm
	if tamper != tamperNone {
		alarm = m.noteTamperLocked(b, d, hooks, tamper)
	}
	m.mu.Unlock()
	if counted && blocked {
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
	if alarm != nil {
		m.raiseTamper(b, *alarm)
	}
}

// displayReason keeps a verdict reason fit for the session summary and the
// activity feed. The gateway gives sandbox verdicts a plain reason built
// from rule metadata; a reason still carrying a redaction placeholder
// explains nothing and is dropped.
func displayReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if strings.Contains(reason, "<redacted") {
		return ""
	}
	return reason
}

// isToolEvent reports whether a hook event is a harness's pre-tool call,
// which the session summary counts (every sandboxed harness's spelling).
func isToolEvent(event string) bool {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(event)) {
	case "pretooluse", "beforetooluse", "pretoolcall",
		// OpenCode's tool.execute.before and Amp's tool.call plugin events.
		"toolexecutebefore", "toolcall":
		return true
	}
	return false
}

func isBlockAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny", "denied":
		return true
	}
	return false
}

// tamperAlarm is one detected hook tamper, captured under Manager.mu.
type tamperAlarm struct {
	kind      tamperKind
	identity  audit.SandboxIdentity
	name      string
	bindingID string
	tool      string
	event     string
	toolUseID string
	// preHook names the harness's pre-tool hook (PreToolUse, preToolUse,
	// tool.execute.before, ...).
	preHook  string
	onTamper string
	// stop is set for the alarm that schedules the sandbox's stop; later
	// alarms of the same session only report.
	stop bool
}

// noteTamperLocked counts a tamper on the box and decides the response.
// Callers hold Manager.mu.
func (m *Manager) noteTamperLocked(b *box, d HookDecision, hooks toolCallHooks, kind tamperKind) *tamperAlarm {
	b.hooks.tampered++
	b.hooks.lastTamper = m.now()
	a := &tamperAlarm{
		kind: kind, identity: b.identity(), name: b.rec.Name, bindingID: d.BindingID,
		tool: hookLabel(d.Tool, 64), event: d.Event, preHook: hooks.preHookName(),
	}
	if hooks.keying == keyByID {
		a.toolUseID = hookLabel(d.ToolUseID, 64)
	}
	if b.eff != nil {
		a.onTamper = b.eff.HookOnTamper
	}
	return a
}

// raiseTamper reports a hook tamper as a HIGH hook_tamper finding and on
// the activity feed, and responds per the pack's hooks.on_tamper: stop
// stops the sandbox, alert leaves it running.
func (m *Manager) raiseTamper(b *box, a tamperAlarm) {
	if a.onTamper == "" {
		// A sandbox adopted after a restart has no resolved policy yet.
		if eff, err := m.resolveBox(b); err == nil {
			a.onTamper = eff.HookOnTamper
		}
	}
	stop := a.onTamper != packs.OnTamperAlert // an unknown response fails toward stopping
	if stop {
		m.mu.Lock()
		if b.rec.BindingID == a.bindingID && !b.tamperStop {
			b.tamperStop, a.stop = true, true
		}
		m.mu.Unlock()
	}

	tool := a.tool
	if tool == "" {
		tool = "a tool"
	}
	title := "A tool ran without a DefenseClaw verdict"
	what := fmt.Sprintf("%s ran in %s, but its %s hook never reached DefenseClaw.", tool, a.name, a.preHook)
	if a.kind == tamperDenied {
		title = "A tool DefenseClaw denied ran anyway"
		what = fmt.Sprintf("%s ran in %s although DefenseClaw denied its %s.", tool, a.name, a.preHook)
	}
	description := what + " The workload likely killed or bypassed its DefenseClaw hook, so this call was not judged."
	remediation := "DefenseClaw is stopping the sandbox (hooks.on_tamper: stop). Review the session's activity before you start it again."
	if !stop {
		remediation = "The sandbox keeps running (hooks.on_tamper: alert). Review the session's activity and stop the sandbox if you did not expect this."
	}
	evidence := "event=" + a.event
	if a.tool != "" {
		evidence += " tool=" + a.tool
	}
	if a.toolUseID != "" {
		evidence += " tool_use_id=" + a.toolUseID
	}
	now := m.now()
	if err := m.tel.RecordSandboxFinding(context.Background(), audit.SandboxFindingEvent{
		Sandbox: a.identity, Kind: audit.SandboxFindingHookTamper, Severity: "HIGH",
		Title: title, Description: description, Evidence: evidence, Remediation: remediation,
		TargetRef: a.name, Timestamp: now,
	}); err != nil {
		m.logf("hook tamper: record the finding for %s: %v", a.name, err)
	}

	msg := "⚠ hook tamper: " + tool + " ran without a DefenseClaw verdict"
	if a.kind == tamperDenied {
		msg = "⚠ hook tamper: " + tool + " ran although DefenseClaw denied it"
	}
	switch {
	case a.stop:
		msg += "; stopping the sandbox"
	case stop:
		msg += "; the sandbox is already stopping"
	default:
		msg += "; the sandbox keeps running (hooks.on_tamper: alert)"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: a.name, Tool: a.tool,
		Event: a.event, Severity: "HIGH", Reason: string(audit.SandboxFindingHookTamper), Message: msg})

	if a.stop {
		m.tamperStops.Add(1)
		go func() {
			defer m.tamperStops.Done()
			m.stopForTamper(a.name, a.bindingID)
		}()
	}
}

// stopForTamper stops a sandbox whose hooks were tampered with, unless the
// session that tampered is already over.
func (m *Manager) stopForTamper(name, bindingID string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOpTimeout)
	defer cancel()
	b, unlock, err := m.lockBox(name)
	if err != nil {
		m.logf("hook tamper: stop %s: %v", name, err)
		return
	}
	defer unlock()
	m.mu.Lock()
	current := b.rec.BindingID == bindingID && b.phase == audit.SandboxPhaseReady
	m.mu.Unlock()
	if !current {
		return
	}
	if err := m.stop(ctx, b); err != nil {
		m.logf("hook tamper: stop %s: %v", name, err)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: "HIGH",
			Reason: string(audit.SandboxFindingHookTamper), Message: "⚠ DefenseClaw could not stop the tampered sandbox: stop it yourself"})
		return
	}
	m.logf("hook tamper: stopped %s", name)
}

// pruneToolCalls drops the tool-call ledgers of bindings no sandbox holds
// any more (a revoke already drops its own; this catches a decision that
// raced one).
func (m *Manager) pruneToolCalls() {
	m.mu.Lock()
	live := make(map[string]bool, len(m.boxes))
	for _, b := range m.boxes {
		if !b.deleted && b.rec.BindingID != "" {
			live[b.rec.BindingID] = true
		}
	}
	m.mu.Unlock()
	m.toolCalls.Retain(func(id string) bool { return live[id] })
}

// hookLabel keeps a workload-supplied label (a tool name or tool-use ID)
// fit for a finding and the feed: printable, without spaces, bounded.
func hookLabel(s string, limit int) string {
	s = strings.TrimSpace(s)
	var out strings.Builder
	for _, r := range s {
		if out.Len() >= limit {
			break
		}
		if unicode.IsPrint(r) && !unicode.IsSpace(r) && r != '"' && r != '\\' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// checkHookSilence raises a hook_silence finding for a ready sandbox whose
// harness was active (OCSF process or network events of the harness's own
// binaries, egress, native OTLP) more than HookSilence after its last hook
// request, or after it became
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
