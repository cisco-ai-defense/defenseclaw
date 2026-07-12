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

package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func normalizeHookTelemetryLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func (a *APIServer) recordConnectorHookRejection(ctx context.Context, connectorName, eventType, reason string, bodyBytes int64) {
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	eventType = normalizeHookTelemetryLabel(eventType, "unknown")
	reason = normalizeHookTelemetryLabel(reason, "unknown")
	enrichConnectorHookTelemetrySpan(ctx, connectorName, eventType, "rejected", reason, "", "", false, "", 0)
	a.recordHookRejectionMetricsV8(ctx, connectorName, eventType, reason)
	if a.logger != nil {
		a.logConnectorHookAuditEnvelope(ctx, HookAuditEnvelope{
			Connector: connectorName,
			Event:     eventType,
			Result:    "rejected",
			Reason:    reason,
			BodyBytes: bodyBytes,
		})
	}
}

func (a *APIServer) logConnectorHookAudit(ctx context.Context, connectorName, eventType, details string) {
	if a.logger == nil {
		return
	}
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	eventType = normalizeHookTelemetryLabel(eventType, "unknown")
	if strings.TrimSpace(details) == "" {
		details = "result=ok"
	}
	_ = a.logger.LogActionCtx(ctx, string(audit.ActionConnectorHook), eventType,
		fmt.Sprintf("connector=%s %s", connectorName, details))
}

// logConnectorHookAuditEnvelope is the structured-audit entry point
// every connector hook handler should use once it has a fully-built
// HookAuditEnvelope.
//
// The audit row carries two representations of the same hook outcome:
//
//   - Event.Structured is the canonical machine-readable
//     defenseclaw.hook.v1 envelope for SQLite export and audit sinks.
//   - Details keeps the legacy "connector=… action=… raw_action=…"
//     key=value tail plus details_json= for backwards-compatible
//     operator greps and downstream parsers during migration.
//
// The Details JSON value is strconv.Quote'd so it can carry embedded
// commas and quotes without breaking the surrounding tail.
//
// stripLogInjectionRunes runs on every string field in both forms,
// per codeguard-0-logging: a hostile prompt that smuggles CR/LF/ANSI
// escapes cannot forge fake audit rows or corrupt the operator's
// terminal.
//
// Optional action override: when env.AuditActionOverride is set
// (today: ActionConnectorHookSynthetic for synthetic
// codex-notify-derived events), the override is used as the audit
// row's action column instead of the canonical
// ActionConnectorHook. Sinks that want to keep "1 row per
// codex.notify in" should filter on action=connector-hook only.
func (a *APIServer) logConnectorHookAuditEnvelope(ctx context.Context, env HookAuditEnvelope) {
	if a.logger == nil {
		return
	}
	env.Connector = normalizeHookTelemetryLabel(env.Connector, "unknown")
	env.Event = normalizeHookTelemetryLabel(env.Event, "unknown")
	if env.Result == "" {
		env.Result = "ok"
	}
	auditAction := string(audit.ActionConnectorHook)
	if env.AuditActionOverride != "" && audit.IsKnownAction(env.AuditActionOverride) {
		auditAction = env.AuditActionOverride
	}
	jsonDetails, structured := renderHookAuditEnvelopePayload(env)
	legacy := renderHookAuditLegacyDetails(env)
	combined := fmt.Sprintf("connector=%s %s details_json=%s",
		env.Connector, legacy, strconv.Quote(jsonDetails))
	_ = a.logger.LogEventCtx(ctx, audit.Event{
		Action:     auditAction,
		Target:     env.Event,
		Actor:      "defenseclaw",
		Details:    combined,
		Severity:   "INFO",
		Structured: structured,
		// Mirror the structured-envelope identity fields onto the
		// dedicated SQLite columns (migration 16) so the column data
		// and structured_json agree. env.Connector is already
		// normalized to "unknown" above when empty, keeping the column
		// and JSON aligned.
		Connector:   env.Connector,
		StepIdx:     env.StepIdx,
		Enforced:    env.Enforced,
		RulePackDir: env.RulePackDir,
		// Carry the cloud-controlled per-inspection redaction directive
		// (re-injected onto ctx before finalizeAgentHook) so the audit
		// sanitize + webhook fan-out honor it on the Details surface.
		RedactionEnabled: redactionDecisionFromContext(ctx),
	})
}

func (a *APIServer) logAssetPolicyAudit(ctx context.Context, connector, target, details string) {
	if a.logger == nil {
		return
	}
	// Stamp the connector onto the dedicated column (and let LogEventCtx
	// fill the rest of the correlation envelope) so asset-policy decisions
	// are filterable per connector — previously the connector lived only
	// inside the free-form details string and never reached Event.Connector.
	_ = a.logger.LogEventCtx(ctx, audit.Event{
		Action:    string(audit.ActionAssetPolicy),
		Target:    target,
		Details:   details,
		Connector: connector,
	})
}

// enrichConnectorHookIdentitySpan stamps the per-connector forensic identity
// (step_idx / enforced / rule_pack_dir) onto the active span. These mirror the
// dedicated SQLite columns and structured envelope. A zero step_idx (non-turn
// events) and empty rule_pack_dir are omitted to keep noise out of spans. Safe
// no-op when no recording span is on the context.
func enrichConnectorHookIdentitySpan(ctx context.Context, stepIdx int, enforced bool, rulePackDir string) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.Bool("defenseclaw.connector.enforced", enforced),
	}
	if stepIdx > 0 {
		attrs = append(attrs, attribute.Int("defenseclaw.connector.step_idx", stepIdx))
	}
	if rulePackDir = strings.TrimSpace(rulePackDir); rulePackDir != "" {
		attrs = append(attrs, attribute.String("defenseclaw.connector.rule_pack_dir", rulePackDir))
	}
	span.SetAttributes(attrs...)
}

func enrichConnectorHookTelemetrySpan(ctx context.Context, connectorName, eventType, result, reason, decision, rawAction string, wouldBlock bool, mode string, elapsed time.Duration) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	eventType = normalizeHookTelemetryLabel(eventType, "unknown")
	result = normalizeHookTelemetryLabel(result, "unknown")
	attrs := []attribute.KeyValue{
		attribute.String("defenseclaw.connector.source", connectorName),
		attribute.String("defenseclaw.connector.signal", "hook"),
		attribute.String("defenseclaw.connector.result", result),
		attribute.String("defenseclaw.hook.event", eventType),
	}
	if reason = strings.TrimSpace(reason); reason != "" {
		attrs = append(attrs, attribute.String("defenseclaw.hook.reason", reason))
	}
	if decision = strings.TrimSpace(decision); decision != "" {
		attrs = append(attrs, attribute.String("defenseclaw.decision", decision))
	}
	if rawAction = strings.TrimSpace(rawAction); rawAction != "" {
		attrs = append(attrs, attribute.String("defenseclaw.raw_action", rawAction))
	}
	if mode = strings.TrimSpace(mode); mode != "" {
		attrs = append(attrs, attribute.String("defenseclaw.mode", mode))
	}
	if elapsed > 0 {
		attrs = append(attrs, attribute.Int64("defenseclaw.duration_ms", elapsed.Milliseconds()))
	}
	attrs = append(attrs, attribute.Bool("defenseclaw.would_block", wouldBlock))
	span.SetAttributes(attrs...)
}

// maxStepIdxSessions bounds how many distinct sessions the per-turn
// step counter tracks at once. A local gateway sees a handful of live
// sessions; the cap exists only so a long-lived process replaying many
// short-lived session IDs cannot grow the map without limit. When the
// cap is hit a single (arbitrary) entry is evicted — the only
// consequence is that a long-idle session, if it ever resumes, restarts
// its step counter, which is benign.
const maxStepIdxSessions = 8192

// maxStepIdxTurnsPerSession bounds how many distinct TurnIDs a single
// session remembers for StepIdx de-duplication. maxStepIdxSessions caps
// the number of sessions, but on its own a single long-lived session
// that supplies a unique TurnID per turn would grow turnToStep without
// limit. Repeat hook events for a turn arrive while that turn is current,
// so only recent turns need retaining; when the cap is hit the oldest
// (lowest-step) turn is evicted. The only consequence is that a repeat
// event for a long-superseded turn restarts at a fresh index, which is
// benign (same trade-off as session eviction).
const maxStepIdxTurnsPerSession = 1024

// sessionStepState is the per-session turn bookkeeping behind StepIdx.
// step is the highest 1-indexed turn assigned so far; turnToStep maps a
// connector-supplied TurnID to the index it was assigned so repeated
// events in the same turn return the same value.
type sessionStepState struct {
	step       int
	turnToStep map[string]int
}

// evictOldestTurnLocked drops the lowest-step (oldest) TurnID from the
// session's turnToStep map to keep it bounded. Caller must hold
// stepIdxMu. Step values are assigned monotonically, so the smallest
// value is the oldest turn.
func (st *sessionStepState) evictOldestTurnLocked() {
	oldestTurn := ""
	oldestStep := 0
	first := true
	for turn, step := range st.turnToStep {
		if first || step < oldestStep {
			oldestTurn, oldestStep, first = turn, step, false
		}
	}
	if !first {
		delete(st.turnToStep, oldestTurn)
	}
}

// stepIndexForTurn returns the 1-indexed per-turn step counter for the
// given session. The contract (design §5.4 / checkpoint C3):
//
//   - A "turn" is one prompt-response cycle within a session_id. All
//     hook events emitted during the same turn share ONE StepIdx.
//   - Primary signal is TurnID: the first time a (session, turnID) is
//     seen the session counter increments and that turnID is pinned to
//     the new index; later events with the same turnID return it.
//   - When the connector supplies no TurnID, a prompt-class event opens
//     a new turn (increment); tool-call / tool-result events inherit
//     the current index. The first event in a session always yields 1.
//
// Returns 0 ("not turn-anchored") only when sessionID is empty.
// Concurrency-safe and bounded.
func (a *APIServer) stepIndexForTurn(sessionID, turnID, hookEvent string) int {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0
	}
	a.stepIdxMu.Lock()
	defer a.stepIdxMu.Unlock()
	if a.stepIdxBySession == nil {
		a.stepIdxBySession = make(map[string]*sessionStepState)
	}
	st := a.stepIdxBySession[sessionID]
	if st == nil {
		if len(a.stepIdxBySession) >= maxStepIdxSessions {
			a.evictOneStepSessionLocked()
		}
		st = &sessionStepState{turnToStep: make(map[string]int)}
		a.stepIdxBySession[sessionID] = st
	}
	if turnID = strings.TrimSpace(turnID); turnID != "" {
		if idx, ok := st.turnToStep[turnID]; ok {
			return idx
		}
		if len(st.turnToStep) >= maxStepIdxTurnsPerSession {
			st.evictOldestTurnLocked()
		}
		st.step++
		st.turnToStep[turnID] = st.step
		return st.step
	}
	// No TurnID: a prompt-class event starts a turn; the very first
	// event in the session also bootstraps to turn 1.
	if st.step == 0 || isPromptClassHookEvent(hookEvent) {
		st.step++
	}
	return st.step
}

// evictOneStepSessionLocked drops a single arbitrary tracked session.
// Caller must hold stepIdxMu. Go's randomized map iteration makes the
// victim effectively random, which is acceptable for a counter cache.
func (a *APIServer) evictOneStepSessionLocked() {
	for k := range a.stepIdxBySession {
		delete(a.stepIdxBySession, k)
		return
	}
}

// isPromptClassHookEvent reports whether a hook event name denotes the
// start of a prompt-response cycle (a user submitting a prompt). This is
// EVENT-class detection, not connector branching — the same names are
// matched regardless of which connector produced them. Used only as the
// turn-boundary fallback when a connector supplies no TurnID.
func isPromptClassHookEvent(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "userpromptsubmit", "user_prompt_submit", "userprompt", "prompt":
		return true
	default:
		return false
	}
}

// effectiveRulePackDir resolves the rule-pack directory for a connector
// via the per-connector > global resolver, nil-safe for bare test
// servers that never wired a config.
func (a *APIServer) effectiveRulePackDir(connector string) string {
	if a == nil || a.scannerCfg == nil {
		return ""
	}
	return a.scannerCfg.EffectiveRulePackDirForConnector(connector)
}

// stampHookEnvelopeIdentity fills the multi-connector identity fields on
// a HookAuditEnvelope before it is logged. Shared by the live hook path
// (finalizeAgentHook) and the synthetic codex-notify path so the two
// cannot drift. connectorName is threaded explicitly from the request
// entry point; StepIdx comes from the per-turn populator; Enforced
// reflects an actual block; RulePackDir from the effective resolver.
func (a *APIServer) stampHookEnvelopeIdentity(connectorName string, env *HookAuditEnvelope, req agentHookRequest, resp agentHookResponse) {
	if env == nil {
		return
	}
	if env.Connector == "" {
		env.Connector = connectorName
	}
	env.StepIdx = a.stepIndexForTurn(req.SessionID, req.TurnID, req.HookEventName)
	env.Enforced = resp.Action == "block"
	env.RulePackDir = a.effectiveRulePackDir(connectorName)
}
