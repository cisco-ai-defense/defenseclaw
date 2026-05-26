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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// fallbackConnectorRegistry is a process-singleton built on first
// use, exclusively for code paths that look up connector
// capabilities BEFORE APIServer.connectorRegistry is set (early
// init, tests that bypass NewAPIServer, plugin discovery probes).
//
// Why a singleton: NewDefaultRegistry registers ten builtin
// connectors and walks the plugin directory; on the hook hot path
// (every hookCapabilities call), constructing it per-invocation
// turns each block-vs-allow decision into ten allocations and a
// directory walk. The singleton amortises that to once per process.
//
// Thread-safety: sync.Once gives us a happens-before guarantee on
// the assignment, and Registry.Get is documented as concurrent-safe
// for read traffic. We never mutate the singleton after init —
// that's intentional, because the production path already builds a
// per-server registry in NewAPIServer; this is the legacy fallback.
var (
	fallbackConnectorRegistryOnce sync.Once
	fallbackConnectorRegistry     *connector.Registry
)

func getFallbackConnectorRegistry() *connector.Registry {
	fallbackConnectorRegistryOnce.Do(func() {
		fallbackConnectorRegistry = connector.NewDefaultRegistry()
	})
	return fallbackConnectorRegistry
}

type agentHookRequest struct {
	ConnectorName string
	AgentID       string
	AgentName     string
	AgentType     string
	HookEventName string
	SessionID     string
	TurnID        string
	CWD           string
	ToolName      string
	ToolArgs      json.RawMessage
	Content       string
	Direction     string
	Payload       map[string]interface{}
}

type agentHookResponse struct {
	Action            string                 `json:"action"`
	RawAction         string                 `json:"raw_action,omitempty"`
	Severity          string                 `json:"severity"`
	Reason            string                 `json:"reason,omitempty"`
	Findings          []string               `json:"findings,omitempty"`
	Mode              string                 `json:"mode"`
	WouldBlock        bool                   `json:"would_block"`
	AdditionalContext string                 `json:"additional_context,omitempty"`
	HookOutput        map[string]interface{} `json:"hook_output,omitempty"`
	// EvaluationID + RuleIDs join this hook response to the
	// matching scan_findings rows / audit row. Additive — older
	// connector hook scripts ignore the fields.
	EvaluationID string   `json:"evaluation_id,omitempty"`
	RuleIDs      []string `json:"rule_ids,omitempty"`
}

func (a *APIServer) handleAgentHook(connectorName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "method", 0)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, b, err := rawPayloadFromJSONDecoder(json.NewDecoder(r.Body))
		if err != nil {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "invalid_json", 0)
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		profile := a.hookProfileForConnector(connectorName)
		runtime := hookRuntimeForProfile(profile)
		req := normalizeAgentHookRequestWithProfile(connectorName, payload, profile)
		if req.HookEventName == "" {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "missing_event", int64(len(b)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook event name is required"})
			return
		}
		req.CWD = sanitizeHookCWD(req.CWD)
		ctx := enrichAgentHookContext(r.Context(), req)
		t0 := time.Now()
		// attemptedWrite covers BOTH "writeJSON returned successfully"
		// AND "writeJSON started writing and panicked partway". Once
		// the first writeJSON is invoked we must not retry it from the
		// defer: the response stream is in an indeterminate state and
		// a second invocation against a broken writer would just
		// re-panic (this time uncaught, since the defer is not itself
		// wrapped in another recover).
		attemptedWrite := false
		// finalized guards against a double-emit when the post-finalize
		// code (renderAgentHookResponseForProfile / writeJSON) panics.
		// Without this flag the deferred recover would re-run
		// finalizeAgentHook, doubling audit rows, hook-outcome metrics,
		// and the connector telemetry log for a single request.
		finalized := false
		var rawEventIDs []string
		defer func() {
			if recovered := recover(); recovered != nil {
				elapsed := time.Since(t0)
				resp := safeHookPanicResponse(connectorName, req.HookEventName, recovered)
				a.handleHookPanic(ctx, connectorName, req.HookEventName, recovered)
				enrichAgentHookSpan(ctx, req, resp, elapsed)
				enrichAgentHookSpanPanic(ctx)
				if !finalized {
					a.finalizeAgentHook(ctx, connectorName, req, resp, rawEventIDs, b, elapsed, true, nil)
					finalized = true
				}
				if !attemptedWrite {
					// Wrap the fall-back write in its own recover so a
					// second panic (e.g. the same broken
					// http.ResponseWriter that triggered the outer
					// recovery) cannot escape the handler and tear down
					// the HTTP server's serving goroutine.
					func() {
						defer func() { _ = recover() }()
						attemptedWrite = true
						a.writeJSON(w, http.StatusOK, renderAgentHookResponseForProfile(profile, resp))
					}()
				}
			}
		}()

		// Profile-driven raw event remembering. Every connector that
		// maps to a hook event with prompt /
		// tool-call / tool-result shape now gets dedup IDs for
		// joining native OTLP traffic with the hook surface. The
		// IDs flow into the audit envelope below so a SIEM query
		// can correlate a guardrail block with the upstream OTLP
		// log without bespoke per-connector wiring.
		//
		// hookOnly connectors (hermes/cursor/etc.) previously had
		// no dedup coverage; this addition is additive — empty IDs
		// are dropped by the envelope omitempty rule.
		//
		// The profile runtime routes connectors with exact native
		// correlation IDs (Codex / Claude Code today) through their
		// registered dedupe callback and every other connector
		// through the generic profile path.
		rawEventIDs = runtime.RememberRawEvents(a, req, b, payload)

		// Emit the LLM event (prompt/tool/response) BEFORE the
		// evaluator runs. Capturing what the agent attempted
		// regardless of whether the evaluation later blocks it
		// keeps the audit trail honest. Bespoke emitters apply
		// to claudecode/codex so existing PromptID/ToolID
		// correlation chains remain wire-compatible with what the
		// per-connector emitters produced before the unified
		// collector landed; every other connector uses the generic
		// agentHookRequest-driven emitter.
		runtime.EmitLLMEvent(a, ctx, req, b, payload, rawEventIDs)

		// Dispatch evaluation through the profile runtime. Connector-
		// specific event switches, scan triggers, and asset-policy
		// probes are registered callbacks rather than HTTP handlers or
		// gateway-level connector branches. The
		// returned agentHookResponse carries the connector's
		// output map in HookOutput — handleAgentHook below renders
		// that map under the right top-level JSON key
		// (claude_code_output / codex_output / hook_output) so the
		// wire shape stays compatible for each agent CLI.
		//
		// safeEvaluateHook wraps the evaluator in a deferred
		// recover: a panic in any connector-specific scan / asset
		// probe / inspectToolPolicy path no longer terminates the
		// HTTP request uncaught. Before the unified collector each
		// bespoke per-connector handler could panic independently
		// (blast radius: one connector); now this is the SOLE hot
		// path for every connector, so unrecovered panics would take
		// the whole agent estate
		// down at once. The recover emits a RecordPanic counter
		// with subsystem=gateway and synthesises a safe fail-open
		// response (action=allow, would_block=true, reason carries
		// "internal evaluator error"). Operators alert on
		// defenseclaw.panics.total{subsystem="gateway"} and on the
		// `result="panic"` label on the standard hook invocation
		// counter.
		//
		// resp.EvaluationID + resp.RuleIDs are stamped inside the
		// per-profile evaluators (claudeCode / codex / generic) so
		// they round-trip back to the HTTP response and onto the
		// audit envelope without a second pass here.
		resp, panicked := a.safeEvaluateHook(ctx, connectorName, req, b, payload, runtime)
		elapsed := time.Since(t0)
		enrichAgentHookSpan(ctx, req, resp, elapsed)
		if panicked {
			enrichAgentHookSpanPanic(ctx)
		}

		a.finalizeAgentHook(ctx, connectorName, req, resp, rawEventIDs, b, elapsed, panicked, hookCompatibilityExtra(profile))
		finalized = true

		// Mark the write attempt BEFORE invoking writeJSON. A panic
		// from inside renderAgentHookResponseForProfile or json.Encode
		// then signals "do not retry from the defer"; the response
		// stream may already be partially written, and a second
		// attempt against the same writer would just re-panic.
		attemptedWrite = true

		// Render the wire response with the connector-specific
		// top-level field name for the output map (e.g.
		// "claude_code_output", "codex_output", "hook_output").
		// Without this projection, agentHookResponse always
		// renders the output under "hook_output", which Claude
		// Code and Codex agent CLIs reject. See
		// renderAgentHookResponse() for the canonical
		// connector → field-name mapping.
		a.writeJSON(w, http.StatusOK, renderAgentHookResponseForProfile(profile, resp))
	}
}

func (a *APIServer) finalizeAgentHook(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	resp agentHookResponse,
	rawEventIDs []string,
	rawBody []byte,
	elapsed time.Duration,
	panicked bool,
	extra map[string]string,
) {
	safeSection := func(section string, fn func()) {
		defer func() {
			if recovered := recover(); recovered != nil {
				a.handleHookPanic(ctx, connectorName, req.HookEventName,
					fmt.Sprintf("hook finalize %s panic: %v", section, recovered))
			}
		}()
		fn()
	}

	safeSection("health", func() {
		if a.health == nil {
			return
		}
		a.health.RecordConnectorRequest()
		if resp.Action == "block" {
			a.health.RecordToolBlock()
		}
		if isGenericToolInspectionEvent(req.HookEventName) {
			a.health.RecordToolInspection()
		}
	})

	safeSection("otel", func() {
		if a.otel == nil {
			return
		}
		result := "ok"
		reason := normalizeHookReasonLabel(resp.Action, resp.WouldBlock)
		if panicked {
			result = "panic"
			reason = "panic"
		}
		eventLabel := normalizeHookEventLabel(req.HookEventName)
		decisionLabel := normalizeHookActionLabel(resp.Action)
		rawActionLabel := normalizeHookActionLabel(resp.RawAction)
		toolLabel := hookMetricToolLabel(connectorName, req.HookEventName)
		// Dual emission of hook.* and inspect.* is intentional and
		// load-bearing:
		//
		//   - defenseclaw.connector.hook.{invocations,latency,outcome}
		//     split connector and event_type into separate dimensions
		//     — that is the shape new dashboards (defenseclaw-overview,
		//     -hitl, -policy-decisions) and PromQL alerts query.
		//   - defenseclaw.inspect.{evaluations,latency} expose a
		//     composite `tool=<connector>:<event>` label that the
		//     legacy security / connectors / connector-detail
		//     dashboards filter on (tool=~"$connector:.*"). Removing
		//     these calls silently breaks every panel that uses that
		//     filter, including the per-connector verdict breakdown
		//     in defenseclaw-connector-detail.json.
		//
		// Keep both in sync; the inspect counters carry the same
		// (action, severity, latency) information already captured by
		// the hook counters, so a future migration can drop them only
		// once every consuming dashboard has been re-pointed at the
		// hook.* series.
		a.otel.RecordConnectorHookInvocation(ctx, connectorName, eventLabel, result, reason, float64(elapsed.Milliseconds()))
		a.otel.RecordInspectEvaluation(ctx, toolLabel, decisionLabel, resp.Severity)
		a.otel.RecordInspectLatency(ctx, toolLabel, float64(elapsed.Milliseconds()))
		a.otel.RecordHookOutcome(ctx, connectorName, eventLabel, decisionLabel, resp.Severity, resp.WouldBlock)
		usage := extractHookPayloadTokenUsage(req.Payload)
		a.otel.RecordHookTokenUsage(ctx, connectorName, usage.Model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
		a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, result, 1, int64(len(rawBody)),
			fmt.Sprintf("source=hook connector=%s event=%s tool=%s decision=%s raw_action=%s would_block=%v mode=%s duration_ms=%d result=%s",
				hookLogLabel(connectorName), eventLabel, hookLogLabel(req.ToolName), decisionLabel, rawActionLabel, resp.WouldBlock, hookLogLabel(resp.Mode), elapsed.Milliseconds(), result))
	})

	safeSection("audit", func() {
		envResult := "ok"
		if panicked {
			envResult = "panic"
		}
		env := HookAuditEnvelope{
			Connector:    connectorName,
			Event:        req.HookEventName,
			Result:       envResult,
			Action:       resp.Action,
			RawAction:    resp.RawAction,
			Severity:     resp.Severity,
			Mode:         resp.Mode,
			Reason:       resp.Reason,
			WouldBlock:   resp.WouldBlock,
			ElapsedMs:    elapsed.Milliseconds(),
			BodyBytes:    int64(len(rawBody)),
			RawOrigin:    rawOriginIfHook(rawEventIDs),
			RawEventIDs:  rawEventIDs,
			EvaluationID: resp.EvaluationID,
			RuleIDs:      resp.RuleIDs,
		}
		if panicked {
			env.Extra = map[string]string{"panic": "true"}
		}
		env.Extra = mergeHookEnvelopeExtra(env.Extra, extra)
		attachRawPayload(&env, rawBody)
		a.logConnectorHookAuditEnvelope(ctx, env)
	})
}

// renderAgentHookResponse projects the unified agentHookResponse
// shape onto the wire JSON shape each connector's agent CLI
// expects. The fixed agentHookResponse JSON tag for HookOutput
// ("hook_output") works for generic hookOnly connectors
// (hermes/cursor/windsurf/geminicli/copilot) but Claude Code and
// Codex agents expect "claude_code_output" and "codex_output"
// respectively. Rendering as a map[string]interface{} lets us pick
// the right top-level key per connector while keeping
// agentHookResponse a single struct for all internal callers.
//
// Field name choice is driven by hookOutputFieldName(connectorName)
// — a single function so adding a new connector with a different
// output key (e.g. a future zeptoclaw_output) is a one-line change.
// HookProfile.Respond.FieldName would be the obvious source of
// truth here, but consulting it requires loading the registry and
// constructing a profile per request; this hot-path helper inlines
// the mapping for sub-microsecond cost. The connector_hook_profile
// tests still assert FieldName parity so the two cannot drift.
func renderAgentHookResponse(connectorName string, resp agentHookResponse) map[string]interface{} {
	return renderAgentHookResponseForProfile(connector.HookProfile{
		Name:              connectorName,
		ResponseFieldName: hookOutputFieldName(connectorName),
	}, resp)
}

func renderAgentHookResponseForProfile(profile connector.HookProfile, resp agentHookResponse) map[string]interface{} {
	severity := resp.Severity
	if severity == "" {
		severity = "NONE"
	}
	action := resp.Action
	if action == "" {
		action = "allow"
	}
	out := map[string]interface{}{
		"action":      action,
		"severity":    severity,
		"mode":        resp.Mode,
		"would_block": resp.WouldBlock,
	}
	if resp.RawAction != "" {
		out["raw_action"] = resp.RawAction
	}
	if resp.Reason != "" {
		out["reason"] = resp.Reason
	}
	if len(resp.Findings) > 0 {
		out["findings"] = resp.Findings
	}
	if resp.AdditionalContext != "" {
		out["additional_context"] = resp.AdditionalContext
	}
	if len(resp.HookOutput) > 0 {
		fieldName := strings.TrimSpace(profile.ResponseFieldName)
		if fieldName == "" {
			fieldName = hookOutputFieldName(profile.Name)
		}
		out[fieldName] = resp.HookOutput
	}
	// Surface the unified-pipeline correlation keys so hook scripts
	// + downstream tooling can pivot HTTP responses on the same
	// evaluation_id used by gateway.jsonl + the audit DB. Both
	// fields are additive — pre-existing hook scripts that ignore
	// unknown keys continue to parse the same shape.
	if resp.EvaluationID != "" {
		out["evaluation_id"] = resp.EvaluationID
	}
	if len(resp.RuleIDs) > 0 {
		out["rule_ids"] = resp.RuleIDs
	}
	return out
}

// hookOutputFieldName returns the top-level JSON key under which a
// connector expects its hook-output map to be rendered. Defaults to
// "hook_output" for any connector that has not declared a custom
// key; claudecode and codex are the only two custom mappings today.
//
// This MUST stay in sync with HookProfile.Respond.FieldName for
// each connector — the connector_hook_profile_test golden-shape
// tests assert that on the connector-side, and
// TestRenderAgentHookResponse_FieldNames asserts the gateway-side
// projection here matches. Adding a new connector with a custom
// key is a one-line change to both this switch and the connector's
// HookProfile.Respond callback.
func hookOutputFieldName(connectorName string) string {
	switch connectorName {
	case "claudecode":
		return "claude_code_output"
	case "codex":
		return "codex_output"
	default:
		return "hook_output"
	}
}

// handleAgentHookSynthetic runs the same unified evaluate + audit +
// metrics pipeline as handleAgentHook but skips the HTTP-decode
// step. Callers (handleCodexNotify) construct a fully populated
// agentHookRequest themselves so the unified collector can ingest
// non-HTTP-shaped signals (codex notify fire-and-forget POSTs,
// future webhook-style integrations) the same way as a hook-shaped
// POST.
//
// The function intentionally does NOT write to w — callers own the
// transport-layer response shape (codex notify returns 200 / "{}"
// regardless of evaluator outcome, hook POSTs return the
// agentHookResponse JSON). rawBody is supplied only so the audit
// envelope can compute BodyBytes; it is never reparsed.
//
// Telemetry: same shape as handleAgentHook —
// RecordConnectorHookInvocation, RecordHookOutcome,
// RecordHookTokenUsage, span enrichment, plus a structured audit
// envelope persisted under audit.ActionConnectorHookSynthetic.
//
// Why a DIFFERENT audit action? The caller (handleCodexNotify)
// already persists the canonical `codex.notify.<sanitized-type>`
// audit row, and downstream SIEM rules pin "1 codex.notify in → 1
// codex.notify.* row out". Routing the synthetic envelope under
// ActionConnectorHookSynthetic keeps that contract intact while
// adding a separate row class for the synthetic Stop event so
// connector.hook dashboards see the synthesized invocation; the
// two action constants are independent so neither row count
// changes when the other moves.
//
// The OTel attributes carry `defenseclaw.hook.synthetic=true` so
// dashboards can filter synthetic events out of the "real" hook
// traffic when needed (set by enrichAgentHookSpanSynthetic).
func (a *APIServer) handleAgentHookSynthetic(ctx context.Context, connectorName string, req agentHookRequest, rawBody []byte) agentHookResponse {
	ctx = enrichAgentHookContext(ctx, req)
	profile := a.hookProfileForConnector(connectorName)
	rawEventIDs := a.rememberHookRawEvents(req)
	a.emitAgentHookLLMEvent(ctx, req, rawBody)

	// Synthetic paths use the generic evaluator (notify carries no
	// scan/tool context), but they still need panic safety: the
	// codex-notify caller writes "{}" and a 200 regardless of
	// outcome, but the audit + metrics pipeline below this MUST
	// run even when the evaluator dies. Same RecordPanic +
	// fail-open contract as handleAgentHook.
	t0 := time.Now()
	resp, panicked := a.safeEvaluateSyntheticHook(ctx, connectorName, req)
	elapsed := time.Since(t0)
	enrichAgentHookSpan(ctx, req, resp, elapsed)
	enrichAgentHookSpanSynthetic(ctx)
	if panicked {
		enrichAgentHookSpanPanic(ctx)
	}

	if a.health != nil {
		a.health.RecordConnectorRequest()
		if resp.Action == "block" {
			a.health.RecordToolBlock()
		}
	}

	if a.otel != nil {
		result := "ok"
		reason := normalizeHookReasonLabel(resp.Action, resp.WouldBlock)
		if panicked {
			result = "panic"
			reason = "panic"
		}
		// Normalize every dimension at the metric/log boundary so a
		// hostile or simply malformed payload (e.g. an oversized
		// HookEventName, a unicode/control-character ToolName) cannot
		// blow up cardinality on synthetic emissions the same way it
		// can't on the regular hook path above. hookMetricToolLabel
		// is the shared normalizer used by the regular path so the
		// inspect.* tool label has identical shape across both paths
		// — dashboards filtering on tool=~"$connector:.*" must not
		// see two flavours of the same connector/event combo.
		eventLabel := normalizeHookEventLabel(req.HookEventName)
		decisionLabel := normalizeHookActionLabel(resp.Action)
		rawActionLabel := normalizeHookActionLabel(resp.RawAction)
		toolLabel := hookMetricToolLabel(connectorName, req.HookEventName)
		a.otel.RecordConnectorHookInvocation(ctx, connectorName, eventLabel, result, reason, float64(elapsed.Milliseconds()))
		// Mirror the regular hook path: emit both hook.* (new
		// dashboards) and inspect.* (legacy dashboards). See the
		// equivalent block in handleAgentHook for the rationale —
		// the dual emission is the documented contract.
		a.otel.RecordInspectEvaluation(ctx, toolLabel, decisionLabel, resp.Severity)
		a.otel.RecordInspectLatency(ctx, toolLabel, float64(elapsed.Milliseconds()))
		a.otel.RecordHookOutcome(ctx, connectorName, eventLabel, decisionLabel, resp.Severity, resp.WouldBlock)
		usage := extractHookPayloadTokenUsage(req.Payload)
		a.otel.RecordHookTokenUsage(ctx, connectorName, usage.Model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
		a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, result, 1, int64(len(rawBody)),
			fmt.Sprintf("source=hook connector=%s event=%s tool=%s decision=%s raw_action=%s would_block=%v mode=%s duration_ms=%d synthetic=true result=%s",
				hookLogLabel(connectorName), eventLabel, hookLogLabel(req.ToolName), decisionLabel, rawActionLabel, resp.WouldBlock, hookLogLabel(resp.Mode), elapsed.Milliseconds(), result))
	}

	// Persist the synthetic envelope under a distinct audit action
	// so the canonical caller row count stays intact while SIEM /
	// dashboards still see the synthesized Stop event. See the
	// function godoc for the row-counting contract.
	envResult := "ok"
	if panicked {
		envResult = "panic"
	}
	extra := map[string]string{"synthetic": "true"}
	if panicked {
		extra["panic"] = "true"
	}
	env := HookAuditEnvelope{
		Connector:           connectorName,
		Event:               req.HookEventName,
		Result:              envResult,
		Action:              resp.Action,
		RawAction:           resp.RawAction,
		Severity:            resp.Severity,
		Mode:                resp.Mode,
		Reason:              resp.Reason,
		WouldBlock:          resp.WouldBlock,
		ElapsedMs:           elapsed.Milliseconds(),
		BodyBytes:           int64(len(rawBody)),
		RawOrigin:           rawOriginIfHook(rawEventIDs),
		RawEventIDs:         rawEventIDs,
		EvaluationID:        resp.EvaluationID,
		RuleIDs:             resp.RuleIDs,
		AuditActionOverride: string(audit.ActionConnectorHookSynthetic),
		Extra:               mergeHookEnvelopeExtra(extra, hookCompatibilityExtra(profile)),
	}
	attachRawPayload(&env, rawBody)
	a.logConnectorHookAuditEnvelope(ctx, env)
	return resp
}

// enrichAgentHookSpanSynthetic stamps a defenseclaw.hook.synthetic
// attribute on the active span so dashboards built on top of
// RecordConnectorHookInvocation can split "real" hook POSTs from
// notify-bridge synthetic Stop events. Kept as a separate helper so
// the existing enrichAgentHookSpan signature does not grow a
// boolean parameter (every existing call site would otherwise need
// updating).
func enrichAgentHookSpanSynthetic(ctx context.Context) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(attribute.Bool("defenseclaw.hook.synthetic", true))
}

// enrichAgentHookSpanPanic stamps a defenseclaw.hook.panic attribute
// on the active span AND sets the span status to Error so trace
// backends surface the failure even though the HTTP response itself
// was 200 (we fail-open with would_block=true rather than dropping
// the connection — see safeEvaluateHook for the rationale).
//
// Marking Error is what lets Tempo / Jaeger / Honeycomb filters
// like "status=error" and the OTel collector's error-rate panel
// see panic-recovered hook spans without scanning every attribute.
// The attribute is additionally set so per-span detail views and
// drill-downs can split "ordinary upstream error" from "DefenseClaw
// internal evaluator panic".
func enrichAgentHookSpanPanic(ctx context.Context) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(
		attribute.Bool("defenseclaw.hook.panic", true),
		attribute.String("defenseclaw.connector.result", "panic"),
		attribute.String("defenseclaw.hook.reason", "panic"),
	)
	span.SetStatus(codes.Error, "hook evaluator panic recovered (fail-open)")
}

// hookReasonLabelAllowlist constrains the `reason` Prometheus/OTLP
// label cardinality on the connector-hook invocation counter. Verdicts
// from the evaluator are an enum today (allow/block/alert/confirm)
// but nothing in the type system enforces that at the metric
// boundary; if a future evaluator branch were to leak free-form text
// into resp.Action, the TSDB would absorb arbitrary cardinality.
// Anything outside this set collapses to "other" so dashboards stay
// stable.
//
// Synthesized labels:
//   - would_block: resp.Action would have blocked except mode != "action".
//   - panic:       safeEvaluateHook caught a panic.
//   - other:       anything not modelled here (must never reach prod).
//   - none:        empty action (defensive — shouldn't happen).
var hookReasonLabelAllowlist = map[string]struct{}{
	"allow":       {},
	"block":       {},
	"alert":       {},
	"confirm":     {},
	"would_block": {},
	"panic":       {},
	"other":       {},
	"none":        {},
}

// normalizeHookReasonLabel projects (resp.Action, resp.WouldBlock)
// onto the bounded hookReasonLabelAllowlist so the connector-hook
// invocation counter cannot grow unbounded reason cardinality.
func normalizeHookReasonLabel(action string, wouldBlock bool) string {
	if wouldBlock {
		return "would_block"
	}
	a := strings.TrimSpace(action)
	if a == "" {
		return "none"
	}
	a = strings.ToLower(a)
	if _, ok := hookReasonLabelAllowlist[a]; ok {
		return a
	}
	return "other"
}

func normalizeHookActionLabel(action string) string {
	a := strings.ToLower(strings.TrimSpace(action))
	if a == "" {
		return "none"
	}
	if _, ok := hookReasonLabelAllowlist[a]; ok {
		return a
	}
	return "other"
}

func normalizeHookEventLabel(event string) string {
	canon := canonicalEvent(event)
	if canon == "" {
		return "unknown"
	}
	switch {
	case isPromptLikeEvent(canon):
		return "prompt"
	case isGenericToolInspectionEvent(canon):
		return "tool_call"
	case isResultLikeEvent(canon) || canon == "posttoolbatch":
		return "tool_result"
	}
	switch canon {
	case "permissionrequest":
		return "permissionrequest"
	case "stop", "agentstop", "subagentstop":
		return "stop"
	case "notification":
		return "notification"
	case "sessionstart":
		return "sessionstart"
	default:
		return "other"
	}
}

func hookMetricToolLabel(connectorName, event string) string {
	connectorName = normalizeHookTelemetryLabel(connectorName, "unknown")
	return connectorName + ":" + normalizeHookEventLabel(event)
}

func hookLogLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(stripLogInjectionRunes(value)))
	if value == "" {
		return "unknown"
	}
	if len(value) > 64 {
		return "other"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '-' || r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "other"
	}
	return out
}

// hookPanicRawPayloadCap is the byte cap applied to env.RawPayload
// when redaction is globally disabled (DEFENSECLAW_REDACTION_DISABLE=1).
// 64 KiB is large enough to cover any realistic prompt + tool-call
// payload but small enough that a 10 MiB hostile POST cannot amplify
// through json.Marshal → strconv.Quote → SQLite insert → every audit
// sink. Bytes beyond the cap are dropped and a SHA-256 hash of the
// full body + the truncated-size marker land in env.Extra so SIEM
// rules can still detect "same body, replayed" and operators can
// verify the upstream body via tracing if needed.
const hookPanicRawPayloadCap = 64 * 1024

// attachRawPayload conditionally attaches the request body to the
// audit envelope, applying the M3 cap so a hostile or malformed
// payload cannot turn one POST into a multi-megabyte SQLite row.
// Only runs when redaction.DisableAll() returned true (operator
// explicitly disabled all redaction); otherwise raw bodies must not
// reach persistent storage at all.
func attachRawPayload(env *HookAuditEnvelope, body []byte) {
	if env == nil || len(body) == 0 {
		return
	}
	if !redaction.DisableAll() {
		return
	}
	if len(body) <= hookPanicRawPayloadCap {
		env.RawPayload = string(body)
		return
	}
	if env.Extra == nil {
		env.Extra = map[string]string{}
	}
	env.RawPayload = string(body[:hookPanicRawPayloadCap])
	env.Extra["raw_payload_truncated"] = "true"
	env.Extra["raw_payload_full_bytes"] = strconv.Itoa(len(body))
	env.Extra["raw_payload_sha256"] = hashRawPayloadHex(body)
}

func hookCompatibilityExtra(profile connector.HookProfile) map[string]string {
	extra := map[string]string{}
	if profile.ContractID != "" {
		extra["hook_contract_id"] = profile.ContractID
	}
	if profile.HookScriptVersion != "" {
		extra["hook_script_version"] = profile.HookScriptVersion
	}
	if profile.AgentVersion != "" {
		extra["agent_version_raw"] = profile.AgentVersion
	}
	if profile.NormalizedAgentVersion != "" {
		extra["agent_version_normalized"] = profile.NormalizedAgentVersion
	}
	if profile.CompatibilityStatus != "" {
		extra["hook_compatibility_status"] = profile.CompatibilityStatus
	}
	if profile.CompatibilityReason != "" {
		extra["hook_compatibility_reason"] = profile.CompatibilityReason
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

func mergeHookEnvelopeExtra(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range extra {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		base[k] = v
	}
	return base
}

// hashRawPayloadHex returns the first 16 hex chars of the SHA-256
// of body. 64 bits is enough to deduplicate replay-storms in SIEM
// rules without bloating audit rows; full digest would be 64 hex
// chars per truncated row.
func hashRawPayloadHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

// safeEvaluateHook wraps the profile-runtime evaluator with a
// deferred recover so a panic in any connector-specific code path
// (asset-policy probes, scanner invocations, codex notify-bridge
// fan-out, …) cannot terminate the HTTP request uncaught.
//
// Threat model: before the unified collector, each connector owned
// its own bespoke HTTP handler so a panic's blast radius was one
// connector. This is now the SOLE hot path for every connector, so
// an unrecovered panic would take the entire agent estate down at
// once. The recover:
//
//   - records defenseclaw.panics.total{subsystem="gateway"} (the
//     shared process-health counter from the telemetry package) so
//     existing SRE alerting fires without us inventing a new
//     metric.
//   - logs the recovered value + stack to stderr (only place we
//     have during a panic — the structured logger may itself be
//     the panic source).
//   - returns a SAFE fail-open agentHookResponse:
//     action=allow, raw_action=allow, severity=WARN, would_block=true,
//     mode="unknown" (the evaluator that resolves mode never
//     ran), reason carries a stable "defenseclaw internal
//     evaluator error" string so operator log greps can find the
//     row, additional_context carries an operator-facing hint.
//
// We deliberately fail OPEN (allow) rather than fail-closed (block)
// because: a panic likely means a transient bug in a single
// evaluator branch, and silently blocking every agent's every
// tool call would be a worse production incident than carrying
// on with telemetry-only mode. would_block=true preserves the
// guardrail intent ("I would have blocked this in stricter
// posture") and result="panic" + audit row + RecordPanic counter
// give SRE every signal they need to investigate.
//
// The bool return tells the caller whether to label downstream
// metrics + audit envelope with result="panic". Without it, the
// caller would have to inspect the response to infer "did we
// panic?" which is fragile.
func (a *APIServer) safeEvaluateHook(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	runtime hookProfileRuntime,
) (resp agentHookResponse, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			resp = safeHookPanicResponse(connectorName, req.HookEventName, r)
			a.handleHookPanic(ctx, connectorName, req.HookEventName, r)
		}
	}()
	if runtime.Evaluate == nil {
		runtime = defaultHookProfileRuntime(connector.HookProfile{Name: connectorName})
	}
	resp = runtime.Evaluate(a, ctx, req, rawBody, payload)
	return resp, false
}

// safeEvaluateSyntheticHook is the synthetic-path counterpart of
// safeEvaluateHook. Same fail-open contract; the generic evaluator
// is the only callee (notify-bridge events have no per-connector
// scan / asset-policy semantics).
func (a *APIServer) safeEvaluateSyntheticHook(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
) (resp agentHookResponse, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			resp = safeHookPanicResponse(connectorName, req.HookEventName, r)
			a.handleHookPanic(ctx, connectorName, req.HookEventName, r)
		}
	}()
	resp = a.evaluateAgentHook(ctx, req)
	return resp, false
}

// safeHookPanicResponse builds the agentHookResponse returned when
// safeEvaluateHook / safeEvaluateSyntheticHook recover from a panic.
// The fields here are deliberately conservative — see
// safeEvaluateHook godoc for the fail-open rationale.
func safeHookPanicResponse(connectorName, eventName string, _ any) agentHookResponse {
	return agentHookResponse{
		Action:            "allow",
		RawAction:         "allow",
		Severity:          "WARN",
		Mode:              "unknown",
		WouldBlock:        true,
		Reason:            "defenseclaw internal evaluator error",
		AdditionalContext: fmt.Sprintf("DefenseClaw hook evaluator for %s/%s recovered from an internal error; the action was allowed with would_block=true. Operators: check defenseclaw.panics.total and recent audit rows with extra.panic=true.", connectorName, eventName),
	}
}

// handleHookPanic centralises the side-effects of a recovered hook
// panic: metric increment, stderr log with stack, optional EventError
// emission via Provider.emitPanicRecovered (already wired into
// RecordPanic). Safe to call with nil otel / nil logger; both
// branches are nil-guarded.
func (a *APIServer) handleHookPanic(ctx context.Context, connectorName, eventName string, recovered any) {
	stack := debug.Stack()
	fmt.Fprintf(os.Stderr, "[gateway] PANIC recovered in hook evaluator connector=%s event=%s value=%v\n%s\n",
		connectorName, eventName, recovered, stack)
	if a != nil && a.otel != nil {
		a.otel.RecordPanic(ctx, gatewaylog.SubsystemGateway)
	}
}

func enrichAgentHookContext(ctx context.Context, req agentHookRequest) context.Context {
	ctx = ContextWithSessionID(ctx, req.SessionID)
	identity := agentIdentityForGenericHook(ctx, req)
	ctx = ContextWithAgentIdentity(ctx, identity)
	// Refresh the audit correlation envelope with payload-derived
	// correlation. CorrelationMiddleware snapshots the envelope
	// from the HTTP headers BEFORE this handler runs; for hook
	// connectors the session_id / agent_id arrive in the JSON
	// body (the hook shell scripts don't set
	// X-DefenseClaw-Session-Id), so without this refresh every
	// audit row written by logConnectorHookAuditEnvelope would
	// land with session_id=NULL and agent_id=NULL — defeating
	// SIEM correlation between hook decisions and LLM events.
	//
	// MergeEnvelope's contract is "non-empty base fields always
	// win"; we override that by clearing matching fields when the
	// payload provides a more specific value, so a hook posted on
	// a different session than the inbound header (the synthetic
	// codex-notify path is the canonical case) takes precedence.
	ctx = refreshAuditEnvelopeFromHook(ctx, req, identity)
	enrichHTTPSpanFromContext(ctx)
	return ctx
}

// refreshAuditEnvelopeFromHook copies payload-derived correlation
// fields (session_id, agent_id, agent_name, agent_instance_id) onto
// the audit envelope stored in ctx, so every downstream
// logger.LogActionCtx call writes the right row.
//
// Why not just overwrite the envelope unconditionally? Because the
// middleware-set envelope may already carry tenant correlation the
// payload doesn't know about (RunID, TraceID, RequestID, PolicyID,
// DestinationApp). We refresh only the four hook-derived fields and
// leave the rest of the envelope intact.
//
// Empty payload fields are no-ops — a hook event without a session
// id still respects whatever the middleware resolved, so today's
// rows that DO have a session id (because the operator stuck a
// loadbalancer that injects the header) keep it.
func refreshAuditEnvelopeFromHook(ctx context.Context, req agentHookRequest, identity AgentIdentity) context.Context {
	return refreshAuditEnvelopeFromIdentity(ctx, req.SessionID, identity)
}

// refreshAuditEnvelopeFromIdentity is the type-agnostic core of the
// audit-envelope refresh contract. Every connector hook flows through
// handleAgentHook → enrichAgentHookContext → refreshAuditEnvelopeFromHook
// → this helper, so there is exactly one place where the audit
// correlation envelope gets payload-derived session_id / agent_id
// stitched on. The function is kept exported-by-package (lower-case
// first letter is fine; it's gateway-internal) so other unified
// paths (handleAgentHookSynthetic for codex notify) can call it
// directly with an already-resolved AgentIdentity.
//
// History: an earlier iteration of this fix wired only the unified
// path; live Splunk verification then proved claudecode + codex hook
// rows landed with session_id=NULL because each owned a separate
// bespoke HTTP handler that never invoked the unified
// enrichAgentHookContext. Those bespoke handlers were subsequently
// deleted, and the profile-runtime registry now keeps every
// remaining connector-specific evaluator behind this single
// envelope-refresh choke point.
func refreshAuditEnvelopeFromIdentity(ctx context.Context, sessionID string, identity AgentIdentity) context.Context {
	env := audit.EnvelopeFromContext(ctx)
	changed := false
	if sid := strings.TrimSpace(sessionID); sid != "" && env.SessionID != sid {
		env.SessionID = sid
		changed = true
	}
	if aid := strings.TrimSpace(identity.AgentID); aid != "" && env.AgentID != aid {
		env.AgentID = aid
		changed = true
	}
	if name := strings.TrimSpace(identity.AgentName); name != "" && env.AgentName != name {
		env.AgentName = name
		changed = true
	}
	if instance := strings.TrimSpace(identity.AgentInstanceID); instance != "" && env.AgentInstanceID != instance {
		env.AgentInstanceID = instance
		changed = true
	}
	if !changed {
		return ctx
	}
	return audit.ContextWithEnvelope(ctx, env)
}

func agentIdentityForGenericHook(ctx context.Context, req agentHookRequest) AgentIdentity {
	agentName := firstNonEmpty(req.AgentName, req.AgentType, req.ConnectorName)
	agentType := firstNonEmpty(req.AgentType, req.ConnectorName)
	identity := AgentIdentity{
		AgentID:   strings.TrimSpace(req.AgentID),
		AgentName: agentName,
		AgentType: agentType,
	}
	if reg := SharedAgentRegistry(); reg != nil {
		resolved := reg.Resolve(ctx, req.SessionID, identity.AgentID)
		if identity.AgentID == "" {
			identity.AgentID = resolved.AgentID
		}
		identity.AgentInstanceID = resolved.AgentInstanceID
		identity.SidecarInstanceID = resolved.SidecarInstanceID
	}
	return identity
}

func enrichAgentHookSpan(ctx context.Context, req agentHookRequest, resp agentHookResponse, elapsed time.Duration) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	reason := resp.Action
	if resp.WouldBlock {
		reason = "would_block"
	}
	reason = normalizeHookReasonLabel(reason, false)
	attrs := []attribute.KeyValue{
		attribute.String("defenseclaw.connector", req.ConnectorName),
		attribute.String("defenseclaw.connector.source", req.ConnectorName),
		attribute.String("defenseclaw.connector.signal", "hook"),
		attribute.String("defenseclaw.connector.result", "ok"),
		attribute.String("defenseclaw.hook.reason", reason),
		attribute.String("defenseclaw.telemetry.source", "hook"),
		attribute.String("defenseclaw.hook.event", normalizeHookEventLabel(req.HookEventName)),
		attribute.String("defenseclaw.tool.name", hookLogLabel(req.ToolName)),
		attribute.String("defenseclaw.decision", normalizeHookActionLabel(resp.Action)),
		attribute.String("defenseclaw.raw_action", normalizeHookActionLabel(resp.RawAction)),
		attribute.Bool("defenseclaw.would_block", resp.WouldBlock),
		attribute.String("defenseclaw.mode", hookLogLabel(resp.Mode)),
		attribute.Int64("defenseclaw.duration_ms", elapsed.Milliseconds()),
	}
	if req.SessionID != "" {
		attrs = append(attrs, attribute.String("gen_ai.conversation.id", req.SessionID))
	}
	identity := AgentIdentityFromContext(ctx)
	if identity.AgentName != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.name", identity.AgentName))
	}
	if identity.AgentType != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.type", identity.AgentType))
	}
	if identity.AgentID != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.id", identity.AgentID))
	}
	if req.TurnID != "" {
		attrs = append(attrs, attribute.String("gen_ai.operation.id", req.TurnID))
	}
	span.SetAttributes(attrs...)
}

func normalizeAgentHookRequest(connectorName string, payload map[string]interface{}) agentHookRequest {
	event := firstString(payload,
		"hook_event_name",
		"hookEventName",
		"event_type",
		"eventType",
		"event_name",
		"eventName",
		"agent_action_name",
	)
	if event == "" {
		event = inferAgentHookEvent(payload)
	}
	agentID, agentName, agentType := extractAgentIdentityFromHookPayload(payload)
	sessionID := firstString(payload, "session_id", "sessionId", "task_id", "conversation_id", "conversationId", "thread_id", "threadId")
	turnID := firstString(payload, "turn_id", "turnId", "execution_id", "executionId", "generation_id", "generationId", "tool_call_id", "toolCallId")
	cwd := firstString(payload, "cwd", "working_dir", "workingDir", "working_directory", "workingDirectory")
	if cwd == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			cwd = firstString(toolInfo, "cwd", "working_directory")
		}
	}

	toolName := firstString(payload, "tool_name", "toolName", "command_name", "name")
	if toolName == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			toolName = firstString(toolInfo, "mcp_tool_name", "tool_name", "command_name")
			if toolName == "" && firstString(toolInfo, "command_line", "command") != "" {
				toolName = "shell"
			}
		}
	}
	if toolName == "" && isPromptLikeEvent(event) {
		toolName = "message"
	}
	if toolName == "" {
		toolName = "tool"
	}

	args := firstValue(payload, "tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if args == nil {
		args = firstValue(payload, "tool_info", "toolInfo")
	}
	if args == nil {
		args = payload
	}
	argBytes, err := json.Marshal(args)
	if err != nil {
		argBytes = []byte(`{}`)
	}

	content := firstString(payload,
		"prompt",
		"user_prompt",
		"userPrompt",
		"message",
		"initial_prompt",
		"initialPrompt",
		"custom_instructions",
		"customInstructions",
	)
	if content == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			content = firstString(toolInfo, "user_prompt", "content", "command_line", "command", "mcp_result")
		}
	}
	if content == "" {
		content = stringifyHookValue(firstValue(payload, "tool_response", "toolResponse", "tool_result", "toolResult", "result", "error"))
	}

	direction := "tool_call"
	switch {
	case isPromptLikeEvent(event):
		direction = "prompt"
	case isResultLikeEvent(event):
		direction = "tool_result"
	}

	return agentHookRequest{
		ConnectorName: connectorName,
		AgentID:       agentID,
		AgentName:     agentName,
		AgentType:     agentType,
		HookEventName: event,
		SessionID:     sessionID,
		TurnID:        turnID,
		CWD:           cwd,
		ToolName:      toolName,
		ToolArgs:      json.RawMessage(argBytes),
		Content:       content,
		Direction:     direction,
		Payload:       payload,
	}
}

func normalizeAgentHookRequestWithProfile(connectorName string, payload map[string]interface{}, profile connector.HookProfile) agentHookRequest {
	req := normalizeAgentHookRequest(connectorName, payload)
	if profile.Decode == nil {
		return req
	}
	decoded := profile.Decode(payload)
	if decoded.ConnectorName != "" {
		req.ConnectorName = decoded.ConnectorName
	}
	if req.ConnectorName == "" {
		req.ConnectorName = connectorName
	}
	if decoded.HookEventName != "" {
		req.HookEventName = decoded.HookEventName
	}
	if decoded.SessionID != "" {
		req.SessionID = decoded.SessionID
	}
	if decoded.TurnID != "" {
		req.TurnID = decoded.TurnID
	}
	if decoded.AgentID != "" {
		req.AgentID = decoded.AgentID
	}
	if decoded.AgentName != "" {
		req.AgentName = decoded.AgentName
	}
	if decoded.AgentType != "" {
		req.AgentType = decoded.AgentType
	}
	if decoded.CWD != "" {
		req.CWD = decoded.CWD
	}
	if decoded.ToolName != "" {
		req.ToolName = decoded.ToolName
	}
	if decoded.Content != "" {
		req.Content = decoded.Content
	}
	if decoded.Direction != "" {
		req.Direction = decoded.Direction
	}
	if decoded.Payload != nil {
		req.Payload = decoded.Payload
	}
	return req
}

func extractAgentIdentityFromHookPayload(payload map[string]interface{}) (agentID, agentName, agentType string) {
	agentID = firstHookIdentityString(payload, "agent_id", "agentId", "assistant_id", "assistantId", "client_agent_id", "clientAgentId")
	agentName = firstHookIdentityString(payload, "agent_name", "agentName", "assistant_name", "assistantName")
	agentType = firstHookIdentityString(payload, "agent_type", "agentType", "agent_kind", "agentKind", "runtime", "runtime_name")
	if agentObj := objectAt(payload, "agent"); agentObj != nil {
		if agentID == "" {
			agentID = firstHookIdentityString(agentObj, "id", "agent_id", "agentId", "assistant_id", "assistantId")
		}
		if agentName == "" {
			agentName = firstHookIdentityString(agentObj, "name", "agent_name", "agentName", "display_name", "displayName")
		}
		if agentType == "" {
			agentType = firstHookIdentityString(agentObj, "type", "agent_type", "agentType", "kind", "runtime", "runtime_name")
		}
	}
	if agentName == "" {
		agentName = firstHookIdentityString(payload, "agent")
	}
	return agentID, agentName, agentType
}

func inferAgentHookEvent(payload map[string]interface{}) string {
	if firstValue(payload, "toolName", "tool_name", "toolArgs", "tool_args", "tool_input") != nil {
		return "PreToolUse"
	}
	if firstString(payload, "prompt", "user_prompt", "initialPrompt", "initial_prompt") != "" {
		return "UserPromptSubmit"
	}
	if firstValue(payload, "toolResult", "tool_result", "tool_response", "result") != nil {
		return "PostToolUse"
	}
	return ""
}

// hookEvaluatorPanicHook is a test-only seam: when non-nil it is
// invoked at the top of evaluateAgentHook, allowing
// agent_hook_panic_test.go to inject a controlled panic and verify
// safeEvaluateHook's recover path end-to-end through the HTTP layer.
//
// Production callers leave this nil; the nil-check on the hot path is
// one branch on a never-taken conditional and compiles to a single
// load + cmp + jz — sub-nanosecond, no allocation. It is intentionally
// NOT gated on a build tag so the test seam stays type-correct in the
// production binary (build-tagged seams have historically drifted out
// of sync with their callers, which is the failure mode this design
// avoids).
var hookEvaluatorPanicHook func()

func (a *APIServer) evaluateAgentHook(ctx context.Context, req agentHookRequest) agentHookResponse {
	if hookEvaluatorPanicHook != nil {
		hookEvaluatorPanicHook()
	}
	mode := a.agentHookMode(req.ConnectorName)
	if a.scannerCfg != nil && !a.agentHookEnabled(req.ConnectorName) {
		return agentHookResponseFor(req, "allow", "allow", "NONE", "", nil, mode, false, connector.HookCapability{})
	}
	t0 := time.Now()

	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	var assetDecisions []runtimeAssetDecision
	switch {
	case isPromptLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: "message", Content: req.Content, Direction: "prompt"})
	case isResultLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: req.ToolName, Content: req.Content, Direction: "tool_result"})
		// Asset policy still runs on result-shaped events so a
		// PostToolUse referencing an unregistered MCP server gets
		// captured in audit / would-block telemetry. mergeAssetDecision
		// handles the "non-enforceable event" case by downgrading to
		// would-block automatically.
		assetDecisions = a.collectAgentHookAssetDecisions(ctx, req)
	case isGenericToolInspectionEvent(req.HookEventName):
		verdict = a.inspectToolPolicy(&ToolInspectRequest{Tool: req.ToolName, Args: req.ToolArgs, Direction: "tool_call"})
		assetDecisions = a.collectAgentHookAssetDecisions(ctx, req)
	}

	rawAction := normalizeCodexAction(verdict.Action)
	rawActionBeforeAssets := rawAction
	profile := a.hookProfileForConnector(req.ConnectorName)
	caps := profile.Capabilities
	action, wouldBlock := mapHookActionForProfile(rawAction, mode, req.HookEventName, caps, profile)
	severity := verdict.Severity
	reason := verdict.Reason
	findings := verdict.Findings

	// Fold runtime asset-policy verdicts into the hook verdict.
	// mergeAssetDecision handles "this event is not enforceable"
	// by returning advisory-only changes (action stays allow,
	// rawAction promoted to block, wouldBlock=true). For events
	// the connector itself does not declare blockable, we further
	// downgrade through mapHookAction so we never tell the agent
	// to block on a surface it cannot honor.
	for _, asset := range assetDecisions {
		mergedAction, mergedRawAction, mergedSeverity, mergedReason, mergedFindings, assetWouldBlock := mergeAssetDecision(
			asset.decision, true, asset.targetType, req.HookEventName,
			action, rawAction, severity, reason, findings,
		)
		if mergedAction == "block" {
			capable, capableWouldBlock := mapHookActionForProfile("block", mode, req.HookEventName, caps, profile)
			if capable != "block" {
				mergedAction = capable
				if capableWouldBlock {
					assetWouldBlock = true
				}
			}
		}
		action = mergedAction
		rawAction = mergedRawAction
		severity = mergedSeverity
		reason = mergedReason
		findings = mergedFindings
		if assetWouldBlock {
			wouldBlock = true
		}
	}

	// Emit the per-rule findings BEFORE dispatching the OS toast
	// so the notification can carry the same evaluation_id +
	// rule_ids surfaced on the audit row + HTTP response.
	evalCtx := a.emitHookRuleFindings(ctx, req.ConnectorName, req.HookEventName, verdict,
		hookTargetTypeForEvent(req.HookEventName), time.Since(t0))
	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchAgentHookNotification(req, action, rawAction, severity, reason, wouldBlock, evalCtx)
	}
	resp := agentHookResponseForProfile(profile, req, action, rawAction, severity, reason, findings, mode, wouldBlock, caps)
	// Stamp the unified-pipeline correlation keys so the HTTP
	// response, the audit envelope (HookAuditEnvelope.EvaluationID
	// / RuleIDs), and the scan_finding events all join on the same
	// evaluation_id.
	resp.EvaluationID = evalCtx.EvaluationID
	resp.RuleIDs = evalCtx.RuleIDs
	return resp
}

// collectAgentHookAssetDecisions runs the runtime asset-policy
// evaluators (MCP + skill) for a hook-only-connector event and
// returns the matched blocking verdicts. Non-blocking matches and
// non-matches return as zero entries; the caller folds the results
// into the hook decision via mergeAssetDecision.
//
// The MCP and skill probes are derived from the same payload —
// req.Payload, req.ToolName, req.ToolArgs — that the upstream event
// log already covers, so no additional information leaves the
// process. tool_input is derived from ToolArgs lazily because the
// asset probes need a typed map view (ServerName / Command / args)
// that the raw json.RawMessage does not provide directly.
func (a *APIServer) collectAgentHookAssetDecisions(ctx context.Context, req agentHookRequest) []runtimeAssetDecision {
	var out []runtimeAssetDecision
	if decision, matched := a.agentHookMCPAssetDecision(ctx, req); matched {
		out = append(out, runtimeAssetDecision{targetType: "mcp", decision: decision})
	}
	if decision, matched := a.agentHookSkillAssetDecision(ctx, req); matched {
		out = append(out, runtimeAssetDecision{targetType: "skill", decision: decision})
	}
	return out
}

func (a *APIServer) agentHookMCPAssetDecision(ctx context.Context, req agentHookRequest) (config.AssetPolicyDecision, bool) {
	toolInput := decodeAgentHookToolInput(req.ToolArgs)
	probe := mcpProbeFromFields(payloadString(req.Payload, "mcp_server_name"), req.ToolName, toolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, req.ConnectorName, req.HookEventName, probe)
}

func (a *APIServer) agentHookSkillAssetDecision(ctx context.Context, req agentHookRequest) (config.AssetPolicyDecision, bool) {
	toolInput := decodeAgentHookToolInput(req.ToolArgs)
	probe := skillProbeFromFields(req.ToolName, toolInput, req.Payload)
	return a.evaluateRuntimeSkillAssetPolicy(ctx, req.ConnectorName, req.HookEventName, probe)
}

// decodeAgentHookToolInput decodes ToolArgs into a generic map so
// the asset-policy probe helpers can pull command / arguments /
// nested fields. Returns nil on malformed JSON; callers tolerate
// a nil map (the probe falls back to tool-name / payload heuristics).
func decodeAgentHookToolInput(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// dispatchAgentHookNotification mirrors dispatchClaudeCodeHookNotification
// / dispatchCodexHookNotification but for the five generic hook-only
// connectors. Routing contract:
//
//   - action=="block"                              → OnBlock        (enforced)
//   - rawAction=="block" + (wouldBlock||!block)    → OnWouldBlock   (observe-block)
//   - action=="confirm"                            → OnApprovalPending (real native ask)
//   - rawAction=="confirm" && action!="confirm"    → OnWouldBlock(WouldAsk=true)
//
// The last case is the "would have asked but did not" bucket and
// covers two concrete scenarios:
//
//   - observe mode for any connector — mapHookAction returns
//     ("allow", false) so the response carries permission=allow and
//     no chat ask is issued.
//   - cursor beforeReadFile (and any other event missing from
//     caps.AskEvents) — confirm gets demoted to alert so, again, no
//     chat ask is issued.
//
// Both belong in the would-block category, NOT in OnApprovalPending,
// because OnApprovalPending implies "the user has a chat reply box
// open right now". By collapsing them onto OnWouldBlock with
// WouldAsk=true, a single `notifications.block_would_block: false`
// switch silences every observe-mode hook notification (would-block
// and would-ask alike) — which is the right knob for users running
// connectors in pure observe mode and wanting a quiet desktop.
//
// Reason is run through redaction.ForSinkReason before display so a
// regex-match verdict carrying echoed user content (PII / secrets)
// does not land verbatim on the OS toast. Connector is taken from
// req.ConnectorName so the subtitle reads e.g. "DefenseClaw hermes
// PreToolUse" — operators paging through toasts can attribute each
// one to a specific framework without opening the audit log.
func (a *APIServer) dispatchAgentHookNotification(req agentHookRequest, action, rawAction, severity, reason string, wouldBlock bool, evalCtx hookEvaluationContext) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(req.ToolName)
	if target == "" {
		target = req.HookEventName
	}
	safeReason := string(redaction.ForSinkReason(reason))
	base := notifier.BlockEvent{
		Source:       notifier.SourceHook,
		Target:       target,
		Reason:       safeReason,
		Severity:     severity,
		Connector:    req.ConnectorName,
		Event:        req.HookEventName,
		EvaluationID: evalCtx.EvaluationID,
		RuleIDs:      evalCtx.RuleIDs,
	}
	switch {
	case action == "block":
		a.notifier.OnBlock(base)
	case rawAction == "block" && (wouldBlock || action != "block"):
		a.notifier.OnWouldBlock(base)
	case action == "confirm":
		// Native chat-side ask actually issued — only path that
		// belongs in the approvals category.
		a.notifier.OnApprovalPending(notifier.ApprovalEvent{
			Subject:      fmt.Sprintf("%s (%s)", target, req.HookEventName),
			Reason:       safeReason,
			Severity:     severity,
			Source:       notifier.SourceHook,
			Connector:    req.ConnectorName,
			Event:        req.HookEventName,
			EvaluationID: evalCtx.EvaluationID,
			RuleIDs:      evalCtx.RuleIDs,
		})
	case rawAction == "confirm":
		// Verdict was confirm but the user will not see a chat ask
		// (observe mode, or event not in caps.AskEvents). Route
		// through the would-block category so a single
		// block_would_block=false silences all observe-mode noise.
		evt := base
		evt.WouldAsk = true
		a.notifier.OnWouldBlock(evt)
	}
}

func (a *APIServer) agentHookEnabled(name string) bool {
	if a.scannerCfg == nil {
		return false
	}
	if a.scannerCfg.ConnectorHookConfig(name).Enabled {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(a.scannerCfg.Guardrail.Connector), name)
}

func (a *APIServer) agentHookMode(name string) string {
	mode := "observe"
	if a.scannerCfg != nil {
		hookCfg := a.scannerCfg.ConnectorHookConfig(name)
		mode = strings.TrimSpace(hookCfg.Mode)
		if mode == "" || strings.EqualFold(mode, "inherit") {
			mode = strings.TrimSpace(a.scannerCfg.Guardrail.Mode)
		}
	}
	return normalizeAgentHookMode(mode)
}

func normalizeAgentHookMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "action", "enforce":
		return "action"
	default:
		return "observe"
	}
}

func (a *APIServer) hookCapabilities(name string) connector.HookCapability {
	return a.hookProfileForConnector(name).Capabilities
}

func (a *APIServer) configDataDir() string {
	if a != nil && a.scannerCfg != nil {
		return a.scannerCfg.DataDir
	}
	return ""
}

func (a *APIServer) connectorWorkspaceDir() string {
	if a != nil && a.scannerCfg != nil {
		return a.scannerCfg.ConnectorWorkspaceDir()
	}
	return currentWorkingDir()
}

func (a *APIServer) apiAddrForCapabilities() string {
	if a != nil && strings.TrimSpace(a.addr) != "" {
		return strings.TrimSpace(a.addr)
	}
	return "127.0.0.1:18970"
}

func currentWorkingDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

func mapHookAction(rawAction, mode, event string, caps connector.HookCapability) (string, bool) {
	return mapHookActionForProfile(rawAction, mode, event, caps, connector.HookProfile{})
}

func mapHookActionForProfile(rawAction, mode, event string, caps connector.HookCapability, profile connector.HookProfile) (string, bool) {
	if profile.MapVerdict != nil {
		out := profile.MapVerdict(connector.HookVerdictInput{
			RawAction: rawAction,
			Event:     event,
			Mode:      mode,
			Caps:      caps,
		})
		return out.Action, out.WouldBlock
	}
	rawAction = normalizeCodexAction(rawAction)
	if rawAction == "" {
		rawAction = "allow"
	}
	if mode != "action" {
		return "allow", rawAction == "block"
	}
	switch rawAction {
	case "block":
		if caps.CanBlock && eventIn(event, caps.BlockEvents) {
			return "block", false
		}
		return "allow", true
	case "confirm":
		if caps.CanAskNative && eventIn(event, caps.AskEvents) {
			return "confirm", false
		}
		return "alert", false
	default:
		return rawAction, false
	}
}

func agentHookResponseFor(req agentHookRequest, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool, caps connector.HookCapability) agentHookResponse {
	return agentHookResponseForProfile(connector.HookProfile{}, req, action, rawAction, severity, reason, findings, mode, wouldBlock, caps)
}

func agentHookResponseForProfile(profile connector.HookProfile, req agentHookRequest, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool, caps connector.HookCapability) agentHookResponse {
	if severity == "" {
		severity = "NONE"
	}
	if action == "" {
		action = "allow"
	}
	if rawAction == "" {
		rawAction = action
	}
	safeReason := string(redaction.ForSinkReason(reason))
	additional := genericHookAdditionalContext(req.ConnectorName, rawAction, severity, safeReason, wouldBlock)
	resp := agentHookResponse{
		Action:            action,
		RawAction:         rawAction,
		Severity:          severity,
		Reason:            safeReason,
		Findings:          findings,
		Mode:              mode,
		WouldBlock:        wouldBlock,
		AdditionalContext: additional,
	}
	if profile.Respond != nil {
		out := profile.Respond(connector.HookRespondInput{
			Req:               hookProfileRequestFromAgentHook(req),
			Action:            action,
			RawAction:         rawAction,
			Reason:            safeReason,
			AdditionalContext: additional,
			Caps:              caps,
		})
		if out.FieldName != "" && profile.ResponseFieldName == "" {
			profile.ResponseFieldName = out.FieldName
		}
		resp.HookOutput = out.Output
	} else {
		resp.HookOutput = hookOutputFor(req, action, rawAction, safeReason, additional, caps)
	}
	return resp
}

func hookProfileRequestFromAgentHook(req agentHookRequest) connector.HookProfileRequest {
	return connector.HookProfileRequest{
		ConnectorName: req.ConnectorName,
		HookEventName: req.HookEventName,
		SessionID:     req.SessionID,
		TurnID:        req.TurnID,
		AgentID:       req.AgentID,
		AgentName:     req.AgentName,
		AgentType:     req.AgentType,
		CWD:           req.CWD,
		ToolName:      req.ToolName,
		Content:       req.Content,
		Direction:     req.Direction,
		Payload:       req.Payload,
	}
}

func hookOutputFor(req agentHookRequest, action, rawAction, reason, additional string, caps connector.HookCapability) map[string]interface{} {
	reason = connectorReason(req.ConnectorName, action, req.ToolName, reason)
	switch req.ConnectorName {
	case "hermes":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
		if req.HookEventName == "pre_llm_call" && additional != "" {
			return map[string]interface{}{"context": additional}
		}
	case "cursor":
		switch action {
		case "block":
			return map[string]interface{}{"continue": true, "permission": "deny", "user_message": reason, "agent_message": reason}
		case "confirm":
			return map[string]interface{}{"continue": true, "permission": "ask", "user_message": reason, "agent_message": reason}
		case "alert":
			if additional != "" {
				return map[string]interface{}{"continue": true, "permission": "allow", "agent_message": additional}
			}
		}
	case "windsurf":
		if action == "block" {
			return map[string]interface{}{"message": reason}
		}
	case "geminicli":
		if action == "block" {
			return map[string]interface{}{"decision": "deny", "reason": reason}
		}
		if action == "alert" && additional != "" {
			return map[string]interface{}{"systemMessage": additional}
		}
	case "copilot":
		return copilotHookOutput(req.HookEventName, action, rawAction, reason, additional)
	case "openhands":
		if action == "block" {
			return map[string]interface{}{"decision": "deny", "reason": reason}
		}
		if (action == "alert" || rawAction == "confirm") && additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	}
	if rawAction == "confirm" && additional != "" && !caps.CanAskNative {
		return map[string]interface{}{"systemMessage": additional}
	}
	return nil
}

func copilotHookOutput(event, action, rawAction, reason, additional string) map[string]interface{} {
	switch canonicalEvent(event) {
	case "pretooluse":
		switch action {
		case "confirm":
			return map[string]interface{}{"permissionDecision": "ask", "permissionDecisionReason": reason}
		case "block":
			return map[string]interface{}{"permissionDecision": "deny", "permissionDecisionReason": reason}
		}
	case "permissionrequest":
		if action == "block" {
			return map[string]interface{}{"behavior": "deny", "message": reason, "interrupt": true}
		}
	case "agentstop", "stop", "subagentstop":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
	case "posttoolusefailure":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	case "notification":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	}
	if rawAction == "confirm" && additional != "" {
		return map[string]interface{}{"additionalContext": additional}
	}
	return nil
}

func genericHookAdditionalContext(connectorName, rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s %s hook finding.", prefix, severity, connectorName)
	}
	return fmt.Sprintf("%s a %s %s hook finding: %s", prefix, severity, connectorName, reason)
}

// connectorReason renders the user-facing reason string surfaced by
// the per-connector hook_output JSON. Cursor and Copilot pass the
// "permission.user_message" / "permissionDecisionReason" verbatim
// to the operator (chat surface or modal), so a bare upstream reason
// like "matched policy: deny-rm-rf" is too terse to be actionable.
//
// When the upstream verdict already provides a sentence-shape reason
// we pass it through unchanged — operators have invested effort in
// crafting their policy reasons and we should not paper over them.
// We only synthesize a default when reason is empty, and the default
// is action-aware:
//
//   - block:                "DefenseClaw blocked <tool>. Run 'defenseclaw mcp list' / 'skill list' to review approved assets."
//   - confirm (ask):        "DefenseClaw needs your approval before <tool> can run."
//   - alert/allow_with_warn:"DefenseClaw flagged <tool> with a warning."
//   - allow / fallback:     "Allowed by DefenseClaw <connector> policy."
//
// The wording is short on purpose — "permissionDecisionReason"
// renders inside an OS-level approval prompt where long sentences
// get truncated. tool may be empty (e.g. UserPromptSubmit-class
// events); in that case we fall back to a tool-agnostic phrase.
func connectorReason(connectorName, action, tool, reason string) string {
	if r := strings.TrimSpace(reason); r != "" {
		return r
	}
	tool = strings.TrimSpace(tool)
	switch action {
	case "block":
		if tool == "" {
			return "DefenseClaw blocked this action. Run `defenseclaw mcp list` or `skill list` to review approved assets."
		}
		return fmt.Sprintf("DefenseClaw blocked %s. Run `defenseclaw mcp list` or `skill list` to review approved assets.", tool)
	case "confirm":
		if tool == "" {
			return "DefenseClaw needs your approval before this action can run."
		}
		return fmt.Sprintf("DefenseClaw needs your approval before %s can run.", tool)
	case "alert", "allow_with_warning":
		if tool == "" {
			return "DefenseClaw flagged this action with a warning."
		}
		return fmt.Sprintf("DefenseClaw flagged %s with a warning.", tool)
	default:
		if connectorName != "" {
			return fmt.Sprintf("Allowed by DefenseClaw %s policy.", connectorName)
		}
		return "Allowed by DefenseClaw policy."
	}
}

func eventIn(event string, events []string) bool {
	canon := canonicalEvent(event)
	for _, candidate := range events {
		if canonicalEvent(candidate) == canon {
			return true
		}
	}
	return false
}

func canonicalEvent(event string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	event = strings.ReplaceAll(event, "_", "")
	event = strings.ReplaceAll(event, "-", "")
	return event
}

func isGenericToolInspectionEvent(event string) bool {
	switch canonicalEvent(event) {
	case "pretooluse", "beforetool", "pretoolcall", "permissionrequest",
		"beforeshellexecution", "beforemcpexecution", "beforereadfile", "beforetabfileread",
		"prereadcode", "prewritecode", "preruncommand", "premcptooluse":
		return true
	default:
		return false
	}
}

func isPromptLikeEvent(event string) bool {
	switch canonicalEvent(event) {
	case "userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "preuserprompt",
		"prellmcall", "beforeagent", "beforemodel":
		return true
	default:
		return false
	}
}

func isResultLikeEvent(event string) bool {
	switch canonicalEvent(event) {
	case "posttooluse", "posttoolusefailure", "aftertool", "posttoolcall",
		"postreadcode", "postwritecode", "postruncommand", "postmcptooluse",
		"aftershellexecution", "aftermcpexecution", "afterfileedit", "aftertabfileedit",
		"afteragentresponse", "afteragentthought", "afteragent", "aftermodel":
		return true
	default:
		return false
	}
}

func firstString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if s := stringifyHookValue(obj[key]); strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func firstHookIdentityString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			if s := sanitizeHookIdentityValue(v); s != "" {
				return s
			}
		case json.Number:
			if s := sanitizeHookIdentityValue(v.String()); s != "" {
				return s
			}
		case float64:
			if s := sanitizeHookIdentityValue(strconv.FormatFloat(v, 'f', -1, 64)); s != "" {
				return s
			}
		case bool:
			if s := sanitizeHookIdentityValue(strconv.FormatBool(v)); s != "" {
				return s
			}
		}
	}
	return ""
}

func sanitizeHookIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 128 {
		value = string(runes[:128])
	}
	return value
}

func firstValue(obj map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := obj[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func objectAt(obj map[string]interface{}, key string) map[string]interface{} {
	if child, ok := obj[key].(map[string]interface{}); ok {
		return child
	}
	return nil
}

func stringifyHookValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
