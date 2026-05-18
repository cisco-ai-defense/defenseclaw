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
// Why a singleton: NewDefaultRegistry registers eight builtin
// connectors and walks the plugin directory; on the hook hot path
// (every hookCapabilities call), constructing it per-invocation
// turns each block-vs-allow decision into eight allocations and a
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

		req := normalizeAgentHookRequest(connectorName, payload)
		if req.HookEventName == "" {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "missing_event", int64(len(b)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook event name is required"})
			return
		}
		req.CWD = sanitizeHookCWD(req.CWD)
		ctx := enrichAgentHookContext(r.Context(), req)

		// PR 6 / Phase D — profile-driven raw event remembering.
		// Every connector that maps to a hook event with prompt /
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
		// The "BespokeOrGeneric" dispatcher routes claudecode/codex
		// through their connector-specific dedupers (which probe
		// fields like req.ToolUseID / req.PermissionRequestID that
		// the generic agentHookRequest does not model) and every
		// other connector through the generic path. See
		// bespoke_hook_adapter.go for the rationale on why these
		// three pieces (eval / emit / dedupe) stay bespoke even
		// after we deleted the bespoke HTTP handlers.
		rawEventIDs := a.rememberBespokeOrGenericRawEvents(connectorName, req, b, payload)

		// Emit the LLM event (prompt/tool/response) BEFORE the
		// evaluator runs. Capturing what the agent attempted
		// regardless of whether the evaluation later blocks it
		// keeps the audit trail honest. Bespoke emitters apply
		// to claudecode/codex so existing PromptID/ToolID
		// correlation chains remain identical to the pre-PR-#284
		// wire format; every other connector uses the generic
		// agentHookRequest-driven emitter.
		a.emitBespokeOrGenericLLMEvent(ctx, connectorName, req, b, payload, rawEventIDs)

		// Dispatch evaluation. claudecode/codex route through
		// their bespoke evaluators (different event-name switches,
		// connector-specific scans, asset-policy probes); every
		// other connector flows through evaluateAgentHook. The
		// returned agentHookResponse carries the connector's
		// output map in HookOutput — handleAgentHook below renders
		// that map under the right top-level JSON key
		// (claude_code_output / codex_output / hook_output) so the
		// wire shape stays byte-identical for each agent CLI.
		//
		// safeEvaluateHook wraps the evaluator in a deferred
		// recover: a panic in any connector-specific scan / asset
		// probe / inspectToolPolicy path no longer terminates the
		// HTTP request uncaught. Pre-PR-#284 each bespoke handler
		// could panic independently (blast radius: one connector);
		// post-fold this is the SOLE hot path for every connector,
		// so unrecovered panics would take the whole agent estate
		// down at once. The recover emits a RecordPanic counter
		// with subsystem=gateway and synthesises a safe fail-open
		// response (action=allow, would_block=true, reason carries
		// "internal evaluator error"). Operators alert on
		// defenseclaw.panics.total{subsystem="gateway"} and on the
		// `result="panic"` label on the standard hook invocation
		// counter.
		t0 := time.Now()
		resp, panicked := a.safeEvaluateHook(ctx, connectorName, req, b, payload)
		elapsed := time.Since(t0)
		enrichAgentHookSpan(ctx, req, resp, elapsed)
		if panicked {
			enrichAgentHookSpanPanic(ctx)
		}

		if a.health != nil {
			a.health.RecordConnectorRequest()
			if resp.Action == "block" {
				a.health.RecordToolBlock()
			}
			if isGenericToolInspectionEvent(req.HookEventName) {
				a.health.RecordToolInspection()
			}
		}

		if a.otel != nil {
			result := "ok"
			reason := normalizeHookReasonLabel(resp.Action, resp.WouldBlock)
			if panicked {
				result = "panic"
				reason = "panic"
			}
			a.otel.RecordConnectorHookInvocation(ctx, connectorName, req.HookEventName, result, reason, float64(elapsed.Milliseconds()))
			a.otel.RecordInspectEvaluation(ctx, connectorName+":"+req.HookEventName, resp.Action, resp.Severity)
			a.otel.RecordInspectLatency(ctx, connectorName+":"+req.HookEventName, float64(elapsed.Milliseconds()))
			// PR 3 / Phase B.2 — parity metrics every connector emits.
			// Outcome is unconditional (the dashboard panel always
			// has a series per connector); token usage runs only when
			// the payload carries usable counters so we never emit
			// zero-valued series that bloat the TSDB.
			a.otel.RecordHookOutcome(ctx, connectorName, req.HookEventName, resp.Action, resp.Severity, resp.WouldBlock)
			usage := extractHookPayloadTokenUsage(req.Payload)
			a.otel.RecordHookTokenUsage(ctx, connectorName, usage.Model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
			a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, result, 1, int64(len(b)),
				fmt.Sprintf("source=hook connector=%s event=%s tool=%s decision=%s raw_action=%s would_block=%v mode=%s duration_ms=%d result=%s",
					connectorName, req.HookEventName, req.ToolName, resp.Action, resp.RawAction, resp.WouldBlock, resp.Mode, elapsed.Milliseconds(), result))
		}

		// Build the structured envelope once and let
		// logConnectorHookAuditEnvelope persist BOTH the JSON
		// envelope AND the legacy key=value tail in the audit
		// `details` column. The envelope carries the same fields
		// the legacy formatter produced (action, raw_action,
		// severity, mode, would_block, elapsed) plus structured
		// raw-event metadata; the dual format means existing
		// operator log greps and new jq-based pipelines are both
		// served without an env-var toggle.
		envResult := "ok"
		if panicked {
			envResult = "panic"
		}
		env := HookAuditEnvelope{
			Connector:   connectorName,
			Event:       req.HookEventName,
			Result:      envResult,
			Action:      resp.Action,
			RawAction:   resp.RawAction,
			Severity:    resp.Severity,
			Mode:        resp.Mode,
			Reason:      resp.Reason,
			WouldBlock:  resp.WouldBlock,
			ElapsedMs:   elapsed.Milliseconds(),
			BodyBytes:   int64(len(b)),
			RawOrigin:   rawOriginIfHook(rawEventIDs),
			RawEventIDs: rawEventIDs,
		}
		if panicked {
			env.Extra = map[string]string{"panic": "true"}
		}
		attachRawPayload(&env, b)
		a.logConnectorHookAuditEnvelope(ctx, env)

		// Render the wire response with the connector-specific
		// top-level field name for the output map (e.g.
		// "claude_code_output", "codex_output", "hook_output").
		// Without this projection, agentHookResponse always
		// renders the output under "hook_output", which Claude
		// Code and Codex agent CLIs reject. See
		// renderAgentHookResponse() for the canonical
		// connector → field-name mapping.
		a.writeJSON(w, http.StatusOK, renderAgentHookResponse(connectorName, resp))
	}
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
		out[hookOutputFieldName(connectorName)] = resp.HookOutput
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
		a.otel.RecordConnectorHookInvocation(ctx, connectorName, req.HookEventName, result, reason, float64(elapsed.Milliseconds()))
		a.otel.RecordInspectEvaluation(ctx, connectorName+":"+req.HookEventName, resp.Action, resp.Severity)
		a.otel.RecordInspectLatency(ctx, connectorName+":"+req.HookEventName, float64(elapsed.Milliseconds()))
		a.otel.RecordHookOutcome(ctx, connectorName, req.HookEventName, resp.Action, resp.Severity, resp.WouldBlock)
		usage := extractHookPayloadTokenUsage(req.Payload)
		a.otel.RecordHookTokenUsage(ctx, connectorName, usage.Model, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens)
		a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, result, 1, int64(len(rawBody)),
			fmt.Sprintf("source=hook connector=%s event=%s tool=%s decision=%s raw_action=%s would_block=%v mode=%s duration_ms=%d synthetic=true result=%s",
				connectorName, req.HookEventName, req.ToolName, resp.Action, resp.RawAction, resp.WouldBlock, resp.Mode, elapsed.Milliseconds(), result))
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
		AuditActionOverride: string(audit.ActionConnectorHookSynthetic),
		Extra:               extra,
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
	span.SetAttributes(attribute.Bool("defenseclaw.hook.panic", true))
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

// hashRawPayloadHex returns the first 16 hex chars of the SHA-256
// of body. 64 bits is enough to deduplicate replay-storms in SIEM
// rules without bloating audit rows; full digest would be 64 hex
// chars per truncated row.
func hashRawPayloadHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

// safeEvaluateHook wraps the bespoke-or-generic evaluator with a
// deferred recover so a panic in any connector-specific code path
// (asset-policy probes, scanner invocations, codex notify-bridge
// fan-out, …) cannot terminate the HTTP request uncaught.
//
// Threat model: pre-PR-#284 each connector owned its own bespoke
// HTTP handler, so a panic blast-radius was one connector. After
// the full fold this is the SOLE hot path for every connector;
// an unrecovered panic would take the entire agent estate down at
// once. The recover:
//
//   - records defenseclaw.panics.total{subsystem="gateway"} (the
//     v7 process-health counter from track-7-capacity-slo) so
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
) (resp agentHookResponse, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			resp = safeHookPanicResponse(connectorName, req.HookEventName, r)
			a.handleHookPanic(ctx, connectorName, req.HookEventName, r)
		}
	}()
	resp = a.evaluateBespokeOrGenericHook(ctx, connectorName, req, rawBody, payload)
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
// F2 fix. Post PR #284 every connector hook flows through
// handleAgentHook → enrichAgentHookContext → refreshAuditEnvelopeFromHook
// → this helper, so there is exactly one place where the audit
// correlation envelope gets payload-derived session_id / agent_id
// stitched on. The function is kept exported-by-package (lower-case
// first letter is fine; it's gateway-internal) so other unified
// paths (handleAgentHookSynthetic for codex notify) can call it
// directly with an already-resolved AgentIdentity.
//
// History: the original F2 patch wired only the unified path; live
// Splunk verification then proved claudecode + codex hook rows
// landed with session_id=NULL because each owned a separate
// bespoke HTTP handler that never invoked the unified
// enrichAgentHookContext. PR #284 deleted those bespoke handlers
// outright so the regression class is impossible going forward —
// see CHANGELOG and bespoke_hook_adapter.go for the rationale.
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
	attrs := []attribute.KeyValue{
		attribute.String("defenseclaw.connector", req.ConnectorName),
		attribute.String("defenseclaw.connector.source", req.ConnectorName),
		attribute.String("defenseclaw.connector.signal", "hook"),
		attribute.String("defenseclaw.connector.result", "ok"),
		attribute.String("defenseclaw.hook.reason", reason),
		attribute.String("defenseclaw.telemetry.source", "hook"),
		attribute.String("defenseclaw.hook.event", req.HookEventName),
		attribute.String("defenseclaw.tool.name", req.ToolName),
		attribute.String("defenseclaw.workspace", req.CWD),
		attribute.String("defenseclaw.decision", resp.Action),
		attribute.String("defenseclaw.raw_action", resp.RawAction),
		attribute.Bool("defenseclaw.would_block", resp.WouldBlock),
		attribute.String("defenseclaw.mode", resp.Mode),
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
	cwd := firstString(payload, "cwd", "working_directory", "workingDirectory")
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
// production binary (we have learned the hard way that build-tagged
// seams drift out of sync with their callers — see PR #189).
var hookEvaluatorPanicHook func()

func (a *APIServer) evaluateAgentHook(ctx context.Context, req agentHookRequest) agentHookResponse {
	if hookEvaluatorPanicHook != nil {
		hookEvaluatorPanicHook()
	}
	mode := a.agentHookMode(req.ConnectorName)
	if a.scannerCfg != nil && !a.agentHookEnabled(req.ConnectorName) {
		return agentHookResponseFor(req, "allow", "allow", "NONE", "", nil, mode, false, connector.HookCapability{})
	}

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
	caps := a.hookCapabilities(req.ConnectorName)
	action, wouldBlock := mapHookAction(rawAction, mode, req.HookEventName, caps)
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
			capable, capableWouldBlock := mapHookAction("block", mode, req.HookEventName, caps)
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

	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchAgentHookNotification(req, action, rawAction, severity, reason, wouldBlock)
	}
	return agentHookResponseFor(req, action, rawAction, severity, reason, findings, mode, wouldBlock, caps)
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
func (a *APIServer) dispatchAgentHookNotification(req agentHookRequest, action, rawAction, severity, reason string, wouldBlock bool) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(req.ToolName)
	if target == "" {
		target = req.HookEventName
	}
	safeReason := string(redaction.ForSinkReason(reason))
	base := notifier.BlockEvent{
		Source:    notifier.SourceHook,
		Target:    target,
		Reason:    safeReason,
		Severity:  severity,
		Connector: req.ConnectorName,
		Event:     req.HookEventName,
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
			Subject:   fmt.Sprintf("%s (%s)", target, req.HookEventName),
			Reason:    safeReason,
			Severity:  severity,
			Source:    notifier.SourceHook,
			Connector: req.ConnectorName,
			Event:     req.HookEventName,
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
	reg := a.connectorRegistry
	if reg == nil {
		// Lazy singleton — see getFallbackConnectorRegistry. The
		// hook hot path used to call connector.NewDefaultRegistry()
		// per request, paying a fresh registry build (eight
		// connectors + plugin directory walk) on every block /
		// allow decision in tests that bypass NewAPIServer. The
		// production path always supplies a non-nil
		// a.connectorRegistry; this branch only fires for legacy
		// constructions, and it now uses a process-singleton to
		// keep p99 hookCapabilities cost flat.
		reg = getFallbackConnectorRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return connector.HookCapability{}
	}
	hp, ok := conn.(connector.HookCapabilityProvider)
	if !ok {
		return connector.HookCapability{}
	}
	return hp.HookCapabilities(connector.SetupOpts{
		DataDir:      a.configDataDir(),
		APIAddr:      a.apiAddrForCapabilities(),
		WorkspaceDir: currentWorkingDir(),
	})
}

func (a *APIServer) configDataDir() string {
	if a != nil && a.scannerCfg != nil {
		return a.scannerCfg.DataDir
	}
	return ""
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
	resp.HookOutput = hookOutputFor(req, action, rawAction, safeReason, additional, caps)
	return resp
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

func reasonOrDefaultGeneric(connectorName, reason string) string {
	if strings.TrimSpace(reason) != "" {
		return reason
	}
	return fmt.Sprintf("Blocked by DefenseClaw %s policy.", connectorName)
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
