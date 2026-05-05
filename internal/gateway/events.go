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
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// gatewayEvents is the process-wide structured event writer. It is
// installed by the sidecar boot path and consumed by the verdict /
// judge / lifecycle emission helpers in this package.
//
// A nil writer is a valid "events disabled" state — every helper
// checks for nil so unit tests and libraries that import internal/
// gateway without running the sidecar can no-op cleanly.
var (
	gatewayEventsMu sync.RWMutex
	gatewayEvents   *gatewaylog.Writer

	// judgeResponseStore persists v7-correlated judge rows when set
	// (tests, or sidecar wiring). When nil, legacy judgePersistor may
	// still run for backward compatibility.
	judgeResponseStoreMu sync.RWMutex
	judgeResponseStore   *JudgeStore

	// judgePersistor is an optional hook invoked for every Judge
	// event when guardrail.retain_judge_bodies is on and the
	// sidecar wired up a persistence callback. Left nil in unit
	// tests and in the "retention off" path.
	//
	// Signature carries Direction alongside the payload because the
	// JudgePayload envelope intentionally does NOT — direction
	// belongs to the surrounding Event. A prior revision dropped
	// this data when persisting, so every SQLite row wrote an empty
	// direction regardless of inbound/outbound.
	//
	// v7: also carries the request ctx + per-emission opts
	// (tool_name/tool_id/policy_id/destination_app) so the
	// persistor can merge the request-scoped envelope with the
	// emit-scoped overrides before writing the audit row. Before
	// this, every llm-judge-response audit row had
	// agent/session/run/trace/request NULL because the closure
	// had no request context to pull from.
	judgePersistor func(ctx context.Context, p gatewaylog.JudgePayload, dir gatewaylog.Direction, opts JudgeEmitOpts)
)

// SetJudgePersistor installs the optional SQLite persistence hook
// invoked from emitJudge when retention is enabled. Passing nil
// disables persistence (safe default). The callback receives the
// raw payload plus the request direction so downstream storage
// can tag whether the judge fired on an inbound prompt or an
// outbound completion.
func SetJudgePersistor(fn func(ctx context.Context, p gatewaylog.JudgePayload, dir gatewaylog.Direction, opts JudgeEmitOpts)) {
	gatewayEventsMu.Lock()
	defer gatewayEventsMu.Unlock()
	judgePersistor = fn
}

// SetJudgeResponseStore installs the v7 SQLite writer for retained judge
// bodies. When non-nil it takes precedence over SetJudgePersistor for
// persistence (only one path runs per emit).
func SetJudgeResponseStore(js *JudgeStore) {
	judgeResponseStoreMu.Lock()
	defer judgeResponseStoreMu.Unlock()
	judgeResponseStore = js
}

func activeJudgeStore() *JudgeStore {
	judgeResponseStoreMu.RLock()
	defer judgeResponseStoreMu.RUnlock()
	return judgeResponseStore
}

// judgePersist returns the currently installed persistor (may be nil).
func judgePersist() func(ctx context.Context, p gatewaylog.JudgePayload, dir gatewaylog.Direction, opts JudgeEmitOpts) {
	gatewayEventsMu.RLock()
	defer gatewayEventsMu.RUnlock()
	return judgePersistor
}

// SetEventWriter installs the process-wide gatewaylog.Writer. The
// sidecar calls this exactly once, right after the writer is
// constructed, before any request handling begins.
func SetEventWriter(w *gatewaylog.Writer) {
	gatewayEventsMu.Lock()
	defer gatewayEventsMu.Unlock()
	gatewayEvents = w
}

// EventWriter returns the active writer (may be nil).
func EventWriter() *gatewaylog.Writer {
	gatewayEventsMu.RLock()
	defer gatewayEventsMu.RUnlock()
	return gatewayEvents
}

// emitEvent is the low-level helper that all other emitters delegate
// to. It enforces the "gateway.jsonl (and every downstream OTel /
// Splunk / webhook fan-out) never sees unredacted PII" invariant by
// scrubbing caller-supplied free-form strings here. Rule IDs and
// canonical IDs survive (ForSinkReason/ForSinkString preserve the
// metadata token shape); matched literals are masked with a
// deterministic hash prefix so operators can still correlate.
//
// Copy-on-write discipline: every payload struct that we need to
// mutate is shallow-copied before we touch its fields, so a caller
// that kept a reference to the original (e.g. for a subsequent
// audit.Log call) does NOT observe the redacted values. The
// scrubbing here is a sink-only transform.
//
// Lifecycle.Details and Diagnostic.Fields are NOT redacted. Those
// bags carry operator-authored metadata — ports, file paths,
// version strings, subsystem names — which operators need in the
// clear to triage incidents. Redacting them turns every startup
// event into an opaque smear of `<redacted len=6 sha=…>`
// placeholders, breaking the primary use case for structured
// lifecycle logs. If a caller ever needs to put user-provided
// content into one of these fields they must run it through the
// appropriate redaction helper before the emit.
// stampEventCorrelation populates the eight correlation / identity
// fields of a gatewaylog.Event from a request context. Called by
// every hot-path emit helper so the contract "verdict/judge/error
// events carry run_id, request_id, session_id, trace_id, agent_id,
// agent_name, agent_instance_id, sidecar_instance_id whenever the
// enclosing request has them" is enforced at a single choke point
// instead of at each call site.
//
// Nil ctx is tolerated (boot/shutdown emits) and leaves every field
// at the caller-supplied value. Non-empty caller-supplied values
// always win — this helper fills in blanks, never overwrites.
func stampEventCorrelation(ev *gatewaylog.Event, ctx context.Context) {
	if ev == nil || ctx == nil {
		return
	}
	if ev.RequestID == "" {
		ev.RequestID = RequestIDFromContext(ctx)
	}
	if ev.SessionID == "" {
		ev.SessionID = SessionIDFromContext(ctx)
	}
	if ev.TraceID == "" {
		ev.TraceID = TraceIDFromContext(ctx)
		if ev.TraceID == "" {
			if sp := trace.SpanFromContext(ctx); sp != nil && sp.SpanContext().IsValid() {
				ev.TraceID = sp.SpanContext().TraceID().String()
			}
		}
	}
	if ev.RunID == "" {
		ev.RunID = gatewaylog.ProcessRunID()
	}
	id := AgentIdentityFromContext(ctx)
	if ev.AgentID == "" {
		ev.AgentID = id.AgentID
	}
	if ev.AgentName == "" {
		ev.AgentName = id.AgentName
	}
	if ev.AgentType == "" {
		ev.AgentType = id.AgentType
	}
	if ev.AgentInstanceID == "" {
		ev.AgentInstanceID = id.AgentInstanceID
	}
	if ev.SidecarInstanceID == "" {
		ev.SidecarInstanceID = id.SidecarInstanceID
	}
}

func emitEvent(ctx context.Context, e gatewaylog.Event) {
	w := EventWriter()
	if w == nil {
		return
	}
	stampEventCorrelation(&e, ctx)
	if v := e.Verdict; v != nil {
		cp := *v
		cp.Reason = redaction.ForSinkReason(cp.Reason)
		e.Verdict = &cp
	}
	if j := e.Judge; j != nil {
		cp := *j
		// RawResponse routinely echoes the triggering
		// prompt verbatim — sinks must only ever see the
		// redacted form. ParseError is short caller-owned
		// metadata but we redact it too in case a parser
		// embeds a snippet of the offending body.
		cp.RawResponse = redaction.ForSinkString(cp.RawResponse)
		cp.ParseError = redaction.ForSinkString(cp.ParseError)
		e.Judge = &cp
	}
	if er := e.Error; er != nil {
		cp := *er
		cp.Message = redaction.ForSinkString(cp.Message)
		cp.Cause = redaction.ForSinkString(cp.Cause)
		e.Error = &cp
	}
	if p := e.LLMPrompt; p != nil {
		cp := *p
		if cp.Prompt != "" {
			cp.Prompt = redaction.ForSinkMessageContent(cp.Prompt)
		}
		if cp.RawRequestBody != "" {
			cp.RawRequestBody = redaction.ForSinkMessageContent(cp.RawRequestBody)
		}
		e.LLMPrompt = &cp
	}
	if r := e.LLMResponse; r != nil {
		cp := *r
		if cp.Response != "" {
			cp.Response = redaction.ForSinkMessageContent(cp.Response)
		}
		if cp.RawResponseBody != "" {
			cp.RawResponseBody = redaction.ForSinkMessageContent(cp.RawResponseBody)
		}
		e.LLMResponse = &cp
	}
	if t := e.Tool; t != nil {
		cp := *t
		if cp.ToolInput != "" {
			cp.ToolInput = redaction.ForSinkMessageContent(cp.ToolInput)
		}
		if cp.ToolOutput != "" {
			cp.ToolOutput = redaction.ForSinkMessageContent(cp.ToolOutput)
		}
		e.Tool = &cp
	}
	w.Emit(e)
}

// emitVerdict records a single guardrail-pipeline stage decision.
// ctx carries the request correlation + agent identity that Gets
// stamped onto the envelope. Pass context.Background() when emitting
// outside a request (boot fall-backs, background self-tests).
func emitVerdict(
	ctx context.Context,
	stage gatewaylog.Stage,
	direction gatewaylog.Direction,
	model string,
	action, reason string,
	severity gatewaylog.Severity,
	categories []string,
	latencyMs int64,
) {
	// Plan B6 / S0.10: VerdictPayload.Reason is documented as
	// "short, redacted" but the redactor pipeline DOES legitimately
	// receive raw-secret strings on the way in (the redaction layer
	// strips them in-place before the wire emit). Scrub assertion
	// would fight that path; the canary lives only on the egress
	// shape where no caller has any legitimate reason to pass a
	// credential prefix. See emitEgress in this file.
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventVerdict,
		Severity:  severity,
		Direction: direction,
		Model:     model,
		Verdict: &gatewaylog.VerdictPayload{
			Stage:      stage,
			Action:     action,
			Reason:     reason,
			Categories: categories,
			LatencyMs:  latencyMs,
		},
	})
}

// JudgeEmitOpts carries optional correlation for judge persistence and payloads.
type JudgeEmitOpts struct {
	Findings       []gatewaylog.Finding
	ToolName       string
	ToolID         string
	PolicyID       string
	DestinationApp string
}

// emitJudge records a single LLM-judge invocation. raw may be empty
// when guardrail.retain_judge_bodies is off — the writer still emits
// the surrounding metadata (latency, model, verdict) so operators
// can see judge health without inspecting PII-heavy bodies.
func emitJudge(
	ctx context.Context,
	kind, model string,
	direction gatewaylog.Direction,
	inputBytes int,
	latencyMs int64,
	action string,
	severity gatewaylog.Severity,
	parseError string,
	raw string,
	opts JudgeEmitOpts,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	payload := gatewaylog.JudgePayload{
		Kind:        kind,
		Model:       model,
		InputBytes:  inputBytes,
		LatencyMs:   latencyMs,
		Action:      action,
		Severity:    severity,
		ParseError:  parseError,
		RawResponse: raw,
		Findings:    opts.Findings,
	}

	// SQLite persistence runs first because emitEvent mutates its own
	// shallow copy of the payload (it scrubs RawResponse before
	// forwarding to the sinks pipeline). We want the local,
	// operator-owned store to receive the un-redacted body — retention
	// is explicit opt-in via guardrail.retain_judge_bodies and the SQLite
	// file is already covered by the same filesystem ACLs as the rest
	// of ~/.defenseclaw.
	if js := activeJudgeStore(); js != nil && raw != "" {
		_ = js.PersistJudgeEvent(ctx, direction, payload, opts.ToolName, opts.ToolID, opts.PolicyID, opts.DestinationApp)
	} else if persist := judgePersist(); persist != nil && raw != "" {
		persist(ctx, payload, direction, opts)
	}

	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventJudge,
		Severity:  severity,
		Direction: direction,
		Model:     model,
		Judge:     &payload,
	})
}

// emitLifecycle records a sidecar state change. Details is free-form
// caller-owned metadata — put path/port/version in here, not in the
// message field. ctx may be context.Background() for boot/shutdown
// transitions; when available (reloads triggered from an HTTP call)
// pass the request context so the envelope carries correlation.
//
// Transition is normalized to the gateway-event-envelope schema enum
// ("start"|"stop"|"ready"|"degraded"|"restored"|"alert"|"completed")
// so semantically meaningful caller strings (e.g. "init", "reload",
// "stream.open", "stream.close") do not trip the runtime validator
// and get dropped as schema violations. The original intent is
// preserved on details.transition_raw for audit fidelity.
func emitLifecycle(ctx context.Context, subsystem, transition string, details map[string]string) {
	normalized := normalizeLifecycleTransition(transition)
	if normalized != transition {
		if details == nil {
			details = map[string]string{}
		}
		if _, ok := details["transition_raw"]; !ok {
			details["transition_raw"] = transition
		}
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventLifecycle,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  subsystem,
			Transition: normalized,
			Details:    details,
		},
	})
}

// normalizeLifecycleTransition maps caller-supplied transition
// strings to the closed enum defined in
// internal/gatewaylog/schemas/gateway-event-envelope.json. Anything
// that cannot be cleanly mapped is coerced to "completed" — the
// least harmful terminal state — rather than left invalid.
func normalizeLifecycleTransition(t string) string {
	switch t {
	case "start", "stop", "ready", "degraded", "restored", "alert", "completed":
		return t
	case "init", "boot", "stream.open", "open", "connect":
		return "start"
	case "stream.close", "close", "disconnect":
		return "stop"
	case "reload", "refresh":
		return "completed"
	case "error", "failed", "failure":
		return "degraded"
	case "recover", "reconnect":
		return "restored"
	default:
		return "completed"
	}
}

// emitError records a structured gateway error. Prefer this over
// fmt.Fprintf(defaultLogWriter, ...) for anything that should surface
// in /health or alerting — stderr-only diagnostics stay in the
// legacy writer. ctx supplies the correlation triplet when available.
func emitError(ctx context.Context, subsystem, code, message string, cause error) {
	payload := &gatewaylog.ErrorPayload{
		Subsystem: subsystem,
		Code:      code,
		Message:   message,
	}
	if cause != nil {
		payload.Cause = cause.Error()
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventError,
		Severity:  gatewaylog.SeverityHigh,
		Error:     payload,
	})
}

// emitDiagnostic records a structured debug-level event. Use this
// for request-scoped state transitions that operators may want to
// replay (e.g. "regex produced N signals, routing to judge") — not
// for noisy per-byte traces.
//
// The gatewaylog.DiagnosticPayload schema uses {Component, Fields}
// (Fields is an open typed bag). Callers pass a simple string map
// for ergonomics; we widen it to interface{} here.
func emitDiagnostic(ctx context.Context, component, message string, details map[string]string) {
	var fields map[string]interface{}
	if len(details) > 0 {
		fields = make(map[string]interface{}, len(details))
		for k, v := range details {
			fields[k] = v
		}
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventDiagnostic,
		Severity:  gatewaylog.SeverityInfo,
		Diagnostic: &gatewaylog.DiagnosticPayload{
			Component: component,
			Message:   message,
			Fields:    fields,
		},
	})
}

// emitEgress records a classified outbound request observed by the
// guardrail proxy's passthrough path (Layer 1) or reported back from
// the TypeScript fetch-interceptor (Layer 3). Severity follows the
// branch × decision matrix:
//
//	branch=shape       decision=block  → HIGH     (silent-bypass attempt)
//	branch=passthrough decision=block  → MEDIUM   (SSRF defense in depth)
//	branch=shape       decision=allow  → MEDIUM   (operator opted into unknown hosts)
//	branch=known                        → INFO
//
// source is "go" for gateway-observed events and "ts" for
// fetch-interceptor-reported events. Callers MUST pass the exact
// enum values defined in EgressPayload — the schema validator will
// drop misspelled branches/decisions.
func emitEgress(ctx context.Context, p gatewaylog.EgressPayload) {
	if p.Source == "" {
		p.Source = "go"
	}
	sev := gatewaylog.SeverityInfo
	switch {
	case p.Branch == "shape" && p.Decision == "block":
		sev = gatewaylog.SeverityHigh
	case p.Branch == "passthrough" && p.Decision == "block":
		sev = gatewaylog.SeverityMedium
	case p.Branch == "shape" && p.Decision == "allow":
		sev = gatewaylog.SeverityMedium
	}
	// TargetPath is sanitized before truncation so query strings and
	// fragments never reach gateway.jsonl. Providers routinely
	// smuggle tokens / session IDs / tenant hints through the
	// query string (OpenAI-compat proxies use ?api-key=, Anthropic
	// compat uses ?token=, vendor SDKs append ?key=, Gemini uses
	// ?key=<API key>). We keep only the URL path component for
	// routing observability and drop everything after the first
	// '?' or '#' unconditionally. Callers that want to preserve a
	// specific path suffix for endpoint detection (e.g.
	// ":generateContent") are unaffected because the colon is a
	// path-valid character. TargetHost is a FQDN so 253 is the DNS
	// ceiling. Reason is operator-facing; 512 keeps it useful
	// without letting a misbehaving TS caller bloat gateway.jsonl.
	if p.TargetPath != "" {
		if i := strings.IndexAny(p.TargetPath, "?#"); i >= 0 {
			p.TargetPath = p.TargetPath[:i]
		}
	}
	if len(p.TargetPath) > 256 {
		p.TargetPath = p.TargetPath[:256]
	}
	if len(p.TargetHost) > 253 {
		p.TargetHost = p.TargetHost[:253]
	}
	if len(p.Reason) > 512 {
		p.Reason = p.Reason[:512]
	}
	// Plan B6 / S0.10: defense-in-depth scrub guard. The egress
	// schema is structurally key-free (no APIKey field) but a
	// future refactor that accidentally lands a credential in
	// TargetHost / TargetPath / Reason should crash CI before
	// shipping a leak. In production we log and continue — the
	// canary fires once, the operator reads the warning, and the
	// follow-up fix lands without an outage.
	redaction.MustAssertNoCredentials(p.TargetHost, p.TargetPath, p.Reason)
	// BodyShape is a known enum — reject anything else so a
	// malformed TS client cannot inject arbitrary strings into the
	// downstream contract. validEgressBranch / validEgressDecision
	// already enforce Branch / Decision at the HTTP boundary; shape
	// is the remaining free-form field.
	switch p.BodyShape {
	case "none", "messages", "prompt", "input", "contents", "":
		// ok
	default:
		p.BodyShape = "unknown"
	}
	// Source is also enum-shaped (go / ts / <empty>). Drop unknown
	// values so a rogue caller cannot forge "go"-origin events.
	if p.Source != "go" && p.Source != "ts" {
		p.Source = "ts"
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventEgress,
		Severity:  sev,
		Egress:    &p,
	})
	incEgressCounter(ctx, p.Branch, p.Decision, p.Source)
	if sev == gatewaylog.SeverityHigh {
		emitEgressAlert(ctx, p)
	}
}

// incEgressCounter + emitEgressAlert are package-level hooks so the
// telemetry / alerting wiring can be swapped out in tests without
// pulling in the full OTel stack. Default: stderr alert + no-op
// counter; SetEgressTelemetry upgrades both to real OTel sinks.
var (
	egressTelemetryMu sync.RWMutex
	egressTelemetry   *telemetry.Provider

	incEgressCounter = func(ctx context.Context, branch, decision, source string) {
		egressTelemetryMu.RLock()
		tp := egressTelemetry
		egressTelemetryMu.RUnlock()
		if tp == nil {
			return
		}
		tp.RecordEgress(ctx, branch, decision, source)
	}
	emitEgressAlert = func(ctx context.Context, p gatewaylog.EgressPayload) {
		// Always log to stderr — operators need a signal even when
		// the OTel stack is disabled. The gatewaylog Writer already
		// emits the structured event; this is the complementary
		// human-facing rail.
		//
		// Sanitize every caller-controlled string before printing to
		// stderr to prevent log injection: a malicious reason/host
		// containing "\n" could otherwise forge a fake following
		// alert line, breaking any tailing pipeline that treats a
		// line as the atomic unit.
		fmt.Fprintf(os.Stderr, "[guardrail] ALERT egress branch=%s decision=%s host=%s shape=%s reason=%s source=%s\n",
			sanitizeAlertField(p.Branch),
			sanitizeAlertField(p.Decision),
			sanitizeAlertField(p.TargetHost),
			sanitizeAlertField(p.BodyShape),
			sanitizeAlertField(p.Reason),
			sanitizeAlertField(p.Source))
	}
)

// sanitizeAlertField strips control characters from an operator-
// or network-supplied string before it is written to stderr or
// another line-delimited log stream. Prevents log injection
// (embedded "\n" forging a follow-up alert line) and trims the
// result so a single alert line cannot exceed a reasonable size.
// We preserve 7-bit ASCII printable bytes (0x20..0x7E) plus tab
// (rendered as space) and drop everything else; non-ASCII bytes
// are replaced with a '?' placeholder so a malicious UTF-8 host
// cannot embed ANSI escape sequences that re-render the terminal.
func sanitizeAlertField(s string) string {
	if s == "" {
		return s
	}
	const maxAlertField = 256
	if len(s) > maxAlertField {
		s = s[:maxAlertField]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t':
			b.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
			b.WriteByte('?')
		case c > 0x7e:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// SetEgressTelemetry installs the OTel provider used by the
// emitEgress counter hook. Passing nil resets to the no-op default.
// The sidecar boot path calls this right after telemetry is
// configured so Layer 3 events begin counting as soon as the
// passthrough handler accepts traffic.
func SetEgressTelemetry(tp *telemetry.Provider) {
	egressTelemetryMu.Lock()
	defer egressTelemetryMu.Unlock()
	egressTelemetry = tp
}

// deriveSeverity maps an audit.Event severity string into the strict
// gatewaylog.Severity type. Unknown strings fall back to INFO rather
// than panicking so we never lose an event to an enum mismatch.
func deriveSeverity(s string) gatewaylog.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return gatewaylog.SeverityCritical
	case "HIGH":
		return gatewaylog.SeverityHigh
	case "MEDIUM":
		return gatewaylog.SeverityMedium
	case "LOW":
		return gatewaylog.SeverityLow
	default:
		return gatewaylog.SeverityInfo
	}
}
