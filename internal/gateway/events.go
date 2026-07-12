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
	"fmt"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

var (
	// judgeResponseStore is the process-wide bounded completion queue. Its body
	// inserter is optional, so canonical judge logs remain active when forensic
	// response retention is disabled.
	judgeResponseStoreMu sync.RWMutex
	judgeResponseStore   *JudgeStore
)

// SetJudgeResponseStore installs the bounded judge completion queue. Passing
// nil disables queued canonical completion and optional body persistence.
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

// stampEventCorrelation populates the eight correlation / identity
// fields of the compatibility gatewaylog envelope used as source input by the
// generated egress adapter. Generated family producers own persistence,
// routing, destination delivery, and redaction.
//
// Nil ctx is tolerated (boot/shutdown emits) and leaves every field
// at the caller-supplied value. Non-empty caller-supplied values
// always win — this helper fills in blanks, never overwrites.
func stampEventCorrelation(ev *gatewaylog.Event, ctx context.Context) {
	if ev == nil || ctx == nil {
		return
	}
	env := audit.EnvelopeFromContext(ctx)
	if ev.RequestID == "" {
		ev.RequestID = firstNonEmpty(RequestIDFromContext(ctx), env.RequestID)
	}
	if ev.SessionID == "" {
		ev.SessionID = firstNonEmpty(SessionIDFromContext(ctx), env.SessionID)
	}
	if ev.TurnID == "" {
		ev.TurnID = env.TurnID
	}
	if ev.TraceID == "" {
		ev.TraceID = firstNonEmpty(TraceIDFromContext(ctx), env.TraceID)
		if ev.TraceID == "" {
			if sp := trace.SpanFromContext(ctx); sp != nil && sp.SpanContext().IsValid() {
				ev.TraceID = sp.SpanContext().TraceID().String()
			}
		}
	}
	if ev.RunID == "" {
		ev.RunID = firstNonEmpty(env.RunID, gatewaylog.ProcessRunID())
	}
	id := AgentIdentityFromContext(ctx)
	if ev.AgentID == "" {
		ev.AgentID = firstNonEmpty(id.AgentID, env.AgentID)
	}
	if ev.AgentName == "" {
		ev.AgentName = firstNonEmpty(id.AgentName, env.AgentName)
	}
	if ev.AgentType == "" {
		ev.AgentType = id.AgentType
	}
	if ev.UserID == "" {
		ev.UserID = id.UserID
	}
	if ev.UserName == "" {
		ev.UserName = id.UserName
	}
	if ev.AgentInstanceID == "" {
		ev.AgentInstanceID = firstNonEmpty(id.AgentInstanceID, env.AgentInstanceID)
	}
	if ev.SidecarInstanceID == "" {
		ev.SidecarInstanceID = firstNonEmpty(id.SidecarInstanceID, env.SidecarInstanceID)
	}
	if ev.PolicyID == "" {
		ev.PolicyID = env.PolicyID
	}
	if ev.DestinationApp == "" {
		ev.DestinationApp = env.DestinationApp
	}
	if ev.ToolName == "" {
		ev.ToolName = env.ToolName
	}
	if ev.ToolID == "" {
		ev.ToolID = env.ToolID
	}
	if ev.Connector == "" {
		ev.Connector = env.Connector
	}
	if ev.SessionID != "" && ev.AgentID != "" {
		source := strings.ToLower(strings.TrimSpace(ev.Connector))
		if source == "" {
			source = "unknown"
		}
		if ev.AgentLifecycleID == "" {
			ev.AgentLifecycleID = stableLLMEventID("lifecycle", source, ev.SessionID, ev.AgentID)
		}
		if ev.AgentExecutionID == "" {
			ev.AgentExecutionID = stableLLMEventID(
				"execution", source, ev.SessionID, ev.AgentID, gatewaylog.ProcessRunID(),
			)
		}
	}
}

// emitVerdictExtras carries optional verdict-event fields that
// runtime finding emitters (guardrail Inspect, mid-stream,
// tool-call inspect) stamp so SIEM can join the verdict to its
// per-finding scan_findings rows. Pure additive — emitVerdict
// callers that pass no extras get exactly the same wire shape as
// before.
type emitVerdictExtras struct {
	EvaluationID string
	RuleIDs      []string
}

// emitVerdict preserves the old call shape while generated guardrail, finding,
// enforcement, and tool producers own the occurrence. It intentionally emits
// nothing and must be removed with the remaining call sites.
func emitVerdict(
	ctx context.Context,
	stage gatewaylog.Stage,
	direction gatewaylog.Direction,
	model string,
	action, reason string,
	severity gatewaylog.Severity,
	categories []string,
	latencyMs int64,
	extras ...emitVerdictExtras,
) {
	// Generated guardrail producers own the production occurrence. This legacy
	// call shape remains temporarily source-compatible while call sites migrate;
	// it must never create a second record.
}

// JudgeEmitOpts carries optional correlation for judge persistence and payloads.
type JudgeEmitOpts struct {
	Findings       []gatewaylog.Finding
	ToolName       string
	ToolID         string
	PolicyID       string
	DestinationApp string
	// FailureClass is required exactly when action is "error". It is a
	// closed, low-cardinality classification; the positional failureSummary
	// argument remains the centrally-redacted diagnostic detail.
	FailureClass gatewaylog.JudgeFailureClass
	// InputContent, when non-empty, is the inspected judge input
	// (the prompt/request text the judge was asked to evaluate).
	// emitJudge computes its sha256 digest and stores the result in
	// JudgePayload.InputHash so the audit row carries an InputHash
	// that actually represents the *input*. ("Judge
	// input_hash is computed from the response body") closure: the
	// previous implementation hashed the response, which corrupted
	// dedup/pivot semantics. emitJudge intentionally does not log
	// or persist InputContent itself — only the digest.
	InputContent string
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
	failureSummary string,
	raw string,
	opts JudgeEmitOpts,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	action = strings.ToLower(strings.TrimSpace(action))
	failureSummary = strings.ToValidUTF8(failureSummary, "\uFFFD")
	if len(failureSummary) > 65536 {
		failureSummary = truncateToRuneBoundary(failureSummary, 65536)
	}
	if action == "error" {
		if !opts.FailureClass.Valid() || strings.TrimSpace(failureSummary) == "" {
			emitError(ctx, string(gatewaylog.SubsystemGuardrail), string(gatewaylog.ErrCodeLLMBridgeError),
				"judge error omitted a valid internal failure classification", nil)
			return
		}
	} else if opts.FailureClass != "" || failureSummary != "" {
		emitError(ctx, string(gatewaylog.SubsystemGuardrail), string(gatewaylog.ErrCodeLLMBridgeError),
			"successful judge result carried failure-only metadata", nil)
		return
	}
	payload := gatewaylog.JudgePayload{
		Kind:         kind,
		Model:        model,
		InputBytes:   inputBytes,
		LatencyMs:    latencyMs,
		Action:       action,
		Severity:     severity,
		FailureClass: opts.FailureClass,
		ErrorSummary: failureSummary,
		RawResponse:  raw,
		Findings:     opts.Findings,
	}
	if opts.FailureClass == gatewaylog.JudgeFailureOutputParse {
		payload.ParseError = failureSummary
	}
	// ("Judge input_hash is computed from the
	// response body") closure: when callers supply the inspected
	// judge input via opts.InputContent, derive the canonical
	// "sha256:<hex>" digest of that content here. Persistence
	// (judge_store.go) propagates payload.InputHash verbatim and
	// no longer falls back to hashing the response body, so the
	// audit row's InputHash truly represents the input.
	if opts.InputContent != "" {
		sum := sha256.Sum256([]byte(opts.InputContent))
		payload.InputHash = "sha256:" + hex.EncodeToString(sum[:])
	}

	// Queue the original payload. The
	// worker always emits the canonical completion; only a queue configured with
	// an optional body inserter writes RawResponse to the operator-owned SQLite
	// file. Retention remains explicit and never changes completion visibility.
	if js := activeJudgeStore(); js != nil {
		_ = js.PersistJudgeEvent(ctx, direction, payload, opts.ToolName, opts.ToolID, opts.PolicyID, opts.DestinationApp)
	}

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
	_ = ctx
	_ = details
	fmt.Fprintf(os.Stderr, "[gateway] lifecycle subsystem=%s transition=%s\n",
		sanitizeAlertField(subsystem), sanitizeAlertField(normalizeLifecycleTransition(transition)))
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
	emitErrorConnector(ctx, subsystem, code, "", message, cause)
}

// emitErrorConnector is emitError with first-class connector attribution.
// Connector-scoped failures (e.g. hook self-heal re-install failures) pass
// the originating connector so canonical error events carry the same
// connector dimension as every other surface; "" behaves like emitError.
func emitErrorConnector(ctx context.Context, subsystem, code, connector, message string, cause error) {
	_ = ctx
	_ = connector
	causeClass := ""
	if cause != nil {
		causeClass = " cause=present"
	}
	fmt.Fprintf(os.Stderr, "[gateway] error subsystem=%s code=%s message=%s%s\n",
		sanitizeAlertField(subsystem), sanitizeAlertField(code), sanitizeAlertField(message), causeClass)
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
	_ = ctx
	_ = message
	_ = details
	fmt.Fprintf(os.Stderr, "[gateway] diagnostic component=%s\n", sanitizeAlertField(component))
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
	emitEgressWithRuntime(ctx, p, nil, false)
}

func (p *GuardrailProxy) emitEgress(ctx context.Context, payload gatewaylog.EgressPayload) {
	runtime, authoritative := p.observabilityV8EgressRuntime()
	emitEgressWithRuntime(ctx, payload, runtime, authoritative)
}

func emitEgressWithRuntime(
	ctx context.Context,
	p gatewaylog.EgressPayload,
	runtime gatewayEgressV8Runtime,
	authoritative bool,
) {
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
	// fragments never reach canonical observability records. Providers routinely
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
	// without letting a misbehaving TS caller bloat canonical records.
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
	if emitGatewayEgressV8(ctx, p, sev, runtime, authoritative) {
		return
	}
	incEgressCounter(ctx, p.Branch, p.Decision, p.Source)
	if sev == gatewaylog.SeverityHigh {
		emitEgressAlert(ctx, p)
	}
}

// incEgressCounter is retained only as a test-visible assertion that the
// canonical generated egress path does not fall through. Production generated
// metrics are emitted by emitGatewayEgressV8; there is no provider-backed
// fallback. emitEgressAlert remains the independent human-facing rail.
var (
	incEgressCounter = func(context.Context, string, string, string) {}
	emitEgressAlert  = func(ctx context.Context, p gatewaylog.EgressPayload) {
		// Always log to stderr — operators need a signal even when
		// remote export is disabled. Canonical v8 routing owns the
		// structured record; this is the complementary human-facing rail.
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
