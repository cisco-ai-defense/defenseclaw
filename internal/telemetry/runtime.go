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

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// EmitStartupSpan creates a short-lived span to verify the trace export pipeline
// is working. Called once at sidecar startup.
func (p *Provider) EmitStartupSpan(ctx context.Context) {
	if !p.TracesEnabled() {
		return
	}
	_, span := p.tracer.Start(ctx, "defenseclaw/startup",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)
	span.SetAttributes(attribute.String("defenseclaw.event", "sidecar_start"))
	span.SetStatus(codes.Ok, "")
	span.End()
}

// StartGuardrailStageSpan begins a span covering one guardrail
// pipeline stage (regex_only, regex_judge, judge_first, etc.).
// Callers must End the returned span via EndGuardrailStageSpan —
// Start/End are split so the inspector can attach the final verdict
// action/severity/latency once scan+judge+OPA have all resolved.
//
// Nil span is safely returned when traces are disabled; consumers
// can call End on nil spans per the OTel SDK contract.
func (p *Provider) StartGuardrailStageSpan(ctx context.Context, stage, direction, model string) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}
	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("guardrail/%s", stage),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.SetAttributes(
		attribute.String("defenseclaw.guardrail.stage", stage),
		attribute.String("defenseclaw.guardrail.direction", direction),
		attribute.String("defenseclaw.guardrail.model", model),
	)
	return ctx, span
}

// EndGuardrailStageSpan attaches the final verdict attributes and
// closes the span. action=block maps to OTel Error status; anything
// else is Ok so block-rate can be queried directly from span status
// in Tempo/Jaeger without a custom filter expression.
func (p *Provider) EndGuardrailStageSpan(span trace.Span, action, severity, reason string, latencyMs int64) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.String("defenseclaw.guardrail.action", action),
		attribute.String("defenseclaw.guardrail.severity", severity),
		attribute.String("defenseclaw.guardrail.reason", truncateStr(reason, 256)),
		attribute.Int64("defenseclaw.guardrail.latency_ms", latencyMs),
	)
	if action == "block" {
		span.SetStatus(codes.Error, "blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// StartGuardrailPhaseSpan opens a child span for one sub-stage of a
// guardrail inspection — e.g. "regex", "cisco_ai_defense", "judge.pii",
// "judge.prompt_injection", "opa", "finalize". Phase spans nest under
// the Stage span opened by StartGuardrailStageSpan so operators can
// pivot on stage (regex_only vs regex_judge vs judge_first) AND drill
// into phase-level latency (which phase ate the P99 budget) in a
// single trace waterfall.
//
// Nil span is returned when traces are disabled; End is a safe no-op
// per the OTel SDK contract.
func (p *Provider) StartGuardrailPhaseSpan(ctx context.Context, phase string) (context.Context, trace.Span) {
	if p == nil || !p.TracesEnabled() {
		return ctx, nil
	}
	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("guardrail.%s", phase),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.SetAttributes(
		attribute.String("defenseclaw.guardrail.phase", phase),
	)
	return ctx, span
}

// EndGuardrailPhaseSpan attaches the phase outcome (action + severity
// + latency) and closes the span. Action may be empty for phases that
// don't produce a verdict directly (e.g. "regex" when there are no
// matches); we still record latency so phase timing is always queryable.
func (p *Provider) EndGuardrailPhaseSpan(span trace.Span, action, severity string, latencyMs int64) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.Int64("defenseclaw.guardrail.latency_ms", latencyMs),
	)
	if action != "" {
		span.SetAttributes(attribute.String("defenseclaw.guardrail.action", action))
	}
	if severity != "" {
		span.SetAttributes(attribute.String("defenseclaw.guardrail.severity", severity))
	}
	if action == "block" {
		span.SetStatus(codes.Error, "blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// EmitInspectSpan creates a span for a tool/message inspection evaluation.
func (p *Provider) EmitInspectSpan(ctx context.Context, tool, action, severity string, durationMs float64) string {
	if !p.TracesEnabled() {
		return ""
	}
	_, span := p.tracer.Start(ctx, fmt.Sprintf("inspect/%s", tool),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now().Add(-time.Duration(durationMs)*time.Millisecond)),
	)
	span.SetAttributes(
		attribute.String("defenseclaw.inspect.tool", tool),
		attribute.String("defenseclaw.inspect.action", action),
		attribute.String("defenseclaw.inspect.severity", severity),
		attribute.Float64("defenseclaw.inspect.duration_ms", durationMs),
	)
	if action == "block" {
		span.SetStatus(codes.Error, "blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	traceID := span.SpanContext().TraceID().String()
	span.End()
	return traceID
}

// StartAgentSpan starts a new OTel span for an agent invocation session.
// Follows OTel GenAI semconv: span name = "invoke_agent {agentName}".
//
// conversationID is mapped to gen_ai.conversation.id.
// agentID is the logical stable agent identity and maps to
// gen_ai.agent.id when present. agentInstanceID is separately
// resolved from the process-level default and emitted only via the
// DefenseClaw-specific defenseclaw.agent.instance_id attribute.
func (p *Provider) StartAgentSpan(
	ctx context.Context,
	conversationID, agentName, agentID, provider string,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}

	spanName := "invoke_agent"
	if agentName != "" {
		spanName = fmt.Sprintf("invoke_agent %s", agentName)
	}

	ctx, span := p.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("gen_ai.operation.name", "invoke_agent"),
		attribute.String("gen_ai.agent.name", agentName),
		attribute.String("gen_ai.conversation.id", conversationID),
	)
	if provider != "" {
		span.SetAttributes(attribute.String("gen_ai.provider.name", provider))
	}
	if agentID != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.id", agentID))
	}
	if inst := p.AgentInstanceID(); inst != "" {
		span.SetAttributes(attribute.String("defenseclaw.agent.instance_id", inst))
	}

	return ctx, span
}

// EndAgentSpan ends an active agent invocation span.
func (p *Provider) EndAgentSpan(span trace.Span, errMsg string) {
	if span == nil {
		return
	}
	if errMsg != "" {
		span.SetStatus(codes.Error, errMsg)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// ToolSpanContext bundles the correlation identifiers the tool-call
// runtime (and the audit/sink emitters) need to stamp on every tool
// span. Split out into a struct so adding a new field (policy_id,
// destination_app, eventual transaction ids) does not churn every
// call site's positional parameter list.
//
// Zero fields are safe — the span helper only sets attributes when
// the corresponding string is non-empty. Callers that have richer
// information (tool id from the LLM stream, active session key from
// the router) fill what they have.
type ToolSpanContext struct {
	// ToolID is the provider-assigned identifier for this specific
	// tool invocation (e.g. the OpenAI tool_call_id). Required for
	// /v1/agentwatch/summary top_tools aggregation and for joining
	// tool_call and tool_result rows in SQL.
	ToolID string

	// SessionID is the conversation / sessionKey this tool call
	// belongs to. It maps to gen_ai.conversation.id.
	SessionID string

	// RunID is the sidecar-process run identifier (DEFENSECLAW_RUN_ID).
	// Kept on the span so operators can filter a single sidecar
	// lifetime's tool activity without a join.
	RunID string

	// DestinationApp identifies the upstream provider the tool call
	// targets (builtin | mcp:<server> | skill:<key>). Populated by
	// the router once it resolves the tool provider.
	DestinationApp string

	// PolicyID is the identifier of the policy that approved or
	// blocked this tool invocation. Empty when no policy fired.
	PolicyID string

	// AgentName is the logical agent name driving the invocation.
	// Derived from the incoming stream event (if present) or from
	// cfg.Claw.Mode.
	AgentName string

	// AgentID is the logical agent identity when known. Unlike
	// AgentInstanceID, this is stable across restarts and sessions.
	// It maps to gen_ai.agent.id when present.
	AgentID string
}

// StartToolSpan starts a new OTel span for a tool_call event.
// Follows OTel GenAI semconv: span name = "execute_tool {toolName}".
// Raw args are not exported to avoid leaking tokens, keys, or prompt content.
// Metrics are always recorded when OTel is enabled, even if traces are off.
//
// cor carries optional correlation identifiers (tool id, session id,
// policy id, destination app). Every field is optional — blank values
// simply skip the corresponding attribute so older call sites keep
// working without churn.
func (p *Provider) StartToolSpan(
	ctx context.Context,
	tool, status string,
	args json.RawMessage,
	dangerous bool,
	flaggedPattern, toolProvider, skillKey string,
	cor ToolSpanContext,
) (context.Context, trace.Span) {
	p.RecordToolCall(ctx, tool, toolProvider, dangerous)

	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("execute_tool %s", tool),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("gen_ai.operation.name", "execute_tool"),
		attribute.String("gen_ai.tool.name", tool),
		attribute.String("gen_ai.tool.type", "function"),
		// DefenseClaw-specific attributes
		attribute.String("defenseclaw.tool.status", status),
		attribute.Int("defenseclaw.tool.args_length", len(args)),
		attribute.Bool("defenseclaw.tool.dangerous", dangerous),
		attribute.String("defenseclaw.tool.provider", toolProvider),
	)
	if redaction.DisableAll() && len(args) > 0 {
		span.SetAttributes(attribute.String("defenseclaw.tool.args", string(args)))
	}

	if skillKey != "" {
		span.SetAttributes(attribute.String("defenseclaw.tool.skill_key", skillKey))
	}

	if cor.ToolID != "" {
		span.SetAttributes(attribute.String("gen_ai.tool.call.id", cor.ToolID))
	}
	if cor.SessionID != "" {
		span.SetAttributes(attribute.String("gen_ai.conversation.id", cor.SessionID))
	}
	if cor.RunID != "" {
		span.SetAttributes(attribute.String("defenseclaw.run.id", cor.RunID))
	}
	if cor.DestinationApp != "" {
		span.SetAttributes(attribute.String("defenseclaw.destination.app", cor.DestinationApp))
	}
	if cor.PolicyID != "" {
		span.SetAttributes(attribute.String("defenseclaw.policy.id", cor.PolicyID))
	}
	if cor.AgentName != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.name", cor.AgentName))
	}
	if cor.AgentID != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.id", cor.AgentID))
	}
	if inst := p.AgentInstanceID(); inst != "" {
		span.SetAttributes(attribute.String("defenseclaw.agent.instance_id", inst))
	}

	if flaggedPattern != "" {
		span.SetAttributes(attribute.String("defenseclaw.tool.flagged_pattern", flaggedPattern))
		span.AddEvent("tool.flagged", trace.WithAttributes(
			attribute.String("defenseclaw.flag.reason", "dangerous-pattern"),
			attribute.String("defenseclaw.flag.pattern", flaggedPattern),
		))
	}

	return ctx, span
}

// SetRawSpanString adds a raw string attribute only when the operator has
// explicitly disabled redaction. This is the narrow escape hatch for
// single-tenant/debug installs that want full prompt/tool telemetry while
// preserving the default low-content span contract.
func (p *Provider) SetRawSpanString(span trace.Span, key, value string) {
	if span == nil || key == "" || value == "" || !redaction.DisableAll() {
		return
	}
	span.SetAttributes(attribute.String(key, value))
}

// SetRawSpanStringSlice is the slice variant of SetRawSpanString.
func (p *Provider) SetRawSpanStringSlice(span trace.Span, key string, values []string) {
	if span == nil || key == "" || len(values) == 0 || !redaction.DisableAll() {
		return
	}
	span.SetAttributes(attribute.StringSlice(key, values))
}

// EndToolSpan ends an active tool call span with result data.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndToolSpan(span trace.Span, exitCode, outputLen int, startTime time.Time, tool, toolProvider string) {
	ctx := context.Background()
	durationMs := float64(time.Since(startTime).Milliseconds())

	if exitCode != 0 {
		p.RecordToolError(ctx, tool, exitCode)
	}
	p.RecordToolDuration(ctx, tool, toolProvider, durationMs)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.Int("defenseclaw.tool.exit_code", exitCode),
		attribute.Int("defenseclaw.tool.output_length", outputLen),
	)

	if exitCode != 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("exit_code=%d", exitCode))
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartApprovalSpan starts a new OTel span for an exec approval request.
// Raw command strings and argv are exported only when redaction is explicitly
// disabled.
//
// cor carries optional correlation identifiers (session, run, policy,
// destination). Empty fields are skipped; older callers that still
// pass a zero ToolSpanContext see the pre-existing behavior.
func (p *Provider) StartApprovalSpan(
	ctx context.Context,
	id, command string,
	argv []string,
	cwd string,
	cor ToolSpanContext,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("exec.approval/%s", id),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("defenseclaw.approval.id", id),
		attribute.String("defenseclaw.approval.command_name", baseCommand(command)),
		attribute.Int("defenseclaw.approval.argc", len(argv)),
	)
	if redaction.DisableAll() {
		if command != "" {
			span.SetAttributes(attribute.String("defenseclaw.approval.command", command))
		}
		if len(argv) > 0 {
			span.SetAttributes(attribute.StringSlice("defenseclaw.approval.argv", argv))
		}
		if cwd != "" {
			span.SetAttributes(attribute.String("defenseclaw.approval.cwd", cwd))
		}
	}
	if cor.ToolID != "" {
		span.SetAttributes(attribute.String("gen_ai.tool.call.id", cor.ToolID))
	}
	if cor.SessionID != "" {
		span.SetAttributes(attribute.String("gen_ai.conversation.id", cor.SessionID))
	}
	if cor.RunID != "" {
		span.SetAttributes(attribute.String("defenseclaw.run.id", cor.RunID))
	}
	if cor.DestinationApp != "" {
		span.SetAttributes(attribute.String("defenseclaw.destination.app", cor.DestinationApp))
	}
	if cor.PolicyID != "" {
		span.SetAttributes(attribute.String("defenseclaw.policy.id", cor.PolicyID))
	}
	if cor.AgentName != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.name", cor.AgentName))
	}
	if cor.AgentID != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.id", cor.AgentID))
	}
	if inst := p.AgentInstanceID(); inst != "" {
		span.SetAttributes(attribute.String("defenseclaw.agent.instance_id", inst))
	}

	return ctx, span
}

// EndApprovalSpan ends an active approval span with the resolution.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndApprovalSpan(span trace.Span, result, reason string, auto, dangerous bool) {
	p.RecordApproval(context.Background(), result, auto, dangerous)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.String("defenseclaw.approval.result", result),
		attribute.String("defenseclaw.approval.reason", reason),
		attribute.Bool("defenseclaw.approval.auto", auto),
		attribute.Bool("defenseclaw.approval.dangerous", dangerous),
	)

	if result == "denied" || result == "timeout" {
		span.SetStatus(codes.Error, result)
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartLLMSpan starts a new OTel span for an LLM inference call.
// Follows OTel GenAI semconv: span name = "chat {model}".
// Metrics are always recorded when OTel is enabled, even if traces are off.
func (p *Provider) StartLLMSpan(
	ctx context.Context,
	system, model, provider string,
	maxTokens int,
	temperature float64,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("chat %s", model),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("gen_ai.operation.name", "chat"),
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.provider.name", provider),
		attribute.String("gen_ai.request.model", model),
		attribute.Int("gen_ai.request.max_tokens", maxTokens),
		attribute.Float64("gen_ai.request.temperature", temperature),
	)

	return ctx, span
}

// EndLLMSpan ends an active LLM call span with response data.
// Follows OTel GenAI semconv for token attribute names.
// Metrics are always recorded when OTel is enabled, even if the span is nil
// (traces disabled).
func (p *Provider) EndLLMSpan(
	span trace.Span,
	responseModel string,
	promptTokens, completionTokens int,
	finishReasons []string,
	toolCallCount int,
	guardrail, guardrailResult string,
	providerName string,
	startTime time.Time,
	agentName string,
	agentID string,
) {
	// Use the span's context so the SDK attaches exemplars (trace ID + span ID)
	// to the histogram data points, linking metrics to traces.
	ctx := context.Background()
	if span != nil {
		ctx = trace.ContextWithSpan(ctx, span)
	}
	durationSec := time.Since(startTime).Seconds()
	p.RecordLLMTokens(ctx, "chat", providerName, responseModel, agentName, agentID, int64(promptTokens), int64(completionTokens))
	p.RecordLLMDuration(ctx, "chat", providerName, responseModel, agentName, agentID, durationSec)

	if span == nil {
		return
	}

	spanAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.response.model", responseModel),
		attribute.StringSlice("gen_ai.response.finish_reasons", finishReasons),
		attribute.Int("gen_ai.usage.input_tokens", promptTokens),
		attribute.Int("gen_ai.usage.output_tokens", completionTokens),
		attribute.Int("defenseclaw.llm.tool_calls", toolCallCount),
		attribute.String("defenseclaw.llm.guardrail", guardrail),
		attribute.String("defenseclaw.llm.guardrail.result", guardrailResult),
	}
	// Stamp agent identity onto the LLM span so traces in o11y join
	// cleanly with metrics by the same labels. Metrics omit empty,
	// so we do too — keeps span attribute noise bounded.
	if agentName != "" {
		spanAttrs = append(spanAttrs, attribute.String("gen_ai.agent.name", agentName))
	}
	if agentID != "" {
		spanAttrs = append(spanAttrs, attribute.String("gen_ai.agent.id", agentID))
	}
	span.SetAttributes(spanAttrs...)

	if guardrailResult == "blocked" {
		span.SetStatus(codes.Error, "guardrail blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartJudgeSpan starts a span for one LLM judge ChatCompletion (Track 3).
// Name: defenseclaw.guardrail.judge
func (p *Provider) StartJudgeSpan(
	ctx context.Context,
	genAISystem, model string,
	maxTokens int,
	kind string,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}
	ctx, span := p.tracer.Start(ctx, "defenseclaw.guardrail.judge",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(time.Now()),
	)
	span.SetAttributes(
		attribute.String("gen_ai.system", genAISystem),
		attribute.String("gen_ai.request.model", model),
		attribute.Int("gen_ai.request.max_tokens", maxTokens),
		attribute.String("judge.kind", kind),
	)
	return ctx, span
}

// EndJudgeSpan ends a judge span with GenAI usage + DefenseClaw attributes.
// Callers record histograms via Provider.RecordJudgeLatency / RecordJudgeTokens.
func (p *Provider) EndJudgeSpan(
	span trace.Span,
	responseModel string,
	promptTokens, completionTokens int,
	latencyMs int64,
	verdictAction string,
	cacheHit bool,
	err error,
) {
	if span == nil {
		return
	}
	if responseModel == "" {
		responseModel = "unknown"
	}
	span.SetAttributes(
		attribute.String("gen_ai.response.model", responseModel),
		attribute.Int("gen_ai.usage.input_tokens", promptTokens),
		attribute.Int("gen_ai.usage.output_tokens", completionTokens),
		attribute.Int64("judge.latency_ms", latencyMs),
		attribute.String("judge.verdict", verdictAction),
		attribute.Bool("cache.hit", cacheHit),
	)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// StartGuardrailSpan starts a new OTel span for a guardrail evaluation.
// Follows OTel GenAI semconv PR #3233: span name = "apply_guardrail {name} {targetType}".
func (p *Provider) StartGuardrailSpan(
	ctx context.Context,
	name, targetType, model string,
) (context.Context, trace.Span) {
	if !p.TracesEnabled() {
		return ctx, nil
	}

	spanName := fmt.Sprintf("apply_guardrail %s %s", name, targetType)
	ctx, span := p.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("gen_ai.operation.name", "apply_guardrail"),
		attribute.String("gen_ai.guardrail.name", name),
		attribute.String("gen_ai.security.target.type", targetType),
		attribute.String("gen_ai.request.model", model),
	)

	return ctx, span
}

// EndGuardrailSpan ends an active guardrail span with the security decision.
func (p *Provider) EndGuardrailSpan(
	span trace.Span,
	decision, severity, reason string,
	startTime time.Time,
) {
	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.String("gen_ai.security.decision.type", decision),
		attribute.String("defenseclaw.guardrail.severity", severity),
	)

	if reason != "" {
		span.SetAttributes(attribute.String("defenseclaw.guardrail.reason", truncateStr(reason, 256)))
	}

	if decision == "deny" || decision == "block" {
		span.SetStatus(codes.Error, "guardrail blocked")
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// StartPolicySpan starts a new OTel span for an OPA policy evaluation.
// Metrics are always recorded when OTel is enabled, even if traces are off.
func (p *Provider) StartPolicySpan(ctx context.Context, domain, targetType, targetName string) (context.Context, trace.Span) {
	if !p.Enabled() {
		return ctx, nil
	}

	if !p.TracesEnabled() {
		return ctx, nil
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("policy/%s", domain),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(time.Now()),
	)

	span.SetAttributes(
		attribute.String("defenseclaw.policy.domain", domain),
		attribute.String("defenseclaw.policy.target_type", targetType),
		attribute.String("defenseclaw.policy.target_name", targetName),
	)

	return ctx, span
}

// EndPolicySpan ends an active policy evaluation span with verdict data.
// Metrics are always recorded when OTel is enabled, even if the span is nil.
func (p *Provider) EndPolicySpan(span trace.Span, domain, verdict, reason string, startTime time.Time) {
	ctx := context.Background()
	durationMs := float64(time.Since(startTime).Milliseconds())

	p.RecordPolicyEvaluation(ctx, domain, verdict)
	p.RecordPolicyLatency(ctx, domain, durationMs)

	if span == nil {
		return
	}

	span.SetAttributes(
		attribute.String("defenseclaw.policy.verdict", verdict),
		attribute.String("defenseclaw.policy.reason", truncateStr(reason, 256)),
	)

	switch verdict {
	case "blocked", "rejected", "deny":
		span.SetStatus(codes.Error, verdict)
	default:
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// baseCommand extracts the executable name from a command string,
// stripping path prefixes and arguments to avoid leaking sensitive content.
func baseCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	fields := strings.Fields(cmd)
	base := fields[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	return base
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
