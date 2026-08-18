// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const hookDecisionMetricsV8Producer = "gateway.hook.decision.metrics"

func (a *APIServer) emitHookDecisionObservabilityV8(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
	panicked bool,
) {
	if a == nil || ctx == nil {
		return
	}
	meta, connectorName, ok := a.hookDecisionMeta(ctx, req)
	if !ok {
		return
	}
	a.emitHookDecisionLogV8(ctx, req, resp, env, panicked, meta, connectorName)
	a.recordHookDecisionMetricsV8(ctx, req, resp, env, panicked, meta, connectorName)
}

func (a *APIServer) emitHookDecisionLogV8(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
	panicked bool,
	meta llmEventMeta,
	connectorName string,
) {
	emitter, ok := a.observabilityV8RuntimeEmitter().(sidecarRuntimeEmitter)
	if !ok || emitter == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	severity := observability.NormalizeSeverity(firstNonEmpty(resp.Severity, "NONE"))
	if !severity.Valid || !severity.Present {
		return
	}
	logLevel := severity.LogLevel
	if logLevel == "" {
		logLevel = observability.LogLevelInfo
	}
	result := "ok"
	if panicked || env.Result == "panic" {
		result = "panic"
	}
	effectiveAction := normalizeHookActionLabel(resp.Action)
	classification := observability.ClassificationContext{
		Bucket: observability.BucketGuardrailEvaluation, EventName: observability.EventName(observability.TelemetryEventHookDecision),
		RawSeverity: string(severity.Severity), Enforced: env.Enforced,
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: env.Enforced},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey(gatewaylog.EventHookDecision),
		classification,
		observability.SourceConnector,
		connectorName,
		observability.ProducerKey(gatewaylog.EventHookDecision),
	)
	if err != nil {
		return
	}
	_, _ = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		correlation := observability.Correlation{
			RunID: meta.RunID, RequestID: meta.RequestID, SessionID: meta.SessionID,
			TurnID: meta.TurnID, AgentID: meta.AgentID, PolicyID: meta.PolicyID,
			ToolInvocationID: meta.ToolID, ConnectorID: connectorName,
		}
		if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
			correlation.TraceID = spanContext.TraceID().String()
			correlation.SpanID = spanContext.SpanID().String()
		}
		envelope := observability.FamilyEnvelopeInput{
			Source: observability.SourceConnector, Connector: connectorName,
			Action: string(gatewaylog.EventHookDecision), Phase: meta.Phase,
			Correlation: correlation,
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
				ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
		}
		return builder.BuildLogCompatHookDecision(observability.LogCompatHookDecisionInput{
			Envelope: envelope, Severity: observability.Present(severity.Severity),
			LogLevel: observability.Present(logLevel), Outcome: hookDecisionV8Outcome(effectiveAction, result),
			DefenseClawRequestID:                hookV8OptionalIdentifier(meta.RequestID),
			DefenseClawTurnID:                   hookV8OptionalIdentifier(meta.TurnID),
			DefenseClawOperationID:              hookV8OptionalIdentifier(meta.OperationID),
			DefenseClawRunID:                    hookV8OptionalIdentifier(meta.RunID),
			UserID:                              hookV8OptionalIdentifier(meta.UserID),
			DefenseClawUserName:                 hookV8OptionalIdentifier(meta.UserName),
			DefenseClawPolicyID:                 hookV8OptionalIdentifier(meta.PolicyID),
			DefenseClawDestinationApp:           hookV8OptionalIdentifier(meta.DestinationApp),
			GenAIConversationID:                 hookV8OptionalIdentifier(meta.SessionID),
			GenAIAgentID:                        hookV8OptionalIdentifier(meta.AgentID),
			GenAIAgentName:                      hookV8OptionalIdentifier(meta.AgentName),
			DefenseClawAgentType:                hookV8OptionalText(meta.AgentType, 4096),
			DefenseClawAgentRootID:              hookV8OptionalIdentifier(meta.RootAgentID),
			DefenseClawAgentParentID:            hookV8OptionalIdentifier(meta.ParentAgentID),
			DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(meta.LineageProvenance),
			DefenseClawSessionRootID:            hookV8OptionalIdentifier(meta.RootSessionID),
			DefenseClawSessionParentID:          hookV8OptionalIdentifier(meta.ParentSessionID),
			DefenseClawAgentLifecycleID:         hookV8OptionalIdentifier(meta.LifecycleID),
			DefenseClawAgentExecutionID:         hookV8OptionalIdentifier(meta.ExecutionID),
			DefenseClawAgentDepth:               hookDecisionV8Depth(meta.AgentDepth),
			DefenseClawAgentLifecycleEvent:      hookV8OptionalText(meta.LifecycleEvent, 4096),
			DefenseClawAgentLifecycleState:      hookV8OptionalText(meta.LifecycleState, 4096),
			DefenseClawAgentPhase:               hookV8OptionalPhase(meta.Phase),
			DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(meta.PreviousPhase),
			DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(meta.Phase),
			DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(meta.Sequence),
			DefenseClawSessionSource:            hookV8OptionalSessionSource(meta.SessionSource),
			DefenseClawSessionResumed:           hookV8OptionalSessionResumed(meta),
			DefenseClawEvaluationID:             hookV8OptionalIdentifier(resp.EvaluationID),
			DefenseClawHookEvent:                hookDecisionV8RequiredText(req.HookEventName, normalizeHookEventLabel(req.HookEventName)),
			DefenseClawHookResult:               result,
			DefenseClawGuardrailEffectiveAction: effectiveAction,
			DefenseClawGuardrailRawAction:       hookDecisionV8RequiredText(resp.RawAction, effectiveAction),
			DefenseClawSecuritySeverity:         string(severity.Severity),
			DefenseClawGuardrailMode:            hookDecisionV8Mode(resp.Mode),
			DefenseClawGuardrailWouldBlock:      resp.WouldBlock,
			DefenseClawGuardrailEnforced:        env.Enforced,
			DefenseClawConnectorStepIdx:         hookV8OptionalPositiveInt64(int64(env.StepIdx)),
			DefenseClawGuardrailLatencyMs:       observability.Present(max(float64(env.ElapsedMs), 0)),
			DefenseClawGuardrailReason:          hookV8OptionalText(hookSourceReason(resp), 65536),
			DefenseClawGuardrailRuleIds:         hookDecisionV8RuleIDs(resp.RuleIDs),
		})
	})
}

func (a *APIServer) recordHookDecisionMetricsV8(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
	panicked bool,
	meta llmEventMeta,
	connectorName string,
) {
	emitter := a.observabilityV8RuntimeEmitter()
	runtime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	meta.Source = connectorName
	// Preserve the compatibility projection previously applied inside the
	// legacy Provider. The generated builder owns validation, but the source
	// event still needs the same bounded dashboard label vocabulary.
	eventLabel := telemetry.NormalizeHookEventTypeLabel(normalizeHookEventLabel(req.HookEventName))
	decisionLabel := normalizeHookActionLabel(resp.Action)
	result := "ok"
	reason := normalizeHookReasonLabel(resp.Action, resp.WouldBlock)
	if panicked {
		result, reason = "panic", "panic"
	}
	severity := observability.NormalizeSeverity(firstNonEmpty(resp.Severity, "NONE"))
	if !severity.Valid || !severity.Present {
		return
	}
	observedAt := time.Now().UTC()
	latencyMillis := float64(env.ElapsedMs)
	if latencyMillis < 0 {
		latencyMillis = 0
	}
	toolLabel := hookMetricToolLabel(connectorName, req.HookEventName)
	items := []observabilityruntime.GeneratedMetricBatchItem{
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookInvocations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookInvocations(
					observability.MetricDefenseClawConnectorHookInvocationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricEventType: observability.Present(eventLabel),
						DefenseClawMetricReason:    observability.Present(reason),
						DefenseClawMetricResult:    observability.Present(result),
					},
				)
			}),
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookLatency(
					observability.MetricDefenseClawConnectorHookLatencyInput{
						Envelope: envelope, Value: latencyMillis,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricEventType: observability.Present(eventLabel),
						DefenseClawMetricReason:    observability.Present(reason),
						DefenseClawMetricResult:    observability.Present(result),
					},
				)
			}),
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawInspectEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawInspectEvaluations(
					observability.MetricDefenseClawInspectEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricAction:     observability.Present(decisionLabel),
						DefenseClawConnectorSource:  observability.Present(connectorName),
						DefenseClawSecuritySeverity: observability.Present(string(severity.Severity)),
						DefenseClawMetricTool:       observability.Present(toolLabel),
					},
				)
			}),
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawInspectLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawInspectLatency(
					observability.MetricDefenseClawInspectLatencyInput{
						Envelope: envelope, Value: latencyMillis,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricTool:      observability.Present(toolLabel),
					},
				)
			}),
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookOutcome,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookOutcome(
					observability.MetricDefenseClawConnectorHookOutcomeInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricAction:     observability.Present(decisionLabel),
						DefenseClawConnectorSource:  observability.Present(connectorName),
						DefenseClawMetricEventType:  observability.Present(eventLabel),
						DefenseClawSecuritySeverity: observability.Present(string(severity.Severity)),
						DefenseClawMetricWouldBlock: observability.Present(resp.WouldBlock),
					},
				)
			}),
	}
	usage := extractHookPayloadTokenUsage(req.Payload)
	model := telemetry.NormalizeModelLabel(usage.Model)
	for _, token := range []struct {
		kind  string
		value int64
	}{{"prompt", usage.PromptTokens}, {"completion", usage.CompletionTokens}, {"total", usage.TotalTokens}} {
		if token.value <= 0 {
			continue
		}
		kind, value := token.kind, token.value
		items = append(items, hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookTokens,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookTokens(
					observability.MetricDefenseClawConnectorHookTokensInput{
						Envelope: envelope, Value: value,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricKind:      observability.Present(kind),
						GenAIRequestModel:          observability.Present(model),
					},
				)
			},
		))
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (a *APIServer) recordHookRejectionMetricsV8(
	ctx context.Context,
	connectorName string,
	eventType string,
	reason string,
) {
	if a == nil || ctx == nil {
		return
	}
	emitter := a.observabilityV8RuntimeEmitter()
	runtime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	eventType = telemetry.NormalizeHookEventTypeLabel(normalizeHookEventLabel(eventType))
	reason = normalizeHookActionLabel(reason)
	observedAt := time.Now().UTC()
	meta := hookDecisionMetricMeta(ctx, connectorName)
	items := []observabilityruntime.GeneratedMetricBatchItem{
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookInvocations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookInvocations(
					observability.MetricDefenseClawConnectorHookInvocationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricEventType: observability.Present(eventType),
						DefenseClawMetricReason:    observability.Present(reason),
						DefenseClawMetricResult:    observability.Present("rejected"),
					},
				)
			}),
		hookDecisionMetricItem(ctx, observedAt, meta,
			observability.TelemetryInstrumentDefenseClawConnectorHookLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawConnectorHookLatency(
					observability.MetricDefenseClawConnectorHookLatencyInput{
						Envelope: envelope, Value: 0,
						DefenseClawConnectorSource: observability.Present(connectorName),
						DefenseClawMetricEventType: observability.Present(eventType),
						DefenseClawMetricReason:    observability.Present(reason),
						DefenseClawMetricResult:    observability.Present("rejected"),
					},
				)
			}),
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (a *APIServer) recordUnifiedHookDispatchMetricV8(ctx context.Context, connectorName string) {
	if a == nil || ctx == nil {
		return
	}
	emitter := a.observabilityV8RuntimeEmitter()
	runtime, ok := emitter.(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return
	}
	connectorName = hookDecisionMetricConnector(connectorName)
	meta := hookDecisionMetricMeta(ctx, connectorName)
	item := hookDecisionMetricItem(ctx, time.Now().UTC(), meta,
		observability.TelemetryInstrumentDefenseClawConnectorHookUnifiedDispatch,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawConnectorHookUnifiedDispatch(
				observability.MetricDefenseClawConnectorHookUnifiedDispatchInput{
					Envelope: envelope, Value: 1,
					DefenseClawConnectorSource: observability.Present(connectorName),
				},
			)
		})
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func hookDecisionMetricItem(
	ctx context.Context,
	observedAt time.Time,
	meta llmEventMeta,
	family string,
	build hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return newHookV8MetricBatchItemForProducer(
		ctx, observedAt, meta, hookDecisionMetricsV8Producer,
		observability.EventName(family), build,
	)
}

func hookDecisionMetricConnector(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !observability.IsStableToken(value) {
		return "unknown"
	}
	return value
}

func hookDecisionMetricMeta(ctx context.Context, connectorName string) llmEventMeta {
	envelope := audit.EnvelopeFromContext(ctx)
	identity := AgentIdentityFromContext(ctx)
	return llmEventMeta{
		Source: connectorName, RunID: envelope.RunID, RequestID: envelope.RequestID,
		SessionID: envelope.SessionID, TurnID: envelope.TurnID,
		AgentID:   firstNonEmpty(identity.AgentID, envelope.AgentID),
		AgentName: firstNonEmpty(identity.AgentName, envelope.AgentName),
		AgentType: identity.AgentType, PolicyID: envelope.PolicyID,
		DestinationApp: envelope.DestinationApp, ToolName: envelope.ToolName, ToolID: envelope.ToolID,
	}
}

func hookDecisionV8Outcome(action, result string) observability.Outcome {
	if result == "panic" {
		return observability.OutcomePartial
	}
	switch action {
	case "allow":
		return observability.OutcomeAllowed
	case "block":
		return observability.OutcomeBlocked
	case "confirm":
		return observability.OutcomePartial
	default:
		return observability.OutcomeCompleted
	}
}

func hookDecisionV8Mode(value string) string {
	if normalizeAgentHookMode(value) == "action" {
		return "enforce"
	}
	return "observe"
}

func hookDecisionV8RequiredText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return fallback
	}
	return value
}

func hookDecisionV8Depth(value int) observability.Optional[int64] {
	if value < 0 || value > 64 {
		return observability.Absent[int64]()
	}
	return observability.Present(int64(value))
}

func hookDecisionV8RuleIDs(values []string) observability.Optional[[]string] {
	if len(values) == 0 {
		return observability.Absent[[]string]()
	}
	if len(values) > 8 {
		values = values[:8]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if hookV8OptionalIdentifier(value).IsPresent() {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return observability.Absent[[]string]()
	}
	return observability.Present(result)
}
