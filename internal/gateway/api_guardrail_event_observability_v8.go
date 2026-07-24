// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const apiGuardrailEventV8Producer = "gateway.api.guardrail_event"

type apiGuardrailEventV8Facts struct {
	request    guardrailEventRequest
	connector  string
	direction  string
	decision   string
	outcome    observability.Outcome
	severity   observability.Severity
	logLevel   observability.LogLevel
	ruleIDs    observability.Optional[[]string]
	reason     observability.Optional[string]
	model      observability.Optional[string]
	observedAt time.Time
	meta       llmEventMeta
	identity   AgentIdentity
}

func newAPIGuardrailEventV8Facts(
	ctx context.Context,
	connector string,
	request guardrailEventRequest,
) (apiGuardrailEventV8Facts, error) {
	request.EvaluationID = strings.TrimSpace(request.EvaluationID)
	request.Direction = strings.ToLower(strings.TrimSpace(request.Direction))
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	if !hookModelV8Identifier(request.EvaluationID) {
		return apiGuardrailEventV8Facts{}, errors.New("evaluation_id must be a stable identifier")
	}
	if request.Direction != "prompt" && request.Direction != "completion" {
		return apiGuardrailEventV8Facts{}, errors.New("direction must be prompt or completion")
	}
	if request.Action != "allow" && request.Action != "alert" && request.Action != "block" {
		return apiGuardrailEventV8Facts{}, errors.New("action must be allow, alert, or block")
	}
	rawSeverity := strings.ToUpper(strings.TrimSpace(request.Severity))
	switch rawSeverity {
	case "NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return apiGuardrailEventV8Facts{}, errors.New("severity must be NONE, INFO, LOW, MEDIUM, HIGH, or CRITICAL")
	}
	severity := observability.NormalizeSeverity(request.Severity)
	if !severity.Valid || !severity.Present {
		return apiGuardrailEventV8Facts{}, errors.New("severity is invalid")
	}
	if request.ElapsedMs < 0 || math.IsNaN(request.ElapsedMs) || math.IsInf(request.ElapsedMs, 0) ||
		request.CiscoElapsedMs < 0 || math.IsNaN(request.CiscoElapsedMs) || math.IsInf(request.CiscoElapsedMs, 0) {
		return apiGuardrailEventV8Facts{}, errors.New("latency must be a finite non-negative number")
	}
	for _, tokens := range []*int64{request.TokensIn, request.TokensOut} {
		if tokens != nil && *tokens < 0 {
			return apiGuardrailEventV8Facts{}, errors.New("token counts must be non-negative")
		}
	}
	model := observability.Absent[string]()
	if strings.TrimSpace(request.Model) != "" {
		model = hookV8OptionalIdentifier(request.Model)
		if !model.IsPresent() {
			return apiGuardrailEventV8Facts{}, errors.New("model must be a stable identifier")
		}
	}
	if strings.EqualFold(strings.TrimSpace(connector), "unknown") {
		connector = ""
	}
	connector = hookDecisionMetricConnector(firstNonEmpty(connector, audit.EnvelopeFromContext(ctx).Connector))
	logLevel := severity.LogLevel
	if logLevel == "" {
		logLevel = observability.LogLevelInfo
	}
	ruleNames := make([]string, 0, len(request.Findings))
	for _, finding := range NormalizeScanVerdict(&ScanVerdict{
		Severity: request.Severity, Findings: request.Findings,
	}) {
		ruleNames = append(ruleNames, finding.CanonicalID)
	}
	meta := hookDecisionMetricMeta(ctx, connector)
	meta.Model = request.Model
	return apiGuardrailEventV8Facts{
		request: request, connector: connector, direction: inspectTraceV8Direction(request.Direction),
		decision: inspectTraceV8Decision(request.Action), outcome: proxyGuardrailV8Outcome(request.Action),
		severity: severity.Severity, logLevel: logLevel, ruleIDs: inspectTraceV8RuleIDs(ruleNames),
		reason: hookV8OptionalText(request.Reason, 65536), model: model,
		observedAt: time.Now().UTC(), meta: meta, identity: AgentIdentityFromContext(ctx),
	}, nil
}

func (a *APIServer) emitGuardrailEventV8(ctx context.Context, facts apiGuardrailEventV8Facts) error {
	if a == nil || ctx == nil {
		return errors.New("guardrail event runtime is unavailable")
	}
	emitter := a.observabilityV8RuntimeEmitter()
	metricRuntime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if emitter == nil || metricRuntime == nil {
		return errors.New("guardrail event runtime is unavailable")
	}
	producerKey := observability.ProducerKey(audit.ActionGuardrailVerdict)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketGuardrailEvaluation,
		EventName:   observability.EventName(observability.TelemetryEventGuardrailEvaluationCompleted),
		RawSeverity: string(facts.severity),
	}
	connector := facts.connector
	if connector == "unknown" {
		connector = ""
	}
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, connector, producerKey,
	)
	if err != nil {
		return err
	}
	_, logErr := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("guardrail event admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(facts.observedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, connector, apiGuardrailEventV8Producer,
			string(audit.ActionGuardrailVerdict), "finalize",
		)
		envelope.ObservedAt = observability.Present(facts.observedAt)
		envelope.Correlation.EvaluationID = facts.request.EvaluationID
		return builder.BuildLogGuardrailEvaluationCompleted(observability.LogGuardrailEvaluationCompletedInput{
			Envelope: envelope, Severity: observability.Present(facts.severity),
			LogLevel: observability.Present(facts.logLevel), Outcome: facts.outcome,
			GenAIConversationID:                 optionalJudgeMetricText(facts.meta.SessionID),
			GenAIAgentID:                        optionalJudgeMetricText(facts.meta.AgentID),
			GenAIAgentName:                      inspectTraceV8AgentName(facts.meta.AgentName),
			DefenseClawAgentType:                hookV8OptionalText(facts.identity.AgentType, 4096),
			DefenseClawAgentInstanceID:          optionalJudgeMetricText(facts.identity.AgentInstanceID),
			DefenseClawEvaluationID:             facts.request.EvaluationID,
			DefenseClawPolicyID:                 optionalJudgeMetricText(facts.meta.PolicyID),
			DefenseClawGuardrailName:            observability.Present("guardrail-event-api"),
			DefenseClawGuardrailStage:           observability.Present(facts.direction),
			DefenseClawGuardrailPhase:           observability.Present("finalize"),
			DefenseClawGuardrailDirection:       observability.Present(facts.direction),
			DefenseClawGuardrailTargetType:      observability.Present(facts.request.Direction),
			DefenseClawGuardrailDetectorName:    observability.Present("guardrail-proxy"),
			DefenseClawGuardrailLatencyMs:       observability.Present(facts.request.ElapsedMs),
			DefenseClawGuardrailRuleIds:         facts.ruleIDs,
			DefenseClawGuardrailFindingCount:    observability.Present(int64(len(facts.request.Findings))),
			DefenseClawGuardrailDecision:        facts.decision,
			DefenseClawGuardrailEffectiveAction: observability.Present(facts.request.Action),
			DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
			DefenseClawGuardrailReason:          facts.reason,
			GenAIRequestModel:                   facts.model,
			ConditionSecuritySeverityAvailable:  true,
		})
	})
	facts.recordMetrics(ctx, metricRuntime)
	return logErr
}

func (facts apiGuardrailEventV8Facts) recordMetrics(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
) {
	connector := facts.connector
	if connector == "unknown" {
		connector = ""
	}
	metric := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newGatewayGeneratedMetricItem(
			ctx, facts.observedAt, observability.SourceGateway, connector, apiGuardrailEventV8Producer,
			observability.EventName(family),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				envelope.Correlation.EvaluationID = facts.request.EvaluationID
				return build(builder, envelope)
			},
		)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		metric(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailEvaluations(observability.MetricDefenseClawGuardrailEvaluationsInput{
					Envelope: envelope, Value: 1,
					DefenseClawGuardrailEffectiveAction: observability.Present(facts.request.Action),
					DefenseClawConnectorSource:          optionalJudgeMetricText(connector),
					DefenseClawMetricGuardrailScanner:   observability.Present("guardrail-proxy"),
				})
			}),
		metric(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailLatency(observability.MetricDefenseClawGuardrailLatencyInput{
					Envelope: envelope, Value: facts.request.ElapsedMs,
					DefenseClawConnectorSource:        optionalJudgeMetricText(connector),
					DefenseClawMetricGuardrailScanner: observability.Present("guardrail-proxy"),
				})
			}),
	}
	if facts.request.CiscoElapsedMs > 0 {
		items = append(items,
			metric(observability.TelemetryInstrumentDefenseClawGuardrailEvaluations,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawGuardrailEvaluations(observability.MetricDefenseClawGuardrailEvaluationsInput{
						Envelope: envelope, Value: 1,
						DefenseClawGuardrailEffectiveAction: observability.Present(facts.request.Action),
						DefenseClawConnectorSource:          optionalJudgeMetricText(connector),
						DefenseClawMetricGuardrailScanner:   observability.Present("cisco-ai-defense"),
					})
				}),
			metric(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawGuardrailLatency(observability.MetricDefenseClawGuardrailLatencyInput{
						Envelope: envelope, Value: facts.request.CiscoElapsedMs,
						DefenseClawConnectorSource:        optionalJudgeMetricText(connector),
						DefenseClawMetricGuardrailScanner: observability.Present("cisco-ai-defense"),
					})
				}),
		)
	}
	appendTokens := func(tokens *int64, tokenType string) {
		if tokens == nil || *tokens <= 0 {
			return
		}
		items = append(items, metric(observability.TelemetryInstrumentGenAIClientTokenUsage,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				model := observability.Present("unknown")
				if facts.model.IsPresent() {
					model = observability.Present(telemetry.NormalizeModelLabel(facts.request.Model))
				}
				return builder.BuildMetricGenAIClientTokenUsage(observability.MetricGenAIClientTokenUsageInput{
					Envelope: envelope, Value: float64(*tokens),
					GenAIOperationName: observability.Present("chat"),
					GenAIProviderName:  observability.Present("defenseclaw"),
					GenAIRequestModel:  model,
					GenAITokenType:     observability.Present(tokenType),
				})
			}))
	}
	appendTokens(facts.request.TokensIn, "input")
	appendTokens(facts.request.TokensOut, "output")
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}
