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
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

const apiGuardrailEvaluateV8Producer = "gateway.api.guardrail_evaluate"

type apiGuardrailEvaluateV8Runtime interface {
	sidecarRuntimeEmitter
	inspectTraceV8Runtime
	hookLifecycleMetricV8Runtime
}

type apiGuardrailEvaluateV8Facts struct {
	request         guardrailEvaluateRequest
	connector       string
	direction       string
	mode            string
	strategy        observability.Optional[string]
	model           observability.Optional[string]
	decision        string
	effectiveAction string
	outcome         observability.Outcome
	severity        observability.Severity
	logLevel        observability.LogLevel
	detectorSources observability.Optional[[]string]
	ruleIDs         observability.Optional[[]string]
	findingCount    int64
	reason          observability.Optional[string]
	startedAt       time.Time
	completedAt     time.Time
	meta            llmEventMeta
	identity        AgentIdentity
}

func newAPIGuardrailEvaluateV8RequestFacts(
	ctx context.Context,
	api *APIServer,
	request guardrailEvaluateRequest,
) (apiGuardrailEvaluateV8Facts, error) {
	request.EvaluationID = strings.TrimSpace(request.EvaluationID)
	request.Direction = strings.ToLower(strings.TrimSpace(request.Direction))
	request.Mode = strings.ToLower(strings.TrimSpace(request.Mode))
	request.ScannerMode = strings.ToLower(strings.TrimSpace(request.ScannerMode))
	if !hookModelV8Identifier(request.EvaluationID) {
		return apiGuardrailEvaluateV8Facts{}, errors.New("evaluation_id must be a stable identifier")
	}
	if request.Direction != "prompt" && request.Direction != "completion" {
		return apiGuardrailEvaluateV8Facts{}, errors.New("direction must be prompt or completion")
	}
	if request.Mode != "observe" && request.Mode != "action" {
		return apiGuardrailEvaluateV8Facts{}, errors.New("mode must be observe or action")
	}
	if request.ScannerMode != "" && request.ScannerMode != "local" &&
		request.ScannerMode != "remote" && request.ScannerMode != "both" {
		return apiGuardrailEvaluateV8Facts{}, errors.New("scanner_mode must be local, remote, or both")
	}
	if request.ContentLength < 0 {
		return apiGuardrailEvaluateV8Facts{}, errors.New("content_length must be non-negative")
	}
	if request.ElapsedMs < 0 || math.IsNaN(request.ElapsedMs) || math.IsInf(request.ElapsedMs, 0) {
		return apiGuardrailEvaluateV8Facts{}, errors.New("elapsed_ms must be a finite non-negative number")
	}
	model := observability.Absent[string]()
	if strings.TrimSpace(request.Model) != "" {
		model = hookV8OptionalIdentifier(request.Model)
		if !model.IsPresent() {
			return apiGuardrailEvaluateV8Facts{}, errors.New("model must be a stable identifier")
		}
	}
	strategy := observability.Absent[string]()
	if request.ScannerMode != "" {
		strategy = observability.Present(request.ScannerMode)
	}
	connector := ""
	if api != nil {
		connector = api.connectorName()
	}
	if strings.EqualFold(strings.TrimSpace(connector), "unknown") {
		connector = ""
	}
	connector = hookDecisionMetricConnector(firstNonEmpty(connector, audit.EnvelopeFromContext(ctx).Connector))
	meta := hookDecisionMetricMeta(ctx, connector)
	if api != nil {
		meta = api.inspectTraceV8Meta(ctx, connector)
	}
	return apiGuardrailEvaluateV8Facts{
		request: request, connector: connector, direction: inspectTraceV8Direction(request.Direction),
		mode: hookDecisionV8Mode(request.Mode), strategy: strategy, model: model,
		meta: meta, identity: AgentIdentityFromContext(ctx),
	}, nil
}

func (facts apiGuardrailEvaluateV8Facts) complete(
	output *policy.GuardrailOutput,
	startedAt time.Time,
	completedAt time.Time,
) (apiGuardrailEvaluateV8Facts, error) {
	if output == nil {
		return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail output is unavailable")
	}
	action := strings.ToLower(strings.TrimSpace(output.Action))
	switch action {
	case "allow", "alert", "block", "confirm", "deny", "redact":
	default:
		return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail output action is invalid")
	}
	rawSeverity := strings.ToUpper(strings.TrimSpace(output.Severity))
	switch rawSeverity {
	case "NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail output severity is invalid")
	}
	severity := observability.NormalizeSeverity(rawSeverity)
	if !severity.Valid || !severity.Present {
		return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail output severity is invalid")
	}
	sources, err := apiGuardrailEvaluateV8Sources(output.ScannerSources)
	if err != nil {
		return apiGuardrailEvaluateV8Facts{}, err
	}
	reason := observability.Absent[string]()
	if strings.TrimSpace(output.Reason) != "" {
		reason = hookV8OptionalText(output.Reason, 65536)
		if !reason.IsPresent() {
			return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail output reason is invalid")
		}
	}
	if startedAt.IsZero() || completedAt.IsZero() || completedAt.Before(startedAt) {
		return apiGuardrailEvaluateV8Facts{}, errors.New("guardrail evaluation timing is invalid")
	}
	ruleIDs, findingCount := apiGuardrailEvaluateV8RuleIDs(facts.request)
	logLevel := severity.LogLevel
	if logLevel == "" {
		logLevel = observability.LogLevelInfo
	}
	facts.decision = inspectTraceV8Decision(action)
	facts.effectiveAction = action
	facts.outcome = inspectTraceV8Outcome(action)
	facts.severity = severity.Severity
	facts.logLevel = logLevel
	facts.detectorSources = sources
	facts.ruleIDs = ruleIDs
	facts.findingCount = findingCount
	facts.reason = reason
	facts.startedAt = startedAt.UTC()
	facts.completedAt = completedAt.UTC()
	return facts, nil
}

func apiGuardrailEvaluateV8Sources(
	values []string,
) (observability.Optional[[]string], error) {
	if len(values) == 0 {
		return observability.Absent[[]string](), nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !hookModelV8Identifier(value) {
			return observability.Absent[[]string](), errors.New("guardrail output scanner source is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) > 8 {
			return observability.Absent[[]string](), errors.New("guardrail output has too many scanner sources")
		}
	}
	return observability.Present(result), nil
}

func apiGuardrailEvaluateV8RuleIDs(
	request guardrailEvaluateRequest,
) (observability.Optional[[]string], int64) {
	var values []string
	var findingCount int64
	for _, result := range []*policy.GuardrailScanResult{request.LocalResult, request.CiscoResult} {
		if result == nil {
			continue
		}
		findingCount += int64(len(result.Findings))
		for _, finding := range NormalizeScanVerdict(&ScanVerdict{
			Severity: result.Severity, Findings: result.Findings,
		}) {
			values = append(values, finding.CanonicalID)
		}
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
		if len(unique) == 8 {
			break
		}
	}
	return inspectTraceV8RuleIDs(unique), findingCount
}

func (facts apiGuardrailEvaluateV8Facts) routeConnector() string {
	if facts.connector == "unknown" {
		return ""
	}
	return facts.connector
}

func (facts apiGuardrailEvaluateV8Facts) emit(
	ctx context.Context,
	runtime apiGuardrailEvaluateV8Runtime,
) error {
	if ctx == nil || runtime == nil {
		return errors.New("guardrail evaluate runtime is unavailable")
	}
	signalContext := ctx
	traceInput, traceOK := facts.traceInput(ctx)
	var guardrailTrace *observabilityruntime.GuardrailApplyTrace
	if traceOK {
		started, span, err := runtime.StartGuardrailApplyTrace(ctx, traceInput)
		if err == nil && span != nil {
			guardrailTrace = span
			if started != nil {
				signalContext = started
			}
		}
	}
	if guardrailTrace != nil {
		defer guardrailTrace.Abort()
	}
	logErr := facts.emitLog(signalContext, runtime)
	facts.recordMetrics(signalContext, runtime)
	if guardrailTrace != nil {
		_ = guardrailTrace.End(traceInput)
	}
	return logErr
}

func (facts apiGuardrailEvaluateV8Facts) emitLog(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
) error {
	producerKey := observability.ProducerKey(audit.ActionGuardrailOPAVerdict)
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		producerKey,
		observability.ClassificationContext{
			Bucket:      observability.BucketGuardrailEvaluation,
			EventName:   observability.EventName(observability.TelemetryEventGuardrailEvaluationCompleted),
			RawSeverity: string(facts.severity),
		},
		observability.SourceGateway,
		facts.routeConnector(),
		producerKey,
	)
	if err != nil {
		return err
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("guardrail evaluate admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(facts.completedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceGateway, facts.routeConnector(),
			apiGuardrailEvaluateV8Producer, string(audit.ActionGuardrailOPAVerdict), "finalize",
		)
		envelope.ObservedAt = observability.Present(facts.completedAt)
		envelope.Correlation.EvaluationID = facts.request.EvaluationID
		return builder.BuildLogGuardrailEvaluationCompleted(observability.LogGuardrailEvaluationCompletedInput{
			Envelope: envelope, Severity: observability.Present(facts.severity),
			LogLevel: observability.Present(facts.logLevel), Outcome: facts.outcome,
			GenAIConversationID:                 optionalJudgeMetricText(facts.meta.SessionID),
			GenAIAgentID:                        optionalJudgeMetricText(facts.meta.AgentID),
			GenAIAgentName:                      inspectTraceV8AgentName(facts.meta.AgentName),
			DefenseClawAgentType:                hookV8OptionalText(facts.identity.AgentType, 4096),
			DefenseClawAgentInstanceID:          optionalJudgeMetricText(facts.identity.AgentInstanceID),
			DefenseClawAgentRootID:              optionalJudgeMetricText(facts.meta.RootAgentID),
			DefenseClawAgentParentID:            optionalJudgeMetricText(facts.meta.ParentAgentID),
			DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(facts.meta.LineageProvenance),
			DefenseClawSessionRootID:            optionalJudgeMetricText(facts.meta.RootSessionID),
			DefenseClawSessionParentID:          optionalJudgeMetricText(facts.meta.ParentSessionID),
			DefenseClawAgentLifecycleID:         optionalJudgeMetricText(facts.meta.LifecycleID),
			DefenseClawAgentExecutionID:         optionalJudgeMetricText(facts.meta.ExecutionID),
			DefenseClawAgentDepth:               inspectTraceV8Depth(facts.meta),
			DefenseClawAgentLifecycleEvent:      hookV8OptionalText(facts.meta.LifecycleEvent, 4096),
			DefenseClawAgentLifecycleState:      hookV8OptionalText(facts.meta.LifecycleState, 4096),
			DefenseClawAgentPhase:               hookV8OptionalPhase(facts.meta.Phase),
			DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(facts.meta.PreviousPhase),
			DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(facts.meta.Phase),
			DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(facts.meta.Sequence),
			DefenseClawSessionSource:            hookV8OptionalSessionSource(facts.meta.SessionSource),
			DefenseClawSessionResumed:           hookV8OptionalSessionResumed(facts.meta),
			DefenseClawEvaluationID:             facts.request.EvaluationID,
			DefenseClawPolicyID:                 optionalJudgeMetricText(facts.meta.PolicyID),
			DefenseClawGuardrailName:            observability.Present("opa-guardrail"),
			DefenseClawGuardrailStrategy:        facts.strategy,
			DefenseClawGuardrailStage:           observability.Present(facts.direction),
			DefenseClawGuardrailPhase:           observability.Present("policy"),
			DefenseClawGuardrailDirection:       observability.Present(facts.direction),
			DefenseClawGuardrailTargetType:      observability.Present(facts.request.Direction),
			DefenseClawGuardrailDetectorName:    observability.Present("opa-guardrail"),
			DefenseClawGuardrailDetectorSources: facts.detectorSources,
			DefenseClawGuardrailLatencyMs:       observability.Present(facts.request.ElapsedMs),
			DefenseClawGuardrailRuleIds:         facts.ruleIDs,
			DefenseClawGuardrailFindingCount:    observability.Present(facts.findingCount),
			DefenseClawGuardrailDecision:        facts.decision,
			DefenseClawGuardrailEffectiveAction: observability.Present(facts.effectiveAction),
			DefenseClawGuardrailMode:            observability.Present(facts.mode),
			DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
			DefenseClawGuardrailReason:          facts.reason,
			GenAIRequestModel:                   facts.model,
			ConditionSecuritySeverityAvailable:  true,
		})
	})
	return err
}

func (facts apiGuardrailEvaluateV8Facts) recordMetrics(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
) {
	connector := facts.routeConnector()
	metric := func(
		family string,
		build hookV8MetricRecordBuilder,
	) observabilityruntime.GeneratedMetricBatchItem {
		return newGatewayGeneratedMetricItem(
			ctx, facts.completedAt, observability.SourceGateway, connector,
			apiGuardrailEvaluateV8Producer, observability.EventName(family),
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
					DefenseClawGuardrailEffectiveAction: observability.Present(facts.effectiveAction),
					DefenseClawConnectorSource:          optionalJudgeMetricText(connector),
					DefenseClawMetricGuardrailScanner:   observability.Present("opa-guardrail"),
				})
			}),
		metric(observability.TelemetryInstrumentDefenseClawGuardrailLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawGuardrailLatency(observability.MetricDefenseClawGuardrailLatencyInput{
					Envelope: envelope, Value: facts.request.ElapsedMs,
					DefenseClawConnectorSource:        optionalJudgeMetricText(connector),
					DefenseClawMetricGuardrailScanner: observability.Present("opa-guardrail"),
				})
			}),
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func (facts apiGuardrailEvaluateV8Facts) traceInput(
	ctx context.Context,
) (observability.SpanGuardrailApplyInput, bool) {
	correlation := gatewayGeneratedCorrelation(ctx, facts.routeConnector())
	correlation.EvaluationID = facts.request.EvaluationID
	events := make([]observability.TraceEventInput, 0, 1)
	decisionEvent, err := observability.NewSpanGuardrailApplyGuardrailDecisionEvent(
		observability.SpanGuardrailApplyGuardrailDecisionEventInput{
			TimeUnixNano:                        uint64(facts.completedAt.UnixNano()),
			DefenseClawEvaluationID:             observability.Present(facts.request.EvaluationID),
			DefenseClawGuardrailDecision:        observability.Present(facts.decision),
			DefenseClawGuardrailEffectiveAction: observability.Present(facts.effectiveAction),
			DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
		},
	)
	if err != nil {
		return observability.SpanGuardrailApplyInput{}, false
	}
	events = append(events, decisionEvent)
	return observability.SpanGuardrailApplyInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(facts.completedAt),
			Source:     observability.SourceGateway, Connector: facts.routeConnector(),
			Action: string(audit.ActionGuardrailOPAVerdict), Phase: "policy",
			Correlation: correlation,
			Provenance:  observability.FamilyProvenanceInput{Producer: apiGuardrailEvaluateV8Producer},
		},
		Outcome: facts.outcome, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(facts.startedAt.UnixNano()),
		EndTimeUnixNano:   uint64(facts.completedAt.UnixNano()),
		Status:            observability.NewTraceStatusOK(), Events: events,
		DefenseClawConnectorSource:          optionalJudgeMetricText(facts.routeConnector()),
		DefenseClawRunID:                    optionalJudgeMetricText(facts.meta.RunID),
		DefenseClawOperationID:              optionalJudgeMetricText(facts.meta.OperationID),
		DefenseClawRequestID:                optionalJudgeMetricText(facts.meta.RequestID),
		DefenseClawTurnID:                   optionalJudgeMetricText(facts.meta.TurnID),
		GenAIConversationID:                 optionalJudgeMetricText(facts.meta.SessionID),
		GenAIAgentID:                        optionalJudgeMetricText(facts.meta.AgentID),
		GenAIAgentName:                      inspectTraceV8AgentName(facts.meta.AgentName),
		DefenseClawAgentType:                hookV8OptionalText(facts.identity.AgentType, 4096),
		DefenseClawAgentInstanceID:          optionalJudgeMetricText(facts.identity.AgentInstanceID),
		DefenseClawAgentRootID:              optionalJudgeMetricText(facts.meta.RootAgentID),
		DefenseClawAgentParentID:            optionalJudgeMetricText(facts.meta.ParentAgentID),
		DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(facts.meta.LineageProvenance),
		DefenseClawSessionRootID:            optionalJudgeMetricText(facts.meta.RootSessionID),
		DefenseClawSessionParentID:          optionalJudgeMetricText(facts.meta.ParentSessionID),
		DefenseClawAgentLifecycleID:         optionalJudgeMetricText(facts.meta.LifecycleID),
		DefenseClawAgentExecutionID:         optionalJudgeMetricText(facts.meta.ExecutionID),
		DefenseClawAgentDepth:               inspectTraceV8Depth(facts.meta),
		DefenseClawAgentLifecycleEvent:      hookV8OptionalText(facts.meta.LifecycleEvent, 4096),
		DefenseClawAgentLifecycleState:      hookV8OptionalText(facts.meta.LifecycleState, 4096),
		DefenseClawAgentPhase:               hookV8OptionalPhase(facts.meta.Phase),
		DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(facts.meta.PreviousPhase),
		DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(facts.meta.Phase),
		DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(facts.meta.Sequence),
		DefenseClawSessionSource:            hookV8OptionalSessionSource(facts.meta.SessionSource),
		DefenseClawSessionResumed:           hookV8OptionalSessionResumed(facts.meta),
		DefenseClawEvaluationID:             observability.Present(facts.request.EvaluationID),
		DefenseClawPolicyID:                 optionalJudgeMetricText(facts.meta.PolicyID),
		DefenseClawGuardrailName:            "opa-guardrail",
		DefenseClawGuardrailStrategy:        facts.strategy,
		DefenseClawGuardrailStage:           observability.Present(facts.direction),
		DefenseClawGuardrailPhase:           observability.Present("policy"),
		DefenseClawGuardrailDirection:       observability.Present(facts.direction),
		DefenseClawGuardrailTargetType:      facts.request.Direction,
		DefenseClawGuardrailDetectorName:    observability.Present("opa-guardrail"),
		DefenseClawGuardrailDetectorSources: facts.detectorSources,
		DefenseClawGuardrailLatencyMs:       observability.Present(float64(facts.completedAt.Sub(facts.startedAt)) / float64(time.Millisecond)),
		DefenseClawGuardrailRuleIds:         facts.ruleIDs,
		DefenseClawGuardrailFindingCount:    observability.Present(facts.findingCount),
		DefenseClawGuardrailDecision:        observability.Present(facts.decision),
		DefenseClawGuardrailEffectiveAction: observability.Present(facts.effectiveAction),
		DefenseClawGuardrailMode:            observability.Present(facts.mode),
		DefenseClawSecuritySeverity:         observability.Present(string(facts.severity)),
		DefenseClawGuardrailReason:          facts.reason,
		ConditionConnectorKnown:             facts.routeConnector() != "",
		ConditionOperationTerminal:          true,
	}, true
}
