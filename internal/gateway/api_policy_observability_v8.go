// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const apiPolicyEvaluationV8Producer = "gateway.api.policy_evaluation"

type apiPolicyEvaluationV8Runtime interface {
	sidecarRuntimeEmitter
	inspectTraceV8Runtime
	hookLifecycleMetricV8Runtime
}

// apiPolicyEvaluationV8Operation owns one real OPA policy evaluation. The
// operation mints only its evaluation correlation identifier; request, W3C,
// agent, turn, tool, session, and policy topology remain source-backed.
type apiPolicyEvaluationV8Operation struct {
	runtime      apiPolicyEvaluationV8Runtime
	trace        *observabilityruntime.GuardrailApplyTrace
	signalCtx    context.Context
	domain       string
	guardrail    string
	targetType   string
	targetRef    observability.Optional[string]
	evaluationID string
	connector    string
	startedAt    time.Time
	meta         llmEventMeta
	identity     AgentIdentity
}

func (a *APIServer) startAPIPolicyEvaluationV8(
	ctx context.Context,
	domain string,
	targetType string,
	targetRef string,
) (context.Context, *apiPolicyEvaluationV8Operation, error) {
	if a == nil || ctx == nil {
		return ctx, nil, errors.New("policy observability runtime is unavailable")
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(apiPolicyEvaluationV8Runtime)
	if !ok || runtime == nil {
		return ctx, nil, errors.New("policy observability runtime is unavailable")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	if domain == "" || targetType == "" || len(domain) > 128 || len(targetType) > 4096 {
		return ctx, nil, errors.New("policy observability identity is invalid")
	}
	target := observability.Absent[string]()
	if targetRef != "" {
		target = hookV8OptionalText(targetRef, 4096)
		if !target.IsPresent() {
			return ctx, nil, errors.New("policy target reference is invalid")
		}
	}
	connector := hookDecisionMetricConnector(firstNonEmpty(
		a.connectorName(), audit.EnvelopeFromContext(ctx).Connector,
	))
	if connector == "unknown" {
		connector = ""
	}
	operation := &apiPolicyEvaluationV8Operation{
		runtime: runtime, signalCtx: ctx, domain: domain, guardrail: "opa-" + domain,
		targetType: targetType, targetRef: target, evaluationID: uuid.NewString(), connector: connector,
		startedAt: time.Now().UTC(), meta: a.inspectTraceV8Meta(ctx, connector),
		identity: AgentIdentityFromContext(ctx),
	}
	input := operation.traceInput(ctx, operation.startedAt, observability.OutcomeAttempted, "", "", nil)
	started, span, err := runtime.StartGuardrailApplyTrace(ctx, input)
	if err != nil {
		return ctx, nil, errors.New("policy observability trace is unavailable")
	}
	operation.trace = span
	if started != nil {
		operation.signalCtx = started
	}
	return operation.signalCtx, operation, nil
}

func (operation *apiPolicyEvaluationV8Operation) complete(
	verdict string,
	reason string,
	rawSeverity string,
	technicalErr error,
) error {
	if operation == nil || operation.runtime == nil || operation.signalCtx == nil {
		return errors.New("policy observability operation is unavailable")
	}
	completedAt := time.Now().UTC()
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if technicalErr != nil {
		verdict = "error"
		reason = technicalErr.Error()
	}
	severity := apiPolicyEvaluationSeverity(rawSeverity)
	var emitErr error
	if technicalErr != nil {
		emitErr = operation.emitFailed(completedAt, reason, severity)
	} else {
		emitErr = operation.emitCompleted(completedAt, verdict, reason, severity)
	}
	metricErr := operation.recordMetrics(completedAt, verdict)

	outcome := apiPolicyEvaluationOutcome(verdict)
	status := observability.NewTraceStatusOK()
	errorType := ""
	if technicalErr != nil {
		outcome = observability.OutcomeFailed
		errorType = "policy_evaluation_failed"
		status = observability.NewTraceStatusError(observability.Present(errorType))
	}
	if operation.trace != nil {
		input := operation.traceInput(operation.signalCtx, completedAt, outcome, verdict, reason, technicalErr)
		input.Status = status
		input.ErrorType = hookV8OptionalText(errorType, 4096)
		if err := operation.trace.End(input); err != nil {
			emitErr = errors.Join(emitErr, err)
		}
	}
	return errors.Join(emitErr, metricErr)
}

func apiPolicyEvaluationSeverity(raw string) observability.Optional[string] {
	if strings.TrimSpace(raw) == "" {
		return observability.Absent[string]()
	}
	normalized := observability.NormalizeSeverity(raw)
	if !normalized.Valid || !normalized.Present {
		return observability.Absent[string]()
	}
	return observability.Present(string(normalized.Severity))
}

func apiPolicyEvaluationOutcome(verdict string) observability.Outcome {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "allow", "allowed", "retain":
		return observability.OutcomeAllowed
	case "block", "blocked":
		return observability.OutcomeBlocked
	case "deny", "denied":
		return observability.OutcomeDenied
	case "reject", "rejected":
		return observability.OutcomeRejected
	case "redact", "redacted":
		return observability.OutcomeRedacted
	case "skip", "skipped":
		return observability.OutcomeSkipped
	case "error", "failed":
		return observability.OutcomeFailed
	default:
		return observability.OutcomeCompleted
	}
}

func apiPolicyEvaluationDecision(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "allow", "allowed", "retain":
		return "allow"
	case "block", "blocked", "reject", "rejected":
		return "block"
	case "deny", "denied":
		return "deny"
	case "redact", "redacted":
		return "redact"
	default:
		return "review"
	}
}

func (operation *apiPolicyEvaluationV8Operation) emitCompleted(
	completedAt time.Time,
	verdict string,
	reason string,
	severity observability.Optional[string],
) error {
	metadata, err := operation.logMetadata(
		observability.TelemetryEventGuardrailEvaluationCompleted, string(observability.SeverityInfo),
	)
	if err != nil {
		return err
	}
	_, err = operation.runtime.Emit(operation.signalCtx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("policy evaluation admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(completedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := gatewayGeneratedEnvelope(
			operation.signalCtx, snapshot, observability.SourceGateway, operation.connector,
			apiPolicyEvaluationV8Producer, string(audit.ActionGuardrailOPAVerdict), operation.domain,
		)
		envelope.ObservedAt = observability.Present(completedAt)
		envelope.Correlation.EvaluationID = operation.evaluationID
		return builder.BuildLogGuardrailEvaluationCompleted(observability.LogGuardrailEvaluationCompletedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
			LogLevel:                            observability.Present(observability.LogLevelInfo),
			Outcome:                             apiPolicyEvaluationOutcome(verdict),
			GenAIConversationID:                 optionalJudgeMetricText(operation.meta.SessionID),
			GenAIAgentID:                        optionalJudgeMetricText(operation.meta.AgentID),
			GenAIAgentName:                      inspectTraceV8AgentName(operation.meta.AgentName),
			DefenseClawAgentType:                hookV8OptionalText(operation.identity.AgentType, 4096),
			DefenseClawAgentInstanceID:          optionalJudgeMetricText(operation.identity.AgentInstanceID),
			DefenseClawAgentRootID:              optionalJudgeMetricText(operation.meta.RootAgentID),
			DefenseClawAgentParentID:            optionalJudgeMetricText(operation.meta.ParentAgentID),
			DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(operation.meta.LineageProvenance),
			DefenseClawSessionRootID:            optionalJudgeMetricText(operation.meta.RootSessionID),
			DefenseClawSessionParentID:          optionalJudgeMetricText(operation.meta.ParentSessionID),
			DefenseClawAgentLifecycleID:         optionalJudgeMetricText(operation.meta.LifecycleID),
			DefenseClawAgentExecutionID:         optionalJudgeMetricText(operation.meta.ExecutionID),
			DefenseClawAgentDepth:               inspectTraceV8Depth(operation.meta),
			DefenseClawAgentLifecycleEvent:      hookV8OptionalText(operation.meta.LifecycleEvent, 4096),
			DefenseClawAgentLifecycleState:      hookV8OptionalText(operation.meta.LifecycleState, 4096),
			DefenseClawAgentPhase:               hookV8OptionalPhase(operation.meta.Phase),
			DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(operation.meta.PreviousPhase),
			DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(operation.meta.Phase),
			DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(operation.meta.Sequence),
			DefenseClawSessionSource:            hookV8OptionalSessionSource(operation.meta.SessionSource),
			DefenseClawSessionResumed:           hookV8OptionalSessionResumed(operation.meta),
			DefenseClawEvaluationID:             operation.evaluationID,
			DefenseClawPolicyID:                 optionalJudgeMetricText(operation.meta.PolicyID),
			DefenseClawGuardrailName:            observability.Present(operation.guardrail),
			DefenseClawGuardrailStage:           observability.Present(operation.domain),
			DefenseClawGuardrailPhase:           observability.Present("policy"),
			DefenseClawGuardrailTargetType:      observability.Present(operation.targetType),
			DefenseClawGuardrailTargetRef:       operation.targetRef,
			DefenseClawGuardrailDetectorName:    observability.Present("opa"),
			DefenseClawGuardrailLatencyMs:       observability.Present(apiPolicyEvaluationLatency(operation.startedAt, completedAt)),
			DefenseClawGuardrailDecision:        apiPolicyEvaluationDecision(verdict),
			DefenseClawGuardrailEffectiveAction: hookV8OptionalText(verdict, 4096),
			DefenseClawSecuritySeverity:         severity,
			DefenseClawGuardrailReason:          hookV8OptionalText(reason, 65536),
			ConditionSecuritySeverityAvailable:  severity.IsPresent(),
		})
	})
	return err
}

func (operation *apiPolicyEvaluationV8Operation) emitFailed(
	completedAt time.Time,
	reason string,
	severity observability.Optional[string],
) error {
	metadata, err := operation.logMetadata(
		observability.TelemetryEventGuardrailEvaluationFailed, string(observability.SeverityHigh),
	)
	if err != nil {
		return err
	}
	_, err = operation.runtime.Emit(operation.signalCtx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("policy evaluation failure admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(completedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := gatewayGeneratedEnvelope(
			operation.signalCtx, snapshot, observability.SourceGateway, operation.connector,
			apiPolicyEvaluationV8Producer, string(audit.ActionGuardrailOPAVerdict), operation.domain,
		)
		envelope.ObservedAt = observability.Present(completedAt)
		envelope.Correlation.EvaluationID = operation.evaluationID
		return builder.BuildLogGuardrailEvaluationFailed(observability.LogGuardrailEvaluationFailedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityHigh),
			LogLevel: observability.Present(observability.LogLevelError), Outcome: observability.OutcomeFailed,
			GenAIConversationID:                optionalJudgeMetricText(operation.meta.SessionID),
			GenAIAgentID:                       optionalJudgeMetricText(operation.meta.AgentID),
			GenAIAgentName:                     inspectTraceV8AgentName(operation.meta.AgentName),
			DefenseClawAgentType:               hookV8OptionalText(operation.identity.AgentType, 4096),
			DefenseClawAgentInstanceID:         optionalJudgeMetricText(operation.identity.AgentInstanceID),
			DefenseClawAgentRootID:             optionalJudgeMetricText(operation.meta.RootAgentID),
			DefenseClawAgentParentID:           optionalJudgeMetricText(operation.meta.ParentAgentID),
			DefenseClawAgentLineageProvenance:  hookV8OptionalLineageProvenance(operation.meta.LineageProvenance),
			DefenseClawSessionRootID:           optionalJudgeMetricText(operation.meta.RootSessionID),
			DefenseClawSessionParentID:         optionalJudgeMetricText(operation.meta.ParentSessionID),
			DefenseClawAgentLifecycleID:        optionalJudgeMetricText(operation.meta.LifecycleID),
			DefenseClawAgentExecutionID:        optionalJudgeMetricText(operation.meta.ExecutionID),
			DefenseClawAgentDepth:              inspectTraceV8Depth(operation.meta),
			DefenseClawEvaluationID:            operation.evaluationID,
			DefenseClawPolicyID:                optionalJudgeMetricText(operation.meta.PolicyID),
			DefenseClawGuardrailName:           observability.Present(operation.guardrail),
			DefenseClawGuardrailStage:          observability.Present(operation.domain),
			DefenseClawGuardrailPhase:          observability.Present("policy"),
			DefenseClawGuardrailTargetType:     observability.Present(operation.targetType),
			DefenseClawGuardrailTargetRef:      operation.targetRef,
			DefenseClawGuardrailDetectorName:   observability.Present("opa"),
			DefenseClawGuardrailLatencyMs:      observability.Present(apiPolicyEvaluationLatency(operation.startedAt, completedAt)),
			DefenseClawSecuritySeverity:        severity,
			DefenseClawGuardrailReason:         hookV8OptionalText(reason, 65536),
			ConditionSecuritySeverityAvailable: severity.IsPresent(),
		})
	})
	return err
}

func (operation *apiPolicyEvaluationV8Operation) logMetadata(
	eventName string,
	severity string,
) (observabilityrouter.Metadata, error) {
	producerKey := observability.ProducerKey(audit.ActionGuardrailOPAVerdict)
	return observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey,
		observability.ClassificationContext{
			Bucket:    observability.BucketGuardrailEvaluation,
			EventName: observability.EventName(eventName), RawSeverity: severity,
		},
		observability.SourceGateway, operation.connector, producerKey,
	)
}

func (operation *apiPolicyEvaluationV8Operation) recordMetrics(
	completedAt time.Time,
	verdict string,
) error {
	metric := func(family string, build hookV8MetricRecordBuilder) observabilityruntime.GeneratedMetricBatchItem {
		return newGatewayGeneratedMetricItem(
			operation.signalCtx, completedAt, observability.SourceGateway, operation.connector,
			apiPolicyEvaluationV8Producer, observability.EventName(family),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				envelope.Correlation.EvaluationID = operation.evaluationID
				return build(builder, envelope)
			},
		)
	}
	items := []observabilityruntime.GeneratedMetricBatchItem{
		metric(observability.TelemetryInstrumentDefenseClawPolicyEvaluations,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawPolicyEvaluations(observability.MetricDefenseClawPolicyEvaluationsInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricPolicyDomain:  observability.Present(operation.domain),
					DefenseClawMetricPolicyVerdict: observability.Present(verdict),
				})
			}),
		metric(observability.TelemetryInstrumentDefenseClawPolicyLatency,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawPolicyLatency(observability.MetricDefenseClawPolicyLatencyInput{
					Envelope: envelope, Value: apiPolicyEvaluationLatency(operation.startedAt, completedAt),
					DefenseClawMetricPolicyDomain: observability.Present(operation.domain),
				})
			}),
	}
	if operation.domain == "admission" {
		items = append(items,
			metric(observability.TelemetryInstrumentDefenseClawAdmissionDecisions,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawAdmissionDecisions(observability.MetricDefenseClawAdmissionDecisionsInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricDecision:   observability.Present(verdict),
						DefenseClawMetricSource:     observability.Present("api"),
						DefenseClawMetricTargetType: observability.Present(operation.targetType),
					})
				}),
			metric(observability.TelemetryInstrumentDefenseClawSloBlockLatency,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawSloBlockLatency(observability.MetricDefenseClawSloBlockLatencyInput{
						Envelope: envelope, Value: apiPolicyEvaluationLatency(operation.startedAt, completedAt),
						DefenseClawMetricTargetType: observability.Present(operation.targetType),
					})
				}),
		)
	}
	_, err := operation.runtime.RecordGeneratedMetricBatch(operation.signalCtx, items)
	return err
}

func (operation *apiPolicyEvaluationV8Operation) traceInput(
	ctx context.Context,
	completedAt time.Time,
	outcome observability.Outcome,
	verdict string,
	reason string,
	technicalErr error,
) observability.SpanGuardrailApplyInput {
	correlation := gatewayGeneratedCorrelation(ctx, operation.connector)
	correlation.EvaluationID = operation.evaluationID
	status := observability.NewTraceStatusUnset()
	if outcome != observability.OutcomeAttempted {
		status = observability.NewTraceStatusOK()
	}
	decision := observability.Absent[string]()
	effectiveAction := observability.Absent[string]()
	if technicalErr == nil && verdict != "" {
		decision = hookV8OptionalText(apiPolicyEvaluationDecision(verdict), 4096)
		effectiveAction = hookV8OptionalText(verdict, 4096)
	}
	input := observability.SpanGuardrailApplyInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(completedAt), Source: observability.SourceGateway,
			Connector: operation.connector, Action: string(audit.ActionGuardrailOPAVerdict), Phase: operation.domain,
			Correlation: correlation, Provenance: observability.FamilyProvenanceInput{Producer: apiPolicyEvaluationV8Producer},
		},
		Outcome: outcome, Kind: "INTERNAL", StartTimeUnixNano: uint64(operation.startedAt.UnixNano()),
		EndTimeUnixNano: uint64(completedAt.UnixNano()), Status: status,
		DefenseClawConnectorSource:        optionalJudgeMetricText(operation.connector),
		DefenseClawRunID:                  optionalJudgeMetricText(operation.meta.RunID),
		DefenseClawOperationID:            optionalJudgeMetricText(operation.meta.OperationID),
		DefenseClawRequestID:              optionalJudgeMetricText(operation.meta.RequestID),
		DefenseClawTurnID:                 optionalJudgeMetricText(operation.meta.TurnID),
		GenAIConversationID:               optionalJudgeMetricText(operation.meta.SessionID),
		GenAIAgentID:                      optionalJudgeMetricText(operation.meta.AgentID),
		GenAIAgentName:                    inspectTraceV8AgentName(operation.meta.AgentName),
		DefenseClawAgentType:              hookV8OptionalText(operation.identity.AgentType, 4096),
		DefenseClawAgentInstanceID:        optionalJudgeMetricText(operation.identity.AgentInstanceID),
		DefenseClawAgentRootID:            optionalJudgeMetricText(operation.meta.RootAgentID),
		DefenseClawAgentParentID:          optionalJudgeMetricText(operation.meta.ParentAgentID),
		DefenseClawAgentLineageProvenance: hookV8OptionalLineageProvenance(operation.meta.LineageProvenance),
		DefenseClawSessionRootID:          optionalJudgeMetricText(operation.meta.RootSessionID),
		DefenseClawSessionParentID:        optionalJudgeMetricText(operation.meta.ParentSessionID),
		DefenseClawAgentLifecycleID:       optionalJudgeMetricText(operation.meta.LifecycleID),
		DefenseClawAgentExecutionID:       optionalJudgeMetricText(operation.meta.ExecutionID),
		DefenseClawAgentDepth:             inspectTraceV8Depth(operation.meta),
		DefenseClawAgentLifecycleEvent:    hookV8OptionalText(operation.meta.LifecycleEvent, 4096),
		DefenseClawAgentLifecycleState:    hookV8OptionalText(operation.meta.LifecycleState, 4096),
		DefenseClawAgentPhase:             hookV8OptionalPhase(operation.meta.Phase),
		DefenseClawAgentPhasePrevious:     hookV8OptionalPhase(operation.meta.PreviousPhase),
		DefenseClawAgentPhaseCode:         hookV8OptionalPhaseCode(operation.meta.Phase),
		DefenseClawAgentSequence:          hookV8OptionalPositiveInt64(operation.meta.Sequence),
		DefenseClawSessionSource:          hookV8OptionalSessionSource(operation.meta.SessionSource),
		DefenseClawSessionResumed:         hookV8OptionalSessionResumed(operation.meta),
		DefenseClawEvaluationID:           observability.Present(operation.evaluationID),
		DefenseClawPolicyID:               optionalJudgeMetricText(operation.meta.PolicyID),
		DefenseClawGuardrailName:          operation.guardrail,
		DefenseClawGuardrailStage:         observability.Present(operation.domain),
		DefenseClawGuardrailPhase:         observability.Present("policy"),
		DefenseClawGuardrailTargetType:    operation.targetType,
		DefenseClawGuardrailTargetRef:     operation.targetRef,
		DefenseClawGuardrailDetectorName:  observability.Present("opa"),
		DefenseClawGuardrailLatencyMs: observability.Present(
			apiPolicyEvaluationLatency(operation.startedAt, completedAt),
		),
		DefenseClawGuardrailDecision:        decision,
		DefenseClawGuardrailEffectiveAction: effectiveAction,
		DefenseClawGuardrailReason:          hookV8OptionalText(reason, 65536),
		ConditionConnectorKnown:             operation.connector != "",
		ConditionOperationTerminal:          outcome != observability.OutcomeAttempted,
		ConditionTechnicalFailure:           technicalErr != nil,
	}
	return input
}

func apiPolicyEvaluationLatency(startedAt time.Time, completedAt time.Time) float64 {
	if completedAt.Before(startedAt) {
		return 0
	}
	return float64(completedAt.Sub(startedAt)) / float64(time.Millisecond)
}

func (a *APIServer) recordAPIPolicyReloadMetricV8(ctx context.Context, status string) error {
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil || ctx == nil {
		return errors.New("policy reload observability runtime is unavailable")
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "success" && status != "failed" {
		return errors.New("policy reload status is invalid")
	}
	connector := hookDecisionMetricConnector(firstNonEmpty(
		a.connectorName(), audit.EnvelopeFromContext(ctx).Connector,
	))
	if connector == "unknown" {
		connector = ""
	}
	completedAt := time.Now().UTC()
	item := newGatewayGeneratedMetricItem(
		ctx, completedAt, observability.SourceOperatorAPI, connector,
		apiPolicyEvaluationV8Producer, observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyReloads),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawPolicyReloads(observability.MetricDefenseClawPolicyReloadsInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricPolicyStatus: observability.Present(status),
			})
		},
	)
	_, err := runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
	return err
}

func (a *APIServer) emitAPIPolicyReloadRejectedV8(ctx context.Context, reason string) error {
	runtime, ok := a.observabilityV8RuntimeEmitter().(sidecarRuntimeEmitter)
	if !ok || runtime == nil || ctx == nil {
		return errors.New("policy reload observability runtime is unavailable")
	}
	producerKey := observability.ProducerKey(audit.ActionPolicyReload)
	classification := observability.ClassificationContext{
		Bucket:         observability.BucketComplianceActivity,
		EventName:      observability.EventName(observability.TelemetryEventPolicyReloadRejected),
		RawSeverity:    string(observability.SeverityHigh),
		MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
	}
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey,
		classification,
		observability.SourceOperatorAPI, "", producerKey,
	)
	if err != nil {
		return err
	}
	observedAt := time.Now().UTC()
	_, err = runtime.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 || !observability.IsStableToken(snapshot.Digest()) {
			return observability.Record{}, errors.New("policy reload rejection generation is invalid")
		}
		if admission == observabilityrouter.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
				ClassificationContext: classification, Source: observability.SourceOperatorAPI,
				Action: string(audit.ActionPolicyReload), Phase: "reload", Outcome: observability.OutcomeFailed,
				Correlation: gatewayGeneratedCorrelation(ctx, ""),
				Provenance: observability.Provenance{
					Producer: apiPolicyEvaluationV8Producer, BinaryVersion: version.Current().BinaryVersion,
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			})
		}
		if admission != observabilityrouter.AdmissionOrdinary {
			return observability.Record{}, errors.New("policy reload rejection admission is invalid")
		}
		builder, buildErr := proxyGuardrailV8Builder(observedAt)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := gatewayGeneratedEnvelope(
			ctx, snapshot, observability.SourceOperatorAPI, "", apiPolicyEvaluationV8Producer,
			string(audit.ActionPolicyReload), "reload",
		)
		envelope.ObservedAt = observability.Present(observedAt)
		principal := observability.Absent[string]()
		return builder.BuildLogPolicyReloadRejected(observability.LogPolicyReloadRejectedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityHigh),
			LogLevel: observability.Present(observability.LogLevelError), Outcome: observability.OutcomeFailed,
			DefenseClawAdminOperation:     string(audit.ActionPolicyReload),
			DefenseClawAdminPrincipalRef:  principal,
			DefenseClawAdminActorRef:      principal,
			DefenseClawAdminOrigin:        observability.Present("api"),
			DefenseClawAdminReason:        hookV8OptionalText(truncate(reason, 256), 256),
			ConditionAdminPrincipalKnown:  principal.IsPresent(),
			MandatoryControlPlaneMutation: true,
		})
	})
	return err
}
