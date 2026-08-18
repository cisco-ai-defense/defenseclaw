// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const (
	hiltV8Producer          = "gateway.hilt.approval"
	hiltV8Connector         = "openclaw"
	hiltV8MetricRecordLimit = time.Second
	hiltV8LogRecordLimit    = 5 * time.Second
)

type hiltObservabilityV8Runtime interface {
	sidecarRuntimeEmitter
	StartApprovalTrace(context.Context, observability.SpanApprovalResolveInput) (context.Context, *observabilityruntime.ApprovalTrace, error)
	RecordGeneratedMetricBatch(context.Context, []observabilityruntime.GeneratedMetricBatchItem) ([]telemetry.V8MetricRecordResult, error)
}

type hiltV8Operation struct {
	mu       sync.Mutex
	finished bool
	runtime  hiltObservabilityV8Runtime
	trace    *observabilityruntime.ApprovalTrace
	ctx      context.Context
	input    observability.SpanApprovalResolveInput
	severity observability.Severity
	started  time.Time
}

func (m *HILTApprovalManager) bindObservabilityV8(runtime hiltObservabilityV8Runtime) {
	if m == nil {
		return
	}
	m.observabilityMu.Lock()
	m.observabilityV8 = runtime
	m.observabilityV8Authoritative = true
	m.observabilityMu.Unlock()
}

func (m *HILTApprovalManager) observabilityV8Snapshot() (hiltObservabilityV8Runtime, bool) {
	if m == nil {
		return nil, false
	}
	m.observabilityMu.RLock()
	defer m.observabilityMu.RUnlock()
	return m.observabilityV8, m.observabilityV8Authoritative
}

func (m *HILTApprovalManager) startHILTApprovalV8(
	ctx context.Context,
	id string,
	sessionID string,
	subject string,
	severity string,
	reason string,
	evaluation HILTApprovalContext,
	started time.Time,
) (*hiltV8Operation, error) {
	runtime, authoritative := m.observabilityV8Snapshot()
	if !authoritative {
		// Isolated unit users do not own process observability. Production binds
		// the runtime before Sidecar.Run can accept an approval request.
		return nil, nil
	}
	if runtime == nil || ctx == nil || started.IsZero() || started.UnixNano() <= 0 ||
		!hookModelV8Identifier(id) {
		return nil, errors.New("hilt v8 runtime is unavailable")
	}
	ruleIDs, ok := boundedHILTRuleIDs(evaluation.RuleIDs)
	if !ok {
		return nil, errors.New("hilt v8 rule identity is invalid")
	}
	canonicalSeverity := hiltV8Severity(severity)
	subject = boundedHILTText(subject, 65_536)
	reason = boundedHILTText(reason, 4_096)
	envelope := audit.MergeEnvelope(audit.CorrelationEnvelope{
		RunID: evaluation.RunID, RequestID: evaluation.RequestID, SessionID: evaluation.SessionID,
		TurnID: evaluation.TurnID, AgentID: evaluation.AgentID, AgentName: evaluation.AgentName,
		AgentInstanceID: evaluation.AgentInstanceID, PolicyID: evaluation.PolicyID,
		DestinationApp: evaluation.DestinationApp, ToolName: evaluation.ToolName,
		ToolID: evaluation.ToolID,
	}, audit.EnvelopeFromContext(ctx))
	correlation := observability.Correlation{
		RunID:     proxyV8StableID(envelope.RunID),
		RequestID: proxyV8StableID(envelope.RequestID), SessionID: proxyV8StableID(firstNonEmpty(envelope.SessionID, sessionID)),
		TurnID: proxyV8StableID(envelope.TurnID), AgentID: proxyV8StableID(envelope.AgentID),
		AgentInstanceID: proxyV8StableID(envelope.AgentInstanceID), PolicyID: proxyV8StableID(envelope.PolicyID),
		PolicyVersion: proxyV8StableID(evaluation.PolicyVersion), ToolInvocationID: proxyV8StableID(evaluation.ToolCallID),
		EvaluationID: proxyV8StableID(evaluation.EvaluationID), ConnectorID: hiltV8Connector,
		SidecarInstanceID: proxyV8StableID(gatewaylog.SidecarInstanceID()),
	}
	requested, err := observability.NewSpanApprovalResolveApprovalRequestedEvent(
		observability.SpanApprovalResolveApprovalRequestedEventInput{
			TimeUnixNano: uint64(started.UnixNano()), DefenseClawApprovalID: observability.Present(id),
		},
	)
	if err != nil {
		return nil, err
	}
	input := observability.SpanApprovalResolveInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway, Connector: hiltV8Connector,
			Action: string(audit.ActionGuardrailHILT), Phase: "approval",
			Correlation: correlation, Provenance: observability.FamilyProvenanceInput{Producer: hiltV8Producer},
		},
		Outcome: observability.OutcomeFailed, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(started.UnixNano()), Status: observability.NewTraceStatusOK(),
		Events:                            []observability.TraceEventInput{requested},
		DefenseClawConnectorSource:        observability.Present(hiltV8Connector),
		DefenseClawRunID:                  optionalJudgeMetricText(correlation.RunID),
		DefenseClawOperationID:            proxyV8OptionalID(evaluation.OperationID),
		GenAIConversationID:               optionalJudgeMetricText(correlation.SessionID),
		GenAIAgentID:                      optionalJudgeMetricText(correlation.AgentID),
		GenAIAgentName:                    optionalJudgeMetricText(proxyV8StableID(envelope.AgentName)),
		DefenseClawAgentType:              hookModelV8OptionalText(evaluation.AgentType),
		DefenseClawAgentInstanceID:        optionalJudgeMetricText(correlation.AgentInstanceID),
		DefenseClawAgentRootID:            proxyV8OptionalID(evaluation.RootAgentID),
		DefenseClawAgentParentID:          proxyV8OptionalID(evaluation.ParentAgentID),
		DefenseClawAgentLineageProvenance: hookV8OptionalLineageProvenance(evaluation.LineageProvenance),
		DefenseClawSessionRootID:          proxyV8OptionalID(evaluation.RootSessionID),
		DefenseClawSessionParentID:        proxyV8OptionalID(evaluation.ParentSessionID),
		DefenseClawAgentLifecycleID:       proxyV8OptionalID(evaluation.LifecycleID),
		DefenseClawAgentExecutionID:       proxyV8OptionalID(evaluation.ExecutionID),
		DefenseClawAgentDepth:             hiltV8OptionalDepth(evaluation.Depth),
		DefenseClawAgentPhase:             hookV8OptionalPhase(evaluation.Phase),
		DefenseClawAgentPhaseCode:         hookV8OptionalPhaseCode(evaluation.Phase),
		DefenseClawAgentSequence:          hiltV8OptionalSequence(evaluation.Sequence),
		DefenseClawRequestID:              proxyV8OptionalID(correlation.RequestID),
		DefenseClawTurnID:                 proxyV8OptionalID(correlation.TurnID),
		UserID:                            proxyV8OptionalID(evaluation.UserID),
		DefenseClawUserName:               proxyV8OptionalID(evaluation.UserName),
		DefenseClawEvaluationID:           optionalJudgeMetricText(correlation.EvaluationID),
		DefenseClawPolicyID:               optionalJudgeMetricText(correlation.PolicyID),
		DefenseClawPolicyVersion:          proxyV8OptionalID(correlation.PolicyVersion),
		DefenseClawDestinationApp:         proxyV8OptionalID(envelope.DestinationApp),
		DefenseClawToolID:                 proxyV8OptionalID(envelope.ToolID),
		GenAIToolName:                     proxyV8OptionalID(envelope.ToolName),
		GenAIToolType:                     hookModelV8OptionalText(evaluation.ToolType),
		GenAIToolCallID:                   proxyV8OptionalID(evaluation.ToolCallID),
		DefenseClawToolProvider:           hookModelV8OptionalText(evaluation.ToolProvider),
		DefenseClawToolSkillKey:           proxyV8OptionalID(evaluation.ToolSkillKey),
		DefenseClawApprovalID:             observability.Present(id),
		DefenseClawApprovalCommand:        optionalApprovalContent(subject),
		DefenseClawGuardrailReason:        optionalApprovalReason(reason),
		DefenseClawGuardrailRuleIds:       optionalApprovalRuleIDs(ruleIDs),
		DefenseClawSecuritySeverity:       observability.Present(string(canonicalSeverity)),
		ConditionConnectorKnown:           true, ConditionOperationTerminal: true,
	}
	startedContext, approvalTrace, traceErr := runtime.StartApprovalTrace(ctx, input)
	if traceErr == nil {
		input.Envelope.Correlation = correlationWithSpanContext(input.Envelope.Correlation, startedContext)
	} else {
		startedContext = ctx
	}
	operation := &hiltV8Operation{
		runtime: runtime, trace: approvalTrace, ctx: startedContext,
		input: input, severity: canonicalSeverity, started: started,
	}
	if err := operation.emitLog(startedContext, true, input); err != nil {
		if approvalTrace != nil {
			approvalTrace.Abort()
		}
		return nil, err
	}
	return operation, nil
}

func (operation *hiltV8Operation) finish(
	ctx context.Context,
	result string,
	outcome observability.Outcome,
	technicalFailure bool,
	errorType string,
	finished time.Time,
) error {
	if operation == nil {
		return nil
	}
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished {
		return errors.New("hilt v8 approval already finished")
	}
	operation.finished = true
	if !validHILTV8Resolution(result, outcome) || finished.Before(operation.started) {
		if operation.trace != nil {
			operation.trace.Abort()
		}
		return errors.New("hilt v8 approval resolution is invalid")
	}
	input := operation.input
	input.EndTimeUnixNano = uint64(finished.UnixNano())
	input.Outcome = outcome
	input.DefenseClawApprovalResult = observability.Present(result)
	actorType := "operator"
	if result == "expired" || result == "cancelled" {
		actorType = "automatic"
	}
	input.DefenseClawApprovalActorType = observability.Present(actorType)
	input.ConditionTechnicalFailure = technicalFailure
	if technicalFailure {
		input.ErrorType = observability.Present(errorType)
		input.Status = observability.NewTraceStatusError(observability.Present(errorType))
	}
	resolved, err := observability.NewSpanApprovalResolveApprovalResolvedEvent(
		observability.SpanApprovalResolveApprovalResolvedEventInput{
			TimeUnixNano:                 uint64(finished.UnixNano()),
			DefenseClawApprovalID:        input.DefenseClawApprovalID,
			DefenseClawApprovalResult:    observability.Present(result),
			DefenseClawApprovalActorType: observability.Present(actorType),
		},
	)
	if err != nil {
		if operation.trace != nil {
			operation.trace.Abort()
		}
		return err
	}
	input.Events = append(input.Events, resolved)
	logCtx, cancel := context.WithTimeout(context.WithoutCancel(firstContext(ctx, operation.ctx)), hiltV8LogRecordLimit)
	defer cancel()
	if err := operation.emitLog(logCtx, false, input); err != nil {
		if operation.trace != nil {
			operation.trace.Abort()
		}
		return err
	}
	operation.recordMetric(logCtx, input, finished, hiltV8MetricResult(result, errorType))
	if operation.trace != nil {
		_ = operation.trace.End(input)
	}
	return nil
}

func (operation *hiltV8Operation) emitLog(
	ctx context.Context,
	requested bool,
	input observability.SpanApprovalResolveInput,
) error {
	if operation == nil || operation.runtime == nil || ctx == nil {
		return errors.New("hilt v8 log runtime is unavailable")
	}
	eventName := observability.EventName(observability.TelemetryEventApprovalResolved)
	classification := observability.ClassificationContext{
		Bucket: observability.BucketComplianceActivity, EventName: eventName,
		RawSeverity:    string(operation.severity),
		MandatoryFacts: observability.MandatoryFacts{ApprovalResolution: true},
	}
	observedAt := time.Unix(0, int64(input.EndTimeUnixNano)).UTC()
	if requested {
		eventName = observability.EventName(observability.TelemetryEventApprovalRequested)
		classification.EventName = eventName
		classification.MandatoryFacts = observability.MandatoryFacts{}
		observedAt = operation.started
	}
	producerKey := observability.ProducerKey(audit.ActionGuardrailHILT)
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, hiltV8Connector, producerKey,
	)
	if err != nil {
		return err
	}
	_, err = operation.runtime.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 || !observability.IsStableToken(snapshot.Digest()) {
			return observability.Record{}, errors.New("hilt v8 generation is invalid")
		}
		clock := observability.ClockFunc(func() time.Time { return observedAt })
		ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil })
		provenance := observability.Provenance{
			Producer: hiltV8Producer, BinaryVersion: version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		if admission == observabilityrouter.AdmissionFloor {
			if requested {
				return observability.Record{}, errors.New("hilt approval request cannot enter the compliance floor")
			}
			builder, buildErr := observability.NewRecordBuilder(clock, ids)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
				ClassificationContext: classification, Source: observability.SourceGateway,
				Connector: hiltV8Connector, Action: string(audit.ActionGuardrailHILT), Phase: "resolve",
				Outcome: input.Outcome, Correlation: input.Envelope.Correlation, Provenance: provenance,
			})
		}
		if admission != observabilityrouter.AdmissionOrdinary {
			return observability.Record{}, errors.New("hilt v8 log admission is invalid")
		}
		builder, buildErr := observability.NewFamilyBuilder(clock, ids)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := input.Envelope
		envelope.ObservedAt = observability.Present(observedAt)
		envelope.Phase = "resolve"
		if requested {
			envelope.Phase = "request"
		}
		envelope.Provenance = observability.FamilyProvenanceInput{
			Producer: hiltV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		if requested {
			return builder.BuildLogApprovalRequested(observability.LogApprovalRequestedInput{
				Envelope: envelope, Severity: observability.Present(operation.severity),
				Outcome:             observability.OutcomeAttempted,
				GenAIConversationID: input.GenAIConversationID, GenAIAgentID: input.GenAIAgentID,
				GenAIAgentName: input.GenAIAgentName, DefenseClawAgentType: input.DefenseClawAgentType,
				DefenseClawAgentInstanceID: input.DefenseClawAgentInstanceID,
				DefenseClawAgentRootID:     input.DefenseClawAgentRootID, DefenseClawAgentParentID: input.DefenseClawAgentParentID,
				DefenseClawAgentLineageProvenance: input.DefenseClawAgentLineageProvenance,
				DefenseClawSessionRootID:          input.DefenseClawSessionRootID, DefenseClawSessionParentID: input.DefenseClawSessionParentID,
				DefenseClawAgentLifecycleID: input.DefenseClawAgentLifecycleID, DefenseClawAgentExecutionID: input.DefenseClawAgentExecutionID,
				DefenseClawAgentDepth: input.DefenseClawAgentDepth, DefenseClawAgentPhase: input.DefenseClawAgentPhase,
				DefenseClawAgentPhaseCode: input.DefenseClawAgentPhaseCode, DefenseClawAgentSequence: input.DefenseClawAgentSequence,
				DefenseClawRequestID: input.DefenseClawRequestID, DefenseClawTurnID: input.DefenseClawTurnID,
				DefenseClawOperationID: input.DefenseClawOperationID, DefenseClawRunID: input.DefenseClawRunID,
				UserID: input.UserID, DefenseClawUserName: input.DefenseClawUserName,
				DefenseClawEvaluationID: input.DefenseClawEvaluationID, DefenseClawPolicyID: input.DefenseClawPolicyID,
				DefenseClawPolicyVersion: input.DefenseClawPolicyVersion, DefenseClawDestinationApp: input.DefenseClawDestinationApp,
				DefenseClawToolID: input.DefenseClawToolID, GenAIToolName: input.GenAIToolName,
				GenAIToolType: input.GenAIToolType, GenAIToolCallID: input.GenAIToolCallID,
				DefenseClawToolProvider: input.DefenseClawToolProvider, DefenseClawToolSkillKey: input.DefenseClawToolSkillKey,
				DefenseClawApprovalID: approvalID(input), DefenseClawApprovalCommand: input.DefenseClawApprovalCommand,
				DefenseClawGuardrailReason:  input.DefenseClawGuardrailReason,
				DefenseClawGuardrailRuleIds: input.DefenseClawGuardrailRuleIds,
				DefenseClawSecuritySeverity: input.DefenseClawSecuritySeverity,
			})
		}
		result, _ := input.DefenseClawApprovalResult.Get()
		return builder.BuildLogApprovalResolved(observability.LogApprovalResolvedInput{
			Envelope: envelope, Severity: observability.Present(operation.severity), Outcome: input.Outcome,
			GenAIConversationID: input.GenAIConversationID, GenAIAgentID: input.GenAIAgentID,
			GenAIAgentName: input.GenAIAgentName, DefenseClawAgentType: input.DefenseClawAgentType,
			DefenseClawAgentInstanceID: input.DefenseClawAgentInstanceID,
			DefenseClawAgentRootID:     input.DefenseClawAgentRootID, DefenseClawAgentParentID: input.DefenseClawAgentParentID,
			DefenseClawAgentLineageProvenance: input.DefenseClawAgentLineageProvenance,
			DefenseClawSessionRootID:          input.DefenseClawSessionRootID, DefenseClawSessionParentID: input.DefenseClawSessionParentID,
			DefenseClawAgentLifecycleID: input.DefenseClawAgentLifecycleID, DefenseClawAgentExecutionID: input.DefenseClawAgentExecutionID,
			DefenseClawAgentDepth: input.DefenseClawAgentDepth, DefenseClawAgentPhase: input.DefenseClawAgentPhase,
			DefenseClawAgentPhaseCode: input.DefenseClawAgentPhaseCode, DefenseClawAgentSequence: input.DefenseClawAgentSequence,
			DefenseClawRequestID: input.DefenseClawRequestID, DefenseClawTurnID: input.DefenseClawTurnID,
			DefenseClawOperationID: input.DefenseClawOperationID, DefenseClawRunID: input.DefenseClawRunID,
			UserID: input.UserID, DefenseClawUserName: input.DefenseClawUserName,
			DefenseClawEvaluationID: input.DefenseClawEvaluationID, DefenseClawPolicyID: input.DefenseClawPolicyID,
			DefenseClawPolicyVersion: input.DefenseClawPolicyVersion, DefenseClawDestinationApp: input.DefenseClawDestinationApp,
			DefenseClawToolID: input.DefenseClawToolID, GenAIToolName: input.GenAIToolName,
			GenAIToolType: input.GenAIToolType, GenAIToolCallID: input.GenAIToolCallID,
			DefenseClawToolProvider: input.DefenseClawToolProvider, DefenseClawToolSkillKey: input.DefenseClawToolSkillKey,
			DefenseClawApprovalID: approvalID(input), DefenseClawApprovalCommand: input.DefenseClawApprovalCommand,
			DefenseClawApprovalActorType: input.DefenseClawApprovalActorType,
			DefenseClawApprovalResult:    result, DefenseClawGuardrailReason: input.DefenseClawGuardrailReason,
			DefenseClawGuardrailRuleIds: input.DefenseClawGuardrailRuleIds,
			DefenseClawSecuritySeverity: input.DefenseClawSecuritySeverity,
			MandatoryApprovalResolution: true,
		})
	})
	return err
}

func (operation *hiltV8Operation) recordMetric(
	ctx context.Context,
	input observability.SpanApprovalResolveInput,
	observedAt time.Time,
	action string,
) {
	if operation == nil || operation.runtime == nil || ctx == nil || action == "" {
		return
	}
	item := observabilityruntime.GeneratedMetricBatchItem{
		Family: observability.EventName(observability.TelemetryInstrumentDefenseClawApprovalLifecycle),
		Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, errors.New("hilt v8 metric generation is invalid")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			envelope := input.Envelope
			envelope.ObservedAt = observability.Present(observedAt)
			envelope.Provenance = observability.FamilyProvenanceInput{
				Producer: hiltV8Producer, BinaryVersion: version.Current().BinaryVersion,
				ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			}
			return builder.BuildMetricDefenseClawApprovalLifecycle(
				observability.MetricDefenseClawApprovalLifecycleInput{
					Envelope: envelope, Value: 1,
					DefenseClawApprovalLifecycleResult: action,
					DefenseClawApprovalSurface:         "chat",
					DefenseClawConnectorSource:         observability.Present(hiltV8Connector),
				},
			)
		},
	}
	metricCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hiltV8MetricRecordLimit)
	defer cancel()
	_, _ = operation.runtime.RecordGeneratedMetricBatch(metricCtx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func hiltV8MetricResult(result string, errorType string) string {
	switch errorType {
	case "approval_unavailable":
		return "unavailable"
	case "approval_delivery_failed":
		return "delivery_failed"
	case "approval_cancelled":
		return "cancelled"
	}
	switch result {
	case "approved":
		return "approved"
	case "denied":
		return "denied"
	case "expired":
		return "expired"
	case "cancelled":
		return "cancelled"
	default:
		return ""
	}
}

func hiltV8Severity(value string) observability.Severity {
	normalized := observability.NormalizeSeverity(value)
	if normalized.Present && normalized.Valid {
		return normalized.Severity
	}
	return observability.SeverityInfo
}

func hiltV8OptionalDepth(value *int64) observability.Optional[int64] {
	if value == nil || *value < 0 || *value > 64 {
		return observability.Absent[int64]()
	}
	return observability.Present(*value)
}

func hiltV8OptionalSequence(value *int64) observability.Optional[int64] {
	if value == nil || *value < 0 {
		return observability.Absent[int64]()
	}
	return observability.Present(*value)
}

func boundedHILTText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	return truncateToRuneBoundary(value, limit)
}

func boundedHILTRuleIDs(values []string) ([]string, bool) {
	if len(values) > 8 {
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !utf8.ValidString(value) || !hookModelV8Identifier(value) {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func optionalApprovalReason(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalApprovalRuleIDs(values []string) observability.Optional[[]string] {
	if len(values) == 0 {
		return observability.Absent[[]string]()
	}
	return observability.Present(append([]string(nil), values...))
}

func correlationWithSpanContext(correlation observability.Correlation, ctx context.Context) observability.Correlation {
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	return correlation
}

func validHILTV8Resolution(result string, outcome observability.Outcome) bool {
	switch result {
	case "approved":
		return outcome == observability.OutcomeApproved
	case "denied":
		return outcome == observability.OutcomeDenied
	case "expired":
		return outcome == observability.OutcomeTimedOut
	case "cancelled":
		return outcome == observability.OutcomeCancelled
	default:
		return false
	}
}

func approvalID(input observability.SpanApprovalResolveInput) string {
	value, _ := input.DefenseClawApprovalID.Get()
	return value
}

func firstContext(primary context.Context, fallback context.Context) context.Context {
	if primary != nil {
		return primary
	}
	return fallback
}
