// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const watcherAdmissionV8Producer = "watcher.admission"

// ObservabilityV8Runtime is the request-bounded generated trace capability the
// watcher consumes. The process-owned runtime retains routing, sampling,
// redaction, resource, and export authority.
type ObservabilityV8Runtime interface {
	StartGuardrailApplyTrace(context.Context, observability.SpanGuardrailApplyInput) (context.Context, *observabilityruntime.GuardrailApplyTrace, error)
}

type watcherAdmissionTraceV8 struct {
	runtime      ObservabilityV8Runtime
	generated    *observabilityruntime.GuardrailApplyTrace
	ctx          context.Context
	startedAt    time.Time
	evaluationID string
	targetType   string
	targetRef    string
	policyID     string
	connector    string
}

type watcherAdmissionEvaluationIDKey struct{}

// BindObservabilityV8 installs the process-owned generated runtime. A nil
// runtime is a detach; no global or legacy tracer fallback exists.
func (w *InstallWatcher) BindObservabilityV8(runtime ObservabilityV8Runtime) {
	if w == nil {
		return
	}
	w.observabilityV8Mu.Lock()
	w.observabilityV8 = runtime
	w.observabilityV8Mu.Unlock()
}

func (w *InstallWatcher) admissionObservabilityV8() ObservabilityV8Runtime {
	if w == nil {
		return nil
	}
	w.observabilityV8Mu.RLock()
	defer w.observabilityV8Mu.RUnlock()
	return w.observabilityV8
}

func (w *InstallWatcher) startAdmissionTraceV8(
	ctx context.Context,
	event InstallEvent,
	targetType, policyID string,
) (context.Context, *watcherAdmissionTraceV8) {
	if ctx == nil {
		ctx = context.Background()
	}
	operation := &watcherAdmissionTraceV8{
		runtime: w.admissionObservabilityV8(), ctx: ctx, startedAt: time.Now().UTC(),
		evaluationID: uuid.NewString(), targetType: targetType, targetRef: event.Name,
		policyID: policyID, connector: w.eventConnector(event),
	}
	ctx = context.WithValue(ctx, watcherAdmissionEvaluationIDKey{}, operation.evaluationID)
	operation.ctx = ctx
	if operation.runtime == nil {
		return ctx, operation
	}
	input := operation.input(observability.OutcomeAttempted, AdmissionResult{}, operation.startedAt)
	started, generated, err := operation.runtime.StartGuardrailApplyTrace(ctx, input)
	if err != nil {
		return ctx, operation
	}
	if started != nil {
		started = context.WithValue(started, watcherAdmissionEvaluationIDKey{}, operation.evaluationID)
		operation.ctx = started
		ctx = started
	}
	operation.generated = generated
	return ctx, operation
}

func (operation *watcherAdmissionTraceV8) end(result AdmissionResult) error {
	if operation == nil || operation.generated == nil {
		return nil
	}
	completedAt := time.Now().UTC()
	return operation.generated.End(operation.input(watcherAdmissionOutcome(result.Verdict), result, completedAt))
}

func (operation *watcherAdmissionTraceV8) input(
	outcome observability.Outcome,
	result AdmissionResult,
	at time.Time,
) observability.SpanGuardrailApplyInput {
	correlation := watcherAdmissionCorrelation(operation.ctx, operation.connector)
	correlation.EvaluationID = operation.evaluationID
	correlation.PolicyID = operation.policyID
	status := observability.NewTraceStatusUnset()
	if outcome != observability.OutcomeAttempted {
		status = observability.NewTraceStatusOK()
	}
	technicalFailure := result.Verdict == VerdictScanError
	errorType := observability.Absent[string]()
	if technicalFailure {
		errorType = observability.Present("scan_error")
		status = observability.NewTraceStatusError(errorType)
	}
	decision := watcherAdmissionDecision(result.Verdict)
	severity := watcherAdmissionSeverity(result.MaxSeverity)
	connector := watcherAdmissionOptionalIdentifier(operation.connector)
	input := observability.SpanGuardrailApplyInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(at), Source: observability.SourceWatcher,
			Connector: operation.connector, Action: "admission_decide", Phase: "policy",
			Correlation: correlation, Provenance: observability.FamilyProvenanceInput{Producer: watcherAdmissionV8Producer},
		},
		Outcome: outcome, Kind: "INTERNAL", StartTimeUnixNano: uint64(operation.startedAt.UnixNano()),
		EndTimeUnixNano: uint64(at.UnixNano()), Status: status,
		DefenseClawConnectorSource:          connector,
		DefenseClawRunID:                    watcherAdmissionOptionalIdentifier(correlation.RunID),
		DefenseClawRequestID:                watcherAdmissionOptionalIdentifier(correlation.RequestID),
		DefenseClawTurnID:                   watcherAdmissionOptionalIdentifier(correlation.TurnID),
		GenAIConversationID:                 watcherAdmissionOptionalIdentifier(correlation.SessionID),
		GenAIAgentID:                        watcherAdmissionOptionalIdentifier(correlation.AgentID),
		DefenseClawAgentInstanceID:          watcherAdmissionOptionalIdentifier(correlation.AgentInstanceID),
		DefenseClawEvaluationID:             watcherAdmissionOptionalIdentifier(operation.evaluationID),
		DefenseClawPolicyID:                 watcherAdmissionOptionalIdentifier(operation.policyID),
		DefenseClawGuardrailName:            "admission",
		DefenseClawGuardrailStrategy:        observability.Present("watcher_admission"),
		DefenseClawGuardrailStage:           observability.Present("admission"),
		DefenseClawGuardrailPhase:           observability.Present("policy"),
		DefenseClawGuardrailTargetType:      operation.targetType,
		DefenseClawGuardrailTargetRef:       watcherAdmissionOptionalText(operation.targetRef, 4096),
		DefenseClawGuardrailLatencyMs:       observability.Present(float64(at.Sub(operation.startedAt).Milliseconds())),
		DefenseClawGuardrailDecision:        decision,
		DefenseClawGuardrailRawAction:       watcherAdmissionOptionalText(string(result.Verdict), 4096),
		DefenseClawGuardrailEffectiveAction: watcherAdmissionOptionalText(string(result.Verdict), 4096),
		DefenseClawGuardrailWouldBlock:      watcherAdmissionOptionalBool(result.Verdict == VerdictBlocked || result.Verdict == VerdictRejected, outcome),
		DefenseClawGuardrailEnforced:        watcherAdmissionOptionalBool(result.Verdict == VerdictBlocked || result.Verdict == VerdictRejected, outcome),
		DefenseClawSecuritySeverity:         severity,
		DefenseClawGuardrailReason:          watcherAdmissionOptionalText(result.Reason, 65536),
		DefenseClawGuardrailFindingCount:    watcherAdmissionOptionalFindingCount(result.FindingCount, outcome),
		ErrorType:                           errorType,
		ConditionConnectorKnown:             connector.IsPresent(),
		ConditionOperationTerminal:          outcome != observability.OutcomeAttempted,
		ConditionTechnicalFailure:           technicalFailure,
	}
	return input
}

func watcherAdmissionCorrelation(ctx context.Context, connector string) observability.Correlation {
	envelope := audit.EnvelopeFromContext(ctx)
	correlation := observability.Correlation{
		RunID: envelope.RunID, RequestID: envelope.RequestID, SessionID: envelope.SessionID,
		TurnID: envelope.TurnID, TraceID: envelope.TraceID, AgentID: envelope.AgentID,
		AgentInstanceID: envelope.AgentInstanceID, PolicyID: envelope.PolicyID,
		ToolInvocationID: envelope.ToolID, DestinationID: envelope.DestinationApp,
		ConnectorID: connector, SidecarInstanceID: envelope.SidecarInstanceID,
	}
	if correlation.RunID == "" {
		correlation.RunID = gatewaylog.ProcessRunID()
	}
	if correlation.SidecarInstanceID == "" {
		correlation.SidecarInstanceID = gatewaylog.SidecarInstanceID()
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	return correlation
}

func watcherAdmissionOutcome(verdict Verdict) observability.Outcome {
	switch verdict {
	case VerdictAllowed, VerdictClean:
		return observability.OutcomeAllowed
	case VerdictBlocked:
		return observability.OutcomeBlocked
	case VerdictRejected:
		return observability.OutcomeRejected
	case VerdictWarning:
		return observability.OutcomePartial
	case VerdictScanError:
		return observability.OutcomeFailed
	default:
		return observability.OutcomeCompleted
	}
}

func watcherAdmissionDecision(verdict Verdict) observability.Optional[string] {
	switch verdict {
	case VerdictAllowed, VerdictClean:
		return observability.Present("allow")
	case VerdictBlocked, VerdictRejected:
		return observability.Present("block")
	case VerdictWarning:
		return observability.Present("review")
	default:
		return observability.Absent[string]()
	}
}

func watcherAdmissionSeverity(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	normalized := observability.NormalizeSeverity(value)
	if !normalized.Valid || !normalized.Present {
		return observability.Absent[string]()
	}
	return observability.Present(string(normalized.Severity))
}

func watcherAdmissionOptionalIdentifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func watcherAdmissionOptionalText(value string, maxBytes int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func watcherAdmissionOptionalBool(value bool, outcome observability.Outcome) observability.Optional[bool] {
	if outcome == observability.OutcomeAttempted {
		return observability.Absent[bool]()
	}
	return observability.Present(value)
}

func watcherAdmissionOptionalFindingCount(value int, outcome observability.Outcome) observability.Optional[int64] {
	if outcome == observability.OutcomeAttempted || value < 0 {
		return observability.Absent[int64]()
	}
	return observability.Present(int64(value))
}

func watcherAdmissionEvaluationID(ctx context.Context) string {
	value, _ := ctx.Value(watcherAdmissionEvaluationIDKey{}).(string)
	return value
}
