// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// emitHookModelRequestLogV8 and emitHookModelResponseLogV8 are the logs-only
// counterpart to the generated model spans. They deliberately preserve source
// content in the immutable record; the centralized destination projection owns
// every redaction decision.
func (a *APIServer) emitHookModelRequestLogV8(ctx context.Context, meta llmEventMeta, content string) {
	if a == nil {
		return
	}
	_, _ = emitHookModelRequestLogV8WithEmitter(ctx, a.observabilityV8RuntimeEmitter(), meta, content)
}

func emitHookModelRequestLogV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	content string,
) (bool, error) {
	return emitHookModelLogV8WithEmitter(ctx, emitter, meta, observability.TelemetryEventModelRequest, func(
		builder *observability.FamilyBuilder,
		envelope observability.FamilyEnvelopeInput,
	) (observability.Record, error) {
		return buildHookModelRequestLogRecord(builder, envelope, meta, content)
	})
}

func (a *APIServer) emitHookModelResponseLogV8(
	ctx context.Context,
	meta llmEventMeta,
	content string,
	finishReasons []string,
) {
	if a == nil {
		return
	}
	_, _ = emitHookModelResponseLogV8WithEmitter(
		ctx, a.observabilityV8RuntimeEmitter(), meta, content, finishReasons,
	)
}

func emitHookModelResponseLogV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	content string,
	finishReasons []string,
) (bool, error) {
	eventName := observability.TelemetryEventModelResponse
	if outcome, _, _ := hookModelV8TerminalResult(meta); outcome != observability.OutcomeCompleted {
		eventName = observability.TelemetryEventModelCallFailed
	}
	return emitHookModelLogV8WithEmitter(ctx, emitter, meta, eventName, func(
		builder *observability.FamilyBuilder,
		envelope observability.FamilyEnvelopeInput,
	) (observability.Record, error) {
		return buildHookModelResponseLogRecord(builder, envelope, meta, content, finishReasons)
	})
}

func buildHookModelRequestLogRecord(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	meta llmEventMeta,
	content string,
) (observability.Record, error) {
	messages, originalBytes, reported, state, structured := hookModelV8InputMessages(content, int64(len(content)), false)
	input := observability.LogModelRequestInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: observability.OutcomeAttempted,
		DefenseClawTelemetryInputReported: reported, DefenseClawContentInputState: state,
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		DefenseClawTelemetryTokensReported: false, GenAIOperationName: observability.Present("chat"),
	}
	applyHookModelRequestLogIdentity(&input, meta)
	if structured {
		input.GenAIInputMessages = observability.Present(messages)
	}
	if reported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(originalBytes)
		input.DefenseClawContentInputMimeType = observability.Present("text/plain")
	}
	return builder.BuildLogModelRequest(input)
}

func buildHookModelResponseLogRecord(
	builder *observability.FamilyBuilder,
	envelope observability.FamilyEnvelopeInput,
	meta llmEventMeta,
	content string,
	finishReasons []string,
) (observability.Record, error) {
	finishReasons = uniqueNonEmpty(finishReasons)
	messages, originalBytes, reported, state, structured := hookModelV8OutputMessages(content, finishReasons)
	outcome, _, _ := hookModelV8TerminalResult(meta)
	severity := observability.SeverityInfo
	logLevel := observability.LogLevelInfo
	if outcome != observability.OutcomeCompleted {
		severity = observability.SeverityHigh
		logLevel = observability.LogLevelError
	}
	input := observability.LogModelResponseInput{
		Envelope: envelope, Severity: observability.Present(severity),
		LogLevel: observability.Present(logLevel), Outcome: outcome,
		DefenseClawTelemetryInputReported: false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: reported, DefenseClawContentOutputState: state,
		DefenseClawTelemetryTokensReported: false, GenAIOperationName: observability.Present("chat"),
	}
	applyHookModelResponseLogIdentity(&input, meta)
	if structured {
		input.GenAIOutputMessages = observability.Present(messages)
	}
	if reported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(originalBytes)
		input.DefenseClawContentOutputMimeType = observability.Present("text/plain")
	}
	if len(finishReasons) > 0 {
		input.GenAIResponseFinishReasons = observability.Present(finishReasons)
	}
	if outcome != observability.OutcomeCompleted {
		return builder.BuildLogModelCallFailed(observability.LogModelCallFailedInput(input))
	}
	return builder.BuildLogModelResponse(input)
}

type hookModelLogBuilder func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
) (observability.Record, error)

func emitHookModelLogV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	eventName string,
	build hookModelLogBuilder,
) (bool, error) {
	connector := hookModelV8StableToken(meta.Source)
	if emitter == nil || ctx == nil || connector == "" || build == nil {
		return false, nil
	}
	producerKey := observability.ProducerKey(gatewaylog.EventLLMPrompt)
	if eventName != observability.TelemetryEventModelRequest {
		producerKey = observability.ProducerKey(gatewaylog.EventLLMResponse)
	}
	rawSeverity := "INFO"
	if eventName == observability.TelemetryEventModelCallFailed {
		rawSeverity = "HIGH"
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		observability.ClassificationContext{
			Bucket: observability.BucketModelIO, EventName: observability.EventName(eventName), RawSeverity: rawSeverity,
		},
		observability.SourceConnector,
		connector,
		producerKey,
	)
	if err != nil {
		return false, err
	}
	outcome, err := emitter.Emit(ctx, metadata, func(
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
			return observability.Record{}, buildErr
		}
		return build(builder, hookModelLogEnvelope(ctx, snapshot, meta, connector, eventName))
	})
	if err != nil {
		return false, err
	}
	return outcome.LocalPersisted(), nil
}

func hookModelLogEnvelope(
	ctx context.Context,
	snapshot observabilityruntime.EmitContext,
	meta llmEventMeta,
	connector, eventName string,
) observability.FamilyEnvelopeInput {
	correlation := observability.Correlation{
		RunID: modelLogCorrelationID(meta.RunID), RequestID: modelLogCorrelationID(meta.RequestID),
		SessionID: modelLogCorrelationID(meta.SessionID), TurnID: modelLogCorrelationID(meta.TurnID),
		AgentID: modelLogCorrelationID(meta.AgentID), PolicyID: modelLogCorrelationID(meta.PolicyID),
		ModelRequestID: modelLogCorrelationID(meta.PromptID), ModelResponseID: modelLogCorrelationID(meta.ResponseID),
		ToolInvocationID: modelLogCorrelationID(meta.ToolID), ConnectorID: connector,
	}
	if span := trace.SpanContextFromContext(ctx); span.IsValid() {
		correlation.TraceID = span.TraceID().String()
		correlation.SpanID = span.SpanID().String()
	}
	action := string(gatewaylog.EventLLMPrompt)
	if eventName != observability.TelemetryEventModelRequest {
		action = string(gatewaylog.EventLLMResponse)
	}
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: connector, Action: action, Phase: "model",
		Correlation: correlation,
		Provenance: observability.FamilyProvenanceInput{
			Producer: hookModelV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func modelLogCorrelationID(value string) string {
	value = strings.TrimSpace(value)
	if !hookModelV8Identifier(value) {
		return ""
	}
	return value
}

func applyHookModelRequestLogIdentity(input *observability.LogModelRequestInput, meta llmEventMeta) {
	if input == nil {
		return
	}
	input.DefenseClawRequestID = hookModelV8OptionalID(meta.RequestID)
	input.DefenseClawTurnID = hookModelV8OptionalID(meta.TurnID)
	input.DefenseClawOperationID = hookModelV8OptionalID(meta.OperationID)
	input.DefenseClawRunID = hookModelV8OptionalID(meta.RunID)
	input.UserID = hookModelV8OptionalID(meta.UserID)
	input.DefenseClawUserName = hookModelV8OptionalID(meta.UserName)
	input.DefenseClawPolicyID = hookModelV8OptionalID(meta.PolicyID)
	input.DefenseClawDestinationApp = hookModelV8OptionalID(meta.DestinationApp)
	input.GenAIConversationID = hookModelV8OptionalID(meta.SessionID)
	input.GenAIAgentID = hookModelV8OptionalID(meta.AgentID)
	input.GenAIAgentName = hookModelV8OptionalID(meta.AgentName)
	input.DefenseClawAgentType = hookModelV8OptionalText(meta.AgentType)
	input.DefenseClawAgentRootID = hookModelV8OptionalID(meta.RootAgentID)
	input.DefenseClawAgentParentID = hookModelV8OptionalID(meta.ParentAgentID)
	input.DefenseClawAgentLineageProvenance = hookModelV8OptionalLineage(meta.LineageProvenance)
	input.DefenseClawSessionRootID = hookModelV8OptionalID(meta.RootSessionID)
	input.DefenseClawSessionParentID = hookModelV8OptionalID(meta.ParentSessionID)
	input.DefenseClawAgentLifecycleID = hookModelV8OptionalID(meta.LifecycleID)
	input.DefenseClawAgentExecutionID = hookModelV8OptionalID(meta.ExecutionID)
	if meta.AgentID != "" && meta.AgentDepth >= 0 && meta.AgentDepth <= 64 {
		input.DefenseClawAgentDepth = observability.Present(int64(meta.AgentDepth))
	}
	input.DefenseClawAgentLifecycleEvent = hookModelV8OptionalText(meta.LifecycleEvent)
	input.DefenseClawAgentLifecycleState = hookModelV8OptionalText(meta.LifecycleState)
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
	if meta.PreviousPhase != "" && meta.PreviousPhase != "model" {
		input.DefenseClawAgentPhasePrevious = hookModelV8OptionalPhase(meta.PreviousPhase)
	}
	if meta.Sequence > 0 {
		input.DefenseClawAgentSequence = observability.Present(meta.Sequence)
	}
	input.DefenseClawSessionSource = hookModelV8OptionalSessionSource(meta.SessionSource)
	input.DefenseClawSessionResumed = observability.Present(meta.SessionResumed)
	input.GenAIProviderName = hookModelV8OptionalText(meta.Provider)
	input.GenAIRequestModel = hookModelV8OptionalID(meta.Model)
	input.GenAIResponseID = hookModelV8OptionalID(meta.ResponseID)
	input.DefenseClawModelRequestID = hookModelV8OptionalID(meta.PromptID)
	input.DefenseClawModelResponseID = hookModelV8OptionalID(meta.ResponseID)
}

func applyHookModelResponseLogIdentity(input *observability.LogModelResponseInput, meta llmEventMeta) {
	if input == nil {
		return
	}
	request := observability.LogModelRequestInput{}
	applyHookModelRequestLogIdentity(&request, meta)
	input.DefenseClawRequestID = request.DefenseClawRequestID
	input.DefenseClawTurnID = request.DefenseClawTurnID
	input.DefenseClawOperationID = request.DefenseClawOperationID
	input.DefenseClawRunID = request.DefenseClawRunID
	input.UserID = request.UserID
	input.DefenseClawUserName = request.DefenseClawUserName
	input.DefenseClawPolicyID = request.DefenseClawPolicyID
	input.DefenseClawDestinationApp = request.DefenseClawDestinationApp
	input.GenAIConversationID = request.GenAIConversationID
	input.GenAIAgentID = request.GenAIAgentID
	input.GenAIAgentName = request.GenAIAgentName
	input.DefenseClawAgentType = request.DefenseClawAgentType
	input.DefenseClawAgentRootID = request.DefenseClawAgentRootID
	input.DefenseClawAgentParentID = request.DefenseClawAgentParentID
	input.DefenseClawAgentLineageProvenance = request.DefenseClawAgentLineageProvenance
	input.DefenseClawSessionRootID = request.DefenseClawSessionRootID
	input.DefenseClawSessionParentID = request.DefenseClawSessionParentID
	input.DefenseClawAgentLifecycleID = request.DefenseClawAgentLifecycleID
	input.DefenseClawAgentExecutionID = request.DefenseClawAgentExecutionID
	input.DefenseClawAgentDepth = request.DefenseClawAgentDepth
	input.DefenseClawAgentLifecycleEvent = request.DefenseClawAgentLifecycleEvent
	input.DefenseClawAgentLifecycleState = request.DefenseClawAgentLifecycleState
	input.DefenseClawAgentPhase = request.DefenseClawAgentPhase
	input.DefenseClawAgentPhasePrevious = request.DefenseClawAgentPhasePrevious
	input.DefenseClawAgentPhaseCode = request.DefenseClawAgentPhaseCode
	input.DefenseClawAgentSequence = request.DefenseClawAgentSequence
	input.DefenseClawSessionSource = request.DefenseClawSessionSource
	input.DefenseClawSessionResumed = request.DefenseClawSessionResumed
	input.GenAIProviderName = request.GenAIProviderName
	input.GenAIRequestModel = request.GenAIRequestModel
	input.GenAIResponseModel = hookModelV8OptionalID(meta.Model)
	input.GenAIResponseID = request.GenAIResponseID
	input.DefenseClawModelRequestID = request.DefenseClawModelRequestID
	input.DefenseClawModelResponseID = request.DefenseClawModelResponseID
}
