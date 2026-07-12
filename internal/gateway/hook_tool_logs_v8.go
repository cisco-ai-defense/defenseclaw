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

func (a *APIServer) emitHookToolLogV8(
	ctx context.Context,
	meta llmEventMeta,
	phase, tool, input, output string,
	exitCode *int,
) {
	if a == nil {
		return
	}
	emitHookToolLogV8WithEmitter(ctx, a.observabilityV8RuntimeEmitter(), meta, phase, tool, input, output, exitCode)
}

func emitHookToolLogV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	phase, tool, input, output string,
	exitCode *int,
) {
	tool = strings.TrimSpace(tool)
	if ctx == nil || !hookModelV8Identifier(tool) {
		return
	}
	if meta.ToolID == "" {
		meta.ToolID = stableLLMEventID("tool", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, tool, phase)
	}
	eventName := observability.TelemetryEventToolInvocationRequested
	outcome := observability.OutcomeAttempted
	if phase == "result" {
		outcome, _, _, _ = hookToolV8TerminalResult(meta, exitCode)
		switch outcome {
		case observability.OutcomeCompleted:
			eventName = observability.TelemetryEventToolInvocationCompleted
		case observability.OutcomeBlocked:
			eventName = observability.TelemetryEventToolInvocationBlocked
		default:
			eventName = observability.TelemetryEventToolInvocationFailed
		}
	}
	connector := hookModelV8StableToken(meta.Source)
	if connector == "" || emitter == nil {
		return
	}
	rawSeverity := "INFO"
	if outcome != observability.OutcomeAttempted && outcome != observability.OutcomeCompleted {
		rawSeverity = "HIGH"
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey(gatewaylog.EventToolInvocation),
		observability.ClassificationContext{
			Bucket: observability.BucketToolActivity, EventName: observability.EventName(eventName), RawSeverity: rawSeverity,
		},
		observability.SourceConnector,
		connector,
		observability.ProducerKey(gatewaylog.EventToolInvocation),
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
			return observability.Record{}, buildErr
		}
		envelope := hookToolLogEnvelope(ctx, snapshot, meta, connector, eventName)
		if outcome == observability.OutcomeAttempted {
			return builder.BuildLogToolInvocationRequested(
				buildHookToolRequestedLogInput(envelope, meta, tool, input),
			)
		}
		completed := buildHookToolCompletedLogInput(envelope, meta, tool, input, output, exitCode, outcome)
		if outcome == observability.OutcomeBlocked {
			return builder.BuildLogToolInvocationBlocked(observability.LogToolInvocationBlockedInput(completed))
		}
		if outcome != observability.OutcomeCompleted {
			return builder.BuildLogToolInvocationFailed(observability.LogToolInvocationFailedInput(completed))
		}
		return builder.BuildLogToolInvocationCompleted(completed)
	})
}

func hookToolLogEnvelope(
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
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: connector,
		Action: string(gatewaylog.EventToolInvocation), Phase: "tool",
		Correlation: correlation,
		Provenance: observability.FamilyProvenanceInput{
			Producer: hookToolV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		},
	}
}

func buildHookToolRequestedLogInput(
	envelope observability.FamilyEnvelopeInput,
	meta llmEventMeta,
	tool, rawInput string,
) observability.LogToolInvocationRequestedInput {
	arguments, reported, _, originalBytes, _ := hookToolV8Arguments(rawInput, int64(len(rawInput)), false)
	result := observability.LogToolInvocationRequestedInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: observability.OutcomeAttempted,
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: observability.Present(tool),
		GenAIToolType: observability.Present("function"), GenAIToolCallID: hookModelV8OptionalID(meta.ToolID),
		DefenseClawToolID: hookModelV8OptionalID(meta.ToolID), DefenseClawToolProvider: observability.Present("hook"),
		DefenseClawToolStatus: observability.Present("requested"), DefenseClawTelemetryInputReported: reported,
		DefenseClawTelemetryOutputReported: false,
	}
	applyHookToolRequestedLogIdentity(&result, meta)
	if reported {
		result.GenAIToolCallArguments = observability.Present(arguments)
		result.DefenseClawToolArgsLength = observability.Present(originalBytes)
	}
	return result
}

func buildHookToolCompletedLogInput(
	envelope observability.FamilyEnvelopeInput,
	meta llmEventMeta,
	tool, rawInput, rawOutput string,
	exitCode *int,
	outcome observability.Outcome,
) observability.LogToolInvocationCompletedInput {
	arguments, inputReported, _, inputBytes, _ := hookToolV8Arguments(rawInput, int64(len(rawInput)), false)
	resultValue, outputReported, _, outputBytes, _ := hookToolV8Result(rawOutput)
	status := "completed"
	severity := observability.SeverityInfo
	logLevel := observability.LogLevelInfo
	switch outcome {
	case observability.OutcomeBlocked:
		status = "blocked"
		severity = observability.SeverityHigh
		logLevel = observability.LogLevelWarn
	case observability.OutcomeCompleted:
	default:
		status = "failed"
		severity = observability.SeverityHigh
		logLevel = observability.LogLevelError
	}
	result := observability.LogToolInvocationCompletedInput{
		Envelope: envelope, Severity: observability.Present(severity),
		LogLevel: observability.Present(logLevel), Outcome: outcome,
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: observability.Present(tool),
		GenAIToolType: observability.Present("function"), GenAIToolCallID: hookModelV8OptionalID(meta.ToolID),
		DefenseClawToolID: hookModelV8OptionalID(meta.ToolID), DefenseClawToolProvider: observability.Present("hook"),
		DefenseClawToolStatus: observability.Present(status), DefenseClawTelemetryInputReported: inputReported,
		DefenseClawTelemetryOutputReported: outputReported,
	}
	applyHookToolCompletedLogIdentity(&result, meta)
	if inputReported {
		result.GenAIToolCallArguments = observability.Present(arguments)
		result.DefenseClawToolArgsLength = observability.Present(inputBytes)
	}
	if outputReported {
		result.GenAIToolCallResult = observability.Present(resultValue)
		result.DefenseClawToolOutputLength = observability.Present(outputBytes)
	}
	if exitCode != nil {
		result.DefenseClawToolExitCode = observability.Present(int64(*exitCode))
	}
	return result
}

func applyHookToolRequestedLogIdentity(input *observability.LogToolInvocationRequestedInput, meta llmEventMeta) {
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
	input.DefenseClawAgentPhase = observability.Present("tool")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](4)
	if meta.PreviousPhase != "" && meta.PreviousPhase != "tool" {
		input.DefenseClawAgentPhasePrevious = hookModelV8OptionalPhase(meta.PreviousPhase)
	}
	if meta.Sequence > 0 {
		input.DefenseClawAgentSequence = observability.Present(meta.Sequence)
	}
	input.DefenseClawSessionSource = hookModelV8OptionalSessionSource(meta.SessionSource)
	input.DefenseClawSessionResumed = observability.Present(meta.SessionResumed)
}

func applyHookToolCompletedLogIdentity(input *observability.LogToolInvocationCompletedInput, meta llmEventMeta) {
	if input == nil {
		return
	}
	requested := observability.LogToolInvocationRequestedInput{}
	applyHookToolRequestedLogIdentity(&requested, meta)
	input.DefenseClawRequestID = requested.DefenseClawRequestID
	input.DefenseClawTurnID = requested.DefenseClawTurnID
	input.DefenseClawOperationID = requested.DefenseClawOperationID
	input.DefenseClawRunID = requested.DefenseClawRunID
	input.UserID = requested.UserID
	input.DefenseClawUserName = requested.DefenseClawUserName
	input.DefenseClawPolicyID = requested.DefenseClawPolicyID
	input.DefenseClawDestinationApp = requested.DefenseClawDestinationApp
	input.GenAIConversationID = requested.GenAIConversationID
	input.GenAIAgentID = requested.GenAIAgentID
	input.GenAIAgentName = requested.GenAIAgentName
	input.DefenseClawAgentType = requested.DefenseClawAgentType
	input.DefenseClawAgentRootID = requested.DefenseClawAgentRootID
	input.DefenseClawAgentParentID = requested.DefenseClawAgentParentID
	input.DefenseClawAgentLineageProvenance = requested.DefenseClawAgentLineageProvenance
	input.DefenseClawSessionRootID = requested.DefenseClawSessionRootID
	input.DefenseClawSessionParentID = requested.DefenseClawSessionParentID
	input.DefenseClawAgentLifecycleID = requested.DefenseClawAgentLifecycleID
	input.DefenseClawAgentExecutionID = requested.DefenseClawAgentExecutionID
	input.DefenseClawAgentDepth = requested.DefenseClawAgentDepth
	input.DefenseClawAgentLifecycleEvent = requested.DefenseClawAgentLifecycleEvent
	input.DefenseClawAgentLifecycleState = requested.DefenseClawAgentLifecycleState
	input.DefenseClawAgentPhase = requested.DefenseClawAgentPhase
	input.DefenseClawAgentPhasePrevious = requested.DefenseClawAgentPhasePrevious
	input.DefenseClawAgentPhaseCode = requested.DefenseClawAgentPhaseCode
	input.DefenseClawAgentSequence = requested.DefenseClawAgentSequence
	input.DefenseClawSessionSource = requested.DefenseClawSessionSource
	input.DefenseClawSessionResumed = requested.DefenseClawSessionResumed
}
