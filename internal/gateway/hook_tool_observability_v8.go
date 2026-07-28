// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const hookToolV8Producer = "gateway.hook.tool"

type generatedToolV8Observation struct {
	meta                   llmEventMeta
	correlationCtx         context.Context
	producer               string
	tool                   string
	arguments              string
	result                 string
	toolProvider           string
	outcome                observability.Outcome
	toolStatus             string
	errorType              string
	dangerous              bool
	technicalFailure       bool
	exitCode               *int
	startedAt              time.Time
	finishedAt             time.Time
	argumentsOriginalBytes int64
	argumentsTruncated     bool
	agentName              string
	agentType              string
	agentID                string
	sessionID              string
}

func newHookToolV8Observation(
	snapshot hookToolInvocation,
	meta llmEventMeta,
	tool, arguments, result string,
	exitCode *int,
) generatedToolV8Observation {
	startedAt := snapshot.startedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := time.Now().UTC()
	if finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	originalBytes := snapshot.argumentsOriginalBytes
	if originalBytes <= 0 && arguments != "" {
		originalBytes = int64(len(arguments))
	}
	outcome, technicalFailure, errorType, toolStatus := hookToolV8TerminalResult(meta, exitCode)
	return generatedToolV8Observation{
		meta: meta, producer: hookToolV8Producer, tool: strings.TrimSpace(tool), arguments: arguments,
		result: result, toolProvider: "hook",
		outcome: outcome, technicalFailure: technicalFailure, errorType: errorType, toolStatus: toolStatus,
		exitCode: exitCode, startedAt: startedAt, finishedAt: finishedAt,
		argumentsOriginalBytes: originalBytes, argumentsTruncated: snapshot.argumentsTruncated,
		agentName: firstNonEmpty(meta.AgentName, snapshot.meta.AgentName, meta.Source, snapshot.meta.Source),
		agentType: firstNonEmpty(meta.AgentType, snapshot.meta.AgentType, meta.Source, snapshot.meta.Source),
		agentID:   firstNonEmpty(meta.AgentID, snapshot.meta.AgentID),
		sessionID: firstNonEmpty(meta.SessionID, snapshot.meta.SessionID),
	}
}

// hookToolV8TerminalResult maps connector lifecycle semantics onto the
// canonical tool families. PermissionDenied is a semantic block (not a
// technical error); explicit hook failures and timeouts are technical errors.
func hookToolV8TerminalResult(
	meta llmEventMeta,
	exitCode *int,
) (observability.Outcome, bool, string, string) {
	switch strings.TrimSpace(meta.LifecycleOutcome) {
	case "blocked", "denied":
		return observability.OutcomeBlocked, false, "", "blocked"
	case "failed":
		return observability.OutcomeFailed, true, "hook_failure", "failed"
	case "timed_out":
		return observability.OutcomeTimedOut, true, "timeout", "failed"
	case "rejected":
		return observability.OutcomeRejected, false, "", "failed"
	case "cancelled":
		return observability.OutcomeCancelled, false, "", "failed"
	}
	if exitCode != nil && *exitCode != 0 {
		return observability.OutcomeFailed, true, "nonzero_exit", "failed"
	}
	return observability.OutcomeCompleted, false, "", "completed"
}

func (a *APIServer) emitHookToolSpanV8(
	ctx context.Context,
	runtime lifecycleV8Runtime,
	metricRuntime hookLifecycleMetricV8Runtime,
	observation generatedToolV8Observation,
) context.Context {
	if a == nil {
		return ctx
	}
	return emitGeneratedToolSpanV8(ctx, runtime, metricRuntime, observation)
}

func emitGeneratedToolSpanV8(
	ctx context.Context,
	runtime lifecycleV8Runtime,
	metricRuntime hookLifecycleMetricV8Runtime,
	observation generatedToolV8Observation,
) (correlated context.Context) {
	correlated = ctx
	if ctx == nil || runtime == nil || !hookModelV8Identifier(observation.tool) {
		return
	}
	metricContext := ctx
	metricsPinned := false
	defer func() {
		if !metricsPinned {
			recordGeneratedToolMetricsV8(metricContext, metricRuntime, observation)
		}
	}()

	agentInput, hasAgent := hookToolV8AgentInput(observation)
	if hasAgent {
		startedContext, agent, err := runtime.StartAgentTrace(ctx, agentInput)
		if err != nil {
			return
		}
		if startedContext != nil {
			metricContext = startedContext
		}
		if agent != nil {
			defer agent.Abort()
			agentContext := startedContext
			if agentContext == nil {
				agentContext = agent.Context()
			}
			if agentContext != nil {
				metricContext = agentContext
			}
			toolInput := generatedToolV8Input(observation)
			tool, toolErr := agent.StartTool(toolInput)
			if toolErr != nil {
				return
			}
			recordingContext := agentContext
			if tool != nil {
				toolContext := tool.Context()
				if toolContext != nil {
					metricContext = toolContext
					recordingContext = toolContext
				}
				recordGeneratedToolMetricsV8(metricContext, tool, observation)
				metricsPinned = true
				if endErr := tool.End(toolInput); endErr != nil {
					return
				}
			} else {
				recordGeneratedToolMetricsV8(metricContext, agent, observation)
				metricsPinned = true
			}
			if endErr := agent.End(agentInput); endErr != nil {
				return
			}
			if recordingContext != nil {
				correlated = recordingContext
			}
			return
		}
		if hookModelV8AgentSamplingDeclined(ctx, startedContext) {
			correlated = startedContext
			return
		}
	}

	toolInput := generatedToolV8Input(observation)
	startedContext, tool, err := runtime.StartToolTrace(ctx, toolInput)
	if startedContext != nil {
		metricContext = startedContext
	}
	if err != nil {
		return
	}
	if tool == nil {
		if hookModelV8AgentSamplingDeclined(ctx, startedContext) {
			correlated = startedContext
		}
		return
	}
	defer tool.Abort()
	toolContext := tool.Context()
	if toolContext != nil {
		metricContext = toolContext
	}
	recordGeneratedToolMetricsV8(metricContext, tool, observation)
	metricsPinned = true
	if endErr := tool.End(toolInput); endErr != nil {
		return
	}
	if toolContext != nil {
		correlated = toolContext
	} else if startedContext != nil {
		correlated = startedContext
	}
	return
}

func generatedToolV8Envelope(observation generatedToolV8Observation, action string) observability.FamilyEnvelopeInput {
	meta := observation.meta
	connector := hookModelV8StableToken(meta.Source)
	producer := firstNonEmpty(observation.producer, hookToolV8Producer)
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: connector, Action: action, Phase: "tool",
		Correlation: observability.Correlation{
			RunID: meta.RunID, RequestID: meta.RequestID, SessionID: observation.sessionID,
			TurnID: meta.TurnID, AgentID: observation.agentID, PolicyID: meta.PolicyID,
			ModelRequestID: meta.PromptID, ModelResponseID: meta.ResponseID,
			ToolInvocationID: meta.ToolID, ConnectorID: connector,
		},
		Provenance: observability.FamilyProvenanceInput{Producer: producer},
	}
}

func hookToolV8AgentInput(observation generatedToolV8Observation) (observability.SpanAgentInvokeInput, bool) {
	meta := observation.meta
	rootAgentID := firstNonEmpty(meta.RootAgentID, observation.agentID)
	rootSessionID := firstNonEmpty(meta.RootSessionID, observation.sessionID)
	if !hookModelV8Identifier(observation.agentID) ||
		!hookModelV8Identifier(observation.sessionID) ||
		!hookModelV8Identifier(rootAgentID) ||
		!hookModelV8Identifier(rootSessionID) ||
		!hookModelV8Identifier(meta.LifecycleID) ||
		!hookModelV8Identifier(meta.ExecutionID) ||
		strings.TrimSpace(meta.LifecycleEvent) == "" || strings.TrimSpace(meta.LifecycleState) == "" ||
		strings.TrimSpace(observation.agentType) == "" {
		return observability.SpanAgentInvokeInput{}, false
	}
	input := observability.SpanAgentInvokeInput{
		Envelope: generatedToolV8Envelope(observation, "invoke_agent"),
		Outcome:  observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano:                   uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:                     uint64(observation.finishedAt.UnixNano()),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawAgentType:                observation.agentType,
		DefenseClawAgentReportedCostPresent: hookModelV8ReportedCost(meta),
		DefenseClawTelemetryInputReported:   false,
		DefenseClawContentInputState:        "not_reported",
		DefenseClawTelemetryOutputReported:  false,
		DefenseClawContentOutputState:       "not_reported",
		GenAIOperationName:                  observability.Present("invoke_agent"),
		ConditionConnectorKnown:             hookModelV8StableToken(meta.Source) != "",
		ConditionOperationTerminal:          true,
	}
	if outcome, failed, errorType, _ := generatedToolV8Result(observation); outcome != observability.OutcomeCompleted {
		input.Outcome = outcome
		if errorType != "" {
			input.ErrorType = observability.Present(errorType)
		}
		if failed {
			input.Status = observability.NewTraceStatusError(input.ErrorType)
			input.ConditionTechnicalFailure = true
		}
	}
	identity := hookModelV8Observation{
		meta: meta, provider: firstNonEmpty(meta.Provider, meta.Source),
		agentName: observation.agentName, agentType: observation.agentType,
		agentID: observation.agentID, sessionID: observation.sessionID,
	}
	applyHookModelV8AgentFacts(&input, identity, rootAgentID, rootSessionID)
	input.DefenseClawAgentPhase = observability.Present("tool")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](4)
	return input, true
}

func generatedToolV8Input(observation generatedToolV8Observation) observability.SpanToolExecuteInput {
	meta := observation.meta
	arguments, argumentsReported, argumentsState, argumentsBytes, argumentsMIME :=
		hookToolV8Arguments(observation.arguments, observation.argumentsOriginalBytes, observation.argumentsTruncated)
	result, resultReported, resultState, resultBytes, resultMIME := hookToolV8Result(observation.result)
	outcome, technicalFailure, errorText, toolStatus := generatedToolV8Result(observation)
	status := observability.NewTraceStatusOK()
	errorType := observability.Absent[string]()
	if errorText != "" {
		errorType = observability.Present(errorText)
	}
	if technicalFailure {
		status = observability.NewTraceStatusError(errorType)
	}
	input := observability.SpanToolExecuteInput{
		Envelope: generatedToolV8Envelope(observation, "execute_tool"), Outcome: outcome, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:   uint64(observation.finishedAt.UnixNano()),
		Status:            status, ErrorType: errorType,
		DefenseClawAgentReportedCostPresent: hookModelV8ReportedCost(meta),
		DefenseClawTelemetryInputReported:   argumentsReported, DefenseClawContentInputState: argumentsState,
		DefenseClawTelemetryOutputReported: resultReported, DefenseClawContentOutputState: resultState,
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: observation.tool,
		GenAIToolType: observability.Present("function"), DefenseClawToolProvider: observability.Present(firstNonEmpty(observation.toolProvider, "hook")),
		DefenseClawToolDangerous: observability.Present(observation.dangerous), DefenseClawToolStatus: observability.Present(toolStatus),
		DefenseClawToolArgsLength:  observability.Present(argumentsBytes),
		ConditionConnectorKnown:    hookModelV8StableToken(meta.Source) != "",
		ConditionOperationTerminal: true, ConditionTechnicalFailure: technicalFailure,
	}
	if argumentsReported {
		input.GenAIToolCallArguments = observability.Present(arguments)
		input.DefenseClawContentInputOriginalBytes = observability.Present(argumentsBytes)
		input.DefenseClawContentInputMimeType = observability.Present(argumentsMIME)
	}
	if resultReported {
		input.GenAIToolCallResult = observability.Present(result)
		input.DefenseClawToolOutputLength = observability.Present(resultBytes)
		input.DefenseClawContentOutputOriginalBytes = observability.Present(resultBytes)
		input.DefenseClawContentOutputMimeType = observability.Present(resultMIME)
	}
	if observation.exitCode != nil {
		input.DefenseClawToolExitCode = observability.Present(int64(*observation.exitCode))
	}
	input.GenAIToolCallID = hookModelV8OptionalID(meta.ToolID)
	input.DefenseClawToolID = hookModelV8OptionalID(meta.ToolID)
	applyGeneratedToolV8Identity(&input, observation)
	return input
}

func generatedToolV8Result(
	observation generatedToolV8Observation,
) (observability.Outcome, bool, string, string) {
	outcome := observation.outcome
	if outcome == "" {
		outcome = observability.OutcomeCompleted
		if observation.exitCode != nil && *observation.exitCode != 0 {
			outcome = observability.OutcomeFailed
		}
	}
	technicalFailure := observation.technicalFailure ||
		(observation.exitCode != nil && *observation.exitCode != 0)
	errorType := strings.TrimSpace(observation.errorType)
	if technicalFailure && errorType == "" {
		errorType = "nonzero_exit"
	}
	toolStatus := strings.TrimSpace(observation.toolStatus)
	if toolStatus == "" {
		switch outcome {
		case observability.OutcomeBlocked:
			toolStatus = "blocked"
		case observability.OutcomeFailed, observability.OutcomeRejected:
			toolStatus = "failed"
		default:
			toolStatus = "completed"
		}
	}
	return outcome, technicalFailure, errorType, toolStatus
}

func applyGeneratedToolV8Identity(input *observability.SpanToolExecuteInput, observation generatedToolV8Observation) {
	meta := observation.meta
	input.DefenseClawConnectorSource = hookModelV8OptionalID(meta.Source)
	input.DefenseClawRunID = hookModelV8OptionalID(meta.RunID)
	input.DefenseClawOperationID = hookModelV8OptionalID(meta.OperationID)
	input.DefenseClawRequestID = hookModelV8OptionalID(meta.RequestID)
	input.DefenseClawTurnID = hookModelV8OptionalID(meta.TurnID)
	input.UserID = hookModelV8OptionalID(meta.UserID)
	input.DefenseClawUserName = hookModelV8OptionalID(meta.UserName)
	input.DefenseClawPolicyID = hookModelV8OptionalID(meta.PolicyID)
	input.DefenseClawDestinationApp = hookModelV8OptionalID(meta.DestinationApp)
	input.GenAIConversationID = hookModelV8OptionalID(observation.sessionID)
	input.GenAIAgentID = hookModelV8OptionalID(observation.agentID)
	input.GenAIAgentName = hookModelV8OptionalID(observation.agentName)
	input.DefenseClawAgentType = hookModelV8OptionalText(observation.agentType)
	input.DefenseClawAgentRootID = hookModelV8OptionalID(firstNonEmpty(meta.RootAgentID, observation.agentID))
	input.DefenseClawAgentParentID = hookModelV8OptionalID(meta.ParentAgentID)
	input.DefenseClawSessionRootID = hookModelV8OptionalID(firstNonEmpty(meta.RootSessionID, observation.sessionID))
	input.DefenseClawSessionParentID = hookModelV8OptionalID(meta.ParentSessionID)
	input.DefenseClawAgentLifecycleID = hookModelV8OptionalID(meta.LifecycleID)
	input.DefenseClawAgentExecutionID = hookModelV8OptionalID(meta.ExecutionID)
	if observation.agentID != "" {
		input.DefenseClawAgentDepth = observability.Present(int64(max(meta.AgentDepth, 0)))
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
	input.DefenseClawAgentLineageProvenance = hookModelV8OptionalLineage(meta.LineageProvenance)
	input.DefenseClawSessionSource = hookModelV8OptionalSessionSource(meta.SessionSource)
	input.DefenseClawSessionResumed = observability.Present(meta.SessionResumed)
	if input.DefenseClawAgentReportedCostPresent {
		input.DefenseClawAgentReportedCostUsd = observability.Present(meta.ReportedCostUSD)
	}
}

func hookToolV8Arguments(
	raw string,
	originalBytes int64,
	preTruncated bool,
) (observability.TelemetryStructuredGenAIToolCallArguments, bool, string, int64, string) {
	if strings.TrimSpace(raw) == "" {
		return observability.TelemetryStructuredGenAIToolCallArguments{}, false, "not_reported", 0, ""
	}
	if originalBytes <= 0 {
		originalBytes = int64(len(raw))
	}
	state := "preserved"
	if preTruncated || int64(len(raw)) < originalBytes {
		state = "truncated"
	}
	if value, ok := hookToolV8ArgumentObject(raw); ok {
		return value, true, state, originalBytes, "application/json"
	}
	value, truncated, ok := hookToolV8RawArguments(raw)
	if truncated {
		state = "truncated"
	}
	if !ok {
		return observability.TelemetryStructuredGenAIToolCallArguments{}, true, "failed_closed", originalBytes, "text/plain"
	}
	mimeType := "text/plain"
	if json.Valid([]byte(raw)) {
		mimeType = "application/json"
	}
	return value, true, state, originalBytes, mimeType
}

func hookToolV8Result(
	raw string,
) (observability.TelemetryStructuredGenAIToolCallResult, bool, string, int64, string) {
	if strings.TrimSpace(raw) == "" {
		return observability.TelemetryStructuredGenAIToolCallResult{}, false, "not_reported", 0, ""
	}
	originalBytes := int64(len(raw))
	if value, ok := hookToolV8ResultObject(raw); ok {
		return value, true, "preserved", originalBytes, "application/json"
	}
	value, truncated, ok := hookToolV8RawResult(raw)
	state := "preserved"
	if truncated {
		state = "truncated"
	}
	if !ok {
		return observability.TelemetryStructuredGenAIToolCallResult{}, true, "failed_closed", originalBytes, "text/plain"
	}
	mimeType := "text/plain"
	if json.Valid([]byte(raw)) {
		mimeType = "application/json"
	}
	return value, true, state, originalBytes, mimeType
}

func hookToolV8ArgumentObject(raw string) (observability.TelemetryStructuredGenAIToolCallArguments, bool) {
	object, ok := hookToolV8DecodeObject(raw)
	if !ok {
		return observability.TelemetryStructuredGenAIToolCallArguments{}, false
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := observability.TelemetryStructuredGenAIToolCallArguments{
		Entries: make([]observability.GenAIToolCallArgumentsEntryMemberInput, 0, len(keys)),
	}
	for _, key := range keys {
		value, valid := proxyV8CanonicalJSONValue(object[key])
		if !valid {
			return observability.TelemetryStructuredGenAIToolCallArguments{}, false
		}
		entry, err := observability.NewGenAIToolCallArgumentsEntryMember(key, value)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallArguments{}, false
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, observability.ValidateTelemetryStructuredGenAIToolCallArguments(result) == nil
}

func hookToolV8ResultObject(raw string) (observability.TelemetryStructuredGenAIToolCallResult, bool) {
	object, ok := hookToolV8DecodeObject(raw)
	if !ok {
		return observability.TelemetryStructuredGenAIToolCallResult{}, false
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := observability.TelemetryStructuredGenAIToolCallResult{
		Entries: make([]observability.GenAIToolCallResultEntryMemberInput, 0, len(keys)),
	}
	for _, key := range keys {
		value, valid := proxyV8CanonicalJSONValue(object[key])
		if !valid {
			return observability.TelemetryStructuredGenAIToolCallResult{}, false
		}
		entry, err := observability.NewGenAIToolCallResultEntryMember(key, value)
		if err != nil {
			return observability.TelemetryStructuredGenAIToolCallResult{}, false
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, observability.ValidateTelemetryStructuredGenAIToolCallResult(result) == nil
}

func hookToolV8DecodeObject(raw string) (map[string]any, bool) {
	if !json.Valid([]byte(raw)) {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func hookToolV8RawArguments(raw string) (observability.TelemetryStructuredGenAIToolCallArguments, bool, bool) {
	bounded, truncated := hookToolV8RawContent(raw)
	value := observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: bounded}
	entry, err := observability.NewGenAIToolCallArgumentsEntryMember("raw", value)
	if err != nil {
		return observability.TelemetryStructuredGenAIToolCallArguments{}, truncated, false
	}
	result := observability.TelemetryStructuredGenAIToolCallArguments{Entries: []observability.GenAIToolCallArgumentsEntryMemberInput{entry}}
	return result, truncated, observability.ValidateTelemetryStructuredGenAIToolCallArguments(result) == nil
}

func hookToolV8RawResult(raw string) (observability.TelemetryStructuredGenAIToolCallResult, bool, bool) {
	bounded, truncated := hookToolV8RawContent(raw)
	value := observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: bounded}
	entry, err := observability.NewGenAIToolCallResultEntryMember("content", value)
	if err != nil {
		return observability.TelemetryStructuredGenAIToolCallResult{}, truncated, false
	}
	result := observability.TelemetryStructuredGenAIToolCallResult{Entries: []observability.GenAIToolCallResultEntryMemberInput{entry}}
	return result, truncated, observability.ValidateTelemetryStructuredGenAIToolCallResult(result) == nil
}

func hookToolV8RawContent(raw string) (string, bool) {
	valid := strings.ToValidUTF8(raw, "\uFFFD")
	bounded := truncateToRuneBoundary(valid, 4096)
	return bounded, bounded != raw
}

func (a *APIServer) recordHookToolMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation generatedToolV8Observation,
) {
	if a == nil {
		return
	}
	recordGeneratedToolMetricsV8(ctx, runtime, observation)
}

func recordGeneratedToolMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation generatedToolV8Observation,
) {
	if ctx == nil || runtime == nil || observation.tool == "" {
		return
	}
	toolName := observability.Present(observation.tool)
	provider := observability.Present(firstNonEmpty(observation.toolProvider, "hook"))
	producer := firstNonEmpty(observation.producer, hookToolV8Producer)
	items := []observabilityruntime.GeneratedMetricBatchItem{
		newHookV8MetricBatchItemForProducer(ctx, observation.finishedAt, observation.meta, producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawToolCalls),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawToolCalls(observability.MetricDefenseClawToolCallsInput{
					Envelope: envelope, Value: 1, DefenseClawMetricDangerous: observability.Present(observation.dangerous),
					GenAIToolName: toolName, DefenseClawToolProvider: provider,
				})
			}),
	}
	durationMillis := observation.finishedAt.Sub(observation.startedAt).Seconds() * 1000
	if durationMillis >= 0 && !math.IsNaN(durationMillis) && !math.IsInf(durationMillis, 0) {
		items = append(items, newHookV8MetricBatchItemForProducer(
			ctx, observation.finishedAt, observation.meta, producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawToolDuration),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawToolDuration(observability.MetricDefenseClawToolDurationInput{
					Envelope: envelope, Value: durationMillis,
					GenAIToolName: toolName, DefenseClawToolProvider: provider,
				})
			},
		))
	}
	_, technicalFailure, _, _ := generatedToolV8Result(observation)
	if technicalFailure {
		exitCode := observability.Absent[int64]()
		if observation.exitCode != nil {
			exitCode = observability.Present(int64(*observation.exitCode))
		}
		items = append(items, newHookV8MetricBatchItemForProducer(
			ctx, observation.finishedAt, observation.meta, producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawToolErrors),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawToolErrors(observability.MetricDefenseClawToolErrorsInput{
					Envelope: envelope, Value: 1,
					DefenseClawToolExitCode: exitCode, GenAIToolName: toolName,
				})
			},
		))
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}
