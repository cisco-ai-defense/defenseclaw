// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const hookModelV8Producer = "gateway.hook.model"

type hookModelV8Observation struct {
	meta                llmEventMeta
	prompt              string
	response            string
	usage               hookLLMSpanUsage
	provider            string
	reportedModel       string
	model               string
	responseModel       string
	agentName           string
	agentType           string
	agentID             string
	sessionID           string
	startedAt           time.Time
	finishedAt          time.Time
	promptOriginalBytes int64
	promptTruncated     bool
	toolCallCount       int64
	finishReasons       []string
	outcome             observability.Outcome
	technicalFailure    bool
	errorType           string
}

// emitHookLLMSpanV8 emits one request-bounded generated hierarchy. Hook
// sessions can last for hours, so a completed model call is the ownership
// boundary: no graph lease or open SDK span survives this method.
func (a *APIServer) emitHookLLMSpanV8(
	ctx context.Context,
	runtime lifecycleV8Runtime,
	metricRuntime hookLifecycleMetricV8Runtime,
	snapshot hookLLMSpanPrompt,
	meta llmEventMeta,
	response string,
) (correlated context.Context) {
	correlated = ctx
	if a == nil || ctx == nil || runtime == nil {
		return
	}
	observation := a.hookModelV8Observation(snapshot, meta, response)
	agentInput, hasAgent := hookModelV8AgentInput(observation)
	metricContext := ctx
	metricsPinned := false
	// Metrics are an independent signal. Token and duration metrics remain
	// recordable when trace collection or sampling declines every span.
	defer func() {
		if !metricsPinned {
			a.recordHookModelMetricsV8(metricContext, metricRuntime, observation)
		}
	}()
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
			if observation.model == "" {
				a.recordHookModelMetricsV8(metricContext, agent, observation)
				metricsPinned = true
				if endErr := agent.End(agentInput); endErr != nil {
					return
				}
				if agentContext != nil {
					correlated = agentContext
				}
				return
			}
			modelInput := hookModelV8ModelInput(observation)
			modelInput = inheritHookModelV8Agent(modelInput, agentInput)
			model, modelErr := agent.StartModel(modelInput)
			if modelErr != nil {
				return
			}
			recordingContext := agentContext
			if model != nil {
				defer model.Abort()
				modelContext := model.Context()
				if modelContext != nil {
					metricContext = modelContext
					recordingContext = modelContext
				}
				a.recordHookModelMetricsV8(metricContext, model, observation)
				metricsPinned = true
				if endErr := model.End(modelInput); endErr != nil {
					return
				}
			} else {
				a.recordHookModelMetricsV8(metricContext, agent, observation)
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

	if observation.model == "" {
		return
	}
	modelInput := hookModelV8ModelInput(observation)
	startedContext, model, err := runtime.StartModelTrace(ctx, modelInput)
	if startedContext != nil {
		metricContext = startedContext
	}
	if err != nil {
		return
	}
	if model == nil {
		if hookModelV8AgentSamplingDeclined(ctx, startedContext) {
			correlated = startedContext
		}
		return
	}
	defer model.Abort()
	modelContext := model.Context()
	if modelContext != nil {
		metricContext = modelContext
	}
	a.recordHookModelMetricsV8(metricContext, model, observation)
	metricsPinned = true
	if endErr := model.End(modelInput); endErr != nil {
		return
	}
	if modelContext != nil {
		correlated = modelContext
	} else if startedContext != nil {
		correlated = startedContext
	}
	return
}

func (a *APIServer) hookModelV8Observation(
	snapshot hookLLMSpanPrompt,
	meta llmEventMeta,
	response string,
) hookModelV8Observation {
	usage := a.takeHookLLMSpanUsage(meta)
	provider := firstNonEmpty(meta.Provider, snapshot.meta.Provider, meta.Source, snapshot.meta.Source, "unknown")
	reportedModel := firstNonEmpty(snapshot.meta.Model, meta.Model, usage.model)
	model := reportedModel
	if !hookModelV8Identifier(model) {
		model = ""
	}
	responseModel := strings.TrimSpace(meta.Model)
	if !hookModelV8Identifier(responseModel) {
		responseModel = ""
	}
	startedAt := snapshot.startedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := time.Now().UTC()
	if finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	outcome, technicalFailure, errorType := hookModelV8TerminalResult(meta)
	return hookModelV8Observation{
		meta: meta, prompt: snapshot.content, response: response, usage: usage,
		provider: provider, reportedModel: reportedModel, model: model, responseModel: responseModel,
		agentName: firstNonEmpty(meta.AgentName, snapshot.meta.AgentName, meta.Source, snapshot.meta.Source),
		agentType: firstNonEmpty(meta.AgentType, snapshot.meta.AgentType, meta.Source, snapshot.meta.Source),
		agentID:   firstNonEmpty(meta.AgentID, snapshot.meta.AgentID),
		sessionID: firstNonEmpty(meta.SessionID, snapshot.meta.SessionID),
		startedAt: startedAt, finishedAt: finishedAt,
		promptOriginalBytes: snapshot.originalBytes,
		promptTruncated:     snapshot.truncated,
		finishReasons:       hookModelV8FinishReasons(meta.FinishReasons),
		outcome:             outcome,
		technicalFailure:    technicalFailure,
		errorType:           errorType,
	}
}

// hookModelV8TerminalResult translates a bounded hook completion into the
// outcome vocabulary accepted by both model.call.failed and model spans. A
// hook completion is successful unless the connector explicitly reports a
// terminal failure class; start/active lifecycle outcomes must not turn a
// completed request-bounded model operation into an attempted span.
func hookModelV8TerminalResult(meta llmEventMeta) (observability.Outcome, bool, string) {
	switch strings.TrimSpace(meta.LifecycleOutcome) {
	case "failed":
		return observability.OutcomeFailed, true, "hook_failure"
	case "timed_out":
		return observability.OutcomeTimedOut, true, "timeout"
	case "cancelled":
		return observability.OutcomeCancelled, false, ""
	case "rejected":
		return observability.OutcomeRejected, false, ""
	default:
		return observability.OutcomeCompleted, false, ""
	}
}

func hookModelV8ObservationResult(observation hookModelV8Observation) (observability.Outcome, bool, string) {
	outcome := observation.outcome
	if outcome == "" {
		outcome = observability.OutcomeCompleted
	}
	return outcome, observation.technicalFailure, strings.TrimSpace(observation.errorType)
}

func hookModelV8AgentSamplingDeclined(before, after context.Context) bool {
	beforeSpan := trace.SpanContextFromContext(before)
	afterSpan := trace.SpanContextFromContext(after)
	if !afterSpan.IsValid() {
		return false
	}
	newSpan := !beforeSpan.IsValid() || beforeSpan.TraceID() != afterSpan.TraceID() ||
		beforeSpan.SpanID() != afterSpan.SpanID()
	return newSpan && !afterSpan.IsSampled()
}

func hookModelV8Envelope(observation hookModelV8Observation, action string) observability.FamilyEnvelopeInput {
	meta := observation.meta
	connector := hookModelV8StableToken(firstNonEmpty(meta.Source, observation.provider))
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: connector, Action: action, Phase: "model",
		Correlation: observability.Correlation{
			RunID: meta.RunID, RequestID: meta.RequestID, SessionID: observation.sessionID,
			TurnID: meta.TurnID, AgentID: observation.agentID, PolicyID: meta.PolicyID,
			ModelRequestID: meta.PromptID, ModelResponseID: meta.ResponseID,
			ConnectorID: connector,
		},
		Provenance: observability.FamilyProvenanceInput{Producer: hookModelV8Producer},
	}
}

func hookModelV8AgentInput(
	observation hookModelV8Observation,
) (observability.SpanAgentInvokeInput, bool) {
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
	inputMessages, inputBytes, inputReported, inputState, inputStructured := hookModelV8InputMessages(
		observation.prompt, observation.promptOriginalBytes, observation.promptTruncated,
	)
	outputMessages, outputBytes, outputReported, outputState, outputStructured := hookModelV8OutputMessages(
		observation.response, observation.finishReasons,
	)
	outcome, technicalFailure, errorType := hookModelV8ObservationResult(observation)
	input := observability.SpanAgentInvokeInput{
		Envelope: hookModelV8Envelope(observation, "invoke_agent"),
		Outcome:  outcome, Kind: "INTERNAL",
		StartTimeUnixNano:                   uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:                     uint64(observation.finishedAt.UnixNano()),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawAgentType:                observation.agentType,
		DefenseClawAgentReportedCostPresent: hookModelV8ReportedCost(meta),
		DefenseClawTelemetryInputReported:   inputReported, DefenseClawContentInputState: inputState,
		DefenseClawTelemetryOutputReported: outputReported, DefenseClawContentOutputState: outputState,
		GenAIOperationName:         observability.Present("invoke_agent"),
		ConditionConnectorKnown:    hookModelV8StableToken(meta.Source) != "",
		ConditionOperationTerminal: true,
		ConditionTechnicalFailure:  technicalFailure,
	}
	if errorType != "" {
		input.ErrorType = observability.Present(errorType)
	}
	if technicalFailure {
		input.Status = observability.NewTraceStatusError(input.ErrorType)
	}
	if inputStructured {
		input.GenAIInputMessages = observability.Present(inputMessages)
	}
	if inputReported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
		input.DefenseClawContentInputMimeType = observability.Present("text/plain")
	}
	if outputStructured {
		input.GenAIOutputMessages = observability.Present(outputMessages)
	}
	if outputReported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
		input.DefenseClawContentOutputMimeType = observability.Present("text/plain")
	}
	applyHookModelV8AgentFacts(&input, observation, rootAgentID, rootSessionID)
	return input, true
}

func hookModelV8ModelInput(observation hookModelV8Observation) observability.SpanModelChatInput {
	meta := observation.meta
	inputMessages, inputBytes, inputReported, inputState, inputStructured := hookModelV8InputMessages(
		observation.prompt, observation.promptOriginalBytes, observation.promptTruncated,
	)
	outputMessages, outputBytes, outputReported, outputState, outputStructured := hookModelV8OutputMessages(
		observation.response, observation.finishReasons,
	)
	outcome, technicalFailure, errorType := hookModelV8ObservationResult(observation)
	input := observability.SpanModelChatInput{
		Envelope: hookModelV8Envelope(observation, "chat"),
		Outcome:  outcome, Kind: "CLIENT",
		StartTimeUnixNano:                   uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:                     uint64(observation.finishedAt.UnixNano()),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawAgentReportedCostPresent: hookModelV8ReportedCost(meta),
		DefenseClawTelemetryInputReported:   inputReported, DefenseClawContentInputState: inputState,
		DefenseClawTelemetryOutputReported: outputReported, DefenseClawContentOutputState: outputState,
		GenAIOperationName: observability.Present("chat"),
		GenAIRequestModel:  observation.model,
		DefenseClawTelemetryTokensReported: observability.Present(
			observation.usage.promptTokens > 0 || observation.usage.completionTokens > 0,
		),
		ConditionConnectorKnown:    hookModelV8StableToken(meta.Source) != "",
		ConditionOperationTerminal: true,
		ConditionTechnicalFailure:  technicalFailure,
	}
	if errorType != "" {
		input.ErrorType = observability.Present(errorType)
	}
	if technicalFailure {
		input.Status = observability.NewTraceStatusError(input.ErrorType)
	}
	if provider := strings.TrimSpace(observation.provider); provider != "" {
		input.GenAIProviderName = observability.Present(provider)
	}
	if observation.responseModel != "" {
		input.GenAIResponseModel = observability.Present(observation.responseModel)
	}
	if len(observation.finishReasons) > 0 {
		input.GenAIResponseFinishReasons = observability.Present(
			append([]string(nil), observation.finishReasons...),
		)
	}
	if inputStructured {
		input.GenAIInputMessages = observability.Present(inputMessages)
	}
	if inputReported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
		input.DefenseClawContentInputMimeType = observability.Present("text/plain")
	}
	if outputStructured {
		input.GenAIOutputMessages = observability.Present(outputMessages)
	}
	if outputReported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
		input.DefenseClawContentOutputMimeType = observability.Present("text/plain")
	}
	if observation.usage.promptTokens > 0 {
		input.GenAIUsageInputTokens = observability.Present(observation.usage.promptTokens)
	}
	if observation.usage.completionTokens > 0 {
		input.GenAIUsageOutputTokens = observability.Present(observation.usage.completionTokens)
	}
	if observation.toolCallCount > 0 {
		input.DefenseClawModelToolCallCount = observability.Present(observation.toolCallCount)
	}
	input.GenAIResponseID = hookModelV8OptionalID(meta.ResponseID)
	input.DefenseClawModelRequestID = hookModelV8OptionalID(meta.PromptID)
	input.DefenseClawModelResponseID = hookModelV8OptionalID(meta.ResponseID)
	applyHookModelV8ModelFacts(&input, observation)
	return input
}

func applyHookModelV8AgentFacts(
	input *observability.SpanAgentInvokeInput,
	observation hookModelV8Observation,
	rootAgentID string,
	rootSessionID string,
) {
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
	input.GenAIConversationID = observability.Present(observation.sessionID)
	input.GenAIAgentID = observability.Present(observation.agentID)
	input.GenAIAgentName = hookModelV8OptionalID(observation.agentName)
	input.DefenseClawAgentRootID = observability.Present(rootAgentID)
	input.DefenseClawAgentParentID = hookModelV8OptionalID(meta.ParentAgentID)
	input.DefenseClawSessionRootID = observability.Present(rootSessionID)
	input.DefenseClawSessionParentID = hookModelV8OptionalID(meta.ParentSessionID)
	input.DefenseClawAgentLifecycleID = observability.Present(meta.LifecycleID)
	input.DefenseClawAgentExecutionID = observability.Present(meta.ExecutionID)
	input.DefenseClawAgentDepth = observability.Present(int64(max(meta.AgentDepth, 0)))
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
	input.DefenseClawAgentLineageProvenance = hookModelV8OptionalLineage(meta.LineageProvenance)
	input.DefenseClawSessionSource = hookModelV8OptionalSessionSource(meta.SessionSource)
	input.DefenseClawSessionResumed = observability.Present(meta.SessionResumed)
	if input.DefenseClawAgentReportedCostPresent {
		input.DefenseClawAgentReportedCostUsd = observability.Present(meta.ReportedCostUSD)
	}
	if provider := strings.TrimSpace(observation.provider); provider != "" {
		input.GenAIProviderName = observability.Present(provider)
	}
	if observation.model != "" {
		input.GenAIRequestModel = observability.Present(observation.model)
	}
	if observation.responseModel != "" {
		input.GenAIResponseModel = observability.Present(observation.responseModel)
	}
	input.GenAIResponseID = hookModelV8OptionalID(meta.ResponseID)
	input.DefenseClawModelRequestID = hookModelV8OptionalID(meta.PromptID)
	input.DefenseClawModelResponseID = hookModelV8OptionalID(meta.ResponseID)
}

func applyHookModelV8ModelFacts(input *observability.SpanModelChatInput, observation hookModelV8Observation) {
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
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
	if meta.PreviousPhase != "" && meta.PreviousPhase != "model" {
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

func inheritHookModelV8Agent(
	model observability.SpanModelChatInput,
	agent observability.SpanAgentInvokeInput,
) observability.SpanModelChatInput {
	inheritProxyV8AgentIdentity(&model, agent)
	model.DefenseClawAgentLifecycleEvent = agent.DefenseClawAgentLifecycleEvent
	model.DefenseClawAgentLifecycleState = agent.DefenseClawAgentLifecycleState
	model.DefenseClawAgentPhase = agent.DefenseClawAgentPhase
	model.DefenseClawAgentPhasePrevious = agent.DefenseClawAgentPhasePrevious
	model.DefenseClawAgentPhaseCode = agent.DefenseClawAgentPhaseCode
	model.DefenseClawAgentSequence = agent.DefenseClawAgentSequence
	model.DefenseClawSessionSource = agent.DefenseClawSessionSource
	model.DefenseClawSessionResumed = agent.DefenseClawSessionResumed
	return model
}

func hookModelV8InputMessages(
	content string,
	originalBytes int64,
	preTruncated bool,
) (observability.TelemetryStructuredGenAIInputMessages, int64, bool, string, bool) {
	bounded, originalBytes, reported, state := hookModelV8Content(content, originalBytes, preTruncated)
	if !reported {
		return observability.TelemetryStructuredGenAIInputMessages{}, 0, false, state, false
	}
	bounded, fitted := hookModelV8FitContent(bounded, func(candidate string) error {
		return observability.ValidateTelemetryStructuredGenAIInputMessages(hookModelV8InputMessage(candidate))
	})
	if fitted {
		state = "truncated"
	}
	message := hookModelV8InputMessage(bounded)
	if err := observability.ValidateTelemetryStructuredGenAIInputMessages(message); err != nil {
		return observability.TelemetryStructuredGenAIInputMessages{}, originalBytes, true, "failed_closed", false
	}
	return message, originalBytes, true, state, true
}

func hookModelV8OutputMessages(
	content string,
	finishReasons []string,
) (observability.TelemetryStructuredGenAIOutputMessages, int64, bool, string, bool) {
	bounded, originalBytes, reported, state := hookModelV8Content(content, int64(len(content)), false)
	if !reported {
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, false, state, false
	}
	finishReason := observability.Absent[string]()
	if len(finishReasons) > 0 {
		finishReason = observability.Present(finishReasons[0])
	}
	bounded, fitted := hookModelV8FitContent(bounded, func(candidate string) error {
		return observability.ValidateTelemetryStructuredGenAIOutputMessages(
			hookModelV8OutputMessage(candidate, finishReason),
		)
	})
	if fitted {
		state = "truncated"
	}
	message := hookModelV8OutputMessage(bounded, finishReason)
	if err := observability.ValidateTelemetryStructuredGenAIOutputMessages(message); err != nil {
		return observability.TelemetryStructuredGenAIOutputMessages{}, originalBytes, true, "failed_closed", false
	}
	return message, originalBytes, true, state, true
}

func hookModelV8InputMessage(content string) observability.TelemetryStructuredGenAIInputMessages {
	return observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: hookModelV8TextParts(content)},
	}}}
}

func hookModelV8OutputMessage(content string, finishReason observability.Optional[string]) observability.TelemetryStructuredGenAIOutputMessages {
	return observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: finishReason,
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: hookModelV8TextParts(content)},
	}}}
}

// The structured GenAI contract bounds each text part at 4096 UTF-8 bytes,
// while the hook cache intentionally retains up to 32 KiB. Split the bounded
// value on rune boundaries so the generated builder can preserve the complete
// retained payload without weakening either limit.
func hookModelV8TextParts(content string) []observability.TelemetryStructuredGenAIMessagePart {
	const maxPartBytes = 4096
	parts := make([]observability.TelemetryStructuredGenAIMessagePart, 0, 8)
	for len(content) > 0 {
		cut := min(len(content), maxPartBytes)
		for cut > 0 && !utf8.ValidString(content[:cut]) {
			cut--
		}
		if cut == 0 {
			_, width := utf8.DecodeRuneInString(content)
			cut = max(width, 1)
		}
		parts = append(parts, observability.TelemetryStructuredArmGenAIMessagePartText{
			Value: observability.TelemetryStructuredGenAITextPart{Content: content[:cut]},
		})
		content = content[cut:]
	}
	return parts
}

func hookModelV8Content(content string, originalBytes int64, preTruncated bool) (string, int64, bool, string) {
	if strings.TrimSpace(content) == "" {
		return "", 0, false, "not_reported"
	}
	if originalBytes <= 0 {
		originalBytes = int64(len(content))
	}
	bounded := boundedHookLLMSpanContent(strings.ToValidUTF8(content, "\uFFFD"))
	state := "preserved"
	if preTruncated || int64(len(bounded)) < originalBytes {
		state = "truncated"
	}
	return bounded, originalBytes, true, state
}

func hookModelV8FitContent(content string, validate func(string) error) (string, bool) {
	if validate(content) == nil {
		return content, false
	}
	runes := []rune(content)
	low, high := 0, len(runes)
	for low < high {
		mid := low + (high-low+1)/2
		if validate(string(runes[:mid])) == nil {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return string(runes[:low]), low != len(runes)
}

func hookModelV8ReportedCost(meta llmEventMeta) bool {
	return meta.ReportedCost && meta.ReportedCostUSD >= 0 &&
		!math.IsNaN(meta.ReportedCostUSD) && !math.IsInf(meta.ReportedCostUSD, 0)
}

func hookModelV8StableToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !observability.IsStableToken(value) {
		return ""
	}
	return value
}

var hookModelV8IdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

func hookModelV8Identifier(value string) bool {
	return value != "" && len(value) <= 256 && hookModelV8IdentifierPattern.MatchString(value)
}

func hookModelV8OptionalID(value string) observability.Optional[string] {
	if hookModelV8Identifier(value) {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func hookModelV8FinishReasons(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 4096 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func hookModelV8OptionalText(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value != "" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func hookModelV8OptionalPhase(value string) observability.Optional[string] {
	switch value {
	case "session", "planning", "model", "tool", "approval", "waiting", "responding",
		"maintenance", "completed", "failed", "interrupted", "observed":
		return observability.Present(value)
	default:
		return observability.Absent[string]()
	}
}

func hookModelV8OptionalLineage(value string) observability.Optional[string] {
	if value == "reported" || value == "inferred" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func hookModelV8OptionalSessionSource(value string) observability.Optional[string] {
	switch value {
	case "startup", "resume", "clear", "compact":
		return observability.Present(value)
	default:
		return observability.Absent[string]()
	}
}

func (a *APIServer) recordHookModelMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation hookModelV8Observation,
) {
	if a == nil {
		return
	}
	recordGeneratedModelMetricsV8(ctx, runtime, observation)
}

func recordGeneratedModelMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation hookModelV8Observation,
) {
	recordGeneratedModelMetricsV8ForProducer(ctx, runtime, observation, hookModelV8Producer)
}

func recordGeneratedModelMetricsV8ForProducer(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	observation hookModelV8Observation,
	producer string,
) {
	if ctx == nil || runtime == nil {
		return
	}
	meta := observation.meta
	connector := telemetry.NormalizeMetricTextLabel(meta.Source)
	provider := telemetry.NormalizeGenAIProviderLabel(observation.provider)
	model := telemetry.NormalizeModelLabel(observation.reportedModel)
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 5)
	appendTokens := func(tokenType string, tokens int64) {
		if tokens <= 0 {
			return
		}
		items = append(items,
			newHookV8MetricBatchItemForProducer(ctx, observation.finishedAt, meta, producer,
				observability.EventName(observability.TelemetryInstrumentDefenseClawAgentTokenUsage),
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawAgentTokenUsage(observability.MetricDefenseClawAgentTokenUsageInput{
						Envelope: envelope, Value: tokens,
						DefenseClawConnectorSource: observability.Present(connector),
						GenAIProviderName:          observability.Present(provider),
						GenAIRequestModel:          observability.Present(model),
						GenAITokenType:             observability.Present(tokenType),
					})
				}),
			newHookV8MetricBatchItemForProducer(ctx, observation.finishedAt, meta, producer,
				observability.EventName(observability.TelemetryInstrumentGenAIClientTokenUsage),
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricGenAIClientTokenUsage(observability.MetricGenAIClientTokenUsageInput{
						Envelope: envelope, Value: float64(tokens),
						GenAIOperationName: observability.Present("chat"),
						GenAIProviderName:  observability.Present(provider),
						GenAIRequestModel:  observability.Present(model),
						GenAITokenType:     observability.Present(tokenType),
					})
				}),
		)
	}
	appendTokens("input", observation.usage.promptTokens)
	appendTokens("output", observation.usage.completionTokens)
	durationSeconds := observation.finishedAt.Sub(observation.startedAt).Seconds()
	if durationSeconds > 0 && !math.IsNaN(durationSeconds) && !math.IsInf(durationSeconds, 0) {
		items = append(items, newHookV8MetricBatchItemForProducer(ctx, observation.finishedAt, meta, producer,
			observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricGenAIClientOperationDuration(observability.MetricGenAIClientOperationDurationInput{
					Envelope: envelope, Value: durationSeconds,
					GenAIOperationName: observability.Present("chat"),
					GenAIProviderName:  observability.Present(provider),
					GenAIRequestModel:  observability.Present(model),
				})
			}),
		)
	}
	if len(items) > 0 {
		_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
	}
}

type hookV8MetricRecordBuilder func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
) (observability.Record, error)

func newHookV8MetricBatchItem(
	ctx context.Context,
	observedAt time.Time,
	meta llmEventMeta,
	family observability.EventName,
	buildRecord hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return newHookV8MetricBatchItemForProducer(
		ctx, observedAt, meta, hookModelV8Producer, family, buildRecord,
	)
}

func newHookV8MetricBatchItemForProducer(
	ctx context.Context,
	observedAt time.Time,
	meta llmEventMeta,
	producer string,
	family observability.EventName,
	buildRecord hookV8MetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return observabilityruntime.GeneratedMetricBatchItem{
		Family: family,
		Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 || buildRecord == nil {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			envelope := observability.FamilyEnvelopeInput{
				Source: observability.SourceConnector, Connector: hookModelV8StableToken(meta.Source),
				Correlation: observability.Correlation{
					RunID: meta.RunID, RequestID: meta.RequestID, SessionID: meta.SessionID,
					TurnID: meta.TurnID, AgentID: meta.AgentID, PolicyID: meta.PolicyID,
					ModelRequestID: meta.PromptID, ModelResponseID: meta.ResponseID,
					ToolInvocationID: meta.ToolID,
					ConnectorID:      hookModelV8StableToken(meta.Source),
				},
				Provenance: observability.FamilyProvenanceInput{
					Producer: producer, BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			}
			if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
				envelope.Correlation.TraceID = spanContext.TraceID().String()
				envelope.Correlation.SpanID = spanContext.SpanID().String()
			}
			return buildRecord(builder, envelope)
		},
	}
}
