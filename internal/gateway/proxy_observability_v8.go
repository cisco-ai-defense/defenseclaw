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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const proxyV8Producer = "gateway.proxy.chat"

const proxyV8TerminalTelemetryTimeout = 5 * time.Second

const proxyV8MaxStructuredItems = 256

// proxyV8TerminalTelemetryContext preserves request correlation and active
// span values after the caller goes away, while bounding the small amount of
// terminal persistence work. WithoutCancel deliberately removes only caller
// cancellation/deadline; the timeout below prevents detached work lingering.
func proxyV8TerminalTelemetryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), proxyV8TerminalTelemetryTimeout)
}

// lifecycleV8Runtime is the single process-owned generated trace seam shared by
// the proxy, hook API, and EventRouter. It exposes only request-bounded root
// operations; producers must never retain returned handles across deliveries.
type lifecycleV8Runtime interface {
	StartAgentTrace(context.Context, observability.SpanAgentInvokeInput) (context.Context, *observabilityruntime.AgentTrace, error)
	StartAgentTransitionTrace(context.Context, observability.SpanAgentTransitionInput) (context.Context, *observabilityruntime.AgentTransitionTrace, error)
	StartModelTrace(context.Context, observability.SpanModelChatInput) (context.Context, *observabilityruntime.ModelTrace, error)
	StartToolTrace(context.Context, observability.SpanToolExecuteInput) (context.Context, *observabilityruntime.ToolTrace, error)
	StartApprovalTrace(context.Context, observability.SpanApprovalResolveInput) (context.Context, *observabilityruntime.ApprovalTrace, error)
}

type proxyV8RequestTrace struct {
	runtime    lifecycleV8Runtime
	agent      *observabilityruntime.AgentTrace
	agentInput observability.SpanAgentInvokeInput
}

type proxyV8ModelTrace struct {
	runtime   lifecycleV8Runtime
	model     *observabilityruntime.ModelTrace
	input     observability.SpanModelChatInput
	ctx       context.Context
	rootModel bool
}

type proxyV8TraceResult struct {
	Outcome          observability.Outcome
	ErrorType        string
	TechnicalFailure bool
	OutputText       string
	ToolCalls        json.RawMessage
	ResponseModel    string
	ResponseID       string
	FinishReasons    []string
	Usage            *ChatUsage
	ToolCallCount    int
	UpstreamDuration time.Duration
	Streaming        bool
	Cancelled        bool
}

func proxyV8DefaultResult(streaming bool) proxyV8TraceResult {
	return proxyV8TraceResult{
		Outcome: observability.OutcomeFailed, ErrorType: "request_incomplete",
		TechnicalFailure: true, Streaming: streaming,
	}
}

func (p *GuardrailProxy) bindObservabilityV8Trace(runtime lifecycleV8Runtime) {
	p.bindObservabilityV8TraceMode(runtime, runtime != nil)
}

func (p *GuardrailProxy) bindObservabilityV8TraceMode(runtime lifecycleV8Runtime, v8Authoritative bool) {
	if p == nil {
		return
	}
	p.observabilityV8Mu.Lock()
	p.observabilityV8Trace = runtime
	egress, _ := runtime.(gatewayEgressV8Runtime)
	p.observabilityV8Egress = egress
	if runtime != nil || v8Authoritative {
		p.observabilityV8EgressAuthoritative = true
	}
	p.observabilityV8Mu.Unlock()
	metricRuntime, _ := runtime.(hookLifecycleMetricV8Runtime)
	if p.hookGuard != nil {
		p.hookGuard.bindObservabilityV8(metricRuntime)
	}
	judgeRuntime, _ := runtime.(judgeTraceV8Runtime)
	if inspector, ok := p.inspector.(*GuardrailInspector); ok {
		configureGuardrailInspectorObservabilityV8(inspector, runtime, p.connectorName)
		if inspector.judge != nil {
			_, alreadyAuthoritative := inspector.judge.judgeTelemetrySnapshot()
			if v8Authoritative || alreadyAuthoritative {
				inspector.judge.bindJudgeTraceV8(judgeRuntime)
			}
		}
	}
}

func (p *GuardrailProxy) observabilityV8EgressRuntime() (gatewayEgressV8Runtime, bool) {
	if p == nil {
		return nil, false
	}
	p.observabilityV8Mu.RLock()
	defer p.observabilityV8Mu.RUnlock()
	return p.observabilityV8Egress, p.observabilityV8EgressAuthoritative
}

func (p *GuardrailProxy) observabilityV8TraceRuntime() lifecycleV8Runtime {
	if p == nil {
		return nil
	}
	p.observabilityV8Mu.RLock()
	defer p.observabilityV8Mu.RUnlock()
	return p.observabilityV8Trace
}

func (p *GuardrailProxy) startProxyV8RequestTrace(
	ctx context.Context,
	req *ChatRequest,
	requestHeaderAgent string,
	requestConversation string,
) (context.Context, *proxyV8RequestTrace) {
	runtime := p.observabilityV8TraceRuntime()
	if runtime == nil || ctx == nil || req == nil {
		return ctx, nil
	}
	if SessionIDFromContext(ctx) == "" {
		if conversation := proxyV8StableID(requestConversation); conversation != "" {
			ctx = ContextWithSessionID(ctx, conversation)
		}
	}
	reportedAgentType := p.agentNameForRequest(requestHeaderAgent)
	agentType := strings.TrimSpace(reportedAgentType)
	trace := &proxyV8RequestTrace{runtime: runtime}
	_, agentTypeValid := hookModelV8OptionalText(agentType).Get()
	if agentType == "" || agentType != reportedAgentType || !agentTypeValid {
		return ctx, trace
	}
	input := p.proxyV8AgentInput(ctx, req, agentType, time.Now().UTC())
	started, agent, err := runtime.StartAgentTrace(ctx, input)
	if err != nil || agent == nil {
		return ctx, trace
	}
	trace.agent, trace.agentInput = agent, input
	return started, trace
}

func (trace *proxyV8RequestTrace) StartModel(
	ctx context.Context,
	input observability.SpanModelChatInput,
) (context.Context, *proxyV8ModelTrace) {
	if trace == nil || trace.runtime == nil || !hookModelV8Identifier(input.GenAIRequestModel) {
		return ctx, nil
	}
	if trace.agent != nil {
		inheritProxyV8AgentIdentity(&input, trace.agentInput)
		model, err := trace.agent.StartModel(input)
		result := &proxyV8ModelTrace{runtime: trace.runtime, model: model, input: input, ctx: ctx}
		if err != nil || model == nil {
			return ctx, result
		}
		result.ctx = model.Context()
		return result.ctx, result
	}
	started, model, err := trace.runtime.StartModelTrace(ctx, input)
	result := &proxyV8ModelTrace{
		runtime: trace.runtime, model: model, input: input, ctx: started, rootModel: true,
	}
	if err != nil || model == nil {
		result.ctx = ctx
		return ctx, result
	}
	return started, result
}

func (trace *proxyV8RequestTrace) Finish(result proxyV8TraceResult) {
	if trace == nil || trace.agent == nil {
		return
	}
	input := trace.agentInput
	applyProxyV8ResultToAgent(&input, result)
	_ = trace.agent.End(input)
}

func (trace *proxyV8RequestTrace) Abort() {
	if trace != nil && trace.agent != nil {
		trace.agent.Abort()
	}
}

func (trace *proxyV8RequestTrace) AddGuardrailOverlay(overlay proxyGuardrailV8Overlay) {
	if trace == nil || trace.agent == nil || len(overlay.agentEvents) == 0 {
		return
	}
	trace.agentInput.Events = append(trace.agentInput.Events, overlay.agentEvents...)
}

func (trace *proxyV8ModelTrace) Finish(result proxyV8TraceResult) {
	if trace == nil {
		return
	}
	trace.recordMetrics(result)
	if trace.model == nil {
		return
	}
	input := trace.input
	applyProxyV8ResultToModel(&input, result)
	_ = trace.model.End(input)
}

func (trace *proxyV8ModelTrace) Abort() {
	// A child-model abort would abort its still-live agent parent. The request
	// root owns that cleanup path. A root-model fallback has no agent owner and
	// therefore retains its own panic cleanup.
	if trace != nil && trace.model != nil && trace.rootModel {
		trace.model.Abort()
	}
}

func (trace *proxyV8ModelTrace) AddGuardrailOverlay(overlay proxyGuardrailV8Overlay) {
	if trace == nil || trace.model == nil || len(overlay.modelEvents) == 0 {
		return
	}
	trace.input.Events = append(trace.input.Events, overlay.modelEvents...)
}

func (trace *proxyV8ModelTrace) recordMetrics(result proxyV8TraceResult) {
	var runtime hookLifecycleMetricV8Runtime
	if trace.model != nil {
		runtime = trace.model
	} else {
		runtime, _ = trace.runtime.(hookLifecycleMetricV8Runtime)
	}
	if runtime == nil {
		return
	}
	metricCtx, metricCancel := proxyV8TerminalTelemetryContext(trace.ctx)
	defer metricCancel()
	input := trace.input
	provider, _ := input.GenAIProviderName.Get()
	agentName, _ := input.GenAIAgentName.Get()
	meta := llmEventMeta{
		Source: input.Envelope.Connector, RunID: input.Envelope.Correlation.RunID,
		RequestID: input.Envelope.Correlation.RequestID, SessionID: input.Envelope.Correlation.SessionID,
		TurnID: input.Envelope.Correlation.TurnID, AgentID: input.Envelope.Correlation.AgentID,
		AgentName: agentName, PolicyID: input.Envelope.Correlation.PolicyID,
		Provider: provider, Model: input.GenAIRequestModel, ResponseID: result.ResponseID,
	}
	observedAt := time.Now().UTC()
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 3)
	appendToken := func(tokenType string, count int64) {
		items = append(items, newHookV8MetricBatchItemForProducer(
			metricCtx, observedAt, meta, proxyV8Producer,
			observability.EventName(observability.TelemetryInstrumentGenAIClientTokenUsage),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricGenAIClientTokenUsage(observability.MetricGenAIClientTokenUsageInput{
					Envelope: envelope, Value: float64(count),
					GenAIOperationName: observability.Present("chat"),
					GenAIProviderName:  proxyV8OptionalText(provider), GenAIRequestModel: observability.Present(input.GenAIRequestModel),
					GenAITokenType: observability.Present(tokenType),
				})
			},
		))
	}
	if result.Usage != nil {
		if result.Usage.PromptTokens >= 0 {
			appendToken("input", result.Usage.PromptTokens)
		}
		if result.Usage.CompletionTokens >= 0 {
			appendToken("output", result.Usage.CompletionTokens)
		}
	}
	durationSeconds := result.UpstreamDuration.Seconds()
	if durationSeconds > 0 && !math.IsNaN(durationSeconds) && !math.IsInf(durationSeconds, 0) {
		items = append(items, newHookV8MetricBatchItemForProducer(
			metricCtx, observedAt, meta, proxyV8Producer,
			observability.EventName(observability.TelemetryInstrumentGenAIClientOperationDuration),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricGenAIClientOperationDuration(observability.MetricGenAIClientOperationDurationInput{
					Envelope: envelope, Value: durationSeconds,
					GenAIOperationName: observability.Present("chat"),
					GenAIProviderName:  proxyV8OptionalText(provider), GenAIRequestModel: observability.Present(input.GenAIRequestModel),
				})
			},
		))
	}
	if len(items) > 0 {
		_, _ = runtime.RecordGeneratedMetricBatch(metricCtx, items)
	}
}

func (p *GuardrailProxy) proxyV8AgentInput(
	ctx context.Context,
	req *ChatRequest,
	agentType string,
	start time.Time,
) observability.SpanAgentInvokeInput {
	envelope, facts := p.proxyV8Envelope(ctx, "invoke_agent")
	// The configured logical agent is valid evidence only when this request
	// actually produced an agent root (a reported/default agent type selected
	// that branch). A root-model fallback must not inherit process-global agent
	// registry state from an unrelated request or test.
	if facts.agentID == "" {
		facts.agentID = proxyV8StableID(p.agentIDForRequest())
		envelope.Correlation.AgentID = facts.agentID
	}
	messages, inputBytes, inputReported, inputState, inputStructured := proxyV8InputMessages(req.Messages)
	input := observability.SpanAgentInvokeInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(start.UnixNano()), Status: observability.NewTraceStatusOK(),
		DefenseClawAgentType: agentType, DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:  inputReported,
		DefenseClawContentInputState:       inputState,
		DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState:      "not_reported",
		GenAIOperationName:                 observability.Present("invoke_agent"),
		ConditionConnectorKnown:            facts.connectorKnown,
		ConditionOperationTerminal:         true,
	}
	if inputStructured {
		input.GenAIInputMessages = observability.Present(messages)
	}
	if inputReported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	applyProxyV8FactsToAgent(&input, facts, agentType)
	return input
}

func (p *GuardrailProxy) proxyV8ModelInput(
	ctx context.Context,
	req *ChatRequest,
	providerName string,
	start time.Time,
) observability.SpanModelChatInput {
	envelope, facts := p.proxyV8Envelope(ctx, "chat")
	messages, inputBytes, inputReported, inputState, inputStructured := proxyV8InputMessages(req.Messages)
	input := observability.SpanModelChatInput{
		Envelope: envelope, Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: uint64(start.UnixNano()), Status: observability.NewTraceStatusOK(),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   inputReported,
		DefenseClawContentInputState:        inputState,
		DefenseClawTelemetryOutputReported:  false,
		DefenseClawContentOutputState:       "not_reported",
		GenAIOperationName:                  observability.Present("chat"),
		GenAIRequestModel:                   strings.TrimSpace(req.Model),
		DefenseClawModelAttempt:             observability.Present[int64](1),
		DefenseClawModelRetryCount:          observability.Present[int64](0),
		DefenseClawModelStreaming:           observability.Present(req.Stream),
		ConditionConnectorKnown:             facts.connectorKnown,
		ConditionOperationTerminal:          true,
	}
	if providerName = strings.TrimSpace(providerName); providerName != "" &&
		len(providerName) <= hookModelV8MaxMetadataBytes {
		input.GenAIProviderName = observability.Present(providerName)
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		input.GenAIRequestMaxTokens = observability.Present(int64(*req.MaxTokens))
	}
	if req.Temperature != nil && !math.IsNaN(*req.Temperature) && !math.IsInf(*req.Temperature, 0) &&
		*req.Temperature >= -1e308 && *req.Temperature <= 1e308 {
		input.GenAIRequestTemperature = observability.Present(*req.Temperature)
	}
	if req.TopP != nil && !math.IsNaN(*req.TopP) && !math.IsInf(*req.TopP, 0) &&
		*req.TopP >= 0 && *req.TopP <= 1 {
		input.GenAIRequestTopP = observability.Present(*req.TopP)
	}
	if inputStructured {
		input.GenAIInputMessages = observability.Present(messages)
	}
	if inputReported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	applyProxyV8FactsToModel(&input, facts)
	return input
}

type proxyV8Facts struct {
	connectorKnown bool
	connector      string
	runID          string
	requestID      string
	sessionID      string
	turnID         string
	agentID        string
	agentName      string
	agentInstance  string
	policyID       string
	destination    string
}

func (p *GuardrailProxy) proxyV8Envelope(
	ctx context.Context,
	phase string,
) (observability.FamilyEnvelopeInput, proxyV8Facts) {
	auditEnvelope := audit.EnvelopeFromContext(ctx)
	facts := proxyV8Facts{
		connector: proxyV8StableID(firstNonEmpty(auditEnvelope.Connector, p.connectorName())),
		runID:     proxyV8StableID(auditEnvelope.RunID), requestID: proxyV8StableID(firstNonEmpty(auditEnvelope.RequestID, RequestIDFromContext(ctx))),
		sessionID: proxyV8StableID(firstNonEmpty(auditEnvelope.SessionID, SessionIDFromContext(ctx))),
		turnID:    proxyV8StableID(auditEnvelope.TurnID), agentID: proxyV8StableID(auditEnvelope.AgentID),
		agentName: proxyV8StableID(auditEnvelope.AgentName), agentInstance: proxyV8StableID(auditEnvelope.AgentInstanceID),
		policyID:    proxyV8StableID(firstNonEmpty(auditEnvelope.PolicyID, p.defaultPolicyID)),
		destination: proxyV8StableID(auditEnvelope.DestinationApp),
	}
	facts.connectorKnown = facts.connector != "" && facts.connector != "unknown"
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: facts.connector,
		Action: "chat.completions", Phase: phase,
		Correlation: observability.Correlation{
			RunID: facts.runID, RequestID: facts.requestID, SessionID: facts.sessionID,
			TurnID: facts.turnID, AgentID: facts.agentID,
			AgentInstanceID: facts.agentInstance, PolicyID: facts.policyID,
		},
		Provenance: observability.FamilyProvenanceInput{Producer: proxyV8Producer},
	}, facts
}

func inheritProxyV8AgentIdentity(
	model *observability.SpanModelChatInput,
	agent observability.SpanAgentInvokeInput,
) {
	if model == nil {
		return
	}
	model.Envelope.Correlation.AgentID = agent.Envelope.Correlation.AgentID
	model.Envelope.Correlation.AgentInstanceID = agent.Envelope.Correlation.AgentInstanceID
	model.GenAIAgentID = agent.GenAIAgentID
	model.GenAIAgentName = agent.GenAIAgentName
	if value, present := agent.DefenseClawAgentType, agent.DefenseClawAgentType != ""; present {
		model.DefenseClawAgentType = observability.Present(value)
	}
	model.DefenseClawAgentInstanceID = agent.DefenseClawAgentInstanceID
	model.DefenseClawAgentRootID = agent.DefenseClawAgentRootID
	model.DefenseClawAgentParentID = agent.DefenseClawAgentParentID
	model.DefenseClawAgentLineageProvenance = agent.DefenseClawAgentLineageProvenance
	model.DefenseClawSessionRootID = agent.DefenseClawSessionRootID
	model.DefenseClawSessionParentID = agent.DefenseClawSessionParentID
	model.DefenseClawAgentLifecycleID = agent.DefenseClawAgentLifecycleID
	model.DefenseClawAgentExecutionID = agent.DefenseClawAgentExecutionID
	model.DefenseClawAgentDepth = agent.DefenseClawAgentDepth
}

func applyProxyV8FactsToAgent(input *observability.SpanAgentInvokeInput, facts proxyV8Facts, agentType string) {
	input.DefenseClawConnectorSource = proxyV8Optional(facts.connectorKnown, facts.connector)
	input.DefenseClawRunID = proxyV8OptionalID(facts.runID)
	input.DefenseClawRequestID = proxyV8OptionalID(facts.requestID)
	input.DefenseClawTurnID = proxyV8OptionalID(facts.turnID)
	input.DefenseClawPolicyID = proxyV8OptionalID(facts.policyID)
	input.DefenseClawDestinationApp = proxyV8OptionalID(facts.destination)
	input.GenAIConversationID = proxyV8OptionalID(facts.sessionID)
	input.GenAIAgentID = proxyV8OptionalID(facts.agentID)
	input.GenAIAgentName = proxyV8OptionalID(facts.agentName)
	input.DefenseClawAgentInstanceID = proxyV8OptionalID(facts.agentInstance)
	input.DefenseClawAgentRootID = proxyV8OptionalID(facts.agentID)
	input.DefenseClawSessionRootID = proxyV8OptionalID(facts.sessionID)
	if facts.agentID != "" {
		input.DefenseClawAgentLineageProvenance = observability.Present("reported")
		input.DefenseClawAgentDepth = observability.Present[int64](0)
	}
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
	if !input.GenAIAgentName.IsPresent() && observability.IsStableToken(agentType) {
		input.GenAIAgentName = observability.Present(agentType)
	}
}

func applyProxyV8FactsToModel(input *observability.SpanModelChatInput, facts proxyV8Facts) {
	input.DefenseClawConnectorSource = proxyV8Optional(facts.connectorKnown, facts.connector)
	input.DefenseClawRunID = proxyV8OptionalID(facts.runID)
	input.DefenseClawRequestID = proxyV8OptionalID(facts.requestID)
	input.DefenseClawTurnID = proxyV8OptionalID(facts.turnID)
	input.DefenseClawPolicyID = proxyV8OptionalID(facts.policyID)
	input.DefenseClawDestinationApp = proxyV8OptionalID(facts.destination)
	input.GenAIConversationID = proxyV8OptionalID(facts.sessionID)
	input.GenAIAgentID = proxyV8OptionalID(facts.agentID)
	input.GenAIAgentName = proxyV8OptionalID(facts.agentName)
	input.DefenseClawAgentInstanceID = proxyV8OptionalID(facts.agentInstance)
	input.DefenseClawAgentRootID = proxyV8OptionalID(facts.agentID)
	input.DefenseClawSessionRootID = proxyV8OptionalID(facts.sessionID)
	if facts.agentID != "" {
		input.DefenseClawAgentLineageProvenance = observability.Present("reported")
		input.DefenseClawAgentDepth = observability.Present[int64](0)
	}
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
}

func applyProxyV8ResultToAgent(input *observability.SpanAgentInvokeInput, result proxyV8TraceResult) {
	input.Outcome = result.Outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = proxyV8Status(result)
	input.ConditionTechnicalFailure = result.TechnicalFailure
	input.ErrorType = proxyV8OptionalID(result.ErrorType)
	finishReasons := hookModelV8FinishReasons(result.FinishReasons)
	output, outputBytes, reported, outputState, structured := proxyV8OutputMessages(
		result.OutputText, result.ToolCalls, finishReasons,
	)
	input.DefenseClawTelemetryOutputReported = reported
	input.DefenseClawContentOutputState = outputState
	if structured {
		input.GenAIOutputMessages = observability.Present(output)
	}
	if reported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
	}
	if result.ResponseModel != "" {
		input.GenAIResponseModel = hookModelV8OptionalID(result.ResponseModel)
	}
	input.GenAIResponseID = hookModelV8OptionalID(result.ResponseID)
}

func applyProxyV8ResultToModel(input *observability.SpanModelChatInput, result proxyV8TraceResult) {
	input.Outcome = result.Outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = proxyV8Status(result)
	input.ConditionTechnicalFailure = result.TechnicalFailure
	input.ErrorType = proxyV8OptionalID(result.ErrorType)
	finishReasons := hookModelV8FinishReasons(result.FinishReasons)
	output, outputBytes, reported, outputState, structured := proxyV8OutputMessages(
		result.OutputText, result.ToolCalls, finishReasons,
	)
	input.DefenseClawTelemetryOutputReported = reported
	input.DefenseClawContentOutputState = outputState
	if structured {
		input.GenAIOutputMessages = observability.Present(output)
	}
	if reported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
	}
	input.GenAIResponseModel = hookModelV8OptionalID(result.ResponseModel)
	input.GenAIResponseID = hookModelV8OptionalID(result.ResponseID)
	if len(finishReasons) > 0 {
		input.GenAIResponseFinishReasons = observability.Present(finishReasons)
	}
	tokensReported := false
	if result.Usage != nil {
		if result.Usage.PromptTokens >= 0 {
			input.GenAIUsageInputTokens = observability.Present(result.Usage.PromptTokens)
			tokensReported = true
		}
		if result.Usage.CompletionTokens >= 0 {
			input.GenAIUsageOutputTokens = observability.Present(result.Usage.CompletionTokens)
			tokensReported = true
		}
	}
	input.DefenseClawTelemetryTokensReported = observability.Present(tokensReported)
	input.DefenseClawModelUpstreamMs = observability.Present(float64(result.UpstreamDuration.Microseconds()) / 1000)
	input.DefenseClawModelStreaming = observability.Present(result.Streaming)
	input.DefenseClawModelCancelled = observability.Present(result.Cancelled)
	input.DefenseClawModelToolCallCount = observability.Present(int64(result.ToolCallCount))
}

func proxyV8InputMessages(
	messages []ChatMessage,
) (observability.TelemetryStructuredGenAIInputMessages, int64, bool, string, bool) {
	capacity := len(messages)
	if capacity > proxyV8MaxStructuredItems {
		capacity = proxyV8MaxStructuredItems
	}
	items := make([]observability.TelemetryStructuredGenAIChatMessage, 0, capacity)
	var originalBytes int64
	reported := false
	representationComplete := true
	for _, message := range messages {
		rawContentReported := proxyV8JSONValueReported(message.RawContent)
		if message.Content != "" {
			originalBytes += int64(len(message.Content))
			reported = true
		} else if rawContentReported {
			originalBytes += int64(len(message.RawContent))
			reported = true
			representationComplete = false
		}
		if proxyV8JSONValueReported(message.ToolCalls) {
			originalBytes += int64(len(message.ToolCalls))
			reported = true
			representationComplete = false
		}
		if message.ToolCallID != "" {
			originalBytes += int64(len(message.ToolCallID))
			reported = true
			representationComplete = false
		}
		if proxyV8JSONValueReported(message.ExtraContent) {
			originalBytes += int64(len(message.ExtraContent))
			reported = true
			representationComplete = false
		}
		role := strings.TrimSpace(message.Role)
		if !proxyV8MessageRole(role) || message.Content == "" {
			if message.Content != "" {
				representationComplete = false
			}
			continue
		}
		if rawContentReported && strings.TrimSpace(string(message.RawContent))[0] != '"' {
			// ChatMessage flattens content-block arrays for inspection. The
			// canonical mapper cannot claim byte-preserved structured input for
			// a multimodal/provider-extension shape it did not fully represent.
			representationComplete = false
		}
		if len(items) == proxyV8MaxStructuredItems {
			representationComplete = false
			continue
		}
		item := observability.TelemetryStructuredGenAIChatMessage{
			Role: role,
			Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
				observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: message.Content}},
			}},
		}
		if message.Name != "" {
			item.Name = observability.Present(message.Name)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		if reported {
			return observability.TelemetryStructuredGenAIInputMessages{}, originalBytes, true, "failed_closed", false
		}
		return observability.TelemetryStructuredGenAIInputMessages{}, 0, false, "not_reported", false
	}
	if !representationComplete {
		return observability.TelemetryStructuredGenAIInputMessages{}, originalBytes, reported, "failed_closed", false
	}
	input := observability.TelemetryStructuredGenAIInputMessages{Items: items}
	if err := observability.ValidateTelemetryStructuredGenAIInputMessages(input); err != nil {
		return observability.TelemetryStructuredGenAIInputMessages{}, originalBytes, reported, "failed_closed", false
	}
	return input, originalBytes, reported, "preserved", true
}

func proxyV8JSONValueReported(value json.RawMessage) bool {
	switch strings.TrimSpace(string(value)) {
	case "", "null", "[]", "{}", `""`:
		return false
	default:
		return true
	}
}

func proxyV8OutputMessages(
	text string,
	toolCalls json.RawMessage,
	finishReasons []string,
) (observability.TelemetryStructuredGenAIOutputMessages, int64, bool, string, bool) {
	finishReason := hookModelV8OutputFinishReason(finishReasons)
	parts := make([]observability.TelemetryStructuredGenAIMessagePart, 0, 1)
	originalBytes := int64(len(text))
	trimmedToolCalls := strings.TrimSpace(string(toolCalls))
	toolCallsReported := trimmedToolCalls != "" && trimmedToolCalls != "null" && trimmedToolCalls != "[]"
	if toolCallsReported {
		originalBytes += int64(len(toolCalls))
	}
	reported := text != "" || toolCallsReported
	representationComplete := true
	if text != "" {
		parts = append(parts, observability.TelemetryStructuredArmGenAIMessagePartText{
			Value: observability.TelemetryStructuredGenAITextPart{Content: text},
		})
	}
	var calls []toolCallEntry
	if toolCallsReported {
		if json.Unmarshal(toolCalls, &calls) != nil || len(calls) == 0 {
			representationComplete = false
		}
		for _, call := range calls {
			if len(parts) == proxyV8MaxStructuredItems {
				representationComplete = false
				break
			}
			name := call.Function.Name
			if name == "" {
				representationComplete = false
				continue
			}
			part := observability.TelemetryStructuredGenAIToolCallRequestPart{Name: name}
			if call.ID != "" {
				part.ID = observability.Present(call.ID)
			}
			if arguments, ok := proxyV8CanonicalJSON([]byte(call.Function.Arguments)); ok {
				part.Arguments = observability.Present[observability.TelemetryStructuredGenAICanonicalJSON](arguments)
			} else if call.Function.Arguments != "" {
				representationComplete = false
			}
			parts = append(parts, observability.TelemetryStructuredArmGenAIMessagePartToolCall{Value: part})
		}
	}
	if len(parts) == 0 {
		if reported {
			return observability.TelemetryStructuredGenAIOutputMessages{}, originalBytes, true, "failed_closed", false
		}
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, false, "not_reported", false
	}
	if !representationComplete {
		return observability.TelemetryStructuredGenAIOutputMessages{}, originalBytes, reported, "failed_closed", false
	}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: finishReason,
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: parts},
	}}}
	if err := observability.ValidateTelemetryStructuredGenAIOutputMessages(output); err != nil {
		return observability.TelemetryStructuredGenAIOutputMessages{}, originalBytes, reported, "failed_closed", false
	}
	return output, originalBytes, reported, "preserved", true
}

func proxyV8CanonicalJSON(encoded []byte) (observability.TelemetryStructuredGenAICanonicalJSON, bool) {
	if len(encoded) == 0 || !json.Valid(encoded) {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return proxyV8CanonicalJSONValue(value)
}

func proxyV8CanonicalJSONValue(value any) (observability.TelemetryStructuredGenAICanonicalJSON, bool) {
	switch typed := value.(type) {
	case bool:
		return observability.TelemetryStructuredArmGenAICanonicalJSONBoolean{Value: typed}, true
	case string:
		return observability.TelemetryStructuredArmGenAICanonicalJSONString{Value: typed}, true
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return observability.TelemetryStructuredArmGenAICanonicalJSONInt64{Value: integer}, true
		}
		finite, err := typed.Float64()
		if err != nil || math.IsInf(finite, 0) || math.IsNaN(finite) {
			return nil, false
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONFiniteDouble{Value: finite}, true
	case []any:
		items := make([]observability.TelemetryStructuredGenAICanonicalJSON, 0, len(typed))
		for _, item := range typed {
			converted, ok := proxyV8CanonicalJSONValue(item)
			if !ok {
				return nil, false
			}
			items = append(items, converted)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONArray{Items: items}, true
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		entries := make([]observability.GenAICanonicalJSONEntryMemberInput, 0, len(keys))
		for _, key := range keys {
			converted, ok := proxyV8CanonicalJSONValue(typed[key])
			if !ok {
				return nil, false
			}
			entry, err := observability.NewGenAICanonicalJSONEntryMember(key, converted)
			if err != nil {
				return nil, false
			}
			entries = append(entries, entry)
		}
		return observability.TelemetryStructuredArmGenAICanonicalJSONObject{Entries: entries}, true
	default:
		// The generated canonical JSON vocabulary intentionally has no null
		// arm. Preserve the tool call without arguments rather than inventing
		// a replacement value.
		return nil, false
	}
}

func proxyV8Status(result proxyV8TraceResult) observability.TraceStatusInput {
	if result.TechnicalFailure {
		return observability.NewTraceStatusError(proxyV8OptionalID(result.ErrorType))
	}
	return observability.NewTraceStatusOK()
}

func proxyV8MessageRole(role string) bool {
	switch role {
	case "system", "developer", "user", "assistant", "tool":
		return true
	default:
		return false
	}
}

func proxyV8StableID(value string) string {
	if value == "" || strings.TrimSpace(value) != value || !observability.IsStableToken(value) {
		return ""
	}
	return value
}

func proxyV8OptionalID(value string) observability.Optional[string] {
	if value = proxyV8StableID(value); value != "" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func proxyV8OptionalText(value string) observability.Optional[string] {
	return hookModelV8OptionalText(value)
}

func proxyV8Optional(present bool, value string) observability.Optional[string] {
	if present {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}
