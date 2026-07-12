// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const judgeV8Producer = "gateway.llm_judge"

var judgeV8IdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

type judgeTraceV8Runtime interface {
	StartJudgeTrace(context.Context, observability.SpanGuardrailJudgeInput) (context.Context, *observabilityruntime.JudgeTrace, error)
	RecordGeneratedMetricBatch(context.Context, []observabilityruntime.GeneratedMetricBatchItem) ([]telemetry.V8MetricRecordResult, error)
}

type judgeTraceFailure string

const (
	judgeTraceFailureNone          judgeTraceFailure = ""
	judgeTraceFailureProvider      judgeTraceFailure = "judge_provider_error"
	judgeTraceFailureEmptyResponse judgeTraceFailure = "judge_empty_response"
	judgeTraceFailureParse         judgeTraceFailure = "judge_parse_error"
)

type judgeTraceOperation struct {
	generated *observabilityruntime.JudgeTrace
	input     observability.SpanGuardrailJudgeInput
	runtime   judgeTraceV8Runtime
	ctx       context.Context
}

func (j *LLMJudge) bindJudgeTraceV8(runtime judgeTraceV8Runtime) {
	if j == nil {
		return
	}
	j.telemetryMu.Lock()
	j.traceV8 = runtime
	j.traceV8Authoritative = true
	j.telemetryMu.Unlock()
}

func (j *LLMJudge) judgeTelemetrySnapshot() (judgeTraceV8Runtime, bool) {
	if j == nil {
		return nil, false
	}
	j.telemetryMu.RLock()
	runtime, authoritative := j.traceV8, j.traceV8Authoritative
	j.telemetryMu.RUnlock()
	return runtime, authoritative
}

func (j *LLMJudge) recordGatewayErrorV8(ctx context.Context, code gatewaylog.ErrorCode) {
	runtime, _ := j.judgeTelemetrySnapshot()
	if runtime == nil {
		return
	}
	recordGatewayErrorV8(ctx, runtime, string(gatewaylog.SubsystemGuardrail), string(code))
}

func (j *LLMJudge) startJudgeTrace(
	ctx context.Context,
	kind, direction string,
	maxTokens int,
	messages []ChatMessage,
	started time.Time,
) (context.Context, *judgeTraceOperation) {
	runtime, _ := j.judgeTelemetrySnapshot()
	input := j.judgeTraceInput(ctx, kind, direction, maxTokens, messages, started)
	operation := &judgeTraceOperation{input: input, runtime: runtime, ctx: ctx}
	if runtime == nil {
		return ctx, operation
	}
	startedContext, generated, err := runtime.StartJudgeTrace(ctx, input)
	if err != nil {
		return ctx, operation
	}
	operation.ctx = startedContext
	if generated == nil {
		return startedContext, operation
	}
	operation.generated = generated
	return startedContext, operation
}

func (j *LLMJudge) judgeTraceInput(
	ctx context.Context,
	kind string,
	direction string,
	maxTokens int,
	messages []ChatMessage,
	started time.Time,
) observability.SpanGuardrailJudgeInput {
	envelope := audit.EnvelopeFromContext(ctx)
	connector := proxyV8StableID(envelope.Connector)
	inputMessages, inputBytes, inputState, inputEvents := judgeV8InputMessages(messages, started)
	input := observability.SpanGuardrailJudgeInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway, Connector: connector, Action: "judge", Phase: "judge",
			Correlation: observability.Correlation{
				RunID: proxyV8StableID(envelope.RunID), RequestID: proxyV8StableID(envelope.RequestID),
				SessionID: proxyV8StableID(envelope.SessionID), TurnID: proxyV8StableID(envelope.TurnID),
				AgentID: proxyV8StableID(envelope.AgentID), AgentInstanceID: proxyV8StableID(envelope.AgentInstanceID),
				PolicyID: proxyV8StableID(envelope.PolicyID),
			},
			Provenance: observability.FamilyProvenanceInput{Producer: judgeV8Producer},
		},
		Outcome: observability.OutcomeFailed, Kind: "CLIENT", StartTimeUnixNano: uint64(started.UnixNano()),
		Status: observability.NewTraceStatusOK(), Events: inputEvents,
		DefenseClawJudgeKind:               kind,
		DefenseClawConnectorSource:         proxyV8Optional(connector != "", connector),
		DefenseClawRunID:                   proxyV8OptionalID(envelope.RunID),
		DefenseClawPolicyID:                proxyV8OptionalID(envelope.PolicyID),
		GenAIConversationID:                proxyV8OptionalID(envelope.SessionID),
		GenAIAgentID:                       proxyV8OptionalID(envelope.AgentID),
		GenAIAgentName:                     proxyV8OptionalID(envelope.AgentName),
		DefenseClawAgentInstanceID:         proxyV8OptionalID(envelope.AgentInstanceID),
		DefenseClawGuardrailPhase:          observability.Present("judge"),
		DefenseClawGuardrailDirection:      judgeV8Direction(direction),
		DefenseClawGuardrailCacheHit:       observability.Present(false),
		DefenseClawGuardrailAttempt:        observability.Present[int64](1),
		GenAIOperationName:                 observability.Present("chat"),
		GenAIRequestModel:                  j.model,
		DefenseClawModelAttempt:            observability.Present[int64](1),
		DefenseClawModelRetryCount:         observability.Present[int64](0),
		DefenseClawModelStreaming:          observability.Present(false),
		DefenseClawModelCancelled:          observability.Present(false),
		DefenseClawTelemetryTokensReported: observability.Present(false),
		DefenseClawTelemetryInputReported:  len(inputMessages.Items) > 0,
		DefenseClawContentInputState:       inputState,
		DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState:      "not_reported",
		ConditionConnectorKnown:            connector != "",
		ConditionOperationTerminal:         true,
	}
	providerName := strings.TrimSpace(j.providerName)
	if providerName == "" {
		providerName = judgeGenAISystem(j.model)
		if providerName == "unknown" {
			providerName = ""
		}
	}
	if providerName != "" && len(providerName) <= 4096 && utf8.ValidString(providerName) {
		input.GenAIProviderName = observability.Present(providerName)
	}
	if maxTokens >= 0 {
		input.GenAIRequestMaxTokens = observability.Present(int64(maxTokens))
	}
	if len(inputMessages.Items) > 0 {
		input.GenAIInputMessages = observability.Present(inputMessages)
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
	}
	return input
}

func (operation *judgeTraceOperation) End(
	response *ChatResponse,
	rawResponse string,
	verdict *ScanVerdict,
	failure judgeTraceFailure,
	providerErr error,
	latencyMs int64,
) error {
	if operation == nil {
		return nil
	}
	responseModel := ""
	promptTokens, completionTokens := 0, 0
	if response != nil {
		responseModel = response.Model
		if response.Usage != nil {
			promptTokens = int(response.Usage.PromptTokens)
			completionTokens = int(response.Usage.CompletionTokens)
		}
	}
	action := "error"
	if verdict != nil {
		action = verdict.Action
	}

	input := operation.input
	endedAt := time.Now().UTC()
	input.EndTimeUnixNano = uint64(endedAt.UnixNano())
	input.DefenseClawGuardrailLatencyMs = observability.Present(float64(latencyMs))
	input.DefenseClawModelUpstreamMs = observability.Present(float64(latencyMs))
	if action != "" {
		input.DefenseClawGuardrailRawAction = observability.Present(action)
		input.DefenseClawGuardrailEffectiveAction = observability.Present(action)
		if judgeV8Decision(action) {
			input.DefenseClawGuardrailDecision = observability.Present(action)
		}
	}
	if verdict != nil {
		input.DefenseClawGuardrailFindingCount = observability.Present(int64(len(verdict.Findings)))
		if normalized := observability.NormalizeSeverity(verdict.Severity); normalized.Present && normalized.Valid {
			input.DefenseClawSecuritySeverity = observability.Present(string(normalized.Severity))
		}
	}
	if len(responseModel) <= 256 && judgeV8IdentifierPattern.MatchString(responseModel) {
		input.GenAIResponseModel = observability.Present(responseModel)
	}
	if response != nil {
		if responseID := proxyV8StableID(response.ID); responseID != "" {
			input.GenAIResponseID = observability.Present(responseID)
			input.DefenseClawModelResponseID = observability.Present(responseID)
		}
		if response.Usage != nil {
			input.GenAIUsageInputTokens = observability.Present(int64(promptTokens))
			input.GenAIUsageOutputTokens = observability.Present(int64(completionTokens))
			input.DefenseClawTelemetryTokensReported = observability.Present(true)
		}
		reasons := judgeV8FinishReasons(response)
		if len(reasons) > 0 {
			input.GenAIResponseFinishReasons = observability.Present(reasons)
		}
		if output, outputBytes, state, events, reported := judgeV8OutputMessages(rawResponse, reasons, endedAt); reported {
			input.GenAIOutputMessages = observability.Present(output)
			input.DefenseClawTelemetryOutputReported = true
			input.DefenseClawContentOutputState = state
			input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
			input.Events = append(input.Events, events...)
		}
	}

	input.Outcome, input.Status, input.ErrorType, input.ConditionTechnicalFailure = judgeV8Terminal(failure, providerErr, action)
	if errors.Is(providerErr, context.Canceled) {
		input.DefenseClawModelCancelled = observability.Present(true)
	}
	if errors.Is(providerErr, context.DeadlineExceeded) {
		input.DefenseClawModelTimeoutClass = observability.Present("deadline")
	}
	if providerErr != nil {
		if reason := truncateToRuneBoundary(strings.ToValidUTF8(providerErr.Error(), "\uFFFD"), 4096); reason != "" {
			input.DefenseClawGuardrailReason = observability.Present(reason)
		}
	}
	metricErr := operation.recordMetrics(
		endedAt, action, verdict, failure, latencyMs, promptTokens, completionTokens,
	)
	if operation.generated == nil {
		return metricErr
	}
	if traceErr := operation.generated.End(input); traceErr != nil {
		return traceErr
	}
	return metricErr
}

type judgeMetricRecordBuilder func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
) (observability.Record, error)

func (operation *judgeTraceOperation) recordMetrics(
	endedAt time.Time,
	action string,
	verdict *ScanVerdict,
	failure judgeTraceFailure,
	latencyMs int64,
	promptTokens int,
	completionTokens int,
) error {
	if operation == nil || operation.runtime == nil || operation.ctx == nil {
		return nil
	}
	items := operation.metricItems(
		endedAt, action, verdict, failure, latencyMs, promptTokens, completionTokens,
	)
	if len(items) == 0 {
		return nil
	}
	metricCtx, cancel := context.WithTimeout(context.WithoutCancel(operation.ctx), time.Second)
	defer cancel()
	_, err := operation.runtime.RecordGeneratedMetricBatch(metricCtx, items)
	return err
}

func (operation *judgeTraceOperation) metricItems(
	endedAt time.Time,
	action string,
	verdict *ScanVerdict,
	failure judgeTraceFailure,
	latencyMs int64,
	promptTokens int,
	completionTokens int,
) []observabilityruntime.GeneratedMetricBatchItem {
	if operation == nil {
		return nil
	}
	kind := strings.TrimSpace(operation.input.DefenseClawJudgeKind)
	model := strings.TrimSpace(operation.input.GenAIRequestModel)
	providerName, _ := operation.input.GenAIProviderName.Get()
	severity := observability.SeverityInfo
	if verdict != nil {
		if normalized := observability.NormalizeSeverity(verdict.Severity); normalized.Present && normalized.Valid {
			severity = normalized.Severity
		}
	} else if failure != judgeTraceFailureNone {
		severity = observability.SeverityHigh
	}
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 6)
	appendMetric := func(family observability.EventName, build judgeMetricRecordBuilder) {
		items = append(items, operation.metricItem(endedAt, family, build))
	}
	appendMetric(
		observability.EventName(observability.TelemetryInstrumentDefenseClawGatewayJudgeInvocations),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGatewayJudgeInvocations(observability.MetricDefenseClawGatewayJudgeInvocationsInput{
				Envelope: envelope, Value: 1,
				DefenseClawJudgeAction:         observability.Present(action),
				DefenseClawJudgeKind:           observability.Present(kind),
				DefenseClawMetricJudgeSeverity: observability.Present(string(severity)),
			})
		},
	)
	appendMetric(
		observability.EventName(observability.TelemetryInstrumentDefenseClawGatewayJudgeLatency),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGatewayJudgeLatency(observability.MetricDefenseClawGatewayJudgeLatencyInput{
				Envelope: envelope, Value: float64(latencyMs),
				DefenseClawJudgeKind: observability.Present(kind),
			})
		},
	)
	appendMetric(
		observability.EventName(observability.TelemetryInstrumentDefenseClawGuardrailJudgeLatency),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGuardrailJudgeLatency(observability.MetricDefenseClawGuardrailJudgeLatencyInput{
				Envelope: envelope, Value: float64(latencyMs),
				GenAIRequestModel: observability.Present(model), DefenseClawJudgeKind: observability.Present(kind),
			})
		},
	)
	if failure != judgeTraceFailureNone {
		reason := judgeMetricFailureReason(failure)
		if reason != "" {
			appendMetric(
				observability.EventName(observability.TelemetryInstrumentDefenseClawGatewayJudgeErrors),
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawGatewayJudgeErrors(observability.MetricDefenseClawGatewayJudgeErrorsInput{
						Envelope: envelope, Value: 1,
						DefenseClawJudgeKind: observability.Present(kind), DefenseClawMetricJudgeReason: observability.Present(reason),
					})
				},
			)
		}
	}
	appendTokens := func(tokenType string, count int) {
		if count <= 0 {
			return
		}
		appendMetric(
			observability.EventName(observability.TelemetryInstrumentGenAIClientTokenUsage),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricGenAIClientTokenUsage(observability.MetricGenAIClientTokenUsageInput{
					Envelope: envelope, Value: float64(count),
					GenAIAgentID:        optionalJudgeMetricText(operation.input.Envelope.Correlation.AgentID),
					GenAIConversationID: optionalJudgeMetricText(operation.input.Envelope.Correlation.SessionID),
					// The judge is a DefenseClaw role, while the underlying GenAI
					// operation remains the standards-defined chat operation. Keep the
					// role in defenseclaw.judge.kind rather than inventing a GenAI enum.
					GenAIOperationName: observability.Present("chat"),
					GenAIProviderName:  optionalJudgeMetricText(providerName), GenAIRequestModel: observability.Present(model),
					GenAITokenType: observability.Present(tokenType),
				})
			},
		)
	}
	appendTokens("input", promptTokens)
	appendTokens("output", completionTokens)
	return items
}

func (operation *judgeTraceOperation) metricItem(
	endedAt time.Time,
	family observability.EventName,
	build judgeMetricRecordBuilder,
) observabilityruntime.GeneratedMetricBatchItem {
	return observabilityruntime.GeneratedMetricBatchItem{
		Family: family,
		Builder: func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
			if snapshot.Generation() > math.MaxInt64 {
				return observability.Record{}, errors.New("judge metric generation exceeds int64")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return endedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
			)
			if err != nil {
				return observability.Record{}, err
			}
			envelope := operation.input.Envelope
			envelope.ObservedAt = observability.Present(endedAt)
			envelope.Provenance = observability.FamilyProvenanceInput{
				Producer: judgeV8Producer, BinaryVersion: version.Current().BinaryVersion,
				ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			}
			if spanContext := trace.SpanContextFromContext(operation.ctx); spanContext.IsValid() {
				envelope.Correlation.TraceID = spanContext.TraceID().String()
				envelope.Correlation.SpanID = spanContext.SpanID().String()
			}
			return build(builder, envelope)
		},
	}
}

func judgeMetricFailureReason(failure judgeTraceFailure) string {
	switch failure {
	case judgeTraceFailureProvider:
		return "provider"
	case judgeTraceFailureEmptyResponse:
		return "empty_response"
	case judgeTraceFailureParse:
		return "parse"
	default:
		return ""
	}
}

func optionalJudgeMetricText(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func (operation *judgeTraceOperation) Abort() {
	if operation != nil && operation.generated != nil {
		operation.generated.Abort()
	}
}

func judgeV8Terminal(
	failure judgeTraceFailure,
	providerErr error,
	action string,
) (observability.Outcome, observability.TraceStatusInput, observability.Optional[string], bool) {
	if failure == judgeTraceFailureNone && providerErr == nil {
		if action == "block" || action == "deny" {
			return observability.OutcomeBlocked, observability.NewTraceStatusOK(), observability.Absent[string](), false
		}
		return observability.OutcomeAllowed, observability.NewTraceStatusOK(), observability.Absent[string](), false
	}
	errorType := string(failure)
	outcome := observability.OutcomeFailed
	if errors.Is(providerErr, context.Canceled) {
		errorType, outcome = "judge_cancelled", observability.OutcomeCancelled
	} else if errors.Is(providerErr, context.DeadlineExceeded) {
		errorType, outcome = "judge_timeout", observability.OutcomeTimedOut
	} else if errorType == "" {
		errorType = "judge_provider_error"
	}
	typed := observability.Present(errorType)
	return outcome, observability.NewTraceStatusError(typed), typed, true
}

func judgeV8Direction(direction string) observability.Optional[string] {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "prompt", "input":
		return observability.Present("input")
	case "completion", "output", "tool_result":
		return observability.Present("output")
	case "tool", "tool_call":
		return observability.Present("tool")
	default:
		return observability.Absent[string]()
	}
}

func judgeV8Decision(action string) bool {
	switch action {
	case "allow", "block", "deny", "review", "redact":
		return true
	default:
		return false
	}
}

func judgeV8InputMessages(
	messages []ChatMessage,
	eventTime time.Time,
) (observability.TelemetryStructuredGenAIInputMessages, int64, string, []observability.TraceEventInput) {
	items := make([]observability.TelemetryStructuredGenAIChatMessage, 0, len(messages))
	var originalBytes int64
	truncated := false
	for _, message := range messages {
		role := strings.TrimSpace(message.Role)
		if !proxyV8MessageRole(role) || message.Content == "" {
			continue
		}
		originalBytes += int64(len(message.Content))
		validContent := strings.ToValidUTF8(message.Content, "\uFFFD")
		content := truncateToRuneBoundary(validContent, 4096)
		truncated = truncated || content != message.Content
		items = append(items, observability.TelemetryStructuredGenAIChatMessage{
			Role: role,
			Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
				observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content}},
			}},
		})
	}
	state := "preserved"
	if len(items) == 0 {
		state = "not_reported"
	}
	var events []observability.TraceEventInput
	if truncated {
		state = "truncated"
		if event, err := observability.NewSpanGuardrailJudgeContentTruncatedEvent(observability.SpanGuardrailJudgeContentTruncatedEventInput{
			TimeUnixNano:      uint64(eventTime.UnixNano()),
			DefenseClawBucket: observability.Present(string(observability.BucketGuardrailEvaluation)),
		}); err == nil {
			events = append(events, event)
		}
	}
	return observability.TelemetryStructuredGenAIInputMessages{Items: items}, originalBytes, state, events
}

func judgeV8OutputMessages(
	content string,
	finishReasons []string,
	eventTime time.Time,
) (observability.TelemetryStructuredGenAIOutputMessages, int64, string, []observability.TraceEventInput, bool) {
	if content == "" {
		return observability.TelemetryStructuredGenAIOutputMessages{}, 0, "not_reported", nil, false
	}
	finishReason := observability.Absent[string]()
	if len(finishReasons) > 0 {
		finishReason = observability.Present(finishReasons[0])
	}
	originalBytes := int64(len(content))
	validContent := strings.ToValidUTF8(content, "\uFFFD")
	bounded := truncateToRuneBoundary(validContent, 4096)
	state := "preserved"
	var events []observability.TraceEventInput
	if bounded != content {
		state = "truncated"
		if event, err := observability.NewSpanGuardrailJudgeContentTruncatedEvent(observability.SpanGuardrailJudgeContentTruncatedEventInput{
			TimeUnixNano:      uint64(eventTime.UnixNano()),
			DefenseClawBucket: observability.Present(string(observability.BucketGuardrailEvaluation)),
		}); err == nil {
			events = append(events, event)
		}
	}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: finishReason,
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: bounded}},
		}},
	}}}
	return output, originalBytes, state, events, true
}

func judgeV8FinishReasons(response *ChatResponse) []string {
	if response == nil || len(response.Choices) == 0 || response.Choices[0].FinishReason == nil {
		return nil
	}
	reason := *response.Choices[0].FinishReason
	if reason == "" || strings.TrimSpace(reason) != reason || len(reason) > 4096 || !utf8.ValidString(reason) {
		return nil
	}
	return []string{reason}
}
