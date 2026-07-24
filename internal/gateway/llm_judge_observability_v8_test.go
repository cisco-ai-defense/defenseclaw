// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestLocalJudgeGeneratedSpanAllCallPaths(t *testing.T) {
	const cleanAdjudicationJSON = `{"findings":[],"overall_threat":false,"severity":"NONE"}`
	cases := []struct {
		name      string
		kind      string
		direction string
		response  string
		run       func(*LLMJudge)
	}{
		{
			name: "injection", kind: "injection", direction: "input", response: allFalseInjectionJSON,
			run: func(judge *LLMJudge) { judge.runInjectionJudge(t.Context(), strings.Repeat("i", 40)) },
		},
		{
			name: "pii", kind: "pii", direction: "output", response: allCleanPIIJSON,
			run: func(judge *LLMJudge) { judge.runPIIJudge(t.Context(), strings.Repeat("p", 40), "completion", "") },
		},
		{
			name: "exfil", kind: "exfil", direction: "input", response: allFalseExfilJSON,
			run: func(judge *LLMJudge) { judge.runExfilJudge(t.Context(), strings.Repeat("e", 40)) },
		},
		{
			name: "tool", kind: "tool_injection", direction: "tool", response: allFalseToolJSON,
			run: func(judge *LLMJudge) { judge.RunToolJudge(t.Context(), "shell", strings.Repeat("t", 40)) },
		},
		{
			name: "adjudicate injection", kind: "adjudicate_injection", direction: "input", response: cleanAdjudicationJSON,
			run: func(judge *LLMJudge) {
				judge.adjudicateCategory(t.Context(), "prompt", strings.Repeat("a", 40), []TriageSignal{{Pattern: "injection", Evidence: "matched"}}, "injection")
			},
		},
		{
			name: "adjudicate pii", kind: "adjudicate_pii", direction: "output", response: cleanAdjudicationJSON,
			run: func(judge *LLMJudge) {
				judge.adjudicateCategory(t.Context(), "completion", strings.Repeat("a", 40), []TriageSignal{{Pattern: "pii", Evidence: "matched"}}, "pii")
			},
		},
		{
			name: "adjudicate exfil", kind: "adjudicate_exfil", direction: "input", response: cleanAdjudicationJSON,
			run: func(judge *LLMJudge) {
				judge.adjudicateCategory(t.Context(), "prompt", strings.Repeat("a", 40), []TriageSignal{{Pattern: "exfil", Evidence: "matched"}}, "exfil")
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)

			finishReason := "stop"
			judge := &LLMJudge{
				cfg: &config.JudgeConfig{
					Enabled: true, Injection: true, PII: true, PIICompletion: true,
					Exfil: true, ToolInjection: true,
				},
				model: "openai/gpt-judge", providerName: "openai",
				provider: &mockLLMProvider{response: &ChatResponse{
					ID: "judge-response-001", Model: "openai/gpt-judge-actual",
					Choices: []ChatChoice{{
						Message: &ChatMessage{Role: "assistant", Content: test.response}, FinishReason: &finishReason,
					}},
					Usage: &ChatUsage{PromptTokens: 10, CompletionTokens: 5},
				}},
				rp: &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{}},
			}
			judge.bindJudgeTraceV8(runtime)
			test.run(judge)

			spans := capture.snapshot()
			if len(spans) != 1 {
				t.Fatalf("generated judge spans=%d, want 1", len(spans))
			}
			span := spans[0]
			if span.Record().EventName() != observability.EventName(observability.TelemetryFamilyGuardrailJudge) ||
				span.Name() != "chat openai/gpt-judge" {
				t.Fatalf("span family=%s name=%q", span.Record().EventName(), span.Name())
			}
			attributes := proxyCanonicalAttributes(t, span.Record())
			if attributes["gen_ai.provider.name"] != "openai" ||
				attributes["gen_ai.request.model"] != "openai/gpt-judge" ||
				attributes["gen_ai.response.model"] != "openai/gpt-judge-actual" ||
				attributes["defenseclaw.judge.kind"] != test.kind ||
				attributes["defenseclaw.guardrail.direction"] != test.direction ||
				attributes["defenseclaw.guardrail.cache_hit"] != false ||
				attributes["defenseclaw.guardrail.attempt"] == nil ||
				attributes["defenseclaw.model.attempt"] == nil ||
				attributes["defenseclaw.guardrail.raw_action"] != "allow" ||
				attributes["defenseclaw.guardrail.effective_action"] != "allow" ||
				attributes["defenseclaw.security.severity"] != "INFO" ||
				attributes["defenseclaw.outcome"] != "allowed" {
				t.Fatalf("generated judge attributes=%v", attributes)
			}
			if attributes["gen_ai.input.messages"] == nil || attributes["gen_ai.output.messages"] == nil {
				t.Fatalf("generated content fields missing: %v", attributes)
			}
			classes := span.Record().FieldClasses()
			inputContent, outputContent := false, false
			for path, class := range classes {
				switch {
				case strings.HasPrefix(path, "/attributes/gen_ai.input.messages/"):
					inputContent = true
					if class != observability.FieldClassContent {
						t.Fatalf("judge input content class %s=%s", path, class)
					}
				case strings.HasPrefix(path, "/attributes/gen_ai.output.messages/"):
					outputContent = true
					if class != observability.FieldClassContent {
						t.Fatalf("judge output content class %s=%s", path, class)
					}
				}
			}
			if !inputContent || !outputContent {
				t.Fatalf("judge content field classes=%v", classes)
			}
			metrics := capture.metricSnapshot()
			assertJudgeMetricCounts(t, metrics, map[string]int{
				observability.TelemetryInstrumentDefenseClawGatewayJudgeInvocations: 1,
				observability.TelemetryInstrumentDefenseClawGatewayJudgeLatency:     1,
				observability.TelemetryInstrumentDefenseClawGuardrailJudgeLatency:   1,
				observability.TelemetryInstrumentGenAIClientTokenUsage:              2,
			})
			assertJudgeMetricDimensions(t, metrics, test.kind)
		})
	}
}

func TestLocalJudgeGeneratedSpanFailureFacts(t *testing.T) {
	tests := []struct {
		name       string
		provider   *mockLLMProvider
		errorType  string
		wantReason string
	}{
		{
			name: "provider error", provider: &mockLLMProvider{err: errors.New("source provider detail")},
			errorType: "judge_provider_error", wantReason: "source provider detail",
		},
		{
			name: "empty response", provider: &mockLLMProvider{response: &ChatResponse{}},
			errorType: "judge_empty_response",
		},
		{
			name: "parse error", provider: &mockLLMProvider{response: &ChatResponse{
				Model: "openai/gpt-judge", Choices: []ChatChoice{{
					Message: &ChatMessage{Role: "assistant", Content: "not-json"}, FinishReason: strPtr("stop"),
				}},
			}},
			errorType: "judge_parse_error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			judge := &LLMJudge{
				cfg:   &config.JudgeConfig{Enabled: true, Injection: true},
				model: "openai/gpt-judge", providerName: "openai",
				provider: test.provider, rp: &guardrail.RulePack{},
			}
			// Generated tracing must complete through the bound v8 runtime.
			judge.bindJudgeTraceV8(runtime)
			judge.runInjectionJudge(t.Context(), strings.Repeat("i", 40))

			spans := capture.snapshot()
			if len(spans) != 1 {
				t.Fatalf("generated failure spans=%d, want 1", len(spans))
			}
			span := spans[0]
			attributes := proxyCanonicalAttributes(t, span.Record())
			if span.Record().Outcome() != observability.OutcomeFailed ||
				span.StatusCode().String() != "Error" || span.StatusDescription() != test.errorType ||
				attributes["error.type"] != test.errorType {
				t.Fatalf("failure outcome/status/attributes=%s/%s/%q %v", span.Record().Outcome(), span.StatusCode(), span.StatusDescription(), attributes)
			}
			if test.wantReason == "" {
				if _, present := attributes["defenseclaw.guardrail.reason"]; present {
					t.Fatalf("failure synthesized reason=%v", attributes["defenseclaw.guardrail.reason"])
				}
			} else if attributes["defenseclaw.guardrail.reason"] != test.wantReason ||
				span.Record().FieldClasses()["/attributes/defenseclaw.guardrail.reason"] != observability.FieldClassReason {
				t.Fatalf("source error reason/class=%v/%v", attributes["defenseclaw.guardrail.reason"], span.Record().FieldClasses())
			}
			for _, key := range []string{"defenseclaw.evaluation.id", "defenseclaw.finding.id", "defenseclaw.enforcement.id"} {
				if _, fabricated := attributes[key]; fabricated {
					t.Fatalf("failure fabricated %s", key)
				}
			}
			wantMetricCounts := map[string]int{
				observability.TelemetryInstrumentDefenseClawGatewayJudgeErrors:      1,
				observability.TelemetryInstrumentDefenseClawGatewayJudgeInvocations: 1,
				observability.TelemetryInstrumentDefenseClawGatewayJudgeLatency:     1,
				observability.TelemetryInstrumentDefenseClawGuardrailJudgeLatency:   1,
			}
			if test.errorType == "judge_parse_error" {
				wantMetricCounts[observability.TelemetryInstrumentDefenseClawGatewayErrors] = 1
			}
			assertJudgeMetricCounts(t, capture.metricSnapshot(), wantMetricCounts)
		})
	}
}

func TestLocalJudgeAdjudicationGeneratedFailureFacts(t *testing.T) {
	tests := []struct {
		name      string
		provider  *mockLLMProvider
		errorType string
	}{
		{
			name: "provider error", provider: &mockLLMProvider{err: errors.New("source provider detail")},
			errorType: "judge_provider_error",
		},
		{
			name: "empty response", provider: &mockLLMProvider{response: &ChatResponse{}},
			errorType: "judge_empty_response",
		},
		{
			name: "parse error", provider: &mockLLMProvider{response: &ChatResponse{
				Model: "openai/gpt-judge", Choices: []ChatChoice{{
					Message: &ChatMessage{Role: "assistant", Content: "not-json"}, FinishReason: strPtr("stop"),
				}}, Usage: &ChatUsage{PromptTokens: 10, CompletionTokens: 5},
			}},
			errorType: "judge_parse_error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			judge := &LLMJudge{
				cfg: &config.JudgeConfig{Enabled: true}, model: "openai/gpt-judge", providerName: "openai",
				provider: test.provider,
				rp:       &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{}},
			}
			judge.bindJudgeTraceV8(runtime)
			verdict := judge.adjudicateCategory(t.Context(), "prompt", strings.Repeat("a", 40), []TriageSignal{{Pattern: "injection", Evidence: "matched"}}, "injection")
			if !verdict.JudgeFailed {
				t.Fatalf("adjudication failure verdict=%+v", verdict)
			}

			spans := capture.snapshot()
			if len(spans) != 1 {
				t.Fatalf("generated adjudication failure spans=%d, want 1", len(spans))
			}
			attributes := proxyCanonicalAttributes(t, spans[0].Record())
			if attributes["defenseclaw.judge.kind"] != "adjudicate_injection" ||
				attributes["error.type"] != test.errorType ||
				spans[0].StatusCode().String() != "Error" || spans[0].StatusDescription() != test.errorType {
				t.Fatalf("adjudication failure attributes/status=%v/%s/%q", attributes, spans[0].StatusCode(), spans[0].StatusDescription())
			}
			metrics := judgeMetricCounts(capture.metricSnapshot())
			if metrics[observability.TelemetryInstrumentDefenseClawGatewayJudgeErrors] != 1 {
				t.Fatalf("generated adjudication error metrics=%v", metrics)
			}
		})
	}
}

func TestJudgeV8TerminalMapsDenyToBlocked(t *testing.T) {
	outcome, status, errorType, technicalFailure := judgeV8Terminal(judgeTraceFailureNone, nil, "deny")
	_, hasErrorType := errorType.Get()
	if outcome != observability.OutcomeBlocked || status.Code() != observability.TraceStatusOK || hasErrorType || technicalFailure {
		t.Fatalf("deny terminal facts=%s/%+v/%+v/%v", outcome, status, errorType, technicalFailure)
	}
}

type judgeTraceContextRuntime struct {
	started context.Context
	err     error
}

func (runtime judgeTraceContextRuntime) StartJudgeTrace(
	context.Context,
	observability.SpanGuardrailJudgeInput,
) (context.Context, *observabilityruntime.JudgeTrace, error) {
	return runtime.started, nil, runtime.err
}

func (runtime judgeTraceContextRuntime) RecordGeneratedMetricBatch(
	context.Context,
	[]observabilityruntime.GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	return nil, runtime.err
}

func TestJudgeGeneratedSamplingDropPropagatesStartedContext(t *testing.T) {
	type contextKey struct{}
	original := context.WithValue(t.Context(), contextKey{}, "original")
	started := context.WithValue(original, contextKey{}, "sampled-drop")
	judge := &LLMJudge{model: "openai/gpt-judge", providerName: "openai"}
	judge.bindJudgeTraceV8(judgeTraceContextRuntime{started: started})

	propagated, operation := judge.startJudgeTrace(
		original, "injection", "prompt", 1024,
		[]ChatMessage{{Role: "user", Content: "content"}}, time.Now().UTC(),
	)
	if propagated.Value(contextKey{}) != "sampled-drop" || operation == nil || operation.runtime == nil || operation.generated != nil {
		t.Fatalf("sampled-drop context/operation=%v/%+v", propagated.Value(contextKey{}), operation)
	}

	judge.bindJudgeTraceV8(judgeTraceContextRuntime{started: started, err: errors.New("start failed")})
	failed, _ := judge.startJudgeTrace(
		original, "injection", "prompt", 1024,
		[]ChatMessage{{Role: "user", Content: "content"}}, time.Now().UTC(),
	)
	if failed.Value(contextKey{}) != "original" {
		t.Fatalf("failed start propagated runtime context=%v", failed.Value(contextKey{}))
	}
}

func TestJudgeGeneratedMetricsSurviveTraceSampling(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	finishReason := "stop"
	judge := &LLMJudge{
		cfg: &config.JudgeConfig{Enabled: true, Injection: true}, model: "openai/gpt-judge", providerName: "openai",
		provider: &mockLLMProvider{response: &ChatResponse{
			Model: "openai/gpt-judge", Choices: []ChatChoice{{
				Message: &ChatMessage{Role: "assistant", Content: allFalseInjectionJSON}, FinishReason: &finishReason,
			}}, Usage: &ChatUsage{PromptTokens: 10, CompletionTokens: 5},
		}},
		rp: &guardrail.RulePack{},
	}
	judge.bindJudgeTraceV8(runtime)
	judge.runInjectionJudge(t.Context(), strings.Repeat("i", 40))

	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("always-off judge emitted %d spans", len(spans))
	}
	assertJudgeMetricCounts(t, capture.metricSnapshot(), map[string]int{
		observability.TelemetryInstrumentDefenseClawGatewayJudgeInvocations: 1,
		observability.TelemetryInstrumentDefenseClawGatewayJudgeLatency:     1,
		observability.TelemetryInstrumentDefenseClawGuardrailJudgeLatency:   1,
		observability.TelemetryInstrumentGenAIClientTokenUsage:              2,
	})
}

func TestJudgeGeneratedContentUsesBoundedGeneratedFields(t *testing.T) {
	inputContent := strings.Repeat("界", 2000)
	messages, originalBytes, state, events := judgeV8InputMessages([]ChatMessage{{
		Role: "user", Content: inputContent,
	}}, time.Now().UTC())
	if originalBytes != int64(len(inputContent)) || state != "truncated" || len(events) != 1 || len(messages.Items) != 1 {
		t.Fatalf("input bytes/state/events/items=%d/%s/%d/%d", originalBytes, state, len(events), len(messages.Items))
	}
	part, ok := messages.Items[0].Parts.Items[0].(observability.TelemetryStructuredArmGenAIMessagePartText)
	if !ok || len(part.Value.Content) > 4096 || !utf8.ValidString(part.Value.Content) {
		t.Fatalf("bounded input part=%T bytes=%d", messages.Items[0].Parts.Items[0], len(part.Value.Content))
	}

	outputContent := strings.Repeat("界", 2000)
	output, outputBytes, outputState, outputEvents, reported := judgeV8OutputMessages(
		outputContent, []string{"stop"}, time.Now().UTC(),
	)
	if !reported || outputBytes != int64(len(outputContent)) || outputState != "truncated" ||
		len(outputEvents) != 1 || len(output.Items) != 1 {
		t.Fatalf("output reported/bytes/state/events/items=%t/%d/%s/%d/%d", reported, outputBytes, outputState, len(outputEvents), len(output.Items))
	}
	outputPart, ok := output.Items[0].Parts.Items[0].(observability.TelemetryStructuredArmGenAIMessagePartText)
	if !ok || len(outputPart.Value.Content) > 4096 || !utf8.ValidString(outputPart.Value.Content) {
		t.Fatalf("bounded output part=%T bytes=%d", output.Items[0].Parts.Items[0], len(outputPart.Value.Content))
	}
}

func TestJudgeGeneratedRuntimeBindingFollowsSidecarLifecycle(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	hookJudge := &LLMJudge{
		cfg: &config.JudgeConfig{Enabled: true, Injection: true}, model: "openai/gpt-judge", providerName: "openai",
		provider: &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: allFalseInjectionJSON}}}}},
		rp:       &guardrail.RulePack{},
	}
	proxyJudge := &LLMJudge{}
	proxy := &GuardrailProxy{inspector: &GuardrailInspector{judge: proxyJudge}}
	sidecar := &Sidecar{judge: hookJudge}
	sidecar.setGuardrailProxy(proxy)
	if err := sidecar.BindObservabilityRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	hookRuntime, hookAuthority := hookJudge.judgeTelemetrySnapshot()
	proxyRuntime, proxyAuthority := proxyJudge.judgeTelemetrySnapshot()
	if hookRuntime != runtime || proxyRuntime != runtime || !hookAuthority || !proxyAuthority {
		t.Fatalf("bound judge runtimes/authority hook=%T/%t proxy=%T/%t want %T/true", hookRuntime, hookAuthority, proxyRuntime, proxyAuthority, runtime)
	}

	// Mirror the shutdown detach critical section: no newly-started judge call
	// may retain the retiring runtime, while already-started handles keep their
	// own graph lease until End/Abort.
	sidecar.observabilityV8Mu.Lock()
	sidecar.observabilityV8ConsumersDetached = true
	sidecar.bindObservabilityV8ConsumersLocked()
	sidecar.observabilityV8Mu.Unlock()
	hookRuntime, hookAuthority = hookJudge.judgeTelemetrySnapshot()
	proxyRuntime, proxyAuthority = proxyJudge.judgeTelemetrySnapshot()
	if hookRuntime != nil || proxyRuntime != nil || !hookAuthority || !proxyAuthority {
		t.Fatalf("detached judge runtimes/authority hook=%T/%t proxy=%T/%t", hookRuntime, hookAuthority, proxyRuntime, proxyAuthority)
	}

	hookJudge.runInjectionJudge(t.Context(), strings.Repeat("i", 40))
	if got := len(capture.snapshot()); got != 0 {
		t.Fatalf("detached v8 authority emitted %d generated judge spans", got)
	}
}

func assertJudgeMetricCounts(t *testing.T, metrics []telemetry.V8ProjectedMetric, want map[string]int) {
	t.Helper()
	got := judgeMetricCounts(metrics)
	if len(got) != len(want) {
		t.Fatalf("generated judge metric families=%v want=%v", got, want)
	}
	for name, count := range want {
		if got[name] != count {
			t.Fatalf("generated judge metric %s count=%d want=%d (all=%v)", name, got[name], count, got)
		}
	}
}

func judgeMetricCounts(metrics []telemetry.V8ProjectedMetric) map[string]int {
	counts := make(map[string]int)
	for _, metric := range metrics {
		counts[metric.Descriptor().Name]++
	}
	return counts
}

func assertJudgeMetricDimensions(t *testing.T, metrics []telemetry.V8ProjectedMetric, kind string) {
	t.Helper()
	tokenTypes := make(map[string]bool)
	for _, metric := range metrics {
		attributes := metric.Attributes()
		switch metric.Descriptor().Name {
		case observability.TelemetryInstrumentDefenseClawGatewayJudgeInvocations:
			if attributes["defenseclaw.judge.action"] != "allow" ||
				attributes["defenseclaw.judge.kind"] != kind ||
				attributes["defenseclaw.metric.judge.severity"] != "INFO" {
				t.Fatalf("generated judge invocation dimensions=%v", attributes)
			}
		case observability.TelemetryInstrumentGenAIClientTokenUsage:
			if attributes["gen_ai.operation.name"] != "chat" ||
				attributes["gen_ai.provider.name"] != "openai" ||
				attributes["gen_ai.request.model"] != "openai/gpt-judge" {
				t.Fatalf("generated judge token dimensions=%v", attributes)
			}
			tokenType, ok := attributes["gen_ai.token.type"].(string)
			if !ok {
				t.Fatalf("generated judge token type=%#v", attributes["gen_ai.token.type"])
			}
			tokenTypes[tokenType] = true
		}
	}
	if !tokenTypes["input"] || !tokenTypes["output"] || len(tokenTypes) != 2 {
		t.Fatalf("generated judge token types=%v", tokenTypes)
	}
}
