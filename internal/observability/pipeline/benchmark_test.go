// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

var benchmarkProjectedSpanCount int

func BenchmarkRichSpanCreationAndProjection(b *testing.B) {
	for _, destinations := range []int{1, 2, 4} {
		b.Run(fmt.Sprintf("destinations_%d", destinations), func(b *testing.B) {
			plan := benchmarkTracePlan(b, destinations)
			evaluator, err := router.New(plan)
			if err != nil {
				b.Fatal(err)
			}
			engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x54}, 32))
			if err != nil {
				b.Fatal(err)
			}
			projection, err := NewTraceProjectionPipeline(plan, evaluator, engine)
			if err != nil {
				b.Fatal(err)
			}
			fixture := newBenchmarkRichTraceFixture(b, plan)
			records := fixture.build(b)
			assertBenchmarkRichTraceSemantics(b, projection, records, destinations)

			b.ReportAllocs()
			b.ResetTimer()
			projected := 0
			for range b.N {
				records = fixture.build(b)
				for _, record := range records {
					outcome, err := projection.Process(record)
					if err != nil {
						b.Fatal(err)
					}
					projected += len(outcome.OptionalWork())
				}
			}
			b.StopTimer()
			if want := b.N * len(records) * destinations; projected != want {
				b.Fatalf("projected spans=%d want=%d", projected, want)
			}
			b.ReportMetric(float64(len(records)), "spans/op")
			b.ReportMetric(float64(destinations), "destinations/op")
			benchmarkProjectedSpanCount = projected
		})
	}
}

type benchmarkRichTraceFixture struct {
	plan    *config.ObservabilityV8Plan
	builder *observability.FamilyBuilder
	input   observability.TelemetryStructuredGenAIInputMessages
	output  observability.TelemetryStructuredGenAIOutputMessages
}

func newBenchmarkRichTraceFixture(
	b *testing.B,
	plan *config.ObservabilityV8Plan,
) benchmarkRichTraceFixture {
	b.Helper()
	var ids atomic.Uint64
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_800_000_020, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("benchmark-span-%d", ids.Add(1)), nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	input := observability.TelemetryStructuredGenAIInputMessages{
		Items: []observability.TelemetryStructuredGenAIChatMessage{{
			Role: "user",
			Parts: observability.TelemetryStructuredGenAIMessageParts{
				Items: []observability.TelemetryStructuredGenAIMessagePart{
					observability.TelemetryStructuredArmGenAIMessagePartText{
						Value: observability.TelemetryStructuredGenAITextPart{Content: "Review the repository and summarize findings."},
					},
				},
			},
		}},
	}
	output := observability.TelemetryStructuredGenAIOutputMessages{
		Items: []observability.TelemetryStructuredGenAIOutputMessage{{
			Role: "assistant", FinishReason: observability.Present("stop"),
			Parts: observability.TelemetryStructuredGenAIMessageParts{
				Items: []observability.TelemetryStructuredGenAIMessagePart{
					observability.TelemetryStructuredArmGenAIMessagePartText{
						Value: observability.TelemetryStructuredGenAITextPart{Content: "Review completed with one guarded tool call."},
					},
				},
			},
		}},
	}
	return benchmarkRichTraceFixture{plan: plan, builder: builder, input: input, output: output}
}

func (fixture benchmarkRichTraceFixture) build(b *testing.B) []observability.Record {
	const (
		traceID = "89abcdef0123456789abcdef01234567"
		base    = uint64(1_800_000_020_000_000_000)
	)
	envelope := func(spanID string) observability.FamilyEnvelopeInput {
		return observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				RunID: "run-benchmark", SessionID: "session-benchmark", TurnID: "turn-benchmark",
				TraceID: traceID, SpanID: spanID, AgentID: "agent-root",
				AgentInstanceID: "agent-instance-root", ToolInvocationID: "tool-call-benchmark",
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "benchmark", BinaryVersion: "8.0.0",
				ConfigGeneration: 1, ConfigDigest: fixture.plan.Digest(),
			},
		}
	}
	resource := observability.TraceResourceInput{SchemaURL: "https://opentelemetry.io/schemas/1.42.0"}
	startEnd := func(index uint64) (uint64, uint64) {
		start := base + index*1_000_000
		return start, start + 500_000
	}

	start, end := startEnd(1)
	agent, err := fixture.builder.BuildSpanAgentInvoke(observability.SpanAgentInvokeInput{
		Envelope: envelope("0000000000000001"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark",
		DefenseClawAgentType:          "root", GenAIConversationID: observability.Present("conversation-benchmark"),
		GenAIAgentID: observability.Present("agent-root"), GenAIAgentName: observability.Present("root-agent"),
		DefenseClawAgentRootID: observability.Present("agent-root"), DefenseClawAgentLineageProvenance: observability.Present("reported"),
		DefenseClawSessionRootID: observability.Present("session-benchmark"), DefenseClawAgentLifecycleID: observability.Present("lifecycle-root"),
		DefenseClawAgentExecutionID: observability.Present("execution-root"), DefenseClawAgentDepth: observability.Present[int64](0),
		DefenseClawAgentLifecycleEvent: observability.Present("session_start"), DefenseClawAgentLifecycleState: observability.Present("active"),
		DefenseClawAgentPhase: observability.Present("planning"), DefenseClawAgentPhaseCode: observability.Present[int64](2),
		DefenseClawAgentSequence: observability.Present[int64](1), GenAIProviderName: observability.Present("defenseclaw"),
		GenAIOperationName: observability.Present("invoke_agent"), GenAIInputMessages: observability.Present(fixture.input),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		GenAIOutputMessages: observability.Present(fixture.output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", DefenseClawAgentReportedCostPresent: false,
		ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}

	start, end = startEnd(2)
	workflow, err := fixture.builder.BuildSpanWorkflowRun(observability.SpanWorkflowRunInput{
		Envelope: envelope("0000000000000002"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000001"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark", DefenseClawWorkflowName: "review-turn",
		GenAIConversationID: observability.Present("conversation-benchmark"), GenAIAgentID: observability.Present("agent-root"),
		DefenseClawAgentType: observability.Present("root"), DefenseClawAgentRootID: observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"), GenAIInputMessages: observability.Present(fixture.input),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		GenAIOutputMessages: observability.Present(fixture.output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", DefenseClawAgentReportedCostPresent: false,
		ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}

	start, end = startEnd(3)
	model, err := fixture.builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: envelope("0000000000000003"), Outcome: observability.OutcomeCompleted,
		Kind: "CLIENT", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000002"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark", GenAIConversationID: observability.Present("conversation-benchmark"),
		GenAIAgentID: observability.Present("agent-root"), DefenseClawAgentRootID: observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"), GenAIInputMessages: observability.Present(fixture.input),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		GenAIOutputMessages: observability.Present(fixture.output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", GenAIOperationName: observability.Present("chat"),
		GenAIProviderName: observability.Present("openai"), GenAIRequestModel: "gpt-benchmark",
		GenAIResponseModel: observability.Present("gpt-benchmark"), GenAIUsageInputTokens: observability.Present[int64](64),
		GenAIUsageOutputTokens: observability.Present[int64](24), DefenseClawTelemetryTokensReported: observability.Present(true),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}

	start, end = startEnd(4)
	tool, err := fixture.builder.BuildSpanToolExecute(observability.SpanToolExecuteInput{
		Envelope: envelope("0000000000000004"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000002"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark", GenAIConversationID: observability.Present("conversation-benchmark"),
		GenAIAgentID: observability.Present("agent-root"), DefenseClawAgentRootID: observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"), GenAIInputMessages: observability.Present(fixture.input),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		GenAIOutputMessages: observability.Present(fixture.output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", GenAIOperationName: observability.Present("execute_tool"),
		GenAIToolName: "repository_search", GenAIToolCallID: observability.Present("tool-call-benchmark"),
		GenAIToolCallArguments:  observability.Present(observability.TelemetryStructuredGenAIToolCallArguments{}),
		GenAIToolCallResult:     observability.Present(observability.TelemetryStructuredGenAIToolCallResult{}),
		DefenseClawToolProvider: observability.Present("builtin"), DefenseClawToolStatus: observability.Present("completed"),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}

	start, end = startEnd(5)
	retrieval, err := fixture.builder.BuildSpanRetrievalSearch(observability.SpanRetrievalSearchInput{
		Envelope: envelope("0000000000000005"), Outcome: observability.OutcomeCompleted,
		Kind: "CLIENT", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000004"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark", GenAIConversationID: observability.Present("conversation-benchmark"),
		GenAIAgentID: observability.Present("agent-root"), DefenseClawAgentRootID: observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"), GenAIInputMessages: observability.Present(fixture.input),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		GenAIOutputMessages: observability.Present(fixture.output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", DBOperationName: observability.Present("search"),
		DBCollectionName: observability.Present("repository"), DefenseClawRetrievalSourceID: "code-index",
		DefenseClawRetrievalSourceType: observability.Present("vector"), DefenseClawRetrievalResultCount: observability.Present[int64](8),
		DefenseClawRetrievalTopK: observability.Present[int64](10), ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}

	start, end = startEnd(6)
	guardrail, err := fixture.builder.BuildSpanGuardrailApply(observability.SpanGuardrailApplyInput{
		Envelope: envelope("0000000000000006"), Outcome: observability.OutcomeBlocked,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000004"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-benchmark", ResourceDeploymentEnvironmentName: "benchmark",
		ResourceDefenseClawInstanceID: "instance-benchmark", DefenseClawConnectorSource: observability.Present("codex"),
		DefenseClawRunID: observability.Present("run-benchmark"), DefenseClawRequestID: observability.Present("request-benchmark"),
		DefenseClawTurnID: observability.Present("turn-benchmark"), GenAIConversationID: observability.Present("conversation-benchmark"),
		GenAIAgentID: observability.Present("agent-root"), DefenseClawAgentRootID: observability.Present("agent-root"),
		DefenseClawEvaluationID: observability.Present("evaluation-benchmark"), DefenseClawFindingID: observability.Present("finding-benchmark"),
		DefenseClawPolicyID: observability.Present("policy-benchmark"), DefenseClawEnforcementID: observability.Present("enforcement-benchmark"),
		DefenseClawGuardrailName: "command-inspection", DefenseClawGuardrailStage: observability.Present("tool"),
		DefenseClawGuardrailPhase: observability.Present("finalize"), DefenseClawGuardrailDirection: observability.Present("tool"),
		DefenseClawGuardrailTargetType: "tool_call", DefenseClawGuardrailLatencyMs: observability.Present(4.5),
		DefenseClawGuardrailConfidence: observability.Present(0.98), DefenseClawGuardrailRuleIds: observability.Present([]string{"CG-EXEC-001"}),
		DefenseClawGuardrailFindingCount: observability.Present[int64](1), DefenseClawGuardrailDecision: observability.Present("block"),
		DefenseClawGuardrailRawAction: observability.Present("block"), DefenseClawGuardrailEffectiveAction: observability.Present("block"),
		DefenseClawGuardrailMode: observability.Present("enforce"), DefenseClawGuardrailWouldBlock: observability.Present(false),
		DefenseClawGuardrailEnforced: observability.Present(true), DefenseClawSecuritySeverity: observability.Present("HIGH"),
		DefenseClawGuardrailReason:          observability.Present("matched command execution policy"),
		DefenseClawGuardrailEvidenceSummary: observability.Present("one dangerous command matched the active rule set"),
		DefenseClawGuardrailTargetRef:       observability.Present("tool-call-benchmark"), ConditionConnectorKnown: true,
		ConditionOperationTerminal: true,
	})
	if err != nil {
		b.Fatal(err)
	}
	return []observability.Record{agent, model, tool, retrieval, workflow, guardrail}
}

func benchmarkTracePlan(b *testing.B, destinationCount int) *config.ObservabilityV8Plan {
	b.Helper()
	yes := true
	retentionDays := 90
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{RetentionDays: &retentionDays},
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Traces: &yes},
		},
	}
	for index := 1; index <= destinationCount; index++ {
		source.Destinations = append(source.Destinations, config.ObservabilityV8DestinationSource{
			Name: fmt.Sprintf("trace-%d", index), Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: fmt.Sprintf("https://collector-%d.example.test", index),
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		})
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		b.Fatal(err)
	}
	return plan
}

func assertBenchmarkRichTraceSemantics(
	b *testing.B,
	projection *TraceProjectionPipeline,
	records []observability.Record,
	destinationCount int,
) {
	b.Helper()
	wantFamilies := []observability.EventName{
		observability.EventName(observability.TelemetryFamilyAgentInvoke),
		observability.EventName(observability.TelemetryFamilyModelChat),
		observability.EventName(observability.TelemetryFamilyToolExecute),
		observability.EventName(observability.TelemetryFamilyRetrievalSearch),
		observability.EventName(observability.TelemetryFamilyWorkflowRun),
		observability.EventName(observability.TelemetryFamilyGuardrailApply),
	}
	if len(records) != len(wantFamilies) {
		b.Fatalf("rich spans=%d want=%d", len(records), len(wantFamilies))
	}
	for index, record := range records {
		if record.Signal() != observability.SignalTraces || record.EventName() != wantFamilies[index] {
			b.Fatalf("rich span %d identity=%s/%s want=traces/%s",
				index, record.Signal(), record.EventName(), wantFamilies[index])
		}
		outcome, err := projection.Process(record)
		if err != nil {
			b.Fatal(err)
		}
		if outcome.Admission() != router.AdmissionOrdinary || len(outcome.OptionalFailures()) != 0 ||
			len(outcome.OptionalWork()) != destinationCount {
			b.Fatalf("rich span %s projection admission=%s work=%d failures=%d",
				record.EventName(), outcome.Admission(), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
		}
	}
}
