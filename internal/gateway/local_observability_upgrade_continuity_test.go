// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// TestLocalObservabilityUpgradeContinuityProducerScenario is the producer half
// of scripts/test-observability-v8-upgrade-continuity.sh. The release harness
// runs it once before and once after the manifest-declared v8 hard-cut upgrade against the same
// live Prometheus/Loki/Tempo/Grafana volumes. It deliberately uses the real
// generated gateway producers and production OTLP destination; no backend or
// exporter is replaced by a test double.
//
// Required environment:
//
//	DC_TEST_LOCAL_OBSERVABILITY_OTLP_ENDPOINT=http://127.0.0.1:4318
//	DC_TEST_UPGRADE_CONTINUITY_PHASE=pre|post
//	DC_TEST_UPGRADE_CONTINUITY_STAMP=<numeric run stamp>
func TestLocalObservabilityUpgradeContinuityProducerScenario(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("DC_TEST_LOCAL_OBSERVABILITY_OTLP_ENDPOINT"))
	phase := strings.TrimSpace(os.Getenv("DC_TEST_UPGRADE_CONTINUITY_PHASE"))
	stamp := strings.TrimSpace(os.Getenv("DC_TEST_UPGRADE_CONTINUITY_STAMP"))
	if endpoint == "" && phase == "" && stamp == "" {
		t.Skip("set the upgrade-continuity environment to run the live release scenario")
	}
	if endpoint == "" || (phase != "pre" && phase != "post") || !numericContinuityStamp(stamp) {
		t.Fatal("upgrade continuity requires an OTLP endpoint, phase pre|post, and a numeric stamp")
	}

	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	rawConfig := hookModelV8BootstrapRaw(fixture.dataDir, endpoint, []string{"logs", "traces", "metrics"})
	rawConfig = []byte(strings.Replace(
		string(rawConfig), "name: hook-otlp", "name: local-observability", 1,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, rawConfig)
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil ||
		api.observabilityV8LifecycleRuntime() == nil {
		t.Fatalf("bootstrap continuity runtime bound=%t emitter=%T lifecycle=%T error=%v",
			bound, api.observabilityV8RuntimeEmitter(), api.observabilityV8LifecycleRuntime(), err)
	}

	emitUpgradeContinuityExecution(t, api, phase, stamp)

	// The local profile uses a one-second metric interval and a short OTLP
	// batch delay. Fixture cleanup performs the final runtime drain.
	time.Sleep(2500 * time.Millisecond)
}

func TestLocalObservabilityUpgradeContinuityProducerContract(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces", "metrics"})
	const stamp = "1700000000000000000"
	emitUpgradeContinuityExecution(t, api, "pre", stamp)

	var spans []*tracepb.Span
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		spans = hookModelV8CapturedSpans(traceRequests)
		logs := hookModelV8CapturedLogs(capture.logSnapshot())
		if len(spans) >= 8 && len(logs) >= 20 && len(metricRequests) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	modelByTurn := make(map[string]*tracepb.Span)
	for _, span := range spans {
		if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") != observability.TelemetryFamilyModelChat {
			continue
		}
		turnID := gatewayProtoAttribute(span.Attributes, "defenseclaw.turn.id")
		modelByTurn[turnID] = span
	}
	if len(modelByTurn) != 2 {
		t.Fatalf("continuity model turns=%d, want two", len(modelByTurn))
	}
	reported := modelByTurn[continuityTurnID(stamp, 1)]
	unreported := modelByTurn[continuityTurnID(stamp, 2)]
	if reported == nil || unreported == nil {
		t.Fatalf("reported/unreported model span missing")
	}
	reportedAttributes := hookModelV8MetricAttributes(reported.GetAttributes())
	unreportedAttributes := hookModelV8MetricAttributes(unreported.GetAttributes())
	if reportedAttributes["defenseclaw.telemetry.tokens.reported"] != "true" ||
		unreportedAttributes["defenseclaw.telemetry.tokens.reported"] != "false" {
		t.Fatalf(
			"reported/unreported model usage presence drifted: reported=%q unreported=%q",
			reportedAttributes["defenseclaw.telemetry.tokens.reported"],
			unreportedAttributes["defenseclaw.telemetry.tokens.reported"],
		)
	}

	var decision map[string]any
	for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
		attributes := hookModelV8MetricAttributes(record.Attributes)
		if attributes["defenseclaw.event.name"] != observability.TelemetryEventHookDecision {
			continue
		}
		var wire struct {
			Body map[string]any `json:"body"`
		}
		if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
			t.Fatal(err)
		}
		decision = wire.Body
	}
	if decision == nil || decision["defenseclaw.guardrail.raw_action"] != "block" ||
		decision["defenseclaw.guardrail.effective_action"] != "allow" ||
		decision["defenseclaw.guardrail.mode"] != "observe" ||
		decision["defenseclaw.guardrail.would_block"] != true ||
		decision["defenseclaw.guardrail.enforced"] != false {
		t.Fatalf("continuity raw/effective decision=%v", decision)
	}
}

func numericContinuityStamp(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func emitUpgradeContinuityExecution(t *testing.T, api *APIServer, phase, stamp string) {
	t.Helper()
	base := time.Now().UTC().Add(-12 * time.Second)
	marker := "upgrade-continuity-" + phase + "-" + stamp

	root := continuityMeta(stamp, "root", "", 0, "session_start", "session", "", 1)
	root.SessionSource = "startup"
	direct := continuityMeta(stamp, "direct", "root", 1, "subagent_start", "planning", "session", 1)
	nested := continuityMeta(stamp, "nested", "direct", 2, "subagent_start", "planning", "session", 1)

	runtime := api.observabilityV8LifecycleRuntime()
	rootInput := goldenAgentTraceInput(t, root, base, base.Add(11*time.Second))
	directInput := goldenAgentTraceInput(t, direct, base.Add(time.Second), base.Add(10*time.Second))
	nestedInput := goldenAgentTraceInput(t, nested, base.Add(2*time.Second), base.Add(9*time.Second))
	rootCtx, rootSpan, err := runtime.StartAgentTrace(t.Context(), rootInput)
	if err != nil || rootSpan == nil {
		t.Fatalf("start continuity root span=%v error=%v", rootSpan, err)
	}
	defer rootSpan.Abort()
	directSpan, err := rootSpan.StartAgent(directInput)
	if err != nil || directSpan == nil {
		t.Fatalf("start continuity direct span=%v error=%v", directSpan, err)
	}
	defer directSpan.Abort()
	nestedSpan, err := directSpan.StartAgent(nestedInput)
	if err != nil || nestedSpan == nil {
		t.Fatalf("start continuity nested span=%v error=%v", nestedSpan, err)
	}
	defer nestedSpan.Abort()

	emitGoldenLifecycle(t, api, rootCtx, root)
	emitGoldenLifecycle(t, api, directSpan.Context(), direct)
	emitGoldenLifecycle(t, api, nestedSpan.Context(), nested)

	turnOneStart := continuityMeta(stamp, "direct", "root", 1, "turn_start", "planning", "session", 2)
	turnOneStart.TurnID = continuityTurnID(stamp, 1)
	emitGoldenLifecycle(t, api, directSpan.Context(), turnOneStart)
	modelOneMeta := turnOneStart
	modelOneMeta.LifecycleEvent = "turn_end"
	modelOneMeta.LifecycleState = "completed"
	modelOneMeta.LifecycleOutcome = "completed"
	modelOneMeta.PreviousPhase = "planning"
	modelOneMeta.Phase = "model"
	modelOneMeta.Sequence = 3
	modelOneMeta.PromptID = "continuity-prompt-1-" + stamp
	modelOneMeta.ResponseID = "continuity-response-1-" + stamp
	modelOne := continuityModelObservation(
		modelOneMeta,
		marker+" turn-one prompt",
		marker+" turn-one response",
		21,
		13,
		base.Add(2500*time.Millisecond),
		base.Add(4*time.Second),
	)
	modelOneInput := inheritHookModelV8Agent(hookModelV8ModelInput(modelOne), directInput)
	modelOneSpan, err := directSpan.StartModel(modelOneInput)
	if err != nil || modelOneSpan == nil {
		t.Fatalf("start continuity reported model span=%v error=%v", modelOneSpan, err)
	}
	defer modelOneSpan.Abort()
	api.emitHookModelRequestLogV8(modelOneSpan.Context(), modelOneMeta, modelOne.prompt)
	api.emitHookModelResponseLogV8(modelOneSpan.Context(), modelOneMeta, modelOne.response, []string{"stop"})
	api.recordHookModelMetricsV8(modelOneSpan.Context(), modelOneSpan, modelOne)
	turnOneEnd := modelOneMeta
	turnOneEnd.PreviousPhase = "model"
	turnOneEnd.Phase = "completed"
	emitGoldenLifecycle(t, api, modelOneSpan.Context(), turnOneEnd)
	if err := modelOneSpan.End(modelOneInput); err != nil {
		t.Fatal(err)
	}

	compactStart := continuityMeta(stamp, "root", "", 0, "compact_start", "maintenance", "model", 4)
	compactStart.TurnID = continuityTurnID(stamp, 1)
	emitGoldenLifecycle(t, api, rootSpan.Context(), compactStart)
	compactEnd := compactStart
	compactEnd.LifecycleEvent = "compact_end"
	compactEnd.LifecycleState = "active"
	compactEnd.LifecycleOutcome = "completed"
	compactEnd.Sequence = 5
	emitGoldenLifecycle(t, api, rootSpan.Context(), compactEnd)
	resume := continuityMeta(stamp, "root", "", 0, "session_start", "planning", "maintenance", 6)
	resume.SessionSource = "resume"
	resume.SessionResumed = true
	resume.TurnID = continuityTurnID(stamp, 2)
	emitGoldenLifecycle(t, api, rootSpan.Context(), resume)

	turnTwoStart := continuityMeta(stamp, "direct", "root", 1, "turn_start", "planning", "maintenance", 4)
	turnTwoStart.TurnID = continuityTurnID(stamp, 2)
	emitGoldenLifecycle(t, api, directSpan.Context(), turnTwoStart)
	modelTwoMeta := turnTwoStart
	modelTwoMeta.LifecycleEvent = "turn_end"
	modelTwoMeta.LifecycleState = "completed"
	modelTwoMeta.LifecycleOutcome = "completed"
	modelTwoMeta.PreviousPhase = "planning"
	modelTwoMeta.Phase = "model"
	modelTwoMeta.Sequence = 5
	modelTwoMeta.PromptID = "continuity-prompt-2-" + stamp
	modelTwoMeta.ResponseID = "continuity-response-2-" + stamp
	modelTwo := continuityModelObservation(
		modelTwoMeta,
		marker+" turn-two prompt",
		marker+" turn-two response with usage deliberately unreported",
		0,
		0,
		base.Add(5500*time.Millisecond),
		base.Add(7*time.Second),
	)
	modelTwoInput := inheritHookModelV8Agent(hookModelV8ModelInput(modelTwo), directInput)
	modelTwoSpan, err := directSpan.StartModel(modelTwoInput)
	if err != nil || modelTwoSpan == nil {
		t.Fatalf("start continuity unreported model span=%v error=%v", modelTwoSpan, err)
	}
	defer modelTwoSpan.Abort()
	api.emitHookModelRequestLogV8(modelTwoSpan.Context(), modelTwoMeta, modelTwo.prompt)
	api.emitHookModelResponseLogV8(modelTwoSpan.Context(), modelTwoMeta, modelTwo.response, []string{"stop"})
	api.recordHookModelMetricsV8(modelTwoSpan.Context(), modelTwoSpan, modelTwo)
	turnTwoEnd := modelTwoMeta
	turnTwoEnd.PreviousPhase = "model"
	turnTwoEnd.Phase = "completed"
	emitGoldenLifecycle(t, api, modelTwoSpan.Context(), turnTwoEnd)
	if err := modelTwoSpan.End(modelTwoInput); err != nil {
		t.Fatal(err)
	}

	toolMeta := continuityMeta(stamp, "nested", "direct", 2, "tool_end", "tool", "model", 2)
	toolMeta.TurnID = continuityTurnID(stamp, 2)
	toolMeta.ToolName = "shell"
	toolMeta.ToolID = "continuity-tool-" + stamp
	arguments := fmt.Sprintf(`{"command":"printf","marker":%q}`, marker)
	result := fmt.Sprintf(`{"stdout":%q}`, marker)
	exitCode := 0
	toolObservation := goldenToolObservation(
		toolMeta,
		arguments,
		result,
		&exitCode,
		base.Add(7*time.Second),
		base.Add(8*time.Second),
	)
	toolInput := generatedToolV8Input(toolObservation)
	toolSpan, err := nestedSpan.StartTool(toolInput)
	if err != nil || toolSpan == nil {
		t.Fatalf("start continuity tool span=%v error=%v", toolSpan, err)
	}
	defer toolSpan.Abort()
	api.emitHookToolLogV8(toolSpan.Context(), toolMeta, "call", toolMeta.ToolName, arguments, "", nil)
	api.emitHookToolLogV8(toolSpan.Context(), toolMeta, "result", toolMeta.ToolName, arguments, result, &exitCode)
	recordGeneratedToolMetricsV8(toolSpan.Context(), toolSpan, toolObservation)
	emitGoldenLifecycle(t, api, toolSpan.Context(), toolMeta)

	approvalRouter := &EventRouter{defaultPolicyID: "continuity-policy-" + stamp}
	approvalRouter.bindObservabilityV8Capabilities(api.observabilityV8RuntimeEmitter(), runtime)
	approval := eventRouterApprovalObservation{
		id:        "continuity-approval-" + stamp,
		sessionID: nested.SessionID, runID: nested.RunID,
		agentID: nested.AgentID, agentName: nested.AgentName,
		policyID:    "continuity-policy-" + stamp,
		commandName: "printf", command: "printf " + marker,
		argv: []string{"printf", marker}, result: "approved", actorType: "automatic",
		startedAt: base.Add(7600 * time.Millisecond), finishedAt: base.Add(7900 * time.Millisecond),
	}
	if got := approvalRouter.emitApprovalRequestedV8(toolSpan.Context(), approval); got != eventRouterApprovalEmitted {
		t.Fatalf("emit continuity approval request=%d", got)
	}
	if got := approvalRouter.emitApprovalResolutionV8(toolSpan.Context(), approval); got != eventRouterApprovalEmitted {
		t.Fatalf("emit continuity approval resolution=%d", got)
	}

	decisionCtx := audit.ContextWithEnvelope(toolSpan.Context(), audit.CorrelationEnvelope{
		RunID: nested.RunID, RequestID: nested.RequestID, SessionID: nested.SessionID,
		TurnID: continuityTurnID(stamp, 2), AgentID: nested.AgentID,
		PolicyID: "continuity-policy-" + stamp, ToolID: toolMeta.ToolID,
	})
	api.emitHookDecisionObservabilityV8(
		decisionCtx,
		agentHookRequest{
			ConnectorName: "codex", HookEventName: "PreToolUse",
			SessionID: nested.SessionID, TurnID: continuityTurnID(stamp, 2),
			AgentID: nested.AgentID, AgentName: nested.AgentName, AgentType: nested.AgentType,
			ToolName: toolMeta.ToolName,
			Payload: map[string]any{
				"model": "gpt-5", "root_agent_id": root.AgentID,
				"parent_agent_id": direct.AgentID, "root_session_id": root.SessionID,
				"parent_session_id": direct.SessionID, "tool_call_id": toolMeta.ToolID,
				"run_id": nested.RunID, "request_id": nested.RequestID,
				"execution_id": nested.ExecutionID, "lifecycle_id": nested.LifecycleID,
			},
		},
		agentHookResponse{
			Action: "allow", RawAction: "block", Severity: "HIGH", Mode: "observe",
			WouldBlock: true, Reason: "would block", SourceReason: marker + " policy decision",
			EvaluationID: "continuity-evaluation-" + stamp,
			RuleIDs:      []string{"continuity-rule"},
		},
		HookAuditEnvelope{ElapsedMs: 17, StepIdx: 6, Enforced: false},
		false,
	)

	// This terminal operation is emitted before the session-end/Stop event.
	// Loki chronology must retain that order after the upgrade.
	operationComplete := continuityMeta(stamp, "root", "", 0, "event", "completed", "responding", 9)
	operationComplete.LifecycleState = "completed"
	operationComplete.LifecycleOutcome = "completed"
	operationComplete.OperationID = "continuity-prestop-operation-" + stamp
	operationComplete.TurnID = continuityTurnID(stamp, 2)
	emitGoldenLifecycle(t, api, rootSpan.Context(), operationComplete)

	if err := toolSpan.End(toolInput); err != nil {
		t.Fatal(err)
	}

	nestedStop := continuityMeta(stamp, "nested", "direct", 2, "subagent_stop", "completed", "tool", 3)
	directStop := continuityMeta(stamp, "direct", "root", 1, "subagent_stop", "completed", "model", 6)
	rootStop := continuityMeta(stamp, "root", "", 0, "session_end", "completed", "completed", 10)
	rootStop.SessionSource = "resume"
	rootStop.SessionResumed = true
	emitGoldenLifecycle(t, api, nestedSpan.Context(), nestedStop)
	if err := nestedSpan.End(nestedInput); err != nil {
		t.Fatal(err)
	}
	emitGoldenLifecycle(t, api, directSpan.Context(), directStop)
	if err := directSpan.End(directInput); err != nil {
		t.Fatal(err)
	}
	emitGoldenLifecycle(t, api, rootSpan.Context(), rootStop)
	if err := rootSpan.End(rootInput); err != nil {
		t.Fatal(err)
	}
}

func continuityMeta(
	stamp, role, parent string,
	depth int,
	event, phase, previousPhase string,
	sequence int64,
) llmEventMeta {
	meta := goldenLifecycleMeta(stamp, role, parent, depth, event, phase, previousPhase)
	meta.Sequence = sequence
	meta.TurnID = continuityTurnID(stamp, 1)
	return meta
}

func continuityTurnID(stamp string, turn int) string {
	return fmt.Sprintf("continuity-turn-%d-%s", turn, stamp)
}

func continuityModelObservation(
	meta llmEventMeta,
	prompt, response string,
	promptTokens, completionTokens int64,
	startedAt, finishedAt time.Time,
) hookModelV8Observation {
	return hookModelV8Observation{
		meta: meta, prompt: prompt, response: response,
		usage: hookLLMSpanUsage{
			model: meta.Model, promptTokens: promptTokens, completionTokens: completionTokens,
		},
		provider: meta.Provider, reportedModel: meta.Model, model: meta.Model, responseModel: meta.Model,
		agentName: meta.AgentName, agentType: meta.AgentType,
		agentID: meta.AgentID, sessionID: meta.SessionID,
		startedAt: startedAt, finishedAt: finishedAt,
		finishReasons: []string{"stop"}, promptOriginalBytes: int64(len(prompt)),
	}
}
