// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// TestLocalObservabilityGoldenProducerScenario is an opt-in release smoke test.
// It uses the real generated gateway producers and unified runtime, while the
// configured OTLP endpoint is expected to be the running local-observability
// collector. Static dashboard checks cannot prove that native lifecycle logs,
// phase metrics, and W3C topology are actually queryable; this scenario can.
//
// Run with:
//
//	DEFENSECLAW_LOCAL_OBSERVABILITY_OTLP_ENDPOINT=http://127.0.0.1:4318 \
//	  go test ./internal/gateway -run TestLocalObservabilityGoldenProducerScenario -count=1
func TestGoldenLifecycleMetaStartsEachAgentSequenceAtOne(t *testing.T) {
	t.Parallel()

	stamp := "1783400000000000000"
	for _, tc := range []struct {
		role   string
		parent string
		depth  int
	}{
		{role: "root", depth: 0},
		{role: "direct", parent: "root", depth: 1},
		{role: "nested", parent: "direct", depth: 2},
		{role: "leaf", parent: "nested", depth: 3},
	} {
		meta := goldenLifecycleMeta(
			stamp, tc.role, tc.parent, tc.depth, "subagent_start", "planning", "session",
		)
		if meta.Sequence != 1 {
			t.Errorf("%s initial sequence=%d, want 1", tc.role, meta.Sequence)
		}
		if meta.AgentDepth != tc.depth {
			t.Errorf("%s depth=%d, want %d", tc.role, meta.AgentDepth, tc.depth)
		}
		wantParent := ""
		if tc.parent != "" {
			wantParent = "golden-agent-" + tc.parent + "-" + stamp
		}
		if meta.ParentAgentID != wantParent {
			t.Errorf("%s parent=%q, want %q", tc.role, meta.ParentAgentID, wantParent)
		}
	}
}

func TestLocalObservabilityGoldenProducerScenario(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("DEFENSECLAW_LOCAL_OBSERVABILITY_OTLP_ENDPOINT"))
	if endpoint == "" {
		t.Skip("set DEFENSECLAW_LOCAL_OBSERVABILITY_OTLP_ENDPOINT to run the live golden scenario")
	}

	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	rawConfig := hookModelV8BootstrapRaw(fixture.dataDir, endpoint, []string{"logs", "traces", "metrics"})
	rawConfig = []byte(strings.Replace(
		string(rawConfig), "name: hook-otlp", "name: local-observability", 1,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, rawConfig,
	)
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil ||
		api.observabilityV8LifecycleRuntime() == nil {
		t.Fatalf("bootstrap live golden runtime bound=%t emitter=%T lifecycle=%T error=%v",
			bound, api.observabilityV8RuntimeEmitter(), api.observabilityV8LifecycleRuntime(), err)
	}

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	root := goldenLifecycleMeta(stamp, "root", "", 0, "session_start", "session", "")
	rootTurn := root
	rootTurn.LifecycleEvent = "turn_start"
	rootTurn.PreviousPhase = "session"
	rootTurn.Phase = "planning"
	rootTurn.PromptID = "golden-initial-prompt-" + stamp
	rootTurn.Sequence = 2
	rootModel := rootTurn
	rootModel.Phase = "model"
	rootModel.Provider = "openai"
	rootModel.Model = "gpt-5"
	rootModel.ResponseID = "golden-initial-response-" + stamp
	rootToolStart := rootTurn
	rootToolStart.LifecycleEvent = "tool_start"
	rootToolStart.LifecycleOutcome = "attempted"
	rootToolStart.PreviousPhase = "planning"
	rootToolStart.Phase = "tool"
	rootToolStart.ToolName = "read_file"
	rootToolStart.ToolID = "golden-tool-root-" + stamp
	rootToolStart.Sequence = 3
	rootToolEnd := rootToolStart
	rootToolEnd.LifecycleEvent = "tool_end"
	rootToolEnd.LifecycleOutcome = "completed"
	rootToolEnd.PreviousPhase = "tool"
	rootToolEnd.Phase = "planning"
	rootToolEnd.Sequence = 4
	rootTurnEnd := rootTurn
	rootTurnEnd.LifecycleEvent = "turn_end"
	rootTurnEnd.LifecycleState = "completed"
	rootTurnEnd.LifecycleOutcome = "completed"
	rootTurnEnd.PreviousPhase = "planning"
	rootTurnEnd.Phase = "responding"
	rootTurnEnd.Sequence = 5
	direct := goldenLifecycleMeta(stamp, "direct", "root", 1, "subagent_start", "planning", "session")
	directTurn := direct
	directTurn.LifecycleEvent = "turn_start"
	directTurn.Sequence = 2
	nested := goldenLifecycleMeta(stamp, "nested", "direct", 2, "subagent_start", "planning", "session")
	nestedUpdate := nested
	nestedUpdate.LifecycleEvent = "event"
	nestedUpdate.LifecycleState = "observed"
	nestedUpdate.LifecycleOutcome = ""
	nestedUpdate.PreviousPhase = "planning"
	nestedUpdate.Phase = "waiting"
	nestedUpdate.OperationID = "golden-update-" + stamp
	nestedUpdate.Sequence = 2
	leaf := goldenLifecycleMeta(stamp, "leaf", "nested", 3, "subagent_start", "planning", "session")
	model := directTurn
	model.LifecycleEvent = "turn_end"
	model.LifecycleState = "completed"
	model.LifecycleOutcome = "completed"
	model.PreviousPhase = "planning"
	model.Phase = "model"
	model.PromptID = "golden-prompt-" + stamp
	model.ResponseID = "golden-response-" + stamp
	model.Sequence = 3
	model.Provider = "openai"
	model.Model = "gpt-5"
	toolStart := leaf
	toolStart.LifecycleEvent = "tool_start"
	toolStart.LifecycleState = "active"
	toolStart.LifecycleOutcome = "attempted"
	toolStart.PreviousPhase = "planning"
	toolStart.Phase = "tool"
	toolStart.ToolName = "shell"
	toolStart.ToolID = "golden-tool-" + stamp
	toolStart.Sequence = 2
	toolEnd := toolStart
	toolEnd.LifecycleEvent = "tool_end"
	toolEnd.LifecycleOutcome = "completed"
	toolEnd.PreviousPhase = "tool"
	toolEnd.Sequence = 5
	leafStop := leaf
	leafStop.LifecycleEvent = "subagent_stop"
	leafStop.LifecycleState = "completed"
	leafStop.LifecycleOutcome = "completed"
	leafStop.PreviousPhase = "tool"
	leafStop.Phase = "completed"
	leafStop.Sequence = 6
	nestedStop := nestedUpdate
	nestedStop.LifecycleEvent = "subagent_stop"
	nestedStop.LifecycleState = "completed"
	nestedStop.LifecycleOutcome = "completed"
	nestedStop.PreviousPhase = "waiting"
	nestedStop.Phase = "completed"
	nestedStop.Sequence = 3
	directStop := model
	directStop.LifecycleEvent = "subagent_stop"
	directStop.PreviousPhase = "model"
	directStop.Phase = "completed"
	directStop.Sequence = 4
	rootStop := rootTurn
	rootStop.LifecycleEvent = "session_end"
	rootStop.LifecycleState = "completed"
	rootStop.LifecycleOutcome = "completed"
	rootStop.PreviousPhase = "responding"
	rootStop.Phase = "completed"
	rootStop.Sequence = 6
	arguments := `{"command":"printf","marker":"local-observability-golden"}`
	result := `{"stdout":"local-observability-golden"}`
	rootArguments := `{"path":"README.md","marker":"local-observability-golden-root"}`
	rootResult := `{"status":"read","marker":"local-observability-golden-root"}`
	exitCode := 0

	// Build one real W3C graph through the generated runtime: root agent,
	// direct subagent, nested subagent, depth-three leaf, model child, and tool
	// child. This is the arbitrary-depth topology that Tempo and Agent360 must
	// retain without relying on role-specific IDs.
	base := time.Now().UTC().Add(-500 * time.Millisecond)
	rootFinishedAt := base.Add(3 * time.Second)
	directFinishedAt := base.Add(2800 * time.Millisecond)
	nestedFinishedAt := base.Add(2600 * time.Millisecond)
	leafFinishedAt := base.Add(2400 * time.Millisecond)
	rootModelStartedAt := base.Add(100 * time.Millisecond)
	rootModelFinishedAt := base.Add(600 * time.Millisecond)
	rootToolStartedAt := base.Add(200 * time.Millisecond)
	rootToolFinishedAt := base.Add(1200 * time.Millisecond)
	directModelStartedAt := base.Add(300 * time.Millisecond)
	directModelFinishedAt := base.Add(1400 * time.Millisecond)
	leafToolStartedAt := base.Add(400 * time.Millisecond)
	leafToolFinishedAt := base.Add(2200 * time.Millisecond)
	rootInput := goldenAgentTraceInput(t, root, base, rootFinishedAt)
	directInput := goldenAgentTraceInput(t, direct, base.Add(50*time.Millisecond), directFinishedAt)
	nestedInput := goldenAgentTraceInput(t, nested, base.Add(100*time.Millisecond), nestedFinishedAt)
	leafInput := goldenAgentTraceInput(t, leaf, base.Add(150*time.Millisecond), leafFinishedAt)
	runtime := api.observabilityV8LifecycleRuntime()
	_, rootSpan, err := runtime.StartAgentTrace(t.Context(), rootInput)
	if err != nil || rootSpan == nil {
		t.Fatalf("start golden root span=%v error=%v", rootSpan, err)
	}
	defer rootSpan.Abort()
	directSpan, err := rootSpan.StartAgent(directInput)
	if err != nil || directSpan == nil {
		t.Fatalf("start golden direct span=%v error=%v", directSpan, err)
	}
	defer directSpan.Abort()
	nestedSpan, err := directSpan.StartAgent(nestedInput)
	if err != nil || nestedSpan == nil {
		t.Fatalf("start golden nested span=%v error=%v", nestedSpan, err)
	}
	defer nestedSpan.Abort()
	leafSpan, err := nestedSpan.StartAgent(leafInput)
	if err != nil || leafSpan == nil {
		t.Fatalf("start golden leaf span=%v error=%v", leafSpan, err)
	}
	defer leafSpan.Abort()

	rootModelObservation := goldenModelObservation(
		rootModel, rootModelStartedAt, rootModelFinishedAt, stamp,
	)
	rootModelObservation.prompt = "local-observability golden initial prompt " + stamp
	rootModelInput := inheritHookModelV8Agent(hookModelV8ModelInput(rootModelObservation), rootInput)
	rootModelSpan, err := rootSpan.StartModel(rootModelInput)
	if err != nil || rootModelSpan == nil {
		t.Fatalf("start golden root model span=%v error=%v", rootModelSpan, err)
	}
	defer rootModelSpan.Abort()

	rootToolObservation := goldenToolObservation(
		rootToolEnd,
		rootArguments,
		rootResult,
		&exitCode,
		rootToolStartedAt,
		rootToolFinishedAt,
	)
	rootToolInput := generatedToolV8Input(rootToolObservation)
	rootToolSpan, err := rootSpan.StartTool(rootToolInput)
	if err != nil || rootToolSpan == nil {
		t.Fatalf("start golden root tool span=%v error=%v", rootToolSpan, err)
	}
	defer rootToolSpan.Abort()

	modelObservation := goldenModelObservation(model, directModelStartedAt, directModelFinishedAt, stamp)
	modelInput := inheritHookModelV8Agent(hookModelV8ModelInput(modelObservation), directInput)
	modelSpan, err := directSpan.StartModel(modelInput)
	if err != nil || modelSpan == nil {
		t.Fatalf("start golden model span=%v error=%v", modelSpan, err)
	}
	defer modelSpan.Abort()

	toolObservation := goldenToolObservation(
		toolEnd,
		arguments,
		result,
		&exitCode,
		leafToolStartedAt,
		leafToolFinishedAt,
	)
	toolInput := generatedToolV8Input(toolObservation)
	toolSpan, err := leafSpan.StartTool(toolInput)
	if err != nil || toolSpan == nil {
		t.Fatalf("start golden tool span=%v error=%v", toolSpan, err)
	}
	defer toolSpan.Abort()

	// Emit the root turn and its initial prompt before delegation. The source
	// timestamps and per-agent sequences make the causal order independently
	// provable in Loki instead of merely implied by the trace topology.
	emitGoldenLifecycle(t, api, rootSpan.Context(), root)
	emitGoldenLifecycle(t, api, rootSpan.Context(), rootTurn)
	promptDecisionRequest := agentHookRequest{
		ConnectorName: "codex", HookEventName: "UserPromptSubmit",
		SessionID: root.SessionID, TurnID: root.TurnID,
		AgentID: root.AgentID, AgentName: root.AgentName, AgentType: root.AgentType,
		Content: rootModelObservation.prompt,
	}
	promptDecisionResponse := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
		Reason: "golden prompt accepted", SourceReason: "local-observability golden prompt accepted " + stamp,
	}
	promptDecisionEnvelope := HookAuditEnvelope{Result: "ok", ElapsedMs: 1, StepIdx: 1}
	promptDecisionContext := audit.ContextWithEnvelope(rootSpan.Context(), audit.CorrelationEnvelope{
		RunID: root.RunID, RequestID: root.RequestID, SessionID: root.SessionID,
		TurnID: root.TurnID, AgentID: root.AgentID, PolicyID: "golden-policy-" + stamp,
	})
	// The golden lifecycle uses explicit readable IDs, so pass its already-
	// normalized metadata to the same generated decision log and metric
	// producers. Re-normalizing the synthetic request would replace those IDs
	// with hash-derived connector defaults and make the fixture internally
	// inconsistent even though a real hook session retains one identity.
	api.emitHookDecisionLogV8(
		promptDecisionContext, promptDecisionRequest, promptDecisionResponse,
		promptDecisionEnvelope, false, rootTurn, root.Source,
	)
	api.recordHookDecisionMetricsV8(
		promptDecisionContext, promptDecisionRequest, promptDecisionResponse,
		promptDecisionEnvelope, false, rootTurn, root.Source,
	)
	api.emitHookModelRequestLogV8(rootModelSpan.Context(), rootModel, rootModelObservation.prompt)
	api.emitHookModelResponseLogV8(
		rootModelSpan.Context(), rootModel, rootModelObservation.response, []string{"stop"},
	)
	api.recordHookModelMetricsV8(rootModelSpan.Context(), rootModelSpan, rootModelObservation)
	emitGoldenLifecycle(t, api, rootToolSpan.Context(), rootToolStart)
	time.Sleep(time.Millisecond)
	api.emitHookToolLogV8(
		rootToolSpan.Context(), rootToolStart, "call", rootToolStart.ToolName, rootArguments, "", nil,
	)
	time.Sleep(time.Millisecond)
	api.emitHookToolLogV8(
		rootToolSpan.Context(), rootToolEnd, "result", rootToolEnd.ToolName, rootArguments, rootResult, &exitCode,
	)
	time.Sleep(time.Millisecond)
	emitGoldenLifecycle(t, api, rootToolSpan.Context(), rootToolEnd)
	recordGeneratedToolMetricsV8(rootToolSpan.Context(), rootToolSpan, rootToolObservation)
	emitGoldenLifecycle(t, api, directSpan.Context(), direct)
	emitGoldenLifecycle(t, api, directSpan.Context(), directTurn)
	emitGoldenLifecycle(t, api, nestedSpan.Context(), nested)
	emitGoldenLifecycle(t, api, nestedSpan.Context(), nestedUpdate)
	emitGoldenLifecycle(t, api, leafSpan.Context(), leaf)
	api.emitHookModelRequestLogV8(modelSpan.Context(), model, modelObservation.prompt)
	api.emitHookModelResponseLogV8(modelSpan.Context(), model, modelObservation.response, []string{"stop"})
	emitGoldenLifecycle(t, api, modelSpan.Context(), model)
	api.recordHookModelMetricsV8(modelSpan.Context(), modelSpan, modelObservation)
	emitGoldenLifecycle(t, api, toolSpan.Context(), toolStart)
	time.Sleep(time.Millisecond)
	api.emitHookToolLogV8(
		toolSpan.Context(), toolStart, "call", toolStart.ToolName, arguments, "", nil,
	)
	time.Sleep(time.Millisecond)

	// Keep the canonical approval log/span path inside the leaf tool trace.
	// The live checker requires both durable request/resolution records and the
	// generated span.approval.resolve child so dashboard regressions cannot hide
	// behind aggregate approval counters.
	approvalRouter := &EventRouter{defaultPolicyID: "golden-policy-" + stamp}
	approvalRouter.bindObservabilityV8Capabilities(
		api.observabilityV8RuntimeEmitter(),
		api.observabilityV8LifecycleRuntime(),
	)
	approvalStartedAt := time.Now().UTC()
	if approvalStartedAt.Before(leafToolStartedAt) || approvalStartedAt.After(leafToolFinishedAt) {
		t.Fatalf(
			"golden approval start %s falls outside tool span [%s, %s]",
			approvalStartedAt, leafToolStartedAt, leafToolFinishedAt,
		)
	}
	approval := eventRouterApprovalObservation{
		id: "golden-approval-" + stamp, connector: leaf.Source,
		sessionID: leaf.SessionID, rootSessionID: leaf.RootSessionID,
		parentSessionID: leaf.ParentSessionID, runID: leaf.RunID,
		requestID: leaf.RequestID, turnID: leaf.TurnID, operationID: leaf.OperationID,
		agentID: leaf.AgentID, agentName: leaf.AgentName, agentType: leaf.AgentType,
		rootAgentID: leaf.RootAgentID, parentAgentID: leaf.ParentAgentID,
		lineageProvenance: leaf.LineageProvenance,
		lifecycleID:       leaf.LifecycleID, executionID: leaf.ExecutionID,
		phase: "approval", depth: int64(leaf.AgentDepth), sequence: 3,
		policyID:    "golden-policy-" + stamp,
		commandName: "printf", command: "printf local-observability-golden-approval",
		argv:   []string{"printf", "local-observability-golden-approval"},
		result: "approved", actorType: "automatic",
		startedAt: approvalStartedAt, finishedAt: approvalStartedAt,
	}
	if got := approvalRouter.emitApprovalRequestedV8(toolSpan.Context(), approval); got != eventRouterApprovalEmitted {
		t.Fatalf("emit golden approval request=%d", got)
	}
	time.Sleep(time.Millisecond)
	approval.sequence = 4
	approval.finishedAt = time.Now().UTC()
	if approval.finishedAt.After(leafToolFinishedAt) {
		t.Fatalf(
			"golden approval finish %s falls after tool span %s",
			approval.finishedAt, leafToolFinishedAt,
		)
	}
	if got := approvalRouter.emitApprovalResolutionV8(toolSpan.Context(), approval); got != eventRouterApprovalEmitted {
		t.Fatalf("emit golden approval resolution=%d", got)
	}
	time.Sleep(time.Millisecond)
	api.emitHookToolLogV8(
		toolSpan.Context(), toolEnd, "result", toolEnd.ToolName, arguments, result, &exitCode,
	)
	time.Sleep(time.Millisecond)
	emitGoldenLifecycle(t, api, toolSpan.Context(), toolEnd)
	recordGeneratedToolMetricsV8(toolSpan.Context(), toolSpan, toolObservation)

	waitForGoldenSpanEnd(rootModelFinishedAt)
	if err := rootModelSpan.End(rootModelInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(rootToolFinishedAt)
	if err := rootToolSpan.End(rootToolInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(directModelFinishedAt)
	if err := modelSpan.End(modelInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(leafToolFinishedAt)
	if err := toolSpan.End(toolInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(leafFinishedAt)
	if err := leafSpan.End(leafInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(nestedFinishedAt)
	if err := nestedSpan.End(nestedInput); err != nil {
		t.Fatal(err)
	}
	waitForGoldenSpanEnd(directFinishedAt)
	if err := directSpan.End(directInput); err != nil {
		t.Fatal(err)
	}
	emitGoldenLifecycle(t, api, rootSpan.Context(), rootTurnEnd)
	waitForGoldenSpanEnd(rootFinishedAt)
	if err := rootSpan.End(rootInput); err != nil {
		t.Fatal(err)
	}

	// Terminal hooks are distinct connector deliveries. Keep their spans as
	// truthful request-bounded roots and prove the join through canonical IDs;
	// do not fabricate a single retained trace across completed requests.
	for _, meta := range []llmEventMeta{leafStop, nestedStop, directStop, rootStop} {
		emitGoldenLifecycle(t, api, t.Context(), meta)
	}

	// The local profile uses a one-second metric interval and a short OTLP
	// batch delay. Keep the test process alive long enough for both readers to
	// export; fixture cleanup then performs the final runtime drain.
	time.Sleep(2500 * time.Millisecond)
}

func waitForGoldenSpanEnd(finishedAt time.Time) {
	if remaining := time.Until(finishedAt); remaining > 0 {
		time.Sleep(remaining)
	}
}

func goldenAgentTraceInput(t *testing.T, meta llmEventMeta, startedAt, finishedAt time.Time) observability.SpanAgentInvokeInput {
	t.Helper()
	observation := hookModelV8Observation{
		meta: meta, provider: meta.Provider, model: meta.Model,
		agentName: meta.AgentName, agentType: meta.AgentType, agentID: meta.AgentID, sessionID: meta.SessionID,
		startedAt: startedAt, finishedAt: finishedAt,
	}
	input, ok := hookModelV8AgentInput(observation)
	if !ok {
		t.Fatalf("golden agent input is not representable: %#v", meta)
	}
	return input
}

func goldenModelObservation(meta llmEventMeta, startedAt, finishedAt time.Time, stamp string) hookModelV8Observation {
	return hookModelV8Observation{
		meta: meta, prompt: "local-observability golden prompt " + stamp,
		response: "local-observability golden response " + stamp,
		usage:    hookLLMSpanUsage{model: meta.Model, promptTokens: 21, completionTokens: 13},
		provider: meta.Provider, reportedModel: meta.Model, model: meta.Model, responseModel: meta.Model,
		agentName: meta.AgentName, agentType: meta.AgentType, agentID: meta.AgentID, sessionID: meta.SessionID,
		startedAt: startedAt, finishedAt: finishedAt, finishReasons: []string{"stop"},
		promptOriginalBytes: int64(len("local-observability golden prompt " + stamp)),
	}
}

func goldenToolObservation(
	meta llmEventMeta,
	arguments, result string,
	exitCode *int,
	startedAt, finishedAt time.Time,
) generatedToolV8Observation {
	return generatedToolV8Observation{
		meta: meta, producer: hookToolV8Producer, tool: meta.ToolName,
		arguments: arguments, result: result, toolProvider: "hook", exitCode: exitCode,
		startedAt: startedAt, finishedAt: finishedAt, argumentsOriginalBytes: int64(len(arguments)),
		agentName: meta.AgentName, agentType: meta.AgentType, agentID: meta.AgentID, sessionID: meta.SessionID,
	}
}

func emitGoldenLifecycle(t *testing.T, api *APIServer, ctx context.Context, meta llmEventMeta) {
	t.Helper()
	if got := api.emitHookLifecycleEvent(ctx, meta); got != hookLifecycleV8Persisted {
		t.Fatalf("emit %s/%s lifecycle=%d", meta.AgentName, meta.LifecycleEvent, got)
	}
	api.recordHookLifecycleMetric(ctx, meta)
	api.emitHookLifecycleTransitionSpan(ctx, meta)
}

func goldenLifecycleMeta(
	stamp, role, parent string,
	depth int,
	event, phase, previousPhase string,
) llmEventMeta {
	agentID := "golden-agent-" + role + "-" + stamp
	sessionID := "golden-session-" + role + "-" + stamp
	rootAgentID := "golden-agent-root-" + stamp
	rootSessionID := "golden-session-root-" + stamp
	parentAgentID := ""
	parentSessionID := ""
	if parent != "" {
		parentAgentID = "golden-agent-" + parent + "-" + stamp
		parentSessionID = "golden-session-" + parent + "-" + stamp
	}
	state := "active"
	outcome := "attempted"
	if strings.HasSuffix(event, "_stop") || event == "session_end" || event == "turn_end" || event == "tool_end" {
		state = "completed"
		outcome = "completed"
	}
	return llmEventMeta{
		Source: "codex", Provider: "openai", Model: "gpt-5",
		SessionID: sessionID, RootSessionID: rootSessionID, ParentSessionID: parentSessionID,
		RequestID: "golden-request-" + stamp, RunID: "golden-run-" + stamp,
		TurnID: "golden-turn-" + stamp, AgentID: agentID, AgentName: "golden-" + role,
		AgentType: role, RootAgentID: rootAgentID, ParentAgentID: parentAgentID,
		LineageProvenance: "reported", AgentDepth: depth,
		LifecycleID:    "golden-lifecycle-" + role + "-" + stamp,
		ExecutionID:    "golden-execution-" + role + "-" + stamp,
		LifecycleEvent: event, LifecycleState: state, LifecycleOutcome: outcome,
		Phase: phase, PreviousPhase: previousPhase,
		OperationID: "golden-operation-" + role + "-" + stamp,
		Sequence:    1,
	}
}
