// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
)

func TestAMPEventsEnterCorrectGuardrailLanes(t *testing.T) {
	if !isPromptLikeEvent("agent.start") {
		t.Fatal("agent.start is not classified as prompt")
	}
	if !isGenericToolInspectionEvent("tool.call") {
		t.Fatal("tool.call is not classified as pre-execution tool inspection")
	}
	if !isResultLikeEvent("tool.result") {
		t.Fatal("tool.result is not classified as a model-bound tool result")
	}
	if !isResultLikeEvent("agent.end") {
		t.Fatal("agent.end is not classified as observe-only assistant result")
	}

	profile := connector.NewAMPConnector().HookProfile(connector.SetupOpts{})
	req := normalizeAgentHookRequestWithProfile("amp", map[string]interface{}{
		"hook_event_name": "tool.call",
		"session_id":      "T-child",
		"thread_id":       "T-child",
		"turn_id":         "message-7",
		"message_id":      "message-7",
		"tool_call_id":    "toolu-9",
		"tool_name":       "oracle",
		"tool_input":      map[string]interface{}{"prompt": "review this"},
		"source_event_id": "tool.call:T-child:toolu-9:nonce:3",
		"source_sequence": "3",
	}, profile)
	if req.SessionID != "T-child" || req.ThreadID != "T-child" ||
		req.TurnID != "message-7" || req.ToolInvocationID != "toolu-9" ||
		req.ToolName != "oracle" || req.Direction != "tool_call" {
		t.Fatalf("normalized Amp request=%+v", req)
	}
	if req.ParentSessionID != "" || req.ParentAgentID != "" {
		t.Fatalf("Amp callback synthesized lineage: %+v", req)
	}
	if !containsString(profile.Capabilities.BlockEvents, "tool.result") ||
		!containsString(profile.Capabilities.AskEvents, "tool.result") {
		t.Fatalf("tool.result is missing its model-bound output gate: %+v", profile.Capabilities)
	}
	if action, wouldBlock := mapHookActionForProfile(
		"block", "action", "tool.result", profile.Capabilities, profile, req.Payload,
	); action != "block" || wouldBlock {
		t.Fatalf("tool.result block verdict=(%q,%v), want enforced block", action, wouldBlock)
	}
}

func TestAMPAgentEndScansAssistantOutputWithoutBlocking(t *testing.T) {
	profile := connector.NewAMPConnector().HookProfile(connector.SetupOpts{})
	req := normalizeAgentHookRequestWithProfile("amp", map[string]interface{}{
		"hook_event_name": "agent.end",
		"session_id":      "T-turn",
		"thread_id":       "T-turn",
		"turn_id":         "message-8",
		"message_id":      "message-8",
		// This is the plugin-projected assistant text. The original user
		// prompt is deliberately absent so it cannot be re-scanned as output.
		"tool_response":   "assistant final: AWS_SECRET_ACCESS_KEY=redacted",
		"response":        "assistant final: AWS_SECRET_ACCESS_KEY=redacted",
		"tool_name":       "message",
		"source_event_id": "agent.end:T-turn:message-8:nonce:4",
		"source_sequence": "4",
	}, profile)
	if req.Content != "assistant final: AWS_SECRET_ACCESS_KEY=redacted" ||
		req.Direction != "tool_result" || req.ToolName != "message" {
		t.Fatalf("normalized Amp assistant output=%+v", req)
	}
	for _, event := range profile.Capabilities.BlockEvents {
		if event == "agent.end" {
			t.Fatal("agent.end must never be blockable after the turn has completed")
		}
	}
	action, wouldBlock := mapHookActionForProfile(
		"block", "action", "agent.end", profile.Capabilities, profile, req.Payload,
	)
	if action != "allow" || !wouldBlock {
		t.Fatalf("agent.end block verdict=(%q,%v), want allow/would_block", action, wouldBlock)
	}
}

func emitAMPFiveEventObservabilitySequence(t *testing.T, api *APIServer, reportModel bool) {
	t.Helper()
	emitAMPFiveEventObservabilitySequenceWithTool(t, api, reportModel, "shell")
}

func emitAMPFiveEventObservabilitySequenceWithTool(
	t *testing.T,
	api *APIServer,
	reportModel bool,
	toolName string,
) {
	t.Helper()
	const (
		sessionID = "amp-thread-observability"
		turnID    = "amp-message-observability"
		toolID    = "amp-tool-observability"
	)
	payload := func(event string, sequence int) map[string]interface{} {
		result := map[string]interface{}{
			"hook_event_name": event,
			"source_event_id": event + ":amp-thread-observability:" + strconv.Itoa(sequence),
			"source_sequence": sequence,
			"agent_name":      "amp",
			"agent_type":      "amp",
		}
		if reportModel {
			// Amp's current built-in-agent callbacks do not report a model.
			// Custom agent definitions may report the exact provider/model
			// string, which is sufficient source provenance for both fields.
			result["model"] = "openai/gpt-test"
		}
		return result
	}
	emit := func(request agentHookRequest, sequence int, raw string) {
		request.ConnectorName = "amp"
		request.SessionID = sessionID
		request.Payload = payload(request.HookEventName, sequence)
		if request.TurnID != "" {
			request.Payload["turn_id"] = request.TurnID
			request.Payload["message_id"] = request.TurnID
		}
		if request.ToolInvocationID != "" {
			request.Payload["tool_call_id"] = request.ToolInvocationID
			request.Payload["tool_name"] = request.ToolName
		}
		api.emitAgentHookLLMEvent(t.Context(), request, []byte(raw))
	}

	emit(agentHookRequest{HookEventName: "session.start"}, 1,
		`{"hook_event_name":"session.start","session_id":"amp-thread-observability"}`)
	emit(agentHookRequest{
		HookEventName: "agent.start", TurnID: turnID, Content: "Review this workspace safely.",
	}, 2, `{"hook_event_name":"agent.start","prompt":"Review this workspace safely."}`)
	emit(agentHookRequest{
		HookEventName: "tool.call", TurnID: turnID, ToolInvocationID: toolID,
		ToolName: toolName, ToolArgs: json.RawMessage(`{"command":"printf amp"}`),
	}, 3, `{"hook_event_name":"tool.call","tool_name":"shell"}`)
	emit(agentHookRequest{
		HookEventName: "tool.result", TurnID: turnID, ToolInvocationID: toolID,
		ToolName: toolName, ToolArgs: json.RawMessage(`{"command":"printf amp"}`),
		Content: "amp",
	}, 4, `{"hook_event_name":"tool.result","tool_name":"shell","tool_response":"amp"}`)
	emit(agentHookRequest{
		HookEventName: "agent.end", TurnID: turnID, ToolName: "message",
		Content: "Amp completed the review.",
	}, 5, `{"hook_event_name":"agent.end","response":"Amp completed the review."}`)
}

func TestAMPFiveEventCanonicalObservability(t *testing.T) {
	spec := connector.DefaultCorrelationSpec("amp")
	for _, mapping := range []struct {
		raw         string
		lifecycle   string
		phase       string
		correlation connector.CorrelationLifecycle
	}{
		{"session.start", "session_start", "session", connector.CorrelationLifecycleSessionStart},
		{"agent.start", "turn_start", "planning", connector.CorrelationLifecycleTurnStart},
		{"tool.call", "tool_start", "tool", connector.CorrelationLifecycleToolStart},
		{"tool.result", "tool_end", "planning", connector.CorrelationLifecycleToolEnd},
		{"agent.end", "turn_end", "responding", connector.CorrelationLifecycleTurnEnd},
	} {
		state := hookLifecycleState(mapping.lifecycle, nil)
		if got := canonicalHookLifecycleEvent(mapping.raw); got != mapping.lifecycle {
			t.Errorf("%s canonical lifecycle=%s want=%s", mapping.raw, got, mapping.lifecycle)
		}
		if got := hookLifecyclePhase(mapping.raw, mapping.lifecycle, state); got != mapping.phase {
			t.Errorf("%s phase=%s want=%s", mapping.raw, got, mapping.phase)
		}
		if got, ok := spec.LifecycleForEvent(mapping.raw); !ok || got != mapping.correlation {
			t.Errorf("%s correlation cursor=%s present=%t want=%s",
				mapping.raw, got, ok, mapping.correlation)
		}
	}

	t.Run("lifecycle and Agent360 identity", func(t *testing.T) {
		fixture := newSidecarRuntimeFixture(t, true)
		api := &APIServer{}
		bindHookLifecycleV8(t, api, fixture.runtime)
		emitAMPFiveEventObservabilitySequence(t, api, false)

		rows := readStoredHookLifecycleV8(t, fixture.path)
		wantEvents := []string{"session_start", "turn_start", "tool_start", "tool_end", "turn_end"}
		wantBuckets := []string{"agent.lifecycle", "agent.lifecycle", "tool.activity", "tool.activity", "agent.lifecycle"}
		wantOutcomes := []string{"attempted", "attempted", "attempted", "completed", "completed"}
		wantPhases := []string{"session", "planning", "tool", "planning", "responding"}
		if len(rows) != len(wantEvents) {
			t.Fatalf("Amp lifecycle rows=%d want=%d: %#v", len(rows), len(wantEvents), rows)
		}
		rootAgentID := stableLLMEventID("agent", "amp", "amp-thread-observability", "root")
		for index, row := range rows {
			if row.eventName != wantEvents[index] || row.bucket != wantBuckets[index] {
				t.Errorf("row %d family=%s/%s want=%s/%s",
					index, row.bucket, row.eventName, wantBuckets[index], wantEvents[index])
			}
			if got := row.projected["outcome"]; got != wantOutcomes[index] {
				t.Errorf("row %d outcome=%v want=%s", index, got, wantOutcomes[index])
			}
			if got := row.projected["connector"]; got != "amp" {
				t.Errorf("row %d connector=%v want=amp", index, got)
			}
			if got := row.body["gen_ai.agent.id"]; got != rootAgentID {
				t.Errorf("row %d agent=%v want inferred root %s", index, got, rootAgentID)
			}
			if got := row.body["defenseclaw.agent.root.id"]; got != rootAgentID {
				t.Errorf("row %d root=%v want %s", index, got, rootAgentID)
			}
			if got := row.body["defenseclaw.agent.lineage.provenance"]; got != "inferred" {
				t.Errorf("row %d lineage provenance=%v want inferred", index, got)
			}
			if got := row.body["defenseclaw.agent.phase"]; got != wantPhases[index] {
				t.Errorf("row %d phase=%v want=%s", index, got, wantPhases[index])
			}
			if got, present := row.body["gen_ai.provider.name"]; present {
				t.Errorf("row %d fabricated Amp provider=%v", index, got)
			}
			if got, present := row.body["gen_ai.request.model"]; present {
				t.Errorf("row %d fabricated Amp model=%v", index, got)
			}
		}
		snapshot, ok := api.hookLifecycleSnapshot("amp", "amp-thread-observability", rootAgentID)
		if !ok || snapshot.LifecycleEvent != "turn_end" || snapshot.Phase != "responding" ||
			snapshot.Sequence != 5 {
			t.Fatalf("Amp terminal cursor present=%t snapshot=%+v", ok, snapshot)
		}
	})

	t.Run("tool and model completion spans", func(t *testing.T) {
		api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces"})
		emitAMPFiveEventObservabilitySequence(t, api, true)

		familyCounts := map[string]int{}
		eventCounts := map[string]int{}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			clear(familyCounts)
			clear(eventCounts)
			for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
				familyCounts[gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family")]++
			}
			for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
				eventCounts[logStringAttribute(record.Attributes, "defenseclaw.event.name")]++
			}
			if familyCounts[observability.TelemetryFamilyToolExecute] == 1 &&
				familyCounts[observability.TelemetryFamilyModelChat] == 1 &&
				eventCounts[observability.TelemetryEventModelResponse] == 1 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		for family, want := range map[string]int{
			observability.TelemetryFamilyAgentTransition: 3,
			observability.TelemetryFamilyAgentInvoke:     2,
			observability.TelemetryFamilyToolExecute:     1,
			observability.TelemetryFamilyModelChat:       1,
		} {
			if got := familyCounts[family]; got != want {
				t.Errorf("Amp span family %s count=%d want=%d; all=%v", family, got, want, familyCounts)
			}
		}
		for event, want := range map[string]int{
			observability.TelemetryEventSessionStart:            1,
			observability.TelemetryEventTurnStart:               1,
			observability.TelemetryEventToolStart:               1,
			observability.TelemetryEventToolEnd:                 1,
			observability.TelemetryEventTurnEnd:                 1,
			observability.TelemetryEventModelRequest:            1,
			observability.TelemetryEventModelResponse:           1,
			observability.TelemetryEventToolInvocationRequested: 1,
			observability.TelemetryEventToolInvocationCompleted: 1,
		} {
			if got := eventCounts[event]; got != want {
				t.Errorf("Amp canonical event %s count=%d want=%d; all=%v", event, got, want, eventCounts)
			}
		}
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			family := gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family")
			if family != observability.TelemetryFamilyAgentInvoke &&
				family != observability.TelemetryFamilyToolExecute &&
				family != observability.TelemetryFamilyModelChat {
				continue
			}
			attributes := hookModelV8ProtoAttributes(span)
			if attributes["defenseclaw.connector.source"] != "amp" ||
				attributes["gen_ai.agent.id"] == "" {
				t.Errorf("Amp %s span lost connector/agent identity: %v", family, attributes)
			}
			if family != observability.TelemetryFamilyToolExecute &&
				attributes["gen_ai.provider.name"] != "openai" {
				t.Errorf("Amp %s span provider=%q want source-reported openai: %v",
					family, attributes["gen_ai.provider.name"], attributes)
			}
			if family == observability.TelemetryFamilyToolExecute &&
				attributes["gen_ai.tool.name"] != "shell" {
				t.Errorf("Amp fabricated a non-shell tool span: %v", attributes)
			}
			if family == observability.TelemetryFamilyModelChat &&
				attributes["gen_ai.request.model"] != "openai/gpt-test" {
				t.Errorf("Amp model.chat model=%q want exact source report: %v",
					attributes["gen_ai.request.model"], attributes)
			}
		}
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if logStringAttribute(record.Attributes, "defenseclaw.event.name") !=
				observability.TelemetryEventModelResponse {
				continue
			}
			var wire struct {
				Body map[string]interface{} `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				t.Fatalf("decode Amp model response log: %v", err)
			}
			if got := wire.Body["gen_ai.provider.name"]; got != "openai" {
				t.Errorf("Amp model response log provider=%q want source-reported openai", got)
			}
			if got := wire.Body["gen_ai.request.model"]; got != "openai/gpt-test" {
				t.Errorf("Amp model response log model=%q want exact source report", got)
			}
		}
	})

	t.Run("ordinary callbacks do not fabricate model chat spans", func(t *testing.T) {
		api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces", "metrics"})
		emitAMPFiveEventObservabilitySequence(t, api, false)

		familyCounts := map[string]int{}
		var lifecycleMetrics []hookModelV8MetricPoint
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			clear(familyCounts)
			traceRequests, metricRequests := capture.snapshot()
			for _, span := range hookModelV8CapturedSpans(traceRequests) {
				familyCounts[gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family")]++
			}
			lifecycleMetrics = hookModelV8MetricPoints(
				metricRequests,
				observability.TelemetryInstrumentDefenseClawAgentLifecycleTransitions,
			)
			if familyCounts[observability.TelemetryFamilyAgentTransition] == 3 &&
				familyCounts[observability.TelemetryFamilyAgentInvoke] == 2 &&
				familyCounts[observability.TelemetryFamilyToolExecute] == 1 &&
				len(lifecycleMetrics) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		for family, want := range map[string]int{
			observability.TelemetryFamilyAgentTransition: 3,
			observability.TelemetryFamilyAgentInvoke:     2,
			observability.TelemetryFamilyToolExecute:     1,
		} {
			if got := familyCounts[family]; got != want {
				t.Errorf("Amp no-model span family %s count=%d want=%d; all=%v",
					family, got, want, familyCounts)
			}
		}
		if len(lifecycleMetrics) == 0 {
			t.Fatal("Amp lifecycle transition metrics were not exported")
		}

		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			attributes := hookModelV8ProtoAttributes(span)
			if family := attributes["defenseclaw.span.family"]; family ==
				observability.TelemetryFamilyModelChat {
				t.Fatalf("Amp callback without a reported model fabricated model.chat: %v",
					attributes)
			}
			if attributes["defenseclaw.connector.source"] == "amp" {
				if got := attributes["gen_ai.provider.name"]; got != "" {
					t.Errorf("Amp no-model %s span fabricated provider=%q: %v",
						attributes["defenseclaw.span.family"], got, attributes)
				}
				if got := attributes["gen_ai.request.model"]; got != "" {
					t.Errorf("Amp no-model %s span fabricated model=%q: %v",
						attributes["defenseclaw.span.family"], got, attributes)
				}
			}
		}
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			var wire struct {
				Body map[string]interface{} `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				t.Fatalf("decode Amp no-model log: %v", err)
			}
			if wire.Body["defenseclaw.connector.source"] != "amp" {
				continue
			}
			if got, present := wire.Body["gen_ai.provider.name"]; present {
				t.Errorf("Amp no-model %s log fabricated provider=%q",
					logStringAttribute(record.Attributes, "defenseclaw.event.name"), got)
			}
			if got, present := wire.Body["gen_ai.request.model"]; present {
				t.Errorf("Amp no-model %s log fabricated model=%q",
					logStringAttribute(record.Attributes, "defenseclaw.event.name"), got)
			}
		}
		for _, point := range lifecycleMetrics {
			if got := point.attributes["gen_ai.provider.name"]; got != "unknown" {
				t.Errorf("Amp no-model lifecycle metric provider=%q want unknown: %v",
					got, point.attributes)
			}
			if got := point.attributes["gen_ai.request.model"]; got != "unknown" {
				t.Errorf("Amp no-model lifecycle metric model=%q want unknown: %v",
					got, point.attributes)
			}
		}
	})

	t.Run("delegation tool does not fabricate subagent lifecycle", func(t *testing.T) {
		fixture := newSidecarRuntimeFixture(t, true)
		api := &APIServer{}
		bindHookLifecycleV8(t, api, fixture.runtime)
		emitAMPFiveEventObservabilitySequenceWithTool(t, api, false, "oracle")

		rows := readStoredHookLifecycleV8(t, fixture.path)
		if len(rows) != 5 {
			t.Fatalf("Amp oracle lifecycle rows=%d want five source callbacks: %#v", len(rows), rows)
		}
		for _, row := range rows {
			if row.eventName == "subagent_start" || row.eventName == "subagent_stop" {
				t.Fatalf("Amp oracle tool fabricated child lifecycle row: %#v", row)
			}
		}
	})

	t.Run("Galileo canonical route", func(t *testing.T) {
		for _, family := range []string{
			observability.TelemetryFamilyAgentInvoke,
			observability.TelemetryFamilyModelChat,
			observability.TelemetryFamilyToolExecute,
		} {
			if !profilemanifest.Eligible(
				observability.RuntimeGalileoCompatibilityProfile,
				observability.SignalTraces,
				observability.EventName(family),
			) {
				t.Errorf("Amp canonical span family %s is not Galileo-route eligible", family)
			}
		}
		if profilemanifest.Eligible(
			observability.RuntimeGalileoCompatibilityProfile,
			observability.SignalTraces,
			observability.EventName(observability.TelemetryFamilyAgentTransition),
		) {
			t.Fatal("Amp lifecycle transition bypassed Galileo's generated compatibility route")
		}
	})
}
