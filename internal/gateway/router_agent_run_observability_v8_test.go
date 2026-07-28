// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestEventRouterAgentRunObservationContract(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	start := agentStreamData{Phase: "start", StartedAt: baseTimestamp}
	end := agentStreamData{Phase: "end", StartedAt: baseTimestamp, EndedAt: baseTimestamp + 1000}

	t.Run("ER-RUN-01 start is one outcome-free observation", func(t *testing.T) {
		router, store, path := newAgentRunObservationRouterWithPath(t, true)
		emission := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "openclaw-run-1", Stream: "lifecycle", SessionKey: "agent:main:main",
			Seq: 1, Ts: baseTimestamp,
		}, start)
		if emission != agentRunObservationPersisted {
			t.Fatalf("emission=%d", emission)
		}
		rows := agentRunRows(t, store)
		if len(rows) != 1 {
			t.Fatalf("rows=%d", len(rows))
		}
		assertAgentRunRow(t, rows[0], "openclaw-run-1", "start", 1, baseTimestamp)
		assertAgentRunObservedAt(t, path, baseTimestamp)
		for _, forbidden := range []string{
			"defenseclaw.outcome", "gen_ai.agent.id", "defenseclaw.agent.root.id",
			"defenseclaw.agent.parent.id", "defenseclaw.agent.depth",
			"defenseclaw.agent.lifecycle.id", "defenseclaw.agent.execution.id",
		} {
			if _, exists := rows[0].Structured[forbidden]; exists {
				t.Fatalf("source-poor observation fabricated %q: %#v", forbidden, rows[0].Structured)
			}
		}
	})

	t.Run("ER-RUN-02 end preserves checked source interval", func(t *testing.T) {
		router, store, path := newAgentRunObservationRouterWithPath(t, true)
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "openclaw-run-2", Stream: "lifecycle", SessionKey: "agent:main:main",
			Seq: 2, Ts: baseTimestamp + 1000,
		}, end); got != agentRunObservationPersisted {
			t.Fatalf("emission=%d", got)
		}
		row := agentRunRows(t, store)[0]
		assertAgentRunRow(t, row, "openclaw-run-2", "end", 2, baseTimestamp+1000)
		assertAgentRunObservedAt(t, path, baseTimestamp+1000)
		if row.Structured[observability.TelemetryAttributeDefenseClawAgentRunStartedAtUnixNano] != float64(baseTimestamp*1_000_000) ||
			row.Structured[observability.TelemetryAttributeDefenseClawAgentRunEndedAtUnixNano] != float64((baseTimestamp+1000)*1_000_000) {
			t.Fatalf("source interval=%#v", row.Structured)
		}
	})

	t.Run("ER-RUN-03 error and later end remain distinct", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		envelope := agentStreamEnvelope{
			RunID: "openclaw-run-3", Stream: "lifecycle", SessionKey: "agent:main:main",
			Seq: 2, Ts: baseTimestamp + 500,
		}
		if got := router.emitAgentRunObservationV8(envelope, agentStreamData{
			Phase: "error", Error: "provider failed for alice@example.com",
		}); got != agentRunObservationPersisted {
			t.Fatalf("error emission=%d", got)
		}
		envelope.Seq, envelope.Ts = 3, baseTimestamp+1000
		if got := router.emitAgentRunObservationV8(envelope, end); got != agentRunObservationPersisted {
			t.Fatalf("end emission=%d", got)
		}
		rows := agentRunRows(t, store)
		if len(rows) != 2 {
			t.Fatalf("rows=%d", len(rows))
		}
		seen := map[string]bool{}
		for _, row := range rows {
			event, _ := row.Structured[observability.TelemetryAttributeDefenseClawAgentRunEvent].(string)
			seen[event] = true
			if _, exists := row.Structured["defenseclaw.outcome"]; exists {
				t.Fatalf("observation invented outcome: %#v", row.Structured)
			}
		}
		if !seen["error"] || !seen["end"] {
			t.Fatalf("events=%v", seen)
		}
	})

	t.Run("ER-RUN-04 exact duplicate is bounded", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		envelope := agentStreamEnvelope{RunID: "openclaw-run-4", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}
		if first := router.emitAgentRunObservationV8(envelope, start); first != agentRunObservationPersisted {
			t.Fatalf("first=%d", first)
		}
		if duplicate := router.emitAgentRunObservationV8(envelope, start); duplicate != agentRunObservationDuplicate {
			t.Fatalf("duplicate=%d", duplicate)
		}
		if rows := agentRunRows(t, store); len(rows) != 1 {
			t.Fatalf("rows=%d", len(rows))
		}
	})

	t.Run("ER-RUN-05 changed sequence or timestamp is distinct", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		envelope := agentStreamEnvelope{RunID: "openclaw-run-5", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}
		if got := router.emitAgentRunObservationV8(envelope, start); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		envelope.Seq, envelope.Ts = 2, baseTimestamp+1
		if got := router.emitAgentRunObservationV8(envelope, start); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		if rows := agentRunRows(t, store); len(rows) != 2 {
			t.Fatalf("rows=%d", len(rows))
		}
	})

	t.Run("ER-RUN-06 terminal-only does not synthesize start", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "openclaw-run-6", Stream: "lifecycle", Seq: 7, Ts: baseTimestamp,
		}, agentStreamData{Phase: "end", EndedAt: baseTimestamp}); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		rows := agentRunRows(t, store)
		if len(rows) != 1 || rows[0].Structured[observability.TelemetryAttributeDefenseClawAgentRunEvent] != "end" {
			t.Fatalf("rows=%#v", rows)
		}
	})

	t.Run("ER-RUN-07 outer sequence does not own run sequence", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		payload := agentStreamEnvelope{RunID: "openclaw-run-7", Stream: "lifecycle", Seq: 9, Ts: baseTimestamp}
		payload.Data = mustMarshal(agentStreamData{Phase: "start"})
		outerA, outerB := 100, 1
		router.handleAgentStreamEvent(payload, EventFrame{Seq: &outerA})
		payload.Seq, payload.Ts = 10, baseTimestamp+1
		router.handleAgentStreamEvent(payload, EventFrame{Seq: &outerB})
		rows := agentRunRows(t, store)
		if len(rows) != 2 {
			t.Fatalf("rows=%d", len(rows))
		}
		for _, row := range rows {
			sequence := row.Structured[observability.TelemetryAttributeDefenseClawAgentRunSequence]
			if sequence != float64(9) && sequence != float64(10) {
				t.Fatalf("payload sequence replaced by outer frame: %#v", row.Structured)
			}
		}
	})

	t.Run("ER-RUN-08 reconnect retains no cross-delivery handle", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		startEnvelope := agentStreamEnvelope{RunID: "openclaw-run-8", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}
		if got := router.emitAgentRunObservationV8(startEnvelope, start); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		if session, run := router.activeAgentCorrelation(); session != "" || run != "" {
			t.Fatalf("retained inferred correlation=(%q,%q)", session, run)
		}
		terminal := startEnvelope
		terminal.Seq, terminal.Ts = 2, baseTimestamp+1000
		if got := router.emitAgentRunObservationV8(terminal, end); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		if rows := agentRunRows(t, store); len(rows) != 2 {
			t.Fatalf("rows=%d", len(rows))
		}
	})

	t.Run("ER-RUN-09 invalid source facts are rejected", func(t *testing.T) {
		tests := []struct {
			name     string
			envelope agentStreamEnvelope
			data     agentStreamData
		}{
			{"missing run", agentStreamEnvelope{Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}, start},
			{"zero sequence", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Ts: baseTimestamp}, start},
			{"zero timestamp", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Seq: 1}, start},
			{"timestamp overflow", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Seq: 1, Ts: math.MaxInt64}, start},
			{"reversed interval", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}, agentStreamData{Phase: "end", StartedAt: baseTimestamp + 1, EndedAt: baseTimestamp}},
			{"error on start", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}, agentStreamData{Phase: "start", Error: "wrong shape"}},
			{"oversize error", agentStreamEnvelope{RunID: "rejected-run-secret", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp}, agentStreamData{Phase: "error", Error: strings.Repeat("x", 4097)}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				router, store := newAgentRunObservationRouter(t, true)
				if got := router.emitAgentRunObservationV8(test.envelope, test.data); got != agentRunObservationRejected {
					t.Fatalf("emission=%d", got)
				}
				rows := agentRunRows(t, store)
				if len(rows) != 1 || rows[0].Action != string(gatewaylog.EventError) {
					t.Fatalf("diagnostic rows=%#v", rows)
				}
				if rows[0].Structured[observability.TelemetryAttributeDefenseClawSchemaErrorCode] != agentRunObservationErrorCode ||
					rows[0].Structured[observability.TelemetryAttributeDefenseClawHealthSubsystem] != "event_router" {
					t.Fatalf("diagnostic body=%#v", rows[0].Structured)
				}
				encoded, err := json.Marshal(rows[0])
				if err != nil {
					t.Fatal(err)
				}
				for _, rawSourceFact := range []string{test.envelope.RunID, test.envelope.SessionKey, test.data.Error} {
					if rawSourceFact != "" && strings.Contains(string(encoded), rawSourceFact) {
						t.Fatalf("rejected source fact leaked into diagnostic: %q", rawSourceFact)
					}
				}
			})
		}
	})

	t.Run("ER-RUN-10 defaults do not fabricate agent topology", func(t *testing.T) {
		router, store := newAgentRunObservationRouter(t, true)
		router.SetDefaultAgentName("configured-root")
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "openclaw-run-10", Stream: "lifecycle", SessionKey: "agent:main:main",
			Seq: 1, Ts: baseTimestamp,
		}, start); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		row := agentRunRows(t, store)[0]
		for key := range row.Structured {
			if strings.HasPrefix(key, "defenseclaw.agent.") && !strings.HasPrefix(key, "defenseclaw.agent.run.") {
				t.Fatalf("fabricated agent topology %q: %#v", key, row.Structured)
			}
		}
	})

	t.Run("ER-RUN-12 start retains no inferred delivery correlation", func(t *testing.T) {
		router, _ := newAgentRunObservationRouter(t, true)
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "openclaw-run-12", Stream: "lifecycle", Seq: 1, Ts: baseTimestamp,
		}, start); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		if session, run := router.activeAgentCorrelation(); session != "" || run != "" {
			t.Fatalf("retained inferred correlation=(%q,%q)", session, run)
		}
		router.spanMu.Lock()
		defer router.spanMu.Unlock()
		if len(router.activeLLMContexts) != 0 {
			t.Fatal("run observation retained a cross-delivery trace context")
		}
	})
}

func TestEventRouterAgentRunObservationPreservesRecursiveOpenClawTopology(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	router, store := newAgentRunObservationRouter(t, true)

	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "openclaw-root-run", "stream": "lifecycle",
		"sessionKey": "agent:root:main", "sessionId": "session-root-1",
		"agentId": "root-agent", "spawnDepth": 0,
		"seq": 1, "ts": baseTimestamp,
		"data": map[string]any{"phase": "start", "agentId": "root-agent", "spawnDepth": 0},
	})})
	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "openclaw-child-run", "stream": "lifecycle",
		"sessionKey": "agent:child:subagent:one", "sessionId": "session-child-1",
		"agentId":   "child-agent",
		"spawnedBy": "agent:root:main", "parentSessionKey": "agent:root:main",
		"parentSessionId": "session-root-1", "spawnDepth": 1,
		"seq": 1, "ts": baseTimestamp + 1,
		"data": map[string]any{
			"phase": "start", "agentId": "child-agent", "spawnedBy": "agent:root:main",
			"parentSessionKey": "agent:root:main", "parentSessionId": "session-root-1", "spawnDepth": 1,
		},
	})})
	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "openclaw-grandchild-run", "stream": "lifecycle",
		"sessionKey": "agent:grandchild:subagent:two", "seq": 1, "ts": baseTimestamp + 2,
		"data": map[string]any{
			"phase": "start", "sessionId": "session-grandchild-1", "agentId": "grandchild-agent",
			"parentSessionKey": "agent:child:subagent:one", "parentSessionId": "session-child-1",
			"spawnDepth": 2,
		},
	})})

	rows := agentRunRowsByRunID(t, store)
	if len(rows) != 3 {
		t.Fatalf("rows=%d want 3", len(rows))
	}
	tests := []struct {
		runID, sessionKey, conversationID, agentID, rootAgentID, parentAgentID string
		rootSessionID, parentSessionID, lineage                                string
		depth                                                                  float64
		timestamp                                                              int64
	}{
		{
			runID: "openclaw-root-run", sessionKey: "agent:root:main", conversationID: "session-root-1",
			agentID: "root-agent", rootAgentID: "root-agent", rootSessionID: "session-root-1",
			lineage: "reported", depth: 0, timestamp: baseTimestamp,
		},
		{
			runID: "openclaw-child-run", sessionKey: "agent:child:subagent:one",
			conversationID: "session-child-1", agentID: "child-agent",
			rootAgentID: "root-agent", parentAgentID: "root-agent", rootSessionID: "session-root-1",
			parentSessionID: "session-root-1", lineage: "inferred", depth: 1, timestamp: baseTimestamp + 1,
		},
		{
			runID: "openclaw-grandchild-run", sessionKey: "agent:grandchild:subagent:two",
			conversationID: "session-grandchild-1",
			agentID:        "grandchild-agent", rootAgentID: "root-agent", parentAgentID: "child-agent",
			rootSessionID: "session-root-1", parentSessionID: "session-child-1",
			lineage: "inferred", depth: 2, timestamp: baseTimestamp + 2,
		},
	}
	for _, test := range tests {
		t.Run(test.runID, func(t *testing.T) {
			row, exists := rows[test.runID]
			if !exists {
				t.Fatalf("missing row for %s", test.runID)
			}
			if row.AgentID != test.agentID || row.SessionID != test.sessionKey {
				t.Fatalf("audit correlation agent/session=%q/%q", row.AgentID, row.SessionID)
			}
			wants := map[string]any{
				"gen_ai.conversation.id":               test.conversationID,
				"gen_ai.agent.id":                      test.agentID,
				"defenseclaw.agent.root.id":            test.rootAgentID,
				"defenseclaw.agent.lineage.provenance": test.lineage,
				"defenseclaw.session.root.id":          test.rootSessionID,
				"defenseclaw.agent.depth":              test.depth,
				"defenseclaw.agent.lifecycle.id": stableLLMEventID(
					"lifecycle", agentRunObservationConnector, test.conversationID, test.agentID,
				),
				"defenseclaw.agent.execution.id": stableLLMEventID(
					"execution", agentRunObservationConnector, test.conversationID, test.agentID, test.runID,
					strconv.FormatInt(test.timestamp, 10), "1",
				),
			}
			if test.parentAgentID != "" {
				wants["defenseclaw.agent.parent.id"] = test.parentAgentID
				wants["defenseclaw.session.parent.id"] = test.parentSessionID
			}
			for key, want := range wants {
				if row.Structured[key] != want {
					t.Fatalf("body[%q]=%#v want=%#v body=%#v", key, row.Structured[key], want, row.Structured)
				}
			}
		})
	}
}

func TestEventRouterAgentRunObservationPreservesCurrentOpenClawBroadcastShape(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	router, store := newAgentRunObservationRouter(t, true)

	// OpenClaw currently stamps the run-bound sessionId and agentId on lifecycle
	// events and adds spawnedBy only for a subagent session. spawnDepth and
	// parentSessionKey live on session surfaces and are not guaranteed here.
	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "current-root-run", "stream": "lifecycle",
		"sessionKey": "agent:main:main", "sessionId": "session-main-1", "agentId": "main",
		"seq": 1, "ts": baseTimestamp, "data": map[string]any{"phase": "start"},
	})})
	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "current-child-run", "stream": "lifecycle",
		"sessionKey": "agent:coder:subagent:xyz", "sessionId": "session-coder-1", "agentId": "coder",
		"spawnedBy": "agent:main:main",
		"seq":       1, "ts": baseTimestamp + 1, "data": map[string]any{"phase": "start"},
	})})

	rows := agentRunRowsByRunID(t, store)
	root := rows["current-root-run"].Structured
	child := rows["current-child-run"].Structured
	for key, want := range map[string]any{
		"gen_ai.conversation.id":               "session-main-1",
		"gen_ai.agent.id":                      "main",
		"defenseclaw.agent.root.id":            "main",
		"defenseclaw.session.root.id":          "session-main-1",
		"defenseclaw.agent.depth":              float64(0),
		"defenseclaw.agent.lineage.provenance": "inferred",
	} {
		if root[key] != want {
			t.Fatalf("root[%q]=%#v want=%#v body=%#v", key, root[key], want, root)
		}
	}
	for key, want := range map[string]any{
		"gen_ai.conversation.id":               "session-coder-1",
		"gen_ai.agent.id":                      "coder",
		"defenseclaw.agent.parent.id":          "main",
		"defenseclaw.agent.root.id":            "main",
		"defenseclaw.agent.depth":              float64(1),
		"defenseclaw.agent.lineage.provenance": "inferred",
	} {
		if child[key] != want {
			t.Fatalf("child[%q]=%#v want=%#v body=%#v", key, child[key], want, child)
		}
	}
	for _, key := range []string{"defenseclaw.session.parent.id", "defenseclaw.session.root.id"} {
		if _, exists := child[key]; exists {
			t.Fatalf("child inferred unreported parent incarnation %q: %#v", key, child)
		}
	}
}

func TestEventRouterAgentRunObservationDoesNotTreatSessionKeyAsIncarnation(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	depth := int64(0)
	router, store := newAgentRunObservationRouter(t, true)
	if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
		RunID: "routing-key-only-run", Stream: "lifecycle",
		SessionKey: "agent:main:main", AgentID: "main", SpawnDepth: &depth,
		Seq: 1, Ts: baseTimestamp,
	}, agentStreamData{Phase: "start"}); got != agentRunObservationPersisted {
		t.Fatalf("emission=%d", got)
	}
	row := agentRunRows(t, store)[0]
	if row.SessionID != "agent:main:main" {
		t.Fatalf("routing correlation session=%q", row.SessionID)
	}
	for _, key := range []string{
		"gen_ai.conversation.id",
		"defenseclaw.session.root.id",
		"defenseclaw.session.parent.id",
		"defenseclaw.agent.lifecycle.id",
		"defenseclaw.agent.execution.id",
	} {
		if _, exists := row.Structured[key]; exists {
			t.Fatalf("sessionKey fabricated incarnation field %q: %#v", key, row.Structured)
		}
	}
}

func TestEventRouterAgentRunObservationKeepsLifecycleAndRotatesExecutionPerRun(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	depth := int64(0)
	router, store := newAgentRunObservationRouter(t, true)
	emit := func(runID, phase string, sequence, timestamp int64) {
		t.Helper()
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: runID, Stream: "lifecycle", SessionKey: "agent:root:main",
			SessionID: "session-root-1", AgentID: "root-agent",
			SpawnDepth: &depth, Seq: sequence, Ts: timestamp,
		}, agentStreamData{Phase: phase}); got != agentRunObservationPersisted {
			t.Fatalf("%s/%s emission=%d", runID, phase, got)
		}
	}
	emit("openclaw-run-a", "start", 1, baseTimestamp)
	emit("openclaw-run-a", "end", 2, baseTimestamp+1)
	emit("openclaw-run-b", "start", 1, baseTimestamp+2)

	rows := agentRunRows(t, store)
	if len(rows) != 3 {
		t.Fatalf("rows=%d want 3", len(rows))
	}
	lifecycleIDs := map[string]bool{}
	executionsByRun := map[string]map[string]bool{}
	for _, row := range rows {
		runID, _ := row.Structured[observability.TelemetryAttributeDefenseClawAgentRunID].(string)
		lifecycle, _ := row.Structured["defenseclaw.agent.lifecycle.id"].(string)
		execution, _ := row.Structured["defenseclaw.agent.execution.id"].(string)
		lifecycleIDs[lifecycle] = true
		if executionsByRun[runID] == nil {
			executionsByRun[runID] = map[string]bool{}
		}
		executionsByRun[runID][execution] = true
	}
	if len(lifecycleIDs) != 1 || len(executionsByRun["openclaw-run-a"]) != 1 ||
		len(executionsByRun["openclaw-run-b"]) != 1 {
		t.Fatalf("lifecycle=%v executions=%v", lifecycleIDs, executionsByRun)
	}
	var executionA, executionB string
	for value := range executionsByRun["openclaw-run-a"] {
		executionA = value
	}
	for value := range executionsByRun["openclaw-run-b"] {
		executionB = value
	}
	if executionA == executionB {
		t.Fatalf("distinct upstream runs reused execution id %q", executionA)
	}
}

func TestEventRouterAgentRunObservationSeparatesReusedRunIDAfterTerminal(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	depth := int64(0)
	router, store := newAgentRunObservationRouter(t, true)
	emit := func(phase string, sequence, timestamp int64) {
		t.Helper()
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "reused-run", Stream: "lifecycle", SessionKey: "agent:root:main",
			SessionID: "session-root-1", AgentID: "root-agent", SpawnDepth: &depth,
			Seq: sequence, Ts: timestamp,
		}, agentStreamData{Phase: phase}); got != agentRunObservationPersisted {
			t.Fatalf("%s emission=%d", phase, got)
		}
	}
	emit("start", 1, baseTimestamp)
	emit("end", 2, baseTimestamp+1)
	emit("start", 1, baseTimestamp+1000)

	startExecutions := map[string]bool{}
	allExecutions := map[string]bool{}
	for _, row := range agentRunRows(t, store) {
		execution, _ := row.Structured["defenseclaw.agent.execution.id"].(string)
		event, _ := row.Structured[observability.TelemetryAttributeDefenseClawAgentRunEvent].(string)
		allExecutions[execution] = true
		if event == "start" {
			startExecutions[execution] = true
		}
	}
	if len(startExecutions) != 2 || len(allExecutions) != 2 {
		t.Fatalf("start/all execution IDs=%v/%v", startExecutions, allExecutions)
	}
}

func TestEventRouterAgentRunObservationDoesNotJoinStaleParentIncarnation(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	zero, one := int64(0), int64(1)
	router, store := newAgentRunObservationRouter(t, true)
	if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
		RunID: "old-parent-run", Stream: "lifecycle", SessionKey: "agent:root:main",
		SessionID: "session-root-old", AgentID: "root-agent", SpawnDepth: &zero,
		Seq: 1, Ts: baseTimestamp,
	}, agentStreamData{Phase: "start"}); got != agentRunObservationPersisted {
		t.Fatal(got)
	}
	if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
		RunID: "new-child-run", Stream: "lifecycle", SessionKey: "agent:child:subagent:new",
		SessionID: "session-child-new", AgentID: "child-agent",
		ParentSessionKey: "agent:root:main", ParentSessionID: "session-root-new", SpawnDepth: &one,
		Seq: 1, Ts: baseTimestamp + 1,
	}, agentStreamData{Phase: "start"}); got != agentRunObservationPersisted {
		t.Fatal(got)
	}
	child := agentRunRowsByRunID(t, store)["new-child-run"].Structured
	if child["defenseclaw.session.parent.id"] != "session-root-new" {
		t.Fatalf("source parent incarnation=%#v", child)
	}
	for _, key := range []string{
		"defenseclaw.agent.parent.id",
		"defenseclaw.agent.root.id",
		"defenseclaw.session.root.id",
	} {
		if _, exists := child[key]; exists {
			t.Fatalf("stale parent topology leaked %q: %#v", key, child)
		}
	}
}

func TestEventRouterAgentRunObservationRejectsConflictingTopology(t *testing.T) {
	baseTimestamp := int64(1783353600000)
	zero, one, two := int64(0), int64(1), int64(2)
	tests := []struct {
		name     string
		envelope agentStreamEnvelope
		data     agentStreamData
	}{
		{
			name: "top-level and data agent disagree",
			envelope: agentStreamEnvelope{RunID: "conflict-agent", Stream: "lifecycle", SessionKey: "agent:a:main",
				AgentID: "agent-a", SpawnDepth: &zero, Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start", AgentID: "agent-b", SpawnDepth: &zero},
		},
		{
			name: "top-level and data session incarnation disagree",
			envelope: agentStreamEnvelope{RunID: "conflict-session", Stream: "lifecycle",
				SessionKey: "agent:a:main", SessionID: "session-a", AgentID: "agent-a",
				SpawnDepth: &zero, Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start", SessionID: "session-b"},
		},
		{
			name: "parent aliases disagree",
			envelope: agentStreamEnvelope{RunID: "conflict-parent", Stream: "lifecycle", SessionKey: "agent:c:child",
				AgentID: "agent-c", SpawnedBy: "agent:a:main", ParentSessionKey: "agent:b:main",
				SpawnDepth: &one, Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start"},
		},
		{
			name: "depth paths disagree",
			envelope: agentStreamEnvelope{RunID: "conflict-depth", Stream: "lifecycle", SessionKey: "agent:c:child",
				AgentID: "agent-c", ParentSessionKey: "agent:a:main", SpawnDepth: &one,
				Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start", SpawnDepth: &two},
		},
		{
			name: "child depth has no parent",
			envelope: agentStreamEnvelope{RunID: "missing-parent", Stream: "lifecycle", SessionKey: "agent:c:child",
				AgentID: "agent-c", SpawnDepth: &one, Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start"},
		},
		{
			name: "root depth has parent",
			envelope: agentStreamEnvelope{RunID: "root-parent", Stream: "lifecycle", SessionKey: "agent:a:main",
				AgentID: "agent-a", ParentSessionKey: "agent:b:main", SpawnDepth: &zero,
				Seq: 1, Ts: baseTimestamp},
			data: agentStreamData{Phase: "start"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, _ := newAgentRunObservationRouter(t, true)
			if got := router.emitAgentRunObservationV8(test.envelope, test.data); got != agentRunObservationRejected {
				t.Fatalf("emission=%d want rejected", got)
			}
		})
	}

	t.Run("reported depth must extend retained parent", func(t *testing.T) {
		router, _ := newAgentRunObservationRouter(t, true)
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "depth-root", Stream: "lifecycle", SessionKey: "agent:root:main",
			AgentID: "root-agent", SpawnDepth: &zero, Seq: 1, Ts: baseTimestamp,
		}, agentStreamData{Phase: "start"}); got != agentRunObservationPersisted {
			t.Fatal(got)
		}
		if got := router.emitAgentRunObservationV8(agentStreamEnvelope{
			RunID: "depth-child", Stream: "lifecycle", SessionKey: "agent:child:subagent:one",
			AgentID: "child-agent", ParentSessionKey: "agent:root:main", SpawnDepth: &two,
			Seq: 1, Ts: baseTimestamp + 1,
		}, agentStreamData{Phase: "start"}); got != agentRunObservationRejected {
			t.Fatalf("emission=%d want rejected", got)
		}
	})
}

func TestAgentRunObservationCollectionAndDedupeWindow(t *testing.T) {
	router, store := newAgentRunObservationRouter(t, false)
	now := time.Date(2026, 7, 6, 16, 0, 0, 0, time.UTC)
	router.agentRunObservationNow = func() time.Time { return now }
	envelope := agentStreamEnvelope{
		RunID: "openclaw-run-window", Stream: "lifecycle", Seq: 1, Ts: 1783353600000,
	}
	data := agentStreamData{Phase: "start"}
	if got := router.emitAgentRunObservationV8(envelope, data); got != agentRunObservationDropped {
		t.Fatalf("disabled collection emission=%d", got)
	}
	if got := router.emitAgentRunObservationV8(envelope, data); got != agentRunObservationDuplicate {
		t.Fatalf("duplicate emission=%d", got)
	}
	if rows := agentRunRows(t, store); len(rows) != 0 {
		t.Fatalf("disabled collection persisted rows=%#v", rows)
	}
	now = now.Add(agentRunObservationTTL + time.Nanosecond)
	if got := router.emitAgentRunObservationV8(envelope, data); got != agentRunObservationDropped {
		t.Fatalf("post-expiry emission=%d", got)
	}
}

func TestAgentRunObservationCapacityEvictsExactlyTheOldestKey(t *testing.T) {
	router := NewEventRouter(nil, nil, nil, false)
	now := time.Date(2026, 7, 6, 16, 0, 0, 0, time.UTC)
	for sequence := int64(1); sequence <= agentRunObservationCapacity; sequence++ {
		router.insertAgentRunObservationLocked(agentRunObservationKey{
			connector: agentRunObservationConnector,
			runID:     "bounded-run",
			sequence:  sequence,
			timestamp: sequence,
			stream:    "lifecycle",
			event:     "start",
		}, now.Add(time.Duration(sequence)))
	}
	first := agentRunObservationKey{
		connector: agentRunObservationConnector, runID: "bounded-run", sequence: 1,
		timestamp: 1, stream: "lifecycle", event: "start",
	}
	second := first
	second.sequence, second.timestamp = 2, 2
	newest := first
	newest.sequence, newest.timestamp = agentRunObservationCapacity+1, agentRunObservationCapacity+1
	router.insertAgentRunObservationLocked(newest, now.Add(agentRunObservationCapacity+1))
	if len(router.agentRunObservationCache) != agentRunObservationCapacity ||
		len(router.agentRunObservationOrder) != agentRunObservationCapacity {
		t.Fatalf("cache/order size=%d/%d", len(router.agentRunObservationCache), len(router.agentRunObservationOrder))
	}
	if _, exists := router.agentRunObservationCache[first]; exists {
		t.Fatal("oldest key was not evicted")
	}
	if _, exists := router.agentRunObservationCache[second]; !exists {
		t.Fatal("second-oldest key was incorrectly evicted")
	}
	if _, exists := router.agentRunObservationCache[newest]; !exists {
		t.Fatal("newest key was not inserted")
	}
}

func newAgentRunObservationRouter(t *testing.T, collect bool) (*EventRouter, *audit.Store) {
	t.Helper()
	router, store, _ := newAgentRunObservationRouterWithPath(t, collect)
	return router, store
}

func newAgentRunObservationRouterWithPath(t *testing.T, collect bool) (*EventRouter, *audit.Store, string) {
	t.Helper()
	fixture := newSidecarRuntimeFixture(t, collect)
	router := NewEventRouter(nil, fixture.store, audit.NewLogger(fixture.store), false)
	bound := &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime}
	router.bindObservabilityV8Capabilities(bound, bound)
	return router, fixture.store, fixture.path
}

func agentRunRows(t *testing.T, store *audit.Store) []audit.Event {
	t.Helper()
	rows, err := store.ListEvents(32)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func agentRunRowsByRunID(t *testing.T, store *audit.Store) map[string]audit.Event {
	t.Helper()
	result := make(map[string]audit.Event)
	for _, row := range agentRunRows(t, store) {
		if runID, ok := row.Structured[observability.TelemetryAttributeDefenseClawAgentRunID].(string); ok {
			result[runID] = row
		}
	}
	return result
}

func assertAgentRunRow(
	t *testing.T,
	row audit.Event,
	runID string,
	event string,
	sequence int64,
	timestampMillis int64,
) {
	t.Helper()
	if row.Action != "lifecycle" || row.SessionID == "" || row.Connector != agentRunObservationConnector {
		t.Fatalf("envelope=%+v", row)
	}
	wants := map[string]any{
		observability.TelemetryAttributeDefenseClawAgentRunID:       runID,
		observability.TelemetryAttributeDefenseClawAgentRunEvent:    event,
		observability.TelemetryAttributeDefenseClawAgentRunSequence: float64(sequence),
	}
	for key, want := range wants {
		if row.Structured[key] != want {
			t.Fatalf("body[%q]=%#v want=%#v body=%#v", key, row.Structured[key], want, row.Structured)
		}
	}
	if row.Timestamp.IsZero() {
		t.Fatal("canonical receipt timestamp is missing")
	}
}

func assertAgentRunObservedAt(t *testing.T, path string, timestampMillis int64) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var raw string
	if err := database.QueryRow(`SELECT projected_record_json FROM audit_events
		WHERE event_name = 'agent.run.observed' ORDER BY rowid DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var projected map[string]any
	if err := json.Unmarshal([]byte(raw), &projected); err != nil {
		t.Fatal(err)
	}
	observedAt, ok := projected["observed_at"].(string)
	if !ok {
		t.Fatalf("projected observation has no observed_at: %#v", projected)
	}
	want := time.UnixMilli(timestampMillis).UTC().Format(time.RFC3339Nano)
	if observedAt != want {
		t.Fatalf("observed_at=%q want=%q", observedAt, want)
	}
}
