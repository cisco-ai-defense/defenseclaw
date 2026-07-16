// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestNetworkEgressV8RuntimeOwnsAllowedAndBlockedLogs(t *testing.T) {
	for _, test := range []struct {
		name      string
		blocked   bool
		admission router.Admission
		eventName string
		outcome   observability.Outcome
		mandatory bool
	}{
		{name: "allowed", eventName: observability.TelemetryEventEgressAllowed, outcome: observability.OutcomeAllowed},
		{name: "blocked", blocked: true, eventName: observability.TelemetryEventEgressBlocked,
			outcome: observability.OutcomeBlocked, mandatory: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)

			event := NetworkEgressEvent{
				SessionID: "session-1", Connector: "codex", AgentID: "agent-1",
				RootAgentID: "agent-root", ParentAgentID: "agent-parent", RootSessionID: "session-root",
				AgentLifecycleID: "lifecycle-1", AgentExecutionID: "execution-1",
				UserID: "user-1", ToolID: "call-1",
				Hostname: "api.example.com", URL: "https://api.example.com/v1/chat?api-key=secret",
				HTTPMethod: "POST", Protocol: "https", DecisionCode: "NETWORK_POLICY_DECISION",
				PolicyOutcome: "policy evaluated", Details: "matched policy", Blocked: test.blocked,
			}
			if err := logger.LogNetworkEgress(context.Background(), event); err != nil {
				t.Fatalf("LogNetworkEgress: %v", err)
			}
			forensic, err := logger.store.ListNetworkEgressEvents(10, event.Hostname)
			if err != nil || len(forensic) != 1 {
				t.Fatalf("forensic rows=%d err=%v, want 1", len(forensic), err)
			}
			rows, err := logger.store.ListEvents(10)
			metadata, records := runtime.snapshot()
			if err != nil || len(rows) != 1 || len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("rows=%d metadata=%d records=%d err=%v", len(rows), len(metadata), len(records), err)
			}
			record := records[0]
			if record.EventName() != observability.EventName(test.eventName) ||
				record.Bucket() != observability.BucketNetworkEgress || record.Outcome() != test.outcome ||
				record.Mandatory() != test.mandatory || metadata[0].Identity() != record.Identity() ||
				metadata[0].Source() != observability.SourceGateway || rows[0].ID != record.RecordID() {
				t.Fatalf("record=%#v metadata=%#v row=%#v", record.Identity(), metadata[0].Identity(), rows[0])
			}
			body := securityActionBody(t, record)
			for key, want := range map[string]any{
				"gen_ai.conversation.id":             event.SessionID,
				"gen_ai.agent.id":                    event.AgentID,
				"defenseclaw.agent.root.id":          event.RootAgentID,
				"defenseclaw.agent.parent.id":        event.ParentAgentID,
				"defenseclaw.session.root.id":        event.RootSessionID,
				"defenseclaw.agent.lifecycle.id":     event.AgentLifecycleID,
				"defenseclaw.agent.execution.id":     event.AgentExecutionID,
				"user.id":                            event.UserID,
				"gen_ai.tool.call.id":                event.ToolID,
				"defenseclaw.network.target_ref":     event.Hostname,
				"defenseclaw.network.target_path":    "/v1/chat",
				"defenseclaw.network.policy_outcome": event.PolicyOutcome,
				"defenseclaw.network.decision_code":  event.DecisionCode,
				"defenseclaw.network.blocked":        test.blocked,
				"url.scheme":                         "https",
				"server.address":                     event.Hostname,
			} {
				if body[key] != want {
					t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], want, body)
				}
			}
			if _, exists := body["url.full"]; exists {
				t.Fatalf("egress log unexpectedly retained full URL: %#v", body)
			}
		})
	}
}

func TestNetworkEgressV8CollectionDropSuppressesCanonicalAndLegacyFanout(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionDrop)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogNetworkEgress(context.Background(), NetworkEgressEvent{
		Hostname: "api.example.com", PolicyOutcome: "allowed", Blocked: false,
	}); err != nil {
		t.Fatalf("LogNetworkEgress: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	metadata, records := runtime.snapshot()
	if err != nil || len(rows) != 0 || len(metadata) != 1 || len(records) != 0 {
		t.Fatalf("drop rows=%d metadata=%d records=%d err=%v", len(rows), len(metadata), len(records), err)
	}
}

func TestNetworkEgressV8BlockedFloorIsContentFree(t *testing.T) {
	const canary = "egress-secret-719f"
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogNetworkEgress(context.Background(), NetworkEgressEvent{
		Hostname: "blocked.example", URL: "https://blocked.example/" + canary,
		PolicyOutcome: "denied " + canary, Details: canary, Blocked: true,
	}); err != nil {
		t.Fatalf("LogNetworkEgress: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	_, records := runtime.snapshot()
	if err != nil || len(rows) != 1 || len(records) != 1 || !records[0].IsFloorOnly() ||
		records[0].EventName() != observability.EventName(observability.TelemetryEventEgressBlocked) {
		t.Fatalf("floor rows=%d records=%d err=%v", len(rows), len(records), err)
	}
	assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
}

func TestNetworkEgressV8UnavailableRuntimeFailsBeforePersistenceOrFanout(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*Logger)
	}{
		{name: "never_bound", setup: func(*Logger) {}},
		{name: "detached", setup: func(logger *Logger) {
			logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
			logger.SetRuntimeV8Emitter(nil)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			test.setup(logger)
			err := logger.LogNetworkEgress(context.Background(), NetworkEgressEvent{
				Hostname: "blocked.example", PolicyOutcome: "blocked", Blocked: true,
			})
			if err == nil {
				t.Fatal("unavailable v8 runtime did not reject occurrence")
			}
			forensic, listErr := logger.store.ListNetworkEgressEvents(10, "blocked.example")
			if listErr != nil || len(forensic) != 0 {
				t.Fatalf("unavailable runtime persisted forensic rows=%d err=%v", len(forensic), listErr)
			}
		})
	}
}
