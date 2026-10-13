// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

type correlationRelationshipRecordCapture struct {
	records []observability.Record
}

func (capture *correlationRelationshipRecordCapture) Emit(
	_ context.Context,
	_ router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	capture.records = append(capture.records, record)
	return pipeline.LocalLogOutcome{}, nil
}

func TestCommittedCorrelationRelationshipBuildsExplainableExportLog(t *testing.T) {
	capture := &correlationRelationshipRecordCapture{}
	semantic := audit.SemanticEventID("019b2b7b-9f8c-7ea0-8757-3e064bcd9991")
	logical := audit.LogicalEventID("019b2b7b-9f8c-7ea0-8757-3e064bcd9992")
	instance := audit.ConnectorInstanceID("019b2b7b-9f8c-7ea0-8757-3e064bcd9993")
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		TraceID: "0123456789abcdef0123456789abcdef", RequestID: "request-1",
		SessionID: "session-1", TurnID: "turn-1", AgentID: "agent-1",
		AgentInstanceID: "agent-instance-1", PolicyID: "policy-1", ToolID: "tool-1",
	})
	err := emitCorrelationRelationshipsV8WithEmitter(
		ctx, capture, observability.SourceConnector, "codex", semantic, logical, instance,
		[]audit.CorrelationRelationship{{
			RelationshipID: "rel-0123456789abcdef", FromKind: audit.CorrelationNodeSemanticEvent,
			FromID: string(semantic), ToKind: audit.CorrelationNodeSemanticEvent,
			ToID: "019b2b7b-9f8c-7ea0-8757-3e064bcd9994", Type: audit.CorrelationCorrelatesWith,
			Method: audit.CorrelationMethodInferred, Confidence: 50,
			RuleID: "bounded-similarity", RuleVersion: "codex-correlation-v1",
			EvidenceCount: 3,
			Status:        audit.CorrelationRelationshipCandidate, CreatedAt: time.Now().UTC(),
		}, {
			// GAP-0423: an occurrence that only added evidence exports nothing.
			RelationshipID: "rel-fedcba9876543210", FromKind: audit.CorrelationNodeSemanticEvent,
			FromID: string(semantic), ToKind: audit.CorrelationNodeSession, ToID: "session-1",
			Type: audit.CorrelationBelongsTo, Method: audit.CorrelationMethodReported, Confidence: 95,
			RuleID: "session-membership", RuleVersion: "codex-correlation-v1", EvidenceCount: 37,
			Status: audit.CorrelationRelationshipActive, Unchanged: true,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.records) != 1 {
		t.Fatalf("records=%d want 1", len(capture.records))
	}
	record := capture.records[0]
	if record.Bucket() != observability.BucketTelemetryIngest ||
		record.EventName() != observability.EventName(observability.TelemetryEventCorrelationRelationshipChanged) {
		t.Fatalf("identity=%+v", record.Identity())
	}
	correlation := record.Correlation()
	if correlation.SemanticEventID != string(semantic) || correlation.LogicalEventID != string(logical) ||
		correlation.ConnectorInstanceID != string(instance) {
		t.Fatalf("correlation=%+v", correlation)
	}
	for field, want := range map[string]string{
		"trace": "0123456789abcdef0123456789abcdef", "request": "request-1",
		"session": "session-1", "turn": "turn-1", "agent": "agent-1",
		"agent instance": "agent-instance-1", "policy": "policy-1", "tool": "tool-1",
	} {
		got := map[string]string{
			"trace": correlation.TraceID, "request": correlation.RequestID,
			"session": correlation.SessionID, "turn": correlation.TurnID,
			"agent": correlation.AgentID, "agent instance": correlation.AgentInstanceID,
			"policy": correlation.PolicyID, "tool": correlation.ToolInvocationID,
		}[field]
		if got != want {
			t.Errorf("%s=%q want %q", field, got, want)
		}
	}
	body, ok := record.Body()
	if !ok {
		t.Fatal("relationship log has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"defenseclaw.correlation.relationship.id":           "rel-0123456789abcdef",
		"defenseclaw.correlation.relationship.type":         "correlates_with",
		"defenseclaw.correlation.relationship.source_kind":  "semantic_event",
		"defenseclaw.correlation.relationship.target_kind":  "semantic_event",
		"defenseclaw.correlation.relationship.method":       "inferred",
		"defenseclaw.correlation.relationship.status":       "unresolved",
		"defenseclaw.correlation.relationship.rule_id":      "bounded-similarity",
		"defenseclaw.correlation.relationship.rule_version": "codex-correlation-v1",
	} {
		if got := object[key]; got != want {
			t.Errorf("%s=%v want %v", key, got, want)
		}
	}
	for key, want := range map[string]string{
		"defenseclaw.correlation.relationship.confidence":     "0.5",
		"defenseclaw.correlation.relationship.evidence_count": "3",
	} {
		got, ok := object[key].(json.Number)
		if !ok || got.String() != want {
			t.Errorf("%s=%v want numeric %s", key, object[key], want)
		}
	}
}

// GAP-0087: a native Codex log reports conversation.id but no agent, so its
// relationship rows take the session agent the hook rows carry.
func TestCorrelationRelationshipContextTakesSessionAgent(t *testing.T) {
	InstallSharedAgentRegistry("", "")
	api := &APIServer{}
	sessionOnly := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{SessionID: "session-1"})
	got := audit.EnvelopeFromContext(api.contextWithSessionAgentV8(sessionOnly, "codex")).AgentID
	// The root agent the session's hooks record, scoped by the agent
	// identity the hook path derives (GAP-0232).
	hookCtx := enrichAgentHookContext(t.Context(), agentHookRequest{ConnectorName: "codex", SessionID: "session-1"})
	if root := hookLLMEventMeta(hookCtx, "codex", "session-1", "", "", "", "", "", "", map[string]interface{}{}).AgentID; got != root {
		t.Fatalf("no hook snapshot: agent=%q want conversation root %q", got, root)
	}
	api.rememberHookSessionState(t.Context(), llmEventMeta{
		Source: "codex", SessionID: "session-1", AgentID: "agent-live",
		AgentIdentityID: nativeSessionAgentScopeV8(sessionOnly, "codex", "session-1"),
		LifecycleEvent:  "session_start",
	})
	if got := audit.EnvelopeFromContext(api.contextWithSessionAgentV8(sessionOnly, "codex")).AgentID; got != "agent-live" {
		t.Fatalf("hook snapshot: agent=%q want agent-live", got)
	}
}

// GAP-0755: a native relationship must not inherit another caller's hook agent
// when two authenticated users report the same conversation ID.
func TestCorrelationRelationshipContextKeepsAuthenticatedIdentity(t *testing.T) {
	InstallSharedAgentRegistry("", "")
	api := &APIServer{}
	const session = "shared-conversation"
	first := ContextWithAgentIdentity(t.Context(), AgentIdentity{IdentityID: "agt-first", UserID: "1001"})
	second := ContextWithAgentIdentity(t.Context(), AgentIdentity{IdentityID: "agt-second", UserID: "1002"})
	api.rememberHookSessionState(first, llmEventMeta{
		Source: "codex", SessionID: session, AgentID: "first-agent",
		AgentIdentityID: "agt-first", UserID: "1001", LifecycleEvent: "session_start",
	})
	api.rememberHookSessionState(second, llmEventMeta{
		Source: "codex", SessionID: session, AgentID: "second-agent",
		AgentIdentityID: "agt-second", UserID: "1002", LifecycleEvent: "session_start",
	})
	for _, tc := range []struct {
		ctx  context.Context
		want string
	}{
		{first, "first-agent"},
		{second, "second-agent"},
	} {
		ctx := audit.ContextWithEnvelope(tc.ctx, audit.CorrelationEnvelope{SessionID: session})
		if got := audit.EnvelopeFromContext(api.contextWithSessionAgentV8(ctx, "codex")).AgentID; got != tc.want {
			t.Fatalf("agent=%q want %q", got, tc.want)
		}
	}
}
