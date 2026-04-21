// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestJudgeStore_PersistJudgeEventV7Columns(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "judge.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	js := NewJudgeStore(store)
	ctx := ContextWithRequestID(
		ContextWithSessionID(
			ContextWithTraceID(
				ContextWithAgentIdentity(t.Context(), AgentIdentity{
					AgentID:           "agent-logical",
					AgentInstanceID:   "agent-inst-1",
					SidecarInstanceID: "sidecar-uuid",
				}),
				"abcdabcdabcdabcdabcdabcdabcdabcd",
			),
			"sess-99",
		),
		"req-judge-1",
	)

	t.Setenv("DEFENSECLAW_RUN_ID", "run-judge-test")

	p := gatewaylog.JudgePayload{
		Kind:        "injection",
		Model:       "anthropic/claude",
		InputBytes:  100,
		LatencyMs:   12,
		Action:      "allow",
		Severity:    gatewaylog.SeverityInfo,
		RawResponse: `{"Instruction Manipulation":{"label":false}}`,
	}
	if err := js.PersistJudgeEvent(ctx, gatewaylog.DirectionPrompt, p, "my_tool", "tid-1", "pol-1", "app:x"); err != nil {
		t.Fatalf("PersistJudgeEvent: %v", err)
	}

	rows, err := store.ListJudgeResponses(5)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	r := rows[0]
	if r.Kind != "injection" || r.Model != "anthropic/claude" {
		t.Fatalf("kind/model: %+v", r)
	}
	if r.RequestID != "req-judge-1" || r.TraceID != "abcdabcdabcdabcdabcdabcdabcdabcd" || r.SessionID != "sess-99" {
		t.Fatalf("correlation: %+v", r)
	}
	if r.RunID != "run-judge-test" {
		t.Fatalf("run_id=%q", r.RunID)
	}
	if r.SchemaVersion == 0 && r.BinaryVersion == "" {
		t.Fatalf("expected some provenance stamp: %+v", r)
	}
	if r.AgentID != "agent-logical" || r.AgentInstanceID != "agent-inst-1" || r.SidecarInstanceID != "sidecar-uuid" {
		t.Fatalf("identity: %+v", r)
	}
	if r.PolicyID != "pol-1" || r.DestinationApp != "app:x" || r.ToolName != "my_tool" || r.ToolID != "tid-1" {
		t.Fatalf("tool/policy: %+v", r)
	}
	if r.InputHash == "" || r.Raw == "" {
		t.Fatalf("expected raw+input_hash: %+v", r)
	}
}
