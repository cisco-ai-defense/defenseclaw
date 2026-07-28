// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

func newHookCorrelationServer(t *testing.T, path string) (*APIServer, *audit.Store) {
	t.Helper()
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return &APIServer{store: store}, store
}

func installCorrelationHMACForTest() {
	gatewaylog.SetTelemetryHMACSeed(bytes.Repeat([]byte{0x4a}, 32))
}

func persistCanonicalCorrelationObservation(
	t *testing.T,
	store *audit.Store,
	semanticEventID string,
	eventName string,
) {
	t.Helper()
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordObservation(t.Context(), audit.CorrelationObservation{
		RecordID:        "test-canonical-" + semanticEventID,
		SemanticEventID: audit.SemanticEventID(semanticEventID),
		Signal:          audit.CorrelationSignalLogs,
		Bucket:          "model_io",
		EventName:       eventName,
		ObservedAt:      time.Now().UTC(),
		Status:          audit.CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHookOccurrenceMintsOnlyAtReviewedBoundariesAndRestoresCursor(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	profile := server.hookProfileForConnector("claudecode")
	promptPayload := map[string]interface{}{
		"hook_event_name": "UserPromptSubmit", "session_id": "session-1", "prompt": "hello",
	}
	prompt := normalizeAgentHookRequestWithProfile("claudecode", promptPayload, profile)
	ctx, prompt, err := server.correlateHookOccurrence(t.Context(), profile, prompt, []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","prompt":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]string{
		"semantic": prompt.SemanticEventID, "logical": prompt.LogicalEventID,
		"connector instance": prompt.ConnectorInstanceID, "turn": prompt.TurnID, "agent": prompt.AgentID,
	} {
		parsed, parseErr := uuid.Parse(value)
		if parseErr != nil || parsed.Version() != 7 {
			t.Errorf("%s=%q is not UUIDv7", field, value)
		}
	}
	if got := audit.EnvelopeFromContext(ctx); got.SemanticEventID != prompt.SemanticEventID ||
		got.LogicalEventID != prompt.LogicalEventID || got.ConnectorInstanceID != prompt.ConnectorInstanceID ||
		got.TurnID != prompt.TurnID {
		t.Fatalf("context envelope=%+v prompt=%+v", got, prompt)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	server, reopened := newHookCorrelationServer(t, path)
	defer reopened.Close() //nolint:errcheck
	profile = server.hookProfileForConnector("claudecode")
	toolPayload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-1", "tool_name": "Read",
	}
	tool := normalizeAgentHookRequestWithProfile("claudecode", toolPayload, profile)
	_, tool, err = server.correlateHookOccurrence(t.Context(), profile, tool, []byte(`{"hook_event_name":"PreToolUse","session_id":"session-1","tool_name":"Read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tool.AgentID != prompt.AgentID || tool.TurnID != prompt.TurnID {
		t.Fatalf("restart lost cursor: prompt agent/turn=%s/%s tool=%s/%s", prompt.AgentID, prompt.TurnID, tool.AgentID, tool.TurnID)
	}
	if parsed, parseErr := uuid.Parse(tool.ToolInvocationID); parseErr != nil || parsed.Version() != 7 {
		t.Fatalf("minted tool id=%q err=%v", tool.ToolInvocationID, parseErr)
	}
}

func TestHookOccurrenceExactReceiptReplaySuppressesOnlyDuplicateEmission(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	payload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-2", "turn_id": "turn-2",
		"event_id": "delivery-2", "tool_use_id": "tool-2", "tool_name": "shell",
	}
	raw := []byte(`{"event_id":"delivery-2","hook_event_name":"PreToolUse","session_id":"session-2","tool_name":"shell","tool_use_id":"tool-2","turn_id":"turn-2"}`)
	first := normalizeAgentHookRequestWithProfile("codex", payload, profile)
	_, first, err := server.correlateHookOccurrence(t.Context(), profile, first, raw)
	if err != nil {
		t.Fatal(err)
	}
	if first.CorrelationReceipt == nil {
		t.Fatal("first hook receipt locator is missing")
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	second := normalizeAgentHookRequestWithProfile("codex", payload, profile)
	_, second, err = server.correlateHookOccurrence(t.Context(), profile, second, raw)
	if err != nil {
		t.Fatal(err)
	}
	if first.SuppressCorrelationEmit || second.SuppressCorrelationEmit {
		t.Fatalf("pending receipt suppressed before canonical persistence: first=%v second=%v",
			first.SuppressCorrelationEmit, second.SuppressCorrelationEmit)
	}
	if second.SemanticEventID != first.SemanticEventID || second.LogicalEventID != first.LogicalEventID {
		t.Fatalf("replay IDs first=%s/%s second=%s/%s", first.SemanticEventID, first.LogicalEventID, second.SemanticEventID, second.LogicalEventID)
	}
	persistCanonicalCorrelationObservation(t, store, first.SemanticEventID, "tool.start")
	if err := server.finalizeHookCorrelationReceipt(t.Context(), first.CorrelationReceipt); err != nil {
		t.Fatal(err)
	}
	third := normalizeAgentHookRequestWithProfile("codex", payload, profile)
	_, third, err = server.correlateHookOccurrence(t.Context(), profile, third, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !third.SuppressCorrelationEmit || third.SemanticEventID != first.SemanticEventID ||
		third.LogicalEventID != first.LogicalEventID {
		t.Fatalf("accepted exact replay was not suppressed: first=%+v third=%+v", first, third)
	}
	graph, err := repo.QueryGraph(t.Context(), audit.CorrelationGraphQuery{
		Anchor: audit.CorrelationAnchor{SemanticEventID: audit.SemanticEventID(first.SemanticEventID)},
		Page:   audit.CorrelationPageRequest{Limit: 10},
	})
	if err != nil || len(graph.Events) != 1 {
		t.Fatalf("graph events=%d err=%v", len(graph.Events), err)
	}
}

func TestHookOccurrenceSameReceiptWithDifferentFingerprintIsRetainedAsConflict(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	base := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-conflict", "turn_id": "turn-conflict",
		"event_id": "delivery-conflict", "tool_use_id": "tool-conflict", "tool_name": "shell",
	}
	first := normalizeAgentHookRequestWithProfile("codex", base, profile)
	_, first, err := server.correlateHookOccurrence(t.Context(), profile, first,
		[]byte(`{"event_id":"delivery-conflict","hook_event_name":"PreToolUse","session_id":"session-conflict","tool_name":"shell","tool_use_id":"tool-conflict","turn_id":"turn-conflict","tool_input":{"command":"first"}}`))
	if err != nil {
		t.Fatal(err)
	}
	second := normalizeAgentHookRequestWithProfile("codex", base, profile)
	_, second, err = server.correlateHookOccurrence(t.Context(), profile, second,
		[]byte(`{"event_id":"delivery-conflict","hook_event_name":"PreToolUse","session_id":"session-conflict","tool_name":"shell","tool_use_id":"tool-conflict","turn_id":"turn-conflict","tool_input":{"command":"changed"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.SuppressCorrelationEmit || second.SuppressCorrelationEmit {
		t.Fatalf("conflicting deliveries must both emit: first=%v second=%v", first.SuppressCorrelationEmit, second.SuppressCorrelationEmit)
	}
	if first.SemanticEventID == second.SemanticEventID || first.LogicalEventID == second.LogicalEventID {
		t.Fatalf("conflicting deliveries collapsed: first=%s/%s second=%s/%s",
			first.SemanticEventID, first.LogicalEventID, second.SemanticEventID, second.LogicalEventID)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	conflicts, err := repo.QueryConflicts(t.Context(), audit.CorrelationConflictsQuery{
		Anchor: audit.CorrelationAnchor{SemanticEventID: audit.SemanticEventID(second.SemanticEventID)},
		Page:   audit.CorrelationPageRequest{Limit: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts.Receipts) != 1 || len(conflicts.Relationships) != 1 ||
		conflicts.Receipts[0].SemanticEventID != audit.SemanticEventID(second.SemanticEventID) ||
		conflicts.Receipts[0].ConflictsWith != audit.SemanticEventID(first.SemanticEventID) {
		t.Fatalf("receipt conflict not explainable: %+v", conflicts)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(first.ConnectorInstanceID),
		Type:                audit.CorrelationOperationTool, Status: audit.CorrelationOperationActive, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 ||
		operations[0].StartSemanticEventID != audit.SemanticEventID(first.SemanticEventID) {
		t.Fatalf("conflicting receipt mutated pending state: %+v", operations)
	}
}

func TestHookReceiptUsesProviderDeliveryIDBeforeSharedItemIdentity(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")

	for index, eventID := range []string{"hook-delivery-a", "hook-delivery-b"} {
		payload := map[string]interface{}{
			"hook_event_name": "PreToolUse",
			"session_id":      "session-shared-item",
			"turn_id":         "turn-shared-item",
			"item_id":         "provider-item-shared",
			"event_id":        eventID,
			"tool_use_id":     "tool-shared-item",
			"tool_name":       "shell",
		}
		req := normalizeAgentHookRequestWithProfile("codex", payload, profile)
		if req.SourceEventID != eventID || req.SourceIDKind != "hook_event" {
			t.Fatalf("delivery %d canonical source=%q/%q want %q/hook_event",
				index, req.SourceEventID, req.SourceIDKind, eventID)
		}
		_, correlated, err := server.correlateHookOccurrence(t.Context(), profile, req,
			[]byte(fmt.Sprintf(`{"event_id":%q,"hook_event_name":"PreToolUse","item_id":"provider-item-shared","session_id":"session-shared-item","tool_name":"shell","tool_use_id":"tool-shared-item","turn_id":"turn-shared-item"}`, eventID)))
		if err != nil {
			t.Fatal(err)
		}
		if correlated.CorrelationReceipt == nil {
			t.Fatalf("delivery %d has no receipt", index)
		}
		persistCanonicalCorrelationObservation(t, store, correlated.SemanticEventID, "tool.start")
		if err := server.finalizeHookCorrelationReceipt(t.Context(), correlated.CorrelationReceipt); err != nil {
			t.Fatal(err)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	var receipts, conflicts int
	if err := database.QueryRow(`SELECT COUNT(*),
		SUM(CASE WHEN conflicts_with_semantic_event_id IS NOT NULL THEN 1 ELSE 0 END)
		FROM correlation_receipts`).Scan(&receipts, &conflicts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 || conflicts != 0 {
		t.Fatalf("provider delivery receipts=%d conflicts=%d want 2/0", receipts, conflicts)
	}
}

func TestHookOccurrenceToolStartAndEndRemainDistinctAcrossRestart(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	profile := server.hookProfileForConnector("claudecode")
	startPayload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-3", "turn_id": "turn-3",
		"agent_id": "agent-3", "tool_name": "Read",
	}
	start := normalizeAgentHookRequestWithProfile("claudecode", startPayload, profile)
	_, start, err := server.correlateHookOccurrence(t.Context(), profile, start, []byte(`{"hook_event_name":"PreToolUse","session_id":"session-3","turn_id":"turn-3","agent_id":"agent-3","tool_name":"Read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	server, reopened := newHookCorrelationServer(t, path)
	defer reopened.Close() //nolint:errcheck
	profile = server.hookProfileForConnector("claudecode")
	endPayload := map[string]interface{}{
		"hook_event_name": "PostToolUse", "session_id": "session-3", "turn_id": "turn-3",
		"agent_id": "agent-3", "tool_name": "Read",
	}
	end := normalizeAgentHookRequestWithProfile("claudecode", endPayload, profile)
	_, end, err = server.correlateHookOccurrence(t.Context(), profile, end, []byte(`{"hook_event_name":"PostToolUse","session_id":"session-3","turn_id":"turn-3","agent_id":"agent-3","tool_name":"Read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if end.ToolInvocationID != start.ToolInvocationID {
		t.Fatalf("pending tool join start=%q end=%q", start.ToolInvocationID, end.ToolInvocationID)
	}
	if end.SemanticEventID == start.SemanticEventID || end.LogicalEventID == start.LogicalEventID {
		t.Fatalf("pre/post collapsed: start=%s/%s end=%s/%s", start.SemanticEventID, start.LogicalEventID, end.SemanticEventID, end.LogicalEventID)
	}
	repo, err := reopened.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(start.ConnectorInstanceID),
		Type:                audit.CorrelationOperationTool, Status: audit.CorrelationOperationCompleted, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].StartSemanticEventID != audit.SemanticEventID(start.SemanticEventID) ||
		operations[0].TerminalSemanticEventID != audit.SemanticEventID(end.SemanticEventID) {
		t.Fatalf("resolved pending operations=%+v", operations)
	}
}

func TestCursorHookOccurrencePreservesNativeTurnAcrossToolLifecycleAndRestart(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	profile := server.hookProfileForConnector("cursor")

	promptPayload := map[string]interface{}{
		"hook_event_name": "beforeSubmitPrompt", "conversation_id": "cursor-conversation-1",
		"generation_id": "cursor-generation-1", "prompt": "inspect the repository",
	}
	prompt := normalizeAgentHookRequestWithProfile("cursor", promptPayload, profile)
	_, prompt, err := server.correlateHookOccurrence(t.Context(), profile, prompt,
		[]byte(`{"conversation_id":"cursor-conversation-1","generation_id":"cursor-generation-1","hook_event_name":"beforeSubmitPrompt","prompt":"inspect the repository"}`))
	if err != nil {
		t.Fatal(err)
	}
	if prompt.SessionID != "cursor-conversation-1" || prompt.TurnID != "cursor-generation-1" ||
		prompt.SourceEventID != "" || prompt.CorrelationReceipt != nil {
		t.Fatalf("cursor prompt identity=%+v", prompt)
	}
	if parsed, parseErr := uuid.Parse(prompt.AgentID); parseErr != nil || parsed.Version() != 7 {
		t.Fatalf("cursor prompt agent=%q err=%v", prompt.AgentID, parseErr)
	}

	startPayload := map[string]interface{}{
		"hook_event_name": "preToolUse", "conversation_id": "cursor-conversation-1",
		"generation_id": "cursor-generation-1", "tool_call_id": "cursor-tool-1",
		"tool_name": "Read",
	}
	start := normalizeAgentHookRequestWithProfile("cursor", startPayload, profile)
	_, start, err = server.correlateHookOccurrence(t.Context(), profile, start,
		[]byte(`{"conversation_id":"cursor-conversation-1","generation_id":"cursor-generation-1","hook_event_name":"preToolUse","tool_call_id":"cursor-tool-1","tool_name":"Read"}`))
	if err != nil {
		t.Fatal(err)
	}
	if start.SessionID != prompt.SessionID || start.TurnID != prompt.TurnID ||
		start.AgentID != prompt.AgentID || start.ToolInvocationID != "cursor-tool-1" ||
		start.CorrelationReceipt != nil {
		t.Fatalf("cursor tool start=%+v prompt=%+v", start, prompt)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	server, reopened := newHookCorrelationServer(t, path)
	defer reopened.Close() //nolint:errcheck
	profile = server.hookProfileForConnector("cursor")
	endPayload := map[string]interface{}{
		"hook_event_name": "postToolUse", "conversation_id": "cursor-conversation-1",
		"generation_id": "cursor-generation-1", "tool_call_id": "cursor-tool-1",
		"tool_name": "Read", "tool_result": "complete",
	}
	end := normalizeAgentHookRequestWithProfile("cursor", endPayload, profile)
	_, end, err = server.correlateHookOccurrence(t.Context(), profile, end,
		[]byte(`{"conversation_id":"cursor-conversation-1","generation_id":"cursor-generation-1","hook_event_name":"postToolUse","tool_call_id":"cursor-tool-1","tool_name":"Read","tool_result":"complete"}`))
	if err != nil {
		t.Fatal(err)
	}
	if end.SessionID != prompt.SessionID || end.TurnID != prompt.TurnID ||
		end.AgentID != prompt.AgentID || end.ToolInvocationID != start.ToolInvocationID ||
		end.CorrelationReceipt != nil {
		t.Fatalf("cursor tool end=%+v start=%+v prompt=%+v", end, start, prompt)
	}
	if prompt.SemanticEventID == start.SemanticEventID || start.SemanticEventID == end.SemanticEventID ||
		start.LogicalEventID == end.LogicalEventID || start.SuppressCorrelationEmit || end.SuppressCorrelationEmit {
		t.Fatalf("cursor phases collapsed or suppressed: prompt=%s start=%s/%s end=%s/%s",
			prompt.SemanticEventID, start.SemanticEventID, start.LogicalEventID,
			end.SemanticEventID, end.LogicalEventID)
	}

	repo, err := reopened.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(start.ConnectorInstanceID),
		OperationID:         "cursor-tool-1", Type: audit.CorrelationOperationTool,
		Status: audit.CorrelationOperationCompleted, Limit: 10,
	})
	if err != nil || len(operations) != 1 ||
		operations[0].StartSemanticEventID != audit.SemanticEventID(start.SemanticEventID) ||
		operations[0].TerminalSemanticEventID != audit.SemanticEventID(end.SemanticEventID) ||
		operations[0].SessionID != prompt.SessionID || operations[0].TurnID != prompt.TurnID {
		t.Fatalf("cursor completed operation=%+v err=%v", operations, err)
	}
}

func TestModernCursorCrossPhaseHooksWithoutDeliveryIDNeverSuppressEachOther(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("cursor")

	inputs := []struct {
		payload map[string]interface{}
		raw     string
	}{
		{
			payload: map[string]interface{}{
				"hook_event_name": "beforeSubmitPrompt", "conversation_id": "cursor-cross-phase",
				"generation_id": "cursor-cross-phase-generation", "prompt": "hello",
			},
			raw: `{"conversation_id":"cursor-cross-phase","generation_id":"cursor-cross-phase-generation","hook_event_name":"beforeSubmitPrompt","prompt":"hello"}`,
		},
		{
			payload: map[string]interface{}{
				"hook_event_name": "afterAgentResponse", "conversation_id": "cursor-cross-phase",
				"generation_id": "cursor-cross-phase-generation", "text": "done",
			},
			raw: `{"conversation_id":"cursor-cross-phase","generation_id":"cursor-cross-phase-generation","hook_event_name":"afterAgentResponse","text":"done"}`,
		},
	}
	results := make([]agentHookRequest, 0, len(inputs))
	for _, input := range inputs {
		req := normalizeAgentHookRequestWithProfile("cursor", input.payload, profile)
		_, correlated, err := server.correlateHookOccurrence(t.Context(), profile, req, []byte(input.raw))
		if err != nil {
			t.Fatal(err)
		}
		if correlated.SourceEventID != "" || correlated.CorrelationReceipt != nil ||
			correlated.SuppressCorrelationEmit {
			t.Fatalf("modern cursor phase unexpectedly receipt-controlled: %+v", correlated)
		}
		results = append(results, correlated)
	}
	if results[0].SessionID != results[1].SessionID || results[0].TurnID != results[1].TurnID ||
		results[0].AgentID != results[1].AgentID || results[0].SemanticEventID == results[1].SemanticEventID ||
		results[0].LogicalEventID == results[1].LogicalEventID {
		t.Fatalf("modern cursor cross-phase correlation=%+v", results)
	}

	var receipts int
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("modern cursor payloads created %d delivery receipts without a delivery ID", receipts)
	}
}

func TestCrossRailMirrorAuthorityIsScopedToLifecycle(t *testing.T) {
	spec := connector.DefaultCorrelationSpec("codex")

	tests := []struct {
		name      string
		lifecycle connector.CorrelationLifecycle
		want      []audit.CorrelationIdentifierKind
	}{
		{"model-start", connector.CorrelationLifecycleModelStart, nil},
		{"model-end", connector.CorrelationLifecycleModelEnd, nil},
		{"tool-start", connector.CorrelationLifecycleToolStart, []audit.CorrelationIdentifierKind{audit.CorrelationIdentifierTool}},
		{"tool-end", connector.CorrelationLifecycleToolEnd, []audit.CorrelationIdentifierKind{audit.CorrelationIdentifierTool}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compatibility := mirrorCompatibilityForRail(spec, audit.CorrelationRailHook, tc.lifecycle)
			if len(tc.want) == 0 {
				if compatibility != nil {
					t.Fatalf("unproven model lifecycle received mirror authority: %+v", compatibility)
				}
				return
			}
			if compatibility == nil {
				t.Fatal("missing source-proven tool lifecycle mirror compatibility")
			}
			if !slices.Equal(compatibility.EquivalentIdentifierKinds, tc.want) {
				t.Fatalf("kinds=%v want %v", compatibility.EquivalentIdentifierKinds, tc.want)
			}
		})
	}
}

func TestExactIdentityClaimsUseOnlyReportedSamePhaseOccurrenceIDs(t *testing.T) {
	installCorrelationHMACForTest()
	spec, ok := connector.CorrelationSpecForConnector("codex", "codex-hooks-v1")
	if !ok {
		t.Fatal("missing codex correlation profile")
	}
	instanceID, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	instance := audit.ConnectorInstanceID(instanceID)
	hookValues := []connector.CorrelationValue{
		{Target: connector.CorrelationTargetSession, Value: "session", Namespace: "codex", IDKind: "session", Origin: connector.CorrelationOriginReported},
		{Target: connector.CorrelationTargetModelResponse, Value: "response", Namespace: "codex", IDKind: "model_response", Origin: connector.CorrelationOriginReported},
		{Target: connector.CorrelationTargetTool, Value: "tool", Path: "tool_use_id", Namespace: "codex", IDKind: "tool_invocation", Origin: connector.CorrelationOriginReported},
	}
	hookClaims := correlationExactIdentityClaims(spec, instance, audit.CorrelationRailHook,
		connector.CorrelationLifecycleToolStart, hookValues)
	if len(hookClaims) != 1 || hookClaims[0].Kind != audit.CorrelationIdentifierTool ||
		hookClaims[0].CompatibleRail != audit.CorrelationRailNativeOTLP {
		t.Fatalf("hook exact claims=%+v", hookClaims)
	}
	nativeValues := append([]connector.CorrelationValue(nil), hookValues...)
	nativeValues[2].Path = "call_id"
	nativeClaims := correlationExactIdentityClaims(spec, instance, audit.CorrelationRailNativeOTLP,
		connector.CorrelationLifecycleToolStart, nativeValues)
	if len(nativeClaims) != 1 || nativeClaims[0].Kind != audit.CorrelationIdentifierTool ||
		nativeClaims[0].CompatibleRail != audit.CorrelationRailHook {
		t.Fatalf("native exact claims=%+v", nativeClaims)
	}
	hookValues[2].Origin = connector.CorrelationOriginDerived
	if claims := correlationExactIdentityClaims(spec, instance, audit.CorrelationRailHook,
		connector.CorrelationLifecycleToolStart, hookValues); len(claims) != 0 {
		t.Fatalf("derived tool ID received exact cross-rail authority: %+v", claims)
	}
}

func TestCorrelationValueDigestSeparatesIDKindAndTargetDomains(t *testing.T) {
	installCorrelationHMACForTest()
	instance := audit.ConnectorInstanceID("019b0000-0000-7000-8000-000000000001")
	base := connector.CorrelationValue{
		Target: connector.CorrelationTargetSourceEvent, Namespace: "codex",
		IDKind: "item", Value: "provider-reused-value",
	}
	baseDigest := correlationValueDigest(instance, base)
	otherKind := base
	otherKind.IDKind = "hook_event"
	otherTarget := base
	otherTarget.Target = connector.CorrelationTargetMessage
	if baseDigest == correlationValueDigest(instance, otherKind) {
		t.Fatal("correlation digest omitted provider ID kind")
	}
	if baseDigest == correlationValueDigest(instance, otherTarget) {
		t.Fatal("correlation digest omitted canonical target")
	}
}

func TestHookOccurrenceReportedToolStartResolvesMissingEndIDAcrossRestart(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	profile := server.hookProfileForConnector("claudecode")
	startPayload := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "reported-tool-session",
		"turn_id": "reported-tool-turn", "agent_id": "reported-tool-agent",
		"tool_name": "Read", "tool_use_id": "provider-tool-call-1",
	}
	start := normalizeAgentHookRequestWithProfile("claudecode", startPayload, profile)
	_, start, err := server.correlateHookOccurrence(t.Context(), profile, start,
		[]byte(`{"agent_id":"reported-tool-agent","hook_event_name":"PreToolUse","session_id":"reported-tool-session","tool_name":"Read","tool_use_id":"provider-tool-call-1","turn_id":"reported-tool-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if start.ToolInvocationID != "provider-tool-call-1" {
		t.Fatalf("reported tool ID changed: %q", start.ToolInvocationID)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	server, reopened := newHookCorrelationServer(t, path)
	defer reopened.Close() //nolint:errcheck
	profile = server.hookProfileForConnector("claudecode")
	endPayload := map[string]interface{}{
		"hook_event_name": "PostToolUse", "session_id": "reported-tool-session",
		"turn_id": "reported-tool-turn", "agent_id": "reported-tool-agent", "tool_name": "Read",
	}
	end := normalizeAgentHookRequestWithProfile("claudecode", endPayload, profile)
	_, end, err = server.correlateHookOccurrence(t.Context(), profile, end,
		[]byte(`{"agent_id":"reported-tool-agent","hook_event_name":"PostToolUse","session_id":"reported-tool-session","tool_name":"Read","turn_id":"reported-tool-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if end.ToolInvocationID != start.ToolInvocationID {
		t.Fatalf("missing tool end ID did not resolve reported start: start=%q end=%q",
			start.ToolInvocationID, end.ToolInvocationID)
	}
	repo, err := reopened.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(start.ConnectorInstanceID),
		Type:                audit.CorrelationOperationTool, Status: audit.CorrelationOperationCompleted, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].OperationID != "provider-tool-call-1" ||
		operations[0].TerminalSemanticEventID != audit.SemanticEventID(end.SemanticEventID) {
		t.Fatalf("reported tool pending resolution=%+v", operations)
	}
}

func TestHookOccurrenceExactTerminalIDNeverFallsBackToCurrentPendingOperation(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("claudecode")
	start := normalizeAgentHookRequestWithProfile("claudecode", map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "exact-terminal-session",
		"turn_id": "exact-terminal-turn", "agent_id": "exact-terminal-agent",
		"tool_name": "Read", "tool_use_id": "provider-tool-call-correct",
	}, profile)
	_, start, err := server.correlateHookOccurrence(t.Context(), profile, start,
		[]byte(`{"agent_id":"exact-terminal-agent","hook_event_name":"PreToolUse","session_id":"exact-terminal-session","tool_name":"Read","tool_use_id":"provider-tool-call-correct","turn_id":"exact-terminal-turn"}`))
	if err != nil {
		t.Fatal(err)
	}

	terminal := normalizeAgentHookRequestWithProfile("claudecode", map[string]interface{}{
		"hook_event_name": "PostToolUse", "session_id": "exact-terminal-session",
		"turn_id": "exact-terminal-turn", "agent_id": "exact-terminal-agent",
		"tool_name": "Read", "tool_use_id": "provider-tool-call-other",
	}, profile)
	_, terminal, err = server.correlateHookOccurrence(t.Context(), profile, terminal,
		[]byte(`{"agent_id":"exact-terminal-agent","hook_event_name":"PostToolUse","session_id":"exact-terminal-session","tool_name":"Read","tool_use_id":"provider-tool-call-other","turn_id":"exact-terminal-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if terminal.ToolInvocationID != "provider-tool-call-other" {
		t.Fatalf("exact terminal tool ID changed to contextual pending ID: %q", terminal.ToolInvocationID)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(start.ConnectorInstanceID),
		Type:                audit.CorrelationOperationTool, Status: audit.CorrelationOperationActive, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].OperationID != "provider-tool-call-correct" ||
		operations[0].TerminalSemanticEventID != "" {
		t.Fatalf("unrelated pending operation was resolved: %+v", operations)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	var falseJoins int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE from_kind='semantic_event' AND from_id=? AND to_kind='semantic_event' AND to_id=?`,
		terminal.SemanticEventID, start.SemanticEventID).Scan(&falseJoins); err != nil {
		t.Fatal(err)
	}
	if falseJoins != 0 {
		t.Fatalf("exact terminal mismatch created %d false start relationships", falseJoins)
	}
}

func TestHookOccurrenceReportedModelStartResolvesMissingEndIDAcrossRestart(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	profile := server.hookProfileForConnector("omnigent")
	startPayload := map[string]interface{}{
		"hook_event_name": "BeforeModel", "conversation_id": "reported-model-session",
		"response_id": "reported-model-turn", "agent_id": "reported-model-agent",
		"request_id": "provider-model-request-1",
	}
	start := normalizeAgentHookRequestWithProfile("omnigent", startPayload, profile)
	_, start, err := server.correlateHookOccurrence(t.Context(), profile, start,
		[]byte(`{"agent_id":"reported-model-agent","conversation_id":"reported-model-session","hook_event_name":"BeforeModel","request_id":"provider-model-request-1","response_id":"reported-model-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if start.ModelRequestID != "provider-model-request-1" {
		t.Fatalf("reported model request ID changed: %q", start.ModelRequestID)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	server, reopened := newHookCorrelationServer(t, path)
	defer reopened.Close() //nolint:errcheck
	profile = server.hookProfileForConnector("omnigent")
	endPayload := map[string]interface{}{
		"hook_event_name": "AfterModel", "conversation_id": "reported-model-session",
		"response_id": "reported-model-turn", "agent_id": "reported-model-agent",
	}
	end := normalizeAgentHookRequestWithProfile("omnigent", endPayload, profile)
	_, end, err = server.correlateHookOccurrence(t.Context(), profile, end,
		[]byte(`{"agent_id":"reported-model-agent","conversation_id":"reported-model-session","hook_event_name":"AfterModel","response_id":"reported-model-turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if end.ModelRequestID != start.ModelRequestID {
		t.Fatalf("missing model end ID did not resolve reported start: start=%q end=%q",
			start.ModelRequestID, end.ModelRequestID)
	}
	repo, err := reopened.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := repo.ListPendingOperations(t.Context(), audit.CorrelationPendingQuery{
		ConnectorInstanceID: audit.ConnectorInstanceID(start.ConnectorInstanceID),
		Type:                audit.CorrelationOperationModel, Status: audit.CorrelationOperationCompleted, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].OperationID != "provider-model-request-1" ||
		operations[0].TerminalSemanticEventID != audit.SemanticEventID(end.SemanticEventID) {
		t.Fatalf("reported model pending resolution=%+v", operations)
	}
}

func TestHookOccurrenceRejectsMalformedReportedSemanticID(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	req := normalizeAgentHookRequestWithProfile("codex", map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-invalid",
		"turn_id": "turn-invalid", "tool_use_id": "tool-invalid",
	}, profile)
	req.SemanticEventID = "not-a-uuidv7"
	if _, _, err := server.correlateHookOccurrence(t.Context(), profile, req, []byte(`{"hook_event_name":"PreToolUse"}`)); err == nil {
		t.Fatal("malformed reported semantic event ID was accepted")
	}
}

func TestHookOccurrenceRejectsConflictingTypedAliasesBeforePersistence(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	req := normalizeAgentHookRequestWithProfile("codex", map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-a",
		"sessionId":       "session-b",
		"turn_id":         "turn-1",
		"tool_use_id":     "tool-1",
	}, profile)
	if _, _, err := server.correlateHookOccurrence(t.Context(), profile, req,
		[]byte(`{"hook_event_name":"PreToolUse","sessionId":"session-b","session_id":"session-a","tool_use_id":"tool-1","turn_id":"turn-1"}`)); err == nil {
		t.Fatal("conflicting typed hook aliases were accepted")
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	for _, table := range []string{"correlation_connector_instances", "correlation_events", "correlation_identifiers"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("conflicting hook wrote %d rows to %s", count, table)
		}
	}
}

func TestOpenHandsActionIdentityIsPreservedWithoutBecomingToolInvocation(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("openhands")
	req := normalizeAgentHookRequestWithProfile("openhands", map[string]interface{}{
		"hook_event_name": "user_prompt_submit",
		"conversation_id": "conversation-1",
		"message_id":      "message-1",
		"action_id":       "action-1",
	}, profile)
	if req.ToolInvocationID != "" {
		t.Fatalf("action ID populated tool invocation before correlation: %+v", req)
	}
	_, correlated, err := server.correlateHookOccurrence(t.Context(), profile, req,
		[]byte(`{"action_id":"action-1","conversation_id":"conversation-1","hook_event_name":"user_prompt_submit","message_id":"message-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if correlated.ToolInvocationID != "" {
		t.Fatalf("action ID populated tool invocation after correlation: %+v", correlated)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	var actions, tools int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind='action' AND normalized_value='action-1'`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind='tool_invocation' AND normalized_value='action-1'`).Scan(&tools); err != nil {
		t.Fatal(err)
	}
	if actions != 1 || tools != 0 {
		t.Fatalf("action/tool identifier rows=%d/%d", actions, tools)
	}
}

func TestHookOccurrencePersistsReportedAgentAndSessionLineage(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	payload := map[string]interface{}{
		"hook_event_name":   "SubagentStart",
		"session_id":        "session-parent",
		"parent_session_id": "session-parent",
		"child_session_id":  "session-child",
		"parent_agent_id":   "agent-parent",
		"child_agent_id":    "agent-child",
		"tool_use_id":       "tool-spawn",
	}
	req := normalizeAgentHookRequestWithProfile("codex", payload, profile)
	_, req, err := server.correlateHookOccurrence(t.Context(), profile, req,
		[]byte(`{"child_agent_id":"agent-child","child_session_id":"session-child","hook_event_name":"SubagentStart","parent_agent_id":"agent-parent","parent_session_id":"session-parent","session_id":"session-parent","tool_use_id":"tool-spawn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.AgentID != "agent-child" || req.SessionID != "session-child" {
		t.Fatalf("subagent identity=%s/%s want agent-child/session-child", req.AgentID, req.SessionID)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	wants := []struct {
		fromKind, fromID, toKind, toID, relationship string
	}{
		{"agent", "agent-parent", "agent", "agent-child", "parent_of"},
		{"agent", "agent-child", "agent", "agent-parent", "delegated_by"},
		{"session", "session-parent", "session", "session-child", "parent_of"},
		{"agent", "agent-child", "tool_invocation", "tool-spawn", "caused_by"},
	}
	for _, want := range wants {
		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
			WHERE from_kind=? AND from_id=? AND to_kind=? AND to_id=?
			AND relationship_type=? AND method='reported' AND status='active'`,
			want.fromKind, want.fromID, want.toKind, want.toID, want.relationship).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("relationship %+v count=%d want 1", want, count)
		}
	}
	var evidence int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationship_evidence
		WHERE semantic_event_id=? AND integrity_state='verified'`, req.SemanticEventID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if evidence < len(wants) {
		t.Fatalf("lineage evidence=%d want at least %d", evidence, len(wants))
	}
}

func TestHookTraceContextIsTopologyNotSameOccurrenceAuthority(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	profile := server.hookProfileForConnector("codex")
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := repo.ResolveConnectorInstance(t.Context(), "codex", string(profile.Correlation.ProfileVersion), audit.ConnectorCustodyExternal)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tx, _, err := repo.BeginOccurrence(t.Context(), audit.CorrelationOccurrenceInput{Event: audit.CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: audit.LogicalEventID(semantic),
		Connector: "codex", ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: audit.CorrelationRailNativeOTLP, EventName: "tool_start", ReceivedTime: now,
		ProfileVersion: string(profile.Correlation.ProfileVersion), Completeness: audit.CorrelationComplete,
	}})
	if err != nil {
		t.Fatal(err)
	}
	const traceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const spanID = "bbbbbbbbbbbbbbbb"
	if err := tx.PutObservation(t.Context(), audit.CorrelationObservation{
		RecordID: "native-log-in-span", SemanticEventID: semantic,
		Signal: audit.CorrelationSignalLogs, Bucket: "agent", EventName: "tool_start",
		ObservedAt: now, TraceID: traceID, SpanID: spanID,
		Status: audit.CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	parsedTrace, _ := trace.TraceIDFromHex(traceID)
	parsedSpan, _ := trace.SpanIDFromHex(spanID)
	ctx := trace.ContextWithSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: parsedTrace, SpanID: parsedSpan, TraceFlags: trace.FlagsSampled,
	}))
	req := normalizeAgentHookRequestWithProfile("codex", map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "session-trace",
		"turn_id": "turn-trace", "tool_name": "Read",
	}, profile)
	_, correlated, err := server.correlateHookOccurrence(ctx, profile, req, []byte(`{"hook_event_name":"PreToolUse","session_id":"session-trace","tool_name":"Read","turn_id":"turn-trace"}`))
	if err != nil {
		t.Fatal(err)
	}
	if correlated.SemanticEventID == string(semantic) || correlated.LogicalEventID == string(semantic) {
		t.Fatalf("hook collapsed into a log merely because both shared trace/span: %+v", correlated)
	}
	graph, err := repo.QueryGraph(t.Context(), audit.CorrelationGraphQuery{
		Anchor: audit.CorrelationAnchor{
			SemanticEventID: audit.SemanticEventID(correlated.SemanticEventID),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawTrace, sawSpan bool
	for _, relationship := range graph.Relationships {
		switch relationship.ToKind {
		case audit.CorrelationNodeTrace:
			sawTrace = sawTrace || relationship.ToID == traceID
		case audit.CorrelationNodeSpan:
			if relationship.ToID == spanID {
				t.Fatalf("span relationship used ambiguous bare span ID: %+v", relationship)
			}
			sawSpan = sawSpan || relationship.ToID == traceID+":"+spanID
		}
	}
	if !sawTrace || !sawSpan {
		t.Fatalf("trace/span topology missing canonical identities: %+v", graph.Relationships)
	}
}
