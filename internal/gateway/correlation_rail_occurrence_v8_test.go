// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/google/uuid"
)

func TestLLMRailCanonicalEmissionFailureLeavesReceiptRetryable(t *testing.T) {
	installCorrelationHMACForTest()
	store := newLLMRailCorrelationStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	meta := llmEventMeta{
		SessionID: "session-canonical-retry", AgentID: "agent-canonical-retry",
		MessageID: "message-canonical-retry", SourceEventID: "message-canonical-retry",
		PromptID: "prompt-canonical-retry",
	}
	raw := `{"messageId":"message-canonical-retry","sessionKey":"session-canonical-retry"}`
	first := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta, raw)
	if first.receipt == nil {
		t.Fatal("first delivery did not retain an exact receipt")
	}
	emitFailure := errors.New("simulated local canonical persistence failure")
	if err := finalizeLLMRailCanonicalEmission(
		t.Context(), store, first.receipt, false, emitFailure,
	); !errors.Is(err, emitFailure) {
		t.Fatalf("canonical failure=%v want=%v", err, emitFailure)
	}
	retry := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta, raw)
	if retry.suppressEmission {
		t.Fatal("failed canonical persistence suppressed an exact retry")
	}

	envelope := audit.EnvelopeFromContext(first.ctx)
	persistCanonicalCorrelationObservation(t, store, envelope.SemanticEventID, "model.start")
	if err := finalizeLLMRailCanonicalEmission(
		t.Context(), store, first.receipt, true, nil,
	); err != nil {
		t.Fatal(err)
	}
	acceptedReplay := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta, raw)
	if !acceptedReplay.suppressEmission {
		t.Fatal("canonically persisted exact replay was not suppressed")
	}
}

func newLLMRailCorrelationStore(t *testing.T, path string) *audit.Store {
	t.Helper()
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return store
}

func correlateOpenClawStream(
	t *testing.T,
	store *audit.Store,
	lifecycle connector.CorrelationLifecycle,
	meta llmEventMeta,
	raw string,
) llmRailCorrelationResult {
	t.Helper()
	result, err := correlateLLMRailOccurrence(t.Context(), llmRailCorrelationInput{
		store: store, spec: connector.DefaultCorrelationSpec("openclaw"),
		rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
		lifecycle: lifecycle, meta: meta, rawPayload: []byte(raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLLMStreamRailRestoresExactPromptAcrossRestartWithoutTreatingMessageAsTurn(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	store := newLLMRailCorrelationStore(t, path)

	start := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, llmEventMeta{
		SessionID: "session-stream-1", AgentID: "agent-stream-1", RunID: "run-stream-1",
		MessageID: "message-stream-1", SourceEventID: "message-stream-1", SourceSequence: "1",
		PromptID: "prompt-stream-1",
	}, `{"messageId":"message-stream-1","runId":"run-stream-1","sequence":1,"sessionKey":"session-stream-1"}`)
	startEnvelope := audit.EnvelopeFromContext(start.ctx)
	if start.meta.TurnID == "" || start.meta.TurnID == start.meta.MessageID ||
		startEnvelope.TurnID != start.meta.TurnID {
		t.Fatalf("stream start turn=%q message=%q envelope=%+v", start.meta.TurnID, start.meta.MessageID, startEnvelope)
	}
	parsed, err := uuid.Parse(start.meta.TurnID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("minted stream turn=%q err=%v", start.meta.TurnID, err)
	}
	if start.receipt == nil {
		t.Fatal("stream prompt did not retain its exact message delivery receipt")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = newLLMRailCorrelationStore(t, path)
	defer store.Close() //nolint:errcheck
	end := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelEnd, llmEventMeta{
		SessionID: "session-stream-1", AgentID: "agent-stream-1", RunID: "run-stream-1",
		MessageID: "message-stream-2", SourceEventID: "message-stream-2", SourceSequence: "2",
		PromptID: "prompt-stream-1", ResponseID: "response-stream-1", ResponseIDReported: true,
	}, `{"messageId":"message-stream-2","response_id":"response-stream-1","runId":"run-stream-1","sequence":2,"sessionKey":"session-stream-1"}`)
	if end.meta.TurnID != start.meta.TurnID {
		t.Fatalf("restart lost exact prompt handoff: start turn=%q end turn=%q", start.meta.TurnID, end.meta.TurnID)
	}
	if end.meta.TurnID == end.meta.MessageID {
		t.Fatalf("terminal message ID became turn ID: %+v", end.meta)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	var messageKind, messageAsTurn, completed int
	if err := database.QueryRow(`SELECT
		SUM(CASE WHEN identifier_kind='message' AND normalized_value='message-stream-1' THEN 1 ELSE 0 END),
		SUM(CASE WHEN identifier_kind='turn' AND normalized_value='message-stream-1' THEN 1 ELSE 0 END)
		FROM correlation_identifiers`).Scan(&messageKind, &messageAsTurn); err != nil {
		t.Fatal(err)
	}
	if messageKind != 1 || messageAsTurn != 0 {
		t.Fatalf("message identifier count=%d message-as-turn=%d", messageKind, messageAsTurn)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_pending_operations
		WHERE operation_id='prompt-stream-1' AND operation_type='model' AND status='completed'
		AND turn_id=?`, start.meta.TurnID).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if completed != 1 {
		t.Fatalf("completed durable model operation count=%d", completed)
	}
}

func TestLLMStreamRailSuppressesAcceptedReplayAndRetainsFingerprintConflict(t *testing.T) {
	installCorrelationHMACForTest()
	store := newLLMRailCorrelationStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	meta := llmEventMeta{
		SessionID: "session-replay", AgentID: "agent-replay", MessageID: "message-replay",
		SourceEventID: "message-replay", PromptID: "prompt-replay",
	}
	raw := `{"messageId":"message-replay","sessionKey":"session-replay","text":"same"}`
	first := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta, raw)
	if first.receipt == nil {
		t.Fatal("first stream delivery has no receipt")
	}
	firstEnvelope := audit.EnvelopeFromContext(first.ctx)
	persistCanonicalCorrelationObservation(t, store, firstEnvelope.SemanticEventID, "model.start")
	if err := finalizeLLMRailCorrelationReceipt(t.Context(), store, first.receipt); err != nil {
		t.Fatal(err)
	}
	replay := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta, raw)
	if !replay.suppressEmission {
		t.Fatal("accepted exact stream replay was not suppressed")
	}
	replayEnvelope := audit.EnvelopeFromContext(replay.ctx)
	if replayEnvelope.SemanticEventID != firstEnvelope.SemanticEventID ||
		replayEnvelope.LogicalEventID != firstEnvelope.LogicalEventID {
		t.Fatalf("replay identity changed: first=%+v replay=%+v", firstEnvelope, replayEnvelope)
	}

	conflict := correlateOpenClawStream(t, store, connector.CorrelationLifecycleModelStart, meta,
		`{"messageId":"message-replay","sessionKey":"session-replay","text":"changed"}`)
	conflictEnvelope := audit.EnvelopeFromContext(conflict.ctx)
	if conflict.suppressEmission || conflictEnvelope.SemanticEventID == firstEnvelope.SemanticEventID ||
		conflictEnvelope.LogicalEventID == firstEnvelope.LogicalEventID {
		t.Fatalf("changed delivery collapsed into replay: first=%+v conflict=%+v", firstEnvelope, conflictEnvelope)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	conflicts, err := repo.QueryConflicts(t.Context(), audit.CorrelationConflictsQuery{
		Anchor: audit.CorrelationAnchor{SemanticEventID: audit.SemanticEventID(conflictEnvelope.SemanticEventID)},
		Page:   audit.CorrelationPageRequest{Limit: 10},
	})
	if err != nil || len(conflicts.Receipts) != 1 ||
		conflicts.Receipts[0].ConflictsWith != audit.SemanticEventID(firstEnvelope.SemanticEventID) {
		t.Fatalf("stream receipt conflict=%+v err=%v", conflicts, err)
	}
}

func TestLLMRailReceiptsAreScopedByRail(t *testing.T) {
	installCorrelationHMACForTest()
	store := newLLMRailCorrelationStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	spec := connector.DefaultCorrelationSpec("openclaw")
	// The production OpenClaw proxy has no source-event field. Add one only to
	// exercise the generic coordinator's rail scoping with the same reviewed
	// source value on both authenticated channels.
	spec.ProxyBindings = append(spec.ProxyBindings, connector.CorrelationFieldBinding{
		Target: connector.CorrelationTargetSourceEvent, Paths: []string{"messageId"},
		Origin: connector.CorrelationOriginReported, Namespace: "openclaw", IDKind: "message_event",
	})
	meta := llmEventMeta{
		SessionID: "session-rails", AgentID: "agent-rails", MessageID: "delivery-across-rails",
		SourceEventID: "delivery-across-rails",
	}
	stream, err := correlateLLMRailOccurrence(t.Context(), llmRailCorrelationInput{
		store: store, spec: spec, rail: audit.CorrelationRailStream,
		surface: connector.CorrelationSurfaceStream, lifecycle: connector.CorrelationLifecycleModelStart,
		meta: meta, rawPayload: []byte(`{"messageId":"delivery-across-rails"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	meta.PromptID = "proxy-prompt"
	proxy, err := correlateLLMRailOccurrence(t.Context(), llmRailCorrelationInput{
		store: store, spec: spec, rail: audit.CorrelationRailProxy,
		surface: connector.CorrelationSurfaceProxy, lifecycle: connector.CorrelationLifecycleModelStart,
		meta: meta, rawPayload: []byte(`{"messageId":"delivery-across-rails"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stream.receipt == nil || proxy.receipt == nil ||
		stream.receipt.SourceKeyDigest == proxy.receipt.SourceKeyDigest {
		t.Fatalf("rail-scoped receipt locators stream=%+v proxy=%+v", stream.receipt, proxy.receipt)
	}
	if stream.suppressEmission || proxy.suppressEmission {
		t.Fatalf("first delivery on either rail was suppressed: stream=%v proxy=%v",
			stream.suppressEmission, proxy.suppressEmission)
	}
}

func TestLLMProxyTransportRequestNeverBecomesTurn(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	store := newLLMRailCorrelationStore(t, path)
	defer store.Close() //nolint:errcheck
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{RequestID: "transport-request-1"})
	result, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
		store: store, spec: connector.DefaultCorrelationSpec("zeptoclaw"),
		rail: audit.CorrelationRailProxy, surface: connector.CorrelationSurfaceProxy,
		lifecycle:  connector.CorrelationLifecycleModelStart,
		meta:       llmEventMeta{RequestID: "transport-request-1", PromptID: "provider-request-1"},
		rawPayload: []byte(`{"provider_request_id":"provider-request-1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := audit.EnvelopeFromContext(result.ctx)
	if result.meta.TurnID != "" || envelope.TurnID != "" || envelope.RequestID != "transport-request-1" {
		t.Fatalf("transport request/turn conflated: meta=%+v envelope=%+v", result.meta, envelope)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close() //nolint:errcheck
	var requestAsTurn int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind='turn' AND normalized_value='transport-request-1'`).Scan(&requestAsTurn); err != nil {
		t.Fatal(err)
	}
	if requestAsTurn != 0 {
		t.Fatalf("transport request persisted as turn %d times", requestAsTurn)
	}
}

func TestLLMRailGraphFailureEmitsNothing(t *testing.T) {
	installCorrelationHMACForTest()
	store := newLLMRailCorrelationStore(t, filepath.Join(t.TempDir(), "audit.db"))
	capture := &correlationRelationshipRecordCapture{}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := correlateLLMRailOccurrence(t.Context(), llmRailCorrelationInput{
		store: store, emitter: capture, spec: connector.DefaultCorrelationSpec("openclaw"),
		rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
		lifecycle: connector.CorrelationLifecycleModelStart,
		meta: llmEventMeta{SessionID: "session-closed", AgentID: "agent-closed",
			MessageID: "message-closed", SourceEventID: "message-closed", PromptID: "prompt-closed"},
		rawPayload: []byte(`{"messageId":"message-closed"}`),
	})
	if err == nil {
		t.Fatal("closed correlation store unexpectedly accepted an occurrence")
	}
	if len(capture.records) != 0 {
		t.Fatalf("graph failure exported %d records", len(capture.records))
	}
}
