// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newCorrelationTestStore(t *testing.T) (*Store, *CorrelationRepository) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	return store, repo
}

func mustJSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func requireExactJSONKeys(t *testing.T, object map[string]any, keys ...string) {
	t.Helper()
	if len(object) != len(keys) {
		t.Fatalf("json keys=%v want=%v", object, keys)
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			t.Fatalf("json object missing key %q: %v", key, object)
		}
	}
}

func requireJSONMapField(t *testing.T, object map[string]any, field string) map[string]any {
	t.Helper()
	result, ok := object[field].(map[string]any)
	if !ok {
		t.Fatalf("json field %q is %T, want object", field, object[field])
	}
	return result
}

func requireFirstJSONMap(t *testing.T, object map[string]any, field string) map[string]any {
	t.Helper()
	values, ok := object[field].([]any)
	if !ok || len(values) == 0 {
		t.Fatalf("json field %q is %T/%v, want non-empty array", field, object[field], object[field])
	}
	result, ok := values[0].(map[string]any)
	if !ok {
		t.Fatalf("json field %q entry is %T, want object", field, values[0])
	}
	return result
}

func TestCorrelationQueryResponsesUseStableSnakeCaseJSON(t *testing.T) {
	graph := CorrelationGraph{
		Events: []CorrelationEvent{{}}, Observations: []CorrelationObservation{{}},
		Relationships: []CorrelationRelationship{{}}, Evidence: []CorrelationRelationshipEvidence{{}},
	}
	explanation := mustJSONMap(t, CorrelationExplanation{Graph: graph})
	requireExactJSONKeys(t, explanation, "graph", "raw_observation_count", "logical_event_count", "conflict_count")
	graphJSON := requireJSONMapField(t, explanation, "graph")
	requireExactJSONKeys(t, graphJSON, "events", "observations", "relationships", "evidence",
		"as_of", "ingest_watermark", "next_after_time", "next_after_id", "truncated")
	requireExactJSONKeys(t, requireFirstJSONMap(t, graphJSON, "events"),
		"semantic_event_id", "logical_event_id", "connector", "connector_instance_id", "source_rail",
		"event_name", "source_time", "received_time", "source_event_digest", "fingerprint_sha256",
		"first_request_id", "first_record_id", "profile_version", "completeness")
	requireExactJSONKeys(t, requireFirstJSONMap(t, graphJSON, "observations"),
		"record_id", "semantic_event_id", "signal", "bucket", "event_name", "observed_at", "trace_id",
		"span_id", "session_id", "turn_id", "agent_id", "lifecycle_id", "execution_id",
		"model_request_id", "model_response_id", "tool_invocation_id", "projection_hash", "status")
	requireExactJSONKeys(t, requireFirstJSONMap(t, graphJSON, "relationships"),
		"relationship_id", "from_kind", "from_id", "to_kind", "to_id", "type", "method",
		"confidence", "rule_id", "rule_version", "status", "created_at", "last_seen_at")
	requireExactJSONKeys(t, requireFirstJSONMap(t, graphJSON, "evidence"),
		"evidence_id", "relationship_id", "record_id", "semantic_event_id", "role", "integrity", "created_at")

	timeline := mustJSONMap(t, CorrelationTimeline{Entries: []CorrelationTimelineEntry{{
		Event: CorrelationEvent{}, Observation: &CorrelationObservation{},
	}}})
	requireExactJSONKeys(t, timeline, "entries", "as_of", "ingest_watermark", "next_after_time", "next_after_id", "truncated")
	requireExactJSONKeys(t, requireFirstJSONMap(t, timeline, "entries"), "event", "observation")

	conflicts := mustJSONMap(t, CorrelationConflicts{
		Relationships: []CorrelationRelationship{{}}, Receipts: []CorrelationReceiptConflict{{}},
	})
	requireExactJSONKeys(t, conflicts, "relationships", "receipts", "as_of", "ingest_watermark", "truncated")
	requireExactJSONKeys(t, requireFirstJSONMap(t, conflicts, "receipts"),
		"connector_instance_id", "source_key_digest", "fingerprint_sha256", "semantic_event_id",
		"conflicts_with_semantic_event_id", "first_received_at", "last_received_at", "delivery_count")
}

func correlationDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func mustCorrelationInstance(t *testing.T, repo *CorrelationRepository, connector string, custody ConnectorExportCustody) ConnectorInstance {
	t.Helper()
	instance, err := repo.ResolveConnectorInstance(t.Context(), connector, connector+"-profile-v1", custody)
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

type correlationSeedOptions struct {
	rail       CorrelationRail
	eventName  string
	logical    LogicalEventID
	receivedAt time.Time
	receipt    *CorrelationReceiptClaim
	mutate     func(*CorrelationTx, CorrelationEvent)
}

func seedCorrelationEvent(t *testing.T, repo *CorrelationRepository, instance ConnectorInstance, options correlationSeedOptions) (CorrelationEvent, CorrelationOccurrenceResult) {
	t.Helper()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	if options.rail == "" {
		options.rail = CorrelationRailHook
	}
	if options.eventName == "" {
		options.eventName = "tool.started"
	}
	if options.receivedAt.IsZero() {
		options.receivedAt = time.Now().UTC()
	}
	if options.logical == "" {
		options.logical = LogicalEventID(semantic)
	}
	event := CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: options.logical,
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: options.rail, EventName: options.eventName, ReceivedTime: options.receivedAt,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	tx, result, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: event, Receipt: options.receipt})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != CorrelationOccurrenceReplay && options.mutate != nil {
		options.mutate(tx, event)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return event, result
}

func TestCorrelationUUIDsAreCanonicalV7AndUnique(t *testing.T) {
	seen := make(map[string]bool, 512)
	for index := 0; index < 256; index++ {
		semantic, err := NewSemanticEventID()
		if err != nil {
			t.Fatal(err)
		}
		connector, err := NewConnectorInstanceID()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{string(semantic), string(connector)} {
			parsed, err := uuid.Parse(value)
			if err != nil || parsed.Version() != 7 || parsed.String() != value {
				t.Fatalf("non-canonical UUIDv7 %q: parsed=%v err=%v", value, parsed, err)
			}
			if seen[value] {
				t.Fatalf("duplicate UUIDv7 %q", value)
			}
			seen[value] = true
		}
	}
}

func TestCorrelationReceiptReplayConflictAndRollback(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	receipt := &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("source-1"), FingerprintSHA256: correlationDigest("payload-1"),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	first, firstResult := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receipt: receipt})
	if firstResult.Status != CorrelationOccurrenceNew || firstResult.SuppressEmission {
		t.Fatalf("first receipt result=%+v", firstResult)
	}
	if firstResult.Receipt == nil {
		t.Fatal("first receipt locator is missing")
	}
	if err := repo.MarkOccurrenceCanonicalPersisted(t.Context(), *firstResult.Receipt, now.Add(time.Millisecond)); !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("receipt accepted without canonical observation: %v", err)
	}
	if err := repo.RecordObservation(t.Context(), CorrelationObservation{
		RecordID: "receipt-canonical-record", SemanticEventID: first.SemanticEventID,
		Signal: CorrelationSignalLogs, Bucket: "model_io", EventName: first.EventName,
		ObservedAt: now, Status: CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkOccurrenceCanonicalPersisted(t.Context(), *firstResult.Receipt, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	replayEvent, replayResult := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receipt: receipt})
	if replayResult.Status != CorrelationOccurrenceReplay || !replayResult.SuppressEmission ||
		replayResult.SemanticEventID != first.SemanticEventID || replayResult.DeliveryCount != 2 {
		t.Fatalf("replay result=%+v event=%+v", replayResult, replayEvent)
	}
	conflicting := *receipt
	conflicting.FingerprintSHA256 = correlationDigest("payload-2")
	conflictEvent, conflictResult := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receipt: &conflicting})
	if conflictResult.Status != CorrelationOccurrenceConflict || conflictResult.SuppressEmission ||
		conflictResult.ConflictsWith != first.SemanticEventID || conflictEvent.SemanticEventID == first.SemanticEventID {
		t.Fatalf("conflict result=%+v", conflictResult)
	}

	rollbackID, _ := NewSemanticEventID()
	rollback := CorrelationEvent{
		SemanticEventID: rollbackID, LogicalEventID: LogicalEventID(rollbackID), Connector: instance.Connector,
		ConnectorInstanceID: instance.ConnectorInstanceID, Rail: CorrelationRailHook,
		EventName: "rollback", ReceivedTime: now, ProfileVersion: instance.ProfileVersion,
		Completeness: CorrelationPartial,
	}
	tx, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: rollback})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PutObservation(t.Context(), CorrelationObservation{
		RecordID: "rollback-record", SemanticEventID: rollbackID, Signal: CorrelationSignalLogs,
		Bucket: "diagnostic", EventName: "rollback", ObservedAt: now,
		Status: CorrelationObservationConstructed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM correlation_events WHERE semantic_event_id='` + string(rollbackID) + `'`,
		`SELECT COUNT(*) FROM correlation_observations WHERE record_id='rollback-record'`,
	} {
		var count int
		if err := store.db.QueryRow(query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback query count=%d err=%v query=%s", count, err, query)
		}
	}
}

func TestCorrelationReceiptConflictCannotReuseExistingSemanticEvent(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	event := CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailNativeOTLP, EventName: "model_end", ReceivedTime: now,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	firstReceipt := &CorrelationReceiptClaim{
		SourceKeyDigest:   correlationDigest("reused-source"),
		FingerprintSHA256: correlationDigest("first-payload"),
		ReceivedAt:        now, ExpiresAt: now.Add(time.Hour),
	}
	firstTx, first, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		Event: event, Receipt: firstReceipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := firstTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if first.Status != CorrelationOccurrenceNew || first.SemanticEventID != semantic {
		t.Fatalf("first occurrence=%+v", first)
	}

	changedReceipt := *firstReceipt
	changedReceipt.FingerprintSHA256 = correlationDigest("changed-payload")
	changedReceipt.ReceivedAt = now.Add(time.Second)
	secondTx, second, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		// Deliberately repeat the already accepted semantic ID. A conflicting
		// payload must still receive a new immutable occurrence.
		Event: event, Receipt: &changedReceipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := secondTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if second.Status != CorrelationOccurrenceConflict || second.SuppressEmission ||
		second.ConflictsWith != semantic || second.SemanticEventID == semantic {
		t.Fatalf("conflicting occurrence=%+v", second)
	}
	var events, receipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 2 || receipts != 2 {
		t.Fatalf("events=%d receipts=%d", events, receipts)
	}
}

func TestBeginExistingOccurrenceAttachesCrossRailEvidenceWithoutRewritingEvent(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	logicalUUID, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original := CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(logicalUUID),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailHook, EventName: "tool.started", SourceTime: now.Add(-time.Second),
		ReceivedTime: now, SourceEventDigest: correlationDigest("hook-source"),
		FingerprintSHA256: correlationDigest("hook-payload"), FirstRequestID: "hook-request",
		FirstRecordID: "hook-record", ProfileVersion: instance.ProfileVersion,
		Completeness: CorrelationComplete,
	}
	createTx, result, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: original})
	if err != nil || result.Status != CorrelationOccurrenceNew {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	if err := createTx.Commit(); err != nil {
		t.Fatal(err)
	}

	attachTx, stored, err := repo.BeginExistingOccurrence(t.Context(), semantic)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SemanticEventID != original.SemanticEventID || stored.LogicalEventID != original.LogicalEventID ||
		stored.Connector != original.Connector || stored.ConnectorInstanceID != original.ConnectorInstanceID ||
		stored.Rail != original.Rail || stored.EventName != original.EventName ||
		stored.SourceEventDigest != original.SourceEventDigest || stored.FingerprintSHA256 != original.FingerprintSHA256 ||
		stored.FirstRequestID != original.FirstRequestID || stored.FirstRecordID != original.FirstRecordID {
		t.Fatalf("stored event changed: got=%+v want=%+v", stored, original)
	}
	rewrite := stored
	rewrite.Rail = CorrelationRailNativeOTLP
	rewrite.EventName = "model.completed"
	if err := attachTx.PutEvent(t.Context(), rewrite); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("attach transaction rewrote event: %v", err)
	}
	otherConnector, err := NewConnectorInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachTx.PutIdentifier(t.Context(), CorrelationIdentifier{
		SemanticEventID: semantic, ConnectorInstanceID: otherConnector, Namespace: "codex.native",
		Kind: CorrelationIdentifierModelResponse, ValueDigest: correlationDigest("response"),
		NormalizedValue: "response", SourceField: "gen_ai.response.id", Origin: CorrelationOriginReported,
		ProfileVersion: instance.ProfileVersion, ObservedAt: now,
	}); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("attach transaction accepted a different connector instance: %v", err)
	}
	if _, err := attachTx.PutIdentifier(t.Context(), CorrelationIdentifier{
		SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex.native",
		Kind: CorrelationIdentifierModelResponse, ValueDigest: correlationDigest("response"),
		NormalizedValue: "response", SourceField: "gen_ai.response.id", Origin: CorrelationOriginReported,
		ProfileVersion: instance.ProfileVersion, ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := attachTx.PutObservation(t.Context(), CorrelationObservation{
		RecordID: "native-trace-leaf", SemanticEventID: semantic, Signal: CorrelationSignalTraces,
		Bucket: "agent", EventName: "model.completed", ObservedAt: now.Add(time.Millisecond),
		TraceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpanID: "bbbbbbbbbbbbbbbb",
		ModelResponseID: "response", Status: CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
	relationship, err := attachTx.PutRelationship(t.Context(), CorrelationRelationshipInput{
		FromKind: CorrelationNodeSemanticEvent, FromID: string(semantic),
		ToKind: CorrelationNodeTrace, ToID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Type: CorrelationCorrelatesWith, Method: CorrelationMethodTraceExact,
		RuleID: "native-trace-leaf", RuleVersion: "v1", Status: CorrelationRelationshipActive,
		ObservedAt: now.Add(time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachTx.PutRelationshipEvidence(t.Context(), CorrelationRelationshipEvidence{
		RelationshipID: relationship.RelationshipID, SemanticEventID: semantic,
		Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified,
		CreatedAt: now.Add(time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := attachTx.PutRelationshipEvidence(t.Context(), CorrelationRelationshipEvidence{
		RelationshipID: relationship.RelationshipID, RecordID: "native-trace-leaf",
		Role: CorrelationEvidenceCorroborating, Integrity: CorrelationIntegrityVerified,
		CreatedAt: now.Add(2 * time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}
	evidenceCount, err := attachTx.RelationshipEvidenceCount(t.Context(), relationship.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 2 {
		t.Fatalf("relationship evidence count=%d want 2", evidenceCount)
	}
	if err := attachTx.Commit(); err != nil {
		t.Fatal(err)
	}

	graph, err := repo.QueryGraph(t.Context(), CorrelationGraphQuery{
		Anchor: CorrelationAnchor{SemanticEventID: semantic},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Events) != 1 || graph.Events[0].Rail != CorrelationRailHook ||
		graph.Events[0].LogicalEventID != original.LogicalEventID ||
		graph.Events[0].FirstRequestID != original.FirstRequestID ||
		graph.Events[0].FirstRecordID != original.FirstRecordID || len(graph.Observations) != 1 ||
		len(graph.Relationships) != 1 || len(graph.Evidence) != 2 {
		t.Fatalf("attached graph=%+v", graph)
	}
	var nativeIdentifiers int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_identifiers
		WHERE semantic_event_id=? AND namespace='codex.native'`, string(semantic)).Scan(&nativeIdentifiers); err != nil {
		t.Fatal(err)
	}
	if nativeIdentifiers != 1 {
		t.Fatalf("native identifier count=%d", nativeIdentifiers)
	}

	unknown, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	unknownTx, _, err := repo.BeginExistingOccurrence(t.Context(), unknown)
	if unknownTx != nil || !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("unknown existing occurrence tx=%v err=%v", unknownTx, err)
	}
}

func TestConnectorCustodyHotPathIsMonotonicAndExplicitUpdatesRemainPossible(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	promoted, err := repo.ResolveConnectorInstance(t.Context(), "codex", "codex-profile-v2", ConnectorCustodyDefenseClaw)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.ConnectorInstanceID != instance.ConnectorInstanceID || promoted.ExportCustody != ConnectorCustodyDefenseClaw {
		t.Fatalf("promotion=%+v initial=%+v", promoted, instance)
	}
	for _, attempted := range []ConnectorExportCustody{ConnectorCustodyExternal, ConnectorCustodyHookOnly} {
		resolved, err := repo.ResolveConnectorInstance(t.Context(), "codex", "codex-profile-v3", attempted)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.ExportCustody != ConnectorCustodyDefenseClaw {
			t.Fatalf("hot-path custody downgraded to %q", resolved.ExportCustody)
		}
	}
	promoted.ExportCustody = ConnectorCustodyExternal
	promoted.UpdatedAt = time.Now().UTC().Add(time.Second)
	explicit, err := repo.UpsertConnectorInstance(t.Context(), promoted)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.ExportCustody != ConnectorCustodyExternal {
		t.Fatalf("explicit custody=%q", explicit.ExportCustody)
	}
	instances, err := repo.ListConnectorInstances(t.Context())
	if err != nil || len(instances) != 1 || !instances[0].Default {
		t.Fatalf("instances=%+v err=%v", instances, err)
	}
}

func TestCorrelationStateQueriesSurviveRestartAndRejectAmbiguity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, _ := store.CorrelationRepository()
	instance := mustCorrelationInstance(t, repo, "cursor", ConnectorCustodyHookOnly)
	now := time.Now().UTC()
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "session", AgentID: "agent-1",
			ActiveTurnID: "turn", Phase: "active", Sequence: 1, LastSemanticEventID: event.SemanticEventID,
			ProfileVersion: instance.ProfileVersion, Active: true, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
			OperationID: "tool-1", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
			SessionID: "session", TurnID: "turn", AgentID: "agent-1",
			StartSemanticEventID: event.SemanticEventID, StartedAt: now, Status: CorrelationOperationActive,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, _ = store.CorrelationRepository()
	cursor, err := repo.GetCursor(t.Context(), instance.ConnectorInstanceID, "session", "agent-1")
	if err != nil || cursor.LastSemanticEventID != event.SemanticEventID || cursor.ActiveTurnID != "turn" {
		t.Fatalf("cursor=%+v err=%v", cursor, err)
	}
	uniqueCursor, err := repo.FindActiveCursor(t.Context(), instance.ConnectorInstanceID, "session")
	if err != nil || uniqueCursor.AgentID != "agent-1" {
		t.Fatalf("unique cursor=%+v err=%v", uniqueCursor, err)
	}
	pending, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
		OperationID: "tool-1", Type: CorrelationOperationTool,
		ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
		SessionID: "session", TurnID: "turn",
	})
	if err != nil || pending.OperationID != "tool-1" || pending.StartSemanticEventID != event.SemanticEventID {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	if _, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
		OperationID: "missing-tool", Type: CorrelationOperationTool,
		ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
	}); !errors.Is(err, ErrCorrelationNotFound) {
		t.Fatalf("missing exact operation error=%v", err)
	}
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(time.Second), mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "session", AgentID: "agent-2",
			ActiveTurnID: "turn", Phase: "active", Sequence: 1, LastSemanticEventID: event.SemanticEventID,
			ProfileVersion: instance.ProfileVersion, Active: true, UpdatedAt: now.Add(time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
			OperationID: "tool-2", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
			SessionID: "session", TurnID: "turn", AgentID: "agent-2",
			StartSemanticEventID: event.SemanticEventID, StartedAt: now.Add(time.Second),
			Status: CorrelationOperationActive,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	if _, err := repo.FindActiveCursor(t.Context(), instance.ConnectorInstanceID, "session"); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("ambiguous active cursor error=%v", err)
	}
	if _, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
		Type: CorrelationOperationTool, ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
		SessionID: "session", TurnID: "turn",
	}); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("ambiguous pending operation error=%v", err)
	}
	exact, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
		OperationID: "tool-2", Type: CorrelationOperationTool,
		ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
	})
	if err != nil || exact.AgentID != "agent-2" {
		t.Fatalf("exact pending operation=%+v err=%v", exact, err)
	}
}

func TestCorrelationReceiptClaimsSerializeUnderConcurrency(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	claim := &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("concurrent-source"), FingerprintSHA256: correlationDigest("same-payload"),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	var created, replayed atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for index := 0; index < 16; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semantic, err := NewSemanticEventID()
			if err != nil {
				failures.Add(1)
				return
			}
			event := CorrelationEvent{
				SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic), Connector: instance.Connector,
				ConnectorInstanceID: instance.ConnectorInstanceID, Rail: CorrelationRailHook,
				EventName: "concurrent", ReceivedTime: now, ProfileVersion: instance.ProfileVersion,
				Completeness: CorrelationComplete,
			}
			tx, result, err := repo.BeginOccurrence(context.Background(), CorrelationOccurrenceInput{Event: event, Receipt: claim})
			if err != nil {
				failures.Add(1)
				return
			}
			if err := tx.Commit(); err != nil {
				failures.Add(1)
				return
			}
			switch result.Status {
			case CorrelationOccurrenceNew:
				created.Add(1)
			case CorrelationOccurrenceReplay:
				replayed.Add(1)
			default:
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 || created.Load() != 1 || replayed.Load() != 15 {
		t.Fatalf("created=%d replayed=%d failures=%d", created.Load(), replayed.Load(), failures.Load())
	}
	var events, receipts int
	var deliveries uint64
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*), MAX(delivery_count) FROM correlation_receipts`).Scan(&receipts, &deliveries); err != nil {
		t.Fatal(err)
	}
	if events != 1 || receipts != 1 || deliveries != 16 {
		t.Fatalf("events=%d receipts=%d deliveries=%d", events, receipts, deliveries)
	}
}

func TestCorrelationPendingOperationsAreTypedScopedAndRestartSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	starts := make(map[string]CorrelationEvent, 2)
	for index, session := range []string{"session-a", "session-b"} {
		event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
			receivedAt: now.Add(time.Duration(index) * time.Nanosecond),
			mutate: func(tx *CorrelationTx, event CorrelationEvent) {
				operation := CorrelationPendingOperation{
					ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace:           "codex", Kind: CorrelationIdentifierTool,
					OperationID: "provider-reused-id", Type: CorrelationOperationTool,
					ScopeKind: CorrelationOperationScopeSession, ScopeID: session,
					SessionID: session, StartSemanticEventID: event.SemanticEventID,
					StartedAt: event.ReceivedTime, Status: CorrelationOperationActive,
				}
				if err := tx.PutPendingOperation(t.Context(), operation); err != nil {
					t.Fatal(err)
				}
				// An exact replay is explicitly verified rather than silently ignored.
				if err := tx.PutPendingOperation(t.Context(), operation); err != nil {
					t.Fatalf("exact pending replay: %v", err)
				}
			},
		})
		starts[session] = event
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, err = store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"session-a", "session-b"} {
		operation, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
			ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace:           "codex", Kind: CorrelationIdentifierTool,
			OperationID: "provider-reused-id", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeSession, ScopeID: session,
		})
		if err != nil || operation.SessionID != session ||
			operation.StartSemanticEventID != starts[session].SemanticEventID {
			t.Fatalf("session=%s operation=%+v err=%v", session, operation, err)
		}
	}

	terminal, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		receivedAt: now.Add(time.Second), eventName: "tool.completed",
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			wrongScope := CorrelationPendingLocator{
				ConnectorInstanceID: instance.ConnectorInstanceID,
				Namespace:           "codex", Kind: CorrelationIdentifierTool,
				OperationID: "provider-reused-id", Type: CorrelationOperationTool,
				ScopeKind: CorrelationOperationScopeSession, ScopeID: "session-c",
			}
			if err := tx.ResolvePendingOperation(t.Context(), wrongScope, event.SemanticEventID,
				CorrelationOperationCompleted, event.ReceivedTime); !errors.Is(err, ErrCorrelationConflict) {
				t.Fatalf("scope mismatch error=%v", err)
			}
			correct := wrongScope
			correct.ScopeID = "session-a"
			if err := tx.ResolvePendingOperation(t.Context(), correct, event.SemanticEventID,
				CorrelationOperationCompleted, event.ReceivedTime); err != nil {
				t.Fatal(err)
			}
		},
	})
	completed, err := repo.ListPendingOperations(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex",
		Kind: CorrelationIdentifierTool, OperationID: "provider-reused-id",
		Type: CorrelationOperationTool, ScopeKind: CorrelationOperationScopeSession,
		ScopeID: "session-a",
	})
	if err != nil || len(completed) != 1 || completed[0].Status != CorrelationOperationCompleted ||
		completed[0].TerminalSemanticEventID != terminal.SemanticEventID {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	stillActive, err := repo.FindUniquePendingOperation(t.Context(), CorrelationPendingQuery{
		ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex",
		Kind: CorrelationIdentifierTool, OperationID: "provider-reused-id",
		Type: CorrelationOperationTool, ScopeKind: CorrelationOperationScopeSession,
		ScopeID: "session-b",
	})
	if err != nil || stillActive.SessionID != "session-b" {
		t.Fatalf("still active=%+v err=%v", stillActive, err)
	}

	collision, _, err := repo.BeginExistingOccurrence(t.Context(), starts["session-b"].SemanticEventID)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := stillActive
	conflicting.AgentID = "different-agent"
	if err := collision.PutPendingOperation(t.Context(), conflicting); !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("non-replay collision error=%v", err)
	}
	_ = collision.Rollback()
}

func TestCorrelationExactIdentityClaimsConvergeConcurrentCrossRailMirrors(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Now().UTC()
	digest := correlationDigest("provider-tool-call")
	type outcome struct {
		event  CorrelationEvent
		result CorrelationOccurrenceResult
		err    error
	}
	ready := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, rail := range []CorrelationRail{CorrelationRailHook, CorrelationRailNativeOTLP} {
		rail := rail
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			semantic, err := NewSemanticEventID()
			if err != nil {
				results <- outcome{err: err}
				return
			}
			event := CorrelationEvent{
				SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic),
				Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
				Rail: rail, EventName: "tool.started", ReceivedTime: now,
				ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
			}
			peer := CorrelationRailHook
			if rail == CorrelationRailHook {
				peer = CorrelationRailNativeOTLP
			}
			tx, result, err := repo.BeginOccurrence(context.Background(), CorrelationOccurrenceInput{
				Event: event,
				ExactIdentityClaims: []CorrelationExactIdentityClaim{{
					Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: digest,
					EventName: event.EventName, Rail: rail, CompatibleRail: peer,
					RuleID: "codex-tool-mirror", RuleVersion: "v1",
				}},
			})
			if err == nil {
				err = tx.Commit()
			}
			results <- outcome{event: event, result: result, err: err}
		}()
	}
	close(ready)
	wg.Wait()
	close(results)
	var outcomes []outcome
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		outcomes = append(outcomes, result)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes=%d", len(outcomes))
	}
	var events, groups, claims int
	if err := store.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events`).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_identity_claims`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if events != 2 || groups != 1 || claims != 2 {
		t.Fatalf("events=%d groups=%d claims=%d", events, groups, claims)
	}
	var matched int
	for _, result := range outcomes {
		if result.result.LogicalEventID == "" {
			t.Fatalf("missing logical result: %+v", result.result)
		}
		if result.result.MatchedSemanticEventID != "" {
			matched++
			if result.result.MatchedLogicalEventID != result.result.LogicalEventID ||
				len(result.result.IdentityEvidence) != 1 {
				t.Fatalf("matched evidence=%+v", result.result)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("matched results=%d, want one transaction to observe its counterpart", matched)
	}

	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	third := CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic), Connector: instance.Connector,
		ConnectorInstanceID: instance.ConnectorInstanceID, Rail: CorrelationRailHook,
		EventName: "tool.started", ReceivedTime: now.Add(time.Second),
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	tx, repeated, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		Event: third, ExactIdentityClaims: []CorrelationExactIdentityClaim{{
			Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: digest,
			EventName: third.EventName, Rail: third.Rail, CompatibleRail: CorrelationRailNativeOTLP,
			RuleID: "codex-tool-mirror", RuleVersion: "v1",
		}},
	})
	if err != nil {
		t.Fatalf("same-rail exact repeat: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if repeated.LogicalEventID != outcomes[0].result.LogicalEventID ||
		len(repeated.IdentityEvidence) != 2 {
		t.Fatalf("same-rail exact repeat result=%+v", repeated)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events`).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_identity_claims`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if events != 3 || groups != 1 || claims != 2 {
		t.Fatalf("after same-rail repeat events=%d groups=%d claims=%d", events, groups, claims)
	}
	third.SemanticEventID, _ = NewSemanticEventID()
	third.LogicalEventID = LogicalEventID(third.SemanticEventID)
	if tx, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		Event: third, ExactIdentityClaims: []CorrelationExactIdentityClaim{{
			Namespace: "codex", Kind: CorrelationIdentifierTurn, ValueDigest: correlationDigest("turn"),
			EventName: third.EventName, Rail: third.Rail, CompatibleRail: CorrelationRailNativeOTLP,
			RuleID: "invalid-membership", RuleVersion: "v1",
		}},
	}); err == nil {
		_ = tx.Rollback()
		t.Fatal("turn membership identity was accepted as an exact occurrence claim")
	}
}

func TestCorrelationReceiptConflictCannotClaimExactMirrorIdentity(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Now().UTC()
	firstSemantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	first := CorrelationEvent{
		SemanticEventID: firstSemantic, LogicalEventID: LogicalEventID(firstSemantic),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailHook, EventName: "tool.started", ReceivedTime: now,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	baseReceipt := &CorrelationReceiptClaim{
		SourceKeyDigest:   correlationDigest("reused-source-key"),
		FingerprintSHA256: correlationDigest("first-payload"),
		ReceivedAt:        now, ExpiresAt: now.Add(time.Hour),
	}
	claimDigest := correlationDigest("same-provider-tool")
	firstTx, firstResult, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		Event: first, Receipt: baseReceipt,
		ExactIdentityClaims: []CorrelationExactIdentityClaim{{
			Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: claimDigest,
			EventName: first.EventName, Rail: first.Rail, CompatibleRail: CorrelationRailNativeOTLP,
			RuleID: "codex-tool-mirror", RuleVersion: "v1",
		}},
	})
	if err != nil || firstResult.Status != CorrelationOccurrenceNew {
		t.Fatalf("first result=%+v err=%v", firstResult, err)
	}
	if err := firstTx.Commit(); err != nil {
		t.Fatal(err)
	}

	secondSemantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	second := CorrelationEvent{
		SemanticEventID: secondSemantic, LogicalEventID: LogicalEventID(secondSemantic),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailNativeOTLP, EventName: first.EventName, ReceivedTime: now.Add(time.Second),
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
	conflictingReceipt := *baseReceipt
	conflictingReceipt.FingerprintSHA256 = correlationDigest("different-payload")
	conflictingReceipt.ReceivedAt = second.ReceivedTime
	secondTx, secondResult, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{
		Event: second, Receipt: &conflictingReceipt,
		ExactIdentityClaims: []CorrelationExactIdentityClaim{{
			Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: claimDigest,
			EventName: second.EventName, Rail: second.Rail, CompatibleRail: CorrelationRailHook,
			RuleID: "codex-tool-mirror", RuleVersion: "v1",
		}},
	})
	if err != nil || secondResult.Status != CorrelationOccurrenceConflict ||
		secondResult.ConflictsWith != first.SemanticEventID || secondResult.LogicalEventID != LogicalEventID(secondResult.SemanticEventID) ||
		secondResult.MatchedSemanticEventID != "" || len(secondResult.IdentityEvidence) != 0 {
		t.Fatalf("conflict result=%+v err=%v", secondResult, err)
	}
	if err := secondTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var events, groups, claims int
	if err := store.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events`).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_identity_claims`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if events != 2 || groups != 2 || claims != 1 {
		t.Fatalf("events=%d groups=%d claims=%d", events, groups, claims)
	}
}

func TestCorrelationMigrationIsAdditiveForPreviousReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	previousCount := len(migrations) - 1
	for index := 0; index < previousCount; index++ {
		if err := store.applyMigration(index+1, migrations[index]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events
		(id,timestamp,action,actor,details,severity) VALUES
		('bridge-row','2026-07-01T00:00:00Z','bridge','test','unchanged','INFO')`); err != nil {
		t.Fatal(err)
	}
	var schemaBefore string
	if err := store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'`).Scan(&schemaBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.applyMigration(len(migrations), migrations[len(migrations)-1]); err != nil {
		t.Fatal(err)
	}
	var schemaAfter, details string
	if err := store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'`).Scan(&schemaAfter); err != nil {
		t.Fatal(err)
	}
	if schemaAfter != schemaBefore {
		t.Fatal("correlation migration modified the bridge-owned audit_events schema")
	}
	if err := store.db.QueryRow(`SELECT details FROM audit_events WHERE id='bridge-row'`).Scan(&details); err != nil || details != "unchanged" {
		t.Fatalf("previous reader row=%q err=%v", details, err)
	}
	var current int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	// This is the exact loop guard used by the previous binary. A newer max
	// version performs no indexing into its shorter migration slice.
	for index := current; index < previousCount; index++ {
		t.Fatalf("previous reader unexpectedly attempted migration index %d", index)
	}
	var violations int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil || violations != 0 {
		t.Fatalf("foreign key violations=%d err=%v", violations, err)
	}
}

func TestRecordObservationRequiresExistingEventAndCommitsMetadataOnly(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	missing, _ := NewSemanticEventID()
	err := repo.RecordObservation(t.Context(), CorrelationObservation{
		RecordID: "missing", SemanticEventID: missing, Signal: CorrelationSignalTraces,
		Bucket: "agent", EventName: "missing", ObservedAt: time.Now().UTC(),
		Status: CorrelationObservationExportEligible,
	})
	if err == nil {
		t.Fatal("observation without accepted event succeeded")
	}
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{})
	if err := repo.RecordObservation(t.Context(), CorrelationObservation{
		RecordID: "trace-record", SemanticEventID: event.SemanticEventID,
		Signal: CorrelationSignalTraces, Bucket: "agent", EventName: event.EventName,
		ObservedAt: time.Now().UTC(), TraceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SpanID: "bbbbbbbbbbbbbbbb", Status: CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
	var signal, trace string
	if err := store.db.QueryRow(`SELECT signal,trace_id FROM correlation_observations WHERE record_id='trace-record'`).Scan(&signal, &trace); err != nil {
		t.Fatal(err)
	}
	if signal != "traces" || trace != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("signal=%q trace=%q", signal, trace)
	}
}

func TestCorrelationQueriesPaginateDeterministicallyAndScopeConflicts(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	base := time.Now().UTC().Add(-time.Minute)
	var events []CorrelationEvent
	for index := 0; index < 3; index++ {
		recordID := "query-record-" + string(rune('a'+index))
		event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
			receivedAt: base.Add(time.Duration(index) * time.Second),
			mutate: func(tx *CorrelationTx, event CorrelationEvent) {
				if err := tx.PutObservation(t.Context(), CorrelationObservation{
					RecordID: recordID, SemanticEventID: event.SemanticEventID,
					Signal: CorrelationSignalLogs, Bucket: "agent", EventName: event.EventName,
					ObservedAt: event.ReceivedTime, SessionID: "query-session",
					Status: CorrelationObservationExportEligible,
				}); err != nil {
					t.Fatal(err)
				}
			},
		})
		events = append(events, event)
	}
	first, err := repo.QueryGraph(t.Context(), CorrelationGraphQuery{
		Anchor: CorrelationAnchor{ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "query-session"},
		Page:   CorrelationPageRequest{Limit: 2},
	})
	if err != nil || len(first.Events) != 2 || !first.Truncated || first.NextAfterID == "" || first.NextAfterTime.IsZero() {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := repo.QueryGraph(t.Context(), CorrelationGraphQuery{
		Anchor: CorrelationAnchor{ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "query-session"},
		Page:   CorrelationPageRequest{Limit: 2, AfterTime: first.NextAfterTime, AfterID: first.NextAfterID},
	})
	if err != nil || len(second.Events) != 1 || second.Truncated || second.Events[0].SemanticEventID != events[2].SemanticEventID {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	timeline, err := repo.QueryTimeline(t.Context(), CorrelationGraphQuery{
		Anchor: CorrelationAnchor{SessionID: "query-session"}, Page: CorrelationPageRequest{Limit: 3},
	})
	if err != nil || len(timeline.Entries) != 3 {
		t.Fatalf("timeline=%+v err=%v", timeline, err)
	}
	explanation, err := repo.Explain(t.Context(), CorrelationGraphQuery{
		Anchor: CorrelationAnchor{SessionID: "query-session"}, Page: CorrelationPageRequest{Limit: 3},
	})
	if err != nil || explanation.RawObservationCount != 3 || explanation.LogicalEventCount != 3 {
		t.Fatalf("explanation=%+v err=%v", explanation, err)
	}

	now := time.Now().UTC()
	claim := &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("query-conflict-source"), FingerprintSHA256: correlationDigest("query-conflict-one"),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	original, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receipt: claim})
	conflictClaim := *claim
	conflictClaim.FingerprintSHA256 = correlationDigest("query-conflict-two")
	conflict, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receipt: &conflictClaim})
	conflicts, err := repo.QueryConflicts(t.Context(), CorrelationConflictsQuery{
		Anchor: CorrelationAnchor{SemanticEventID: original.SemanticEventID}, Page: CorrelationPageRequest{Limit: 10},
	})
	if err != nil || len(conflicts.Receipts) != 1 || conflicts.Receipts[0].SemanticEventID != conflict.SemanticEventID ||
		conflicts.Receipts[0].ConflictsWith != original.SemanticEventID {
		t.Fatalf("conflicts=%+v err=%v", conflicts, err)
	}
}
