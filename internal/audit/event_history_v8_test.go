// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

type v8HistoryRow struct {
	ID                   string
	Action               string
	Target               string
	Actor                string
	Details              string
	StructuredJSON       string
	Severity             string
	Bucket               string
	EventName            string
	Source               string
	Signal               string
	BucketCatalogVersion int
	PayloadJSON          string
	ProjectedRecordJSON  string
	RecordSchemaVersion  int
	ProjectionHash       string
	RedactionProfile     string
	Mandatory            int
	RunID                string
	RequestID            string
	SessionID            string
	TurnID               string
	TraceID              string
	EvaluationID         string
	ScanID               string
	FindingID            string
	EnforcementActionID  string
	SchemaVersion        int
	ContentHash          string
	Generation           int64
	BinaryVersion        string
	AgentID              string
	AgentInstanceID      string
	SidecarInstanceID    string
	PolicyID             string
	ToolID               string
	Connector            string
	Enforced             int
	PayloadHMAC          string
	IntegrityAlgorithm   string
	IntegrityKeyID       string
}

type testProjectionSigner struct {
	key      []byte
	keyID    string
	err      error
	digest   []byte
	messages [][]byte
}

type testEventHistoryHealthReporter struct {
	codes []EventHistoryHealthCode
}

func (reporter *testEventHistoryHealthReporter) ReportEventHistoryHealth(code EventHistoryHealthCode) {
	reporter.codes = append(reporter.codes, code)
}

type queryingEventHistoryHealthReporter struct {
	store       *Store
	closeOnCode EventHistoryHealthCode
	codes       []EventHistoryHealthCode
	errors      []error
	closeErrors []error
}

type toggleProjectionSigner struct {
	key         [sha256.Size]byte
	unavailable atomic.Bool
}

func (*toggleProjectionSigner) KeyID() string { return "toggle-key-v1" }

func (signer *toggleProjectionSigner) HMACSHA256(
	ctx context.Context,
	message []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if signer.unavailable.Load() {
		return nil, ErrIntegrityKeyUnavailable
	}
	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

type blockingEventHistoryHealthReporter struct {
	started chan EventHistoryHealthCode
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	codes   []EventHistoryHealthCode
}

func (reporter *blockingEventHistoryHealthReporter) ReportEventHistoryHealth(
	code EventHistoryHealthCode,
) {
	reporter.mu.Lock()
	reporter.codes = append(reporter.codes, code)
	reporter.mu.Unlock()
	reporter.once.Do(func() {
		reporter.started <- code
		<-reporter.release
	})
}

func (reporter *blockingEventHistoryHealthReporter) snapshot() []EventHistoryHealthCode {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return append([]EventHistoryHealthCode(nil), reporter.codes...)
}

func (reporter *queryingEventHistoryHealthReporter) ReportEventHistoryHealth(code EventHistoryHealthCode) {
	reporter.codes = append(reporter.codes, code)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var count int
	reporter.errors = append(reporter.errors,
		reporter.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&count))
	if code == reporter.closeOnCode {
		reporter.closeErrors = append(reporter.closeErrors, reporter.store.Close())
	}
}

func (signer *testProjectionSigner) KeyID() string { return signer.keyID }

func (signer *testProjectionSigner) HMACSHA256(_ context.Context, message []byte) ([]byte, error) {
	signer.messages = append(signer.messages, append([]byte(nil), message...))
	if signer.err != nil {
		return nil, signer.err
	}
	if signer.digest != nil {
		return append([]byte(nil), signer.digest...), nil
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

func newV8HistoryStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

func newV8HistoryRecord(t *testing.T, id, message string) observability.Record {
	return newV8HistoryRecordAt(
		t, id, message, time.Date(2026, 7, 3, 14, 15, 16, 17, time.UTC),
	)
}

func newV8HistoryRecordAt(t *testing.T, id, message string, timestamp time.Time) observability.Record {
	t.Helper()
	severity := observability.SeverityHigh
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: timestamp,
		RecordID:  id,
		Identity: observability.EventIdentity{
			Bucket: observability.BucketDiagnostic,
			Signal: observability.SignalLogs,
			Name:   "diagnostic.message",
		},
		Severity:  &severity,
		LogLevel:  observability.LogLevelError,
		Source:    observability.SourceGateway,
		Connector: "codex",
		Action:    "diagnostic.emit",
		Phase:     "completed",
		Outcome:   observability.OutcomeBlocked,
		Correlation: observability.Correlation{
			RunID:               "run-v8",
			RequestID:           "request-v8",
			SessionID:           "session-v8",
			TurnID:              "turn-v8",
			TraceID:             "trace-v8",
			AgentID:             "agent-v8",
			AgentInstanceID:     "agent-instance-v8",
			PolicyID:            "policy-v8",
			EvaluationID:        "evaluation-v8",
			ScanID:              "scan-v8",
			FindingOccurrenceID: "finding-v8",
			EnforcementActionID: "enforcement-v8",
			ToolInvocationID:    "tool-v8",
			SidecarInstanceID:   "sidecar-v8",
		},
		Provenance: observability.Provenance{
			Producer:              "gateway.audit",
			BinaryVersion:         "v8.0.0-test",
			RegistrySchemaVersion: 1,
			ConfigGeneration:      23,
			ConfigDigest:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Body: map[string]any{
			"message": message,
			"count":   2,
		},
		FieldClasses: map[string]observability.FieldClass{
			"/message": observability.FieldClassContent,
			"/count":   observability.FieldClassMetadata,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func projectV8HistoryRecord(
	t *testing.T,
	record observability.Record,
	profileName observabilityredaction.ProfileName,
) observabilityredaction.Projection {
	t.Helper()
	return projectV8HistoryRecordWithEngine(t, testEventHistoryProjectionEngine, record, profileName)
}

func projectV8HistoryRecordWithEngine(
	t *testing.T,
	engine *observabilityredaction.Engine,
	record observability.Record,
	profileName observabilityredaction.ProfileName,
) observabilityredaction.Projection {
	t.Helper()
	profile, ok := observabilityredaction.BuiltInProfile(profileName)
	if !ok {
		t.Fatalf("profile %q is unavailable", profileName)
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func newTestTrustedLocalProjectionBinding(
	t *testing.T,
	digest string,
	engine *observabilityredaction.Engine,
	profile observabilityredaction.Profile,
) *TrustedLocalProjectionBinding {
	t.Helper()
	profiles := make(map[observability.Bucket]observabilityredaction.Profile, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		profiles[bucket] = profile
	}
	binding, err := NewTrustedLocalProjectionBinding(digest, engine, profiles)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func loadV8HistoryRow(t *testing.T, store *Store, id string) v8HistoryRow {
	t.Helper()
	var row v8HistoryRow
	err := store.db.QueryRow(`
		SELECT id, action, COALESCE(target,''), actor, COALESCE(details,''), COALESCE(structured_json,''), COALESCE(severity,''),
		       COALESCE(bucket,''), COALESCE(event_name,''), COALESCE(source,''), COALESCE(signal,''),
		       COALESCE(bucket_catalog_version,0), COALESCE(payload_json,''), COALESCE(projected_record_json,''),
		       COALESCE(record_schema_version,0), COALESCE(projection_hash,''),
		       COALESCE(redaction_profile,''),
		       COALESCE(mandatory,0), COALESCE(run_id,''), COALESCE(request_id,''), COALESCE(session_id,''),
		       COALESCE(turn_id,''), COALESCE(trace_id,''), COALESCE(evaluation_id,''), COALESCE(scan_id,''),
		       COALESCE(finding_id,''), COALESCE(enforcement_action_id,''), COALESCE(schema_version,0),
		       COALESCE(content_hash,''), COALESCE(generation,0), COALESCE(binary_version,''),
		       COALESCE(agent_id,''), COALESCE(agent_instance_id,''), COALESCE(sidecar_instance_id,''),
		       COALESCE(policy_id,''), COALESCE(tool_id,''), COALESCE(connector,''), COALESCE(enforced,0),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''), COALESCE(integrity_key_id,'')
		FROM audit_events WHERE id = ?`, id).Scan(
		&row.ID, &row.Action, &row.Target, &row.Actor, &row.Details, &row.StructuredJSON, &row.Severity,
		&row.Bucket, &row.EventName, &row.Source, &row.Signal, &row.BucketCatalogVersion,
		&row.PayloadJSON, &row.ProjectedRecordJSON, &row.RecordSchemaVersion, &row.ProjectionHash,
		&row.RedactionProfile, &row.Mandatory, &row.RunID, &row.RequestID,
		&row.SessionID, &row.TurnID, &row.TraceID, &row.EvaluationID, &row.ScanID, &row.FindingID,
		&row.EnforcementActionID, &row.SchemaVersion, &row.ContentHash, &row.Generation,
		&row.BinaryVersion, &row.AgentID, &row.AgentInstanceID, &row.SidecarInstanceID,
		&row.PolicyID, &row.ToolID, &row.Connector, &row.Enforced, &row.PayloadHMAC,
		&row.IntegrityAlgorithm, &row.IntegrityKeyID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestV8EventHistoryMigrationIsAdditiveAndIdempotent(t *testing.T) {
	store := newV8HistoryStore(t)
	columns := []string{
		"bucket", "event_name", "source", "signal", "bucket_catalog_version", "payload_json",
		"projected_record_json",
		"record_schema_version", "projection_hash",
		"redaction_profile", "mandatory", "turn_id", "evaluation_id", "scan_id", "finding_id",
		"enforcement_action_id", "payload_hmac", "integrity_algorithm", "integrity_key_id",
	}
	for _, column := range columns {
		exists, err := store.hasColumn("audit_events", column)
		if err != nil || !exists {
			t.Fatalf("audit_events.%s exists=%t err=%v", column, exists, err)
		}
	}

	var historyMigration *migration
	for index := range migrations {
		if migrations[index].description == "observability v8: add canonical local event-history projection columns" {
			if historyMigration != nil {
				t.Fatal("multiple observability v8 event-history migrations found")
			}
			historyMigration = &migrations[index]
		}
	}
	if historyMigration == nil {
		t.Fatal("observability v8 event-history migration not found")
	}
	if err := historyMigration.apply(store.db); err != nil {
		t.Fatalf("first direct migration replay: %v", err)
	}
	if err := historyMigration.apply(store.db); err != nil {
		t.Fatalf("second direct migration replay: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init after migration replay: %v", err)
	}

	for _, index := range []string{
		"idx_audit_bucket_timestamp", "idx_audit_event_name_timestamp", "idx_audit_source_timestamp",
		"idx_audit_turn_id", "idx_audit_evaluation_id", "idx_audit_scan_id",
		"idx_audit_finding_id", "idx_audit_enforcement_action_id",
	} {
		var count int
		if err := store.db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index,
		).Scan(&count); err != nil || count != 1 {
			t.Fatalf("index %s count=%d err=%v", index, count, err)
		}
	}
}

func TestV8EventHistoryMigrationPreservesHistoricalRowsAndLegacyMeanings(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < len(migrations)-1; index++ {
		if err := store.applyMigration(index+1, migrations[index]); err != nil {
			t.Fatalf("apply historical migration %d: %v", index+1, err)
		}
	}
	const legacyHash = "legacy-config-fingerprint"
	if _, err := store.db.Exec(`INSERT INTO audit_events (
		id, timestamp, action, actor, details, severity, schema_version, content_hash,
		generation, binary_version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-history", "2026-07-01T12:00:00Z", "legacy.action", "legacy-producer",
		"legacy human details", "HIGH", version.SchemaVersion, legacyHash, 17, "v7.9.0",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	var schemaVersion, generation int
	var contentHash, details, binaryVersion string
	var bucket, projected, projectionHash sql.NullString
	if err := store.db.QueryRow(`SELECT schema_version, content_hash, generation, binary_version,
		details, bucket, projected_record_json, projection_hash
		FROM audit_events WHERE id='legacy-history'`).Scan(
		&schemaVersion, &contentHash, &generation, &binaryVersion, &details,
		&bucket, &projected, &projectionHash,
	); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != version.SchemaVersion || contentHash != legacyHash || generation != 17 ||
		binaryVersion != "v7.9.0" || details != "legacy human details" {
		t.Fatalf("legacy meanings changed: schema=%d hash=%q generation=%d binary=%q details=%q",
			schemaVersion, contentHash, generation, binaryVersion, details)
	}
	if bucket.Valid || projected.Valid || projectionHash.Valid {
		t.Fatalf("historical row was fabricated as v8: bucket=%#v projected=%#v hash=%#v",
			bucket, projected, projectionHash)
	}
}

func TestStoreInitFailsWhenMandatoryV8EventHistoryAnchorIsMissing(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "partial.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO schema_version(version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`,
		len(migrations)); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err == nil || !strings.Contains(err.Error(), "mandatory event-history table is missing") {
		t.Fatalf("Store.Init missing-anchor error = %v", err)
	}
	if store.Ready() {
		t.Fatal("store published readiness after missing-anchor failure")
	}
}

func TestStoreInitFailsWhenMandatoryV8EventHistoryColumnIsMissing(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "partial-column.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`
		CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL);
		CREATE TABLE audit_events (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO schema_version(version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`,
		len(migrations)); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err == nil || !strings.Contains(err.Error(), "mandatory event-history column bucket is missing") {
		t.Fatalf("Store.Init missing-column error = %v", err)
	}
	if store.Ready() {
		t.Fatal("store published readiness after missing-column failure")
	}
}

func TestEventHistoryWriterPersistsExactCanonicalProjectionAndLegacyView(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-exact", "projected local message")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}

	row := loadV8HistoryRow(t, store, record.RecordID())
	wantPayload := string(projection.Payload().Bytes())
	wantEnvelope, err := projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wantEnvelope)
	wantHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
	if row.ID != record.RecordID() || row.Action != "diagnostic.emit" || row.Actor != "gateway.audit" ||
		row.Details != "projected local message" || row.StructuredJSON != wantPayload || row.Severity != "HIGH" {
		t.Fatalf("legacy columns = %#v", row)
	}
	if row.Bucket != "diagnostic" || row.EventName != "diagnostic.message" || row.Source != "gateway" ||
		row.Signal != "logs" || row.BucketCatalogVersion != 1 || row.PayloadJSON != wantPayload ||
		row.ProjectedRecordJSON != string(wantEnvelope) ||
		row.RedactionProfile != "none" || row.Mandatory != 0 {
		t.Fatalf("v8 identity/payload columns = %#v", row)
	}
	if row.RunID != "run-v8" || row.RequestID != "request-v8" || row.SessionID != "session-v8" ||
		row.TurnID != "turn-v8" || row.TraceID != "trace-v8" || row.EvaluationID != "evaluation-v8" ||
		row.ScanID != "scan-v8" || row.FindingID != "finding-v8" ||
		row.EnforcementActionID != "enforcement-v8" {
		t.Fatalf("correlation columns = %#v", row)
	}
	if row.SchemaVersion != version.SchemaVersion ||
		row.ContentHash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		row.RecordSchemaVersion != 1 || row.ProjectionHash != wantHash || row.Generation != 23 ||
		row.BinaryVersion != "v8.0.0-test" || row.AgentID != "agent-v8" ||
		row.AgentInstanceID != "agent-instance-v8" || row.SidecarInstanceID != "sidecar-v8" ||
		row.PolicyID != "policy-v8" || row.ToolID != "tool-v8" || row.Connector != "codex" || row.Enforced != 1 {
		t.Fatalf("provenance/compatibility columns = %#v", row)
	}
	if row.PayloadHMAC != "" || row.IntegrityAlgorithm != "" || row.IntegrityKeyID != "" {
		t.Fatalf("unsigned integrity columns = %#v", row)
	}

	// The pre-v8 reader keeps working because all legacy columns and semantics
	// remain intact after the additive migration and v8 write.
	legacy, err := store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy) != 1 || legacy[0].ID != record.RecordID() || legacy[0].Action != "diagnostic.emit" ||
		legacy[0].Structured["message"] != "projected local message" {
		t.Fatalf("legacy reader rows = %#v", legacy)
	}
}

func TestEventHistoryWriterCommitsCorrelationObservationAtomically(t *testing.T) {
	store := newV8HistoryStore(t)
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{eventName: "diagnostic.message"})
	buildRecord := func(recordID string, semantic SemanticEventID, traceID, spanID string) observability.Record {
		record, err := observability.NewRecord(observability.RecordInput{
			Timestamp: time.Now().UTC(), RecordID: recordID,
			Identity: observability.EventIdentity{Bucket: observability.BucketDiagnostic,
				Signal: observability.SignalLogs, Name: "diagnostic.message"},
			Source: observability.SourceGateway, Connector: "codex", Action: "diagnostic.emit",
			Outcome: observability.OutcomeCompleted,
			Correlation: observability.Correlation{
				SemanticEventID: string(semantic), LogicalEventID: string(event.LogicalEventID),
				ConnectorInstanceID: string(instance.ConnectorInstanceID), SessionID: "session",
				TurnID: "turn", TraceID: traceID,
				SpanID: spanID, AgentID: "agent",
			},
			Provenance: observability.Provenance{Producer: "gateway.audit", BinaryVersion: "v8-test",
				RegistrySchemaVersion: 1, ConfigGeneration: 1,
				ConfigDigest: stringsOf("a", 64)},
			Body: map[string]any{
				"message":                        "correlated",
				"defenseclaw.agent.lifecycle.id": "lifecycle-exact",
				"defenseclaw.agent.execution.id": "execution-exact",
			},
			FieldClasses: map[string]observability.FieldClass{
				"/message":                        observability.FieldClassContent,
				"/defenseclaw.agent.lifecycle.id": observability.FieldClassIdentifier,
				"/defenseclaw.agent.execution.id": observability.FieldClassIdentifier,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := buildRecord("atomic-correlation-log", event.SemanticEventID,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	var auditRows, observationRows int
	var projectionHash string
	if err := store.db.QueryRow(`SELECT COUNT(*), MAX(projection_hash) FROM audit_events WHERE id=?`, record.RecordID()).Scan(&auditRows, &projectionHash); err != nil {
		t.Fatal(err)
	}
	var observedHash, observedLifecycleID, observedExecutionID string
	if err := store.db.QueryRow(`SELECT COUNT(*), MAX(projection_hash), MAX(lifecycle_id), MAX(execution_id)
		FROM correlation_observations WHERE record_id=?`, record.RecordID()).Scan(
		&observationRows, &observedHash, &observedLifecycleID, &observedExecutionID,
	); err != nil {
		t.Fatal(err)
	}
	if auditRows != 1 || observationRows != 1 || observedHash != projectionHash ||
		observedLifecycleID != "lifecycle-exact" || observedExecutionID != "execution-exact" {
		t.Fatalf("audit=%d observation=%d hashes=%q/%q lifecycle/execution=%q/%q",
			auditRows, observationRows, projectionHash, observedHash, observedLifecycleID, observedExecutionID)
	}
	for _, anchor := range []CorrelationAnchor{
		{LifecycleID: "lifecycle-exact"},
		{ExecutionID: "execution-exact"},
	} {
		graph, queryErr := repo.QueryGraph(t.Context(), CorrelationGraphQuery{
			Anchor: anchor, Page: CorrelationPageRequest{Limit: 10},
		})
		if queryErr != nil || len(graph.Events) != 1 || graph.Events[0].SemanticEventID != event.SemanticEventID {
			t.Fatalf("anchor=%+v graph=%+v err=%v", anchor, graph, queryErr)
		}
	}

	legacy := buildRecord("atomic-correlation-legacy-trace", event.SemanticEventID, "trace-123", "span-123")
	legacyProjection := projectV8HistoryRecord(t, legacy, observabilityredaction.ProfileNone)
	if err := writer.Append(legacy, legacyProjection); err != nil {
		t.Fatalf("legacy opaque trace correlation prevented audit persistence: %v", err)
	}
	var legacyAuditTrace sql.NullString
	if err := store.db.QueryRow(`SELECT trace_id FROM audit_events WHERE id=?`, legacy.RecordID()).Scan(&legacyAuditTrace); err != nil {
		t.Fatal(err)
	}
	var observationTrace, observationSpan sql.NullString
	if err := store.db.QueryRow(`SELECT trace_id, span_id FROM correlation_observations WHERE record_id=?`, legacy.RecordID()).Scan(&observationTrace, &observationSpan); err != nil {
		t.Fatal(err)
	}
	if !legacyAuditTrace.Valid || legacyAuditTrace.String != "trace-123" || observationTrace.Valid || observationSpan.Valid {
		t.Fatalf("legacy/exact topology split = audit:%#v observation:%#v/%#v",
			legacyAuditTrace, observationTrace, observationSpan)
	}

	missing, _ := NewSemanticEventID()
	failed := buildRecord("atomic-correlation-missing", missing,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb")
	failedProjection := projectV8HistoryRecord(t, failed, observabilityredaction.ProfileNone)
	if err := writer.Append(failed, failedProjection); err == nil {
		t.Fatal("event-history append succeeded without an accepted correlation event")
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, failed.RecordID()).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Fatal("failed correlation observation left a partially committed audit row")
	}
}

func TestExactLogLifecycleAndExecutionAttributesRejectAliasesAndInvalidValues(t *testing.T) {
	maximumIdentifier := stringsOf("a", maxCanonicalLogCorrelationIdentifierBytes)
	lifecycleID, executionID := exactLogLifecycleAndExecutionAttributes(map[string]any{
		"attributes": map[string]any{
			"defenseclaw.agent.lifecycle.id": maximumIdentifier,
			"defenseclaw.agent.execution.id": "execution:1",
		},
	})
	if lifecycleID != maximumIdentifier || executionID != "execution:1" {
		t.Fatalf("exact lifecycle/execution=%q/%q", lifecycleID, executionID)
	}

	lifecycleID, executionID = exactLogLifecycleAndExecutionAttributes(map[string]any{
		"lifecycle_id":                   "alias-lifecycle",
		"execution_id":                   "alias-execution",
		"defenseclaw.agent.lifecycle.id": stringsOf("a", maxCanonicalLogCorrelationIdentifierBytes+1),
		"defenseclaw.agent.execution.id": " execution-with-space",
	})
	if lifecycleID != "" || executionID != "" {
		t.Fatalf("unsafe lifecycle/execution accepted=%q/%q", lifecycleID, executionID)
	}
}

func TestLegacyAlertQueryCannotTreatV8HistoryAsMutableQueue(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-immutable-alert", "immutable v8 finding")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	alerts, err := store.ListAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("legacy alert query included v8 immutable history: %#v", alerts)
	}
	if got := loadV8HistoryRow(t, store, record.RecordID()).Severity; got != "HIGH" {
		t.Fatalf("v8 immutable severity changed to %q", got)
	}
}

func TestEventHistoryWriterSignedAndUnavailableIntegrity(t *testing.T) {
	store := newV8HistoryStore(t)
	key := bytes.Repeat([]byte{0x24}, 32)
	signer := &testProjectionSigner{key: key, keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-signed", "signed projected message")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	row := loadV8HistoryRow(t, store, record.RecordID())
	projected, _ := projection.Bytes()
	wantMessage := projectionIntegrityMessage(projected, ProjectionIntegrityAlgorithm, signer.keyID)
	if len(signer.messages) != 1 || !bytes.Equal(signer.messages[0], wantMessage) {
		t.Fatalf("signer message was not the exact domain-separated projection")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(wantMessage)
	if row.PayloadHMAC != hex.EncodeToString(mac.Sum(nil)) ||
		row.IntegrityAlgorithm != ProjectionIntegrityAlgorithm || row.IntegrityKeyID != signer.keyID {
		t.Fatalf("signed integrity columns = %#v", row)
	}
	verified, err := writer.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status != EventHistoryVerified || !verified.ProjectionHashValid ||
		!verified.IntegrityVerified || verified.IntegrityKeyID != signer.keyID {
		t.Fatalf("signed verification = %#v", verified)
	}
	rotatedWriter, err := NewEventHistoryWriter(store, &testProjectionSigner{
		key: bytes.Repeat([]byte{0x25}, 32), keyID: "integrity-key-v2",
	}, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rotatedWriter.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Status != EventHistoryKeyUnavailable || !rotated.ProjectionHashValid || rotated.IntegrityVerified {
		t.Fatalf("rotated-key verification = %#v", rotated)
	}

	unavailable := &testProjectionSigner{
		keyID: "integrity-key-v1",
		err:   fmt.Errorf("custody not ready: %w", ErrIntegrityKeyUnavailable),
	}
	unsignedWriter, err := NewEventHistoryWriter(store, unavailable, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	unsignedRecord := newV8HistoryRecord(t, "history-key-unavailable", "unsigned projected message")
	unsignedProjection := projectV8HistoryRecord(t, unsignedRecord, observabilityredaction.ProfileNone)
	if err := unsignedWriter.Append(unsignedRecord, unsignedProjection); err != nil {
		t.Fatal(err)
	}
	unsignedRow := loadV8HistoryRow(t, store, unsignedRecord.RecordID())
	if unsignedRow.PayloadHMAC != "" || unsignedRow.IntegrityAlgorithm != "" || unsignedRow.IntegrityKeyID != "" {
		t.Fatalf("key-unavailable row must be unsigned: %#v", unsignedRow)
	}
	unsignedResult, err := unsignedWriter.VerifyEventHistoryRecord(t.Context(), unsignedRecord.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if unsignedResult.Status != EventHistoryUnsigned || !unsignedResult.ProjectionHashValid ||
		unsignedResult.IntegrityVerified || unsignedResult.IntegrityKeyID != "" {
		t.Fatalf("unsigned verification = %#v", unsignedResult)
	}
}

func TestEventHistoryVerificationDetectsStoredTamperingAndSupportsRange(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{key: bytes.Repeat([]byte{0x31}, 32), keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 3, 14, 15, 16, 0, time.UTC)
	first := newV8HistoryRecordAt(t, "history-range-a", "first projected message", base.Add(100*time.Millisecond))
	second := newV8HistoryRecordAt(t, "history-range-b", "second projected message", base.Add(500*time.Millisecond))
	for _, record := range []observability.Record{first, second} {
		projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
		if err := writer.Append(record, projection); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.LogEvent(Event{
		ID: "legacy-range", Timestamp: base.Add(250 * time.Millisecond), Action: "legacy.action",
		Actor: "legacy", Details: "legacy row", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}
	page, err := writer.VerifyEventHistoryRange(
		t.Context(), base, base.Add(time.Second), 10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if page.Truncated || len(page.Records) != 3 || page.Records[0].RecordID != first.RecordID() ||
		page.Records[1].RecordID != "legacy-range" || page.Records[2].RecordID != second.RecordID() {
		t.Fatalf("range verification order/results = %#v", page)
	}
	if legacy := page.Records[1]; legacy.Status != EventHistoryNotProjected || legacy.ProjectionHashValid ||
		legacy.IntegrityVerified {
		t.Fatalf("legacy verification = %#v", legacy)
	}
	for _, result := range []EventHistoryVerification{page.Records[0], page.Records[2]} {
		if result.Status != EventHistoryVerified || !result.ProjectionHashValid || !result.IntegrityVerified {
			t.Fatalf("range verification = %#v", result)
		}
	}
	truncated, err := writer.VerifyEventHistoryRange(t.Context(), base, base.Add(time.Second), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated.Truncated || len(truncated.Records) != 2 {
		t.Fatalf("bounded range did not report truncation: %#v", truncated)
	}
	for _, invalid := range []struct {
		from, until time.Time
		limit       int
	}{
		{from: time.Time{}, until: base.Add(time.Second), limit: 1},
		{from: base, until: base, limit: 1},
		{from: base.Add(time.Second), until: base, limit: 1},
		{from: base, until: base.Add(time.Second), limit: 0},
		{from: base, until: base.Add(time.Second), limit: maxEventHistoryVerificationRange + 1},
	} {
		if _, err := writer.VerifyEventHistoryRange(t.Context(), invalid.from, invalid.until, invalid.limit); err == nil {
			t.Fatalf("invalid range accepted: %#v", invalid)
		}
	}

	if _, err := store.db.Exec(`UPDATE audit_events SET projected_record_json=? WHERE id=?`,
		`{"body":{"message":"tampered"}}`, first.RecordID()); err != nil {
		t.Fatal(err)
	}
	tampered, err := writer.VerifyEventHistoryRecord(t.Context(), first.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Status != EventHistoryHashMismatch || tampered.ProjectionHashValid || tampered.IntegrityVerified {
		t.Fatalf("projected-record tamper verification = %#v", tampered)
	}

	if _, err := store.db.Exec(`UPDATE audit_events SET payload_hmac=? WHERE id=?`,
		strings.Repeat("0", sha256.Size*2), second.RecordID()); err != nil {
		t.Fatal(err)
	}
	hmacTampered, err := writer.VerifyEventHistoryRecord(t.Context(), second.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if hmacTampered.Status != EventHistoryHMACMismatch || !hmacTampered.ProjectionHashValid ||
		hmacTampered.IntegrityVerified {
		t.Fatalf("HMAC tamper verification = %#v", hmacTampered)
	}
}

func TestEventHistoryIntegrityDiffersForDifferentRedactionProjections(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, 32)
	record := newV8HistoryRecord(t, "history-profile-difference", "sensitive projected content")

	noneStore := newV8HistoryStore(t)
	noneWriter, err := NewEventHistoryWriter(
		noneStore, &testProjectionSigner{key: key, keyID: "integrity-key-v1"}, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
	)
	if err != nil {
		t.Fatal(err)
	}
	noneProjection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := noneWriter.Append(record, noneProjection); err != nil {
		t.Fatal(err)
	}
	noneRow := loadV8HistoryRow(t, noneStore, record.RecordID())

	contentStore := newV8HistoryStore(t)
	contentWriter, err := NewEventHistoryWriter(
		contentStore, &testProjectionSigner{key: key, keyID: "integrity-key-v1"}, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileContent},
	)
	if err != nil {
		t.Fatal(err)
	}
	contentProjection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileContent)
	if err := contentWriter.Append(record, contentProjection); err != nil {
		t.Fatal(err)
	}
	contentRow := loadV8HistoryRow(t, contentStore, record.RecordID())

	if noneRow.ProjectedRecordJSON == contentRow.ProjectedRecordJSON ||
		noneRow.ProjectionHash == contentRow.ProjectionHash || noneRow.PayloadHMAC == contentRow.PayloadHMAC {
		t.Fatalf("different redaction projections shared bytes/hash/HMAC: none=%#v content=%#v", noneRow, contentRow)
	}
	for _, writer := range []*EventHistoryWriter{noneWriter, contentWriter} {
		result, err := writer.VerifyEventHistoryRecord(t.Context(), record.RecordID())
		if err != nil || result.Status != EventHistoryVerified {
			t.Fatalf("projection verification result=%#v err=%v", result, err)
		}
	}
}

func TestEventHistoryIntegrityCoversAlgorithmAndKeyIdentity(t *testing.T) {
	store := newV8HistoryStore(t)
	key := bytes.Repeat([]byte{0x3a}, 32)
	writer, err := NewEventHistoryWriter(
		store, &testProjectionSigner{key: key, keyID: "integrity-key-v1"}, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
	)
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-integrity-metadata", "signed metadata")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	unavailableVerifier, err := NewEventHistoryWriter(store, &testProjectionSigner{
		keyID: "integrity-key-v1", err: ErrIntegrityKeyUnavailable,
	}, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := unavailableVerifier.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != EventHistoryKeyUnavailable || !unavailable.ProjectionHashValid ||
		unavailable.IntegrityVerified {
		t.Fatalf("verification key unavailable = %#v", unavailable)
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET integrity_key_id=? WHERE id=?`,
		"integrity-key-v2", record.RecordID()); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEventHistoryWriter(
		store, &testProjectionSigner{key: key, keyID: "integrity-key-v2"}, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != EventHistoryHMACMismatch || !result.ProjectionHashValid {
		t.Fatalf("changed key identity verification = %#v", result)
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET integrity_algorithm=? WHERE id=?`,
		"hmac-sha512", record.RecordID()); err != nil {
		t.Fatal(err)
	}
	result, err = verifier.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != EventHistoryInvalidIntegrity || !result.ProjectionHashValid {
		t.Fatalf("changed integrity algorithm verification = %#v", result)
	}
	for name, malformed := range map[string]string{
		"non-hex": "zz",
		"short":   strings.Repeat("0", sha256.Size*2-2),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.db.Exec(`UPDATE audit_events
				SET integrity_algorithm=?, payload_hmac=? WHERE id=?`,
				ProjectionIntegrityAlgorithm, malformed, record.RecordID()); err != nil {
				t.Fatal(err)
			}
			got, err := verifier.VerifyEventHistoryRecord(t.Context(), record.RecordID())
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != EventHistoryInvalidIntegrity || !got.ProjectionHashValid {
				t.Fatalf("malformed HMAC verification = %#v", got)
			}
		})
	}
}

func TestEventHistoryWriterPersistsMandatoryClassification(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC) }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "history-mandatory", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerGatewayEvent,
		ProducerKey:  "activity",
		ClassificationContext: observability.ClassificationContext{
			Bucket:      observability.BucketComplianceActivity,
			EventName:   "config.change.applied",
			RawSeverity: "WARN",
			MandatoryFacts: observability.MandatoryFacts{
				ControlPlaneMutation: true,
			},
		},
		Source:  observability.SourceOperatorAPI,
		Action:  "config.change",
		Phase:   "apply",
		Outcome: observability.OutcomeApplied,
		Provenance: observability.Provenance{
			Producer:              "operator_api",
			BinaryVersion:         "v8.0.0-test",
			RegistrySchemaVersion: 1,
			ConfigGeneration:      24,
		},
		Body: map[string]any{
			"target": "observability.routes",
			"reason": "approved change",
		},
		FieldClasses: map[string]observability.FieldClass{
			"/target": observability.FieldClassPath,
			"/reason": observability.FieldClassReason,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !record.Mandatory() {
		t.Fatal("fixture classification is not mandatory")
	}
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	row := loadV8HistoryRow(t, store, record.RecordID())
	if row.Mandatory != 1 || row.Bucket != "compliance.activity" || row.EventName != "config.change.applied" ||
		row.Target != "observability.routes" {
		t.Fatalf("mandatory row = %#v", row)
	}
}

func TestEventHistoryWriterRejectsMalformedOrMismatchedInputs(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	recordA := newV8HistoryRecord(t, "history-a", "same projected message")
	recordB := newV8HistoryRecord(t, "history-b", "same projected message")
	projectionA := projectV8HistoryRecord(t, recordA, observabilityredaction.ProfileNone)

	tests := []struct {
		name       string
		record     observability.Record
		projection observabilityredaction.Projection
	}{
		{name: "zero record", record: observability.Record{}, projection: projectionA},
		{name: "zero projection", record: recordA, projection: observabilityredaction.Projection{}},
		{name: "different record", record: recordB, projection: projectionA},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := writer.Append(test.record, test.projection); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	strictWriter, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileStrict})
	if err != nil {
		t.Fatal(err)
	}
	if err := strictWriter.Append(recordA, projectionA); err == nil {
		t.Fatal("projection with a profile different from the effective local route was accepted")
	}
	if err := writer.AppendContext(nil, recordA, projectionA); err == nil {
		t.Fatal("nil context was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.AppendContext(cancelled, recordA, projectionA); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	trace, err := observability.NewRecord(observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 16, 0, 0, 0, time.UTC),
		RecordID:  "history-trace",
		Identity: observability.EventIdentity{
			Bucket: observability.BucketAgentLifecycle,
			Signal: observability.SignalTraces,
			Name:   "span.workflow.run",
		},
		SpanName: "workflow run",
		Source:   observability.SourceGateway,
		Provenance: observability.Provenance{
			Producer:              "gateway.trace",
			BinaryVersion:         "v8.0.0-test",
			RegistrySchemaVersion: 1,
			ConfigGeneration:      23,
		},
		Body: map[string]any{"state": "completed"},
		FieldClasses: map[string]observability.FieldClass{
			"/state": observability.FieldClassMetadata,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	traceProjection := projectV8HistoryRecord(t, trace, observabilityredaction.ProfileNone)
	if err := writer.Append(trace, traceProjection); err == nil {
		t.Fatal("trace projection was accepted by the SQLite log history writer")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected inputs left %d rows, err=%v", count, err)
	}
}

func TestEventHistoryWriterRejectsCrossGenerationProjectionContext(t *testing.T) {
	store := newV8HistoryStore(t)
	boundEngine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	none, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	writer, err := NewEventHistoryWriter(
		store, nil, nil,
		newTestTrustedLocalProjectionBinding(t, strings.Repeat("1", 64), boundEngine, none),
	)
	if err != nil {
		t.Fatal(err)
	}
	if writer.GraphDigest() != strings.Repeat("1", 64) {
		t.Fatalf("writer graph digest = %q", writer.GraphDigest())
	}

	for _, test := range []struct {
		name string
		key  []byte
	}{
		{name: "foreign engine same key", key: bytes.Repeat([]byte{0x21}, 32)},
		{name: "foreign engine different key", key: bytes.Repeat([]byte{0x22}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			foreign, engineErr := observabilityredaction.NewEngine(test.key)
			if engineErr != nil {
				t.Fatal(engineErr)
			}
			record := newV8HistoryRecord(t, "cross-generation-"+strings.ReplaceAll(test.name, " ", "-"), "private")
			projection, _, projectErr := foreign.Project(record, none)
			if projectErr != nil {
				t.Fatal(projectErr)
			}
			if appendErr := writer.Append(record, projection); appendErr == nil ||
				!strings.Contains(appendErr.Error(), "active graph") {
				t.Fatalf("foreign projection error = %v", appendErr)
			}
		})
	}

	profileA, err := observabilityredaction.NewCustomProfile(
		"same-name", observabilityredaction.ProfileSensitive, nil,
		map[observability.FieldClass]observabilityredaction.TransformationMode{
			observability.FieldClassContent: observabilityredaction.ModeWhole,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	profileB, err := observabilityredaction.NewCustomProfile(
		"same-name", observabilityredaction.ProfileSensitive, nil,
		map[observability.FieldClass]observabilityredaction.TransformationMode{
			observability.FieldClassContent: observabilityredaction.ModeRemove,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	customWriter, err := NewEventHistoryWriter(
		store, nil, nil,
		newTestTrustedLocalProjectionBinding(t, strings.Repeat("2", 64), boundEngine, profileA),
	)
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "same-name-different-definition", "private")
	projection, _, err := boundEngine.Project(record, profileB)
	if err != nil {
		t.Fatal(err)
	}
	if err := customWriter.Append(record, projection); err == nil || !strings.Contains(err.Error(), "active graph") {
		t.Fatalf("same-name different-definition projection error = %v", err)
	}

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cross-generation projections left %d rows, err=%v", count, err)
	}
}

func TestEventHistoryWriterRollsBackFailuresAndInsertsOnce(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-once", "one projected message")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	if err := writer.Append(record, projection); err == nil {
		t.Fatal("duplicate record ID was accepted")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, record.RecordID()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate attempt left %d rows, err=%v", count, err)
	}

	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_v8_history BEFORE INSERT ON audit_events
		WHEN NEW.id = 'history-rejected'
		BEGIN
			SELECT RAISE(ABORT, 'forced v8 history failure');
		END`); err != nil {
		t.Fatal(err)
	}
	rejected := newV8HistoryRecord(t, "history-rejected", "rejected projected message")
	rejectedProjection := projectV8HistoryRecord(t, rejected, observabilityredaction.ProfileNone)
	if err := writer.Append(rejected, rejectedProjection); err == nil {
		t.Fatal("triggered insert failure was hidden")
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, rejected.RecordID()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed transaction left %d rows, err=%v", count, err)
	}
}

func TestEventHistoryWriterNeverFallsBackToRawRecord(t *testing.T) {
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileContent})
	if err != nil {
		t.Fatal(err)
	}
	const rawMarker = "unprojected-private-material-unique-marker"
	record := newV8HistoryRecord(t, "history-redacted", rawMarker)
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileContent)
	if bytes.Contains(mustProjectionBytes(t, projection), []byte(rawMarker)) {
		t.Fatal("test projection unexpectedly contains the raw marker")
	}
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	row := loadV8HistoryRow(t, store, record.RecordID())
	for field, value := range map[string]string{
		"payload_json":          row.PayloadJSON,
		"projected_record_json": row.ProjectedRecordJSON,
		"structured_json":       row.StructuredJSON,
		"details":               row.Details,
		"target":                row.Target,
		"content_hash":          row.ContentHash,
		"projection_hash":       row.ProjectionHash,
		"payload_hmac":          row.PayloadHMAC,
	} {
		if strings.Contains(value, rawMarker) {
			t.Fatalf("%s used a raw-record fallback", field)
		}
	}
}

func TestEventHistoryCanonicalFamiliesCannotRestoreRawCompatibilityColumns(t *testing.T) {
	const rawMarker = "canonical-source-private-material-unique-marker"
	for _, profileName := range []observabilityredaction.ProfileName{
		observabilityredaction.ProfileContent,
		observabilityredaction.ProfileStrict,
	} {
		t.Run(string(profileName), func(t *testing.T) {
			store := newV8HistoryStore(t)
			writer, err := NewEventHistoryWriter(
				store, nil, nil, testLocalProfileResolver{profile: profileName},
			)
			if err != nil {
				t.Fatal(err)
			}
			event := Event{
				ID: "canonical-no-raw-" + string(profileName), Timestamp: time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC),
				Action: string(ActionConfigUpdate), Target: "target-" + rawMarker,
				Actor: "defenseclaw", Details: "details-" + rawMarker, Severity: "INFO",
				RunID: "run-no-raw", Structured: map[string]any{"private": rawMarker},
			}
			stampAuditEventEnvelope(&event)
			normalized := observability.NormalizeSeverity(event.Severity)
			record, err := buildControlPlaneV8Record(
				event, controlPlaneV8FamilyConfigApplied, observability.SourceSystem,
				controlPlaneV8Classification(controlPlaneV8FamilyConfigApplied, event.Severity),
				normalized,
				RuntimeV8BuildContext{ConfigGeneration: 23, ConfigDigest: testEventHistoryGraphDigest},
				router.AdmissionOrdinary,
				controlPlaneV8Evidence{targetRef: observability.Present("config:observability")},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !record.SchemaDerivedFieldClasses() {
				t.Fatal("test record is not a schema-derived canonical family")
			}
			projection := projectV8HistoryRecord(t, record, profileName)
			ctx := contextWithLegacyEventProjection(context.Background(), event)
			if err := writer.AppendContext(ctx, record, projection); err != nil {
				t.Fatal(err)
			}
			row := loadV8HistoryRow(t, store, record.RecordID())
			for field, value := range map[string]string{
				"target": row.Target, "details": row.Details, "structured_json": row.StructuredJSON,
				"payload_json": row.PayloadJSON, "projected_record_json": row.ProjectedRecordJSON,
			} {
				if strings.Contains(value, rawMarker) {
					t.Fatalf("%s restored raw canonical source after %s projection", field, profileName)
				}
			}
		})
	}
}

func TestEventHistoryWriterSigningFailureLeavesNoRow(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{keyID: "integrity-key-v1", err: errors.New("signing failed")}
	health := &testEventHistoryHealthReporter{}
	writer, err := NewEventHistoryWriter(store, signer, health, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-sign-failed", "projected message")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err == nil {
		t.Fatal("signing failure was hidden")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("signing failure left %d rows, err=%v", count, err)
	}
	if len(health.codes) != 1 || health.codes[0] != EventHistoryHealthSigningFailed {
		t.Fatalf("signing failure health = %#v", health.codes)
	}
}

func TestEventHistoryWriterPreservesSignerCancellationWithoutDegradingHealth(t *testing.T) {
	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cancellation.Error(), func(t *testing.T) {
			store := newV8HistoryStore(t)
			health := &testEventHistoryHealthReporter{}
			writer, err := NewEventHistoryWriter(
				store,
				&testProjectionSigner{keyID: "integrity-key-v1", err: cancellation},
				health,
				testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
			)
			if err != nil {
				t.Fatal(err)
			}
			record := newV8HistoryRecord(t, "history-sign-cancelled-"+strings.ReplaceAll(cancellation.Error(), " ", "-"), "private")
			projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
			if err := writer.Append(record, projection); !errors.Is(err, cancellation) {
				t.Fatalf("signer cancellation = %v, want %v", err, cancellation)
			}
			var count int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, record.RecordID()).
				Scan(&count); err != nil || count != 0 {
				t.Fatalf("cancelled signer left %d rows, err=%v", count, err)
			}
			if len(health.codes) != 0 {
				t.Fatalf("request cancellation degraded event-history health: %#v", health.codes)
			}
		})
	}
}

func TestEventHistorySanitizedWriteErrorPreservesMessageOnlyBusyDetection(t *testing.T) {
	err := eventHistoryFailure(
		EventHistoryHealthWriteFailed,
		&eventHistoryWriteError{cause: errors.New("database is locked")},
	)
	if strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("sanitized event-history error exposed driver diagnostics: %v", err)
	}
	if !isSQLiteBusy(err) {
		t.Fatal("sanitized event-history wrapper hid message-only SQLite BUSY from retry detection")
	}
}

func TestEventHistoryWriterRejectsInvalidSignerDigestAndKeyID(t *testing.T) {
	tests := []struct {
		name   string
		signer *testProjectionSigner
	}{
		{name: "short digest", signer: &testProjectionSigner{
			keyID: "integrity-key-v1", digest: bytes.Repeat([]byte{0x41}, sha256.Size-1),
		}},
		{name: "invalid key id", signer: &testProjectionSigner{
			key: bytes.Repeat([]byte{0x42}, 32), keyID: "invalid\nkey",
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newV8HistoryStore(t)
			health := &testEventHistoryHealthReporter{}
			writer, err := NewEventHistoryWriter(store, test.signer, health, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
			if err != nil {
				t.Fatal(err)
			}
			record := newV8HistoryRecord(t, fmt.Sprintf("history-invalid-signer-%d", index), "private")
			projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
			if err := writer.Append(record, projection); err == nil {
				t.Fatal("invalid signer output was accepted")
			}
			var count int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid signer left %d rows, err=%v", count, err)
			}
			if len(health.codes) != 1 || health.codes[0] != EventHistoryHealthSigningFailed {
				t.Fatalf("invalid signer health = %#v", health.codes)
			}
		})
	}
}

func TestEventHistoryWriterReportsBoundedProjectionUnsignedAndWriteHealth(t *testing.T) {
	store := newV8HistoryStore(t)
	health := &testEventHistoryHealthReporter{}
	writer, err := NewEventHistoryWriter(store, nil, health, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-health", "private value must not enter health")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	strictWriter, err := NewEventHistoryWriter(store, nil, health, testLocalProfileResolver{profile: observabilityredaction.ProfileStrict})
	if err != nil {
		t.Fatal(err)
	}
	if err := strictWriter.Append(record, projection); err == nil {
		t.Fatal("wrong-profile projection was accepted")
	}
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_health_write BEFORE INSERT ON audit_events
		WHEN NEW.id = 'history-health-write' BEGIN SELECT RAISE(ABORT, 'private trigger text'); END`); err != nil {
		t.Fatal(err)
	}
	writeRecord := newV8HistoryRecord(t, "history-health-write", "another private value")
	writeProjection := projectV8HistoryRecord(t, writeRecord, observabilityredaction.ProfileNone)
	writeErr := writer.Append(writeRecord, writeProjection)
	if writeErr == nil {
		t.Fatal("triggered write failure was hidden")
	}
	if strings.Contains(writeErr.Error(), "private trigger text") ||
		strings.Contains(writeErr.Error(), "another private value") {
		t.Fatalf("write error leaked private diagnostics: %v", writeErr)
	}
	want := []EventHistoryHealthCode{
		EventHistoryHealthProjectionRejected,
		EventHistoryHealthUnsigned,
		EventHistoryHealthWriteFailed,
	}
	if !reflect.DeepEqual(health.codes, want) {
		t.Fatalf("health codes = %#v, want %#v", health.codes, want)
	}
	encoded, err := json.Marshal(health.codes)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private value", "private trigger text", "another private value"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("health output leaked %q", secret)
		}
	}
}

func TestEventHistoryWriterReportsHealthOnlyAfterTransactionEnds(t *testing.T) {
	store := newV8HistoryStore(t)
	health := &queryingEventHistoryHealthReporter{
		store: store, closeOnCode: EventHistoryHealthWriteFailed,
	}
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	noneBinding := testLocalProfileResolver{
		profile: observabilityredaction.ProfileNone, engine: engine,
	}
	noneWriter, err := NewEventHistoryWriter(store, nil, health, noneBinding)
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-querying-health", "private value")
	noneProjection := projectV8HistoryRecordWithEngine(
		t, engine, record, observabilityredaction.ProfileNone,
	)

	strictWriter, err := NewEventHistoryWriter(store, nil, health, testLocalProfileResolver{
		profile: observabilityredaction.ProfileStrict, engine: engine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := strictWriter.Append(record, noneProjection); err == nil {
		t.Fatal("foreign-profile projection was accepted")
	}
	if err := noneWriter.Append(record, noneProjection); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_querying_health_write BEFORE INSERT ON audit_events
		WHEN NEW.id = 'history-querying-health-write'
		BEGIN SELECT RAISE(ABORT, 'value-bearing internal error'); END`); err != nil {
		t.Fatal(err)
	}
	failedRecord := newV8HistoryRecord(t, "history-querying-health-write", "another private value")
	failedProjection := projectV8HistoryRecordWithEngine(
		t, engine, failedRecord, observabilityredaction.ProfileNone,
	)
	if err := noneWriter.Append(failedRecord, failedProjection); err == nil {
		t.Fatal("injected write failure was hidden")
	}

	wantCodes := []EventHistoryHealthCode{
		EventHistoryHealthProjectionRejected,
		EventHistoryHealthUnsigned,
		EventHistoryHealthWriteFailed,
	}
	if !reflect.DeepEqual(health.codes, wantCodes) {
		t.Fatalf("health codes = %#v, want %#v", health.codes, wantCodes)
	}
	if len(health.errors) != len(wantCodes) {
		t.Fatalf("health query count = %d, want %d", len(health.errors), len(wantCodes))
	}
	for index, err := range health.errors {
		if err != nil {
			t.Fatalf("health callback %d could not query single-connection store after transaction: %v", index, err)
		}
	}
	if len(health.closeErrors) != 1 || health.closeErrors[0] != nil {
		t.Fatalf("health callback could not close store after lifecycle release: %#v", health.closeErrors)
	}
}

func TestEventHistoryWriterSerializesSignedUnsignedTransitionsWhileReporterBlocked(t *testing.T) {
	store := newV8HistoryStore(t)
	reporter := &blockingEventHistoryHealthReporter{
		started: make(chan EventHistoryHealthCode, 1), release: make(chan struct{}),
	}
	signer := &toggleProjectionSigner{}
	for index := range signer.key {
		signer.key[index] = 0x5a
	}
	signer.unavailable.Store(true)
	writer, err := NewEventHistoryWriter(
		store, signer, reporter,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
	)
	if err != nil {
		t.Fatal(err)
	}

	buildRecord := func(id string) (observability.Record, observabilityredaction.Projection) {
		record := newV8HistoryRecord(t, id, "private value")
		projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
		return record, projection
	}
	firstRecord, firstProjection := buildRecord("history-transition-unsigned-1")
	signedRecord, signedProjection := buildRecord("history-transition-signed")
	secondRecord, secondProjection := buildRecord("history-transition-unsigned-2")
	firstDone := make(chan error, 1)
	go func() { firstDone <- writer.Append(firstRecord, firstProjection) }()
	select {
	case code := <-reporter.started:
		if code != EventHistoryHealthUnsigned {
			t.Fatalf("first health code = %q, want unsigned", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unsigned reporter did not start")
	}

	// The first callback is blocked after its transaction and lifecycle lock
	// ended. A signed recovery and a later unsigned transition must both commit
	// without racing health state or losing the later transition.
	signer.unavailable.Store(false)
	if err := writer.Append(signedRecord, signedProjection); err != nil {
		t.Fatal(err)
	}
	signer.unavailable.Store(true)
	if err := writer.Append(secondRecord, secondProjection); err != nil {
		t.Fatal(err)
	}
	close(reporter.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	want := []EventHistoryHealthCode{
		EventHistoryHealthUnsigned,
		EventHistoryHealthUnsigned,
	}
	if got := reporter.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("signed/unsigned health sequence = %#v, want %#v", got, want)
	}
}

func mustProjectionBytes(t *testing.T, projection observabilityredaction.Projection) []byte {
	t.Helper()
	encoded, err := projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
