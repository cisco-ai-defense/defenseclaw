// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type historicalEvidencePurgeFixture struct {
	store            *Store
	migration        migration
	migrationVersion int
}

var historicalEvidenceTables = []string{
	"findings", "scan_findings", "scan_results", "audit_events",
}

var historicalOperationalStateTables = []string{
	"actions",
	"activity_events",
	"target_snapshots",
	"alert_acknowledgement_projection",
	"alert_acknowledgement_operations",
	"alert_acknowledgement_baselines",
	"alert_acknowledgement_health",
	"correlation_connector_instances",
	"correlation_events",
	"correlation_observations",
	"guardrail_chain_deny_receipts",
	"guardrail_chain_cutoff_barriers",
}

func TestHistoricalEvidencePurgeMigrationDeletesHistoryAndKeepsRuntimeUsable(t *testing.T) {
	fixture := newHistoricalEvidencePurgeFixture(t)
	beforeOperational := snapshotHistoricalEvidenceTables(t, fixture.store.db, historicalOperationalStateTables...)

	if err := fixture.store.Init(); err != nil {
		t.Fatalf("apply historical evidence purge through Init: %v", err)
	}
	version, err := fixture.store.SchemaVersion()
	if err != nil || version != len(migrations) {
		t.Fatalf("schema version=%d want=%d err=%v", version, len(migrations), err)
	}
	assertHistoricalEvidenceTablesEmpty(t, fixture.store.db)
	assertHistoricalEvidenceQueriesEmpty(t, fixture.store)
	assertHistoricalEvidenceSchemaSurvives(t, fixture.store.db)
	assertHistoricalEvidenceForeignKeysClean(t, fixture.store.db)

	afterOperational := snapshotHistoricalEvidenceTables(t, fixture.store.db, historicalOperationalStateTables...)
	if !reflect.DeepEqual(afterOperational, beforeOperational) {
		t.Fatalf("operational state changed during evidence purge:\nbefore=%v\nafter=%v", beforeOperational, afterOperational)
	}

	// A direct helper replay is deliberately harmless. Production runs the
	// helper only through applyMigration, whose schema cursor prevents replay.
	if err := purgeHistoricalEvidence(fixture.store.db); err != nil {
		t.Fatalf("first empty purge replay: %v", err)
	}
	if err := purgeHistoricalEvidence(fixture.store.db); err != nil {
		t.Fatalf("second empty purge replay: %v", err)
	}
	assertHistoricalEvidenceTablesEmpty(t, fixture.store.db)
	if got := snapshotHistoricalEvidenceTables(t, fixture.store.db, historicalOperationalStateTables...); !reflect.DeepEqual(got, beforeOperational) {
		t.Fatalf("empty purge replay changed operational state: got=%v want=%v", got, beforeOperational)
	}

	assertHistoricalEvidenceCurrentWritesWork(t, fixture.store)
	assertHistoricalEvidenceForeignKeysClean(t, fixture.store.db)
}

func TestHistoricalEvidencePurgeMigrationRollsBackAllRowsAndCursor(t *testing.T) {
	fixture := newHistoricalEvidencePurgeFixture(t)
	tracked := append(append([]string{}, historicalEvidenceTables...), "schema_version")
	tracked = append(tracked, historicalOperationalStateTables...)
	before := snapshotHistoricalEvidenceTables(t, fixture.store.db, tracked...)
	if _, err := fixture.store.db.Exec(`
		CREATE TRIGGER historical_evidence_purge_fail_late
		BEFORE DELETE ON audit_events
		BEGIN
			SELECT RAISE(ABORT, 'forced late historical evidence purge failure');
		END`); err != nil {
		t.Fatal(err)
	}

	err := fixture.store.applyMigration(fixture.migrationVersion, fixture.migration)
	if err == nil || !strings.Contains(err.Error(), "forced late historical evidence purge failure") {
		t.Fatalf("late purge failure error=%v", err)
	}
	after := snapshotHistoricalEvidenceTables(t, fixture.store.db, tracked...)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("failed purge did not roll back every row and cursor:\nbefore=%v\nafter=%v", before, after)
	}
	version, versionErr := fixture.store.SchemaVersion()
	if versionErr != nil || version != fixture.migrationVersion-1 {
		t.Fatalf("schema version after rollback=%d want=%d err=%v", version, fixture.migrationVersion-1, versionErr)
	}
}

func TestHistoricalEvidencePurgeRequiresMandatoryActiveTables(t *testing.T) {
	for _, missing := range []string{"scan_findings", "scan_results", "audit_events"} {
		t.Run(missing, func(t *testing.T) {
			store := newPartialHistoricalEvidenceStore(t, missing)
			err := purgeHistoricalEvidence(store.db)
			if err == nil || !strings.Contains(err.Error(), "mandatory historical evidence table "+missing+" is missing") {
				t.Fatalf("missing %s error=%v", missing, err)
			}
			for _, table := range historicalEvidenceTables {
				if table == missing {
					continue
				}
				if got := historicalEvidenceTableCount(t, store.db, table); got != 1 {
					t.Fatalf("%s rows after preflight failure=%d want=1", table, got)
				}
			}
		})
	}
}

func TestHistoricalEvidencePurgeTreatsAbsentLegacyFindingsAsEmpty(t *testing.T) {
	store := newPartialHistoricalEvidenceStore(t, "findings")
	if err := purgeHistoricalEvidence(store.db); err != nil {
		t.Fatalf("purge without migration-1 findings table: %v", err)
	}
	for _, table := range []string{"scan_findings", "scan_results", "audit_events"} {
		if got := historicalEvidenceTableCount(t, store.db, table); got != 0 {
			t.Fatalf("%s rows after purge=%d want=0", table, got)
		}
	}
	if err := purgeHistoricalEvidence(store.db); err != nil {
		t.Fatalf("empty replay without legacy findings table: %v", err)
	}
}

func newHistoricalEvidencePurgeFixture(t *testing.T) historicalEvidencePurgeFixture {
	t.Helper()
	migration, migrationVersion := historicalEvidencePurgeMigration(t)
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < migrationVersion-1; index++ {
		if err := store.applyMigration(index+1, migrations[index]); err != nil {
			t.Fatalf("apply pre-purge migration %d (%s): %v", index+1, migrations[index].description, err)
		}
	}
	version, err := store.SchemaVersion()
	if err != nil || version != migrationVersion-1 {
		t.Fatalf("pre-purge schema version=%d want=%d err=%v", version, migrationVersion-1, err)
	}
	seedHistoricalEvidenceRows(t, store.db)
	seedHistoricalOperationalState(t, store.db)
	return historicalEvidencePurgeFixture{
		store: store, migration: migration, migrationVersion: migrationVersion,
	}
}

func historicalEvidencePurgeMigration(t *testing.T) (migration, int) {
	t.Helper()
	var found migration
	version := 0
	for index, candidate := range migrations {
		if candidate.description != historicalEvidencePurgeMigrationDescription {
			continue
		}
		if found.apply != nil {
			t.Fatal("multiple historical evidence purge migrations found")
		}
		found = candidate
		version = index + 1
	}
	if found.apply == nil || version == 0 {
		t.Fatal("historical evidence purge migration not found")
	}
	return found, version
}

func seedHistoricalEvidenceRows(t *testing.T, db *sql.DB) {
	t.Helper()
	const observed = "2026-08-11T12:00:00.123456789Z"
	if _, err := db.Exec(`
		INSERT INTO scan_results (
			id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json
		) VALUES
			('historical-scan', 'legacy-runtime', 'tool-response', ?, 10, 2, 'HIGH',
			 '{"findings":[{"title":"purged_evidence_historical"}],"root_extension":"purged_evidence_root"}'),
			('historical-missing-findings', 'legacy-runtime', 'tool-response', ?, 1, 0, 'HIGH',
			 '{"root_extension":"purged_evidence_missing_findings"}'),
			('historical-null-findings', 'legacy-runtime', 'tool-response', ?, 1, 0, 'HIGH',
			 '{"findings":null,"root_extension":"purged_evidence_null_findings"}');
		INSERT INTO findings (
			id, scan_id, severity, title, description, location, remediation, scanner, tags, rule_id
		) VALUES (
			'historical-legacy-finding', 'historical-scan', 'HIGH', 'purged_evidence_title',
			'purged_evidence_description', 'purged_evidence_location', 'purged_evidence_remediation',
			'legacy-runtime', '["secret","purged_evidence_tags"]', NULL
		);
		INSERT INTO scan_findings (
			id, scan_id, scanner, target, rule_id, category, severity, title,
			description, evidence_summary, location, remediation, tags, timestamp
		) VALUES (
			'historical-normalized-finding', 'historical-scan', 'legacy-runtime',
			'tool-response', NULL, 'credential-leak', 'HIGH', 'purged_evidence_title',
			'purged_evidence_description', 'purged_evidence_evidence', 'purged_evidence_location',
			'purged_evidence_remediation', '["secret","purged_evidence_tags"]', ?
		);
		INSERT INTO audit_events (
			id, timestamp, action, target, actor, details, structured_json, severity,
			bucket, event_name, payload_json, projected_record_json, projection_hash
		) VALUES
			('historical-finding-event', ?, 'finding', 'tool-response', 'legacy-runtime',
			 'purged_evidence_details', '{"root_extension":"purged_evidence_structured"}', 'HIGH',
			 'security.finding', 'finding.observed',
			 '{"root_extension":"purged_evidence_payload"}',
			 '{"attributes":{"root_extension":"purged_evidence_projected"}}', 'stale-hash'),
			('historical-null-event', ?, 'finding', 'tool-response', 'legacy-runtime',
			 NULL, NULL, 'HIGH', 'security.finding', 'finding.observed',
			 '{"defenseclaw.finding.rule_id":null,"root_extension":"purged_evidence_null_event"}',
			 NULL, NULL)
	`, observed, observed, observed, observed, observed, observed); err != nil {
		t.Fatal(err)
	}
}

func seedHistoricalOperationalState(t *testing.T, db *sql.DB) {
	t.Helper()
	const observed = "2026-08-11T12:00:00.123456789Z"
	if _, err := db.Exec(`
		INSERT INTO actions (
			id, target_type, target_name, source_path, actions_json, reason, updated_at
		) VALUES ('preserved-action', 'skill', 'safe-skill', '/safe/path',
			'{"install":"allow"}', 'operator state', ?);
		INSERT INTO activity_events (
			id, timestamp, actor, action, target_type, target_id, reason,
			before_json, after_json, diff_json
		) VALUES ('preserved-activity', ?, 'operator', 'config.save', 'config', 'gateway',
			'operator state', '{"enabled":false}', '{"enabled":true}', '{"enabled":true}');
		INSERT INTO target_snapshots (
			id, target_type, target_path, content_hash, dependency_hashes,
			config_hashes, network_endpoints, scan_id, captured_at
		) VALUES (
			'preserved-target-snapshot', 'skill', '/safe/path',
			'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
			'["dependency"]', '["config"]', '["safe.example"]',
			'historical-scan', ?
		);
		INSERT INTO correlation_connector_instances (
			connector_instance_id, connector, export_custody, profile_version,
			managed_config_digest, is_default, created_time_unix_nano, updated_time_unix_nano
		) VALUES (
			'11111111-1111-4111-8111-111111111111', 'splunk', 'external', 'v1',
			NULL, 0, 1000000000, 1000000000
		);
		INSERT INTO correlation_events (
			semantic_event_id, logical_group_id, connector, connector_instance_id,
			source_rail, event_name, received_time_unix_nano, first_record_id,
			profile_version, completeness
		) VALUES (
			'22222222-2222-4222-8222-222222222222',
			'33333333-3333-4333-8333-333333333333', 'splunk',
			'11111111-1111-4111-8111-111111111111', 'internal',
			'finding.observed', 1000000000, 'historical-finding-event', 'v1', 'complete'
		);
		INSERT INTO correlation_observations (
			record_id, semantic_event_id, signal, bucket, event_name,
			observed_time_unix_nano, projection_hash, status
		) VALUES (
			'historical-finding-event', '22222222-2222-4222-8222-222222222222',
			'logs', 'security.finding', 'finding.observed', 1000000000,
			'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
			'export_eligible'
		);
		INSERT INTO alert_acknowledgement_projection (
			alert_id, disposition, actor, disposition_at, projection_version,
			source, source_event_id, updated_at
		) VALUES
			('preserved-alert', 'acknowledged', 'operator', ?, 1,
			 'modern', 'preserved-alert-operation-event', ?),
			('preserved-baseline', 'acknowledged', 'legacy-operator', ?, 1,
			 'legacy_ack', 'preserved-legacy-event', ?);
		INSERT INTO alert_acknowledgement_operations (
			operation_id, command_fingerprint, alert_id, requested_disposition, actor,
			expected_projection_version, outcome, rejection_reason,
			observed_projection_version, projection_version_before,
			projection_version_after, event_id, created_at
		) VALUES (
			'preserved-operation', 'fingerprint', 'preserved-operation-alert',
			'acknowledged', 'operator', 0, 'applied', NULL, 0, 0, 1,
			'preserved-alert-operation-event', ?
		);
		INSERT INTO alert_acknowledgement_baselines (
			alert_id, baseline_version, disposition, actor, disposition_at,
			legacy_event_id, raw_legacy_severity, legacy_original_severity,
			timestamp_provenance, created_at
		) VALUES (
			'preserved-baseline', 1, 'acknowledged', 'legacy-operator', ?,
			'preserved-legacy-event', 'ACK', 'unknown',
			'legacy_occurrence_timestamp_unreliable', ?
		);
		INSERT INTO alert_acknowledgement_health (
			alert_id, code, health_event_id, detected_at
		) VALUES ('preserved-health', 'version_gap', 'preserved-health-event', ?)
	`,
		observed, observed, observed,
		observed, observed, observed, observed, observed, observed, observed, observed,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO guardrail_chain_deny_receipts (
			receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
			connector_instance_id, session_value_digest, input_fingerprint,
			ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
			detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
			stable_action_id, severity, delivery_count,
			first_observed_time_unix_nano, last_observed_time_unix_nano,
			expires_time_unix_nano, evaluation_id, audit_event_id
		) VALUES (
			?, '22222222-2222-4222-8222-222222222222',
			'44444444-4444-4444-8444-444444444444',
			'11111111-1111-4111-8111-111111111111', ?, ?, ?, ?,
			'chain.secret_read_then_egress', 'v1', 1, 1, 1, ?, 'HIGH', 1,
			1000000000, 1000000000, 2000000000, 'preserved-evaluation',
			'historical-finding-event'
		);
		INSERT INTO guardrail_chain_cutoff_barriers (
			barrier_kind, cutoff_received_time_unix_nano,
			applied_time_unix_nano, expires_time_unix_nano
		) VALUES ('terminal_reset', 1000000000, 1000000000, 2000000000)
	`, "gcr_"+strings.Repeat("a", 64), strings.Repeat("b", 64),
		strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64),
		"gca_"+strings.Repeat("f", 64),
	); err != nil {
		t.Fatal(err)
	}
}

func assertHistoricalEvidenceTablesEmpty(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range historicalEvidenceTables {
		if got := historicalEvidenceTableCount(t, db, table); got != 0 {
			t.Fatalf("%s rows after purge=%d want=0", table, got)
		}
	}
}

func assertHistoricalEvidenceQueriesEmpty(t *testing.T, store *Store) {
	t.Helper()
	if got, err := store.ListScanResults(100); err != nil || len(got) != 0 {
		t.Fatalf("ListScanResults after purge len=%d err=%v", len(got), err)
	}
	if got, err := store.ListFindingsByScan("historical-scan"); err != nil || len(got) != 0 {
		t.Fatalf("ListFindingsByScan after purge len=%d err=%v", len(got), err)
	}
	if got, err := store.ListScanFindings("historical-scan"); err != nil || len(got) != 0 {
		t.Fatalf("ListScanFindings after purge len=%d err=%v", len(got), err)
	}
	if got, err := store.ListEvents(100); err != nil || len(got) != 0 {
		t.Fatalf("ListEvents after purge len=%d err=%v", len(got), err)
	}
	if got, err := store.ListAlerts(100); err != nil || len(got) != 0 {
		t.Fatalf("ListAlerts after purge len=%d err=%v", len(got), err)
	}
	if got, err := store.GetCounts(); err != nil || got.TotalScans != 0 || got.Alerts != 0 {
		t.Fatalf("GetCounts after purge=%+v err=%v", got, err)
	}
	targets, err := store.SelectAlertAcknowledgementTargets(context.Background(), AlertAcknowledgementSelector{
		AlertIDs: []string{"preserved-alert"},
	})
	if err != nil || len(targets) != 1 || targets[0].AlertID != "preserved-alert" || targets[0].ProjectionVersion != 1 {
		t.Fatalf("preserved alert projection targets=%+v err=%v", targets, err)
	}
}

func assertHistoricalEvidenceSchemaSurvives(t *testing.T, db *sql.DB) {
	t.Helper()
	want := map[string][]string{
		"table":   historicalEvidenceTables,
		"index":   {"idx_finding_scan", "idx_scan_findings_scan_id", "idx_scan_scanner", "idx_audit_timestamp"},
		"trigger": {"scan_findings_require_parent", "scan_findings_update_require_parent", "scan_results_preserve_children"},
	}
	for objectType, names := range want {
		for _, name := range names {
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?`, objectType, name).Scan(&count); err != nil {
				t.Fatalf("query %s %s: %v", objectType, name, err)
			}
			if count != 1 {
				t.Fatalf("%s %s count=%d want=1", objectType, name, count)
			}
		}
	}
}

func assertHistoricalEvidenceForeignKeysClean(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowID sql.NullInt64
		var parent string
		var fkID int
		if err := rows.Scan(&table, &rowID, &parent, &fkID); err != nil {
			t.Fatalf("scan foreign_key_check: %v", err)
		}
		t.Fatalf("foreign_key_check failed: table=%s rowid=%v parent=%s fk=%d", table, rowID, parent, fkID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check rows: %v", err)
	}
}

func assertHistoricalEvidenceCurrentWritesWork(t *testing.T, store *Store) {
	t.Helper()
	observed := time.Date(2026, 8, 11, 13, 0, 0, 0, time.UTC)
	if err := store.InsertScanResult(
		"current-scan", "current-runtime", "safe-target", observed, 5, 1, "HIGH",
		`{"findings":[{"title":"current finding"}]}`,
	); err != nil {
		t.Fatalf("insert current scan result after purge: %v", err)
	}
	if err := store.InsertFinding(
		"current-legacy-finding", "current-scan", "HIGH", "Current finding",
		"Current description", "current/location", "Current remediation", "current-runtime", `["current"]`,
	); err != nil {
		t.Fatalf("insert current legacy finding after purge: %v", err)
	}
	if err := store.InsertScanFindings("current-scan", "safe-target", []scanner.Finding{{
		FindingOccurrenceID: "current-normalized-finding",
		Severity:            scanner.SeverityHigh,
		Title:               "Current normalized finding",
		Description:         "Current normalized description",
		Scanner:             "current-runtime",
		RuleID:              "CURRENT-RULE",
		Category:            "quality",
		Tags:                []string{"current"},
	}}, scanner.ScanFindingMeta{Timestamp: observed}); err != nil {
		t.Fatalf("insert current normalized finding after purge: %v", err)
	}
	if err := store.LogEvent(Event{
		ID: "current-alert", Timestamp: observed, Action: string(ActionAlert),
		Target: "safe-target", Actor: "current-runtime", Details: "current event", Severity: "HIGH",
	}); err != nil {
		t.Fatalf("insert current audit event after purge: %v", err)
	}

	if got, err := store.ListScanResults(10); err != nil || len(got) != 1 || got[0].ID != "current-scan" {
		t.Fatalf("current ListScanResults=%+v err=%v", got, err)
	}
	if got, err := store.ListFindingsByScan("current-scan"); err != nil || len(got) != 1 || got[0].ID != "current-legacy-finding" {
		t.Fatalf("current ListFindingsByScan=%+v err=%v", got, err)
	}
	if got, err := store.ListScanFindings("current-scan"); err != nil || len(got) != 1 || got[0].ID != "current-normalized-finding" {
		t.Fatalf("current ListScanFindings=%+v err=%v", got, err)
	}
	if got, err := store.ListEvents(10); err != nil || len(got) != 1 || got[0].ID != "current-alert" {
		t.Fatalf("current ListEvents=%+v err=%v", got, err)
	}
	if got, err := store.ListAlerts(10); err != nil || len(got) != 1 || got[0].ID != "current-alert" {
		t.Fatalf("current ListAlerts=%+v err=%v", got, err)
	}
	if got, err := store.GetCounts(); err != nil || got.TotalScans != 1 || got.Alerts != 1 {
		t.Fatalf("current GetCounts=%+v err=%v", got, err)
	}
}

func newPartialHistoricalEvidenceStore(t *testing.T, absent string) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, table := range historicalEvidenceTables {
		if table == absent {
			continue
		}
		if _, err := store.db.Exec("CREATE TABLE " + table + " (id TEXT PRIMARY KEY)"); err != nil {
			t.Fatalf("create partial %s: %v", table, err)
		}
		if _, err := store.db.Exec("INSERT INTO " + table + " (id) VALUES ('control')"); err != nil {
			t.Fatalf("seed partial %s: %v", table, err)
		}
	}
	return store
}

func historicalEvidenceTableCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func snapshotHistoricalEvidenceTables(t *testing.T, db *sql.DB, tables ...string) map[string][][]string {
	t.Helper()
	snapshot := make(map[string][][]string, len(tables))
	for _, table := range tables {
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY 1")
		if err != nil {
			t.Fatalf("snapshot %s: %v", table, err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatalf("snapshot columns %s: %v", table, err)
		}
		var tableRows [][]string
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				rows.Close()
				t.Fatalf("snapshot row %s: %v", table, err)
			}
			encoded := make([]string, len(values))
			for index, value := range values {
				switch typed := value.(type) {
				case nil:
					encoded[index] = "null"
				case []byte:
					encoded[index] = "bytes:" + hex.EncodeToString(typed)
				case time.Time:
					encoded[index] = "time:" + typed.Format(time.RFC3339Nano)
				default:
					encoded[index] = fmt.Sprintf("%T:%v", value, value)
				}
			}
			tableRows = append(tableRows, encoded)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("snapshot rows %s: %v", table, err)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("close snapshot rows %s: %v", table, err)
		}
		snapshot[table] = tableRows
	}
	return snapshot
}
