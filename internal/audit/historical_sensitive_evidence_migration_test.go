// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type historicalSensitiveEvidenceFixture struct {
	store                     *Store
	migration                 migration
	migrationVersion          int
	secret, pii               string
	secretEventID, piiEventID string
}

func TestHistoricalSensitiveEvidenceMigrationRepairsEverySurfaceAndIntegrity(t *testing.T) {
	fixture := newHistoricalSensitiveEvidenceFixture(t)
	if err := fixture.store.Init(); err != nil {
		t.Fatalf("apply historical sensitive-evidence migration through Init: %v", err)
	}

	version, err := fixture.store.SchemaVersion()
	if err != nil || version != len(migrations) {
		t.Fatalf("schema version=%d want=%d err=%v", version, len(migrations), err)
	}
	assertHistoricalSensitiveEvidenceAbsent(t, fixture)
	assertHistoricalProjectionIntegrity(t, fixture, fixture.secretEventID)
	assertHistoricalProjectionIntegrity(t, fixture, fixture.piiEventID)

	before := historicalSensitiveEvidenceSnapshot(t, fixture.store.db)
	if err := fixture.migration.apply(fixture.store.db); err != nil {
		t.Fatalf("first direct migration replay: %v", err)
	}
	if err := fixture.migration.apply(fixture.store.db); err != nil {
		t.Fatalf("second direct migration replay: %v", err)
	}
	after := historicalSensitiveEvidenceSnapshot(t, fixture.store.db)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("historical repair is not idempotent:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestHistoricalSensitiveEvidenceMigrationRollsBackEverySurface(t *testing.T) {
	fixture := newHistoricalSensitiveEvidenceFixture(t)
	if _, err := fixture.store.db.Exec(fmt.Sprintf(`
		CREATE TRIGGER fail_historical_evidence_repair
		BEFORE UPDATE ON audit_events
		WHEN OLD.id = %q
		BEGIN SELECT RAISE(ABORT, 'forced historical repair failure'); END`, fixture.piiEventID)); err != nil {
		t.Fatal(err)
	}

	err := fixture.store.applyMigration(fixture.migrationVersion, fixture.migration)
	if err == nil || !strings.Contains(err.Error(), "forced historical repair failure") {
		t.Fatalf("forced transactional migration error=%v", err)
	}
	var evidence string
	if err := fixture.store.db.QueryRow(`
		SELECT evidence_summary FROM scan_findings WHERE id='historical-secret-finding'`).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if evidence != fixture.secret {
		t.Fatalf("scan finding changed despite rollback: %q", evidence)
	}
	var structured string
	if err := fixture.store.db.QueryRow(`
		SELECT structured_json FROM audit_events WHERE id=?`, fixture.secretEventID).Scan(&structured); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(structured, fixture.secret) {
		t.Fatal("audit event changed despite rollback")
	}
	version, err := fixture.store.SchemaVersion()
	if err != nil || version != fixture.migrationVersion-1 {
		t.Fatalf("schema version after rollback=%d want=%d err=%v", version, fixture.migrationVersion-1, err)
	}

	if _, err := fixture.store.db.Exec(`DROP TRIGGER fail_historical_evidence_repair`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Init(); err != nil {
		t.Fatalf("retry historical repair: %v", err)
	}
	assertHistoricalSensitiveEvidenceAbsent(t, fixture)
}

func newHistoricalSensitiveEvidenceFixture(t *testing.T) historicalSensitiveEvidenceFixture {
	t.Helper()
	migration, migrationVersion := historicalSensitiveEvidenceMigration(t)
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < migrationVersion-1; index++ {
		if err := store.applyMigration(index+1, migrations[index]); err != nil {
			t.Fatalf("apply pre-repair migration %d (%s): %v", index+1, migrations[index].description, err)
		}
	}
	version, err := store.SchemaVersion()
	if err != nil || version != migrationVersion-1 {
		t.Fatalf("pre-fix fixture schema version=%d want=%d err=%v", version, migrationVersion-1, err)
	}

	secret := "sk_live_" + strings.Repeat("private", 6)
	pii := strings.Join([]string{"731", "42", "9816"}, "-")
	observed := time.Date(2026, 8, 10, 23, 59, 0, 123456789, time.UTC)
	findings := []scanner.Finding{
		historicalSensitiveFinding("historical-secret-source:"+secret, "SEC-HISTORICAL-"+secret, "credential", secret),
		historicalSensitiveFinding("historical-pii-source:"+pii, "PII-HISTORICAL-"+pii, "pii", pii),
	}
	result := scanner.ScanResult{
		Scanner: "legacy-runtime", Target: "codex:PostToolUse", Timestamp: observed,
		TargetType: "tool_response", Verdict: "alert", Findings: findings,
	}
	rawJSON, err := result.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`
		INSERT INTO scan_results (
			id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json
		) VALUES ('historical-scan', 'legacy-runtime', 'codex:PostToolUse', ?, 12, 2, 'HIGH', ?),
		         ('unrelated-malformed-scan', 'legacy-runtime', 'safe-target', ?, 1, 0, 'INFO', 'not-json')`,
		observed.Format(time.RFC3339Nano), string(rawJSON), observed.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	insertHistoricalScanFinding(t, store.db, "historical-secret-finding", findings[0], secret, observed)
	insertHistoricalScanFinding(t, store.db, "historical-pii-finding", findings[1], pii, observed)

	secretEventID := "historical-secret-event"
	piiEventID := "historical-pii-event"
	insertHistoricalAuditFinding(t, store.db, secretEventID, "historical-secret-finding", findings[0], secret, observed)
	insertHistoricalAuditFinding(t, store.db, piiEventID, "historical-pii-finding", findings[1], pii, observed.Add(time.Second))
	return historicalSensitiveEvidenceFixture{
		store: store, migration: migration, migrationVersion: migrationVersion,
		secret: secret, pii: pii, secretEventID: secretEventID, piiEventID: piiEventID,
	}
}

func historicalSensitiveEvidenceMigration(t *testing.T) (migration, int) {
	t.Helper()
	var found migration
	version := 0
	for index, candidate := range migrations {
		if candidate.description != historicalSensitiveEvidenceMigrationDescription {
			continue
		}
		if found.apply != nil {
			t.Fatal("multiple historical sensitive-evidence migrations found")
		}
		found = candidate
		version = index + 1
	}
	if found.apply == nil || version == 0 {
		t.Fatal("historical sensitive-evidence migration not found")
	}
	return found, version
}

func historicalSensitiveFinding(sourceID, ruleID, category, raw string) scanner.Finding {
	decision, _ := json.Marshal(map[string]string{"matched": raw})
	line := 17
	return scanner.Finding{
		ID: sourceID, FindingOccurrenceID: "occurrence-" + category,
		RuleID: ruleID, Category: category, Scanner: "legacy-runtime",
		Severity: scanner.SeverityHigh, Title: "title:" + raw,
		Description: "description:" + raw, EvidenceSummary: raw,
		Location: "/private/" + raw, LineNumber: &line,
		Remediation: "rotate:" + raw, Tags: []string{category, raw, scanner.FindingTagDetectionOnly},
		DataAxis: []string{"sensitive_access", raw}, ToolCapabilityClass: raw,
		ContentFingerprint: historicalUnkeyedFingerprint(raw),
		ExternalEndpoint:   raw + ".invalid", DecisionPath: decision,
	}
}

func insertHistoricalScanFinding(
	t *testing.T,
	db *sql.DB,
	id string,
	finding scanner.Finding,
	raw string,
	observed time.Time,
) {
	t.Helper()
	tags, _ := json.Marshal(finding.Tags)
	dataAxis, _ := json.Marshal(finding.DataAxis)
	if _, err := db.Exec(`
		INSERT INTO scan_findings (
			id, scan_id, scanner, target, rule_id, category, severity, title,
			description, evidence_summary, location, line_number, remediation, tags,
			timestamp, data_axis, tool_capability_class, content_fingerprint,
			external_endpoint, decision_path
		) VALUES (?, 'historical-scan', 'legacy-runtime', 'codex:PostToolUse', ?, ?, 'HIGH', ?,
		          ?, ?, ?, 17, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, finding.RuleID, finding.Category, finding.Title, finding.Description, raw,
		finding.Location, finding.Remediation, string(tags), observed.Format(time.RFC3339Nano),
		string(dataAxis), finding.ToolCapabilityClass, finding.ContentFingerprint,
		finding.ExternalEndpoint, string(finding.DecisionPath)); err != nil {
		t.Fatal(err)
	}
}

func insertHistoricalAuditFinding(
	t *testing.T,
	db *sql.DB,
	eventID, findingID string,
	finding scanner.Finding,
	raw string,
	observed time.Time,
) {
	t.Helper()
	body := map[string]any{
		"defenseclaw.finding.id":                    findingID,
		"defenseclaw.finding.rule_id":               finding.RuleID,
		"defenseclaw.finding.category":              finding.Category,
		"defenseclaw.finding.title":                 finding.Title,
		"defenseclaw.finding.description":           finding.Description,
		"defenseclaw.guardrail.evidence_summary":    raw,
		"defenseclaw.finding.location":              finding.Location,
		"defenseclaw.finding.remediation":           finding.Remediation,
		"defenseclaw.finding.tags":                  finding.Tags,
		"defenseclaw.finding.data_axes":             finding.DataAxis,
		"defenseclaw.finding.tool_capability_class": finding.ToolCapabilityClass,
		"defenseclaw.finding.content_fingerprint":   finding.ContentFingerprint,
		"defenseclaw.finding.external_endpoint":     finding.ExternalEndpoint,
		"defenseclaw.finding.decision_path":         string(finding.DecisionPath),
		"defenseclaw.scan.scanner":                  "legacy-runtime",
		"producer_extension":                        map[string]any{"raw_match": raw},
	}
	classes := make(map[string]any, len(body))
	for key := range body {
		classes["/"+key] = "evidence"
	}
	projected := map[string]any{
		"record_id": eventID, "signal": "logs", "event_name": "finding.observed",
		"body": body, "field_classes": classes,
		"projection": map[string]any{
			"redaction_profile": "sensitive", "detector_catalog_version": 1,
			"state": "inspected", "transformed_fields": 0, "removed_fields": 0,
			"oversize_fields": 0, "failure_count": 0, "failures_truncated": false,
		},
	}
	structured, err := marshalHistoricalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), structured...)
	projectedJSON, err := marshalHistoricalJSON(projected)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(projectedJSON)
	projectionHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
	details := fmt.Sprintf("scanner=legacy-runtime rule_id=%s category=%s", finding.RuleID, finding.Category)
	if _, err := db.Exec(`
		INSERT INTO audit_events (
			id, timestamp, action, actor, details, structured_json, severity,
			bucket, event_name, source, signal, payload_json, projected_record_json,
			record_schema_version, projection_hash, redaction_profile, mandatory,
			scan_id, finding_id, payload_hmac, integrity_algorithm, integrity_key_id
		) VALUES (?, ?, 'scan-finding', 'defenseclaw', ?, ?, 'HIGH',
		          'security.finding', 'finding.observed', 'scanner', 'logs', ?, ?,
		          1, ?, 'sensitive', 0, 'historical-scan', ?, ?, ?, ?)`,
		eventID, observed.Format(time.RFC3339Nano), details, string(structured), string(payload),
		string(projectedJSON), projectionHash, findingID, strings.Repeat("a", sha256.Size*2),
		ProjectionIntegrityAlgorithm, "historical-key"); err != nil {
		t.Fatal(err)
	}
}

func assertHistoricalSensitiveEvidenceAbsent(t *testing.T, fixture historicalSensitiveEvidenceFixture) {
	t.Helper()
	markers := []string{fixture.secret, fixture.pii, historicalUnkeyedFingerprint(fixture.secret), historicalUnkeyedFingerprint(fixture.pii)}
	rows, err := fixture.store.db.Query(`
		SELECT COALESCE(rule_id,''), COALESCE(category,''), COALESCE(title,''),
		       COALESCE(description,''), COALESCE(evidence_summary,''), COALESCE(location,''),
		       COALESCE(remediation,''), COALESCE(tags,''), COALESCE(data_axis,''),
		       COALESCE(tool_capability_class,''), COALESCE(content_fingerprint,''),
		       COALESCE(external_endpoint,''), COALESCE(decision_path,'')
		FROM scan_findings ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		values := make([]string, 13)
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		assertNoHistoricalSensitiveMarker(t, strings.Join(values, "\x00"), markers)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	var rawJSON string
	if err := fixture.store.db.QueryRow(`SELECT raw_json FROM scan_results WHERE id='historical-scan'`).Scan(&rawJSON); err != nil {
		t.Fatal(err)
	}
	assertNoHistoricalSensitiveMarker(t, rawJSON, markers)

	eventRows, err := fixture.store.db.Query(`
		SELECT COALESCE(details,''), COALESCE(structured_json,''), COALESCE(payload_json,''),
		       COALESCE(projected_record_json,'')
		FROM audit_events WHERE id IN (?, ?) ORDER BY id`, fixture.secretEventID, fixture.piiEventID)
	if err != nil {
		t.Fatal(err)
	}
	for eventRows.Next() {
		var details, structured, payload, projected string
		if err := eventRows.Scan(&details, &structured, &payload, &projected); err != nil {
			_ = eventRows.Close()
			t.Fatal(err)
		}
		assertNoHistoricalSensitiveMarker(t, strings.Join([]string{details, structured, payload, projected}, "\x00"), markers)
	}
	if err := eventRows.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertHistoricalProjectionIntegrity(t *testing.T, fixture historicalSensitiveEvidenceFixture, eventID string) {
	t.Helper()
	var projected, payload, projectionHash, payloadHMAC, algorithm, keyID string
	if err := fixture.store.db.QueryRow(`
		SELECT COALESCE(projected_record_json,''), COALESCE(payload_json,''),
		       COALESCE(projection_hash,''), COALESCE(payload_hmac,''),
		       COALESCE(integrity_algorithm,''), COALESCE(integrity_key_id,'')
		FROM audit_events WHERE id=?`, eventID).Scan(
		&projected, &payload, &projectionHash, &payloadHMAC, &algorithm, &keyID,
	); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(projected))
	wantHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
	if projectionHash != wantHash || payloadHMAC != "" || algorithm != "" || keyID != "" {
		t.Fatalf("repaired integrity hash=%q want=%q hmac=%q algorithm=%q key=%q",
			projectionHash, wantHash, payloadHMAC, algorithm, keyID)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(projected), &envelope); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(envelope["body"], []byte(payload)) {
		t.Fatal("repaired payload_json does not match projected_record_json.body")
	}
	verification, err := (&EventHistoryWriter{}).verifyStoredProjection(
		context.Background(), eventID, []byte(projected), projectionHash, payloadHMAC, algorithm, keyID,
	)
	if err != nil || verification.Status != EventHistoryUnsigned || !verification.ProjectionHashValid {
		t.Fatalf("repaired projection verification=%+v err=%v", verification, err)
	}
	var projection struct {
		State             string `json:"state"`
		TransformedFields int    `json:"transformed_fields"`
		RemovedFields     int    `json:"removed_fields"`
	}
	if err := json.Unmarshal(envelope["projection"], &projection); err != nil {
		t.Fatal(err)
	}
	if projection.State != "transformed" || projection.TransformedFields == 0 || projection.RemovedFields == 0 {
		t.Fatalf("repaired projection metadata=%+v", projection)
	}
}

func historicalSensitiveEvidenceSnapshot(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	type rowSnapshot struct {
		Table  string
		Values []string
	}
	snapshot := make([]rowSnapshot, 0, 5)
	queries := []struct {
		table string
		query string
		cols  int
	}{
		{"scan_findings", `SELECT COALESCE(rule_id,''), COALESCE(category,''), COALESCE(title,''),
			COALESCE(description,''), COALESCE(evidence_summary,''), COALESCE(location,''),
			COALESCE(remediation,''), COALESCE(tags,''), COALESCE(data_axis,''),
			COALESCE(tool_capability_class,''), COALESCE(content_fingerprint,''),
			COALESCE(external_endpoint,''), COALESCE(decision_path,'')
			FROM scan_findings ORDER BY id`, 13},
		{"scan_results", `SELECT COALESCE(raw_json,'') FROM scan_results ORDER BY id`, 1},
		{"audit_events", `SELECT COALESCE(details,''), COALESCE(structured_json,''),
			COALESCE(payload_json,''), COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
			COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''), COALESCE(integrity_key_id,'')
			FROM audit_events WHERE id LIKE 'historical-%-event' ORDER BY id`, 8},
	}
	for _, query := range queries {
		rows, err := db.Query(query.query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]string, query.cols)
			destinations := make([]any, query.cols)
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			snapshot = append(snapshot, rowSnapshot{Table: query.table, Values: values})
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func historicalUnkeyedFingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:8]
}

func assertNoHistoricalSensitiveMarker(t *testing.T, value string, markers []string) {
	t.Helper()
	for _, marker := range markers {
		if marker != "" && strings.Contains(value, marker) {
			t.Fatalf("repaired queryable column retained sensitive marker %q", marker)
		}
	}
}

func jsonEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil &&
		reflect.DeepEqual(leftValue, rightValue)
}
