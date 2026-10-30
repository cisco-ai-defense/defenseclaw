// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// newWideV8HistoryRecord is a record whose field classes are larger than
// fieldClassSetMinBytes, as a hook decision's are.
func newWideV8HistoryRecord(t *testing.T, id string, at time.Time) observability.Record {
	t.Helper()
	body := map[string]any{"message": "wide " + id}
	classes := map[string]observability.FieldClass{"/message": observability.FieldClassContent}
	for index := 0; index < 16; index++ {
		key := fmt.Sprintf("defenseclaw.test.metadata_field_%02d", index)
		body[key] = "value"
		classes["/"+key] = observability.FieldClassMetadata
	}
	severity := observability.SeverityInfo
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: at, RecordID: id,
		Identity: observability.EventIdentity{
			Bucket: observability.BucketDiagnostic, Signal: observability.SignalLogs, Name: "diagnostic.message",
		},
		Severity: &severity, LogLevel: observability.LogLevelInfo, Source: observability.SourceGateway,
		Connector: "claudecode", Action: "diagnostic.emit", Phase: "completed", Outcome: observability.OutcomeAllowed,
		Correlation: observability.Correlation{RunID: "run-fcs", SessionID: "session-fcs", SidecarInstanceID: "sidecar-fcs"},
		Provenance: observability.Provenance{
			Producer: "gateway.audit", BinaryVersion: "v8.0.0-test", RegistrySchemaVersion: 1,
			ConfigGeneration: 3, ConfigDigest: strings.Repeat("b", 64),
		},
		Body: body, FieldClasses: classes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func storedFieldClassRow(t *testing.T, store *Store, id string) (projected, hash, mac, payload string) {
	t.Helper()
	if err := store.db.QueryRow(`SELECT projected_record_json, projection_hash, COALESCE(payload_hmac,''), payload_json
		FROM audit_events WHERE id = ?`, id).Scan(&projected, &hash, &mac, &payload); err != nil {
		t.Fatal(err)
	}
	return projected, hash, mac, payload
}

// #1384 lever 2: a row names its field class set; the set is stored once.
func TestFieldClassSetStoredOnceAndRowsVerify(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{key: bytes.Repeat([]byte{0x31}, 32), keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	projections := map[string][]byte{}
	for index := 0; index < 3; index++ {
		record := newWideV8HistoryRecord(t, fmt.Sprintf("fcs-%d", index), base.Add(time.Duration(index)*time.Second))
		projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
		if err := writer.Append(record, projection); err != nil {
			t.Fatal(err)
		}
		projections[record.RecordID()] = mustProjectionBytes(t, projection)
	}
	var sets int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_field_class_sets`).Scan(&sets); err != nil {
		t.Fatal(err)
	}
	if sets != 1 {
		t.Fatalf("%d field class sets for one family, want 1", sets)
	}
	for id, full := range projections {
		projected, hash, _, payload := storedFieldClassRow(t, store, id)
		if len(projected) >= len(full) || !strings.Contains(projected, `"field_classes":{"$set":"`) {
			t.Fatalf("row %s keeps its field classes inline: %s", id, projected)
		}
		sum := sha256.Sum256([]byte(projected))
		if hash != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("row %s projection_hash does not cover the stored bytes", id)
		}
		verification, err := writer.VerifyEventHistoryRecord(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if verification.Status != EventHistoryVerified || !verification.IntegrityVerified {
			t.Fatalf("row %s verification = %#v", id, verification)
		}
		expanded, err := store.ExpandStoredProjection(t.Context(), []byte(projected))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expanded, full) {
			t.Fatalf("row %s expands to\n%s\nwant\n%s", id, expanded, full)
		}
		if !strings.Contains(payload, `"message":"wide `+id+`"`) {
			t.Fatalf("row %s payload_json = %s", id, payload)
		}
	}
}

// A range verification reads rows that name sets without waiting on the
// store's one connection.
func TestFieldClassSetRangeVerification(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{key: bytes.Repeat([]byte{0x34}, 32), keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 3; index++ {
		record := newWideV8HistoryRecord(t, fmt.Sprintf("fcs-range-%d", index), base.Add(time.Duration(index)*time.Second))
		if err := writer.Append(record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	page, err := writer.VerifyEventHistoryRange(ctx, base, base.Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("range = %#v", page)
	}
	for _, result := range page.Records {
		if result.Status != EventHistoryVerified {
			t.Fatalf("range verification = %#v", result)
		}
	}
}

// A changed or missing set makes the rows that name it fail verification.
func TestFieldClassSetTamperFailsVerification(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{key: bytes.Repeat([]byte{0x32}, 32), keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newWideV8HistoryRecord(t, "fcs-tamper", time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	if err := writer.Append(record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit_field_class_sets SET classes_json = replace(classes_json, '"content"', '"metadata"')`); err != nil {
		t.Fatal(err)
	}
	verification, err := writer.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if verification.Status != EventHistoryHashMismatch || verification.IntegrityVerified {
		t.Fatalf("altered set verification = %#v", verification)
	}
	if _, err := store.db.Exec(`DELETE FROM audit_field_class_sets`); err != nil {
		t.Fatal(err)
	}
	verification, err = writer.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil {
		t.Fatal(err)
	}
	if verification.Status != EventHistoryHashMismatch {
		t.Fatalf("missing set verification = %#v", verification)
	}
	if _, err := store.ExpandStoredProjection(t.Context(), []byte(`{"field_classes":{"$set":"zz"}}`)); err == nil {
		t.Fatal("a malformed set reference expanded")
	}
}

// The rows a 1.0.6 store writes stay readable by the 1.0.4 and 1.0.5 readers
// after a rollback: those readers take the body, outcome and correlation of a
// projection and payload_json, and verify the hash and HMAC of the stored
// bytes. This test runs their SQL and their verification, as those tags have
// it, over a row that names its set.
func TestFieldClassSetRowsReadByEarlierReleases(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{key: bytes.Repeat([]byte{0x33}, 32), keyID: "integrity-key-v1"}
	writer, err := NewEventHistoryWriter(store, signer, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newWideV8HistoryRecord(t, "fcs-rollback", time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	if err := writer.Append(record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	var outcome, message, payloadField, sessionID, fieldClassesType string
	if err := store.db.QueryRow(`SELECT
		CASE WHEN json_valid(COALESCE(projected_record_json,'')) THEN json_extract(projected_record_json,'$.outcome') END,
		CASE WHEN json_valid(COALESCE(projected_record_json,'')) THEN json_extract(projected_record_json,'$.body.message') END,
		CASE WHEN json_valid(COALESCE(payload_json,'')) THEN json_extract(payload_json,'$."defenseclaw.test.metadata_field_03"') END,
		json_extract(projected_record_json,'$.correlation.session_id'),
		json_type(projected_record_json,'$.field_classes')
		FROM audit_events WHERE id = ?`, record.RecordID()).Scan(
		&outcome, &message, &payloadField, &sessionID, &fieldClassesType); err != nil {
		t.Fatal(err)
	}
	if outcome != "allowed" || message != "wide fcs-rollback" || payloadField != "value" ||
		sessionID != "session-fcs" || fieldClassesType != "object" {
		t.Fatalf("earlier readers see outcome=%q message=%q payload=%q session=%q field_classes=%q",
			outcome, message, payloadField, sessionID, fieldClassesType)
	}
	// The 1.0.4/1.0.5 verifier: sha256 and HMAC of the stored projection.
	projected, hash, mac, _ := storedFieldClassRow(t, store, record.RecordID())
	sum := sha256.Sum256([]byte(projected))
	if hash != ProjectionHashAlgorithm+":"+hex.EncodeToString(sum[:]) {
		t.Fatal("an earlier verifier would report a hash mismatch")
	}
	want, err := signer.HMACSHA256(t.Context(), projectionIntegrityMessage([]byte(projected), ProjectionIntegrityAlgorithm, signer.keyID))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := hex.DecodeString(mac)
	if !hmac.Equal(stored, want) {
		t.Fatal("an earlier verifier would report an HMAC mismatch")
	}
	// Their envelope decoders (lifecycle, config pin) read every member but
	// the field classes, which stay an object.
	envelope, err := decodeEnvelope([]byte(projected))
	if err != nil || len(envelope["body"]) == 0 || len(envelope["provenance"]) == 0 {
		t.Fatalf("envelope = %v, %v", envelope, err)
	}
	var classes map[string]string
	if err := json.Unmarshal(envelope["field_classes"], &classes); err != nil {
		t.Fatalf("field_classes no longer decodes as an object of strings: %v", err)
	}
	// Retention owns the table as protected state.
	if retentionAuditMigrationCatalog["audit_field_class_sets"] != retentionOwnedProtected {
		t.Fatal("audit_field_class_sets is not in the retention catalog")
	}
}

// A Secure Client store keeps main's schema: no set table, classes inline.
func TestFieldClassSetsOffOnSecureClientStore(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newWideV8HistoryRecord(t, "fcs-sc", time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	present, err := tableExists(store.db, "audit_field_class_sets")
	if err != nil || present {
		t.Fatalf("Secure Client store has the set table (present=%v err=%v)", present, err)
	}
	projected, _, _, _ := storedFieldClassRow(t, store, record.RecordID())
	if projected != string(mustProjectionBytes(t, projection)) {
		t.Fatalf("Secure Client row does not keep the projection as is: %s", projected)
	}
}

// Past the bound new sets are written inline and the table stops growing.
func TestFieldClassSetsBounded(t *testing.T) {
	store := newV8HistoryStore(t)
	store.fieldClassSetCount.Store(maxFieldClassSets)
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newWideV8HistoryRecord(t, "fcs-bound", time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatal(err)
	}
	projected, _, _, _ := storedFieldClassRow(t, store, record.RecordID())
	if projected != string(mustProjectionBytes(t, projection)) {
		t.Fatal("a row past the set bound did not keep its classes inline")
	}
	verification, err := writer.VerifyEventHistoryRecord(t.Context(), record.RecordID())
	if err != nil || verification.Status != EventHistoryUnsigned {
		t.Fatalf("inline row verification = %#v, %v", verification, err)
	}
}

// A store the published 1.0.3 gateway wrote upgrades with no schema move for
// the set table: its rows keep their inline classes and new rows name sets.
func TestFieldClassSetsOnStoreWrittenByPublished103(t *testing.T) {
	compressed, err := os.Open(filepath.Join("testdata", "audit-1.0.3.db.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, reader); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	var version, inline int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("schema = %d, %v; want %d", version, err, len(migrations))
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE json_type(projected_record_json,'$.field_classes."$set"') IS NULL
		AND projected_record_json IS NOT NULL`).Scan(&inline); err != nil || inline == 0 {
		t.Fatalf("1.0.3 rows with inline classes = %d, %v", inline, err)
	}
	writer, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newWideV8HistoryRecord(t, "fcs-103", time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC))
	if err := writer.Append(record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	projected, _, _, _ := storedFieldClassRow(t, store, record.RecordID())
	if !strings.Contains(projected, `"field_classes":{"$set":"`) {
		t.Fatalf("a new row on an upgraded 1.0.3 store keeps its classes inline: %s", projected)
	}
	if verification, err := writer.VerifyEventHistoryRecord(t.Context(), record.RecordID()); err != nil ||
		verification.Status != EventHistoryUnsigned || !verification.ProjectionHashValid {
		t.Fatalf("verification = %#v, %v", verification, err)
	}
}
