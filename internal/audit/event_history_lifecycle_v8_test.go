// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func newLifecycleHistoryRecord(
	t *testing.T,
	id, event, state, phase, rootAgentID, parentAgentID string,
	depth, sequence int64,
	timestamp time.Time,
) observability.Record {
	t.Helper()
	body := map[string]any{
		"gen_ai.conversation.id":               "session-child",
		"gen_ai.agent.id":                      "agent-child",
		"defenseclaw.agent.root.id":            rootAgentID,
		"defenseclaw.session.root.id":          "session-root",
		"defenseclaw.agent.lifecycle.id":       "lifecycle-child",
		"defenseclaw.agent.execution.id":       "execution-child",
		"defenseclaw.agent.depth":              depth,
		"defenseclaw.agent.lifecycle.event":    event,
		"defenseclaw.agent.lifecycle.state":    state,
		"defenseclaw.agent.phase":              phase,
		"defenseclaw.agent.sequence":           sequence,
		"defenseclaw.agent.lineage.provenance": "reported",
	}
	classes := map[string]observability.FieldClass{
		"/gen_ai.conversation.id":               observability.FieldClassIdentifier,
		"/gen_ai.agent.id":                      observability.FieldClassIdentifier,
		"/defenseclaw.agent.root.id":            observability.FieldClassIdentifier,
		"/defenseclaw.session.root.id":          observability.FieldClassIdentifier,
		"/defenseclaw.agent.lifecycle.id":       observability.FieldClassIdentifier,
		"/defenseclaw.agent.execution.id":       observability.FieldClassIdentifier,
		"/defenseclaw.agent.depth":              observability.FieldClassMetadata,
		"/defenseclaw.agent.lifecycle.event":    observability.FieldClassMetadata,
		"/defenseclaw.agent.lifecycle.state":    observability.FieldClassMetadata,
		"/defenseclaw.agent.phase":              observability.FieldClassMetadata,
		"/defenseclaw.agent.sequence":           observability.FieldClassMetadata,
		"/defenseclaw.agent.lineage.provenance": observability.FieldClassMetadata,
	}
	if parentAgentID != "" {
		body["defenseclaw.agent.parent.id"] = parentAgentID
		body["defenseclaw.session.parent.id"] = "session-root"
		classes["/defenseclaw.agent.parent.id"] = observability.FieldClassIdentifier
		classes["/defenseclaw.session.parent.id"] = observability.FieldClassIdentifier
	}
	severity := observability.SeverityInfo
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: timestamp,
		RecordID:  id,
		Identity: observability.EventIdentity{
			Bucket: observability.BucketAgentLifecycle,
			Signal: observability.SignalLogs,
			Name:   observability.EventName(event),
		},
		Severity:  &severity,
		LogLevel:  observability.LogLevelInfo,
		Source:    observability.SourceConnector,
		Connector: "codex",
		Action:    "lifecycle",
		Phase:     phase,
		Outcome:   observability.OutcomeAttempted,
		Correlation: observability.Correlation{
			SessionID: "session-child", AgentID: "agent-child", ConnectorID: "codex",
		},
		Provenance: observability.Provenance{
			Producer: "gateway.hook.lifecycle", BinaryVersion: "v8-test",
			RegistrySchemaVersion: 1, ConfigGeneration: 1,
			ConfigDigest: testEventHistoryGraphDigest,
		},
		Body: body, FieldClasses: classes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func newLifecycleHistoryWriter(
	t *testing.T,
	store *Store,
	profile observabilityredaction.ProfileName,
) *EventHistoryWriter {
	t.Helper()
	signer := &testProjectionSigner{
		key: []byte("0123456789abcdef0123456789abcdef"), keyID: "lifecycle-test-key",
	}
	writer, err := NewEventHistoryWriter(
		store, signer, nil, testLocalProfileResolver{profile: profile},
	)
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func appendLifecycleHistoryRecord(
	t *testing.T,
	writer *EventHistoryWriter,
	record observability.Record,
	profile observabilityredaction.ProfileName,
) {
	t.Helper()
	if err := writer.Append(record, projectV8HistoryRecord(t, record, profile)); err != nil {
		t.Fatal(err)
	}
}

func TestLatestLifecycleProjectionReturnsNewestExactVerifiedIdentity(t *testing.T) {
	store := newV8HistoryStore(t)
	writer := newLifecycleHistoryWriter(t, store, observabilityredaction.ProfileNone)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	appendLifecycleHistoryRecord(t, writer, newLifecycleHistoryRecord(
		t, "lifecycle-old", "subagent_start", "active", "session",
		"agent-root", "agent-root", 1, 1, base,
	), observabilityredaction.ProfileNone)
	appendLifecycleHistoryRecord(t, writer, newLifecycleHistoryRecord(
		t, "lifecycle-new", "turn_start", "active", "planning",
		"agent-root", "agent-root", 1, 7, base.Add(time.Second),
	), observabilityredaction.ProfileNone)

	got, found, err := writer.LatestLifecycleProjection(t.Context(), LifecycleProjectionQuery{
		Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("newest verified lifecycle projection was not found")
	}
	if got.RecordID != "lifecycle-new" || got.RootAgentID != "agent-root" ||
		got.ParentAgentID != "agent-root" || got.RootSessionID != "session-root" ||
		got.ParentSessionID != "session-root" || got.LifecycleID != "lifecycle-child" ||
		got.ExecutionID != "execution-child" || got.Event != "turn_start" ||
		got.State != "active" || got.Phase != "planning" || got.Depth != 1 || got.Sequence != 7 ||
		got.LineageProvenance != "reported" {
		t.Fatalf("recovered projection = %#v", got)
	}
}

func TestLatestLifecycleProjectionRejectsTamperingAndTransformedIdentifiers(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		profile observabilityredaction.ProfileName
		tamper  func(*testing.T, *Store)
	}{
		{
			name: "projection hash", profile: observabilityredaction.ProfileNone,
			tamper: func(t *testing.T, store *Store) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET projected_record_json='{}' WHERE id='candidate'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "payload hmac", profile: observabilityredaction.ProfileNone,
			tamper: func(t *testing.T, store *Store) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET payload_hmac=? WHERE id='candidate'`,
					make([]byte, sha256.Size*2)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ordering timestamp", profile: observabilityredaction.ProfileNone,
			tamper: func(t *testing.T, store *Store) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET retention_timestamp_unix_nano=retention_timestamp_unix_nano+1 WHERE id='candidate'`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newV8HistoryStore(t)
			writer := newLifecycleHistoryWriter(t, store, test.profile)
			appendLifecycleHistoryRecord(t, writer, newLifecycleHistoryRecord(
				t, "candidate", "turn_start", "active", "planning",
				"agent-root", "agent-root", 1, 7, base,
			), test.profile)
			if test.tamper != nil {
				test.tamper(t, store)
			}
			if _, found, err := writer.LatestLifecycleProjection(t.Context(), LifecycleProjectionQuery{
				Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
			}); err != nil {
				t.Fatal(err)
			} else if found {
				t.Fatal("unsafe lifecycle projection was accepted")
			}
		})
	}
}

func TestLatestLifecycleProjectionRejectsAmbiguousInconsistentAndOutOfRangeRows(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		rows []observability.Record
	}{
		{
			name: "ambiguous newest timestamp",
			rows: []observability.Record{
				newLifecycleHistoryRecord(t, "candidate-a", "turn_start", "active", "planning", "agent-root", "agent-root", 1, 7, base),
				newLifecycleHistoryRecord(t, "candidate-b", "turn_end", "completed", "responding", "agent-root", "agent-root", 1, 8, base),
			},
		},
		{
			name: "inconsistent lineage",
			rows: []observability.Record{
				newLifecycleHistoryRecord(t, "candidate", "turn_start", "active", "planning", "agent-child", "agent-child", 1, 7, base),
			},
		},
		{
			name: "depth out of range",
			rows: []observability.Record{
				newLifecycleHistoryRecord(t, "candidate", "turn_start", "active", "planning", "agent-root", "agent-root", 65, 7, base),
			},
		},
		{
			name: "sequence out of range",
			rows: []observability.Record{
				newLifecycleHistoryRecord(t, "candidate", "turn_start", "active", "planning", "agent-root", "agent-root", 1, 0, base),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newV8HistoryStore(t)
			writer := newLifecycleHistoryWriter(t, store, observabilityredaction.ProfileNone)
			for _, record := range test.rows {
				appendLifecycleHistoryRecord(t, writer, record, observabilityredaction.ProfileNone)
			}
			if _, found, err := writer.LatestLifecycleProjection(t.Context(), LifecycleProjectionQuery{
				Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
			}); err != nil {
				t.Fatal(err)
			} else if found {
				t.Fatal("invalid lifecycle projection was accepted")
			}
		})
	}
}

// TestDecodeLifecycleProjectionRejectsRetiredLegacyV7Rows pins the guard that
// keeps pre-v8 rows out of a v8 projection.
//
// It runs against decodeLifecycleProjection directly, which is where the
// guard lives, because there is no other honest way to build the row. The
// writer refuses to bind the retired profile at all -- correctly, and
// asserted below -- so a legacy-v7 row can only exist as an artifact left on
// disk by a version that is gone.
//
// The earlier version of this test patched the redaction_profile column of a
// stored row and nothing else. That left the projected envelope still naming
// the old profile, and the envelope/column comparison rejected the row before
// the name guard was ever consulted: the case passed with the guard deleted,
// which is the one thing it existed to catch. Here the row is made
// internally consistent first, and asserted to decode, so the retired name is
// the only difference between the accepted case and the rejected one.
func TestDecodeLifecycleProjectionRejectsRetiredLegacyV7Rows(t *testing.T) {
	// The literal, deliberately, not the constant the guard uses. Writing the
	// constant would make the test agree with whatever the guard says, so a
	// wrong value would pass here while pre-v8 rows quietly stopped being
	// rejected.
	const retiredProfile = "legacy-v7"

	store := newV8HistoryStore(t)
	writer := newLifecycleHistoryWriter(t, store, observabilityredaction.ProfileNone)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	appendLifecycleHistoryRecord(t, writer, newLifecycleHistoryRecord(
		t, "candidate", "turn_start", "active", "planning",
		"agent-root", "agent-root", 1, 7, base,
	), observabilityredaction.ProfileNone)

	query := LifecycleProjectionQuery{
		Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
	}
	var row storedLifecycleProjection
	if err := store.db.QueryRow(`
		SELECT id, COALESCE(CAST(timestamp AS TEXT),''), COALESCE(retention_timestamp_unix_nano,0),
		       COALESCE(bucket,''), COALESCE(event_name,''), COALESCE(source,''), COALESCE(signal,''),
		       COALESCE(bucket_catalog_version,0), COALESCE(record_schema_version,0),
		       COALESCE(redaction_profile,''), COALESCE(connector,''),
		       COALESCE(session_id,''), COALESCE(agent_id,''),
		       COALESCE(projected_record_json,'')
		FROM audit_events WHERE id='candidate'`,
	).Scan(
		&row.recordID, &row.timestamp, &row.timestampUnixNano, &row.bucket, &row.eventName,
		&row.source, &row.signal, &row.bucketCatalogVersion, &row.recordSchemaVersion,
		&row.redactionProfile, &row.connector, &row.sessionID, &row.agentID, &row.projected,
	); err != nil {
		t.Fatal(err)
	}

	// The row as written must decode. Without this the rejection below could
	// be caused by anything at all in the fixture.
	if _, valid := decodeLifecycleProjection(row, query); !valid {
		t.Fatal("the row as written did not decode; the fixture proves nothing")
	}

	// Rewrite the profile in both places a stored row records it, so the row
	// stays internally consistent and the retired name is the only defect.
	var envelope map[string]any
	if err := json.Unmarshal([]byte(row.projected), &envelope); err != nil {
		t.Fatal(err)
	}
	projection, ok := envelope["projection"].(map[string]any)
	if !ok {
		t.Fatalf("projected envelope has no projection block: %s", row.projected)
	}
	if projection["redaction_profile"] != string(observabilityredaction.ProfileNone) {
		t.Fatalf("projected envelope names profile %v, want %s",
			projection["redaction_profile"], observabilityredaction.ProfileNone)
	}
	projection["redaction_profile"] = retiredProfile
	rewritten, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	row.projected = string(rewritten)
	row.redactionProfile = retiredProfile

	if _, valid := decodeLifecycleProjection(row, query); valid {
		t.Fatal("a row stored under the retired legacy-v7 profile was accepted")
	}
}

// TestEventHistoryWriterRefusesToBindTheRetiredProfile is the other half of
// the guard: nothing new may be written under the retired name, so the only
// legacy-v7 rows that can exist are the ones already on disk.
func TestEventHistoryWriterRefusesToBindTheRetiredProfile(t *testing.T) {
	store := newV8HistoryStore(t)
	signer := &testProjectionSigner{
		key: []byte("0123456789abcdef0123456789abcdef"), keyID: "lifecycle-test-key",
	}
	writer, err := NewEventHistoryWriter(
		store, signer, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileName("legacy-v7")},
	)
	if err != nil {
		// Refusing at construction is also a refusal.
		return
	}
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	record := newLifecycleHistoryRecord(
		t, "candidate", "turn_start", "active", "planning",
		"agent-root", "agent-root", 1, 7, base,
	)
	if err := writer.Append(record, projectV8HistoryRecord(
		t, record, observabilityredaction.ProfileName("legacy-v7"),
	)); err == nil {
		t.Fatal("the writer bound the retired legacy-v7 profile")
	}
}
