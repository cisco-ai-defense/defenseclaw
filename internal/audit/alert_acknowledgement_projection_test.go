// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func newAlertProjectionStore(t *testing.T) *Store {
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

func seedEligibleAlertTarget(t *testing.T, store *Store, alertIDs ...string) {
	t.Helper()
	for _, alertID := range alertIDs {
		if _, err := store.db.Exec(`INSERT INTO audit_events (
			id, timestamp, action, actor, details, structured_json, severity,
			bucket, event_name, source, signal, bucket_catalog_version,
			payload_json, projected_record_json, record_schema_version,
			projection_hash, redaction_profile, mandatory
		) VALUES (?, ?, 'finding.observed', 'test', 'eligible test finding', '{}', 'HIGH',
			'security.finding', 'finding.observed', 'scanner', 'logs', 1,
			'{}', '{}', 1, 'sha256:test', 'none', 0)`,
			alertID, "2026-07-03T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
}

func newAlertProjectionWriter(t *testing.T, store *Store) *AlertAcknowledgementWriter {
	return newAlertProjectionWriterWithSigner(t, store, newAlertCommandTestSigner("test-key-a"))
}

func newAlertProjectionWriterWithSigner(
	t *testing.T,
	store *Store,
	signer ProjectionIntegritySigner,
) *AlertAcknowledgementWriter {
	t.Helper()
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewEventHistoryWriter(
		store, signer, nil, testLocalProfileResolver{
			profile: observabilityredaction.ProfileNone, engine: engine,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	if !ok {
		t.Fatal("none profile missing")
	}
	writer, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

type alertCommandTestSigner struct {
	keyID  string
	key    []byte
	err    error
	digest []byte
}

type stagedAlertCommandSigner struct {
	*alertCommandTestSigner
	calls         atomic.Int64
	unavailableAt int64
}

func (signer *stagedAlertCommandSigner) HMACSHA256(
	ctx context.Context,
	message []byte,
) ([]byte, error) {
	if signer.calls.Add(1) >= signer.unavailableAt {
		return nil, ErrIntegrityKeyUnavailable
	}
	return signer.alertCommandTestSigner.HMACSHA256(ctx, message)
}

type closingAlertHealthReporter struct {
	store *Store
	codes chan EventHistoryHealthCode
	errs  chan error
}

func (reporter *closingAlertHealthReporter) ReportEventHistoryHealth(code EventHistoryHealthCode) {
	reporter.codes <- code
	reporter.errs <- reporter.store.Close()
}

func newAlertCommandTestSigner(keyID string) *alertCommandTestSigner {
	return &alertCommandTestSigner{
		keyID: keyID,
		key:   []byte("0123456789abcdef0123456789abcdef"),
	}
}

func (signer *alertCommandTestSigner) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

func (signer *alertCommandTestSigner) HMACSHA256(
	ctx context.Context,
	message []byte,
) ([]byte, error) {
	if signer == nil {
		return nil, ErrIntegrityKeyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

type testAlertCanonicalEventFactory struct {
	engine      *observabilityredaction.Engine
	profile     observabilityredaction.Profile
	actorPII    bool
	graphDigest string
}

var testAlertEventSequence atomic.Int64

const testEventHistoryGraphDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testEventHistoryProjectionEngine = func() *observabilityredaction.Engine {
	engine, err := observabilityredaction.NewEngine([]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
	if err != nil {
		panic(err)
	}
	return engine
}()

type testLocalProfileResolver struct {
	profile observabilityredaction.ProfileName
	engine  *observabilityredaction.Engine
	digest  string
}

func (resolver testLocalProfileResolver) eventHistoryProjectionBinding() localProjectionBindingSnapshot {
	engine := resolver.engine
	if engine == nil {
		engine = testEventHistoryProjectionEngine
	}
	digest := resolver.digest
	if digest == "" {
		digest = testEventHistoryGraphDigest
	}
	profile, _ := observabilityredaction.BuiltInProfile(resolver.profile)
	profiles := make(map[observability.Bucket]observabilityredaction.Profile, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		profiles[bucket] = profile
	}
	return localProjectionBindingSnapshot{graphDigest: digest, profiles: profiles, engine: engine}
}

func (factory *testAlertCanonicalEventFactory) GraphDigest() string {
	if factory == nil {
		return ""
	}
	if factory.graphDigest != "" {
		return factory.graphDigest
	}
	return testEventHistoryGraphDigest
}

func (factory *testAlertCanonicalEventFactory) BuildAlertCanonicalEvent(
	_ context.Context,
	input AlertCanonicalEventInput,
) (observability.Record, observabilityredaction.Projection, error) {
	encodedBody, err := json.Marshal(input.Body)
	if err != nil {
		return observability.Record{}, observabilityredaction.Projection{}, err
	}
	value, err := observability.ParseValue(encodedBody)
	if err != nil {
		return observability.Record{}, observabilityredaction.Projection{}, err
	}
	body, err := value.Object()
	if err != nil {
		return observability.Record{}, observabilityredaction.Projection{}, err
	}
	producerKey := observability.ProducerKey("activity")
	facts := observability.MandatoryFacts{AlertMutation: true}
	source := observability.SourceOperatorAPI
	if input.Bucket == observability.BucketPlatformHealth {
		producerKey = "lifecycle"
		facts = observability.MandatoryFacts{DurableHealthTransition: true}
		source = observability.SourceSystem
	}
	sequence := testAlertEventSequence.Add(1)
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 3, 1, 2, 3, int(sequence), time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("alert-test-event-%d", sequence), nil
		}),
	)
	if err != nil {
		return observability.Record{}, observabilityredaction.Projection{}, err
	}
	classes := metadataFieldClasses(body)
	if factory.actorPII {
		classes["/actor"] = observability.FieldClassContent
	}
	record, err := builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerGatewayEvent,
		ProducerKey:  producerKey,
		ClassificationContext: observability.ClassificationContext{
			Bucket: input.Bucket, EventName: input.EventName, RawSeverity: "INFO",
			MandatoryFacts: facts,
		},
		Source: source, Action: string(input.EventName), Outcome: input.Outcome,
		Provenance: observability.Provenance{
			Producer: "alert_test", BinaryVersion: "v8-test",
			RegistrySchemaVersion: 1, ConfigGeneration: 1,
		},
		Body: body, FieldClasses: classes,
	})
	if err != nil {
		return observability.Record{}, observabilityredaction.Projection{}, err
	}
	projection, _, err := factory.engine.Project(record, factory.profile)
	return record, projection, err
}

func TestAlertAcknowledgementUsesTrustedLocalProjectionAndRollsBackProfileMismatch(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "projected-alert", "mismatch-alert")
	key := []byte("0123456789abcdef0123456789abcdef")
	engine, err := observabilityredaction.NewEngine(key)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewEventHistoryWriter(
		store, newAlertCommandTestSigner("test-key-a"), nil, testLocalProfileResolver{
			profile: observabilityredaction.ProfileSensitive, engine: engine,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	sensitive, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileSensitive)
	if !ok {
		t.Fatal("sensitive profile missing")
	}
	writer, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: sensitive, actorPII: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: sensitive, graphDigest: strings.Repeat("b", 64),
	}); err == nil || !strings.Contains(err.Error(), "different runtime graph") {
		t.Fatalf("cross-generation alert factory error = %v", err)
	}
	command := AlertAcknowledgementCommand{
		OperationID: "projected-op", AlertID: "projected-alert", Actor: "person@example.com",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	}
	result, err := writer.ApplyAlertAcknowledgement(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Actor == command.Actor || result.Actor == "" {
		t.Fatalf("result retained raw governed actor: %q", result.Actor)
	}
	retry, err := writer.ApplyAlertAcknowledgement(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Actor != result.Actor || retry.EventID != result.EventID {
		t.Fatalf("projected retry changed result: first=%#v retry=%#v", result, retry)
	}
	var projectedActor, operationActor, profile string
	if err := store.db.QueryRow(`SELECT actor, redaction_profile FROM audit_events WHERE id=?`, result.EventID).
		Scan(&projectedActor, &profile); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT actor FROM alert_acknowledgement_operations WHERE operation_id=?`,
		command.OperationID).Scan(&operationActor); err != nil {
		t.Fatal(err)
	}
	if projectedActor != "alert_test" { // compatibility actor is producer; governed actor is in payload.
		t.Fatalf("compatibility actor = %q", projectedActor)
	}
	if operationActor != result.Actor || profile != string(observabilityredaction.ProfileSensitive) {
		t.Fatalf("projected operation actor=%q result=%q profile=%q", operationActor, result.Actor, profile)
	}

	none, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	mismatchWriter, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: none,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mismatchWriter.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
		OperationID: "mismatch-op", AlertID: "mismatch-alert", Actor: "operator",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 0,
	})
	if err == nil || !strings.Contains(err.Error(), "active graph") {
		t.Fatalf("profile mismatch error = %v", err)
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM audit_events WHERE target='mismatch-alert'`,
		`SELECT COUNT(*) FROM alert_acknowledgement_operations WHERE alert_id='mismatch-alert'`,
		`SELECT COUNT(*) FROM alert_acknowledgement_projection WHERE alert_id='mismatch-alert'`,
	} {
		var count int
		if err := store.db.QueryRow(query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("profile mismatch left %d rows for %s", count, query)
		}
	}
}

func metadataFieldClasses(body any) map[string]observability.FieldClass {
	encoded, _ := json.Marshal(body)
	var decoded any
	_ = json.Unmarshal(encoded, &decoded)
	classes := make(map[string]observability.FieldClass)
	var walk func(any, string)
	walk = func(value any, pointer string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				classes[pointer] = observability.FieldClassMetadata
				return
			}
			for key, child := range typed {
				walk(child, pointer+"/"+strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1"))
			}
		case []any:
			if len(typed) == 0 {
				classes[pointer] = observability.FieldClassMetadata
				return
			}
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s/%d", pointer, index))
			}
		default:
			classes[pointer] = observability.FieldClassMetadata
		}
	}
	walk(decoded, "")
	return classes
}

func TestAlertAcknowledgementCASIdempotencyAndImmutableFinding(t *testing.T) {
	store := newAlertProjectionStore(t)
	writer := newAlertProjectionWriter(t, store)
	const alertID = "finding-occurrence-1"
	const findingPayload = `{"rule_id":"R-1","evidence_summary":"immutable"}`
	if _, err := store.db.Exec(`INSERT INTO audit_events (
		id, timestamp, action, actor, details, structured_json, severity,
		bucket, event_name, source, signal, bucket_catalog_version,
		payload_json, projected_record_json, record_schema_version,
		projection_hash, redaction_profile, mandatory
	) VALUES (?, ?, 'finding.observed', 'scanner', 'original-details', ?, 'HIGH',
		'security.finding', 'finding.observed', 'scanner', 'logs', 1,
		?, '{}', 1, 'sha256:original', 'none', 0)`,
		alertID, "2026-07-03T01:00:00Z", findingPayload, findingPayload); err != nil {
		t.Fatal(err)
	}

	command := AlertAcknowledgementCommand{
		OperationID: "operation-1", AlertID: alertID, Actor: "operator@example.com",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	}
	first, err := writer.ApplyAlertAcknowledgement(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != AlertAcknowledgementApplied || first.ProjectionVersionBefore != 0 ||
		first.ProjectionVersionAfter != 1 || first.ObservedProjectionVersion != 0 {
		t.Fatalf("first result = %#v", first)
	}
	retry, err := writer.ApplyAlertAcknowledgement(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.IdempotentReplay || retry.EventID != first.EventID ||
		retry.CreatedAt != first.CreatedAt || retry.ProjectionVersionAfter != 1 {
		t.Fatalf("retry changed original result: first=%#v retry=%#v", first, retry)
	}

	conflictCommand := command
	conflictCommand.Actor = "different-operator@example.com"
	conflict, err := writer.ApplyAlertAcknowledgement(context.Background(), conflictCommand)
	if err != nil {
		t.Fatal(err)
	}
	if conflict.Outcome != AlertAcknowledgementRejected ||
		conflict.RejectionReason != AlertAcknowledgementIdempotencyConflict ||
		conflict.EventID == first.EventID || conflict.ProjectionVersionAfter != 1 {
		t.Fatalf("conflict result = %#v", conflict)
	}

	invalidTargetConflict := command
	invalidTargetConflict.AlertID = "caller-invented-target"
	if _, err := writer.ApplyAlertAcknowledgement(
		context.Background(), invalidTargetConflict,
	); !errors.Is(err, ErrAlertTargetIneligible) {
		t.Fatalf("invalid-target idempotency conflict error = %v", err)
	}
	var invalidTargetEvents int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE bucket='compliance.activity' AND target=?`, invalidTargetConflict.AlertID).
		Scan(&invalidTargetEvents); err != nil {
		t.Fatal(err)
	}
	if invalidTargetEvents != 0 {
		t.Fatalf("invalid-target idempotency conflict wrote %d events", invalidTargetEvents)
	}

	noChange, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
		OperationID: "operation-2", AlertID: alertID, Actor: "operator@example.com",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if noChange.Outcome != AlertAcknowledgementNoChange || noChange.ProjectionVersionAfter != 1 {
		t.Fatalf("no-change result = %#v", noChange)
	}

	stale, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
		OperationID: "operation-3", AlertID: alertID, Actor: "operator@example.com",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Outcome != AlertAcknowledgementRejected ||
		stale.RejectionReason != AlertAcknowledgementStaleVersion ||
		stale.ObservedProjectionVersion != 1 || stale.ProjectionVersionAfter != 1 {
		t.Fatalf("stale result = %#v", stale)
	}

	var eventCount, operationCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE bucket='compliance.activity' AND target=?`, alertID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 4 { // applied + conflict + no_change + stale; exact retry adds none.
		t.Fatalf("compliance event count = %d, want 4", eventCount)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_operations
		WHERE alert_id=?`, alertID).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if operationCount != 3 { // conflicting reuse never replaces the original operation.
		t.Fatalf("operation count = %d, want 3", operationCount)
	}

	var severity, details, payload string
	if err := store.db.QueryRow(`SELECT severity, details, payload_json
		FROM audit_events WHERE id=?`, alertID).Scan(&severity, &details, &payload); err != nil {
		t.Fatal(err)
	}
	if severity != "HIGH" || details != "original-details" || payload != findingPayload {
		t.Fatalf("immutable finding changed: severity=%q details=%q payload=%q", severity, details, payload)
	}
	if _, err := store.db.Exec(`UPDATE alert_acknowledgement_operations
		SET outcome='rejected' WHERE operation_id='operation-1'`); err == nil {
		t.Fatal("immutable operation row accepted UPDATE")
	}
}

func TestAlertAcknowledgementFingerprintIsKeyedProtectedAndRotationFailsClosed(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "dictionary-alert")
	writer := newAlertProjectionWriter(t, store)
	command := AlertAcknowledgementCommand{
		OperationID: "dictionary-operation", AlertID: "dictionary-alert", Actor: "admin",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	}
	result, err := writer.ApplyAlertAcknowledgement(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	var fingerprint, payload string
	if err := store.db.QueryRow(`SELECT command_fingerprint FROM alert_acknowledgement_operations
		WHERE operation_id=?`, command.OperationID).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if keyID, valid := alertFingerprintKeyID(fingerprint); !valid || keyID != "test-key-a" {
		t.Fatalf("protected fingerprint format = %q", fingerprint)
	}
	storedDigest := fingerprint[strings.LastIndexByte(fingerprint, ':')+1:]
	normalized, err := normalizeAlertCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	message, err := alertCommandFingerprintMessage(normalized)
	if err != nil {
		t.Fatal(err)
	}
	wantMAC := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	_, _ = wantMAC.Write(message)
	if got := hex.EncodeToString(wantMAC.Sum(nil)); got != storedDigest {
		t.Fatalf("stored digest is not the expected keyed MAC: got %q want %q", storedDigest, got)
	}
	for _, candidate := range []string{"admin", "root", "operator", "user"} {
		candidateCommand := command
		candidateCommand.Actor = candidate
		candidateNormalized, err := normalizeAlertCommand(candidateCommand)
		if err != nil {
			t.Fatal(err)
		}
		candidateMessage, err := alertCommandFingerprintMessage(candidateNormalized)
		if err != nil {
			t.Fatal(err)
		}
		unkeyed := sha256.Sum256(candidateMessage)
		if hex.EncodeToString(unkeyed[:]) == storedDigest {
			t.Fatalf("stored fingerprint matched unkeyed low-entropy actor candidate %q", candidate)
		}
	}
	for _, lowEntropyValue := range []string{command.Actor, command.AlertID, command.OperationID} {
		if strings.Contains(fingerprint, lowEntropyValue) {
			t.Fatalf("fingerprint exposed normalized command value %q", lowEntropyValue)
		}
	}
	if err := store.db.QueryRow(`SELECT payload_json FROM audit_events WHERE id=?`, result.EventID).
		Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "command_fingerprint") || strings.Contains(payload, fingerprint) {
		t.Fatalf("canonical compliance payload exposed protected fingerprint: %s", payload)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatal(err)
	}
	if _, present := body["command_fingerprint"]; present {
		t.Fatal("command fingerprint is part of the canonical compliance schema")
	}

	rotated := newAlertProjectionWriterWithSigner(t, store, newAlertCommandTestSigner("test-key-b"))
	if _, err := rotated.ApplyAlertAcknowledgement(context.Background(), command); !errors.Is(
		err, ErrAlertCommandFingerprintUnavailable,
	) {
		t.Fatalf("rotated-key retry error = %v", err)
	}
	var eventCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE bucket='compliance.activity' AND target=?`, command.AlertID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("rotated-key retry wrote %d compliance events", eventCount)
	}
}

func TestAlertAcknowledgementFingerprintFailuresAreSafeAndAtomic(t *testing.T) {
	for _, test := range []struct {
		name   string
		signer ProjectionIntegritySigner
	}{
		{name: "signer unavailable", signer: &alertCommandTestSigner{
			keyID: "test-key-a", err: errors.New("secret signer backend diagnostic"),
		}},
		{name: "invalid digest", signer: &alertCommandTestSigner{
			keyID: "test-key-a", digest: []byte("short"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newAlertProjectionStore(t)
			seedEligibleAlertTarget(t, store, "signing-alert")
			writer := newAlertProjectionWriterWithSigner(t, store, test.signer)
			_, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
				OperationID: "signing-operation", AlertID: "signing-alert", Actor: "admin",
				Disposition: AlertDispositionAcknowledged,
			})
			if !errors.Is(err, ErrAlertCommandFingerprintUnavailable) ||
				strings.Contains(fmt.Sprint(err), "secret signer") {
				t.Fatalf("safe fingerprint failure = %v", err)
			}
			for _, table := range []string{"alert_acknowledgement_operations", "alert_acknowledgement_projection"} {
				var count int
				if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("%s contains %d rows after fingerprint failure", table, count)
				}
			}
		})
	}

	store := newAlertProjectionStore(t)
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewEventHistoryWriter(store, nil, nil, testLocalProfileResolver{
		profile: observabilityredaction.ProfileNone, engine: engine,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	if _, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: profile,
	}); !errors.Is(err, ErrAlertCommandFingerprintUnavailable) {
		t.Fatalf("nil signer constructor error = %v", err)
	}
}

func TestAlertAcknowledgementUnsignedOutcomeReportsAfterStoreRelease(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "unsigned-alert")
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := &stagedAlertCommandSigner{
		alertCommandTestSigner: newAlertCommandTestSigner("test-key-a"),
		unavailableAt:          2, // command receipt is keyed; event-history signing becomes unavailable.
	}
	reporter := &closingAlertHealthReporter{
		store: store, codes: make(chan EventHistoryHealthCode, 1), errs: make(chan error, 1),
	}
	history, err := NewEventHistoryWriter(store, signer, reporter, testLocalProfileResolver{
		profile: observabilityredaction.ProfileNone, engine: engine,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	writer, err := NewAlertAcknowledgementWriter(store, history, &testAlertCanonicalEventFactory{
		engine: engine, profile: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, applyErr := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
			OperationID: "unsigned-operation", AlertID: "unsigned-alert", Actor: "operator",
			Disposition: AlertDispositionAcknowledged,
		})
		finished <- applyErr
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unsigned health reporter deadlocked while closing the alert store")
	}
	select {
	case code := <-reporter.codes:
		if code != EventHistoryHealthUnsigned {
			t.Fatalf("health code = %q", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unsigned health report")
	}
	select {
	case err := <-reporter.errs:
		if err != nil {
			t.Fatalf("reentrant close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reentrant close result")
	}
}

func TestAlertAcknowledgementTargetEligibilityIsFindingScoped(t *testing.T) {
	store := newAlertProjectionStore(t)
	writer := newAlertProjectionWriter(t, store)
	if _, err := store.db.Exec(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity)
		VALUES
		('legacy-auth', '2026-07-03T00:00:00Z', 'api-auth-failure', 'system', 'auth', 'HIGH'),
		('legacy-config', '2026-07-03T00:00:01Z', 'config-update', 'system', 'config', 'HIGH'),
		('legacy-finding', '2026-07-03T00:00:02Z', 'scan-finding', 'scanner', 'finding', 'HIGH'),
		('legacy-finding-none', '2026-07-03T00:00:02Z', 'scan-finding', 'scanner', 'finding', 'NONE'),
		('legacy-finding-empty', '2026-07-03T00:00:02Z', 'scan-finding', 'scanner', 'finding', ''),
		('legacy-alert-action', '2026-07-03T00:00:03Z', 'alert', 'system', 'alert', 'HIGH')`); err != nil {
		t.Fatal(err)
	}
	seedEligibleAlertTarget(t, store, "v8-finding")
	if _, err := store.db.Exec(`INSERT INTO audit_events (
		id, timestamp, action, actor, details, severity, bucket, event_name
	) VALUES ('v8-health', '2026-07-03T00:00:04Z', 'subsystem.degraded', 'system',
		'health', 'HIGH', 'platform.health', 'subsystem.degraded')`); err != nil {
		t.Fatal(err)
	}

	for _, alertID := range []string{
		"missing", "legacy-auth", "legacy-config", "legacy-finding-none",
		"legacy-finding-empty", "v8-health",
	} {
		_, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
			OperationID: "reject-" + alertID, AlertID: alertID, Actor: "operator",
			Disposition: AlertDispositionAcknowledged,
		})
		if !errors.Is(err, ErrAlertTargetIneligible) {
			t.Fatalf("target %q error = %v", alertID, err)
		}
	}
	for _, alertID := range []string{"legacy-finding", "legacy-alert-action", "v8-finding"} {
		result, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
			OperationID: "accept-" + alertID, AlertID: alertID, Actor: "operator",
			Disposition: AlertDispositionAcknowledged,
		})
		if err != nil || result.Outcome != AlertAcknowledgementApplied {
			t.Fatalf("eligible target %q result=%#v err=%v", alertID, result, err)
		}
	}
}

func TestAlertAcknowledgementConcurrentCASHasOneWinner(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "race-alert")
	writer := newAlertProjectionWriter(t, store)
	commands := []AlertAcknowledgementCommand{
		{OperationID: "lexically-last", AlertID: "race-alert", Actor: "actor-z",
			Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0},
		{OperationID: "lexically-first", AlertID: "race-alert", Actor: "actor-a",
			Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 0},
	}
	start := make(chan struct{})
	results := make([]AlertAcknowledgementResult, len(commands))
	errs := make([]error, len(commands))
	var wg sync.WaitGroup
	for index := range commands {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = writer.ApplyAlertAcknowledgement(context.Background(), commands[index])
		}(index)
	}
	close(start)
	wg.Wait()

	applied, rejected := 0, 0
	var winner AlertAcknowledgementResult
	for index, result := range results {
		if errs[index] != nil {
			t.Fatalf("command %d: %v", index, errs[index])
		}
		switch result.Outcome {
		case AlertAcknowledgementApplied:
			applied++
			winner = result
		case AlertAcknowledgementRejected:
			rejected++
			if result.RejectionReason != AlertAcknowledgementStaleVersion ||
				result.ObservedProjectionVersion != 1 {
				t.Fatalf("loser is not stale N=0 rejection: %#v", result)
			}
		default:
			t.Fatalf("unexpected race result: %#v", result)
		}
	}
	if applied != 1 || rejected != 1 {
		t.Fatalf("applied=%d rejected=%d results=%#v", applied, rejected, results)
	}
	projection, err := writer.ReconcileAlertAcknowledgement(context.Background(), "race-alert")
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != 1 || projection.Disposition != winner.Disposition ||
		projection.Actor != winner.Actor || projection.SourceEventID != winner.EventID {
		t.Fatalf("projection did not preserve first committed CAS: %#v winner=%#v", projection, winner)
	}
	var appliedEvents int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE target='race-alert' AND bucket='compliance.activity'
		  AND json_extract(payload_json,'$.outcome')='applied'`).Scan(&appliedEvents); err != nil {
		t.Fatal(err)
	}
	if appliedEvents != 1 {
		t.Fatalf("applied event count = %d, want 1", appliedEvents)
	}
}

func TestAlertAcknowledgementVersionZeroCASUsesRetrySentinel(t *testing.T) {
	store := newAlertProjectionStore(t)
	now := time.Date(2026, 7, 3, 1, 2, 3, 0, time.UTC)
	if _, err := store.db.Exec(`INSERT INTO alert_acknowledgement_projection (
		alert_id, disposition, actor, disposition_at, projection_version,
		source, source_event_id, updated_at
	) VALUES ('cas-alert', 'acknowledged', 'winner', ?, 1, 'modern', 'winner-event', ?)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	err = applyAlertProjectionCAS(context.Background(), tx, AlertAcknowledgementProjection{
		AlertID: "cas-alert", Disposition: AlertDispositionUnreviewed,
	}, AlertAcknowledgementResult{
		AlertID: "cas-alert", Disposition: AlertDispositionDismissed, Actor: "loser",
		CreatedAt: now, ProjectionVersionBefore: 0, ProjectionVersionAfter: 1,
		EventID: "loser-event",
	})
	if !errors.Is(err, errAlertProjectionCASRetry) {
		t.Fatalf("version-zero CAS error = %v", err)
	}
}

func TestAlertAcknowledgementConcurrentStoresRetryWholeTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-audit.db")
	stores := make([]*Store, 2)
	writers := make([]*AlertAcknowledgementWriter, 2)
	for index := range stores {
		store, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.Init(); err != nil {
			t.Fatal(err)
		}
		stores[index] = store
		writers[index] = newAlertProjectionWriter(t, store)
	}
	seedEligibleAlertTarget(t, stores[0], "multi-store-alert")
	commands := []AlertAcknowledgementCommand{
		{OperationID: "multi-store-a", AlertID: "multi-store-alert", Actor: "actor-a",
			Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0},
		{OperationID: "multi-store-b", AlertID: "multi-store-alert", Actor: "actor-b",
			Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 0},
	}
	start := make(chan struct{})
	results := make([]AlertAcknowledgementResult, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range writers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = writers[index].ApplyAlertAcknowledgement(
				context.Background(), commands[index],
			)
		}(index)
	}
	close(start)
	wait.Wait()

	applied, stale := 0, 0
	for index, result := range results {
		if errs[index] != nil {
			t.Fatalf("store %d: %v", index, errs[index])
		}
		switch result.Outcome {
		case AlertAcknowledgementApplied:
			applied++
		case AlertAcknowledgementRejected:
			if result.RejectionReason != AlertAcknowledgementStaleVersion ||
				result.ObservedProjectionVersion != 1 {
				t.Fatalf("store %d loser = %#v", index, result)
			}
			stale++
		default:
			t.Fatalf("store %d result = %#v", index, result)
		}
	}
	if applied != 1 || stale != 1 {
		t.Fatalf("multi-store race applied=%d stale=%d results=%#v", applied, stale, results)
	}
}

func TestAlertAcknowledgementReconciliationRepairsByVersionAndIgnoresNonApplied(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "repair-alert")
	writer := newAlertProjectionWriter(t, store)
	ctx := context.Background()
	first, err := writer.ApplyAlertAcknowledgement(ctx, AlertAcknowledgementCommand{
		OperationID: "repair-1", AlertID: "repair-alert", Actor: "first",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ApplyAlertAcknowledgement(ctx, AlertAcknowledgementCommand{
		OperationID: "repair-no-change", AlertID: "repair-alert", Actor: "observer",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ApplyAlertAcknowledgement(ctx, AlertAcknowledgementCommand{
		OperationID: "repair-stale", AlertID: "repair-alert", Actor: "stale",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	second, err := writer.ApplyAlertAcknowledgement(ctx, AlertAcknowledgementCommand{
		OperationID: "repair-2", AlertID: "repair-alert", Actor: "second",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Outcome != AlertAcknowledgementApplied || second.ProjectionVersionAfter != 2 {
		t.Fatalf("second transition = %#v", second)
	}

	// Timestamp and record-ID ordering are deliberately misleading. Replay must
	// use projection_version_after and still derive the version-two dismissal.
	if _, err := store.db.Exec(`UPDATE audit_events SET timestamp='2030-01-01T00:00:00Z' WHERE id=?`, first.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET timestamp='2020-01-01T00:00:00Z' WHERE id=?`, second.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE alert_acknowledgement_projection
		SET disposition='acknowledged', actor='corrupt', source_event_id='wrong'
		WHERE alert_id='repair-alert'`); err != nil {
		t.Fatal(err)
	}
	projection, err := writer.ReconcileAlertAcknowledgement(ctx, "repair-alert")
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != 2 || projection.Disposition != AlertDispositionDismissed ||
		projection.Actor != "second" || projection.SourceEventID != second.EventID {
		t.Fatalf("stale projection was not repaired: %#v", projection)
	}
	if _, err := store.db.Exec(`DELETE FROM alert_acknowledgement_projection WHERE alert_id='repair-alert'`); err != nil {
		t.Fatal(err)
	}
	projection, err = writer.ReconcileAlertAcknowledgement(ctx, "repair-alert")
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != 2 || projection.Disposition != AlertDispositionDismissed {
		t.Fatalf("missing projection was not rebuilt: %#v", projection)
	}
}

func TestAlertAcknowledgementReceiptsSurviveEventRetention(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "retained-alert")
	writer := newAlertProjectionWriter(t, store)
	ctx := context.Background()
	command := AlertAcknowledgementCommand{
		OperationID: "retained-receipt-1", AlertID: "retained-alert", Actor: "operator",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	}
	first, err := writer.ApplyAlertAcknowledgement(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id IN (?, ?)`, first.EventID, command.AlertID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM alert_acknowledgement_projection
		WHERE alert_id=?`, command.AlertID); err != nil {
		t.Fatal(err)
	}
	projection, err := writer.ReconcileAlertAcknowledgement(ctx, command.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != 1 || projection.Disposition != AlertDispositionAcknowledged ||
		projection.SourceEventID != first.EventID {
		t.Fatalf("receipt reconstruction = %#v", projection)
	}
	retry, err := writer.ApplyAlertAcknowledgement(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.IdempotentReplay || retry.EventID != first.EventID || retry.CreatedAt != first.CreatedAt {
		t.Fatalf("retained receipt retry changed result: first=%#v retry=%#v", first, retry)
	}
	var reCreated int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id=?`, first.EventID).Scan(&reCreated); err != nil {
		t.Fatal(err)
	}
	if reCreated != 0 {
		t.Fatal("exact retry recreated age-reaped audit history")
	}
	second, err := writer.ApplyAlertAcknowledgement(ctx, AlertAcknowledgementCommand{
		OperationID: "retained-receipt-2", AlertID: command.AlertID, Actor: "operator-2",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 1,
	})
	if err != nil || second.Outcome != AlertAcknowledgementApplied || second.ProjectionVersionAfter != 2 {
		t.Fatalf("post-retention transition = %#v err=%v", second, err)
	}
}

func TestAlertAcknowledgementReplayStreamsLargeReapedReceiptPrefix(t *testing.T) {
	store := newAlertProjectionStore(t)
	writer := newAlertProjectionWriter(t, store)
	const (
		alertID      = "large-reaped-alert"
		receiptCount = 4096
	)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO alert_acknowledgement_operations (
		operation_id, command_fingerprint, alert_id, requested_disposition, actor,
		expected_projection_version, outcome, rejection_reason,
		observed_projection_version, projection_version_before,
		projection_version_after, event_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, 'applied', NULL, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	for version := int64(1); version <= receiptCount; version++ {
		disposition := AlertDispositionAcknowledged
		if version%2 == 0 {
			disposition = AlertDispositionDismissed
		}
		operationID := fmt.Sprintf("large-operation-%04d", version)
		eventID := fmt.Sprintf("reaped-event-%04d", version)
		createdAt := time.Date(2026, 7, 3, 1, 0, int(version%60), int(version), time.UTC).
			Format(time.RFC3339Nano)
		if _, err := statement.Exec(
			operationID, "hmac-sha256:v1:test-key-a:"+strings.Repeat("a", 64), alertID,
			disposition, "streamed-actor", version-1, version-1, version-1, version,
			eventID, createdAt,
		); err != nil {
			_ = statement.Close()
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := statement.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	projection, err := writer.ReconcileAlertAcknowledgement(context.Background(), alertID)
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != receiptCount ||
		projection.Disposition != AlertDispositionDismissed ||
		projection.SourceEventID != "reaped-event-4096" {
		t.Fatalf("streamed projection = %#v", projection)
	}
}

func TestAlertAcknowledgementContradictoryRetainedEventFailsClosed(t *testing.T) {
	store := newAlertProjectionStore(t)
	seedEligibleAlertTarget(t, store, "contradiction-alert")
	writer := newAlertProjectionWriter(t, store)
	result, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
		OperationID: "contradiction-op", AlertID: "contradiction-alert", Actor: "operator",
		Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit_events
		SET payload_json=json_set(payload_json, '$.projection_version_after', 7)
		WHERE id=?`, result.EventID); err != nil {
		t.Fatal(err)
	}
	_, err = writer.ReconcileAlertAcknowledgement(context.Background(), "contradiction-alert")
	var integrityErr *AlertProjectionIntegrityError
	if !errors.As(err, &integrityErr) || integrityErr.Code != AlertProjectionHealthVersionConflict {
		t.Fatalf("contradictory retained event error = %v", err)
	}
}

func TestAlertAcknowledgementRetainedEventReplayControlsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name  string
		path  string
		value any
	}{
		{name: "body target", path: "$.target", value: "different-alert"},
		{name: "expected version", path: "$.expected_projection_version", value: 99},
		{name: "observed version", path: "$.observed_projection_version", value: 99},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newAlertProjectionStore(t)
			alertID := "retained-controls-" + strings.ReplaceAll(test.name, " ", "-")
			seedEligibleAlertTarget(t, store, alertID)
			writer := newAlertProjectionWriter(t, store)
			result, err := writer.ApplyAlertAcknowledgement(
				context.Background(),
				AlertAcknowledgementCommand{
					OperationID: "operation-" + alertID, AlertID: alertID, Actor: "operator",
					Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`UPDATE audit_events
				SET payload_json=json_set(payload_json, ?, ?) WHERE id=?`,
				test.path, test.value, result.EventID); err != nil {
				t.Fatal(err)
			}
			_, err = writer.ReconcileAlertAcknowledgement(context.Background(), alertID)
			var integrityErr *AlertProjectionIntegrityError
			if !errors.As(err, &integrityErr) || integrityErr.Code != AlertProjectionHealthVersionConflict {
				t.Fatalf("retained replay-control mutation error = %v", err)
			}
		})
	}
}

func TestAlertAcknowledgementLegacyACKBecomesBaselineWithoutModernAction(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "legacy.db"))
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
	if _, err := store.db.Exec(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity)
		VALUES ('legacy-alert', '2025-02-03T04:05:06Z', 'scan-finding', 'legacy-user', 'lost severity', 'ACK'),
		('legacy-summary', '2025-02-03T04:06:00Z', 'acknowledge-alerts', 'legacy-user', 'summary', 'ACK')`); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	writer := newAlertProjectionWriter(t, store)
	projection, err := writer.ReconcileAlertAcknowledgement(context.Background(), "legacy-alert")
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectionVersion != 1 || projection.Disposition != AlertDispositionAcknowledged ||
		projection.Source != "legacy_ack" || projection.SourceEventID != "legacy-alert" ||
		projection.LegacyOriginalSeverity != "unknown" ||
		projection.LegacyTimestampProvenance != "legacy_occurrence_timestamp_unreliable" {
		t.Fatalf("legacy baseline = %#v", projection)
	}
	var baselineCount, modernEventCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_baselines`).Scan(&baselineCount); err != nil {
		t.Fatal(err)
	}
	if baselineCount != 1 {
		t.Fatalf("baseline count = %d, want 1 (summary row excluded)", baselineCount)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE bucket='compliance.activity' AND target='legacy-alert'`).Scan(&modernEventCount); err != nil {
		t.Fatal(err)
	}
	if modernEventCount != 0 {
		t.Fatalf("legacy baseline fabricated %d modern operator actions", modernEventCount)
	}
	if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id='legacy-alert'`); err != nil {
		t.Fatal(err)
	}
	transition, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
		OperationID: "legacy-after-reap", AlertID: "legacy-alert", Actor: "modern-operator",
		Disposition: AlertDispositionDismissed, ExpectedProjectionVersion: 1,
	})
	if err != nil || transition.Outcome != AlertAcknowledgementApplied ||
		transition.ProjectionVersionAfter != 2 {
		t.Fatalf("protected legacy baseline transition = %#v err=%v", transition, err)
	}
	if _, err := store.db.Exec(`DELETE FROM alert_acknowledgement_baselines
		WHERE alert_id='legacy-alert'`); err == nil {
		t.Fatal("immutable legacy baseline accepted DELETE")
	}
}

func TestAlertAcknowledgementStartupCapturesACKWrittenAfterMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback-ack.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity)
		VALUES ('rollback-ack', '2026-07-03T05:00:00Z', 'scan-finding',
			'rollback-operator', 'legacy rollback write', 'ACK'),
			('rollback-auth-ack', '2026-07-03T05:01:00Z', 'api-auth-failure',
			'rollback-operator', 'not an alert finding', 'ACK')`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := reopened.db.QueryRow(`SELECT baseline_version
		FROM alert_acknowledgement_baselines WHERE alert_id='rollback-ack'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("rollback ACK baseline version = %d, want 1", version)
	}
	var genericBaseline int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_baselines
		WHERE alert_id='rollback-auth-ack'`).Scan(&genericBaseline); err != nil {
		t.Fatal(err)
	}
	if genericBaseline != 0 {
		t.Fatal("generic authentication ACK was incorrectly promoted to an alert baseline")
	}
}

func TestAlertAcknowledgementReconciliationFailsClosedWithMandatoryHealth(t *testing.T) {
	tests := []struct {
		name string
		code AlertProjectionHealthCode
		seed func(t *testing.T, store *Store)
	}{
		{
			name: "gap", code: AlertProjectionHealthVersionGap,
			seed: func(t *testing.T, store *Store) {
				appendAlertEvidenceForTest(t, store, "gap-event", "broken-alert", 1, 2, AlertDispositionDismissed)
			},
		},
		{
			name: "conflict", code: AlertProjectionHealthVersionConflict,
			seed: func(t *testing.T, store *Store) {
				appendAlertEvidenceForTest(t, store, "conflict-a", "broken-alert", 0, 1, AlertDispositionAcknowledged)
				appendAlertEvidenceForTest(t, store, "conflict-b", "broken-alert", 0, 1, AlertDispositionDismissed)
			},
		},
		{
			name: "projection ahead", code: AlertProjectionHealthProjectionAhead,
			seed: func(t *testing.T, store *Store) {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				if _, err := store.db.Exec(`INSERT INTO alert_acknowledgement_projection
					(alert_id, disposition, actor, disposition_at, projection_version,
					 source, source_event_id, updated_at)
					VALUES ('broken-alert','dismissed','corrupt',?,2,'modern','missing',?)`, now, now); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newAlertProjectionStore(t)
			writer := newAlertProjectionWriter(t, store)
			test.seed(t, store)
			for attempt := 0; attempt < 2; attempt++ {
				_, err := writer.ReconcileAlertAcknowledgement(context.Background(), "broken-alert")
				var integrityErr *AlertProjectionIntegrityError
				if !errors.As(err, &integrityErr) || integrityErr.Code != test.code ||
					!errors.Is(err, ErrAlertProjectionUnhealthy) {
					t.Fatalf("attempt %d error = %v, want %s", attempt, err, test.code)
				}
			}
			_, err := writer.ApplyAlertAcknowledgement(context.Background(), AlertAcknowledgementCommand{
				OperationID: "blocked-op", AlertID: "broken-alert", Actor: "operator",
				Disposition: AlertDispositionAcknowledged, ExpectedProjectionVersion: 0,
			})
			if !errors.Is(err, ErrAlertProjectionUnhealthy) {
				t.Fatalf("mutation did not fail closed: %v", err)
			}
			var healthRows, healthEvents int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_health
				WHERE alert_id='broken-alert' AND code=?`, test.code).Scan(&healthRows); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events
				WHERE bucket='platform.health' AND target='broken-alert'
				  AND event_name='subsystem.degraded' AND mandatory=1`).Scan(&healthEvents); err != nil {
				t.Fatal(err)
			}
			if healthRows != 1 || healthEvents != 1 {
				t.Fatalf("health rows=%d events=%d, want one rate-limited transition", healthRows, healthEvents)
			}
			var operationRows int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_operations
				WHERE operation_id='blocked-op'`).Scan(&operationRows); err != nil {
				t.Fatal(err)
			}
			if operationRows != 0 {
				t.Fatalf("unhealthy mutation persisted %d operation rows", operationRows)
			}
		})
	}
}

func appendAlertEvidenceForTest(
	t *testing.T,
	store *Store,
	eventID string,
	alertID string,
	before int64,
	after int64,
	disposition AlertDisposition,
) {
	t.Helper()
	writer := newAlertProjectionWriter(t, store)
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	body := alertComplianceBody{
		Target: alertID, OperationID: fmt.Sprintf("op-%s", eventID), TargetEventID: alertID,
		RequestedDisposition: disposition, Actor: "test-actor",
		Outcome:                   AlertAcknowledgementApplied,
		ExpectedProjectionVersion: before, ObservedProjectionVersion: before,
		ProjectionVersionBefore: before, ProjectionVersionAfter: after,
	}
	appended, err := writer.appendAlertCanonicalEvent(context.Background(), tx, AlertCanonicalEventInput{
		Bucket: observability.BucketComplianceActivity, EventName: alertCommandEventName(disposition),
		Outcome: observability.OutcomeApplied, AlertID: alertID, Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO alert_acknowledgement_operations (
		operation_id, command_fingerprint, alert_id, requested_disposition, actor,
		expected_projection_version, outcome, rejection_reason,
		observed_projection_version, projection_version_before,
		projection_version_after, event_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, 'applied', NULL, ?, ?, ?, ?, ?)`,
		body.OperationID, "hmac-sha256:v1:test-key-a:"+strings.Repeat("a", 64), alertID, disposition, body.Actor,
		before, before, before, after, appended.record.RecordID(),
		appended.record.Timestamp().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAlertAcknowledgementMigrationIsAppendOnlyAndPartialSchemaSafe(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "partial.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	var alertMigration migration
	var alertMigrationVersion int
	for index, candidate := range migrations {
		if candidate.description == "alert acknowledgements: add CAS projection and reconciliation state" {
			alertMigration = candidate
			alertMigrationVersion = index + 1
			break
		}
	}
	if alertMigration.apply == nil {
		t.Fatal("alert acknowledgement migration not found")
	}
	if err := store.applyMigration(alertMigrationVersion, alertMigration); err != nil {
		t.Fatalf("alert projection migration on partial schema: %v", err)
	}
	for _, table := range []string{
		"alert_acknowledgement_projection", "alert_acknowledgement_operations",
		"alert_acknowledgement_baselines", "alert_acknowledgement_health",
	} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
			WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s count = %d", table, count)
		}
	}
}

// Compile-time assertion that migration test uses the database/sql driver
// directly; this prevents an accidental unused import when test helpers move.
var _ = sql.ErrNoRows
