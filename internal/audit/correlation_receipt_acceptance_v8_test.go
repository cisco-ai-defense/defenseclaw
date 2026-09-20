// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func receiptAcceptanceEvent(
	t *testing.T,
	instance ConnectorInstance,
	rail CorrelationRail,
	eventName string,
	now time.Time,
) CorrelationEvent {
	t.Helper()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	return CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: rail, EventName: eventName, ReceivedTime: now,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}
}

func TestExistingOccurrenceReceiptRequiresExactAcceptanceCanary(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	event := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", now)
	create, created, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: event})
	if err != nil || created.Status != CorrelationOccurrenceNew {
		t.Fatalf("create result=%+v err=%v", created, err)
	}
	if err := create.Commit(); err != nil {
		t.Fatal(err)
	}
	claim := CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("native-source"), FingerprintSHA256: correlationDigest("native-payload"),
		ReceivedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}

	attach, stored, first, err := repo.BeginExistingOccurrenceWithReceipt(t.Context(), event.SemanticEventID, claim)
	if err != nil || first.Status != CorrelationOccurrenceExisting || first.SuppressEmission ||
		stored.SemanticEventID != event.SemanticEventID {
		t.Fatalf("first attach stored=%+v result=%+v err=%v", stored, first, err)
	}
	if err := attach.Commit(); err != nil {
		t.Fatal(err)
	}

	secondTx, _, second, err := repo.BeginExistingOccurrenceWithReceipt(t.Context(), event.SemanticEventID, claim)
	if err != nil || second.Status != CorrelationOccurrenceReplay || second.SuppressEmission || second.DeliveryCount != 2 {
		t.Fatalf("pending replay result=%+v err=%v", second, err)
	}
	if err := secondTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordObservation(t.Context(), CorrelationObservation{
		RecordID: "canonical-" + string(event.SemanticEventID), SemanticEventID: event.SemanticEventID,
		Signal: CorrelationSignalLogs, Bucket: "model_io", EventName: event.EventName,
		ObservedAt: now.Add(2 * time.Second), Status: CorrelationObservationExportEligible,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkOccurrenceCanonicalPersisted(t.Context(), CorrelationReceiptLocator{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		SourceKeyDigest:     claim.SourceKeyDigest, FingerprintSHA256: claim.FingerprintSHA256,
		SemanticEventID: event.SemanticEventID,
	}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}

	thirdTx, _, third, err := repo.BeginExistingOccurrenceWithReceipt(t.Context(), event.SemanticEventID, claim)
	if err != nil || third.Status != CorrelationOccurrenceReplay || !third.SuppressEmission || third.DeliveryCount != 3 {
		t.Fatalf("accepted replay result=%+v err=%v", third, err)
	}
	if err := thirdTx.Commit(); err != nil {
		t.Fatal(err)
	}

	other := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "other", now.Add(3*time.Second))
	otherTx, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := otherTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if tx, _, _, err := repo.BeginExistingOccurrenceWithReceipt(t.Context(), other.SemanticEventID, claim); tx != nil || !errors.Is(err, ErrCorrelationConflict) {
		t.Fatalf("cross-semantic receipt tx=%v err=%v", tx, err)
	}
	var deliveries int
	if err := store.db.QueryRow(`SELECT delivery_count FROM correlation_receipts
		WHERE connector_instance_id=? AND source_key_digest=? AND fingerprint_sha256=?`,
		string(instance.ConnectorInstanceID), claim.SourceKeyDigest, claim.FingerprintSHA256).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 3 {
		t.Fatalf("failed cross-semantic attach changed delivery count to %d", deliveries)
	}
}

func TestExistingOccurrenceConcurrentReceiptAttachIsSerialized(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	event := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "tool_end", now)
	create, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: event})
	if err != nil {
		t.Fatal(err)
	}
	if err := create.Commit(); err != nil {
		t.Fatal(err)
	}
	claim := CorrelationReceiptClaim{
		SourceKeyDigest:   correlationDigest("concurrent-native-source"),
		FingerprintSHA256: correlationDigest("concurrent-native-payload"),
		ReceivedAt:        now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}
	const workers = 12
	var attached, replayed, suppressed, failures atomic.Int64
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			tx, _, result, err := repo.BeginExistingOccurrenceWithReceipt(context.Background(), event.SemanticEventID, claim)
			if err != nil {
				failures.Add(1)
				return
			}
			if err := tx.Commit(); err != nil {
				failures.Add(1)
				return
			}
			switch result.Status {
			case CorrelationOccurrenceExisting:
				attached.Add(1)
			case CorrelationOccurrenceReplay:
				replayed.Add(1)
			default:
				failures.Add(1)
			}
			if result.SuppressEmission {
				suppressed.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 || attached.Load() != 1 || replayed.Load() != workers-1 || suppressed.Load() != 0 {
		t.Fatalf("attached=%d replayed=%d suppressed=%d failures=%d",
			attached.Load(), replayed.Load(), suppressed.Load(), failures.Load())
	}
}

func TestExistingOccurrenceConflictPreflightRaceCreatesOneDistinctEvent(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	original := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", now)
	base := CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("raced-source"), FingerprintSHA256: correlationDigest("original"),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	create, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: original, Receipt: &base})
	if err != nil {
		t.Fatal(err)
	}
	if err := create.Commit(); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.FingerprintSHA256 = correlationDigest("changed")
	changed.ReceivedAt = now.Add(time.Second)

	preflightTx, _, preflight, err := repo.BeginExistingOccurrenceWithReceipt(t.Context(), original.SemanticEventID, changed)
	if err != nil || preflight.Status != CorrelationOccurrenceConflict ||
		preflight.SemanticEventID == original.SemanticEventID || preflight.ConflictsWith != original.SemanticEventID {
		t.Fatalf("preflight result=%+v err=%v", preflight, err)
	}
	if err := preflightTx.Rollback(); err != nil {
		t.Fatal(err)
	}

	// A competing writer wins after preflight and before our authoritative
	// BeginOccurrence claim.
	winner := receiptAcceptanceEvent(t, instance, CorrelationRailNativeOTLP, "model_end", now.Add(2*time.Second))
	winnerTx, winnerResult, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: winner, Receipt: &changed})
	if err != nil || winnerResult.Status != CorrelationOccurrenceConflict {
		t.Fatalf("winner result=%+v err=%v", winnerResult, err)
	}
	if err := winnerTx.Commit(); err != nil {
		t.Fatal(err)
	}

	loser := receiptAcceptanceEvent(t, instance, CorrelationRailNativeOTLP, "model_end", now.Add(3*time.Second))
	loserTx, loserResult, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: loser, Receipt: &changed})
	if err != nil || loserResult.Status != CorrelationOccurrenceReplay ||
		loserResult.SemanticEventID != winnerResult.SemanticEventID || loserResult.SuppressEmission {
		t.Fatalf("loser result=%+v winner=%+v err=%v", loserResult, winnerResult, err)
	}
	if err := loserTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var events, receipts int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 2 || receipts != 2 {
		t.Fatalf("preflight race events=%d receipts=%d", events, receipts)
	}
}
