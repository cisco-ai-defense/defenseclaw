// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainTwentyOneSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 46
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-one for bounded SQL value persistence" {
		t.Fatal("twenty-one-slot SQL persistence state is not append-only migration 47")
	}
	fixture := newToolChainFixture(t, ":memory:")
	for table, bounds := range map[string][]string{
		"guardrail_chain_events":          {"923", "14783"},
		"guardrail_chain_pending_actions": {"923", "14783"},
	} {
		var schema string
		if err := fixture.store.db.QueryRow(
			`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		for _, bound := range bounds {
			if !strings.Contains(schema, bound) {
				t.Fatalf("%s schema missing widened bound %s: %s", table, bound, schema)
			}
		}
	}
}

func TestToolChainTwentyOneSlotMigrationRebuildsLegacyDigestCapacity(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	if _, err := fixture.store.db.Exec(`
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
		CREATE TABLE guardrail_chain_events (
			enforcement_join_digests TEXT NOT NULL
				CHECK (length(enforcement_join_digests) <= 879),
			value_join_digests TEXT NOT NULL
				CHECK (length(value_join_digests) <= 14079));
		CREATE TABLE guardrail_chain_pending_actions (
			enforcement_join_digests TEXT NOT NULL
				CHECK (length(enforcement_join_digests) <= 879),
			value_join_digests TEXT NOT NULL
				CHECK (length(value_join_digests) <= 14079));
	`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"guardrail_chain_events", "guardrail_chain_pending_actions",
	} {
		if _, err := fixture.store.db.Exec(
			`INSERT INTO `+table+` VALUES (?, ?)`,
			strings.Repeat("a", 879), strings.Repeat("b", 14079),
		); err != nil {
			t.Fatalf("seed legacy %s: %v", table, err)
		}
	}
	if err := migrateToolChainTwentyOneSlotSQLPersistenceState(fixture.store.db); err != nil {
		t.Fatal(err)
	}
	for table, bounds := range map[string][]string{
		"guardrail_chain_events":          {"923", "14783"},
		"guardrail_chain_pending_actions": {"923", "14783"},
	} {
		var schema string
		if err := fixture.store.db.QueryRow(
			`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		for _, bound := range bounds {
			if !strings.Contains(schema, bound) {
				t.Fatalf("%s was not widened to %s: %s", table, bound, schema)
			}
		}
	}
}

func TestToolChainTwentyOneSlotMigrationResetsEphemeralStateAndPreservesReceipts(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	const session = "slot-21-receipt"
	predecessor := fixture.seed(t, session, correlationDigest("receipt-predecessor"))
	final := fixture.seed(t, session, correlationDigest("receipt-final"))
	final.Projection.ParseStatus = actionfacts.StatusComplete
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainStagedReverseShellPersistence,
	)
	chainFingerprint, err := guardrail.ToolChainFingerprint(
		definition.ID, final.RulesetFingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	actionID := stableToolChainActionID(final, definition.ResultBit)
	receiptID := toolChainReceiptID(
		actionID, definition.ID, string(predecessor.SemanticEventID),
	)
	observed := unixNano(fixture.now)
	if _, err := fixture.store.db.Exec(`INSERT INTO guardrail_chain_deny_receipts (
		receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
		connector_instance_id, session_value_digest, input_fingerprint,
		ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
		detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
		stable_action_id, severity, delivery_count, first_observed_time_unix_nano,
		last_observed_time_unix_nano, expires_time_unix_nano
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		receiptID,
		string(final.SemanticEventID), string(predecessor.SemanticEventID),
		string(final.ConnectorInstanceID), correlationDigest(session),
		final.InputFingerprint, final.RulesetFingerprint, chainFingerprint,
		definition.ID, definition.Version,
		definition.ResultBit, definition.ResultBit, definition.ResultBit,
		actionID, definition.Severity, 1, observed, observed,
		unixNano(fixture.now.Add(time.Hour)),
	); err != nil {
		t.Fatal(err)
	}

	// The migration is deliberately replay-safe: schema rebuilding discards
	// only process-keyed windows and pending proposals, never committed receipts.
	for iteration := 0; iteration < 2; iteration++ {
		if err := migrateToolChainTwentyOneSlotSQLPersistenceState(fixture.store.db); err != nil {
			t.Fatalf("migration iteration %d: %v", iteration, err)
		}
		var gotReceipt, gotAction, gotFingerprint string
		if err := fixture.store.db.QueryRow(`SELECT receipt_id, stable_action_id,
			chain_fingerprint FROM guardrail_chain_deny_receipts WHERE receipt_id=?`,
			receiptID,
		).Scan(&gotReceipt, &gotAction, &gotFingerprint); err != nil {
			t.Fatal(err)
		}
		if gotReceipt != receiptID || gotAction != actionID ||
			gotFingerprint != chainFingerprint {
			t.Fatalf("receipt changed across rebuild: %q/%q/%q",
				gotReceipt, gotAction, gotFingerprint)
		}
		replay, err := fixture.chain.Observe(t.Context(), final)
		if err != nil || replay.Status != ToolChainObserveReplay ||
			replay.DeniedMask != definition.ResultBit ||
			len(replay.ReceiptIDs) != 1 || replay.ReceiptIDs[0] != receiptID {
			t.Fatalf("receipt replay after migration %d=%+v err=%v",
				iteration, replay, err)
		}
	}
}

func TestToolChainTwentyFirstSlotRoundTripsThroughEventAndPendingState(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
	)
	if !ok {
		t.Fatal("missing SQL persistence chain")
	}
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	if index != 20 {
		t.Fatalf("chain index=%d want 20", index)
	}
	const (
		resourceDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		valueDigest    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	eventProjection := guardrail.ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete,
	}
	for slot, candidate := range guardrail.ToolChainDefinitions() {
		eventProjection.DetectionStepMask |= candidate.Step1Bit
		eventProjection.EnforcementJoinDigests[slot] = resourceDigest
	}
	eventProjection.ValueJoinDigests[index][0] = valueDigest
	event := fixture.seed(t, "slot-21-event", correlationDigest("slot-21-event-input"))
	event.Projection = eventProjection
	observed, err := fixture.chain.Observe(t.Context(), event)
	if err != nil || observed.Status != ToolChainObserveFresh {
		t.Fatalf("observe=%+v err=%v", observed, err)
	}
	assertStoredTwentyFirstSlot(
		t,
		fixture.store,
		`SELECT enforcement_join_digests, value_join_digests
		 FROM guardrail_chain_events WHERE semantic_event_id=?`,
		[]any{string(event.SemanticEventID)},
		index,
		resourceDigest,
		valueDigest,
	)
	if replay, err := fixture.chain.Observe(t.Context(), event); err != nil ||
		replay.Status != ToolChainObserveReplay {
		t.Fatalf("event slot-21 replay=%+v err=%v", replay, err)
	}

	fixture.now = fixture.now.Add(1)
	pendingProjection := guardrail.ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete,
	}
	for slot, candidate := range guardrail.ToolChainDefinitions() {
		pendingProjection.DetectionStepMask |= candidate.Step1Bit
		pendingProjection.EnforcementJoinDigests[slot] = resourceDigest
	}
	pendingProjection.DetectionStepMask |= definition.Step2Bit
	pendingProjection.ValueJoinDigests[index][0] = valueDigest
	pending := fixture.seed(t, "slot-21-pending", correlationDigest("slot-21-pending-input"))
	invocation := correlationDigest("slot-21-invocation")
	prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID:  pending.ConnectorInstanceID,
		ToolInvocationDigest: invocation,
		PreSemanticEventID:   pending.SemanticEventID,
		PreInputFingerprint:  pending.InputFingerprint,
		RulesetFingerprint:   pending.RulesetFingerprint,
		Projection:           pendingProjection,
	})
	if err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%+v err=%v", prepared, err)
	}
	assertStoredTwentyFirstSlot(
		t,
		fixture.store,
		`SELECT enforcement_join_digests, value_join_digests
		 FROM guardrail_chain_pending_actions WHERE connector_instance_id=?
		 AND tool_invocation_digest=?`,
		[]any{string(pending.ConnectorInstanceID), invocation},
		index,
		resourceDigest,
		valueDigest,
	)
	if replay, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID:  pending.ConnectorInstanceID,
		ToolInvocationDigest: invocation,
		PreSemanticEventID:   pending.SemanticEventID,
		PreInputFingerprint:  pending.InputFingerprint,
		RulesetFingerprint:   pending.RulesetFingerprint,
		Projection:           pendingProjection,
	}); err != nil || replay.Status != ToolChainPendingReplay {
		t.Fatalf("pending slot-21 replay=%+v err=%v", replay, err)
	}
}

func TestToolChainTwentyOneSlotWorstCaseValueEncodingFitsMigratedCapacity(t *testing.T) {
	var values [guardrail.ToolChainCount]guardrail.ToolChainValueJoinDigests
	for slot := range values {
		for token := range values[slot] {
			values[slot][token] = fmt.Sprintf("%064x", token+1)
		}
	}
	encoded := encodeToolChainValueJoinDigests(values)
	if len(encoded) != 14783 {
		t.Fatalf("worst-case 21-slot value width=%d want 14783", len(encoded))
	}
	decoded, err := decodeToolChainValueJoinDigests(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != values {
		t.Fatal("worst-case 21-slot value encoding did not round trip")
	}
}

func assertStoredTwentyFirstSlot(
	t *testing.T,
	store *Store,
	query string,
	args []any,
	index int,
	wantResource string,
	wantValue string,
) {
	t.Helper()
	var encodedResources, encodedValues string
	if err := store.db.QueryRow(query, args...).Scan(
		&encodedResources, &encodedValues,
	); err != nil {
		t.Fatal(err)
	}
	if len(encodedResources) != 923 {
		t.Fatalf("encoded 21-slot resource width=%d want 923", len(encodedResources))
	}
	if len(encodedValues) > 14783 {
		t.Fatalf("encoded 21-slot value width=%d exceeds 14783", len(encodedValues))
	}
	resources, err := decodeToolChainJoinDigests(encodedResources)
	if err != nil {
		t.Fatal(err)
	}
	values, err := decodeToolChainValueJoinDigests(encodedValues)
	if err != nil {
		t.Fatal(err)
	}
	if resources[index] != wantResource || values[index][0] != wantValue {
		t.Fatalf("round trip resource/value=%q/%q", resources[index], values[index][0])
	}
}
