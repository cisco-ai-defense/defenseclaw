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

func TestToolChainTwentyFourSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 50
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-four for S4U ticket secretsdump" {
		t.Fatal("twenty-four-slot S4U state is not append-only migration 51")
	}
	fixture := newToolChainFixture(t, ":memory:")
	for table, bounds := range map[string][]string{
		"guardrail_chain_events":          {"1055", "16895"},
		"guardrail_chain_pending_actions": {"1055", "16895"},
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
	var receiptSchema string
	if err := fixture.store.db.QueryRow(`SELECT sql FROM sqlite_master
		WHERE type='table' AND name='guardrail_chain_deny_receipts'`).Scan(
		&receiptSchema,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		receiptSchema,
		"chain.s4u_ticket_then_kerberos_secretsdump_same_cache",
	) {
		t.Fatal("deny-receipt schema does not admit the S4U ticket chain")
	}
}

func TestToolChainTwentyFourSlotMigrationPreservesDurableStateOnReplay(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	const session = "slot-24-migration"
	predecessor := fixture.seed(t, session, correlationDigest("slot-24-predecessor"))
	predecessor.Projection = guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: guardrail.ToolChainDefinitions()[0].Step1Bit,
	}
	if observed, err := fixture.chain.Observe(t.Context(), predecessor); err != nil ||
		observed.Status != ToolChainObserveFresh {
		t.Fatalf("seed event=%+v err=%v", observed, err)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	pendingEvent := fixture.seed(t, session, correlationDigest("slot-24-pending"))
	if prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID:  pendingEvent.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("slot-24-invocation"),
		PreSemanticEventID:   pendingEvent.SemanticEventID,
		PreInputFingerprint:  pendingEvent.InputFingerprint,
		RulesetFingerprint:   pendingEvent.RulesetFingerprint,
		Projection: guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: guardrail.ToolChainDefinitions()[0].Step1Bit,
		},
	}); err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("seed pending=%+v err=%v", prepared, err)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	final := fixture.seed(t, session, correlationDigest("slot-24-final"))
	final.Projection.ParseStatus = actionfacts.StatusComplete
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainS4UTicketThenKerberosSecretsdump,
	)
	if !ok {
		t.Fatal("missing durable receipt fixture chain")
	}
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
	observedAt := unixNano(fixture.now)
	if _, err := fixture.store.db.Exec(`INSERT INTO guardrail_chain_deny_receipts (
		receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
		connector_instance_id, session_value_digest, input_fingerprint,
		ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
		detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
		stable_action_id, severity, delivery_count, first_observed_time_unix_nano,
		last_observed_time_unix_nano, expires_time_unix_nano
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		receiptID, string(final.SemanticEventID), string(predecessor.SemanticEventID),
		string(final.ConnectorInstanceID), correlationDigest(session),
		final.InputFingerprint, final.RulesetFingerprint, chainFingerprint,
		definition.ID, definition.Version, definition.ResultBit, definition.ResultBit,
		definition.ResultBit, actionID, definition.Severity, 1, observedAt, observedAt,
		unixNano(fixture.now.Add(time.Hour)),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`INSERT INTO guardrail_chain_cutoff_barriers (
		barrier_kind, cutoff_received_time_unix_nano, applied_time_unix_nano,
		expires_time_unix_nano
	) VALUES ('pending_boundary', ?, ?, ?),
		('terminal_reset', ?, ?, ?)`,
		observedAt, observedAt, unixNano(fixture.now.Add(time.Hour)),
		observedAt, observedAt, unixNano(fixture.now.Add(time.Hour)),
	); err != nil {
		t.Fatal(err)
	}

	for iteration := 0; iteration < 2; iteration++ {
		if err := migrateToolChainTwentyFourSlotS4UState(fixture.store.db); err != nil {
			t.Fatalf("migration replay %d: %v", iteration, err)
		}
		for _, table := range []string{
			"guardrail_chain_pending_actions",
			"guardrail_chain_events",
			"guardrail_chain_partitions",
		} {
			var count int
			if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("migration retained %d ephemeral rows in %s", count, table)
			}
		}
		var receiptCount, barrierCount int
		if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
			FROM guardrail_chain_deny_receipts WHERE receipt_id=?`, receiptID,
		).Scan(&receiptCount); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
			FROM guardrail_chain_cutoff_barriers WHERE barrier_kind IN (
				'pending_boundary', 'terminal_reset')`,
		).Scan(&barrierCount); err != nil {
			t.Fatal(err)
		}
		if receiptCount != 1 || barrierCount != 2 {
			t.Fatalf("durable receipt/barrier counts=%d/%d want 1/2", receiptCount, barrierCount)
		}
		replay, err := fixture.chain.Observe(t.Context(), final)
		if err != nil || replay.Status != ToolChainObserveReplay ||
			replay.DeniedMask != definition.ResultBit ||
			len(replay.ReceiptIDs) != 1 || replay.ReceiptIDs[0] != receiptID {
			t.Fatalf("receipt replay after migration %d=%+v err=%v",
				iteration, replay, err)
		}
		for _, column := range []string{
			"sql_value_source_table_class",
			"sql_value_source_resource_digest",
			"returned_credential_source",
		} {
			exists, err := hasColumnDB(fixture.store.db, "guardrail_chain_pending_actions", column)
			if err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Fatalf("rebuilt pending state is missing %s", column)
			}
		}
	}
}

func TestToolChainTwentyFourthSlotRoundTripsAtMaximumCapacity(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var resources [guardrail.ToolChainCount]string
	var values [guardrail.ToolChainCount]guardrail.ToolChainValueJoinDigests
	for slot := range resources {
		resources[slot] = digest
		for value := range values[slot] {
			values[slot][value] = fmt.Sprintf("%064x", value+1)
		}
	}
	encodedResources := encodeToolChainJoinDigests(resources)
	encodedValues := encodeToolChainValueJoinDigests(values)
	if len(encodedResources) != 1055 || len(encodedValues) != 16895 {
		t.Fatalf("maximum encoded widths=%d/%d want 1055/16895",
			len(encodedResources), len(encodedValues))
	}
	decodedResources, err := decodeToolChainJoinDigests(encodedResources)
	if err != nil {
		t.Fatal(err)
	}
	decodedValues, err := decodeToolChainValueJoinDigests(encodedValues)
	if err != nil {
		t.Fatal(err)
	}
	if decodedResources != resources || decodedValues != values {
		t.Fatal("twenty-four-slot maximum-capacity encoding did not round trip")
	}
}
