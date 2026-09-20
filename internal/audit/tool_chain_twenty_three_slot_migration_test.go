// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainTwentyThreeSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 49
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-three for AD CS certificate impersonation" {
		t.Fatal("twenty-three-slot AD CS state is not append-only migration 50")
	}
	fixture := newToolChainFixture(t, ":memory:")
	for table, bounds := range map[string][]string{
		"guardrail_chain_events":          {"1143", "18303"},
		"guardrail_chain_pending_actions": {"1143", "18303"},
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
		"chain.adcs_certificate_request_then_pfx_authentication",
	) {
		t.Fatal("deny-receipt schema does not admit the AD CS chain")
	}
}

func TestToolChainTwentyThreeSlotMigrationResetsOnlyEphemeralState(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	const session = "slot-23-migration"
	predecessor := fixture.seed(t, session, correlationDigest("slot-23-predecessor"))
	predecessor.Projection = guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: guardrail.ToolChainDefinitions()[0].Step1Bit,
	}
	if observed, err := fixture.chain.Observe(t.Context(), predecessor); err != nil ||
		observed.Status != ToolChainObserveFresh {
		t.Fatalf("seed event=%+v err=%v", observed, err)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	pendingEvent := fixture.seed(t, session, correlationDigest("slot-23-pending"))
	if prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID:  pendingEvent.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("slot-23-invocation"),
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
	final := fixture.seed(t, session, correlationDigest("slot-23-final"))
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainStagedReverseShellPersistence,
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
	) VALUES ('pending_boundary', ?, ?, ?)`,
		observedAt, observedAt, unixNano(fixture.now.Add(time.Hour)),
	); err != nil {
		t.Fatal(err)
	}

	for iteration := 0; iteration < 2; iteration++ {
		if err := migrateToolChainTwentyThreeSlotADCSState(fixture.store.db); err != nil {
			t.Fatalf("migration iteration %d: %v", iteration, err)
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
			FROM guardrail_chain_cutoff_barriers WHERE barrier_kind='pending_boundary'`,
		).Scan(&barrierCount); err != nil {
			t.Fatal(err)
		}
		if receiptCount != 1 || barrierCount != 1 {
			t.Fatalf("durable receipt/barrier counts=%d/%d want 1/1", receiptCount, barrierCount)
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
