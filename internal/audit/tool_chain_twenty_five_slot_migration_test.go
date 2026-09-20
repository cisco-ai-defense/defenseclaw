// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainTwentyFiveSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 51
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-five for policy-gated SQLite read-delete" {
		t.Fatal("twenty-five-slot SQLite state is not append-only migration 52")
	}
	definitions := guardrail.ToolChainDefinitions()
	if len(definitions) < 25 ||
		definitions[24].ID != guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete ||
		definitions[24].ResultBit != uint32(1<<24) ||
		definitions[24].Step1Bit != uint64(1<<57) ||
		definitions[24].Step2Bit != uint64(1<<58) {
		t.Fatalf("slot twenty-five is not append-only: %+v", definitions)
	}

	fixture := newToolChainFixture(t, ":memory:")
	for table := range map[string]struct{}{
		"guardrail_chain_events":          {},
		"guardrail_chain_pending_actions": {},
	} {
		var schema string
		if err := fixture.store.db.QueryRow(
			`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		for _, bound := range []string{"1143", "18303"} {
			if !strings.Contains(schema, bound) {
				t.Fatalf("%s schema missing bound %s: %s", table, bound, schema)
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
		guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
	) {
		t.Fatal("deny-receipt schema does not admit the SQLite read-delete chain")
	}
}

func TestToolChainTwentyFiveSlotMigrationReplaysWithoutLosingAuxiliaryState(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	if _, err := fixture.store.db.Exec(`INSERT INTO guardrail_chain_cutoff_barriers (
		barrier_kind, cutoff_received_time_unix_nano, applied_time_unix_nano,
		expires_time_unix_nano
	) VALUES ('pending_boundary', 1, 1, 2)`); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if err := migrateToolChainTwentyFiveSlotSQLiteReadDeleteState(
			fixture.store.db,
		); err != nil {
			t.Fatalf("migration replay %d: %v", iteration, err)
		}
		var barriers int
		if err := fixture.store.db.QueryRow(
			`SELECT COUNT(*) FROM guardrail_chain_cutoff_barriers`,
		).Scan(&barriers); err != nil || barriers != 1 {
			t.Fatalf("barriers after replay %d=%d err=%v", iteration, barriers, err)
		}
		for _, column := range []string{
			"sql_value_source_table_class",
			"sql_value_source_resource_digest",
			"returned_credential_source",
		} {
			exists, err := hasColumnDB(
				fixture.store.db, "guardrail_chain_pending_actions", column,
			)
			if err != nil || !exists {
				t.Fatalf("pending column %s after replay exists=%t err=%v",
					column, exists, err)
			}
		}
	}
}
