// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainTwentySixSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 52
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-six for exact file-email lineage" {
		t.Fatal("twenty-six-slot file-email state is not append-only migration 53")
	}
	definitions := guardrail.ToolChainDefinitions()
	if len(definitions) != 26 ||
		definitions[25].ID != guardrail.ToolChainFileReadThenEmailSameArtifact ||
		definitions[25].ResultBit != uint32(1<<25) ||
		definitions[25].Step1Bit != uint64(1<<59) ||
		definitions[25].Step2Bit != uint64(1<<60) {
		t.Fatalf("slot twenty-six is not append-only: %+v", definitions)
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
}

func TestToolChainTwentySixSlotMigrationReplaysWithoutLosingAuxiliaryState(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	if _, err := fixture.store.db.Exec(`INSERT INTO guardrail_chain_cutoff_barriers (
		barrier_kind, cutoff_received_time_unix_nano, applied_time_unix_nano,
		expires_time_unix_nano
	) VALUES ('pending_boundary', 1, 1, 2)`); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if err := migrateToolChainTwentySixSlotFileEmailState(fixture.store.db); err != nil {
			t.Fatalf("migration replay %d: %v", iteration, err)
		}
		var barriers int
		if err := fixture.store.db.QueryRow(
			`SELECT COUNT(*) FROM guardrail_chain_cutoff_barriers`,
		).Scan(&barriers); err != nil || barriers != 1 {
			t.Fatalf("barriers after replay %d=%d err=%v", iteration, barriers, err)
		}
	}
}
