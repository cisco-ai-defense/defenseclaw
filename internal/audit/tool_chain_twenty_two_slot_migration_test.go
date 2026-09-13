// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
)

func TestToolChainTwentyTwoSlotMigrationIsAppendOnlyAndSized(t *testing.T) {
	const migrationIndex = 47
	if len(migrations) <= migrationIndex || migrations[migrationIndex].description !=
		"guardrails: add result slot twenty-two for compromised credential authentication" {
		t.Fatal("twenty-two-slot credential authentication state is not append-only migration 48")
	}
	fixture := newToolChainFixture(t, ":memory:")
	for table, bounds := range map[string][]string{
		"guardrail_chain_events":          {"1099", "17599"},
		"guardrail_chain_pending_actions": {"1099", "17599"},
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
