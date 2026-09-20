// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainTwentyOneSlotSQLPersistenceState widens the fixed digest
// encodings for slot twenty-one. Pending actions and event windows are
// ephemeral and intentionally reset: their old CHECK constraints cannot store
// the appended slot, their projection fingerprints use the old width, and
// process-keyed value HMACs cannot survive restart. Committed deny receipts are
// preserved; the new chain is detection-only and can never create one.
func migrateToolChainTwentyOneSlotSQLPersistenceState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-twenty-one-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-one-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-one-slot pending chain state: %w", err)
	}
	if err := migrateToolChainSQLValueSourceState(ex); err != nil {
		return fmt.Errorf("restore pending SQL value-source state: %w", err)
	}
	return nil
}
