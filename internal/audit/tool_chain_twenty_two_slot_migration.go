// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainTwentyTwoSlotCredentialAuthenticationState widens the fixed
// digest encodings for slot twenty-two. Pending actions and event windows are
// process-keyed, ephemeral state and are intentionally reset. Detection-only
// credential-authentication lineage cannot create a deny receipt.
func migrateToolChainTwentyTwoSlotCredentialAuthenticationState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-twenty-two-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-two-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-two-slot pending chain state: %w", err)
	}
	if err := migrateToolChainSQLValueSourceState(ex); err != nil {
		return fmt.Errorf("restore pending SQL value-source state: %w", err)
	}
	return nil
}
