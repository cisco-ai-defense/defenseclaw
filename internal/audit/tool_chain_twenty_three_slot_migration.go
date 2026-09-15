// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainTwentyThreeSlotADCSState widens the fixed digest encodings
// for slot twenty-three and admits the enforcement-capable AD CS chain to the
// durable receipt catalog. Process-keyed pending actions, event windows, and
// partitions are ephemeral and intentionally reset. Durable deny receipts and
// replay cutoffs are preserved.
func migrateToolChainTwentyThreeSlotADCSState(ex dbExecer) error {
	if _, err := ex.Exec(`ALTER TABLE guardrail_chain_deny_receipts
		RENAME TO guardrail_chain_deny_receipts_pre_twenty_three`); err != nil {
		return fmt.Errorf("stage pre-twenty-three-slot deny receipts: %w", err)
	}
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-twenty-three-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-three-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-three-slot pending chain state: %w", err)
	}
	if err := migrateToolChainSQLValueSourceState(ex); err != nil {
		return fmt.Errorf("restore pending SQL value-source state: %w", err)
	}
	if err := migrateToolChainReturnedCredentialSourceState(ex); err != nil {
		return fmt.Errorf("restore pending credential-source state: %w", err)
	}
	if _, err := ex.Exec(`
		INSERT INTO guardrail_chain_deny_receipts (
			receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
			connector_instance_id, session_value_digest, input_fingerprint,
			ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
			detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
			stable_action_id, severity, delivery_count,
			first_observed_time_unix_nano, last_observed_time_unix_nano,
			expires_time_unix_nano, evaluation_id, audit_event_id
		) SELECT receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
			connector_instance_id, session_value_digest, input_fingerprint,
			ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
			detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
			stable_action_id, severity, delivery_count,
			first_observed_time_unix_nano, last_observed_time_unix_nano,
			expires_time_unix_nano, evaluation_id, audit_event_id
		FROM guardrail_chain_deny_receipts_pre_twenty_three;
		DROP TABLE guardrail_chain_deny_receipts_pre_twenty_three;
	`); err != nil {
		return fmt.Errorf("restore pre-twenty-three-slot deny receipts: %w", err)
	}
	// The staged receipt table retained the old index names until it was
	// dropped. Replay the idempotent creators to index the replacement table.
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("index twenty-three-slot guardrail chain state: %w", err)
	}
	return nil
}
