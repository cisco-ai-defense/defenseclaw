// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainTwentyFiveSlotSQLiteReadDeleteState widens fixed digest
// encodings for slot twenty-five and admits the policy-gated SQLite
// read-to-delete chain to durable receipts. Pending actions and event windows
// contain process-private lineage and are intentionally reset; durable deny
// receipts and replay cutoffs are preserved.
func migrateToolChainTwentyFiveSlotSQLiteReadDeleteState(ex dbExecer) error {
	if _, err := ex.Exec(`ALTER TABLE guardrail_chain_deny_receipts
		RENAME TO guardrail_chain_deny_receipts_pre_twenty_five`); err != nil {
		return fmt.Errorf("stage pre-twenty-five-slot deny receipts: %w", err)
	}
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-twenty-five-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-five-slot guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild twenty-five-slot pending chain state: %w", err)
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
		FROM guardrail_chain_deny_receipts_pre_twenty_five;
		DROP TABLE guardrail_chain_deny_receipts_pre_twenty_five;
	`); err != nil {
		return fmt.Errorf("restore pre-twenty-five-slot deny receipts: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("index twenty-five-slot guardrail chain state: %w", err)
	}
	return nil
}
