// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainState adds the bounded, content-free state used by the six
// fixed tool-call chains. Store.applyMigration owns the surrounding
// transaction.
func migrateToolChainState(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS guardrail_chain_partitions (
			connector_instance_id TEXT NOT NULL
				CHECK (length(connector_instance_id) = 36),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND session_value_digest NOT GLOB '*[^0-9a-f]*'),
			active_ruleset_fingerprint TEXT NOT NULL
				CHECK (length(active_ruleset_fingerprint) = 64 AND active_ruleset_fingerprint NOT GLOB '*[^0-9a-f]*'),
			next_sequence INTEGER NOT NULL CHECK (next_sequence >= 1),
			updated_time_unix_nano INTEGER NOT NULL CHECK (updated_time_unix_nano > 0),
			PRIMARY KEY (connector_instance_id, session_value_digest),
			FOREIGN KEY (connector_instance_id)
				REFERENCES correlation_connector_instances(connector_instance_id) ON DELETE RESTRICT
		) WITHOUT ROWID;

		CREATE TABLE IF NOT EXISTS guardrail_chain_events (
			semantic_event_id TEXT PRIMARY KEY CHECK (length(semantic_event_id) = 36),
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND session_value_digest NOT GLOB '*[^0-9a-f]*'),
			sequence INTEGER NOT NULL CHECK (sequence >= 1),
			received_time_unix_nano INTEGER NOT NULL CHECK (received_time_unix_nano > 0),
			input_fingerprint TEXT NOT NULL
				CHECK (length(input_fingerprint) = 64 AND input_fingerprint NOT GLOB '*[^0-9a-f]*'),
			projection_fingerprint TEXT NOT NULL
				CHECK (length(projection_fingerprint) = 64 AND projection_fingerprint NOT GLOB '*[^0-9a-f]*'),
			ruleset_fingerprint TEXT NOT NULL
				CHECK (length(ruleset_fingerprint) = 64 AND ruleset_fingerprint NOT GLOB '*[^0-9a-f]*'),
			parse_status TEXT NOT NULL CHECK (parse_status IN (
				'not_applicable','complete','partial','unsupported','invalid','limit_exceeded','ambiguous')),
			detection_step_mask INTEGER NOT NULL
				CHECK (detection_step_mask BETWEEN 0 AND 4095),
			enforcement_step_mask INTEGER NOT NULL
				CHECK (enforcement_step_mask BETWEEN 0 AND 4095 AND
					(enforcement_step_mask & ~detection_step_mask) = 0),
			detected_chain_mask INTEGER NOT NULL
				CHECK (detected_chain_mask BETWEEN 0 AND 63),
			enforcement_safe_chain_mask INTEGER NOT NULL
				CHECK (enforcement_safe_chain_mask BETWEEN 0 AND 63 AND
					(enforcement_safe_chain_mask & ~detected_chain_mask) = 0),
			denied_chain_mask INTEGER NOT NULL
				CHECK (denied_chain_mask BETWEEN 0 AND 63 AND
					(denied_chain_mask & ~enforcement_safe_chain_mask) = 0),
			stable_action_id TEXT CHECK (
				(denied_chain_mask = 0 AND stable_action_id IS NULL) OR
				(denied_chain_mask <> 0 AND length(stable_action_id) = 68 AND
					substr(stable_action_id, 1, 4) = 'gca_' AND
					substr(stable_action_id, 5) NOT GLOB '*[^0-9a-f]*')),
			UNIQUE (connector_instance_id, session_value_digest, sequence),
			FOREIGN KEY (semantic_event_id)
				REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT,
			FOREIGN KEY (connector_instance_id, session_value_digest)
				REFERENCES guardrail_chain_partitions(connector_instance_id, session_value_digest)
				ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS guardrail_chain_deny_receipts (
			receipt_id TEXT PRIMARY KEY CHECK (
				length(receipt_id) = 68 AND substr(receipt_id, 1, 4) = 'gcr_' AND
				substr(receipt_id, 5) NOT GLOB '*[^0-9a-f]*'),
			final_semantic_event_id TEXT NOT NULL CHECK (length(final_semantic_event_id) = 36),
			predecessor_semantic_event_id TEXT NOT NULL
				CHECK (length(predecessor_semantic_event_id) = 36),
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND session_value_digest NOT GLOB '*[^0-9a-f]*'),
			input_fingerprint TEXT NOT NULL
				CHECK (length(input_fingerprint) = 64 AND input_fingerprint NOT GLOB '*[^0-9a-f]*'),
			ruleset_fingerprint TEXT NOT NULL
				CHECK (length(ruleset_fingerprint) = 64 AND ruleset_fingerprint NOT GLOB '*[^0-9a-f]*'),
			chain_fingerprint TEXT NOT NULL
				CHECK (length(chain_fingerprint) = 64 AND chain_fingerprint NOT GLOB '*[^0-9a-f]*'),
			chain_id TEXT NOT NULL CHECK (chain_id IN (
				'chain.guardrails_off_then_egress',
				'chain.permission_denied_then_runtime_bypass',
				'chain.privilege_discovery_then_elevation',
				'chain.secret_manager_read_then_egress',
				'chain.secret_read_then_egress',
				'chain.workload_identity_then_lateral_execution')),
			chain_version TEXT NOT NULL CHECK (length(chain_version) BETWEEN 1 AND 16),
			detected_chain_mask INTEGER NOT NULL
				CHECK (detected_chain_mask BETWEEN 0 AND 63),
			enforcement_safe_chain_mask INTEGER NOT NULL
				CHECK (enforcement_safe_chain_mask BETWEEN 0 AND 63 AND
					(enforcement_safe_chain_mask & ~detected_chain_mask) = 0),
			denied_chain_mask INTEGER NOT NULL
				CHECK (denied_chain_mask BETWEEN 1 AND 63 AND
					(denied_chain_mask & ~enforcement_safe_chain_mask) = 0),
			stable_action_id TEXT NOT NULL CHECK (
				length(stable_action_id) = 68 AND substr(stable_action_id, 1, 4) = 'gca_' AND
				substr(stable_action_id, 5) NOT GLOB '*[^0-9a-f]*'),
			severity TEXT NOT NULL CHECK (severity = 'HIGH'),
			delivery_count INTEGER NOT NULL CHECK (delivery_count >= 1),
			first_observed_time_unix_nano INTEGER NOT NULL
				CHECK (first_observed_time_unix_nano > 0),
			last_observed_time_unix_nano INTEGER NOT NULL
				CHECK (last_observed_time_unix_nano >= first_observed_time_unix_nano),
			expires_time_unix_nano INTEGER NOT NULL
				CHECK (expires_time_unix_nano >= last_observed_time_unix_nano),
			evaluation_id TEXT CHECK (
				evaluation_id IS NULL OR length(evaluation_id) BETWEEN 1 AND 512),
			audit_event_id TEXT CHECK (
				audit_event_id IS NULL OR length(audit_event_id) BETWEEN 1 AND 512),
			UNIQUE (final_semantic_event_id, input_fingerprint, chain_id)
		);

		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_partitions_lru
			ON guardrail_chain_partitions(updated_time_unix_nano,
				connector_instance_id, session_value_digest);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_events_window
			ON guardrail_chain_events(connector_instance_id, session_value_digest,
				ruleset_fingerprint, sequence);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_events_received
			ON guardrail_chain_events(received_time_unix_nano, semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_receipts_replay
			ON guardrail_chain_deny_receipts(final_semantic_event_id, input_fingerprint,
				expires_time_unix_nano, chain_id);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_receipts_expiry
			ON guardrail_chain_deny_receipts(expires_time_unix_nano, receipt_id);
	`)
	if err != nil {
		return fmt.Errorf("create bounded guardrail chain state: %w", err)
	}
	return nil
}
