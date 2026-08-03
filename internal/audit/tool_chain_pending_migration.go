// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainPendingState adds bounded, content-free state for tool calls
// whose predecessor projection must not become visible until a successful
// terminal hook. Store.applyMigration owns the surrounding transaction.
func migrateToolChainPendingState(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS guardrail_chain_pending_actions (
			connector_instance_id TEXT NOT NULL
				CHECK (length(connector_instance_id) = 36),
			tool_invocation_digest TEXT NOT NULL
				CHECK (length(tool_invocation_digest) = 64 AND
					tool_invocation_digest NOT GLOB '*[^0-9a-f]*'),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND
					session_value_digest NOT GLOB '*[^0-9a-f]*'),
			pre_semantic_event_id TEXT NOT NULL
				CHECK (length(pre_semantic_event_id) = 36),
			pre_input_fingerprint TEXT NOT NULL
				CHECK (length(pre_input_fingerprint) = 64 AND
					pre_input_fingerprint NOT GLOB '*[^0-9a-f]*'),
			projection_fingerprint TEXT NOT NULL
				CHECK (length(projection_fingerprint) = 64 AND
					projection_fingerprint NOT GLOB '*[^0-9a-f]*'),
			ruleset_fingerprint TEXT NOT NULL
				CHECK (length(ruleset_fingerprint) = 64 AND
					ruleset_fingerprint NOT GLOB '*[^0-9a-f]*'),
			parse_status TEXT NOT NULL CHECK (parse_status IN (
				'not_applicable','complete','partial','unsupported','invalid',
				'limit_exceeded','ambiguous')),
			-- Zero is an invocation-only marker; 1365 (0x555) is the
			-- immutable mask of the six step-one bits.
			detection_step_mask INTEGER NOT NULL
				CHECK (detection_step_mask BETWEEN 0 AND 1365 AND
					(detection_step_mask & ~1365) = 0),
			enforcement_step_mask INTEGER NOT NULL
				CHECK (enforcement_step_mask BETWEEN 0 AND 1365 AND
					(enforcement_step_mask & ~detection_step_mask) = 0),
			prepared_time_unix_nano INTEGER NOT NULL
				CHECK (prepared_time_unix_nano > 0),
			expires_time_unix_nano INTEGER NOT NULL
				CHECK (expires_time_unix_nano > prepared_time_unix_nano),
			PRIMARY KEY (connector_instance_id, session_value_digest,
				tool_invocation_digest),
			FOREIGN KEY (connector_instance_id)
				REFERENCES correlation_connector_instances(connector_instance_id)
				ON DELETE CASCADE,
			FOREIGN KEY (pre_semantic_event_id)
				REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE
		) WITHOUT ROWID;

		-- A turn boundary discards only unconfirmed proposals. Retaining its
		-- content-free cutoff prevents transport replay from re-arming a
		-- proposal whose original event belongs to the completed turn.
		CREATE TABLE IF NOT EXISTS guardrail_chain_pending_boundaries (
			connector_instance_id TEXT NOT NULL
				CHECK (length(connector_instance_id) = 36),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND
					session_value_digest NOT GLOB '*[^0-9a-f]*'),
			boundary_semantic_event_id TEXT NOT NULL
				CHECK (length(boundary_semantic_event_id) = 36),
			boundary_input_fingerprint TEXT NOT NULL
				CHECK (length(boundary_input_fingerprint) = 64 AND
					boundary_input_fingerprint NOT GLOB '*[^0-9a-f]*'),
			cutoff_received_time_unix_nano INTEGER NOT NULL
				CHECK (cutoff_received_time_unix_nano > 0),
			discard_time_unix_nano INTEGER NOT NULL
				CHECK (discard_time_unix_nano > 0),
			expires_time_unix_nano INTEGER NOT NULL
				CHECK (expires_time_unix_nano > discard_time_unix_nano),
			PRIMARY KEY (connector_instance_id, session_value_digest),
			FOREIGN KEY (connector_instance_id)
				REFERENCES correlation_connector_instances(connector_instance_id)
				ON DELETE CASCADE,
			FOREIGN KEY (boundary_semantic_event_id)
				REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE
		) WITHOUT ROWID;

		-- An authenticated session terminal is a causal cutoff, not merely a
		-- deletion request. Retaining its content-free identity prevents a
		-- replayed pre-terminal event from re-arming chain state after reset.
		CREATE TABLE IF NOT EXISTS guardrail_chain_terminal_resets (
			connector_instance_id TEXT NOT NULL
				CHECK (length(connector_instance_id) = 36),
			session_value_digest TEXT NOT NULL
				CHECK (length(session_value_digest) = 64 AND
					session_value_digest NOT GLOB '*[^0-9a-f]*'),
			terminal_semantic_event_id TEXT NOT NULL
				CHECK (length(terminal_semantic_event_id) = 36),
			terminal_input_fingerprint TEXT NOT NULL
				CHECK (length(terminal_input_fingerprint) = 64 AND
					terminal_input_fingerprint NOT GLOB '*[^0-9a-f]*'),
			cutoff_received_time_unix_nano INTEGER NOT NULL
				CHECK (cutoff_received_time_unix_nano > 0),
			reset_time_unix_nano INTEGER NOT NULL
				CHECK (reset_time_unix_nano > 0),
			expires_time_unix_nano INTEGER NOT NULL
				CHECK (expires_time_unix_nano > reset_time_unix_nano),
			PRIMARY KEY (connector_instance_id, session_value_digest),
			FOREIGN KEY (connector_instance_id)
				REFERENCES correlation_connector_instances(connector_instance_id)
				ON DELETE CASCADE,
			FOREIGN KEY (terminal_semantic_event_id)
				REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE
		) WITHOUT ROWID;

		-- Saturating either exact-session cutoff catalog must not make its
		-- oldest live cutoff replayable. A fixed two-row barrier lets the
		-- repository summarize evicted exact cutoffs without retaining their
		-- identifiers or growing storage. Events after the barrier stay eligible.
		CREATE TABLE IF NOT EXISTS guardrail_chain_cutoff_barriers (
			barrier_kind TEXT PRIMARY KEY CHECK (barrier_kind IN (
				'pending_boundary','terminal_reset')),
			cutoff_received_time_unix_nano INTEGER NOT NULL
				CHECK (cutoff_received_time_unix_nano > 0),
			applied_time_unix_nano INTEGER NOT NULL
				CHECK (applied_time_unix_nano > 0),
			expires_time_unix_nano INTEGER NOT NULL
				CHECK (expires_time_unix_nano > applied_time_unix_nano)
		) WITHOUT ROWID;

		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_pending_expiry
			ON guardrail_chain_pending_actions(expires_time_unix_nano,
				connector_instance_id, session_value_digest,
				tool_invocation_digest);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_pending_pre_event
			ON guardrail_chain_pending_actions(pre_semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_pending_boundaries_expiry
			ON guardrail_chain_pending_boundaries(expires_time_unix_nano,
				connector_instance_id, session_value_digest);
		CREATE INDEX IF NOT EXISTS idx_guardrail_chain_terminal_resets_expiry
			ON guardrail_chain_terminal_resets(expires_time_unix_nano,
				connector_instance_id, session_value_digest);
	`)
	if err != nil {
		return fmt.Errorf("create pending guardrail chain state: %w", err)
	}
	return nil
}
