// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainLineageState adds opaque per-chain resource identities. Old
// chain state is intentionally discarded: its projection fingerprint predates
// lineage and therefore cannot safely participate in an enforcement proof.
func migrateToolChainLineageState(ex dbExecer) error {
	for _, alteration := range []struct {
		table string
		query string
	}{
		{
			table: "guardrail_chain_events",
			query: `ALTER TABLE guardrail_chain_events
				ADD COLUMN enforcement_join_digests TEXT NOT NULL DEFAULT ''
				CHECK (length(enforcement_join_digests) <= 389)`,
		},
		{
			table: "guardrail_chain_pending_actions",
			query: `ALTER TABLE guardrail_chain_pending_actions
				ADD COLUMN enforcement_join_digests TEXT NOT NULL DEFAULT ''
				CHECK (length(enforcement_join_digests) <= 389)`,
		},
	} {
		exists, err := hasColumnDB(ex, alteration.table, "enforcement_join_digests")
		if err != nil {
			return err
		}
		if !exists {
			if _, err := ex.Exec(alteration.query); err != nil {
				return fmt.Errorf("add %s enforcement lineage: %w", alteration.table, err)
			}
		}
	}
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
	`); err != nil {
		return fmt.Errorf("reset pre-lineage guardrail chain state: %w", err)
	}
	return nil
}

// migrateToolChainDerivedLineageState adds the second opaque identity needed
// by a three-step transform proof. Pre-migration state cannot participate
// because its projection fingerprints did not bind the derived output join.
func migrateToolChainDerivedLineageState(ex dbExecer) error {
	for _, alteration := range []struct {
		table string
		query string
	}{
		{
			table: "guardrail_chain_events",
			query: `ALTER TABLE guardrail_chain_events
				ADD COLUMN enforcement_output_join_digests TEXT NOT NULL DEFAULT ''
				CHECK (length(enforcement_output_join_digests) <= 454)`,
		},
		{
			table: "guardrail_chain_pending_actions",
			query: `ALTER TABLE guardrail_chain_pending_actions
				ADD COLUMN enforcement_output_join_digests TEXT NOT NULL DEFAULT ''
				CHECK (length(enforcement_output_join_digests) <= 454)`,
		},
	} {
		exists, err := hasColumnDB(ex, alteration.table, "enforcement_output_join_digests")
		if err != nil {
			return err
		}
		if !exists {
			if _, err := ex.Exec(alteration.query); err != nil {
				return fmt.Errorf("add %s derived enforcement lineage: %w", alteration.table, err)
			}
		}
	}
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-derived-lineage guardrail chain state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild derived-lineage guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild derived-lineage pending chain state: %w", err)
	}
	return nil
}

// migrateToolChainExpandedCatalogState rebuilds only ephemeral bounded-chain
// state so persisted masks and digest arrays can represent nine chain slots.
// Existing rows use the pre-expansion fingerprint and cannot safely be joined
// with the expanded catalog.
func migrateToolChainExpandedCatalogState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-nine-slot guardrail state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild nine-slot guardrail state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild nine-slot pending state: %w", err)
	}
	return nil
}

// migrateToolChainTenSlotCatalogState rebuilds only ephemeral bounded-chain
// state so masks and digest arrays can represent the appended firewall trust
// chain while preserving bit 19 as the deployed mutation-barrier ABI.
func migrateToolChainTenSlotCatalogState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-ten-slot guardrail state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild ten-slot guardrail state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild ten-slot pending state: %w", err)
	}
	return nil
}

// migrateToolChainElevenSlotCatalogState rebuilds only ephemeral bounded-chain
// state so masks and digest arrays can represent the appended SQL Server proof.
// No raw SQL or connection identity is migrated or retained.
func migrateToolChainElevenSlotCatalogState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-eleven-slot guardrail state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild eleven-slot guardrail state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild eleven-slot pending state: %w", err)
	}
	return nil
}

// migrateToolChainTwelveSlotCatalogState rebuilds only ephemeral bounded-chain
// state so masks and digest arrays can represent the success-gated Kubernetes
// write/apply/exec proof. No manifest, command, path, namespace, or pod value is
// migrated or retained.
func migrateToolChainTwelveSlotCatalogState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-twelve-slot guardrail state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild twelve-slot guardrail state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild twelve-slot pending state: %w", err)
	}
	return nil
}

// migrateToolChainThirteenSlotCatalogState rebuilds only ephemeral bounded-
// chain state for the appended success-gated wireless BSSID proof. No BSSID,
// filter, output path, interface, client, count, or command value is migrated.
func migrateToolChainThirteenSlotCatalogState(ex dbExecer) error {
	if _, err := ex.Exec(`
		DELETE FROM guardrail_chain_deny_receipts;
		DELETE FROM guardrail_chain_pending_actions;
		DELETE FROM guardrail_chain_events;
		DELETE FROM guardrail_chain_partitions;
		DROP TABLE guardrail_chain_deny_receipts;
		DROP TABLE guardrail_chain_pending_actions;
		DROP TABLE guardrail_chain_events;
	`); err != nil {
		return fmt.Errorf("reset pre-thirteen-slot guardrail state: %w", err)
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("rebuild thirteen-slot guardrail state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("rebuild thirteen-slot pending state: %w", err)
	}
	return nil
}

// migrateToolChainFourteenSlotWideMaskState rebuilds only the three tables
// whose CHECK constraints encode chain and step-mask bounds. Unlike earlier
// catalog expansions, it copies all ephemeral rows so pre-widening projections
// remain replayable while reserving result slots fourteen through seventeen.
// Legacy 13-slot lineage strings and projection fingerprints are accepted by
// the widened readers; a runtime ruleset change still rolls a partition through
// the existing fail-safe path.
func migrateToolChainFourteenSlotWideMaskState(ex dbExecer) error {
	return migrateToolChainWideMaskState(ex)
}

// migrateToolChainEighteenSlotWideMaskState reuses the lossless wide table
// rebuild for the appended staged-payload persistence slot. Databases that
// already applied migration 42 therefore receive the widened mask, digest, ID,
// and severity constraints without discarding live bounded-chain state.
func migrateToolChainEighteenSlotWideMaskState(ex dbExecer) error {
	return migrateToolChainWideMaskState(ex)
}

func migrateToolChainWideMaskState(ex dbExecer) error {
	for _, statement := range []string{
		`ALTER TABLE guardrail_chain_deny_receipts
			RENAME TO guardrail_chain_deny_receipts_pre_widen`,
		`ALTER TABLE guardrail_chain_pending_actions
			RENAME TO guardrail_chain_pending_actions_pre_widen`,
		`ALTER TABLE guardrail_chain_events
			RENAME TO guardrail_chain_events_pre_widen`,
	} {
		if _, err := ex.Exec(statement); err != nil {
			return fmt.Errorf("stage pre-widening guardrail chain state: %w", err)
		}
	}
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("create widened guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("create widened pending chain state: %w", err)
	}
	for _, statement := range []string{
		`INSERT INTO guardrail_chain_events (
			semantic_event_id, connector_instance_id, session_value_digest, sequence,
			received_time_unix_nano, input_fingerprint, projection_fingerprint,
			ruleset_fingerprint, parse_status, detection_step_mask,
			enforcement_step_mask, enforcement_join_digests,
			enforcement_output_join_digests, detected_chain_mask,
			enforcement_safe_chain_mask, denied_chain_mask, stable_action_id
		) SELECT semantic_event_id, connector_instance_id, session_value_digest,
			sequence, received_time_unix_nano, input_fingerprint,
			projection_fingerprint, ruleset_fingerprint, parse_status,
			detection_step_mask, enforcement_step_mask, enforcement_join_digests,
			enforcement_output_join_digests, detected_chain_mask,
			enforcement_safe_chain_mask, denied_chain_mask, stable_action_id
		FROM guardrail_chain_events_pre_widen`,
		`INSERT INTO guardrail_chain_pending_actions (
			connector_instance_id, tool_invocation_digest, session_value_digest,
			pre_semantic_event_id, pre_input_fingerprint, projection_fingerprint,
			ruleset_fingerprint, parse_status, detection_step_mask,
			enforcement_step_mask, enforcement_join_digests,
			enforcement_output_join_digests, prepared_time_unix_nano,
			expires_time_unix_nano
		) SELECT connector_instance_id, tool_invocation_digest,
			session_value_digest, pre_semantic_event_id, pre_input_fingerprint,
			projection_fingerprint, ruleset_fingerprint, parse_status,
			detection_step_mask, enforcement_step_mask, enforcement_join_digests,
			enforcement_output_join_digests, prepared_time_unix_nano,
			expires_time_unix_nano
		FROM guardrail_chain_pending_actions_pre_widen`,
		`INSERT INTO guardrail_chain_deny_receipts (
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
		FROM guardrail_chain_deny_receipts_pre_widen`,
		`DROP TABLE guardrail_chain_deny_receipts_pre_widen`,
		`DROP TABLE guardrail_chain_pending_actions_pre_widen`,
		`DROP TABLE guardrail_chain_events_pre_widen`,
	} {
		if _, err := ex.Exec(statement); err != nil {
			return fmt.Errorf("copy pre-widening guardrail chain state: %w", err)
		}
	}
	// The old index names remain occupied until the staged tables are dropped.
	// Replaying the idempotent creators now installs them on the widened tables.
	if err := migrateToolChainState(ex); err != nil {
		return fmt.Errorf("index widened guardrail chain state: %w", err)
	}
	if err := migrateToolChainPendingState(ex); err != nil {
		return fmt.Errorf("index widened pending chain state: %w", err)
	}
	return nil
}
