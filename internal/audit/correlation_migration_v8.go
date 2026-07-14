// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateCorrelationStateV8 adds the focused correlation ledger to the
// existing audit database. The migration is deliberately additive: it creates
// only new tables and indexes and never reads, copies, rewrites, or deletes an
// audit_events row. Store.applyMigration owns the surrounding transaction, so
// all correlation tables and the schema-version record become visible atomically.
func migrateCorrelationStateV8(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS correlation_connector_instances (
			connector_instance_id TEXT PRIMARY KEY CHECK (length(connector_instance_id) = 36),
			connector TEXT NOT NULL CHECK (length(connector) BETWEEN 1 AND 64),
			export_custody TEXT NOT NULL CHECK (export_custody IN ('defenseclaw','external','hook_only')),
			profile_version TEXT NOT NULL CHECK (length(profile_version) BETWEEN 1 AND 128),
			managed_config_digest TEXT CHECK (managed_config_digest IS NULL OR
				(length(managed_config_digest) = 64 AND managed_config_digest NOT GLOB '*[^0-9a-f]*')),
			is_default INTEGER NOT NULL CHECK (is_default IN (0, 1)),
			created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0),
			updated_time_unix_nano INTEGER NOT NULL CHECK (updated_time_unix_nano >= created_time_unix_nano)
		);

		CREATE TABLE IF NOT EXISTS correlation_events (
			semantic_event_id TEXT PRIMARY KEY
				CHECK (length(semantic_event_id) = 36),
			logical_group_id TEXT NOT NULL
				CHECK (length(logical_group_id) = 36),
			connector TEXT NOT NULL
				CHECK (length(connector) BETWEEN 1 AND 64),
			connector_instance_id TEXT NOT NULL
				CHECK (length(connector_instance_id) = 36),
			source_rail TEXT NOT NULL
				CHECK (source_rail IN ('hook','native_otlp','proxy','stream','internal')),
			event_name TEXT NOT NULL
				CHECK (length(event_name) BETWEEN 1 AND 128),
			source_time_unix_nano INTEGER
				CHECK (source_time_unix_nano IS NULL OR source_time_unix_nano > 0),
			received_time_unix_nano INTEGER NOT NULL
				CHECK (received_time_unix_nano > 0),
			source_event_digest TEXT
				CHECK (source_event_digest IS NULL OR
					(length(source_event_digest) = 64 AND source_event_digest NOT GLOB '*[^0-9a-f]*')),
			fingerprint_sha256 TEXT
				CHECK (fingerprint_sha256 IS NULL OR
					(length(fingerprint_sha256) = 64 AND fingerprint_sha256 NOT GLOB '*[^0-9a-f]*')),
			first_request_id TEXT
				CHECK (first_request_id IS NULL OR length(first_request_id) BETWEEN 1 AND 512),
			first_record_id TEXT
				CHECK (first_record_id IS NULL OR length(first_record_id) BETWEEN 1 AND 512),
			profile_version TEXT NOT NULL
				CHECK (length(profile_version) BETWEEN 1 AND 128),
			completeness TEXT NOT NULL
				CHECK (completeness IN ('complete','partial','unknown')),
			FOREIGN KEY (connector_instance_id) REFERENCES correlation_connector_instances(connector_instance_id) ON DELETE RESTRICT
		);

		CREATE TABLE IF NOT EXISTS correlation_identifiers (
			identifier_id TEXT PRIMARY KEY
				CHECK (length(identifier_id) = 67 AND substr(identifier_id, 1, 3) = 'id_'),
			semantic_event_id TEXT NOT NULL,
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			namespace TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 128),
			identifier_kind TEXT NOT NULL CHECK (identifier_kind IN (
				'source_event','source_sequence','source_timestamp','message','thread','prompt','step',
				'session','root_session','parent_session','child_session','turn','agent','root_agent',
				'parent_agent','child_agent','lifecycle','execution','model_request','model_response',
				'action','tool_invocation','trace','span')),
			value_digest TEXT NOT NULL
				CHECK (length(value_digest) = 64 AND value_digest NOT GLOB '*[^0-9a-f]*'),
			normalized_value TEXT NOT NULL CHECK (length(normalized_value) BETWEEN 1 AND 512),
			source_field TEXT NOT NULL CHECK (length(source_field) BETWEEN 1 AND 128),
			origin TEXT NOT NULL CHECK (origin IN ('reported','defenseclaw_minted','derived','trace_exact')),
			profile_version TEXT NOT NULL CHECK (length(profile_version) BETWEEN 1 AND 128),
			created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0),
			last_seen_time_unix_nano INTEGER NOT NULL CHECK (last_seen_time_unix_nano >= created_time_unix_nano),
			FOREIGN KEY (semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE,
			FOREIGN KEY (connector_instance_id) REFERENCES correlation_connector_instances(connector_instance_id) ON DELETE RESTRICT,
			UNIQUE (connector_instance_id, namespace, identifier_kind, value_digest, semantic_event_id)
		);

		CREATE TABLE IF NOT EXISTS correlation_observations (
			record_id TEXT PRIMARY KEY
				CHECK (length(record_id) BETWEEN 1 AND 512),
			semantic_event_id TEXT NOT NULL,
			signal TEXT NOT NULL CHECK (signal IN ('logs','traces','metrics')),
			bucket TEXT NOT NULL CHECK (length(bucket) BETWEEN 1 AND 64),
			event_name TEXT NOT NULL CHECK (length(event_name) BETWEEN 1 AND 128),
			observed_time_unix_nano INTEGER NOT NULL CHECK (observed_time_unix_nano > 0),
			trace_id TEXT CHECK (trace_id IS NULL OR
				(length(trace_id) = 32 AND trace_id NOT GLOB '*[^0-9a-f]*')),
			span_id TEXT CHECK (span_id IS NULL OR
				(length(span_id) = 16 AND span_id NOT GLOB '*[^0-9a-f]*')),
			session_id TEXT CHECK (session_id IS NULL OR length(session_id) BETWEEN 1 AND 512),
			turn_id TEXT CHECK (turn_id IS NULL OR length(turn_id) BETWEEN 1 AND 512),
			agent_id TEXT CHECK (agent_id IS NULL OR length(agent_id) BETWEEN 1 AND 512),
			lifecycle_id TEXT CHECK (lifecycle_id IS NULL OR length(lifecycle_id) BETWEEN 1 AND 512),
			execution_id TEXT CHECK (execution_id IS NULL OR length(execution_id) BETWEEN 1 AND 512),
			model_request_id TEXT CHECK (model_request_id IS NULL OR length(model_request_id) BETWEEN 1 AND 512),
			model_response_id TEXT CHECK (model_response_id IS NULL OR length(model_response_id) BETWEEN 1 AND 512),
			tool_invocation_id TEXT CHECK (tool_invocation_id IS NULL OR length(tool_invocation_id) BETWEEN 1 AND 512),
			projection_hash TEXT CHECK (projection_hash IS NULL OR length(projection_hash) BETWEEN 64 AND 71),
			status TEXT NOT NULL CHECK (status IN ('constructed','export_eligible')),
			FOREIGN KEY (semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS correlation_relationships (
			relationship_id TEXT PRIMARY KEY
				CHECK (length(relationship_id) = 68 AND substr(relationship_id, 1, 4) = 'rel_'),
			from_kind TEXT NOT NULL CHECK (from_kind IN (
				'semantic_event','logical_event','record','session','turn','agent','lifecycle',
				'execution','model_request','model_response','tool_invocation','trace','span')),
			from_id TEXT NOT NULL CHECK (length(from_id) BETWEEN 1 AND 512),
			to_kind TEXT NOT NULL CHECK (to_kind IN (
				'semantic_event','logical_event','record','session','turn','agent','lifecycle',
				'execution','model_request','model_response','tool_invocation','trace','span')),
			to_id TEXT NOT NULL CHECK (length(to_id) BETWEEN 1 AND 512),
			relationship_type TEXT NOT NULL CHECK (relationship_type IN (
				'same_as','duplicate_of','belongs_to','parent_of','delegated_by','caused_by',
				'invokes','responds_to','resumes','correlates_with')),
			method TEXT NOT NULL CHECK (method IN ('reported','trace_exact','derived','inferred')),
			confidence INTEGER NOT NULL CHECK (
				(method IN ('reported','trace_exact') AND confidence = 100) OR
				(method = 'derived' AND confidence = 95) OR
				(method = 'inferred' AND confidence = 50)),
			rule_id TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 128),
			rule_version TEXT NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 128),
			status TEXT NOT NULL CHECK (status IN ('active','candidate','superseded','rejected','conflicted')),
			created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0),
			last_seen_time_unix_nano INTEGER NOT NULL CHECK (last_seen_time_unix_nano >= created_time_unix_nano),
			UNIQUE (from_kind, from_id, to_kind, to_id, relationship_type, method, rule_id, rule_version)
		);

		CREATE TABLE IF NOT EXISTS correlation_relationship_evidence (
			evidence_id TEXT PRIMARY KEY
				CHECK (length(evidence_id) = 67 AND substr(evidence_id, 1, 3) = 'ev_'),
			relationship_id TEXT NOT NULL,
			evidence_record_id TEXT,
			semantic_event_id TEXT,
			evidence_role TEXT NOT NULL CHECK (evidence_role IN ('source','target','corroborating','conflicting')),
			integrity_state TEXT NOT NULL CHECK (integrity_state IN ('verified','unverified','failed')),
			created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0),
			CHECK ((evidence_record_id IS NULL) <> (semantic_event_id IS NULL)),
			FOREIGN KEY (relationship_id) REFERENCES correlation_relationships(relationship_id) ON DELETE CASCADE,
			FOREIGN KEY (evidence_record_id) REFERENCES correlation_observations(record_id) ON DELETE CASCADE,
			FOREIGN KEY (semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS correlation_cursors (
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 512),
			agent_id TEXT NOT NULL CHECK (length(agent_id) BETWEEN 1 AND 512),
			lifecycle_id TEXT CHECK (lifecycle_id IS NULL OR length(lifecycle_id) BETWEEN 1 AND 512),
			execution_id TEXT CHECK (execution_id IS NULL OR length(execution_id) BETWEEN 1 AND 512),
			active_turn_id TEXT CHECK (active_turn_id IS NULL OR length(active_turn_id) BETWEEN 1 AND 512),
			active_prompt_id TEXT CHECK (active_prompt_id IS NULL OR length(active_prompt_id) BETWEEN 1 AND 512),
			phase TEXT NOT NULL CHECK (length(phase) BETWEEN 1 AND 64),
			sequence INTEGER NOT NULL CHECK (sequence >= 0),
			root_agent_id TEXT CHECK (root_agent_id IS NULL OR length(root_agent_id) BETWEEN 1 AND 512),
			parent_agent_id TEXT CHECK (parent_agent_id IS NULL OR length(parent_agent_id) BETWEEN 1 AND 512),
			root_session_id TEXT CHECK (root_session_id IS NULL OR length(root_session_id) BETWEEN 1 AND 512),
			parent_session_id TEXT CHECK (parent_session_id IS NULL OR length(parent_session_id) BETWEEN 1 AND 512),
			last_semantic_event_id TEXT,
			last_record_id TEXT CHECK (last_record_id IS NULL OR length(last_record_id) BETWEEN 1 AND 512),
			profile_version TEXT NOT NULL CHECK (length(profile_version) BETWEEN 1 AND 128),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			updated_time_unix_nano INTEGER NOT NULL CHECK (updated_time_unix_nano > 0),
			PRIMARY KEY (connector_instance_id, session_id, agent_id),
			FOREIGN KEY (last_semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT
		);

		CREATE TABLE IF NOT EXISTS correlation_pending_operations (
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			operation_namespace TEXT NOT NULL CHECK (length(operation_namespace) BETWEEN 1 AND 128),
			operation_kind TEXT NOT NULL CHECK (operation_kind IN (
				'prompt','model_request','tool_invocation','action')),
			operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 512),
			operation_type TEXT NOT NULL CHECK (operation_type IN ('model','tool')),
			scope_kind TEXT NOT NULL CHECK (scope_kind IN (
				'connector_instance','session','thread','turn','execution')),
			scope_id TEXT NOT NULL CHECK (length(scope_id) BETWEEN 1 AND 512),
			operation_name TEXT CHECK (operation_name IS NULL OR length(operation_name) BETWEEN 1 AND 256),
			session_id TEXT CHECK (session_id IS NULL OR length(session_id) BETWEEN 1 AND 512),
			turn_id TEXT CHECK (turn_id IS NULL OR length(turn_id) BETWEEN 1 AND 512),
			agent_id TEXT CHECK (agent_id IS NULL OR length(agent_id) BETWEEN 1 AND 512),
			execution_id TEXT CHECK (execution_id IS NULL OR length(execution_id) BETWEEN 1 AND 512),
			start_semantic_event_id TEXT NOT NULL,
			start_time_unix_nano INTEGER NOT NULL CHECK (start_time_unix_nano > 0),
			input_digest TEXT CHECK (input_digest IS NULL OR
				(length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*')),
			terminal_semantic_event_id TEXT,
			terminal_time_unix_nano INTEGER CHECK (terminal_time_unix_nano IS NULL OR terminal_time_unix_nano > 0),
			status TEXT NOT NULL CHECK (status IN ('active','completed','failed','cancelled','unresolved')),
			updated_time_unix_nano INTEGER NOT NULL CHECK (updated_time_unix_nano > 0),
			CHECK ((status = 'active' AND terminal_semantic_event_id IS NULL AND terminal_time_unix_nano IS NULL) OR
				(status <> 'active' AND terminal_semantic_event_id IS NOT NULL AND terminal_time_unix_nano IS NOT NULL)),
			PRIMARY KEY (connector_instance_id, operation_namespace, operation_kind,
				operation_id, operation_type, scope_kind, scope_id),
			FOREIGN KEY (start_semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT,
			FOREIGN KEY (terminal_semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT
		);

		CREATE TABLE IF NOT EXISTS correlation_identity_claims (
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			namespace TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 128),
			identifier_kind TEXT NOT NULL CHECK (identifier_kind IN (
				'source_event','model_request','model_response','tool_invocation')),
			value_digest TEXT NOT NULL
				CHECK (length(value_digest) = 64 AND value_digest NOT GLOB '*[^0-9a-f]*'),
			event_name TEXT NOT NULL CHECK (length(event_name) BETWEEN 1 AND 128),
			rail_a TEXT NOT NULL CHECK (rail_a IN ('hook','native_otlp','proxy','stream')),
			rail_b TEXT NOT NULL CHECK (rail_b IN ('hook','native_otlp','proxy','stream')),
			rule_id TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 128),
			rule_version TEXT NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 128),
			source_rail TEXT NOT NULL CHECK (source_rail IN ('hook','native_otlp','proxy','stream')),
			semantic_event_id TEXT NOT NULL CHECK (length(semantic_event_id) = 36),
			logical_group_id TEXT NOT NULL CHECK (length(logical_group_id) = 36),
			created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0),
			CHECK (rail_a < rail_b),
			CHECK (source_rail = rail_a OR source_rail = rail_b),
			PRIMARY KEY (connector_instance_id, namespace, identifier_kind, value_digest,
				event_name, rail_a, rail_b, rule_id, rule_version, source_rail),
			FOREIGN KEY (connector_instance_id) REFERENCES correlation_connector_instances(connector_instance_id) ON DELETE RESTRICT,
			FOREIGN KEY (semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
		);

		CREATE TABLE IF NOT EXISTS correlation_receipts (
			connector_instance_id TEXT NOT NULL CHECK (length(connector_instance_id) = 36),
			source_key_digest TEXT NOT NULL
				CHECK (length(source_key_digest) = 64 AND source_key_digest NOT GLOB '*[^0-9a-f]*'),
			fingerprint_sha256 TEXT NOT NULL
				CHECK (length(fingerprint_sha256) = 64 AND fingerprint_sha256 NOT GLOB '*[^0-9a-f]*'),
			semantic_event_id TEXT NOT NULL,
			conflicts_with_semantic_event_id TEXT,
			first_received_time_unix_nano INTEGER NOT NULL CHECK (first_received_time_unix_nano > 0),
			last_received_time_unix_nano INTEGER NOT NULL CHECK (last_received_time_unix_nano >= first_received_time_unix_nano),
			delivery_count INTEGER NOT NULL CHECK (delivery_count > 0),
			accepted_time_unix_nano INTEGER
				CHECK (accepted_time_unix_nano IS NULL OR accepted_time_unix_nano >= first_received_time_unix_nano),
			expires_time_unix_nano INTEGER NOT NULL CHECK (expires_time_unix_nano >= last_received_time_unix_nano),
			PRIMARY KEY (connector_instance_id, source_key_digest, fingerprint_sha256),
			FOREIGN KEY (semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT,
			FOREIGN KEY (conflicts_with_semantic_event_id) REFERENCES correlation_events(semantic_event_id) ON DELETE RESTRICT
		);

		CREATE INDEX IF NOT EXISTS idx_correlation_events_received
			ON correlation_events(received_time_unix_nano, semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_events_connector
			ON correlation_events(connector_instance_id, received_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_events_logical
			ON correlation_events(logical_group_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_connector_custody
			ON correlation_connector_instances(export_custody, connector);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_correlation_connector_default
			ON correlation_connector_instances(connector) WHERE is_default = 1;
		CREATE INDEX IF NOT EXISTS idx_correlation_identifiers_exact
			ON correlation_identifiers(connector_instance_id, namespace, identifier_kind, value_digest);
		CREATE INDEX IF NOT EXISTS idx_correlation_identifiers_event
			ON correlation_identifiers(semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_event
			ON correlation_observations(semantic_event_id, observed_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_session
			ON correlation_observations(session_id, observed_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_turn
			ON correlation_observations(turn_id, observed_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_agent
			ON correlation_observations(agent_id, observed_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_model_request
			ON correlation_observations(model_request_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_model_response
			ON correlation_observations(model_response_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_tool
			ON correlation_observations(tool_invocation_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_observations_trace
			ON correlation_observations(trace_id, span_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_relationships_from
			ON correlation_relationships(from_kind, from_id, status);
		CREATE INDEX IF NOT EXISTS idx_correlation_relationships_to
			ON correlation_relationships(to_kind, to_id, status);
		CREATE INDEX IF NOT EXISTS idx_correlation_relationships_status
			ON correlation_relationships(status, last_seen_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_relationships_seen
			ON correlation_relationships(last_seen_time_unix_nano, relationship_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_evidence_relationship
			ON correlation_relationship_evidence(relationship_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_evidence_semantic
			ON correlation_relationship_evidence(semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_evidence_record
			ON correlation_relationship_evidence(evidence_record_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_cursors_active
			ON correlation_cursors(active, updated_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_cursors_event
			ON correlation_cursors(last_semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_pending_status
			ON correlation_pending_operations(connector_instance_id, operation_namespace,
				operation_kind, scope_kind, scope_id, operation_type, status, updated_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_pending_exact
			ON correlation_pending_operations(connector_instance_id, operation_namespace,
				operation_kind, operation_id, operation_type, scope_kind, scope_id, status);
		CREATE INDEX IF NOT EXISTS idx_correlation_pending_start_event
			ON correlation_pending_operations(start_semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_pending_terminal_event
			ON correlation_pending_operations(terminal_semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_receipts_expiry
			ON correlation_receipts(expires_time_unix_nano);
		CREATE INDEX IF NOT EXISTS idx_correlation_receipts_source
			ON correlation_receipts(connector_instance_id, source_key_digest);
		CREATE INDEX IF NOT EXISTS idx_correlation_receipts_event
			ON correlation_receipts(semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_receipts_conflict_event
			ON correlation_receipts(conflicts_with_semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_identity_claims_event
			ON correlation_identity_claims(semantic_event_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_identity_claims_logical
			ON correlation_identity_claims(logical_group_id);
	`)
	if err != nil {
		return fmt.Errorf("create observability v8 correlation ledger: %w", err)
	}
	return nil
}
