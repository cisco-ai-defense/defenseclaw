// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Tool-chain state for Agent Substrate actors (PLAN §5.4). Hosts and
// OpenShell sandboxes use none of this: Store.ToolChainRepository and
// Store.ToolChainRootRepository behave as they always did.
//
// On Substrate the gateway leader keeps the chain store, and every actor is
// one connector instance (ToolChainSubstrateInstanceID). Its windows are:
//
//   - one per session (ToolChainSubstrateSessionDigest of the connector and
//     the session id), in the session table set;
//   - one actor window (WithToolChainActorScope, ToolChainActorScopeDigest),
//     in the root table set: every call of the actor lands there too, so
//     rotating session ids cannot empty it.
//
// Time is the actor's running time (WithToolChainClock): the leader stores
// each event at the actor's running time when the gateway received it, and
// the repository reads its clock in the same running time. The chain
// matcher's per-chain time windows, the horizon, the prunes and the pending
// expiries then all stop while the actor is suspended.

// ToolChainOption configures a repository ToolChainRepositoryWith returns.
type ToolChainOption func(*toolChainOptions) error

type toolChainOptions struct {
	actorDigest string
	now         func() time.Time
}

const (
	toolChainActorScopeDomain     = "defenseclaw.chain.actor.v1"
	toolChainSubstrateInstanceDom = "defenseclaw.chain.substrate.instance.v1"
	toolChainSubstrateSessionDom  = "defenseclaw.chain.substrate.session.v1"
	// ToolChainSubstrateProfileVersion is the profile version of the join
	// rows the leader records for Substrate events.
	ToolChainSubstrateProfileVersion = "substrate-chain-v1"
	// ToolChainSubstrateConnector is the connector name of an actor's
	// connector instance (one instance per actor, whatever agent it runs).
	ToolChainSubstrateConnector = "substrate"
)

func lengthPrefixedDigest(parts ...string) []byte {
	hash := sha256.New()
	for _, part := range parts {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hash.Sum(nil)
}

func validateActorParts(atespace, actorUID string) error {
	for _, part := range [...]struct{ field, value string }{
		{"actor atespace", atespace},
		{"actor uid", actorUID},
	} {
		if err := validateBoundedIdentifier(part.field, part.value, true, toolChainRootIDMaxBytes); err != nil {
			return err
		}
	}
	return nil
}

// ToolChainActorScopeDigest is the actor root partition key: SHA-256 over
// the length-prefixed namespace, atespace and actor UID. The UID is the
// verified actor token's actorUID, so another actor (a fork among them,
// which gets a new UID) never names this one's partition, and the namespace
// keeps it apart from every ToolChainRootScopeDigest.
func ToolChainActorScopeDigest(atespace, actorUID string) (string, error) {
	if err := validateActorParts(atespace, actorUID); err != nil {
		return "", err
	}
	return hex.EncodeToString(lengthPrefixedDigest(toolChainActorScopeDomain, atespace, actorUID)), nil
}

// ToolChainSubstrateInstanceID is the connector instance of one actor: a
// canonical UUIDv7-shaped id derived from the atespace and actor UID, the
// same on every gateway replica and leader.
func ToolChainSubstrateInstanceID(atespace, actorUID string) (ConnectorInstanceID, error) {
	if err := validateActorParts(atespace, actorUID); err != nil {
		return "", err
	}
	b := lengthPrefixedDigest(toolChainSubstrateInstanceDom, atespace, actorUID)[:16]
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return ConnectorInstanceID(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]), nil
}

// ToolChainSubstrateSessionDigest is the session partition key of one
// agent session inside an actor (the actor is the connector instance).
// The session id is a claim; it only ever selects a window of its own actor.
func ToolChainSubstrateSessionDigest(connector, sessionID string) (string, error) {
	if err := validateBoundedIdentifier("connector", connector, true, 64); err != nil {
		return "", err
	}
	if err := validateBoundedIdentifier("session id", sessionID, true, toolChainRootIDMaxBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(lengthPrefixedDigest(toolChainSubstrateSessionDom, connector, sessionID)), nil
}

// WithToolChainActorScope keeps the repository's state in the actor root
// scope of atespace and actorUID (ToolChainActorScopeDigest).
func WithToolChainActorScope(atespace, actorUID string) ToolChainOption {
	return func(o *toolChainOptions) error {
		digest, err := ToolChainActorScopeDigest(atespace, actorUID)
		if err != nil {
			return err
		}
		o.actorDigest = digest
		return nil
	}
}

// WithToolChainClock makes now the repository's clock: an actor's running
// time on Substrate.
func WithToolChainClock(now func() time.Time) ToolChainOption {
	return func(o *toolChainOptions) error {
		if now == nil {
			return errors.New("audit: tool-chain clock is required")
		}
		o.now = now
		return nil
	}
}

// ToolChainRepositoryWith returns a repository configured by opts. Without
// options it is Store.ToolChainRepository.
func (s *Store) ToolChainRepositoryWith(ctx context.Context, opts ...ToolChainOption) (*ToolChainRepository, error) {
	if ctx == nil {
		return nil, errors.New("audit: tool-chain context is required")
	}
	var o toolChainOptions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	var (
		repo *ToolChainRepository
		err  error
	)
	if o.actorDigest != "" {
		repo, err = s.ToolChainRootRepository(ctx, o.actorDigest)
	} else {
		repo, err = s.ToolChainRepository()
	}
	if err != nil {
		return nil, err
	}
	if o.now != nil {
		repo.now = o.now
	}
	return repo, nil
}

// ToolChainJoin is what a chain operation on the leader needs to join one
// event to its session: the event, its input fingerprint, the time it was
// received (the actor's running time at the gateway's receive time) and the
// session partition.
type ToolChainJoin struct {
	ConnectorInstanceID ConnectorInstanceID
	SemanticEventID     SemanticEventID
	EventName           string
	InputFingerprint    string
	ReceivedAt          time.Time
	SessionDigest       string
}

// EnsureToolChainSubstrateInstance records an actor's connector instance.
func (s *Store) EnsureToolChainSubstrateInstance(ctx context.Context, instance ConnectorInstanceID) error {
	repo, err := s.CorrelationRepository()
	if err != nil {
		return err
	}
	_, err = repo.UpsertConnectorInstance(ctx, ConnectorInstance{
		ConnectorInstanceID: instance, Connector: ToolChainSubstrateConnector,
		ExportCustody: ConnectorCustodyHookOnly, ProfileVersion: ToolChainSubstrateProfileVersion,
	})
	return err
}

// RecordToolChainJoin writes the join rows of one event (its correlation
// event and its session identifier), once. A second record of the same
// event must name the same instance, fingerprint and session.
func (s *Store) RecordToolChainJoin(ctx context.Context, join ToolChainJoin) error {
	if err := validateUUIDv7("connector instance id", string(join.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateUUIDv7("semantic event id", string(join.SemanticEventID)); err != nil {
		return err
	}
	if err := validateSHA256("tool-chain input fingerprint", join.InputFingerprint, true); err != nil {
		return err
	}
	if err := validateSHA256("session digest", join.SessionDigest, true); err != nil {
		return err
	}
	if join.ReceivedAt.IsZero() || join.ReceivedAt.UnixNano() <= 0 {
		return errors.New("audit: tool-chain join needs a received time")
	}
	name := join.EventName
	if name == "" {
		name = "substrate.hook"
	}
	if err := validateBoundedIdentifier("event name", name, true, 128); err != nil {
		return err
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var instance, fingerprint string
	err = tx.QueryRowContext(ctx, `SELECT connector_instance_id, COALESCE(fingerprint_sha256, '')
		FROM correlation_events WHERE semantic_event_id=?`, string(join.SemanticEventID)).Scan(&instance, &fingerprint)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		received := unixNano(join.ReceivedAt)
		if _, err := tx.ExecContext(ctx, `INSERT INTO correlation_events (
			semantic_event_id, logical_group_id, connector, connector_instance_id, source_rail,
			event_name, received_time_unix_nano, fingerprint_sha256, profile_version, completeness
		) VALUES (?, ?, ?, ?, 'hook', ?, ?, ?, ?, 'complete')`,
			string(join.SemanticEventID), string(join.SemanticEventID), ToolChainSubstrateConnector,
			string(join.ConnectorInstanceID), name, received, join.InputFingerprint,
			ToolChainSubstrateProfileVersion); err != nil {
			return fmt.Errorf("audit: record tool-chain join event: %w", err)
		}
		id := "id_" + hex.EncodeToString(lengthPrefixedDigest("defenseclaw.chain.substrate.join.v1",
			string(join.SemanticEventID), join.SessionDigest))
		if _, err := tx.ExecContext(ctx, `INSERT INTO correlation_identifiers (
			identifier_id, semantic_event_id, connector_instance_id, namespace, identifier_kind,
			value_digest, normalized_value, source_field, origin, profile_version,
			created_time_unix_nano, last_seen_time_unix_nano
		) VALUES (?, ?, ?, 'substrate', 'session', ?, ?, 'session_id', 'derived', ?, ?, ?)`,
			id, string(join.SemanticEventID), string(join.ConnectorInstanceID), join.SessionDigest,
			join.SessionDigest, ToolChainSubstrateProfileVersion, received, received); err != nil {
			return fmt.Errorf("audit: record tool-chain join session: %w", err)
		}
	case err != nil:
		return err
	default:
		if instance != string(join.ConnectorInstanceID) || fingerprint != join.InputFingerprint {
			return ErrToolChainIntegrity
		}
		session, joined, err := loadExactToolChainSession(ctx, tx, join.SemanticEventID, join.ConnectorInstanceID)
		if err != nil {
			return err
		}
		if !joined || session != join.SessionDigest {
			return ErrToolChainIntegrity
		}
		return nil
	}
	return tx.Commit()
}

// ToolChainForkCopy names a fork: the parent's and the child's connector
// instances and actor scope digests.
type ToolChainForkCopy struct {
	ParentInstance    ConnectorInstanceID
	ChildInstance     ConnectorInstanceID
	ParentActorDigest string
	ChildActorDigest  string
	// At is when the copy is made (lineage row; the child's clock).
	At time.Time
}

// ErrToolChainForkAlreadyStarted is the answer to a fork copy for a child
// that already has a window: the copy runs once, before the child's first
// call, and never merges into history the child made itself.
var ErrToolChainForkAlreadyStarted = errors.New("audit: the forked actor already has tool-chain state")

const toolChainLineageDDL = `CREATE TABLE IF NOT EXISTS guardrail_chain_substrate_lineage (
	child_instance_id TEXT PRIMARY KEY CHECK (length(child_instance_id) = 36),
	parent_instance_id TEXT NOT NULL CHECK (length(parent_instance_id) = 36),
	copied_events INTEGER NOT NULL CHECK (copied_events >= 0),
	created_time_unix_nano INTEGER NOT NULL CHECK (created_time_unix_nano > 0)
) WITHOUT ROWID`

// toolChainForkEventColumns are the copied columns of guardrail_chain_events
// after semantic_event_id, connector_instance_id and session_value_digest.
const toolChainForkEventColumns = `sequence, received_time_unix_nano, input_fingerprint,
	projection_fingerprint, ruleset_fingerprint, parse_status, detection_step_mask,
	enforcement_step_mask, enforcement_join_digests, enforcement_output_join_digests,
	value_join_digests, detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
	stable_action_id`

// CopyToolChainFork starts a forked actor's windows from a copy of its
// parent's: every session window of the parent instance, and the parent's
// actor window under the child's actor digest. Copied events get new event
// ids; partitions keep their sequence and active ruleset. Deny receipts,
// pending proposals, boundaries and resets are not copied (asks and
// approvals live elsewhere and are never inherited either). The copy runs
// once per child (a lineage row records it); it returns the number of
// copied events.
func (s *Store) CopyToolChainFork(ctx context.Context, fork ToolChainForkCopy) (int, error) {
	for _, id := range []ConnectorInstanceID{fork.ParentInstance, fork.ChildInstance} {
		if err := validateUUIDv7("fork connector instance id", string(id)); err != nil {
			return 0, err
		}
	}
	for _, d := range []string{fork.ParentActorDigest, fork.ChildActorDigest} {
		if err := validateSHA256("fork actor digest", d, true); err != nil {
			return 0, err
		}
	}
	if fork.ParentInstance == fork.ChildInstance || fork.ParentActorDigest == fork.ChildActorDigest {
		return 0, errors.New("audit: a fork is not its own parent")
	}
	if fork.At.IsZero() {
		return 0, errors.New("audit: fork copy needs a time")
	}
	if err := s.ensureToolChainRootTables(ctx); err != nil {
		return 0, err
	}
	release, err := s.acquireReady()
	if err != nil {
		return 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, toolChainLineageDDL); err != nil {
		return 0, err
	}
	var started int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM guardrail_chain_substrate_lineage WHERE child_instance_id=?) +
		(SELECT COUNT(*) FROM guardrail_chain_partitions WHERE connector_instance_id=?) +
		(SELECT COUNT(*) FROM guardrail_chain_root_partitions WHERE connector_instance_id=?)`,
		string(fork.ChildInstance), string(fork.ChildInstance), string(fork.ChildInstance)).Scan(&started); err != nil {
		return 0, err
	}
	if started != 0 {
		return 0, ErrToolChainForkAlreadyStarted
	}
	copied := 0
	for _, set := range []struct {
		tables       toolChainTableSet
		parentDigest string
		childDigest  string
	}{
		{toolChainSessionTables, "", ""},
		{toolChainRootTables, fork.ParentActorDigest, fork.ChildActorDigest},
	} {
		repo := &ToolChainRepository{tables: set.tables}
		where, args := "connector_instance_id=?", []any{string(fork.ParentInstance)}
		if set.parentDigest != "" {
			where += " AND session_value_digest=?"
			args = append(args, set.parentDigest)
		}
		childDigest := "session_value_digest"
		partArgs := []any{string(fork.ChildInstance)}
		if set.childDigest != "" {
			childDigest = "?"
			partArgs = append(partArgs, set.childDigest)
		}
		partArgs = append(partArgs, unixNano(fork.At))
		partArgs = append(partArgs, args...)
		if _, err := tx.ExecContext(ctx, repo.sql(`INSERT INTO guardrail_chain_partitions (
			connector_instance_id, session_value_digest, active_ruleset_fingerprint,
			next_sequence, updated_time_unix_nano)
			SELECT ?, `+childDigest+`, active_ruleset_fingerprint, next_sequence, ?
			FROM guardrail_chain_partitions WHERE `+where), partArgs...); err != nil {
			return 0, fmt.Errorf("audit: copy fork partitions: %w", err)
		}
		rows, err := tx.QueryContext(ctx, repo.sql(`SELECT semantic_event_id, session_value_digest
			FROM guardrail_chain_events WHERE `+where+` ORDER BY session_value_digest, sequence`), args...)
		if err != nil {
			return 0, err
		}
		type event struct{ id, session string }
		var events []event
		for rows.Next() {
			var e event
			if err := rows.Scan(&e.id, &e.session); err != nil {
				rows.Close()
				return 0, err
			}
			events = append(events, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}
		for _, e := range events {
			id, err := NewSemanticEventID()
			if err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO correlation_events (
				semantic_event_id, logical_group_id, connector, connector_instance_id, source_rail,
				event_name, received_time_unix_nano, fingerprint_sha256, profile_version, completeness)
				SELECT ?, ?, connector, ?, source_rail, event_name, received_time_unix_nano,
					fingerprint_sha256, profile_version, completeness
				FROM correlation_events WHERE semantic_event_id=?`,
				string(id), string(id), string(fork.ChildInstance), e.id); err != nil {
				return 0, fmt.Errorf("audit: copy fork event: %w", err)
			}
			session := e.session
			if set.childDigest != "" {
				session = set.childDigest
			}
			if _, err := tx.ExecContext(ctx, repo.sql(`INSERT INTO guardrail_chain_events (
				semantic_event_id, connector_instance_id, session_value_digest, `+toolChainForkEventColumns+`)
				SELECT ?, ?, ?, `+toolChainForkEventColumns+`
				FROM guardrail_chain_events WHERE semantic_event_id=?`),
				string(id), string(fork.ChildInstance), session, e.id); err != nil {
				return 0, fmt.Errorf("audit: copy fork chain event: %w", err)
			}
			copied++
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO guardrail_chain_substrate_lineage (
		child_instance_id, parent_instance_id, copied_events, created_time_unix_nano) VALUES (?, ?, ?, ?)`,
		string(fork.ChildInstance), string(fork.ParentInstance), copied, unixNano(fork.At)); err != nil {
		return 0, err
	}
	return copied, tx.Commit()
}

// ToolChainWindow names one window of an instance and its active ruleset.
type ToolChainWindow struct {
	Scope          ToolChainScope
	ScopeDigest    string
	RulesetDigest  string
	NextSequence   uint64
	UpdatedAtNanos int64
}

// ToolChainInstanceWindows lists every window of a connector instance in
// both table sets (a revert puts a barrier into each).
func (s *Store) ToolChainInstanceWindows(ctx context.Context, instance ConnectorInstanceID) ([]ToolChainWindow, error) {
	if err := validateUUIDv7("connector instance id", string(instance)); err != nil {
		return nil, err
	}
	if err := s.ensureToolChainRootTables(ctx); err != nil {
		return nil, err
	}
	release, err := s.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	var out []ToolChainWindow
	for _, set := range []toolChainTableSet{toolChainSessionTables, toolChainRootTables} {
		repo := &ToolChainRepository{tables: set}
		rows, err := s.db.QueryContext(ctx, repo.sql(`SELECT session_value_digest, active_ruleset_fingerprint,
			next_sequence, updated_time_unix_nano FROM guardrail_chain_partitions
			WHERE connector_instance_id=? ORDER BY session_value_digest`), string(instance))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			w := ToolChainWindow{Scope: repo.Scope()}
			if err := rows.Scan(&w.ScopeDigest, &w.RulesetDigest, &w.NextSequence, &w.UpdatedAtNanos); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, w)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RetireToolChainInstance marks every window of a finished actor (deleted,
// or suspended past retention) least recently used, so the partition cap
// evicts finished actors before live ones. Nothing is deleted here.
func (s *Store) RetireToolChainInstance(ctx context.Context, instance ConnectorInstanceID) error {
	if err := validateUUIDv7("connector instance id", string(instance)); err != nil {
		return err
	}
	if err := s.ensureToolChainRootTables(ctx); err != nil {
		return err
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	for _, set := range []toolChainTableSet{toolChainSessionTables, toolChainRootTables} {
		repo := &ToolChainRepository{tables: set}
		if _, err := s.db.ExecContext(ctx, repo.sql(`UPDATE guardrail_chain_partitions
			SET updated_time_unix_nano=1 WHERE connector_instance_id=?`), string(instance)); err != nil {
			return err
		}
	}
	return nil
}
