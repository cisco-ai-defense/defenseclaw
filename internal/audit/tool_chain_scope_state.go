// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// ToolChainScopeState is what a new event of one root scope is matched
// against, read from the store: the scope's active ruleset and next
// sequence, the window events of that ruleset as Observe loads them (the
// newest ToolChainMaxEvents-1, within the horizon), and the scope's
// prepared pending actions that carry a step of pendingMask. Projections
// are content-free: no argument, path or value leaves the repository.
type ToolChainScopeState struct {
	RulesetFingerprint string
	NextSequence       uint64
	Events             []guardrail.ToolChainWindowEvent
	Pending            []ToolChainPendingStep
}

// ToolChainPendingStep is one prepared action that has not resolved yet.
type ToolChainPendingStep struct {
	PreparedAt time.Time
	ExpiresAt  time.Time
	Projection guardrail.ToolChainProjection
}

// ScopeState reads the root scope's state (root repositories only). The
// Substrate leader keeps it in memory, so the callout's egress check
// matches exactly what the store would without opening the store
// (GAP-0179).
func (repo *ToolChainRepository) ScopeState(
	ctx context.Context,
	instance ConnectorInstanceID,
	pendingMask uint64,
) (ToolChainScopeState, error) {
	var out ToolChainScopeState
	if repo == nil || repo.store == nil || repo.tables.rewrite == nil || repo.rootDigest == "" {
		return out, errors.New("audit: scope state needs a root tool-chain repository")
	}
	if ctx == nil {
		return out, errors.New("audit: tool-chain context is required")
	}
	if err := validateUUIDv7("connector instance id", string(instance)); err != nil {
		return out, err
	}
	if pendingMask&^guardrail.ToolChainStorageStepMask != 0 {
		return out, errors.New("audit: invalid pending step mask")
	}
	now, err := repo.pendingNow()
	if err != nil {
		return out, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return out, err
	}
	defer release()
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback() //nolint:errcheck // read only
	err = tx.QueryRowContext(ctx, repo.sql(`SELECT active_ruleset_fingerprint, next_sequence
		FROM guardrail_chain_partitions WHERE connector_instance_id=? AND session_value_digest=?`),
		string(instance), repo.rootDigest).Scan(&out.RulesetFingerprint, &out.NextSequence)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return ToolChainScopeState{}, err
	default:
		if out.NextSequence == 0 {
			return ToolChainScopeState{}, ErrToolChainIntegrity
		}
		out.Events, err = repo.loadWindow(ctx, tx, ToolChainObserveInput{
			ConnectorInstanceID: instance, RulesetFingerprint: out.RulesetFingerprint,
		}, repo.rootDigest, out.NextSequence, now)
		if err != nil {
			return ToolChainScopeState{}, err
		}
	}
	if pendingMask == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, repo.sql(`SELECT prepared_time_unix_nano,
		expires_time_unix_nano, parse_status, detection_step_mask, enforcement_step_mask,
		enforcement_join_digests, enforcement_output_join_digests, value_join_digests,
		projection_fingerprint
		FROM guardrail_chain_pending_actions
		WHERE connector_instance_id=? AND session_value_digest=? AND expires_time_unix_nano>?
			AND (detection_step_mask & ?) != 0
		ORDER BY prepared_time_unix_nano, tool_invocation_digest`),
		string(instance), repo.rootDigest, unixNano(now), int64(pendingMask))
	if err != nil {
		return ToolChainScopeState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			prepared, expires                   int64
			parseStatus, joins, outputs, values string
			projectionFP                        string
			detection, enforcement              uint64
		)
		if err := rows.Scan(&prepared, &expires, &parseStatus, &detection, &enforcement,
			&joins, &outputs, &values, &projectionFP); err != nil {
			return ToolChainScopeState{}, err
		}
		p := guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.ParseStatus(parseStatus),
			DetectionStepMask: detection, EnforcementStepMask: enforcement,
		}
		var joinErr, outputErr, valueErr error
		p.EnforcementJoinDigests, joinErr = decodeToolChainJoinDigests(joins)
		p.EnforcementOutputJoinDigests, outputErr = decodeToolChainJoinDigests(outputs)
		p.ValueJoinDigests, valueErr = decodeToolChainValueJoinDigests(values)
		if joinErr != nil || outputErr != nil || valueErr != nil {
			return ToolChainScopeState{}, ErrToolChainIntegrity
		}
		if expected, err := guardrail.ToolChainProjectionFingerprint(p); err != nil || expected != projectionFP || prepared < 1 {
			return ToolChainScopeState{}, ErrToolChainIntegrity
		}
		out.Pending = append(out.Pending, ToolChainPendingStep{
			PreparedAt: time.Unix(0, prepared).UTC(), ExpiresAt: time.Unix(0, expires).UTC(), Projection: p,
		})
	}
	if err := rows.Err(); err != nil {
		return ToolChainScopeState{}, err
	}
	return out, nil
}
