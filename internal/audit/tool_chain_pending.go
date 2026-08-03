// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

const (
	ToolChainPendingPrepared ToolChainPendingStatus = "prepared"
	ToolChainPendingReplay   ToolChainPendingStatus = "replay"
	ToolChainPendingResolved ToolChainPendingStatus = "resolved"
	ToolChainPendingMissing  ToolChainPendingStatus = "missing"
	ToolChainPendingExpired  ToolChainPendingStatus = "expired"
	ToolChainPendingNoJoin   ToolChainPendingStatus = "no_join"

	ToolChainSessionResetApplied ToolChainSessionResetStatus = "applied"
	ToolChainSessionResetReplay  ToolChainSessionResetStatus = "replay"
	ToolChainSessionResetNoJoin  ToolChainSessionResetStatus = "no_join"

	ToolChainPendingOutcomeSuccess   ToolChainPendingOutcome = "success"
	ToolChainPendingOutcomeFailure   ToolChainPendingOutcome = "failure"
	ToolChainPendingOutcomeDenied    ToolChainPendingOutcome = "denied"
	ToolChainPendingOutcomeCancelled ToolChainPendingOutcome = "cancelled"
	ToolChainPendingOutcomeUnknown   ToolChainPendingOutcome = "unknown"

	toolChainPendingBoundaryBarrier = "pending_boundary"
	toolChainTerminalResetBarrier   = "terminal_reset"
)

var ErrToolChainPendingConflict = errors.New("audit: pending tool-chain action conflict")

type ToolChainPendingStatus string

type ToolChainPendingOutcome string

type ToolChainSessionResetStatus string

// ToolChainPreparePendingInput contains only stable identifiers, digests, and
// the semantic projection needed after a successful terminal hook. A zero
// projection is a content-free invocation marker used to authenticate a later
// denial outcome. The exact session digest is derived from the correlation
// ledger rather than accepted from the caller.
type ToolChainPreparePendingInput struct {
	ConnectorInstanceID  ConnectorInstanceID
	ToolInvocationDigest string
	PreSemanticEventID   SemanticEventID
	PreInputFingerprint  string
	RulesetFingerprint   string
	Projection           guardrail.ToolChainProjection
}

type ToolChainPreparePendingResult struct {
	Status ToolChainPendingStatus
}

// ToolChainResolvePendingInput identifies one prepared action. The terminal
// event fields are required for every outcome so the exact session is derived
// before lookup or deletion. The active ruleset is required only for success.
type ToolChainResolvePendingInput struct {
	ConnectorInstanceID      ConnectorInstanceID
	ToolInvocationDigest     string
	Outcome                  ToolChainPendingOutcome
	RulesetFingerprint       string
	TerminalSemanticEventID  SemanticEventID
	TerminalInputFingerprint string
}

type ToolChainResolvePendingResult struct {
	Status      ToolChainPendingStatus
	Observation ToolChainObserveResult
}

// ToolChainDiscardPendingForEventSessionInput identifies an authoritative
// terminal event. Its exact session digest is derived from the correlation
// ledger; the caller never supplies session state directly.
type ToolChainDiscardPendingForEventSessionInput struct {
	ConnectorInstanceID      ConnectorInstanceID
	TerminalSemanticEventID  SemanticEventID
	TerminalInputFingerprint string
}

// ToolChainDiscardPendingForEventSessionResult reports only bounded metadata;
// pending projections and correlation values never leave the repository.
type ToolChainDiscardPendingForEventSessionResult struct {
	Status ToolChainPendingStatus
	Count  int
}

// ToolChainResetForTerminalEventSessionInput identifies a reviewed terminal
// lifecycle event. Its exact session and causal time are loaded from the
// correlation ledger; neither is accepted from the caller.
type ToolChainResetForTerminalEventSessionInput struct {
	ConnectorInstanceID      ConnectorInstanceID
	TerminalSemanticEventID  SemanticEventID
	TerminalInputFingerprint string
}

// ToolChainResetForTerminalEventSessionResult contains bounded counts only.
// Deny receipts intentionally survive reset so an already committed block
// keeps its stable replay behavior.
type ToolChainResetForTerminalEventSessionResult struct {
	Status       ToolChainSessionResetStatus
	PendingCount int
	EventCount   int
}

type persistedToolChainPending struct {
	connector, invocation, session, preEvent, preInput, projectionFP string
	ruleset, parseStatus                                             string
	detectionSteps, enforcementSteps                                 uint16
	prepared, expires                                                int64
}

type persistedToolChainPendingBoundary struct {
	connector, session, boundaryEvent, boundaryInput string
	cutoff, discardedAt, expires                     int64
}

type persistedToolChainCutoffBarrier struct {
	kind                       string
	cutoff, appliedAt, expires int64
}

func (repo *ToolChainRepository) PreparePending(
	ctx context.Context,
	input ToolChainPreparePendingInput,
) (ToolChainPreparePendingResult, error) {
	var result ToolChainPreparePendingResult
	if repo == nil || repo.store == nil {
		return result, errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return result, errors.New("audit: tool-chain context is required")
	}
	if err := validateToolChainPreparePendingInput(input); err != nil {
		return result, err
	}
	now, err := repo.pendingNow()
	if err != nil {
		return result, err
	}

	var postCommitErr error
	err = retryBusyObserved(ctx, "guardrail_chain_pending_prepare",
		repo.store.sqliteBusyObservabilityV8(), func() error {
			release, err := repo.store.acquireReady()
			if err != nil {
				return err
			}
			defer release()
			tx, err := repo.store.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			attempt, prepareErr := repo.preparePendingTx(ctx, tx, input, now)
			if prepareErr != nil &&
				!errors.Is(prepareErr, ErrToolChainPendingConflict) {
				return prepareErr
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			result = attempt
			postCommitErr = prepareErr
			return nil
		})
	if err != nil {
		return result, err
	}
	return result, postCommitErr
}

func (repo *ToolChainRepository) preparePendingTx(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainPreparePendingInput,
	now time.Time,
) (ToolChainPreparePendingResult, error) {
	session, received, joined, err := loadToolChainEventSession(
		ctx, tx, input.PreSemanticEventID, input.ConnectorInstanceID,
		input.PreInputFingerprint,
	)
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	if !joined {
		return ToolChainPreparePendingResult{Status: ToolChainPendingNoJoin}, nil
	}
	suppressed, err := repo.terminalResetSuppressesEvent(
		ctx, tx, input.ConnectorInstanceID, session, received, now,
	)
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	if suppressed {
		return ToolChainPreparePendingResult{Status: ToolChainPendingExpired}, nil
	}
	suppressed, err = repo.pendingBoundarySuppressesEvent(
		ctx, tx, input.ConnectorInstanceID, session, received, now,
	)
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	if suppressed {
		return ToolChainPreparePendingResult{Status: ToolChainPendingExpired}, nil
	}
	projectionFP, err := guardrail.ToolChainProjectionFingerprint(input.Projection)
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}

	existing, found, err := loadToolChainPending(
		ctx, tx, input.ConnectorInstanceID, session, input.ToolInvocationDigest,
	)
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	if found {
		if err := validatePersistedToolChainPending(existing); err != nil {
			return ToolChainPreparePendingResult{}, err
		}
		if existing.expires > unixNano(now) {
			if sameToolChainPending(existing, input, session, projectionFP) {
				return ToolChainPreparePendingResult{Status: ToolChainPendingReplay}, nil
			}
			// A reused connector-owned invocation ID makes both proposals
			// unauthoritative. Delete the original inside this transaction and
			// commit that invalidation before returning the conflict sentinel;
			// otherwise either result could promote attacker-chosen state.
			if err := deleteToolChainPending(
				ctx, tx, repo, input.ConnectorInstanceID, session,
				input.ToolInvocationDigest,
			); err != nil {
				return ToolChainPreparePendingResult{}, err
			}
			return ToolChainPreparePendingResult{}, ErrToolChainPendingConflict
		}
		if err := deleteToolChainPending(
			ctx, tx, repo, input.ConnectorInstanceID, session,
			input.ToolInvocationDigest,
		); err != nil {
			return ToolChainPreparePendingResult{}, err
		}
	}

	if _, err := txExecContextObserved(ctx, tx, "guardrail_chain_pending_prune_expired",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_pending_actions
		WHERE expires_time_unix_nano<=?`, unixNano(now)); err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	if err := repo.makePendingCapacity(ctx, tx); err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	expires := now.Add(repo.pendingTTL)
	_, err = txExecContextObserved(ctx, tx, "guardrail_chain_pending_insert",
		repo.store.sqliteBusyObservabilityV8(), `INSERT INTO guardrail_chain_pending_actions (
			connector_instance_id, tool_invocation_digest, session_value_digest,
			pre_semantic_event_id, pre_input_fingerprint, projection_fingerprint,
			ruleset_fingerprint, parse_status, detection_step_mask,
			enforcement_step_mask, prepared_time_unix_nano, expires_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(input.ConnectorInstanceID), input.ToolInvocationDigest, session,
		string(input.PreSemanticEventID), input.PreInputFingerprint, projectionFP,
		input.RulesetFingerprint, string(input.Projection.ParseStatus),
		input.Projection.DetectionStepMask, input.Projection.EnforcementStepMask,
		unixNano(now), unixNano(expires))
	if err != nil {
		return ToolChainPreparePendingResult{}, err
	}
	return ToolChainPreparePendingResult{Status: ToolChainPendingPrepared}, nil
}

func (repo *ToolChainRepository) ResolvePending(
	ctx context.Context,
	input ToolChainResolvePendingInput,
) (ToolChainResolvePendingResult, error) {
	var result ToolChainResolvePendingResult
	if repo == nil || repo.store == nil {
		return result, errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return result, errors.New("audit: tool-chain context is required")
	}
	if err := validateToolChainResolvePendingInput(input); err != nil {
		return result, err
	}
	now, err := repo.pendingNow()
	if err != nil {
		return result, err
	}

	err = retryBusyObserved(ctx, "guardrail_chain_pending_resolve",
		repo.store.sqliteBusyObservabilityV8(), func() error {
			release, err := repo.store.acquireReady()
			if err != nil {
				return err
			}
			defer release()
			tx, err := repo.store.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			attempt, err := repo.resolvePendingTx(ctx, tx, input, now)
			if err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			result = attempt
			return nil
		})
	return result, err
}

func (repo *ToolChainRepository) resolvePendingTx(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainResolvePendingInput,
	now time.Time,
) (ToolChainResolvePendingResult, error) {
	session, joined, err := loadPendingEventSession(
		ctx, tx, input.TerminalSemanticEventID, input.ConnectorInstanceID,
		input.TerminalInputFingerprint,
	)
	if err != nil {
		return ToolChainResolvePendingResult{}, err
	}
	if !joined {
		return ToolChainResolvePendingResult{Status: ToolChainPendingNoJoin}, nil
	}
	pending, found, err := loadToolChainPending(
		ctx, tx, input.ConnectorInstanceID, session, input.ToolInvocationDigest,
	)
	if err != nil {
		return ToolChainResolvePendingResult{}, err
	}
	if !found {
		return ToolChainResolvePendingResult{Status: ToolChainPendingMissing}, nil
	}
	if err := validatePersistedToolChainPending(pending); err != nil {
		return ToolChainResolvePendingResult{}, err
	}
	if pending.expires <= unixNano(now) {
		if err := deleteToolChainPending(
			ctx, tx, repo, input.ConnectorInstanceID, session,
			input.ToolInvocationDigest,
		); err != nil {
			return ToolChainResolvePendingResult{}, err
		}
		return ToolChainResolvePendingResult{Status: ToolChainPendingExpired}, nil
	}
	if input.Outcome != ToolChainPendingOutcomeSuccess {
		if err := deleteToolChainPending(
			ctx, tx, repo, input.ConnectorInstanceID, session,
			input.ToolInvocationDigest,
		); err != nil {
			return ToolChainResolvePendingResult{}, err
		}
		return ToolChainResolvePendingResult{Status: ToolChainPendingResolved}, nil
	}
	if pending.ruleset != input.RulesetFingerprint {
		if err := deleteToolChainPending(
			ctx, tx, repo, input.ConnectorInstanceID, session,
			input.ToolInvocationDigest,
		); err != nil {
			return ToolChainResolvePendingResult{}, err
		}
		return ToolChainResolvePendingResult{Status: ToolChainPendingExpired}, nil
	}
	projection := guardrail.ToolChainProjection{
		ParseStatus:         actionfacts.ParseStatus(pending.parseStatus),
		DetectionStepMask:   pending.detectionSteps,
		EnforcementStepMask: pending.enforcementSteps,
	}
	if projection.DetectionStepMask == 0 {
		if err := deleteToolChainPending(
			ctx, tx, repo, input.ConnectorInstanceID, session,
			input.ToolInvocationDigest,
		); err != nil {
			return ToolChainResolvePendingResult{}, err
		}
		return ToolChainResolvePendingResult{Status: ToolChainPendingResolved}, nil
	}
	observation, err := repo.observeTx(ctx, tx, ToolChainObserveInput{
		SemanticEventID:     input.TerminalSemanticEventID,
		ConnectorInstanceID: input.ConnectorInstanceID,
		InputFingerprint:    input.TerminalInputFingerprint,
		RulesetFingerprint:  input.RulesetFingerprint,
		Projection:          projection,
		DenyEligible:        false,
	}, now)
	if err != nil {
		return ToolChainResolvePendingResult{}, err
	}
	if observation.Status == ToolChainObserveNoJoin {
		return ToolChainResolvePendingResult{}, ErrToolChainIntegrity
	}
	if err := deleteToolChainPending(
		ctx, tx, repo, input.ConnectorInstanceID, session,
		input.ToolInvocationDigest,
	); err != nil {
		return ToolChainResolvePendingResult{}, err
	}
	return ToolChainResolvePendingResult{
		Status: ToolChainPendingResolved, Observation: observation,
	}, nil
}

// DiscardPendingForEventSession clears pending predecessors at or before the
// exact connector/session boundary identified by an authoritative event.
// Proposals received after that boundary are retained so a delayed turn event
// cannot discard work from a newer turn that reuses the same session.
func (repo *ToolChainRepository) DiscardPendingForEventSession(
	ctx context.Context,
	input ToolChainDiscardPendingForEventSessionInput,
) (ToolChainDiscardPendingForEventSessionResult, error) {
	var result ToolChainDiscardPendingForEventSessionResult
	if repo == nil || repo.store == nil {
		return result, errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return result, errors.New("audit: tool-chain context is required")
	}
	if err := validateToolChainDiscardPendingInput(input); err != nil {
		return result, err
	}
	now, err := repo.pendingNow()
	if err != nil {
		return result, err
	}
	if repo.maxPartitions < 1 || repo.maxPartitions > guardrail.ToolChainMaxPartitions ||
		repo.maxHorizon <= 0 || repo.maxHorizon > guardrail.ToolChainMaxHorizon {
		return result, errors.New("audit: invalid tool-chain repository bounds")
	}

	err = retryBusyObserved(ctx, "guardrail_chain_pending_discard_session",
		repo.store.sqliteBusyObservabilityV8(), func() error {
			release, err := repo.store.acquireReady()
			if err != nil {
				return err
			}
			defer release()
			tx, err := repo.store.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			session, cutoff, joined, err := loadToolChainEventSession(
				ctx, tx, input.TerminalSemanticEventID,
				input.ConnectorInstanceID, input.TerminalInputFingerprint,
			)
			if err != nil {
				return err
			}
			if !joined {
				result.Status = ToolChainPendingNoJoin
				return tx.Commit()
			}
			suppressed, err := repo.globalCutoffBarrierSuppressesEvent(
				ctx, tx, toolChainPendingBoundaryBarrier, cutoff, now,
			)
			if err != nil {
				return err
			}
			if suppressed {
				result.Status = ToolChainPendingReplay
				return tx.Commit()
			}
			boundary, found, err := loadToolChainPendingBoundary(
				ctx, tx, input.ConnectorInstanceID, session,
			)
			if err != nil {
				return err
			}
			if found {
				if err := validatePersistedToolChainPendingBoundary(boundary); err != nil {
					return err
				}
				if boundary.connector != string(input.ConnectorInstanceID) ||
					boundary.session != session {
					return ErrToolChainIntegrity
				}
				if boundary.expires < unixNano(now) {
					if _, err := txExecContextObserved(
						ctx, tx, "guardrail_chain_pending_boundary_delete_expired",
						repo.store.sqliteBusyObservabilityV8(),
						`DELETE FROM guardrail_chain_pending_boundaries
						WHERE connector_instance_id=? AND session_value_digest=?`,
						string(input.ConnectorInstanceID), session,
					); err != nil {
						return err
					}
					found = false
				} else if boundary.cutoff > cutoff {
					result.Status = ToolChainPendingReplay
					return tx.Commit()
				} else if boundary.cutoff == cutoff {
					if boundary.boundaryEvent != string(input.TerminalSemanticEventID) ||
						boundary.boundaryInput != input.TerminalInputFingerprint {
						return ErrToolChainIntegrity
					}
					result.Status = ToolChainPendingReplay
					return tx.Commit()
				}
			}
			if !found {
				if err := repo.makePendingBoundaryCapacity(
					ctx, tx, now, cutoff,
				); err != nil {
					return err
				}
			}
			expires := now.Add(repo.maxHorizon)
			if found {
				_, err = txExecContextObserved(
					ctx, tx, "guardrail_chain_pending_boundary_update",
					repo.store.sqliteBusyObservabilityV8(),
					`UPDATE guardrail_chain_pending_boundaries
					SET boundary_semantic_event_id=?, boundary_input_fingerprint=?,
						cutoff_received_time_unix_nano=?, discard_time_unix_nano=?,
						expires_time_unix_nano=?
					WHERE connector_instance_id=? AND session_value_digest=?`,
					string(input.TerminalSemanticEventID), input.TerminalInputFingerprint,
					cutoff, unixNano(now), unixNano(expires),
					string(input.ConnectorInstanceID), session,
				)
			} else {
				_, err = txExecContextObserved(
					ctx, tx, "guardrail_chain_pending_boundary_insert",
					repo.store.sqliteBusyObservabilityV8(),
					`INSERT INTO guardrail_chain_pending_boundaries (
						connector_instance_id, session_value_digest,
						boundary_semantic_event_id, boundary_input_fingerprint,
						cutoff_received_time_unix_nano, discard_time_unix_nano,
						expires_time_unix_nano
					) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					string(input.ConnectorInstanceID), session,
					string(input.TerminalSemanticEventID), input.TerminalInputFingerprint,
					cutoff, unixNano(now), unixNano(expires),
				)
			}
			if err != nil {
				return err
			}
			queryResult, err := txExecContextObserved(
				ctx, tx, "guardrail_chain_pending_discard_session_delete",
				repo.store.sqliteBusyObservabilityV8(),
				`DELETE FROM guardrail_chain_pending_actions
				WHERE connector_instance_id=? AND session_value_digest=?
				AND pre_semantic_event_id IN (
					SELECT semantic_event_id FROM correlation_events
					WHERE received_time_unix_nano<=?
				)`,
				string(input.ConnectorInstanceID), session, cutoff,
			)
			if err != nil {
				return err
			}
			count, err := queryResult.RowsAffected()
			if err != nil {
				return err
			}
			if count < 0 || count > int64(repo.maxPending) {
				return ErrToolChainIntegrity
			}
			result.Count = int(count)
			if count == 0 {
				result.Status = ToolChainPendingMissing
			} else {
				result.Status = ToolChainPendingResolved
			}
			return tx.Commit()
		})
	return result, err
}

// ResetForTerminalEventSession clears pending and committed chain inputs at or
// before one authenticated session-terminal event. A durable cutoff suppresses
// stale predecessor replays while allowing later events that reuse the same
// connector-owned session identifier.
func (repo *ToolChainRepository) ResetForTerminalEventSession(
	ctx context.Context,
	input ToolChainResetForTerminalEventSessionInput,
) (ToolChainResetForTerminalEventSessionResult, error) {
	var result ToolChainResetForTerminalEventSessionResult
	if repo == nil || repo.store == nil {
		return result, errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return result, errors.New("audit: tool-chain context is required")
	}
	if err := validateToolChainResetInput(input); err != nil {
		return result, err
	}
	now, err := repo.pendingNow()
	if err != nil {
		return result, err
	}
	if repo.maxEvents == 0 || repo.maxEvents > guardrail.ToolChainMaxEvents ||
		repo.maxPartitions < 1 || repo.maxPartitions > guardrail.ToolChainMaxPartitions ||
		repo.maxHorizon <= 0 || repo.maxHorizon > guardrail.ToolChainMaxHorizon {
		return result, errors.New("audit: invalid tool-chain repository bounds")
	}

	err = retryBusyObserved(ctx, "guardrail_chain_terminal_reset",
		repo.store.sqliteBusyObservabilityV8(), func() error {
			release, err := repo.store.acquireReady()
			if err != nil {
				return err
			}
			defer release()
			tx, err := repo.store.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback() //nolint:errcheck
			attempt, err := repo.resetForTerminalEventSessionTx(
				ctx, tx, input, now,
			)
			if err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			result = attempt
			return nil
		})
	return result, err
}

type persistedToolChainTerminalReset struct {
	connector, session, terminalEvent, terminalInput string
	cutoff, resetAt, expires                         int64
}

func (repo *ToolChainRepository) resetForTerminalEventSessionTx(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainResetForTerminalEventSessionInput,
	now time.Time,
) (ToolChainResetForTerminalEventSessionResult, error) {
	session, cutoff, joined, err := loadToolChainEventSession(
		ctx, tx, input.TerminalSemanticEventID, input.ConnectorInstanceID,
		input.TerminalInputFingerprint,
	)
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	if !joined {
		return ToolChainResetForTerminalEventSessionResult{
			Status: ToolChainSessionResetNoJoin,
		}, nil
	}
	suppressed, err := repo.globalCutoffBarrierSuppressesEvent(
		ctx, tx, toolChainTerminalResetBarrier, cutoff, now,
	)
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	if suppressed {
		return ToolChainResetForTerminalEventSessionResult{
			Status: ToolChainSessionResetReplay,
		}, nil
	}

	existing, found, err := loadToolChainTerminalReset(
		ctx, tx, input.ConnectorInstanceID, session,
	)
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	if found {
		if err := validatePersistedToolChainTerminalReset(existing); err != nil {
			return ToolChainResetForTerminalEventSessionResult{}, err
		}
		if existing.cutoff > cutoff {
			return ToolChainResetForTerminalEventSessionResult{
				Status: ToolChainSessionResetReplay,
			}, nil
		}
		if existing.cutoff == cutoff {
			if existing.terminalEvent != string(input.TerminalSemanticEventID) ||
				existing.terminalInput != input.TerminalInputFingerprint {
				return ToolChainResetForTerminalEventSessionResult{}, ErrToolChainIntegrity
			}
			return ToolChainResetForTerminalEventSessionResult{
				Status: ToolChainSessionResetReplay,
			}, nil
		}
	} else if err := repo.makeTerminalResetCapacity(ctx, tx, now, cutoff); err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}

	expires := now.Add(repo.maxHorizon)
	if found {
		_, err = txExecContextObserved(ctx, tx, "guardrail_chain_terminal_reset_update",
			repo.store.sqliteBusyObservabilityV8(), `UPDATE guardrail_chain_terminal_resets
			SET terminal_semantic_event_id=?, terminal_input_fingerprint=?,
				cutoff_received_time_unix_nano=?, reset_time_unix_nano=?,
				expires_time_unix_nano=?
			WHERE connector_instance_id=? AND session_value_digest=?`,
			string(input.TerminalSemanticEventID), input.TerminalInputFingerprint,
			cutoff, unixNano(now), unixNano(expires),
			string(input.ConnectorInstanceID), session)
	} else {
		_, err = txExecContextObserved(ctx, tx, "guardrail_chain_terminal_reset_insert",
			repo.store.sqliteBusyObservabilityV8(), `INSERT INTO guardrail_chain_terminal_resets (
				connector_instance_id, session_value_digest, terminal_semantic_event_id,
				terminal_input_fingerprint, cutoff_received_time_unix_nano,
				reset_time_unix_nano, expires_time_unix_nano
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			string(input.ConnectorInstanceID), session,
			string(input.TerminalSemanticEventID), input.TerminalInputFingerprint,
			cutoff, unixNano(now), unixNano(expires))
	}
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}

	pendingResult, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_terminal_reset_pending",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_pending_actions
		WHERE connector_instance_id=? AND session_value_digest=?
		AND pre_semantic_event_id IN (
			SELECT semantic_event_id FROM correlation_events
			WHERE received_time_unix_nano<=?
		)`,
		string(input.ConnectorInstanceID), session, cutoff,
	)
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	pendingCount, err := pendingResult.RowsAffected()
	if err != nil || pendingCount < 0 || pendingCount > int64(repo.maxPending) {
		return ToolChainResetForTerminalEventSessionResult{}, ErrToolChainIntegrity
	}
	eventResult, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_terminal_reset_events",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_events
		WHERE connector_instance_id=? AND session_value_digest=?
		AND received_time_unix_nano<=?`,
		string(input.ConnectorInstanceID), session, cutoff,
	)
	if err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	eventCount, err := eventResult.RowsAffected()
	if err != nil || eventCount < 0 || eventCount > int64(repo.maxEvents) {
		return ToolChainResetForTerminalEventSessionResult{}, ErrToolChainIntegrity
	}
	if _, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_terminal_reset_empty_partition",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_partitions
		WHERE connector_instance_id=? AND session_value_digest=?
		AND NOT EXISTS (
			SELECT 1 FROM guardrail_chain_events event
			WHERE event.connector_instance_id=guardrail_chain_partitions.connector_instance_id
			AND event.session_value_digest=guardrail_chain_partitions.session_value_digest
		)`, string(input.ConnectorInstanceID), session,
	); err != nil {
		return ToolChainResetForTerminalEventSessionResult{}, err
	}
	return ToolChainResetForTerminalEventSessionResult{
		Status: ToolChainSessionResetApplied, PendingCount: int(pendingCount),
		EventCount: int(eventCount),
	}, nil
}

func validateToolChainPreparePendingInput(input ToolChainPreparePendingInput) error {
	if err := validateUUIDv7("connector instance id", string(input.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateSHA256("tool invocation digest", input.ToolInvocationDigest, true); err != nil {
		return err
	}
	if err := validateUUIDv7("pre semantic event id", string(input.PreSemanticEventID)); err != nil {
		return err
	}
	if err := validateSHA256("pre input fingerprint", input.PreInputFingerprint, true); err != nil {
		return err
	}
	if err := validateSHA256("tool-chain ruleset fingerprint", input.RulesetFingerprint, true); err != nil {
		return err
	}
	return validatePendingToolChainProjection(input.Projection)
}

func validateToolChainResolvePendingInput(input ToolChainResolvePendingInput) error {
	if err := validateUUIDv7("connector instance id", string(input.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateSHA256("tool invocation digest", input.ToolInvocationDigest, true); err != nil {
		return err
	}
	switch input.Outcome {
	case ToolChainPendingOutcomeSuccess, ToolChainPendingOutcomeFailure,
		ToolChainPendingOutcomeDenied, ToolChainPendingOutcomeCancelled,
		ToolChainPendingOutcomeUnknown:
	default:
		return errors.New("audit: invalid pending tool-chain outcome")
	}
	if err := validateUUIDv7(
		"terminal semantic event id", string(input.TerminalSemanticEventID),
	); err != nil {
		return err
	}
	if err := validateSHA256(
		"terminal input fingerprint", input.TerminalInputFingerprint, true,
	); err != nil {
		return err
	}
	if input.Outcome != ToolChainPendingOutcomeSuccess {
		return nil
	}
	return validateSHA256("tool-chain ruleset fingerprint", input.RulesetFingerprint, true)
}

func validateToolChainDiscardPendingInput(
	input ToolChainDiscardPendingForEventSessionInput,
) error {
	if err := validateUUIDv7("connector instance id", string(input.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateUUIDv7(
		"terminal semantic event id", string(input.TerminalSemanticEventID),
	); err != nil {
		return err
	}
	return validateSHA256(
		"terminal input fingerprint", input.TerminalInputFingerprint, true,
	)
}

func validateToolChainResetInput(
	input ToolChainResetForTerminalEventSessionInput,
) error {
	return validateToolChainDiscardPendingInput(
		ToolChainDiscardPendingForEventSessionInput(input),
	)
}

func (repo *ToolChainRepository) pendingNow() (time.Time, error) {
	now := repo.now().UTC()
	if now.IsZero() || repo.pendingTTL <= 0 ||
		repo.pendingTTL > guardrail.ToolChainMaxHorizon ||
		repo.maxPending < 1 || repo.maxPending > guardrail.ToolChainMaxPartitions {
		return time.Time{}, errors.New("audit: invalid pending tool-chain repository bounds")
	}
	return now, nil
}

func loadPendingEventSession(
	ctx context.Context,
	tx *sql.Tx,
	eventID SemanticEventID,
	connectorID ConnectorInstanceID,
	inputFingerprint string,
) (string, bool, error) {
	session, _, joined, err := loadToolChainEventSession(
		ctx, tx, eventID, connectorID, inputFingerprint,
	)
	return session, joined, err
}

func loadToolChainEventSession(
	ctx context.Context,
	tx *sql.Tx,
	eventID SemanticEventID,
	connectorID ConnectorInstanceID,
	inputFingerprint string,
) (string, int64, bool, error) {
	var connector string
	var eventFP sql.NullString
	var received int64
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id,
		received_time_unix_nano, fingerprint_sha256
		FROM correlation_events WHERE semantic_event_id=?`, string(eventID)).Scan(
		&connector, &received, &eventFP,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	if connector != string(connectorID) || received <= 0 || !eventFP.Valid ||
		eventFP.String != inputFingerprint {
		return "", 0, false, ErrToolChainIntegrity
	}
	session, joined, err := loadExactToolChainSession(ctx, tx, eventID, connectorID)
	return session, received, joined, err
}

func loadToolChainPending(
	ctx context.Context,
	tx *sql.Tx,
	connectorID ConnectorInstanceID,
	sessionDigest string,
	invocationDigest string,
) (persistedToolChainPending, bool, error) {
	var pending persistedToolChainPending
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id,
		tool_invocation_digest, session_value_digest, pre_semantic_event_id,
		pre_input_fingerprint, projection_fingerprint, ruleset_fingerprint,
		parse_status, detection_step_mask, enforcement_step_mask,
		prepared_time_unix_nano, expires_time_unix_nano
		FROM guardrail_chain_pending_actions
		WHERE connector_instance_id=? AND session_value_digest=?
		AND tool_invocation_digest=?`,
		string(connectorID), sessionDigest, invocationDigest).Scan(
		&pending.connector, &pending.invocation, &pending.session,
		&pending.preEvent, &pending.preInput, &pending.projectionFP,
		&pending.ruleset, &pending.parseStatus, &pending.detectionSteps,
		&pending.enforcementSteps, &pending.prepared, &pending.expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedToolChainPending{}, false, nil
	}
	if err != nil {
		return persistedToolChainPending{}, false, err
	}
	return pending, true, nil
}

func loadToolChainTerminalReset(
	ctx context.Context,
	tx *sql.Tx,
	connectorID ConnectorInstanceID,
	sessionDigest string,
) (persistedToolChainTerminalReset, bool, error) {
	var reset persistedToolChainTerminalReset
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id,
		session_value_digest, terminal_semantic_event_id,
		terminal_input_fingerprint, cutoff_received_time_unix_nano,
		reset_time_unix_nano, expires_time_unix_nano
		FROM guardrail_chain_terminal_resets
		WHERE connector_instance_id=? AND session_value_digest=?`,
		string(connectorID), sessionDigest).Scan(
		&reset.connector, &reset.session, &reset.terminalEvent,
		&reset.terminalInput, &reset.cutoff, &reset.resetAt, &reset.expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedToolChainTerminalReset{}, false, nil
	}
	if err != nil {
		return persistedToolChainTerminalReset{}, false, err
	}
	return reset, true, nil
}

func loadToolChainPendingBoundary(
	ctx context.Context,
	tx *sql.Tx,
	connectorID ConnectorInstanceID,
	sessionDigest string,
) (persistedToolChainPendingBoundary, bool, error) {
	var boundary persistedToolChainPendingBoundary
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id,
		session_value_digest, boundary_semantic_event_id,
		boundary_input_fingerprint, cutoff_received_time_unix_nano,
		discard_time_unix_nano, expires_time_unix_nano
		FROM guardrail_chain_pending_boundaries
		WHERE connector_instance_id=? AND session_value_digest=?`,
		string(connectorID), sessionDigest).Scan(
		&boundary.connector, &boundary.session, &boundary.boundaryEvent,
		&boundary.boundaryInput, &boundary.cutoff, &boundary.discardedAt,
		&boundary.expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedToolChainPendingBoundary{}, false, nil
	}
	if err != nil {
		return persistedToolChainPendingBoundary{}, false, err
	}
	return boundary, true, nil
}

func loadToolChainCutoffBarrier(
	ctx context.Context,
	tx *sql.Tx,
	kind string,
) (persistedToolChainCutoffBarrier, bool, error) {
	var barrier persistedToolChainCutoffBarrier
	err := tx.QueryRowContext(ctx, `SELECT barrier_kind,
		cutoff_received_time_unix_nano, applied_time_unix_nano,
		expires_time_unix_nano
		FROM guardrail_chain_cutoff_barriers WHERE barrier_kind=?`, kind).Scan(
		&barrier.kind, &barrier.cutoff, &barrier.appliedAt, &barrier.expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedToolChainCutoffBarrier{}, false, nil
	}
	if err != nil {
		return persistedToolChainCutoffBarrier{}, false, err
	}
	return barrier, true, nil
}

func validatePersistedToolChainPendingBoundary(
	boundary persistedToolChainPendingBoundary,
) error {
	if validateUUIDv7("pending boundary connector instance id", boundary.connector) != nil ||
		validateSHA256("pending boundary session value digest", boundary.session, true) != nil ||
		validateUUIDv7("pending boundary semantic event id", boundary.boundaryEvent) != nil ||
		validateSHA256("pending boundary input fingerprint", boundary.boundaryInput, true) != nil ||
		boundary.cutoff <= 0 || boundary.discardedAt <= 0 ||
		boundary.expires <= boundary.discardedAt {
		return ErrToolChainIntegrity
	}
	return nil
}

func validatePersistedToolChainTerminalReset(
	reset persistedToolChainTerminalReset,
) error {
	if validateUUIDv7("terminal reset connector instance id", reset.connector) != nil ||
		validateSHA256("terminal reset session value digest", reset.session, true) != nil ||
		validateUUIDv7("terminal reset semantic event id", reset.terminalEvent) != nil ||
		validateSHA256("terminal reset input fingerprint", reset.terminalInput, true) != nil ||
		reset.cutoff <= 0 || reset.resetAt <= 0 || reset.expires <= reset.resetAt {
		return ErrToolChainIntegrity
	}
	return nil
}

func validatePersistedToolChainCutoffBarrier(
	barrier persistedToolChainCutoffBarrier,
) error {
	if (barrier.kind != toolChainPendingBoundaryBarrier &&
		barrier.kind != toolChainTerminalResetBarrier) ||
		barrier.cutoff <= 0 || barrier.appliedAt <= 0 ||
		barrier.expires <= barrier.appliedAt {
		return ErrToolChainIntegrity
	}
	return nil
}

func (repo *ToolChainRepository) globalCutoffBarrierSuppressesEvent(
	ctx context.Context,
	tx *sql.Tx,
	kind string,
	received int64,
	now time.Time,
) (bool, error) {
	barrier, found, err := loadToolChainCutoffBarrier(ctx, tx, kind)
	if err != nil || !found {
		return false, err
	}
	if err := validatePersistedToolChainCutoffBarrier(barrier); err != nil {
		return false, err
	}
	return barrier.expires >= unixNano(now) && received <= barrier.cutoff, nil
}

func (repo *ToolChainRepository) terminalResetSuppressesEvent(
	ctx context.Context,
	tx *sql.Tx,
	connectorID ConnectorInstanceID,
	sessionDigest string,
	received int64,
	now time.Time,
) (bool, error) {
	suppressed, err := repo.globalCutoffBarrierSuppressesEvent(
		ctx, tx, toolChainTerminalResetBarrier, received, now,
	)
	if err != nil || suppressed {
		return suppressed, err
	}
	reset, found, err := loadToolChainTerminalReset(
		ctx, tx, connectorID, sessionDigest,
	)
	if err != nil || !found {
		return false, err
	}
	if err := validatePersistedToolChainTerminalReset(reset); err != nil {
		return false, err
	}
	if reset.connector != string(connectorID) || reset.session != sessionDigest {
		return false, ErrToolChainIntegrity
	}
	return reset.expires >= unixNano(now) && received <= reset.cutoff, nil
}

func (repo *ToolChainRepository) pendingBoundarySuppressesEvent(
	ctx context.Context,
	tx *sql.Tx,
	connectorID ConnectorInstanceID,
	sessionDigest string,
	received int64,
	now time.Time,
) (bool, error) {
	suppressed, err := repo.globalCutoffBarrierSuppressesEvent(
		ctx, tx, toolChainPendingBoundaryBarrier, received, now,
	)
	if err != nil || suppressed {
		return suppressed, err
	}
	boundary, found, err := loadToolChainPendingBoundary(
		ctx, tx, connectorID, sessionDigest,
	)
	if err != nil || !found {
		return false, err
	}
	if err := validatePersistedToolChainPendingBoundary(boundary); err != nil {
		return false, err
	}
	if boundary.connector != string(connectorID) || boundary.session != sessionDigest {
		return false, ErrToolChainIntegrity
	}
	return boundary.expires >= unixNano(now) && received <= boundary.cutoff, nil
}

func validatePersistedToolChainPending(pending persistedToolChainPending) error {
	if validateUUIDv7("pending connector instance id", pending.connector) != nil ||
		validateSHA256("pending tool invocation digest", pending.invocation, true) != nil ||
		validateSHA256("pending session value digest", pending.session, true) != nil ||
		validateUUIDv7("pending pre semantic event id", pending.preEvent) != nil ||
		validateSHA256("pending pre input fingerprint", pending.preInput, true) != nil ||
		validateSHA256("pending projection fingerprint", pending.projectionFP, true) != nil ||
		validateSHA256("pending ruleset fingerprint", pending.ruleset, true) != nil ||
		pending.prepared <= 0 || pending.expires <= pending.prepared {
		return ErrToolChainIntegrity
	}
	projection := guardrail.ToolChainProjection{
		ParseStatus:         actionfacts.ParseStatus(pending.parseStatus),
		DetectionStepMask:   pending.detectionSteps,
		EnforcementStepMask: pending.enforcementSteps,
	}
	if err := validatePendingToolChainProjection(projection); err != nil {
		return ErrToolChainIntegrity
	}
	projectionFP, err := guardrail.ToolChainProjectionFingerprint(projection)
	if err != nil || projectionFP != pending.projectionFP {
		return ErrToolChainIntegrity
	}
	return nil
}

func validatePendingToolChainProjection(projection guardrail.ToolChainProjection) error {
	if err := guardrail.ValidateToolChainProjection(projection); err != nil {
		return err
	}
	predecessorMask := uint16(0)
	for _, definition := range guardrail.ToolChainDefinitions() {
		predecessorMask |= definition.Step1Bit
	}
	if projection.DetectionStepMask&^predecessorMask != 0 {
		return errors.New("audit: pending tool-chain projection contains a terminal step")
	}
	return nil
}

func sameToolChainPending(
	pending persistedToolChainPending,
	input ToolChainPreparePendingInput,
	session, projectionFP string,
) bool {
	return pending.connector == string(input.ConnectorInstanceID) &&
		pending.invocation == input.ToolInvocationDigest && pending.session == session &&
		pending.preEvent == string(input.PreSemanticEventID) &&
		pending.preInput == input.PreInputFingerprint && pending.projectionFP == projectionFP &&
		pending.ruleset == input.RulesetFingerprint &&
		pending.parseStatus == string(input.Projection.ParseStatus) &&
		pending.detectionSteps == input.Projection.DetectionStepMask &&
		pending.enforcementSteps == input.Projection.EnforcementStepMask
}

func deleteToolChainPending(
	ctx context.Context,
	tx *sql.Tx,
	repo *ToolChainRepository,
	connectorID ConnectorInstanceID,
	sessionDigest string,
	invocationDigest string,
) error {
	_, err := txExecContextObserved(ctx, tx, "guardrail_chain_pending_delete",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_pending_actions
		WHERE connector_instance_id=? AND session_value_digest=?
		AND tool_invocation_digest=?`,
		string(connectorID), sessionDigest, invocationDigest)
	return err
}

func (repo *ToolChainRepository) makePendingCapacity(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&count); err != nil {
		return err
	}
	excess := count - repo.maxPending + 1
	if excess <= 0 {
		return nil
	}
	_, err := txExecContextObserved(ctx, tx, "guardrail_chain_pending_prune_lru",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_pending_actions
		WHERE (connector_instance_id, session_value_digest,
			tool_invocation_digest) IN (
			SELECT connector_instance_id, session_value_digest,
				tool_invocation_digest
			FROM guardrail_chain_pending_actions
			ORDER BY prepared_time_unix_nano, connector_instance_id,
				session_value_digest, tool_invocation_digest
			LIMIT ?
		)`, excess)
	return err
}

func (repo *ToolChainRepository) makeTerminalResetCapacity(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
	cutoff int64,
) error {
	if _, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_terminal_reset_prune_expired",
		repo.store.sqliteBusyObservabilityV8(),
		`DELETE FROM guardrail_chain_terminal_resets
		WHERE expires_time_unix_nano<?`, unixNano(now),
	); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM guardrail_chain_terminal_resets`).Scan(&count); err != nil {
		return err
	}
	if count < 0 {
		return ErrToolChainIntegrity
	}
	if count < repo.maxPartitions {
		return nil
	}
	_, err := repo.advanceCutoffBarrier(
		ctx, tx, toolChainTerminalResetBarrier,
		`SELECT COALESCE(MAX(cutoff_received_time_unix_nano),0),
			COALESCE(MAX(expires_time_unix_nano),0)
		FROM guardrail_chain_terminal_resets`, cutoff, now,
	)
	if err != nil {
		return err
	}
	// The barrier replaces only the evicted reset identities. Keep unrelated
	// pending and committed chain state; the caller resets the current session.
	excess := count - repo.maxPartitions + 1
	result, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_terminal_reset_evict_summarized",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM
		guardrail_chain_terminal_resets
		WHERE (connector_instance_id, session_value_digest) IN (
			SELECT connector_instance_id, session_value_digest
			FROM guardrail_chain_terminal_resets
			ORDER BY cutoff_received_time_unix_nano, reset_time_unix_nano,
				connector_instance_id, session_value_digest
			LIMIT ?
		)`, excess,
	)
	if err != nil {
		return err
	}
	removed, err := result.RowsAffected()
	if err != nil || removed != int64(excess) {
		return ErrToolChainIntegrity
	}
	return nil
}

func (repo *ToolChainRepository) makePendingBoundaryCapacity(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
	cutoff int64,
) error {
	if _, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_pending_boundary_prune_expired",
		repo.store.sqliteBusyObservabilityV8(),
		`DELETE FROM guardrail_chain_pending_boundaries
		WHERE expires_time_unix_nano<?`, unixNano(now),
	); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM guardrail_chain_pending_boundaries`).Scan(&count); err != nil {
		return err
	}
	if count < 0 {
		return ErrToolChainIntegrity
	}
	if count < repo.maxPartitions {
		return nil
	}
	_, err := repo.advanceCutoffBarrier(
		ctx, tx, toolChainPendingBoundaryBarrier,
		`SELECT COALESCE(MAX(cutoff_received_time_unix_nano),0),
			COALESCE(MAX(expires_time_unix_nano),0)
		FROM guardrail_chain_pending_boundaries`, cutoff, now,
	)
	if err != nil {
		return err
	}
	// The barrier replaces only the evicted boundary identities. Keep unrelated
	// pending actions; the caller discards work from the current session.
	excess := count - repo.maxPartitions + 1
	result, err := txExecContextObserved(
		ctx, tx, "guardrail_chain_pending_boundary_evict_summarized",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM
		guardrail_chain_pending_boundaries
		WHERE (connector_instance_id, session_value_digest) IN (
			SELECT connector_instance_id, session_value_digest
			FROM guardrail_chain_pending_boundaries
			ORDER BY cutoff_received_time_unix_nano, discard_time_unix_nano,
				connector_instance_id, session_value_digest
			LIMIT ?
		)`, excess,
	)
	if err != nil {
		return err
	}
	removed, err := result.RowsAffected()
	if err != nil || removed != int64(excess) {
		return ErrToolChainIntegrity
	}
	return nil
}

func (repo *ToolChainRepository) advanceCutoffBarrier(
	ctx context.Context,
	tx *sql.Tx,
	kind string,
	catalogMaxQuery string,
	cutoff int64,
	now time.Time,
) (persistedToolChainCutoffBarrier, error) {
	var catalogCutoff, catalogExpires int64
	if err := tx.QueryRowContext(ctx, catalogMaxQuery).Scan(
		&catalogCutoff, &catalogExpires,
	); err != nil {
		return persistedToolChainCutoffBarrier{}, err
	}
	barrier, found, err := loadToolChainCutoffBarrier(ctx, tx, kind)
	if err != nil {
		return persistedToolChainCutoffBarrier{}, err
	}
	if found {
		if err := validatePersistedToolChainCutoffBarrier(barrier); err != nil {
			return persistedToolChainCutoffBarrier{}, err
		}
	}
	if catalogCutoff > cutoff {
		cutoff = catalogCutoff
	}
	expires := unixNano(now.Add(repo.maxHorizon))
	if catalogExpires > expires {
		expires = catalogExpires
	}
	if found {
		if barrier.cutoff > cutoff {
			cutoff = barrier.cutoff
		}
		if barrier.expires > expires {
			expires = barrier.expires
		}
	}
	barrier = persistedToolChainCutoffBarrier{
		kind: kind, cutoff: cutoff, appliedAt: unixNano(now), expires: expires,
	}
	if err := validatePersistedToolChainCutoffBarrier(barrier); err != nil {
		return persistedToolChainCutoffBarrier{}, err
	}
	_, err = txExecContextObserved(
		ctx, tx, "guardrail_chain_cutoff_barrier_upsert",
		repo.store.sqliteBusyObservabilityV8(), `INSERT INTO
		guardrail_chain_cutoff_barriers (
			barrier_kind, cutoff_received_time_unix_nano,
			applied_time_unix_nano, expires_time_unix_nano
		) VALUES (?, ?, ?, ?) ON CONFLICT(barrier_kind) DO UPDATE SET
			cutoff_received_time_unix_nano=excluded.cutoff_received_time_unix_nano,
			applied_time_unix_nano=excluded.applied_time_unix_nano,
			expires_time_unix_nano=excluded.expires_time_unix_nano`,
		barrier.kind, barrier.cutoff, barrier.appliedAt, barrier.expires,
	)
	if err != nil {
		return persistedToolChainCutoffBarrier{}, err
	}
	return barrier, nil
}
