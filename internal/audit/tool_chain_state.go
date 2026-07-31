// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const (
	ToolChainObserveFresh  ToolChainObserveStatus = "fresh"
	ToolChainObserveReplay ToolChainObserveStatus = "replay"
	ToolChainObserveNoJoin ToolChainObserveStatus = "no_join"
	toolChainStableDomain                         = "defenseclaw.guardrail-chain-action.v1\x00"
	toolChainReceiptDomain                        = "defenseclaw.guardrail-chain-receipt.v1\x00"
)

var (
	ErrToolChainIntegrity = errors.New("audit: guardrail chain integrity failure")
	ErrToolChainConflict  = errors.New("audit: guardrail chain finalization conflict")
)

type ToolChainObserveStatus string

type ToolChainObserveInput struct {
	SemanticEventID     SemanticEventID
	ConnectorInstanceID ConnectorInstanceID
	InputFingerprint    string
	RulesetFingerprint  string
	Projection          guardrail.ToolChainProjection
	DenyEligible        bool
}

type ToolChainObserveResult struct {
	Status                  ToolChainObserveStatus
	DetectedMask            uint8
	EnforcementSafeMask     uint8
	DeniedMask              uint8
	DetectedChainIDs        []string
	EnforcementSafeChainIDs []string
	DeniedChainIDs          []string
	StableActionID          string
	ReceiptIDs              []string
	SuppressTelemetry       bool
}

// ToolChainRepository owns the atomic durable state for the fixed tool-call
// chains. Its configurable bounds are private and exist only for compact tests.
type ToolChainRepository struct {
	store         *Store
	now           func() time.Time
	maxEvents     uint64
	maxPartitions int
	receiptTTL    time.Duration
	maxHorizon    time.Duration
}

func (s *Store) ToolChainRepository() (*ToolChainRepository, error) {
	if s == nil || s.db == nil || !s.Ready() {
		return nil, errors.New("audit: ready tool-chain store is required")
	}
	return &ToolChainRepository{
		store: s, now: time.Now, maxEvents: guardrail.ToolChainMaxEvents,
		maxPartitions: guardrail.ToolChainMaxPartitions,
		receiptTTL:    guardrail.ToolChainReceiptTTL, maxHorizon: guardrail.ToolChainMaxHorizon,
	}, nil
}

func (repo *ToolChainRepository) Observe(
	ctx context.Context,
	input ToolChainObserveInput,
) (ToolChainObserveResult, error) {
	var result ToolChainObserveResult
	if repo == nil || repo.store == nil {
		return result, errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return result, errors.New("audit: tool-chain context is required")
	}
	if err := validateToolChainObserveInput(input); err != nil {
		return result, err
	}
	now := repo.now().UTC()
	if now.IsZero() || repo.maxEvents == 0 || repo.maxEvents > guardrail.ToolChainMaxEvents ||
		repo.maxPartitions < 1 || repo.maxPartitions > guardrail.ToolChainMaxPartitions ||
		repo.receiptTTL <= 0 || repo.receiptTTL > guardrail.ToolChainReceiptTTL ||
		repo.maxHorizon <= 0 || repo.maxHorizon > guardrail.ToolChainMaxHorizon {
		return result, errors.New("audit: invalid tool-chain repository bounds")
	}

	err := retryBusyObserved(ctx, "guardrail_chain_observe",
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
			attempt, err := repo.observeTx(ctx, tx, input, now)
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

func validateToolChainObserveInput(input ToolChainObserveInput) error {
	if err := validateUUIDv7("semantic event id", string(input.SemanticEventID)); err != nil {
		return err
	}
	if err := validateUUIDv7("connector instance id", string(input.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateSHA256("tool-chain input fingerprint", input.InputFingerprint, true); err != nil {
		return err
	}
	if err := validateSHA256("tool-chain ruleset fingerprint", input.RulesetFingerprint, true); err != nil {
		return err
	}
	return guardrail.ValidateToolChainProjection(input.Projection)
}

func (repo *ToolChainRepository) observeTx(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	now time.Time,
) (ToolChainObserveResult, error) {
	var (
		connector string
		received  int64
		eventFP   sql.NullString
	)
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id,
		received_time_unix_nano, fingerprint_sha256
		FROM correlation_events WHERE semantic_event_id=?`,
		string(input.SemanticEventID)).Scan(&connector, &received, &eventFP)
	if errors.Is(err, sql.ErrNoRows) {
		return ToolChainObserveResult{Status: ToolChainObserveNoJoin}, nil
	}
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	if connector != string(input.ConnectorInstanceID) || !eventFP.Valid ||
		eventFP.String != input.InputFingerprint {
		return ToolChainObserveResult{}, ErrToolChainIntegrity
	}
	sessionDigest, joined, err := loadExactToolChainSession(
		ctx, tx, input.SemanticEventID, input.ConnectorInstanceID)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	if !joined {
		return ToolChainObserveResult{Status: ToolChainObserveNoJoin}, nil
	}

	replay, ok, err := repo.loadReceiptReplay(ctx, tx, input, sessionDigest, now)
	if err != nil || ok {
		return replay, err
	}
	existing, ok, err := repo.loadExistingEvent(ctx, tx, input, sessionDigest, now)
	if err != nil || ok {
		return existing, err
	}

	sequence, err := repo.activatePartition(ctx, tx, input, sessionDigest, now)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	prior, err := repo.loadWindow(ctx, tx, input, sessionDigest, sequence, time.Unix(0, received).UTC())
	if err != nil {
		if !errors.Is(err, ErrToolChainIntegrity) {
			return ToolChainObserveResult{}, err
		}
		if _, deleteErr := txExecContextObserved(ctx, tx, "guardrail_chain_reset_corrupt",
			repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_events
				WHERE connector_instance_id=? AND session_value_digest=?`,
			string(input.ConnectorInstanceID), sessionDigest); deleteErr != nil {
			return ToolChainObserveResult{}, deleteErr
		}
		prior = nil
	}
	final := guardrail.ToolChainWindowEvent{
		SemanticEventID: string(input.SemanticEventID), Sequence: sequence,
		ReceivedAt: time.Unix(0, received).UTC(), Projection: input.Projection,
	}
	matches, err := guardrail.MatchToolChains(prior, final)
	if err != nil {
		return ToolChainObserveResult{}, ErrToolChainIntegrity
	}
	denied := uint8(0)
	if input.DenyEligible {
		denied = matches.EnforcementSafeMask
	}
	stableActionID := ""
	if denied != 0 {
		stableActionID = stableToolChainActionID(input, denied)
	}
	projectionFP, _ := guardrail.ToolChainProjectionFingerprint(input.Projection)
	_, err = txExecContextObserved(ctx, tx, "guardrail_chain_event_insert",
		repo.store.sqliteBusyObservabilityV8(), `INSERT INTO guardrail_chain_events (
			semantic_event_id, connector_instance_id, session_value_digest, sequence,
			received_time_unix_nano, input_fingerprint, projection_fingerprint,
			ruleset_fingerprint, parse_status, detection_step_mask, enforcement_step_mask,
			detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask, stable_action_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(input.SemanticEventID), string(input.ConnectorInstanceID), sessionDigest,
		sequence, received, input.InputFingerprint, projectionFP, input.RulesetFingerprint,
		string(input.Projection.ParseStatus), input.Projection.DetectionStepMask,
		input.Projection.EnforcementStepMask, matches.DetectedMask, matches.EnforcementSafeMask,
		denied, nullStr(stableActionID))
	if err != nil {
		return ToolChainObserveResult{}, err
	}

	receiptIDs, err := repo.insertReceipts(ctx, tx, input, sessionDigest, matches, denied,
		stableActionID, now)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	if err := repo.prune(ctx, tx, input, sessionDigest, sequence, final.ReceivedAt, now); err != nil {
		return ToolChainObserveResult{}, err
	}
	return makeToolChainResult(ToolChainObserveFresh, matches.DetectedMask,
		matches.EnforcementSafeMask, denied, stableActionID, receiptIDs, false)
}

func loadExactToolChainSession(
	ctx context.Context,
	tx *sql.Tx,
	eventID SemanticEventID,
	connectorID ConnectorInstanceID,
) (string, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT value_digest
		FROM correlation_identifiers
		WHERE semantic_event_id=? AND connector_instance_id=? AND identifier_kind='session'
		ORDER BY value_digest LIMIT 2`, string(eventID), string(connectorID))
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return "", false, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if len(values) != 1 || validateSHA256("session value digest", values[0], true) != nil {
		return "", false, nil
	}
	return values[0], true, nil
}

type persistedToolChainEvent struct {
	connector, session, inputFP, projectionFP, ruleset, parseStatus, stableAction string
	sequence, received                                                            int64
	detectionSteps, enforcementSteps                                              uint16
	detected, enforcementSafe, denied                                             uint8
}

func (repo *ToolChainRepository) loadExistingEvent(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	now time.Time,
) (ToolChainObserveResult, bool, error) {
	event, found, err := scanPersistedToolChainEvent(ctx, tx, input.SemanticEventID)
	if err != nil || !found {
		return ToolChainObserveResult{}, false, err
	}
	projectionFP, _ := guardrail.ToolChainProjectionFingerprint(input.Projection)
	if event.connector != string(input.ConnectorInstanceID) || event.session != session ||
		event.inputFP != input.InputFingerprint || event.projectionFP != projectionFP ||
		event.ruleset != input.RulesetFingerprint ||
		event.parseStatus != string(input.Projection.ParseStatus) ||
		event.detectionSteps != input.Projection.DetectionStepMask ||
		event.enforcementSteps != input.Projection.EnforcementStepMask ||
		(event.denied != 0 && event.stableAction != stableToolChainActionID(input, event.denied)) {
		return ToolChainObserveResult{}, true, ErrToolChainIntegrity
	}
	if event.denied == 0 {
		if input.DenyEligible && event.enforcementSafe != 0 {
			return repo.upgradeExistingEventDeny(
				ctx,
				tx,
				input,
				session,
				event,
				now,
			)
		}
		result, err := makeToolChainResult(ToolChainObserveReplay, event.detected,
			event.enforcementSafe, 0, "", nil, true)
		return result, true, err
	}
	replay, found, err := repo.loadReceiptReplay(ctx, tx, input, session, now)
	if err != nil || found {
		return replay, true, err
	}
	if now.Before(time.Unix(0, event.received).Add(repo.receiptTTL)) {
		return ToolChainObserveResult{}, true, ErrToolChainIntegrity
	}
	result, err := makeToolChainResult(ToolChainObserveReplay, event.detected,
		event.enforcementSafe, 0, "", nil, true)
	return result, true, err
}

func (repo *ToolChainRepository) upgradeExistingEventDeny(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	event persistedToolChainEvent,
	now time.Time,
) (ToolChainObserveResult, bool, error) {
	received := time.Unix(0, event.received).UTC()
	prior, err := repo.loadWindow(
		ctx,
		tx,
		input,
		session,
		uint64(event.sequence),
		received,
	)
	if err != nil {
		return ToolChainObserveResult{}, true, err
	}
	matches, err := guardrail.MatchToolChains(
		prior,
		guardrail.ToolChainWindowEvent{
			SemanticEventID: string(input.SemanticEventID),
			Sequence:        uint64(event.sequence),
			ReceivedAt:      received,
			Projection:      input.Projection,
		},
	)
	if err != nil ||
		matches.DetectedMask != event.detected ||
		matches.EnforcementSafeMask != event.enforcementSafe {
		return ToolChainObserveResult{}, true, ErrToolChainIntegrity
	}
	denied := event.enforcementSafe
	stableAction := stableToolChainActionID(input, denied)
	update, err := txExecContextObserved(
		ctx,
		tx,
		"guardrail_chain_event_upgrade_deny",
		repo.store.sqliteBusyObservabilityV8(),
		`UPDATE guardrail_chain_events
		 SET denied_chain_mask=?, stable_action_id=?
		 WHERE semantic_event_id=? AND denied_chain_mask=0 AND stable_action_id IS NULL`,
		denied,
		stableAction,
		string(input.SemanticEventID),
	)
	if err != nil {
		return ToolChainObserveResult{}, true, err
	}
	updated, err := update.RowsAffected()
	if err != nil || updated != 1 {
		return ToolChainObserveResult{}, true, ErrToolChainIntegrity
	}
	receiptIDs, err := repo.insertReceipts(
		ctx,
		tx,
		input,
		session,
		matches,
		denied,
		stableAction,
		now,
	)
	if err != nil {
		return ToolChainObserveResult{}, true, err
	}
	result, err := makeToolChainResult(
		ToolChainObserveFresh,
		event.detected,
		event.enforcementSafe,
		denied,
		stableAction,
		receiptIDs,
		false,
	)
	return result, true, err
}

func scanPersistedToolChainEvent(
	ctx context.Context,
	tx *sql.Tx,
	eventID SemanticEventID,
) (persistedToolChainEvent, bool, error) {
	var event persistedToolChainEvent
	var stable sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT connector_instance_id, session_value_digest,
		sequence, received_time_unix_nano, input_fingerprint, projection_fingerprint,
		ruleset_fingerprint, parse_status, detection_step_mask, enforcement_step_mask,
		detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask, stable_action_id
		FROM guardrail_chain_events WHERE semantic_event_id=?`, string(eventID)).Scan(
		&event.connector, &event.session, &event.sequence, &event.received, &event.inputFP,
		&event.projectionFP, &event.ruleset, &event.parseStatus, &event.detectionSteps,
		&event.enforcementSteps, &event.detected, &event.enforcementSafe, &event.denied, &stable)
	if errors.Is(err, sql.ErrNoRows) {
		return event, false, nil
	}
	if err != nil {
		return event, false, err
	}
	event.stableAction = stable.String
	if err := validatePersistedToolChainEvent(event); err != nil {
		return event, true, ErrToolChainIntegrity
	}
	return event, true, nil
}

func validatePersistedToolChainEvent(event persistedToolChainEvent) error {
	projection := guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.ParseStatus(event.parseStatus),
		DetectionStepMask: event.detectionSteps, EnforcementStepMask: event.enforcementSteps,
	}
	projectionFP, err := guardrail.ToolChainProjectionFingerprint(projection)
	if err != nil || projectionFP != event.projectionFP ||
		validateSHA256("input fingerprint", event.inputFP, true) != nil ||
		validateSHA256("ruleset fingerprint", event.ruleset, true) != nil ||
		event.detected&^guardrail.ToolChainKnownResultMask != 0 ||
		event.enforcementSafe&^event.detected != 0 || event.denied&^event.enforcementSafe != 0 ||
		event.sequence < 1 || event.received < 1 {
		return ErrToolChainIntegrity
	}
	if (event.denied == 0) != (event.stableAction == "") {
		return ErrToolChainIntegrity
	}
	return nil
}

func (repo *ToolChainRepository) activatePartition(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	now time.Time,
) (uint64, error) {
	var next uint64
	err := tx.QueryRowContext(ctx, `SELECT next_sequence FROM guardrail_chain_partitions
		WHERE connector_instance_id=? AND session_value_digest=?`,
		string(input.ConnectorInstanceID), session).Scan(&next)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		next = 1
		_, err = txExecContextObserved(ctx, tx, "guardrail_chain_partition_insert",
			repo.store.sqliteBusyObservabilityV8(), `INSERT INTO guardrail_chain_partitions (
				connector_instance_id, session_value_digest, active_ruleset_fingerprint,
				next_sequence, updated_time_unix_nano) VALUES (?, ?, ?, 2, ?)`,
			string(input.ConnectorInstanceID), session, input.RulesetFingerprint, unixNano(now))
	case err == nil:
		if next == 0 {
			return 0, ErrToolChainIntegrity
		}
		_, err = txExecContextObserved(ctx, tx, "guardrail_chain_partition_advance",
			repo.store.sqliteBusyObservabilityV8(), `UPDATE guardrail_chain_partitions
				SET active_ruleset_fingerprint=?, next_sequence=next_sequence+1,
					updated_time_unix_nano=?
				WHERE connector_instance_id=? AND session_value_digest=?`,
			input.RulesetFingerprint, unixNano(now), string(input.ConnectorInstanceID), session)
	}
	if err != nil {
		return 0, err
	}
	return next, nil
}

func (repo *ToolChainRepository) loadWindow(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	sequence uint64,
	received time.Time,
) ([]guardrail.ToolChainWindowEvent, error) {
	minSequence := uint64(1)
	if sequence >= repo.maxEvents {
		minSequence = sequence - repo.maxEvents + 1
	}
	rows, err := tx.QueryContext(ctx, `SELECT semantic_event_id, sequence,
		received_time_unix_nano, parse_status, detection_step_mask,
		enforcement_step_mask, projection_fingerprint
		FROM guardrail_chain_events
		WHERE connector_instance_id=? AND session_value_digest=? AND ruleset_fingerprint=?
			AND sequence>=? AND sequence<? AND received_time_unix_nano>=?
		ORDER BY sequence, received_time_unix_nano, semantic_event_id LIMIT ?`,
		string(input.ConnectorInstanceID), session, input.RulesetFingerprint,
		minSequence, sequence, unixNano(received.Add(-repo.maxHorizon)), repo.maxEvents-1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	window := make([]guardrail.ToolChainWindowEvent, 0, repo.maxEvents-1)
	for rows.Next() {
		var (
			eventID, parseStatus, projectionFP string
			seq, receivedNano                  int64
			detection, enforcement             uint16
		)
		if err := rows.Scan(&eventID, &seq, &receivedNano, &parseStatus,
			&detection, &enforcement, &projectionFP); err != nil {
			return nil, err
		}
		projection := guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.ParseStatus(parseStatus),
			DetectionStepMask: detection, EnforcementStepMask: enforcement,
		}
		expected, fingerprintErr := guardrail.ToolChainProjectionFingerprint(projection)
		if fingerprintErr != nil || expected != projectionFP || seq < 1 || receivedNano < 1 {
			return nil, ErrToolChainIntegrity
		}
		window = append(window, guardrail.ToolChainWindowEvent{
			SemanticEventID: eventID, Sequence: uint64(seq),
			ReceivedAt: time.Unix(0, receivedNano).UTC(), Projection: projection,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return window, nil
}

type toolChainReceipt struct {
	id, final, predecessor, connector, session, inputFP, ruleset, chainFP string
	chainID, chainVersion, stableAction                                   string
	detected, enforcementSafe, denied                                     uint8
	expires                                                               int64
}

func (repo *ToolChainRepository) loadReceiptReplay(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	now time.Time,
) (ToolChainObserveResult, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT receipt_id, final_semantic_event_id,
		predecessor_semantic_event_id, connector_instance_id, session_value_digest,
		input_fingerprint, ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
		detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
		stable_action_id, expires_time_unix_nano
		FROM guardrail_chain_deny_receipts
		WHERE final_semantic_event_id=? AND input_fingerprint=? AND expires_time_unix_nano>=?
		ORDER BY chain_id`,
		string(input.SemanticEventID), input.InputFingerprint, unixNano(now))
	if err != nil {
		return ToolChainObserveResult{}, false, err
	}
	defer rows.Close()
	var receipts []toolChainReceipt
	for rows.Next() {
		var receipt toolChainReceipt
		if err := rows.Scan(&receipt.id, &receipt.final, &receipt.predecessor,
			&receipt.connector, &receipt.session, &receipt.inputFP, &receipt.ruleset,
			&receipt.chainFP, &receipt.chainID, &receipt.chainVersion, &receipt.detected,
			&receipt.enforcementSafe, &receipt.denied, &receipt.stableAction,
			&receipt.expires); err != nil {
			return ToolChainObserveResult{}, false, err
		}
		receipts = append(receipts, receipt)
	}
	if err := rows.Err(); err != nil {
		return ToolChainObserveResult{}, false, err
	}
	if len(receipts) == 0 {
		return ToolChainObserveResult{}, false, nil
	}
	first := receipts[0]
	seen := uint8(0)
	ids := make([]string, 0, len(receipts))
	for _, receipt := range receipts {
		definition, ok := guardrail.ToolChainDefinitionByID(receipt.chainID)
		chainFP, fingerprintErr := guardrail.ToolChainFingerprint(receipt.chainID, receipt.ruleset)
		if !ok || fingerprintErr != nil || definition.Version != receipt.chainVersion ||
			receipt.chainFP != chainFP || receipt.connector != string(input.ConnectorInstanceID) ||
			receipt.session != session || receipt.final != string(input.SemanticEventID) ||
			receipt.inputFP != input.InputFingerprint || receipt.ruleset != first.ruleset ||
			receipt.detected != first.detected || receipt.enforcementSafe != first.enforcementSafe ||
			receipt.denied != first.denied || receipt.stableAction != first.stableAction ||
			receipt.denied&definition.ResultBit == 0 ||
			validateUUIDv7("chain predecessor semantic event id", receipt.predecessor) != nil ||
			receipt.id != toolChainReceiptID(
				receipt.stableAction, receipt.chainID, receipt.predecessor) ||
			receipt.stableAction != stableToolChainActionID(ToolChainObserveInput{
				SemanticEventID: input.SemanticEventID, InputFingerprint: input.InputFingerprint,
				RulesetFingerprint: receipt.ruleset,
			}, receipt.denied) ||
			seen&definition.ResultBit != 0 {
			return ToolChainObserveResult{}, true, ErrToolChainIntegrity
		}
		seen |= definition.ResultBit
		ids = append(ids, receipt.id)
	}
	if seen != first.denied || bits.OnesCount8(first.denied) != len(receipts) {
		return ToolChainObserveResult{}, true, ErrToolChainIntegrity
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, err := txExecContextObserved(ctx, tx, "guardrail_chain_receipt_replay",
			repo.store.sqliteBusyObservabilityV8(), `UPDATE guardrail_chain_deny_receipts
				SET delivery_count=delivery_count+1,
					last_observed_time_unix_nano=MAX(last_observed_time_unix_nano, ?)
				WHERE receipt_id=?`, unixNano(now), id); err != nil {
			return ToolChainObserveResult{}, true, err
		}
	}
	result, err := makeToolChainResult(ToolChainObserveReplay, first.detected,
		first.enforcementSafe, first.denied, first.stableAction, ids, true)
	return result, true, err
}

func (repo *ToolChainRepository) insertReceipts(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	matches guardrail.ToolChainMatches,
	denied uint8,
	stableAction string,
	now time.Time,
) ([]string, error) {
	if denied == 0 {
		return nil, nil
	}
	ids := make([]string, 0, bits.OnesCount8(denied))
	for i, definition := range guardrail.ToolChainDefinitions() {
		if denied&definition.ResultBit == 0 {
			continue
		}
		chainFP, err := guardrail.ToolChainFingerprint(definition.ID, input.RulesetFingerprint)
		if err != nil || matches.EnforcementPredecessors[i] == "" {
			return nil, ErrToolChainIntegrity
		}
		id := toolChainReceiptID(
			stableAction, definition.ID, matches.EnforcementPredecessors[i])
		_, err = txExecContextObserved(ctx, tx, "guardrail_chain_receipt_insert",
			repo.store.sqliteBusyObservabilityV8(), `INSERT INTO guardrail_chain_deny_receipts (
				receipt_id, final_semantic_event_id, predecessor_semantic_event_id,
				connector_instance_id, session_value_digest, input_fingerprint,
				ruleset_fingerprint, chain_fingerprint, chain_id, chain_version,
				detected_chain_mask, enforcement_safe_chain_mask, denied_chain_mask,
				stable_action_id, severity, delivery_count, first_observed_time_unix_nano,
				last_observed_time_unix_nano, expires_time_unix_nano
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'HIGH', 1, ?, ?, ?)`,
			id, string(input.SemanticEventID), matches.EnforcementPredecessors[i],
			string(input.ConnectorInstanceID), session, input.InputFingerprint,
			input.RulesetFingerprint, chainFP, definition.ID, definition.Version,
			matches.DetectedMask, matches.EnforcementSafeMask, denied, stableAction,
			unixNano(now), unixNano(now), unixNano(now.Add(repo.receiptTTL)))
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func (repo *ToolChainRepository) prune(
	ctx context.Context,
	tx *sql.Tx,
	input ToolChainObserveInput,
	session string,
	sequence uint64,
	received, now time.Time,
) error {
	minSequence := uint64(1)
	if sequence >= repo.maxEvents {
		minSequence = sequence - repo.maxEvents + 1
	}
	statements := []struct {
		op, query string
		args      []any
	}{
		{"guardrail_chain_prune_receipts", `DELETE FROM guardrail_chain_deny_receipts
			WHERE rowid IN (
				SELECT rowid FROM guardrail_chain_deny_receipts
				WHERE expires_time_unix_nano<?
				ORDER BY expires_time_unix_nano, receipt_id LIMIT 64
			)`, []any{unixNano(now)}},
		{"guardrail_chain_prune_events", `DELETE FROM guardrail_chain_events
			WHERE connector_instance_id=? AND session_value_digest=?
			AND (sequence<? OR received_time_unix_nano<?)`,
			[]any{string(input.ConnectorInstanceID), session, minSequence,
				unixNano(received.Add(-repo.maxHorizon))}},
		{"guardrail_chain_prune_empty", `DELETE FROM guardrail_chain_partitions
			WHERE updated_time_unix_nano<? AND NOT EXISTS (
				SELECT 1 FROM guardrail_chain_events event
				WHERE event.connector_instance_id=guardrail_chain_partitions.connector_instance_id
				AND event.session_value_digest=guardrail_chain_partitions.session_value_digest)`,
			[]any{unixNano(now.Add(-repo.maxHorizon))}},
	}
	for _, statement := range statements {
		if _, err := txExecContextObserved(ctx, tx, statement.op,
			repo.store.sqliteBusyObservabilityV8(), statement.query, statement.args...); err != nil {
			return err
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM guardrail_chain_partitions`).Scan(&count); err != nil {
		return err
	}
	excess := count - repo.maxPartitions
	if excess <= 0 {
		return nil
	}
	_, err := txExecContextObserved(ctx, tx, "guardrail_chain_prune_lru",
		repo.store.sqliteBusyObservabilityV8(), `DELETE FROM guardrail_chain_partitions
		WHERE (connector_instance_id, session_value_digest) IN (
			SELECT connector_instance_id, session_value_digest
			FROM guardrail_chain_partitions
			WHERE NOT (connector_instance_id=? AND session_value_digest=?)
			ORDER BY updated_time_unix_nano, connector_instance_id, session_value_digest
			LIMIT ?)`,
		string(input.ConnectorInstanceID), session, excess)
	return err
}

func stableToolChainActionID(input ToolChainObserveInput, denied uint8) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(toolChainStableDomain))
	_, _ = hash.Write([]byte(input.SemanticEventID))
	_, _ = hash.Write([]byte(input.InputFingerprint))
	_, _ = hash.Write([]byte(input.RulesetFingerprint))
	_, _ = hash.Write([]byte{denied})
	return "gca_" + hex.EncodeToString(hash.Sum(nil))
}

func toolChainReceiptID(stableAction, chainID, predecessor string) string {
	sum := sha256.Sum256([]byte(
		toolChainReceiptDomain + stableAction + "\x00" + chainID + "\x00" + predecessor))
	return "gcr_" + hex.EncodeToString(sum[:])
}

func makeToolChainResult(
	status ToolChainObserveStatus,
	detected, enforcementSafe, denied uint8,
	stableAction string,
	receiptIDs []string,
	suppress bool,
) (ToolChainObserveResult, error) {
	detectedIDs, err := guardrail.ToolChainIDs(detected)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	enforcementIDs, err := guardrail.ToolChainIDs(enforcementSafe)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	deniedIDs, err := guardrail.ToolChainIDs(denied)
	if err != nil {
		return ToolChainObserveResult{}, err
	}
	return ToolChainObserveResult{
		Status: status, DetectedMask: detected, EnforcementSafeMask: enforcementSafe,
		DeniedMask: denied, DetectedChainIDs: detectedIDs,
		EnforcementSafeChainIDs: enforcementIDs, DeniedChainIDs: deniedIDs,
		StableActionID: stableAction, ReceiptIDs: append([]string(nil), receiptIDs...),
		SuppressTelemetry: suppress,
	}, nil
}

// AttachFinalization binds bounded downstream identifiers to exact deny
// receipts. Repeating the same values is idempotent; overwriting is rejected.
func (repo *ToolChainRepository) AttachFinalization(
	ctx context.Context,
	receiptIDs []string,
	evaluationID string,
	auditEventID string,
) error {
	if repo == nil || repo.store == nil {
		return errors.New("audit: tool-chain repository is not initialized")
	}
	if ctx == nil {
		return errors.New("audit: tool-chain context is required")
	}
	if len(receiptIDs) == 0 || len(receiptIDs) > guardrail.ToolChainCount {
		return errors.New("audit: invalid tool-chain receipt count")
	}
	if err := validateBoundedIdentifier("evaluation id", evaluationID, false, 512); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("audit event id", auditEventID, false, 512); err != nil {
		return err
	}
	if evaluationID == "" && auditEventID == "" {
		return errors.New("audit: tool-chain finalization identifier is required")
	}
	seen := make(map[string]struct{}, len(receiptIDs))
	for _, id := range receiptIDs {
		if !validPrefixedDigest(id, "gcr_") {
			return errors.New("audit: invalid tool-chain receipt id")
		}
		if _, exists := seen[id]; exists {
			return errors.New("audit: duplicate tool-chain receipt id")
		}
		seen[id] = struct{}{}
	}
	return retryBusyObserved(ctx, "guardrail_chain_attach_finalization",
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
			for _, id := range receiptIDs {
				var currentEvaluation, currentAudit sql.NullString
				err := tx.QueryRowContext(ctx, `SELECT evaluation_id, audit_event_id
					FROM guardrail_chain_deny_receipts WHERE receipt_id=?`, id).
					Scan(&currentEvaluation, &currentAudit)
				if errors.Is(err, sql.ErrNoRows) {
					return ErrToolChainConflict
				}
				if err != nil {
					return err
				}
				if (evaluationID != "" && currentEvaluation.Valid &&
					currentEvaluation.String != evaluationID) ||
					(auditEventID != "" && currentAudit.Valid &&
						currentAudit.String != auditEventID) {
					return ErrToolChainConflict
				}
				if _, err := txExecContextObserved(ctx, tx,
					"guardrail_chain_attach_finalization_receipt",
					repo.store.sqliteBusyObservabilityV8(), `UPDATE guardrail_chain_deny_receipts
						SET evaluation_id=COALESCE(evaluation_id, ?),
							audit_event_id=COALESCE(audit_event_id, ?)
						WHERE receipt_id=?`,
					nullStr(evaluationID), nullStr(auditEventID), id); err != nil {
					return err
				}
			}
			return tx.Commit()
		})
}

func validPrefixedDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && strings.ToLower(value) == value
}
