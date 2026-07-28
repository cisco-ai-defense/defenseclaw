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

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const (
	maxAlertCommandIdentifierBytes = observability.MaxCorrelationIDBytes
	alertCommandFingerprintDomain  = "defenseclaw.alert-acknowledgement.command-fingerprint.v1\x00"
	alertCommandFingerprintPrefix  = "hmac-sha256:v1:"
	alertCASRetryAttempts          = 5
)

// AlertDisposition is mutable review state kept outside immutable finding and
// event-history rows. An absent projection is Unreviewed at version zero.
type AlertDisposition string

const (
	AlertDispositionUnreviewed   AlertDisposition = "unreviewed"
	AlertDispositionAcknowledged AlertDisposition = "acknowledged"
	AlertDispositionDismissed    AlertDisposition = "dismissed"
)

// AlertAcknowledgementOutcome is the closed result vocabulary persisted in
// compliance.activity evidence.
type AlertAcknowledgementOutcome string

const (
	AlertAcknowledgementApplied  AlertAcknowledgementOutcome = "applied"
	AlertAcknowledgementNoChange AlertAcknowledgementOutcome = "no_change"
	AlertAcknowledgementRejected AlertAcknowledgementOutcome = "rejected"
)

// AlertAcknowledgementRejectionReason disambiguates stale CAS rejection from
// operation-ID payload conflicts. It is intentionally bounded and value-free.
type AlertAcknowledgementRejectionReason string

const (
	AlertAcknowledgementStaleVersion        AlertAcknowledgementRejectionReason = "stale_projection_version"
	AlertAcknowledgementIdempotencyConflict AlertAcknowledgementRejectionReason = "idempotency_conflict"
)

// AlertProjectionHealthCode is a bounded reconciliation failure vocabulary.
type AlertProjectionHealthCode string

const (
	AlertProjectionHealthVersionGap      AlertProjectionHealthCode = "version_gap"
	AlertProjectionHealthVersionConflict AlertProjectionHealthCode = "version_conflict"
	AlertProjectionHealthProjectionAhead AlertProjectionHealthCode = "projection_ahead"
)

// ErrAlertProjectionUnhealthy marks an alert whose immutable evidence cannot
// be replayed safely. Callers may use errors.Is without inspecting diagnostics.
var ErrAlertProjectionUnhealthy = errors.New("alert acknowledgement projection is unhealthy")

// ErrAlertTargetIneligible prevents acknowledgement state from being created
// for an arbitrary caller-supplied identifier that has no alert occurrence or
// pre-existing protected state.
var ErrAlertTargetIneligible = errors.New("alert acknowledgement target is not eligible")

// ErrAlertCommandFingerprintUnavailable is deliberately value-free. It covers
// missing/rotated key custody, signing failures, and malformed signer output
// without exposing signer diagnostics or normalized command material.
var ErrAlertCommandFingerprintUnavailable = errors.New("alert acknowledgement command fingerprint unavailable")

// errAlertProjectionCASRetry is private because callers must never observe a
// storage race. The outer operation rolls back and retries the whole command,
// which then records the normal stale/no-change compliance result.
var errAlertProjectionCASRetry = errors.New("retry alert acknowledgement compare-and-swap")

// AlertProjectionIntegrityError contains only a safe alert identifier and
// bounded code. It never includes event bodies or SQL diagnostics.
type AlertProjectionIntegrityError struct {
	AlertID string
	Code    AlertProjectionHealthCode
}

func (err *AlertProjectionIntegrityError) Error() string {
	return fmt.Sprintf("%v: alert %q: %s", ErrAlertProjectionUnhealthy, err.AlertID, err.Code)
}

func (err *AlertProjectionIntegrityError) Unwrap() error { return ErrAlertProjectionUnhealthy }

// AlertAcknowledgementCommand is one independently preconditioned target
// mutation. Bulk callers must supply and execute one command per alert.
type AlertAcknowledgementCommand struct {
	OperationID               string
	AlertID                   string
	Actor                     string
	Disposition               AlertDisposition
	ExpectedProjectionVersion int64
}

// AlertAcknowledgementResult is stable across an exact operation-ID retry.
type AlertAcknowledgementResult struct {
	OperationID               string
	AlertID                   string
	Disposition               AlertDisposition
	Actor                     string
	Outcome                   AlertAcknowledgementOutcome
	RejectionReason           AlertAcknowledgementRejectionReason
	ExpectedProjectionVersion int64
	ObservedProjectionVersion int64
	ProjectionVersionBefore   int64
	ProjectionVersionAfter    int64
	EventID                   string
	CreatedAt                 time.Time
	IdempotentReplay          bool
}

// AlertAcknowledgementProjection is the current query representation. Legacy
// provenance is explicit because ACK destroyed the original severity.
type AlertAcknowledgementProjection struct {
	AlertID                   string
	Disposition               AlertDisposition
	Actor                     string
	DispositionAt             time.Time
	ProjectionVersion         int64
	Source                    string
	SourceEventID             string
	LegacyOriginalSeverity    string
	LegacyTimestampProvenance string
	UpdatedAt                 time.Time
}

// AlertCanonicalEventInput is the storage-owned semantic event request. The
// compiled runtime factory must build a classified canonical record, resolve
// the effective local redaction profile, and project it with its current
// redaction engine. Control fields needed for replay must remain present in the
// local projection; the factory may redact governed actor data.
type AlertCanonicalEventInput struct {
	Bucket    observability.Bucket
	EventName observability.EventName
	Outcome   observability.Outcome
	AlertID   string
	Body      any
}

const redactedAlertActor = "redacted"

// AlertCanonicalEventFactory is the runtime-graph integration boundary. It
// builds the canonical record and trusted projection; EventHistoryWriter
// independently resolves the effective local profile and rejects mismatches.
type AlertCanonicalEventFactory interface {
	GraphDigest() string
	BuildAlertCanonicalEvent(
		context.Context,
		AlertCanonicalEventInput,
	) (observability.Record, observabilityredaction.Projection, error)
}

// AlertAcknowledgementWriter owns atomic mutable-projection operations while
// delegating canonical record construction and projection to the compiled
// runtime graph. There is intentionally no Store-only fallback.
type AlertAcknowledgementWriter struct {
	store        *Store
	eventHistory *EventHistoryWriter
	eventFactory AlertCanonicalEventFactory
}

func NewAlertAcknowledgementWriter(
	store *Store,
	eventHistory *EventHistoryWriter,
	eventFactory AlertCanonicalEventFactory,
) (*AlertAcknowledgementWriter, error) {
	if store == nil || store.db == nil || !store.Ready() {
		return nil, fmt.Errorf("audit: ready alert acknowledgement store is required")
	}
	if eventHistory == nil || eventHistory.store != store ||
		len(eventHistory.localProfiles) != len(observability.Buckets()) ||
		eventHistory.GraphDigest() == "" {
		return nil, fmt.Errorf("audit: alert acknowledgement event-history writer must use the same store and trusted profile resolver")
	}
	if eventFactory == nil {
		return nil, fmt.Errorf("audit: alert canonical event factory is required")
	}
	if eventFactory.GraphDigest() == "" || eventFactory.GraphDigest() != eventHistory.GraphDigest() {
		return nil, fmt.Errorf("audit: alert canonical event factory belongs to a different runtime graph")
	}
	if eventHistory.signer == nil || !validAlertFingerprintKeyID(eventHistory.signer.KeyID()) {
		return nil, ErrAlertCommandFingerprintUnavailable
	}
	return &AlertAcknowledgementWriter{
		store: store, eventHistory: eventHistory, eventFactory: eventFactory,
	}, nil
}

type normalizedAlertCommand struct {
	operationID     string
	alertID         string
	actor           string
	disposition     AlertDisposition
	expectedVersion int64
	fingerprint     string
}

type alertComplianceBody struct {
	Target                    string                              `json:"target"`
	OperationID               string                              `json:"operation_id"`
	TargetEventID             string                              `json:"target_event_id"`
	RequestedDisposition      AlertDisposition                    `json:"requested_disposition"`
	Actor                     string                              `json:"actor"`
	Outcome                   AlertAcknowledgementOutcome         `json:"outcome"`
	RejectionReason           AlertAcknowledgementRejectionReason `json:"rejection_reason,omitempty"`
	ExpectedProjectionVersion int64                               `json:"expected_projection_version"`
	ObservedProjectionVersion int64                               `json:"observed_projection_version"`
	ProjectionVersionBefore   int64                               `json:"projection_version_before"`
	ProjectionVersionAfter    int64                               `json:"projection_version_after"`
}

type alertAppliedEvidence struct {
	operationID   string
	eventID       string
	timestamp     time.Time
	disposition   AlertDisposition
	actor         string
	expected      int64
	observed      int64
	versionBefore int64
	versionAfter  int64
}

type alertProjectionHealthBody struct {
	Target  string                    `json:"target"`
	AlertID string                    `json:"alert_id"`
	Code    AlertProjectionHealthCode `json:"code"`
}

// ApplyAlertAcknowledgement performs one transactional operation-ID check,
// evidence reconciliation, compliance append, and conditional N -> N+1 CAS.
func (writer *AlertAcknowledgementWriter) ApplyAlertAcknowledgement(
	ctx context.Context,
	command AlertAcknowledgementCommand,
) (AlertAcknowledgementResult, error) {
	var result AlertAcknowledgementResult
	var err error
	for attempt := 0; attempt < alertCASRetryAttempts; attempt++ {
		err = retryBusy(ctx, "alert_acknowledgement_transaction", func() error {
			var attemptErr error
			result, attemptErr = writer.applyAlertAcknowledgementOnce(ctx, command)
			return attemptErr
		})
		if !errors.Is(err, errAlertProjectionCASRetry) {
			break
		}
		if ctx == nil {
			break
		}
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
			break
		}
	}
	if errors.Is(err, errAlertProjectionCASRetry) {
		err = errors.New("audit: alert acknowledgement projection ownership unavailable")
	}
	if err != nil {
		if writer != nil && writer.eventHistory != nil {
			writer.eventHistory.reportAppendError(err)
		}
		return AlertAcknowledgementResult{}, err
	}
	return result, nil
}

func (writer *AlertAcknowledgementWriter) applyAlertAcknowledgementOnce(
	ctx context.Context,
	command AlertAcknowledgementCommand,
) (AlertAcknowledgementResult, error) {
	if writer == nil || writer.store == nil || writer.eventHistory == nil || writer.eventFactory == nil {
		return AlertAcknowledgementResult{}, fmt.Errorf("audit: alert acknowledgement writer is not initialized")
	}
	s := writer.store
	if ctx == nil {
		return AlertAcknowledgementResult{}, fmt.Errorf("audit: alert acknowledgement context is required")
	}
	if err := ctx.Err(); err != nil {
		return AlertAcknowledgementResult{}, err
	}
	normalized, err := normalizeAlertCommand(command)
	if err != nil {
		return AlertAcknowledgementResult{}, err
	}
	if err := writer.fingerprintAlertCommand(ctx, &normalized); err != nil {
		return AlertAcknowledgementResult{}, err
	}
	release, err := s.acquireReady()
	if err != nil {
		return AlertAcknowledgementResult{}, err
	}
	released := false
	releaseStore := func() {
		if !released {
			released = true
			release()
		}
	}
	defer releaseStore()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertAcknowledgementResult{}, fmt.Errorf("audit: begin alert acknowledgement: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	existing, existingFingerprint, found, err := lookupAlertOperation(ctx, tx, normalized.operationID)
	if err != nil {
		return AlertAcknowledgementResult{}, err
	}
	if found {
		existingKeyID, valid := alertFingerprintKeyID(existingFingerprint)
		if !valid || existingKeyID != writer.eventHistory.signer.KeyID() {
			return AlertAcknowledgementResult{}, ErrAlertCommandFingerprintUnavailable
		}
		if subtle.ConstantTimeCompare([]byte(existingFingerprint), []byte(normalized.fingerprint)) == 1 {
			if err := tx.Commit(); err != nil {
				return AlertAcknowledgementResult{}, fmt.Errorf("audit: commit alert acknowledgement retry: %w", err)
			}
			existing.IdempotentReplay = true
			return existing, nil
		}
		// A conflicting reuse is audited only for a real alert target. This
		// keeps arbitrary caller-supplied identifiers from creating compliance
		// history merely by colliding with a known operation ID.
		if err := requireEligibleAlertTarget(ctx, tx, normalized.alertID); err != nil {
			return AlertAcknowledgementResult{}, err
		}
		result, appendOutcome, err := writer.recordAlertIdempotencyConflict(ctx, tx, normalized)
		if err != nil {
			return AlertAcknowledgementResult{}, err
		}
		if err := writer.eventHistory.commitAppendTransaction(tx, appendOutcome); err != nil {
			releaseStore()
			writer.eventHistory.flushHealth()
			return AlertAcknowledgementResult{}, fmt.Errorf("audit: commit alert acknowledgement conflict: %w", err)
		}
		releaseStore()
		writer.eventHistory.flushHealth()
		return result, nil
	}
	if err := requireEligibleAlertTarget(ctx, tx, normalized.alertID); err != nil {
		return AlertAcknowledgementResult{}, err
	}

	projection, integrityErr, err := reconcileAlertTx(ctx, tx, normalized.alertID)
	if err != nil {
		return AlertAcknowledgementResult{}, err
	}
	if integrityErr != nil {
		appendOutcome, err := writer.appendAlertProjectionHealth(ctx, tx, normalized.alertID, integrityErr.Code)
		if err != nil {
			return AlertAcknowledgementResult{}, err
		}
		if err := writer.eventHistory.commitAppendTransaction(tx, appendOutcome); err != nil {
			releaseStore()
			writer.eventHistory.flushHealth()
			return AlertAcknowledgementResult{}, fmt.Errorf("audit: commit alert projection health: %w", err)
		}
		releaseStore()
		writer.eventHistory.flushHealth()
		return AlertAcknowledgementResult{}, integrityErr
	}

	result := AlertAcknowledgementResult{
		OperationID:               normalized.operationID,
		AlertID:                   normalized.alertID,
		Disposition:               normalized.disposition,
		Actor:                     normalized.actor,
		ExpectedProjectionVersion: normalized.expectedVersion,
		ObservedProjectionVersion: projection.ProjectionVersion,
		ProjectionVersionBefore:   projection.ProjectionVersion,
		ProjectionVersionAfter:    projection.ProjectionVersion,
	}
	switch {
	case projection.Disposition == normalized.disposition:
		result.Outcome = AlertAcknowledgementNoChange
	case normalized.expectedVersion != projection.ProjectionVersion:
		result.Outcome = AlertAcknowledgementRejected
		result.RejectionReason = AlertAcknowledgementStaleVersion
	default:
		result.Outcome = AlertAcknowledgementApplied
		result.ProjectionVersionAfter = projection.ProjectionVersion + 1
	}
	body := alertComplianceBodyFromResult(result)
	eventName := alertCommandEventName(normalized.disposition)
	appended, err := writer.appendAlertCanonicalEvent(ctx, tx, AlertCanonicalEventInput{
		Bucket: observability.BucketComplianceActivity, EventName: eventName,
		Outcome: observability.Outcome(result.Outcome), AlertID: normalized.alertID, Body: body,
	})
	if err != nil {
		return AlertAcknowledgementResult{}, err
	}
	result.EventID = appended.record.RecordID()
	result.CreatedAt = appended.record.Timestamp()
	result.Actor = projectedAlertActor(appended.body)
	if result.Outcome == AlertAcknowledgementApplied {
		if err := applyAlertProjectionCAS(ctx, tx, projection, result); err != nil {
			return AlertAcknowledgementResult{}, err
		}
	}
	if err := insertAlertOperation(ctx, tx, normalized.fingerprint, result); err != nil {
		return AlertAcknowledgementResult{}, err
	}
	if err := writer.eventHistory.commitAppendTransaction(tx, appended.historyOutcome); err != nil {
		releaseStore()
		writer.eventHistory.flushHealth()
		return AlertAcknowledgementResult{}, fmt.Errorf("audit: commit alert acknowledgement: %w", err)
	}
	releaseStore()
	writer.eventHistory.flushHealth()
	return result, nil
}

func requireEligibleAlertTarget(ctx context.Context, tx *sql.Tx, alertID string) error {
	var protectedState int
	if err := tx.QueryRowContext(ctx, `
		SELECT CASE WHEN
			EXISTS(SELECT 1 FROM alert_acknowledgement_projection WHERE alert_id=?) OR
			EXISTS(SELECT 1 FROM alert_acknowledgement_operations WHERE alert_id=?) OR
			EXISTS(SELECT 1 FROM alert_acknowledgement_baselines WHERE alert_id=?) OR
			EXISTS(SELECT 1 FROM alert_acknowledgement_health WHERE alert_id=?)
		THEN 1 ELSE 0 END`, alertID, alertID, alertID, alertID).Scan(&protectedState); err != nil {
		return fmt.Errorf("audit: inspect alert target state: %w", err)
	}
	if protectedState == 1 {
		return nil
	}
	var bucket, eventName, action, severity sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT bucket, event_name, action, severity FROM audit_events WHERE id=?`, alertID).
		Scan(&bucket, &eventName, &action, &severity)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAlertTargetIneligible
	}
	if err != nil {
		return fmt.Errorf("audit: inspect alert target occurrence: %w", err)
	}
	if bucket.Valid {
		if bucket.String == string(observability.BucketSecurityFinding) &&
			eventName.String == "finding.observed" {
			return nil
		}
		return ErrAlertTargetIneligible
	}
	if !legacyAlertActionEligible(action.String) {
		return ErrAlertTargetIneligible
	}
	switch strings.ToUpper(strings.TrimSpace(severity.String)) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "INFO":
		return nil
	default:
		return ErrAlertTargetIneligible
	}
}

// ReconcileAlertAcknowledgement replays the gap-free applied sequence and
// repairs a missing or stale projection in the same transaction. Ambiguous
// evidence is recorded as mandatory health and returned as a fail-closed error.
func (writer *AlertAcknowledgementWriter) ReconcileAlertAcknowledgement(
	ctx context.Context,
	alertID string,
) (AlertAcknowledgementProjection, error) {
	var projection AlertAcknowledgementProjection
	err := retryBusy(ctx, "alert_acknowledgement_reconcile", func() error {
		var attemptErr error
		projection, attemptErr = writer.reconcileAlertAcknowledgementOnce(ctx, alertID)
		return attemptErr
	})
	if err != nil {
		if writer != nil && writer.eventHistory != nil {
			writer.eventHistory.reportAppendError(err)
		}
		return AlertAcknowledgementProjection{}, err
	}
	return projection, nil
}

func (writer *AlertAcknowledgementWriter) reconcileAlertAcknowledgementOnce(
	ctx context.Context,
	alertID string,
) (AlertAcknowledgementProjection, error) {
	if writer == nil || writer.store == nil || writer.eventHistory == nil || writer.eventFactory == nil {
		return AlertAcknowledgementProjection{}, fmt.Errorf("audit: alert acknowledgement writer is not initialized")
	}
	s := writer.store
	if ctx == nil {
		return AlertAcknowledgementProjection{}, fmt.Errorf("audit: alert acknowledgement context is required")
	}
	alertID = strings.TrimSpace(alertID)
	if err := validateAlertCommandIdentifier("alert ID", alertID); err != nil {
		return AlertAcknowledgementProjection{}, err
	}
	release, err := s.acquireReady()
	if err != nil {
		return AlertAcknowledgementProjection{}, err
	}
	released := false
	releaseStore := func() {
		if !released {
			released = true
			release()
		}
	}
	defer releaseStore()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertAcknowledgementProjection{}, fmt.Errorf("audit: begin alert acknowledgement reconciliation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	projection, integrityErr, err := reconcileAlertTx(ctx, tx, alertID)
	if err != nil {
		return AlertAcknowledgementProjection{}, err
	}
	if integrityErr != nil {
		appendOutcome, err := writer.appendAlertProjectionHealth(ctx, tx, alertID, integrityErr.Code)
		if err != nil {
			return AlertAcknowledgementProjection{}, err
		}
		if err := writer.eventHistory.commitAppendTransaction(tx, appendOutcome); err != nil {
			releaseStore()
			writer.eventHistory.flushHealth()
			return AlertAcknowledgementProjection{}, fmt.Errorf("audit: commit alert projection health: %w", err)
		}
		releaseStore()
		writer.eventHistory.flushHealth()
		return AlertAcknowledgementProjection{}, integrityErr
	}
	if err := tx.Commit(); err != nil {
		return AlertAcknowledgementProjection{}, fmt.Errorf("audit: commit alert acknowledgement reconciliation: %w", err)
	}
	return projection, nil
}

func normalizeAlertCommand(command AlertAcknowledgementCommand) (normalizedAlertCommand, error) {
	normalized := normalizedAlertCommand{
		operationID:     strings.TrimSpace(command.OperationID),
		alertID:         strings.TrimSpace(command.AlertID),
		actor:           strings.TrimSpace(command.Actor),
		disposition:     AlertDisposition(strings.ToLower(strings.TrimSpace(string(command.Disposition)))),
		expectedVersion: command.ExpectedProjectionVersion,
	}
	for field, value := range map[string]string{
		"operation ID": normalized.operationID,
		"alert ID":     normalized.alertID,
		"actor":        normalized.actor,
	} {
		if err := validateAlertCommandIdentifier(field, value); err != nil {
			return normalizedAlertCommand{}, err
		}
	}
	if normalized.disposition != AlertDispositionAcknowledged && normalized.disposition != AlertDispositionDismissed {
		return normalizedAlertCommand{}, fmt.Errorf("audit: requested alert disposition must be acknowledged or dismissed")
	}
	if normalized.expectedVersion < 0 {
		return normalizedAlertCommand{}, fmt.Errorf("audit: expected alert projection version must not be negative")
	}
	return normalized, nil
}

func (writer *AlertAcknowledgementWriter) fingerprintAlertCommand(
	ctx context.Context,
	command *normalizedAlertCommand,
) error {
	if writer == nil || writer.eventHistory == nil || writer.eventHistory.signer == nil || command == nil {
		return ErrAlertCommandFingerprintUnavailable
	}
	keyID := writer.eventHistory.signer.KeyID()
	if !validAlertFingerprintKeyID(keyID) {
		return ErrAlertCommandFingerprintUnavailable
	}
	message, err := alertCommandFingerprintMessage(*command)
	if err != nil {
		return ErrAlertCommandFingerprintUnavailable
	}
	digest, signErr := writer.eventHistory.signer.HMACSHA256(ctx, message)
	for index := range message {
		message[index] = 0
	}
	if signErr != nil {
		for index := range digest {
			digest[index] = 0
		}
		if ctx != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
		}
		return ErrAlertCommandFingerprintUnavailable
	}
	if len(digest) != sha256.Size {
		for index := range digest {
			digest[index] = 0
		}
		return ErrAlertCommandFingerprintUnavailable
	}
	command.fingerprint = alertCommandFingerprintPrefix + keyID + ":" + hex.EncodeToString(digest)
	for index := range digest {
		digest[index] = 0
	}
	return nil
}

func alertCommandFingerprintMessage(command normalizedAlertCommand) ([]byte, error) {
	fingerprintInput := struct {
		OperationID     string           `json:"operation_id"`
		AlertID         string           `json:"alert_id"`
		Actor           string           `json:"actor"`
		Disposition     AlertDisposition `json:"disposition"`
		ExpectedVersion int64            `json:"expected_projection_version"`
	}{command.operationID, command.alertID, command.actor, command.disposition, command.expectedVersion}
	encoded, err := json.Marshal(fingerprintInput)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(alertCommandFingerprintDomain)+len(encoded))
	message = append(message, alertCommandFingerprintDomain...)
	message = append(message, encoded...)
	for index := range encoded {
		encoded[index] = 0
	}
	return message, nil
}

func validAlertFingerprintKeyID(keyID string) bool {
	return observability.IsStableToken(keyID) && len(keyID) <= maxAlertCommandIdentifierBytes
}

func alertFingerprintKeyID(fingerprint string) (string, bool) {
	if !strings.HasPrefix(fingerprint, alertCommandFingerprintPrefix) {
		return "", false
	}
	remainder := strings.TrimPrefix(fingerprint, alertCommandFingerprintPrefix)
	separator := strings.IndexByte(remainder, ':')
	if separator <= 0 || separator == len(remainder)-1 {
		return "", false
	}
	keyID, encodedDigest := remainder[:separator], remainder[separator+1:]
	if !validAlertFingerprintKeyID(keyID) || len(encodedDigest) != sha256.Size*2 {
		return "", false
	}
	digest, err := hex.DecodeString(encodedDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != encodedDigest {
		return "", false
	}
	return keyID, true
}

func validateAlertCommandIdentifier(field, value string) error {
	if value == "" {
		return fmt.Errorf("audit: %s is required", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("audit: %s must be valid UTF-8", field)
	}
	if len(value) > maxAlertCommandIdentifierBytes {
		return fmt.Errorf("audit: %s exceeds %d bytes", field, maxAlertCommandIdentifierBytes)
	}
	return nil
}

func lookupAlertOperation(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
) (AlertAcknowledgementResult, string, bool, error) {
	var result AlertAcknowledgementResult
	var disposition, outcome, reason, fingerprint, createdAt string
	err := tx.QueryRowContext(ctx, `
		SELECT operation_id, alert_id, requested_disposition, actor, outcome,
			COALESCE(rejection_reason,''), expected_projection_version,
			observed_projection_version, projection_version_before,
			projection_version_after, event_id, created_at, command_fingerprint
		FROM alert_acknowledgement_operations WHERE operation_id = ?`, operationID).Scan(
		&result.OperationID, &result.AlertID, &disposition, &result.Actor, &outcome,
		&reason, &result.ExpectedProjectionVersion, &result.ObservedProjectionVersion,
		&result.ProjectionVersionBefore, &result.ProjectionVersionAfter,
		&result.EventID, &createdAt, &fingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertAcknowledgementResult{}, "", false, nil
	}
	if err != nil {
		return AlertAcknowledgementResult{}, "", false, fmt.Errorf("audit: read alert operation: %w", err)
	}
	result.Disposition = AlertDisposition(disposition)
	result.Outcome = AlertAcknowledgementOutcome(outcome)
	result.RejectionReason = AlertAcknowledgementRejectionReason(reason)
	result.CreatedAt, err = parseAlertProjectionTime(createdAt)
	if err != nil {
		return AlertAcknowledgementResult{}, "", false, err
	}
	return result, fingerprint, true, nil
}

func (writer *AlertAcknowledgementWriter) recordAlertIdempotencyConflict(
	ctx context.Context,
	tx *sql.Tx,
	command normalizedAlertCommand,
) (AlertAcknowledgementResult, eventHistoryAppendOutcome, error) {
	projection, found, err := readAlertProjection(ctx, tx, command.alertID)
	if err != nil {
		return AlertAcknowledgementResult{}, eventHistoryAppendOutcome{}, err
	}
	if !found {
		projection = AlertAcknowledgementProjection{
			AlertID: command.alertID, Disposition: AlertDispositionUnreviewed,
		}
	}
	result := AlertAcknowledgementResult{
		OperationID:               command.operationID,
		AlertID:                   command.alertID,
		Disposition:               command.disposition,
		Actor:                     command.actor,
		Outcome:                   AlertAcknowledgementRejected,
		RejectionReason:           AlertAcknowledgementIdempotencyConflict,
		ExpectedProjectionVersion: command.expectedVersion,
		ObservedProjectionVersion: projection.ProjectionVersion,
		ProjectionVersionBefore:   projection.ProjectionVersion,
		ProjectionVersionAfter:    projection.ProjectionVersion,
	}
	body := alertComplianceBodyFromResult(result)
	appended, err := writer.appendAlertCanonicalEvent(ctx, tx, AlertCanonicalEventInput{
		Bucket:    observability.BucketComplianceActivity,
		EventName: alertCommandEventName(command.disposition),
		Outcome:   observability.OutcomeRejected, AlertID: command.alertID, Body: body,
	})
	if err != nil {
		return AlertAcknowledgementResult{}, eventHistoryAppendOutcome{}, err
	}
	result.EventID = appended.record.RecordID()
	result.CreatedAt = appended.record.Timestamp()
	result.Actor = projectedAlertActor(appended.body)
	return result, appended.historyOutcome, nil
}

func reconcileAlertTx(
	ctx context.Context,
	tx *sql.Tx,
	alertID string,
) (AlertAcknowledgementProjection, *AlertProjectionIntegrityError, error) {
	if err := ensureLegacyAlertBaseline(ctx, tx, alertID); err != nil {
		return AlertAcknowledgementProjection{}, nil, err
	}
	expected, err := replayAlertEvidence(ctx, tx, alertID)
	if err != nil {
		var integrityErr *AlertProjectionIntegrityError
		if errors.As(err, &integrityErr) {
			return AlertAcknowledgementProjection{}, integrityErr, nil
		}
		return AlertAcknowledgementProjection{}, nil, err
	}
	stored, found, err := readAlertProjection(ctx, tx, alertID)
	if err != nil {
		return AlertAcknowledgementProjection{}, nil, err
	}
	if found && stored.ProjectionVersion > expected.ProjectionVersion {
		return AlertAcknowledgementProjection{}, &AlertProjectionIntegrityError{
			AlertID: alertID, Code: AlertProjectionHealthProjectionAhead,
		}, nil
	}
	if expected.ProjectionVersion == 0 {
		if found {
			return AlertAcknowledgementProjection{}, &AlertProjectionIntegrityError{
				AlertID: alertID, Code: AlertProjectionHealthProjectionAhead,
			}, nil
		}
		if err := clearAlertProjectionHealth(ctx, tx, alertID); err != nil {
			return AlertAcknowledgementProjection{}, nil, err
		}
		return expected, nil, nil
	}
	if !found || !sameAlertProjection(stored, expected) {
		if err := replaceAlertProjection(ctx, tx, expected); err != nil {
			return AlertAcknowledgementProjection{}, nil, err
		}
	}
	if err := clearAlertProjectionHealth(ctx, tx, alertID); err != nil {
		return AlertAcknowledgementProjection{}, nil, err
	}
	return expected, nil, nil
}

func ensureLegacyAlertBaseline(ctx context.Context, tx *sql.Tx, alertID string) error {
	var eventID, action, actor, timestamp string
	err := tx.QueryRowContext(ctx, `
		SELECT id, action, COALESCE(NULLIF(actor,''),'unknown'), timestamp
		FROM audit_events
		WHERE id = ? AND bucket IS NULL AND UPPER(COALESCE(severity,'')) = 'ACK'
		  AND action NOT IN ('acknowledge-alerts','dismiss-alerts','dismiss-alert')`, alertID).
		Scan(&eventID, &action, &actor, &timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit: read legacy alert acknowledgement baseline: %w", err)
	}
	if !legacyAlertActionEligible(action) {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO alert_acknowledgement_baselines (
			alert_id, baseline_version, disposition, actor, disposition_at,
			legacy_event_id, raw_legacy_severity, legacy_original_severity,
			timestamp_provenance, created_at
		) VALUES (?, 1, 'acknowledged', ?, ?, ?, 'ACK', 'unknown',
			'legacy_occurrence_timestamp_unreliable', ?)`,
		alertID, actor, timestamp, eventID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("audit: persist legacy alert acknowledgement baseline: %w", err)
	}
	return nil
}

// materializeLegacyAlertAcknowledgementBaselines is intentionally replayed on
// every current startup. A rollback binary can write a new legacy ACK after the
// one-time schema migration, and v8 must capture it before normal retention can
// remove the source occurrence.
func materializeLegacyAlertAcknowledgementBaselines(ex dbExecer) error {
	for _, table := range []string{
		"audit_events", "alert_acknowledgement_baselines", "alert_acknowledgement_projection",
	} {
		present, err := tableExists(ex, table)
		if err != nil || !present {
			return err
		}
	}
	eligibleActions := legacyAlertEligibleActions()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(eligibleActions)), ",")
	arguments := make([]any, len(eligibleActions))
	for index, action := range eligibleActions {
		arguments[index] = action
	}
	_, err := ex.Exec(fmt.Sprintf(`
		INSERT OR IGNORE INTO alert_acknowledgement_baselines (
			alert_id, baseline_version, disposition, actor, disposition_at,
			legacy_event_id, raw_legacy_severity, legacy_original_severity,
			timestamp_provenance, created_at
		)
		SELECT id, 1, 'acknowledged', COALESCE(NULLIF(actor,''), 'unknown'), timestamp,
			id, 'ACK', 'unknown', 'legacy_occurrence_timestamp_unreliable', CURRENT_TIMESTAMP
		FROM audit_events
		WHERE bucket IS NULL AND UPPER(COALESCE(severity,'')) = 'ACK'
		  AND action IN (%s);

		INSERT OR IGNORE INTO alert_acknowledgement_projection (
			alert_id, disposition, actor, disposition_at, projection_version,
			source, source_event_id, updated_at
		)
		SELECT alert_id, disposition, actor, disposition_at, baseline_version,
			'legacy_ack', legacy_event_id, CURRENT_TIMESTAMP
		FROM alert_acknowledgement_baselines;
	`, placeholders), arguments...)
	if err != nil {
		return fmt.Errorf("audit: materialize legacy alert acknowledgement baselines: %w", err)
	}
	return nil
}

func legacyAlertActionEligible(action string) bool {
	action = strings.TrimSpace(action)
	if strings.EqualFold(action, string(ActionAlert)) {
		return true
	}
	classification, classified := observability.AuditActionClassification(
		observability.ProducerKey(action),
	)
	return classified && classification.Bucket == observability.BucketSecurityFinding
}

func legacyAlertEligibleActions() []string {
	actions := []string{string(ActionAlert)}
	for _, key := range observability.ClassificationKeys(observability.ProducerAuditAction) {
		classification, found := observability.AuditActionClassification(key)
		if found && classification.Bucket == observability.BucketSecurityFinding {
			actions = append(actions, string(key))
		}
	}
	return actions
}

func replayAlertEvidence(
	ctx context.Context,
	tx *sql.Tx,
	alertID string,
) (AlertAcknowledgementProjection, error) {
	projection := AlertAcknowledgementProjection{
		AlertID: alertID, Disposition: AlertDispositionUnreviewed,
	}
	var baselineVersion int64
	var baselineDisposition, baselineActor, baselineAt, baselineEventID, originalSeverity, timestampProvenance string
	err := tx.QueryRowContext(ctx, `
		SELECT baseline_version, disposition, actor, disposition_at, legacy_event_id,
			legacy_original_severity, timestamp_provenance
		FROM alert_acknowledgement_baselines WHERE alert_id = ?`, alertID).Scan(
		&baselineVersion, &baselineDisposition, &baselineActor, &baselineAt, &baselineEventID,
		&originalSeverity, &timestampProvenance,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return projection, fmt.Errorf("audit: read alert acknowledgement baseline: %w", err)
	}
	if err == nil {
		dispositionAt, parseErr := parseAlertProjectionTime(baselineAt)
		if parseErr != nil {
			return projection, parseErr
		}
		projection = AlertAcknowledgementProjection{
			AlertID: alertID, Disposition: AlertDisposition(baselineDisposition),
			Actor: baselineActor, DispositionAt: dispositionAt,
			ProjectionVersion: baselineVersion, Source: "legacy_ack",
			SourceEventID: baselineEventID, LegacyOriginalSeverity: originalSeverity,
			LegacyTimestampProvenance: timestampProvenance, UpdatedAt: dispositionAt,
		}
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT operation.operation_id, operation.event_id, operation.created_at,
			operation.requested_disposition, operation.actor,
			operation.expected_projection_version, operation.observed_projection_version,
			operation.projection_version_before, operation.projection_version_after,
			event.id, event.bucket, event.event_name, event.target, event.payload_json
		FROM alert_acknowledgement_operations AS operation
		LEFT JOIN audit_events AS event ON event.id = operation.event_id
		WHERE operation.alert_id = ? AND operation.outcome = 'applied'
		ORDER BY operation.projection_version_after, operation.event_id`, alertID)
	if err != nil {
		return projection, fmt.Errorf("audit: read alert acknowledgement receipts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item alertAppliedEvidence
		var timestamp, disposition string
		var retainedID, retainedBucket, retainedEventName, retainedTarget, retainedPayload sql.NullString
		if err := rows.Scan(
			&item.operationID, &item.eventID, &timestamp, &disposition, &item.actor,
			&item.expected, &item.observed, &item.versionBefore, &item.versionAfter,
			&retainedID, &retainedBucket,
			&retainedEventName, &retainedTarget, &retainedPayload,
		); err != nil {
			return projection, fmt.Errorf("audit: scan alert acknowledgement receipt: %w", err)
		}
		item.disposition = AlertDisposition(disposition)
		if item.disposition != AlertDispositionAcknowledged &&
			item.disposition != AlertDispositionDismissed {
			return projection, &AlertProjectionIntegrityError{
				AlertID: alertID, Code: AlertProjectionHealthVersionConflict,
			}
		}
		item.timestamp, err = parseAlertProjectionTime(timestamp)
		if err != nil {
			return projection, err
		}
		if item.actor == "" {
			return projection, &AlertProjectionIntegrityError{
				AlertID: alertID, Code: AlertProjectionHealthVersionConflict,
			}
		}
		if item.expected != item.versionBefore || item.observed != item.versionBefore {
			return projection, &AlertProjectionIntegrityError{
				AlertID: alertID, Code: AlertProjectionHealthVersionConflict,
			}
		}
		if err := validateJoinedAlertEventReceipt(
			alertID, item, retainedID, retainedBucket, retainedEventName, retainedTarget, retainedPayload,
		); err != nil {
			return projection, err
		}
		if item.versionAfter <= projection.ProjectionVersion {
			return projection, &AlertProjectionIntegrityError{
				AlertID: alertID, Code: AlertProjectionHealthVersionConflict,
			}
		}
		if item.versionBefore != projection.ProjectionVersion || item.versionAfter != item.versionBefore+1 {
			code := AlertProjectionHealthVersionGap
			if item.versionAfter == projection.ProjectionVersion+1 {
				code = AlertProjectionHealthVersionConflict
			}
			return projection, &AlertProjectionIntegrityError{AlertID: alertID, Code: code}
		}
		projection.Disposition = item.disposition
		projection.Actor = item.actor
		projection.DispositionAt = item.timestamp
		projection.ProjectionVersion = item.versionAfter
		projection.Source = "modern"
		projection.SourceEventID = item.eventID
		projection.UpdatedAt = item.timestamp
	}
	if err := rows.Err(); err != nil {
		return projection, fmt.Errorf("audit: iterate alert acknowledgement evidence: %w", err)
	}
	return projection, nil
}

func validateJoinedAlertEventReceipt(
	alertID string,
	receipt alertAppliedEvidence,
	retainedID sql.NullString,
	bucket sql.NullString,
	eventName sql.NullString,
	target sql.NullString,
	payload sql.NullString,
) error {
	if !retainedID.Valid {
		// Event history is retention-bound; the protected receipt remains the
		// state-machine authority after its audit representation ages out.
		return nil
	}
	if retainedID.String != receipt.eventID || !bucket.Valid || !eventName.Valid || !target.Valid || !payload.Valid {
		return &AlertProjectionIntegrityError{AlertID: alertID, Code: AlertProjectionHealthVersionConflict}
	}
	var body alertComplianceBody
	decoder := json.NewDecoder(strings.NewReader(payload.String))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return &AlertProjectionIntegrityError{AlertID: alertID, Code: AlertProjectionHealthVersionConflict}
	}
	wantEventName := string(alertCommandEventName(receipt.disposition))
	eventActor := body.Actor
	if eventActor == "" {
		eventActor = redactedAlertActor
	}
	if bucket.String != string(observability.BucketComplianceActivity) || eventName.String != wantEventName ||
		target.String != alertID || body.Target != alertID || body.TargetEventID != alertID ||
		body.OperationID != receipt.operationID ||
		body.RequestedDisposition != receipt.disposition || body.Outcome != AlertAcknowledgementApplied ||
		body.ExpectedProjectionVersion != receipt.expected ||
		body.ObservedProjectionVersion != receipt.observed ||
		body.ProjectionVersionBefore != receipt.versionBefore ||
		body.ProjectionVersionAfter != receipt.versionAfter || eventActor != receipt.actor {
		return &AlertProjectionIntegrityError{AlertID: alertID, Code: AlertProjectionHealthVersionConflict}
	}
	return nil
}

func readAlertProjection(
	ctx context.Context,
	tx *sql.Tx,
	alertID string,
) (AlertAcknowledgementProjection, bool, error) {
	var projection AlertAcknowledgementProjection
	var disposition, dispositionAt, updatedAt string
	err := tx.QueryRowContext(ctx, `
		SELECT alert_id, disposition, actor, disposition_at, projection_version,
			source, source_event_id, updated_at
		FROM alert_acknowledgement_projection WHERE alert_id = ?`, alertID).Scan(
		&projection.AlertID, &disposition, &projection.Actor, &dispositionAt,
		&projection.ProjectionVersion, &projection.Source, &projection.SourceEventID, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertAcknowledgementProjection{}, false, nil
	}
	if err != nil {
		return AlertAcknowledgementProjection{}, false, fmt.Errorf("audit: read alert acknowledgement projection: %w", err)
	}
	projection.Disposition = AlertDisposition(disposition)
	projection.DispositionAt, err = parseAlertProjectionTime(dispositionAt)
	if err != nil {
		return AlertAcknowledgementProjection{}, false, err
	}
	projection.UpdatedAt, err = parseAlertProjectionTime(updatedAt)
	if err != nil {
		return AlertAcknowledgementProjection{}, false, err
	}
	if projection.Source == "legacy_ack" {
		err = tx.QueryRowContext(ctx, `
			SELECT legacy_original_severity, timestamp_provenance
			FROM alert_acknowledgement_baselines WHERE alert_id = ?`, alertID).
			Scan(&projection.LegacyOriginalSeverity, &projection.LegacyTimestampProvenance)
		if err != nil {
			return AlertAcknowledgementProjection{}, false, fmt.Errorf("audit: read alert legacy provenance: %w", err)
		}
	}
	return projection, true, nil
}

func sameAlertProjection(a, b AlertAcknowledgementProjection) bool {
	return a.AlertID == b.AlertID && a.Disposition == b.Disposition && a.Actor == b.Actor &&
		a.DispositionAt.Equal(b.DispositionAt) && a.ProjectionVersion == b.ProjectionVersion &&
		a.Source == b.Source && a.SourceEventID == b.SourceEventID
}

func replaceAlertProjection(ctx context.Context, tx *sql.Tx, projection AlertAcknowledgementProjection) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_acknowledgement_projection (
			alert_id, disposition, actor, disposition_at, projection_version,
			source, source_event_id, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(alert_id) DO UPDATE SET
			disposition=excluded.disposition, actor=excluded.actor,
			disposition_at=excluded.disposition_at,
			projection_version=excluded.projection_version, source=excluded.source,
			source_event_id=excluded.source_event_id, updated_at=excluded.updated_at`,
		projection.AlertID, projection.Disposition, projection.Actor,
		projection.DispositionAt.Format(time.RFC3339Nano), projection.ProjectionVersion,
		projection.Source, projection.SourceEventID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("audit: rebuild alert acknowledgement projection: %w", err)
	}
	return nil
}

func applyAlertProjectionCAS(
	ctx context.Context,
	tx *sql.Tx,
	current AlertAcknowledgementProjection,
	result AlertAcknowledgementResult,
) error {
	if current.ProjectionVersion == 0 {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO alert_acknowledgement_projection (
				alert_id, disposition, actor, disposition_at, projection_version,
				source, source_event_id, updated_at
			) VALUES (?, ?, ?, ?, 1, 'modern', ?, ?)
			ON CONFLICT(alert_id) DO NOTHING`,
			result.AlertID, result.Disposition, result.Actor,
			result.CreatedAt.Format(time.RFC3339Nano), result.EventID,
			result.CreatedAt.Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("audit: insert alert acknowledgement projection: %w", err)
		}
		changed, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("audit: inspect alert acknowledgement insert CAS: %w", err)
		}
		if changed != 1 {
			return errAlertProjectionCASRetry
		}
		return nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE alert_acknowledgement_projection
		SET disposition=?, actor=?, disposition_at=?, projection_version=?,
			source='modern', source_event_id=?, updated_at=?
		WHERE alert_id=? AND projection_version=?`,
		result.Disposition, result.Actor, result.CreatedAt.Format(time.RFC3339Nano),
		result.ProjectionVersionAfter, result.EventID, result.CreatedAt.Format(time.RFC3339Nano),
		result.AlertID, result.ProjectionVersionBefore)
	if err != nil {
		return fmt.Errorf("audit: update alert acknowledgement projection: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect alert acknowledgement CAS: %w", err)
	}
	if changed != 1 {
		return errAlertProjectionCASRetry
	}
	return nil
}

func insertAlertOperation(
	ctx context.Context,
	tx *sql.Tx,
	fingerprint string,
	result AlertAcknowledgementResult,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alert_acknowledgement_operations (
			operation_id, command_fingerprint, alert_id, requested_disposition, actor,
			expected_projection_version, outcome, rejection_reason,
			observed_projection_version, projection_version_before,
			projection_version_after, event_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.OperationID, fingerprint, result.AlertID, result.Disposition, result.Actor,
		result.ExpectedProjectionVersion, result.Outcome, nullStr(string(result.RejectionReason)),
		result.ObservedProjectionVersion, result.ProjectionVersionBefore,
		result.ProjectionVersionAfter, result.EventID, result.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("audit: insert alert acknowledgement operation: %w", err)
	}
	return nil
}

func alertComplianceBodyFromResult(result AlertAcknowledgementResult) alertComplianceBody {
	return alertComplianceBody{
		Target: result.AlertID, OperationID: result.OperationID, TargetEventID: result.AlertID,
		RequestedDisposition: result.Disposition, Actor: result.Actor,
		Outcome: result.Outcome, RejectionReason: result.RejectionReason,
		ExpectedProjectionVersion: result.ExpectedProjectionVersion,
		ObservedProjectionVersion: result.ObservedProjectionVersion,
		ProjectionVersionBefore:   result.ProjectionVersionBefore,
		ProjectionVersionAfter:    result.ProjectionVersionAfter,
	}
}

func alertCommandEventName(disposition AlertDisposition) observability.EventName {
	if disposition == AlertDispositionDismissed {
		return "alert.dismissal.requested"
	}
	return "alert.acknowledgement.requested"
}

func (writer *AlertAcknowledgementWriter) appendAlertProjectionHealth(
	ctx context.Context,
	tx *sql.Tx,
	alertID string,
	code AlertProjectionHealthCode,
) (eventHistoryAppendOutcome, error) {
	var existingCode string
	err := tx.QueryRowContext(ctx, `
		SELECT code FROM alert_acknowledgement_health WHERE alert_id = ?`, alertID).Scan(&existingCode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return eventHistoryAppendOutcome{}, fmt.Errorf("audit: read alert projection health: %w", err)
	}
	if err == nil && existingCode == string(code) {
		return eventHistoryAppendOutcome{}, nil
	}
	body := alertProjectionHealthBody{Target: alertID, AlertID: alertID, Code: code}
	appended, err := writer.appendAlertCanonicalEvent(ctx, tx, AlertCanonicalEventInput{
		Bucket:    observability.BucketPlatformHealth,
		EventName: "subsystem.degraded", Outcome: observability.OutcomeFailed,
		AlertID: alertID, Body: body,
	})
	if err != nil {
		return eventHistoryAppendOutcome{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_acknowledgement_health (alert_id, code, health_event_id, detected_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(alert_id) DO UPDATE SET code=excluded.code,
			health_event_id=excluded.health_event_id, detected_at=excluded.detected_at`,
		alertID, code, appended.record.RecordID(), appended.record.Timestamp().Format(time.RFC3339Nano))
	if err != nil {
		return eventHistoryAppendOutcome{}, fmt.Errorf("audit: persist alert projection health: %w", err)
	}
	return appended.historyOutcome, nil
}

func clearAlertProjectionHealth(ctx context.Context, tx *sql.Tx, alertID string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM alert_acknowledgement_health WHERE alert_id = ?`, alertID); err != nil {
		return fmt.Errorf("audit: clear alert projection health: %w", err)
	}
	return nil
}

type appendedAlertCanonicalEvent struct {
	record         observability.Record
	body           map[string]any
	historyOutcome eventHistoryAppendOutcome
}

func (writer *AlertAcknowledgementWriter) appendAlertCanonicalEvent(
	ctx context.Context,
	tx *sql.Tx,
	input AlertCanonicalEventInput,
) (appendedAlertCanonicalEvent, error) {
	record, projection, err := writer.eventFactory.BuildAlertCanonicalEvent(ctx, input)
	if err != nil {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: build canonical alert event: %w", err)
	}
	severity, hasSeverity := record.Severity()
	if record.Bucket() != input.Bucket || record.EventName() != input.EventName ||
		record.Signal() != observability.SignalLogs || record.Outcome() != input.Outcome ||
		!record.Mandatory() || !hasSeverity || severity != observability.SeverityInfo {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert event does not match the storage operation")
	}
	expectedBody, err := json.Marshal(input.Body)
	if err != nil {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: encode expected alert event body: %w", err)
	}
	expectedValue, err := observability.ParseValue(expectedBody)
	if err != nil {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: expected alert event body is invalid")
	}
	recordBody, ok := record.Body()
	if !ok || !bytes.Equal(recordBody.Bytes(), expectedValue.Bytes()) {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert event body does not match the storage operation")
	}
	projectedBody, err := projection.Payload().Object()
	if err != nil {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert event projection body is invalid")
	}
	if target, ok := projectedBody["target"].(string); !ok || target != input.AlertID {
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert event projection removed its reconciliation target")
	}
	switch expected := input.Body.(type) {
	case alertComplianceBody:
		var projected alertComplianceBody
		if err := json.Unmarshal(projection.Payload().Bytes(), &projected); err != nil ||
			projected.Target != expected.Target || projected.TargetEventID != expected.TargetEventID ||
			projected.OperationID != expected.OperationID ||
			projected.RequestedDisposition != expected.RequestedDisposition ||
			projected.Outcome != expected.Outcome || projected.RejectionReason != expected.RejectionReason ||
			projected.ExpectedProjectionVersion != expected.ExpectedProjectionVersion ||
			projected.ObservedProjectionVersion != expected.ObservedProjectionVersion ||
			projected.ProjectionVersionBefore != expected.ProjectionVersionBefore ||
			projected.ProjectionVersionAfter != expected.ProjectionVersionAfter {
			return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert event projection changed replay control fields")
		}
	case alertProjectionHealthBody:
		var projected alertProjectionHealthBody
		if err := json.Unmarshal(projection.Payload().Bytes(), &projected); err != nil || projected != expected {
			return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: canonical alert health projection changed control fields")
		}
	default:
		return appendedAlertCanonicalEvent{}, fmt.Errorf("audit: unsupported canonical alert event body")
	}
	historyOutcome, err := writer.eventHistory.appendContextTx(ctx, tx, record, projection)
	if err != nil {
		return appendedAlertCanonicalEvent{}, err
	}
	return appendedAlertCanonicalEvent{
		record: record, body: projectedBody, historyOutcome: historyOutcome,
	}, nil
}

func projectedAlertActor(body map[string]any) string {
	if actor, ok := body["actor"].(string); ok && actor != "" {
		return actor
	}
	return redactedAlertActor
}

func parseAlertProjectionTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("audit: invalid alert projection timestamp")
}
