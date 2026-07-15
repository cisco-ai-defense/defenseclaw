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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const (
	// ProjectionHashAlgorithm is the v8 event-history projection-hash
	// algorithm. The stored value is this prefix followed by lower-case hex.
	ProjectionHashAlgorithm = "sha256"
	// ProjectionIntegrityAlgorithm identifies a full HMAC-SHA-256 digest over
	// the domain-separated final projected envelope.
	ProjectionIntegrityAlgorithm = "hmac-sha256"

	projectionIntegrityDomain = "defenseclaw-observability-projection-integrity-v1"
)

const (
	maxEventHistoryVerificationRange          = 1000
	maxCanonicalLogCorrelationIdentifierBytes = 256
)

// EventHistoryVerificationStatus is a bounded, machine-readable local
// integrity result. No status embeds persisted record content or database
// diagnostics.
type EventHistoryVerificationStatus string

const (
	EventHistoryVerified         EventHistoryVerificationStatus = "verified"
	EventHistoryUnsigned         EventHistoryVerificationStatus = "unsigned"
	EventHistoryKeyUnavailable   EventHistoryVerificationStatus = "key_unavailable"
	EventHistoryNotProjected     EventHistoryVerificationStatus = "not_projected"
	EventHistoryHashMismatch     EventHistoryVerificationStatus = "hash_mismatch"
	EventHistoryHMACMismatch     EventHistoryVerificationStatus = "hmac_mismatch"
	EventHistoryInvalidIntegrity EventHistoryVerificationStatus = "invalid_integrity_metadata"
)

// EventHistoryVerification deliberately contains identifiers and bounded
// status only. Verification APIs never return projected or raw record bytes.
type EventHistoryVerification struct {
	RecordID            string                         `json:"record_id"`
	Status              EventHistoryVerificationStatus `json:"status"`
	ProjectionHashValid bool                           `json:"projection_hash_valid"`
	IntegrityVerified   bool                           `json:"integrity_verified"`
	IntegrityKeyID      string                         `json:"integrity_key_id,omitempty"`
}

// EventHistoryVerificationRange is explicit about bounded output. Callers must
// not treat a truncated page as a complete range attestation.
type EventHistoryVerificationRange struct {
	Records   []EventHistoryVerification `json:"records"`
	Truncated bool                       `json:"truncated"`
}

// ErrIntegrityKeyUnavailable lets a signer report expected boot-order or key
// custody unavailability. V8 writes the projection as unsigned in this case;
// every other signing error aborts the write.
var ErrIntegrityKeyUnavailable = errors.New("projection integrity key unavailable")

// ProjectionIntegritySigner owns integrity key material. The writer supplies a
// domain-separated message and requires a full 32-byte HMAC-SHA-256 result;
// neither key material nor signer errors enter the stored event.
type ProjectionIntegritySigner interface {
	KeyID() string
	HMACSHA256(context.Context, []byte) ([]byte, error)
}

// EventHistoryHealthCode is a bounded failure/degraded-state vocabulary. It is
// safe to bridge into a mandatory platform.health event because it contains no
// record values, JSON pointers, signer error strings, or database diagnostics.
type EventHistoryHealthCode string

const (
	EventHistoryHealthProjectionRejected EventHistoryHealthCode = "projection_rejected"
	EventHistoryHealthUnsigned           EventHistoryHealthCode = "integrity_unsigned"
	EventHistoryHealthSigningFailed      EventHistoryHealthCode = "integrity_signing_failed"
	EventHistoryHealthWriteFailed        EventHistoryHealthCode = "sqlite_write_failed"
)

type EventHistoryHealthReporter interface {
	ReportEventHistoryHealth(EventHistoryHealthCode)
}

type eventHistoryWriteError struct{ cause error }

func (*eventHistoryWriteError) Error() string { return "audit: insert v8 event-history row failed" }
func (err *eventHistoryWriteError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

type eventHistoryHealthError struct {
	code  EventHistoryHealthCode
	cause error
}

func (err *eventHistoryHealthError) Error() string {
	if err == nil || err.cause == nil {
		return "audit: event-history operation failed"
	}
	return err.cause.Error()
}

func (err *eventHistoryHealthError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

type eventHistoryAppendOutcome struct {
	signed   bool
	unsigned bool
}

func eventHistoryFailure(code EventHistoryHealthCode, err error) error {
	if err == nil {
		return nil
	}
	return &eventHistoryHealthError{code: code, cause: err}
}

// LocalProjectionBinding is a sealed immutable runtime-graph binding. External
// packages obtain one through NewTrustedLocalProjectionBinding; the unexported
// snapshot method prevents an arbitrary resolver from weakening event-history
// validation to profile-name equality.
type LocalProjectionBinding interface {
	eventHistoryProjectionBinding() localProjectionBindingSnapshot
}

type localProjectionBindingSnapshot struct {
	graphDigest string
	profiles    map[observability.Bucket]observabilityredaction.Profile
	engine      *observabilityredaction.Engine
}

// TrustedLocalProjectionBinding captures one compiled graph's digest, exact
// resolved profile values, and exact redaction engine. Profiles are immutable
// values and both construction and writer initialization clone the bucket map.
type TrustedLocalProjectionBinding struct {
	snapshot localProjectionBindingSnapshot
}

// NewTrustedLocalProjectionBinding constructs the only production-capable
// EventHistoryWriter binding. The writer later uses Engine.Reproject to prove
// every projection came from this exact engine/profile/key/catalog tuple.
func NewTrustedLocalProjectionBinding(
	graphDigest string,
	engine *observabilityredaction.Engine,
	profiles map[observability.Bucket]observabilityredaction.Profile,
) (*TrustedLocalProjectionBinding, error) {
	if !observability.IsStableToken(graphDigest) || engine == nil ||
		len(profiles) != len(observability.Buckets()) {
		return nil, fmt.Errorf("audit: local projection graph binding is invalid")
	}
	snapshot := localProjectionBindingSnapshot{
		graphDigest: graphDigest,
		profiles:    make(map[observability.Bucket]observabilityredaction.Profile, len(profiles)),
		engine:      engine,
	}
	for _, bucket := range observability.Buckets() {
		profile, ok := profiles[bucket]
		if !ok || !observability.IsStableToken(string(profile.Name())) {
			return nil, fmt.Errorf("audit: local projection profile binding for bucket %s is invalid", bucket)
		}
		snapshot.profiles[bucket] = profile
	}
	return &TrustedLocalProjectionBinding{snapshot: snapshot}, nil
}

func (binding *TrustedLocalProjectionBinding) eventHistoryProjectionBinding() localProjectionBindingSnapshot {
	if binding == nil {
		return localProjectionBindingSnapshot{}
	}
	snapshot := binding.snapshot
	snapshot.profiles = cloneLocalProjectionProfiles(snapshot.profiles)
	return snapshot
}

// GraphDigest identifies the compiled graph snapshotted by this binding.
func (binding *TrustedLocalProjectionBinding) GraphDigest() string {
	if binding == nil {
		return ""
	}
	return binding.snapshot.graphDigest
}

func cloneLocalProjectionProfiles(
	profiles map[observability.Bucket]observabilityredaction.Profile,
) map[observability.Bucket]observabilityredaction.Profile {
	result := make(map[observability.Bucket]observabilityredaction.Profile, len(profiles))
	for bucket, profile := range profiles {
		result[bucket] = profile
	}
	return result
}

// EventHistoryWriter appends immutable v8 log projections to audit_events. A
// nil signer is valid and produces an explicitly unsigned row.
type EventHistoryWriter struct {
	store            *Store
	signer           ProjectionIntegritySigner
	healthReporter   EventHistoryHealthReporter
	localProfiles    map[observability.Bucket]observabilityredaction.Profile
	projectionEngine *observabilityredaction.Engine
	graphDigest      string
	appendCommitMu   sync.Mutex
	healthMu         sync.Mutex
	healthQueue      []EventHistoryHealthCode
	healthPending    map[EventHistoryHealthCode]bool
	healthDraining   bool
	healthActive     EventHistoryHealthCode
	unsignedReported bool
}

// NewEventHistoryWriter snapshots the compiled runtime graph's complete local
// profile binding. Append callers can therefore never attest or override the
// profile used by mandatory SQLite persistence.
func NewEventHistoryWriter(
	store *Store,
	signer ProjectionIntegritySigner,
	healthReporter EventHistoryHealthReporter,
	binding LocalProjectionBinding,
) (*EventHistoryWriter, error) {
	if store == nil || store.db == nil || !store.Ready() {
		return nil, fmt.Errorf("audit: ready v8 event-history store is required")
	}
	if binding == nil {
		return nil, fmt.Errorf("audit: local projection binding is required")
	}
	snapshot := binding.eventHistoryProjectionBinding()
	if !observability.IsStableToken(snapshot.graphDigest) || snapshot.engine == nil ||
		len(snapshot.profiles) != len(observability.Buckets()) {
		return nil, fmt.Errorf("audit: local projection graph binding is invalid")
	}
	profiles := make(map[observability.Bucket]observabilityredaction.Profile, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		profile, ok := snapshot.profiles[bucket]
		if !ok || !observability.IsStableToken(string(profile.Name())) {
			return nil, fmt.Errorf("audit: local redaction profile binding for bucket %s is invalid", bucket)
		}
		profiles[bucket] = profile
	}
	return &EventHistoryWriter{
		store: store, signer: signer, healthReporter: healthReporter, localProfiles: profiles,
		projectionEngine: snapshot.engine, graphDigest: snapshot.graphDigest,
	}, nil
}

// GraphDigest identifies the immutable compiled graph that owns this writer.
// Runtime assembly rejects evaluators and factories from any other generation.
func (writer *EventHistoryWriter) GraphDigest() string {
	if writer == nil {
		return ""
	}
	return writer.graphDigest
}

// Append persists exactly one local event-history row using a background
// context. Call AppendContext when cancellation must be propagated.
func (writer *EventHistoryWriter) Append(
	record observability.Record,
	projection observabilityredaction.Projection,
) error {
	return writer.AppendContext(context.Background(), record, projection)
}

// AppendContext validates that projection is the immutable local projection of
// record, hashes and optionally signs its final serialization, then commits one
// row atomically. It never falls back to record.Body or record.Bytes for stored
// payload data.
func (writer *EventHistoryWriter) AppendContext(
	ctx context.Context,
	record observability.Record,
	projection observabilityredaction.Projection,
) error {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return fmt.Errorf("audit: v8 event-history context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := writer.store.acquireReady()
	if err != nil {
		writer.reportHealth(EventHistoryHealthWriteFailed)
		return err
	}
	released := false
	releaseReady := func() {
		if !released {
			release()
			released = true
		}
	}
	defer releaseReady()
	tx, err := writer.store.db.BeginTx(ctx, nil)
	if err != nil {
		releaseReady()
		writer.reportHealth(EventHistoryHealthWriteFailed)
		return fmt.Errorf("audit: begin v8 event-history write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	outcome, err := writer.appendContextTx(ctx, tx, record, projection)
	if err != nil {
		// Health reporters may persist their own mandatory record through the
		// same single-connection Store. End this transaction before invoking
		// external code so failure reporting cannot self-deadlock.
		_ = tx.Rollback()
		releaseReady()
		writer.reportAppendError(err)
		return err
	}
	if err := writer.commitAppendTransaction(tx, outcome); err != nil {
		releaseReady()
		writer.flushHealth()
		return fmt.Errorf("audit: commit v8 event-history row: %w", err)
	}
	releaseReady()
	writer.flushHealth()
	return nil
}

// appendContextTx is the one authoritative prepare-and-insert path for both
// ordinary event-history appends and storage operations that require the event
// plus a normalized projection to commit atomically. Callers own tx commit or
// rollback; this method performs the same canonical-record correspondence,
// local-profile, projection hash, and HMAC validation as AppendContext.
func (writer *EventHistoryWriter) appendContextTx(
	ctx context.Context,
	tx *sql.Tx,
	record observability.Record,
	projection observabilityredaction.Projection,
) (eventHistoryAppendOutcome, error) {
	if writer == nil || writer.store == nil || !writer.store.Ready() || writer.localProfiles == nil ||
		writer.projectionEngine == nil || writer.graphDigest == "" {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthWriteFailed,
			fmt.Errorf("audit: trusted local event-history writer is not ready"),
		)
	}
	expectedProfile, ok := writer.localProfiles[record.Bucket()]
	if !ok {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthProjectionRejected,
			fmt.Errorf("audit: no effective local redaction profile for bucket %s", record.Bucket()),
		)
	}
	trustedProjection, _, err := writer.projectionEngine.Reproject(projection, expectedProfile)
	if err != nil {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthProjectionRejected,
			fmt.Errorf("audit: local log projection does not belong to the active graph"),
		)
	}
	return writer.appendContextTxResolvedProfile(ctx, tx, record, trustedProjection, expectedProfile.Name())
}

func (writer *EventHistoryWriter) appendContextTxResolvedProfile(
	ctx context.Context,
	tx *sql.Tx,
	record observability.Record,
	projection observabilityredaction.Projection,
	expectedProfile observabilityredaction.ProfileName,
) (eventHistoryAppendOutcome, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil || tx == nil {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthWriteFailed,
			fmt.Errorf("audit: v8 event-history transaction writer is not initialized"),
		)
	}
	if ctx == nil {
		return eventHistoryAppendOutcome{}, fmt.Errorf("audit: v8 event-history context is required")
	}
	if err := ctx.Err(); err != nil {
		return eventHistoryAppendOutcome{}, err
	}
	if record.Signal() != observability.SignalLogs {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthProjectionRejected,
			fmt.Errorf("audit: v8 event history accepts log records only"),
		)
	}

	projectedEnvelope, payloadJSON, err := validateLocalProjection(record, projection, expectedProfile)
	if err != nil {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(EventHistoryHealthProjectionRejected, err)
	}
	contentDigest := sha256.Sum256(projectedEnvelope)
	projectionHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(contentDigest[:])

	payloadHMAC, integrityAlgorithm, integrityKeyID, unsigned, err := writer.integrity(ctx, projectedEnvelope)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return eventHistoryAppendOutcome{}, err
		}
		return eventHistoryAppendOutcome{}, eventHistoryFailure(EventHistoryHealthSigningFailed, err)
	}
	outcome := eventHistoryAppendOutcome{signed: !unsigned, unsigned: unsigned}

	correlation := record.Correlation()
	provenance := record.Provenance()
	metadata := projection.Metadata()
	target := projectedCompatibilityTarget(projection)
	details := projectedCompatibilityDetails(projection, string(record.EventName()))
	severity, hasSeverity := record.Severity()
	var severityValue any
	if hasSeverity {
		severityValue = string(severity)
	}
	action := record.Action()
	if action == "" {
		action = string(record.EventName())
	}
	enforced := record.Outcome() == observability.OutcomeBlocked ||
		record.Outcome() == observability.OutcomeDenied ||
		record.Outcome() == observability.OutcomeQuarantined ||
		record.Outcome() == observability.OutcomeRevoked ||
		record.Outcome() == observability.OutcomeTerminated

	legacyTarget := any(nullStr(target))
	legacyActor := any(provenance.Producer)
	legacyDetails := any(details)
	legacyStructured := any(string(payloadJSON))
	legacySeverity := severityValue
	legacySchemaVersion := any(version.SchemaVersion)
	legacyContentHash := any(nullStr(provenance.ConfigDigest))
	legacyGeneration := any(provenance.ConfigGeneration)
	legacyBinaryVersion := any(provenance.BinaryVersion)
	legacyAgentName := any(nullStr(projectedCompatibilityString(projection, "gen_ai.agent.name")))
	legacyDestinationApp := any(nullStr(projectedCompatibilityString(projection, "defenseclaw.destination.app")))
	legacyToolName := any(nullStr(projectedCompatibilityString(projection, "gen_ai.tool.name")))
	toolID := projectedCompatibilityString(projection, "defenseclaw.tool.id")
	if toolID == "" {
		toolID = projectedCompatibilityString(projection, "gen_ai.tool.call.id")
	}
	if toolID == "" {
		toolID = correlation.ToolInvocationID
	}
	legacyToolID := any(nullStr(toolID))
	legacyStepIndex := any(sql.NullInt64{})
	legacyEnforced := any(nullBool(enforced))
	legacyRulePackDir := any(sql.NullString{})
	if legacy, present, legacyErr := legacyEventProjectionFromContext(ctx, record); legacyErr != nil {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(EventHistoryHealthProjectionRejected, legacyErr)
	} else if present {
		structured, encodeErr := encodeStructuredPayload(legacy.Structured)
		if encodeErr != nil {
			return eventHistoryAppendOutcome{}, eventHistoryFailure(EventHistoryHealthProjectionRejected, encodeErr)
		}
		legacyTarget = nullStr(legacy.Target)
		legacyActor = legacy.Actor
		legacyDetails = legacy.Details
		legacyStructured = structured
		legacySeverity = nullStr(legacy.Severity)
		legacySchemaVersion = nullInt(legacy.SchemaVersion)
		legacyContentHash = nullStr(legacy.ContentHash)
		legacyGeneration = nullUint64(legacy.Generation)
		legacyBinaryVersion = nullStr(legacy.BinaryVersion)
		legacyAgentName = nullStr(legacy.AgentName)
		legacyDestinationApp = nullStr(legacy.DestinationApp)
		legacyToolName = nullStr(legacy.ToolName)
		legacyToolID = nullStr(legacy.ToolID)
		legacyStepIndex = nullInt(legacy.StepIdx)
		legacyEnforced = nullBool(legacy.Enforced)
		legacyRulePackDir = nullStr(legacy.RulePackDir)
	}

	_, err = txExecContextObserved(ctx, tx, "v8_event_history_insert", writer.store.sqliteBusyObservabilityV8(), `
		INSERT INTO audit_events (
			id, timestamp, action, target, actor, details, structured_json, severity,
			run_id, trace_id, request_id, session_id, turn_id, agent_name, agent_instance_id,
			policy_id, destination_app, tool_name, tool_id,
			schema_version, content_hash, generation, binary_version, agent_id, sidecar_instance_id,
			connector, step_idx, enforced, rule_pack_dir,
			bucket, event_name, source, signal, bucket_catalog_version, payload_json, projected_record_json,
			record_schema_version, projection_hash,
			redaction_profile, mandatory, evaluation_id, scan_id, finding_id,
			enforcement_action_id, payload_hmac, integrity_algorithm, integrity_key_id
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?
		)`,
		record.RecordID(), record.Timestamp().Format(time.RFC3339Nano),
		action, legacyTarget, legacyActor, legacyDetails, legacyStructured, legacySeverity,
		nullStr(correlation.RunID), nullStr(correlation.TraceID), nullStr(correlation.RequestID),
		nullStr(correlation.SessionID), nullStr(correlation.TurnID), legacyAgentName,
		nullStr(correlation.AgentInstanceID), nullStr(correlation.PolicyID), legacyDestinationApp,
		legacyToolName, legacyToolID,
		legacySchemaVersion, legacyContentHash, legacyGeneration, legacyBinaryVersion,
		nullStr(correlation.AgentID), nullStr(correlation.SidecarInstanceID),
		nullStr(record.Connector()), legacyStepIndex, legacyEnforced, legacyRulePackDir,
		string(record.Bucket()), string(record.EventName()), string(record.Source()), string(record.Signal()),
		record.BucketCatalogVersion(), string(payloadJSON), string(projectedEnvelope),
		record.SchemaVersion(), projectionHash,
		metadata.RedactionProfile, boolInt(record.Mandatory()),
		nullStr(correlation.EvaluationID), nullStr(correlation.ScanID),
		nullStr(correlation.FindingOccurrenceID), nullStr(correlation.EnforcementActionID),
		nullStr(payloadHMAC), nullStr(integrityAlgorithm), nullStr(integrityKeyID),
	)
	if err != nil {
		return eventHistoryAppendOutcome{}, eventHistoryFailure(
			EventHistoryHealthWriteFailed,
			&eventHistoryWriteError{cause: err},
		)
	}
	if correlation.SemanticEventID != "" {
		observationTraceID, observationSpanID := exactObservationTopology(correlation.TraceID, correlation.SpanID)
		observationLifecycleID, observationExecutionID := exactLogLifecycleAndExecution(record)
		if err := putCorrelationObservationTx(ctx, tx, writer.store, CorrelationObservation{
			RecordID:         record.RecordID(),
			SemanticEventID:  SemanticEventID(correlation.SemanticEventID),
			Signal:           CorrelationSignalLogs,
			Bucket:           string(record.Bucket()),
			EventName:        string(record.EventName()),
			ObservedAt:       record.Timestamp(),
			TraceID:          observationTraceID,
			SpanID:           observationSpanID,
			SessionID:        correlation.SessionID,
			TurnID:           correlation.TurnID,
			AgentID:          correlation.AgentID,
			LifecycleID:      observationLifecycleID,
			ExecutionID:      observationExecutionID,
			ModelRequestID:   correlation.ModelRequestID,
			ModelResponseID:  correlation.ModelResponseID,
			ToolInvocationID: correlation.ToolInvocationID,
			ProjectionHash:   projectionHash,
			Status:           CorrelationObservationExportEligible,
		}); err != nil {
			return eventHistoryAppendOutcome{}, eventHistoryFailure(
				EventHistoryHealthWriteFailed,
				&eventHistoryWriteError{cause: err},
			)
		}
	}
	return outcome, nil
}

// exactLogLifecycleAndExecution reads only the two registered canonical
// lifecycle attributes. They are intentionally not generic Correlation fields,
// so preserving them in log observations requires an exact attribute lookup.
// No connector aliases, content fields, or contextual fallbacks are inspected.
func exactLogLifecycleAndExecution(record observability.Record) (string, string) {
	var lifecycleID, executionID string
	for _, value := range []func() (observability.Value, bool){record.InstrumentData, record.Body} {
		candidate, ok := value()
		if !ok {
			continue
		}
		object, err := candidate.Object()
		if err != nil {
			continue
		}
		candidateLifecycleID, candidateExecutionID := exactLogLifecycleAndExecutionAttributes(object)
		if lifecycleID == "" {
			lifecycleID = candidateLifecycleID
		}
		if executionID == "" {
			executionID = candidateExecutionID
		}
		if lifecycleID != "" && executionID != "" {
			break
		}
	}
	return lifecycleID, executionID
}

func exactLogLifecycleAndExecutionAttributes(object map[string]any) (string, string) {
	attributes := object
	if nested, ok := object["attributes"].(map[string]any); ok {
		attributes = nested
	}
	return exactLogCorrelationIdentifier(attributes["defenseclaw.agent.lifecycle.id"]),
		exactLogCorrelationIdentifier(attributes["defenseclaw.agent.execution.id"])
}

func exactLogCorrelationIdentifier(value any) string {
	identifier, ok := value.(string)
	// The canonical telemetry registry constrains these two log attributes to
	// 256 UTF-8 bytes. The ledger's broader 512-byte identifier ceiling covers
	// other rails and must not make an invalid canonical log record admissible.
	if !ok || identifier == "" || len(identifier) > maxCanonicalLogCorrelationIdentifierBytes || !utf8.ValidString(identifier) {
		return ""
	}
	for index := 0; index < len(identifier); index++ {
		character := identifier[index]
		alphaNumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if alphaNumeric || index > 0 && (character == '.' || character == '_' ||
			character == ':' || character == '/' || character == '-') {
			continue
		}
		return ""
	}
	return identifier
}

// exactObservationTopology separates the legacy audit correlation envelope
// from the correlation ledger's exact OTLP topology. Older callers have always
// been allowed to use bounded opaque trace/request strings; those values remain
// in audit_events for compatibility but must not enter exact trace/span joins.
// A span without a valid trace anchor is also omitted.
func exactObservationTopology(traceID, spanID string) (string, string) {
	if validateTraceID(traceID) != nil {
		return "", ""
	}
	if validateSpanID(spanID) != nil {
		return traceID, ""
	}
	return traceID, spanID
}

func (writer *EventHistoryWriter) reportAppendError(err error) {
	var healthErr *eventHistoryHealthError
	if errors.As(err, &healthErr) {
		writer.enqueueHealth(healthErr.code)
	}
	writer.flushHealth()
}

// commitAppendTransaction serializes commit order with signed/unsigned health
// state staging. It never invokes external reporter code; callers must release
// Store lifecycle ownership before flushHealth.
func (writer *EventHistoryWriter) commitAppendTransaction(
	tx *sql.Tx,
	outcome eventHistoryAppendOutcome,
) error {
	if writer == nil || tx == nil {
		return fmt.Errorf("audit: event-history commit transaction is unavailable")
	}
	writer.appendCommitMu.Lock()
	defer writer.appendCommitMu.Unlock()
	if err := tx.Commit(); err != nil {
		writer.enqueueHealth(EventHistoryHealthWriteFailed)
		return err
	}
	writer.stageAppendOutcome(outcome)
	return nil
}

func (writer *EventHistoryWriter) stageAppendOutcome(outcome eventHistoryAppendOutcome) {
	if writer == nil {
		return
	}
	writer.healthMu.Lock()
	defer writer.healthMu.Unlock()
	if outcome.signed {
		writer.unsignedReported = false
		return
	}
	if outcome.unsigned && !writer.unsignedReported {
		writer.unsignedReported = true
		// A signed commit can restore health while an earlier unsigned
		// transition is still being reported. Preserve one later unsigned
		// transition behind the active callback instead of dropping it.
		writer.enqueueHealthLocked(EventHistoryHealthUnsigned, true)
	}
}

func (writer *EventHistoryWriter) reportHealth(code EventHistoryHealthCode) {
	writer.enqueueHealth(code)
	writer.flushHealth()
}

func (writer *EventHistoryWriter) enqueueHealth(code EventHistoryHealthCode) {
	if writer == nil || writer.healthReporter == nil {
		return
	}
	writer.healthMu.Lock()
	defer writer.healthMu.Unlock()
	writer.enqueueHealthLocked(code, false)
}

func (writer *EventHistoryWriter) enqueueHealthLocked(
	code EventHistoryHealthCode,
	allowAfterActive bool,
) {
	if writer.healthReporter == nil || code == "" || (code == writer.healthActive && !allowAfterActive) {
		return
	}
	if writer.healthPending == nil {
		writer.healthPending = make(map[EventHistoryHealthCode]bool, 4)
	}
	if writer.healthPending[code] {
		return
	}
	// The vocabulary has four values. Coalescing one pending transition per
	// code makes the queue bounded even if a reporter re-enters this writer.
	if len(writer.healthQueue) >= 4 {
		return
	}
	writer.healthPending[code] = true
	writer.healthQueue = append(writer.healthQueue, code)
}

func (writer *EventHistoryWriter) flushHealth() {
	if writer == nil || writer.healthReporter == nil {
		return
	}
	writer.healthMu.Lock()
	if writer.healthDraining {
		writer.healthMu.Unlock()
		return
	}
	writer.healthDraining = true
	writer.healthMu.Unlock()

	for {
		writer.healthMu.Lock()
		if len(writer.healthQueue) == 0 {
			writer.healthActive = ""
			writer.healthDraining = false
			writer.healthMu.Unlock()
			return
		}
		code := writer.healthQueue[0]
		writer.healthQueue = writer.healthQueue[1:]
		delete(writer.healthPending, code)
		writer.healthActive = code
		writer.healthMu.Unlock()

		writer.healthReporter.ReportEventHistoryHealth(code)

		writer.healthMu.Lock()
		writer.healthActive = ""
		writer.healthMu.Unlock()
	}
}

func projectedCompatibilityTarget(projection observabilityredaction.Projection) string {
	payload, err := projection.Payload().Object()
	if err != nil {
		return ""
	}
	target, _ := payload["target"].(string)
	return target
}

func projectedCompatibilityDetails(projection observabilityredaction.Projection, fallback string) string {
	payload, err := projection.Payload().Object()
	if err != nil {
		return fallback
	}
	for _, field := range []string{"message", "description", "reason"} {
		if value, ok := payload[field].(string); ok && value != "" {
			return value
		}
	}
	return fallback
}

func projectedCompatibilityString(
	projection observabilityredaction.Projection,
	field string,
) string {
	if field == "" {
		return ""
	}
	payload, err := projection.Payload().Object()
	if err != nil {
		return ""
	}
	value, _ := payload[field].(string)
	return value
}

func (writer *EventHistoryWriter) integrity(
	ctx context.Context,
	projectedEnvelope []byte,
) (payloadHMAC, algorithm, keyID string, unsigned bool, err error) {
	if writer.signer == nil {
		return "", "", "", true, nil
	}
	keyID = writer.signer.KeyID()
	if err := validateIntegrityKeyID(keyID); err != nil {
		return "", "", "", false, err
	}
	message := projectionIntegrityMessage(projectedEnvelope, ProjectionIntegrityAlgorithm, keyID)
	signature, signErr := writer.signer.HMACSHA256(ctx, message)
	for index := range message {
		message[index] = 0
	}
	if errors.Is(signErr, ErrIntegrityKeyUnavailable) {
		return "", "", "", true, nil
	}
	if signErr != nil {
		if errors.Is(signErr, context.Canceled) || errors.Is(signErr, context.DeadlineExceeded) {
			return "", "", "", false, signErr
		}
		return "", "", "", false, errors.New("audit: sign v8 event-history projection failed")
	}
	if len(signature) != sha256.Size {
		return "", "", "", false, fmt.Errorf("audit: projection integrity signer returned an invalid digest")
	}
	return hex.EncodeToString(signature), ProjectionIntegrityAlgorithm, keyID, false, nil
}

func validateIntegrityKeyID(keyID string) error {
	if keyID == "" || !utf8.ValidString(keyID) || len(keyID) > observability.MaxCorrelationIDBytes {
		return fmt.Errorf("audit: projection integrity key ID is invalid")
	}
	for _, character := range keyID {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("audit: projection integrity key ID is invalid")
		}
	}
	return nil
}

func validateLocalProjection(
	record observability.Record,
	projection observabilityredaction.Projection,
	expectedProfile observabilityredaction.ProfileName,
) ([]byte, []byte, error) {
	if !observability.IsStableToken(string(expectedProfile)) {
		return nil, nil, fmt.Errorf("audit: effective local redaction profile is invalid")
	}
	canonicalEnvelope, err := record.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("audit: canonical log record is invalid")
	}
	projectedEnvelope, err := projection.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection is invalid")
	}
	canonical, err := decodeEnvelope(canonicalEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: canonical log record is invalid")
	}
	projected, err := decodeEnvelope(projectedEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection is invalid")
	}

	for key, value := range canonical {
		switch key {
		case "body", "field_classes":
			continue
		}
		projectedValue, present := projected[key]
		if !present || !bytes.Equal(value, projectedValue) {
			return nil, nil, fmt.Errorf("audit: record and local projection do not correspond")
		}
	}
	if len(projected) != len(canonical)+1 {
		return nil, nil, fmt.Errorf("audit: local log projection has an invalid envelope")
	}

	payloadJSON := projection.Payload().Bytes()
	if len(payloadJSON) == 0 || !bytes.Equal(projected["body"], payloadJSON) {
		return nil, nil, fmt.Errorf("audit: local log projection payload is invalid")
	}
	if _, exists := projected["instrument_data"]; exists {
		return nil, nil, fmt.Errorf("audit: local log projection has an invalid payload arm")
	}

	var metadata observabilityredaction.ProjectionMetadata
	if err := json.Unmarshal(projected["projection"], &metadata); err != nil ||
		!reflect.DeepEqual(metadata, projection.Metadata()) {
		return nil, nil, fmt.Errorf("audit: local log projection metadata is invalid")
	}
	if metadata.RedactionProfile != string(expectedProfile) {
		return nil, nil, fmt.Errorf("audit: local log projection profile does not match the effective route")
	}
	var projectedClasses map[string]observability.FieldClass
	if err := json.Unmarshal(projected["field_classes"], &projectedClasses); err != nil {
		return nil, nil, fmt.Errorf("audit: local log projection field classes are invalid")
	}
	canonicalClasses := record.FieldClasses()
	for pointer, class := range projectedClasses {
		if canonicalClass, present := canonicalClasses[pointer]; !present || canonicalClass != class {
			return nil, nil, fmt.Errorf("audit: record and local projection field classes do not correspond")
		}
	}
	return append([]byte(nil), projectedEnvelope...), append([]byte(nil), payloadJSON...), nil
}

// VerifyEventHistoryRecord verifies one stored projection without returning its
// content. A missing/rotated key is distinct from corruption.
func (writer *EventHistoryWriter) VerifyEventHistoryRecord(
	ctx context.Context,
	recordID string,
) (EventHistoryVerification, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history context is required")
	}
	if recordID == "" || len(recordID) > observability.MaxRecordIDBytes || !utf8.ValidString(recordID) {
		return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history record ID is invalid")
	}
	var projected, projectionHash, payloadHMAC, algorithm, keyID string
	err := writer.store.db.QueryRowContext(ctx, `
		SELECT COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''),
		       COALESCE(integrity_key_id,'')
		FROM audit_events WHERE id = ?`, recordID).Scan(
		&projected, &projectionHash, &payloadHMAC, &algorithm, &keyID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EventHistoryVerification{}, fmt.Errorf("audit: v8 event-history record was not found")
		}
		return EventHistoryVerification{}, fmt.Errorf("audit: read v8 event-history verification fields: %w", err)
	}
	return writer.verifyStoredProjection(ctx, recordID, []byte(projected), projectionHash, payloadHMAC, algorithm, keyID)
}

// VerifyEventHistoryRange verifies a half-open UTC timestamp range. The result
// order is stable and contains no record content.
func (writer *EventHistoryWriter) VerifyEventHistoryRange(
	ctx context.Context,
	from, until time.Time,
	limit int,
) (EventHistoryVerificationRange, error) {
	if writer == nil || writer.store == nil || writer.store.db == nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history writer is not initialized")
	}
	if ctx == nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history context is required")
	}
	if from.IsZero() || until.IsZero() || !from.Before(until) {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history verification range is invalid")
	}
	if limit <= 0 || limit > maxEventHistoryVerificationRange {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: v8 event-history verification limit is invalid")
	}
	rows, err := writer.store.db.QueryContext(ctx, `
		SELECT id, COALESCE(projected_record_json,''), COALESCE(projection_hash,''),
		       COALESCE(payload_hmac,''), COALESCE(integrity_algorithm,''),
		       COALESCE(integrity_key_id,'')
		FROM audit_events
		WHERE julianday(timestamp) >= julianday(?) AND julianday(timestamp) < julianday(?)
		ORDER BY julianday(timestamp) ASC, id ASC LIMIT ?`,
		from.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano), limit+1,
	)
	if err != nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: read v8 event-history verification range: %w", err)
	}
	defer rows.Close()
	results := make([]EventHistoryVerification, 0, limit+1)
	for rows.Next() {
		var recordID, projected, projectionHash, payloadHMAC, algorithm, keyID string
		if err := rows.Scan(&recordID, &projected, &projectionHash, &payloadHMAC, &algorithm, &keyID); err != nil {
			return EventHistoryVerificationRange{}, fmt.Errorf("audit: scan v8 event-history verification range")
		}
		result, err := writer.verifyStoredProjection(
			ctx, recordID, []byte(projected), projectionHash, payloadHMAC, algorithm, keyID,
		)
		if err != nil {
			return EventHistoryVerificationRange{}, err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return EventHistoryVerificationRange{}, fmt.Errorf("audit: iterate v8 event-history verification range: %w", err)
	}
	page := EventHistoryVerificationRange{Records: results}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		page.Truncated = true
	}
	return page, nil
}

func (writer *EventHistoryWriter) verifyStoredProjection(
	ctx context.Context,
	recordID string,
	projected []byte,
	projectionHash, payloadHMAC, algorithm, keyID string,
) (EventHistoryVerification, error) {
	result := EventHistoryVerification{RecordID: recordID}
	if len(projected) == 0 && projectionHash == "" && payloadHMAC == "" && algorithm == "" && keyID == "" {
		result.Status = EventHistoryNotProjected
		return result, nil
	}
	digest := sha256.Sum256(projected)
	wantHash := ProjectionHashAlgorithm + ":" + hex.EncodeToString(digest[:])
	result.ProjectionHashValid = subtle.ConstantTimeCompare([]byte(projectionHash), []byte(wantHash)) == 1
	if !result.ProjectionHashValid {
		result.Status = EventHistoryHashMismatch
		return result, nil
	}
	if payloadHMAC == "" && algorithm == "" && keyID == "" {
		result.Status = EventHistoryUnsigned
		return result, nil
	}
	if payloadHMAC == "" || algorithm != ProjectionIntegrityAlgorithm || validateIntegrityKeyID(keyID) != nil {
		result.Status = EventHistoryInvalidIntegrity
		return result, nil
	}
	result.IntegrityKeyID = keyID
	storedMAC, err := hex.DecodeString(payloadHMAC)
	if err != nil || len(storedMAC) != sha256.Size {
		result.Status = EventHistoryInvalidIntegrity
		return result, nil
	}
	if writer.signer == nil || writer.signer.KeyID() != keyID {
		result.Status = EventHistoryKeyUnavailable
		return result, nil
	}
	message := projectionIntegrityMessage(projected, algorithm, keyID)
	calculated, signErr := writer.signer.HMACSHA256(ctx, message)
	for index := range message {
		message[index] = 0
	}
	if errors.Is(signErr, ErrIntegrityKeyUnavailable) {
		result.Status = EventHistoryKeyUnavailable
		return result, nil
	}
	if signErr != nil {
		return EventHistoryVerification{}, errors.New("audit: verify v8 event-history projection failed")
	}
	if len(calculated) != sha256.Size || !hmac.Equal(storedMAC, calculated) {
		result.Status = EventHistoryHMACMismatch
		return result, nil
	}
	result.Status = EventHistoryVerified
	result.IntegrityVerified = true
	return result, nil
}

func projectionIntegrityMessage(projectedEnvelope []byte, algorithm, keyID string) []byte {
	message := make([]byte, 0, len(projectionIntegrityDomain)+len(algorithm)+len(keyID)+3+len(projectedEnvelope))
	message = append(message, projectionIntegrityDomain...)
	message = append(message, 0)
	message = append(message, algorithm...)
	message = append(message, 0)
	message = append(message, keyID...)
	message = append(message, 0)
	message = append(message, projectedEnvelope...)
	return message
}

func decodeEnvelope(encoded []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var envelope map[string]json.RawMessage
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing envelope data")
	}
	return envelope, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
