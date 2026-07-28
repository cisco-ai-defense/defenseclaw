// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxCorrelationIdentifierBytes = 512
	maxCorrelationTokenBytes      = 128
	maxCorrelationNameBytes       = 256
	maxCorrelationIdentityClaims  = 16
	defaultCorrelationQueryLimit  = 100
	maxCorrelationQueryLimit      = 500
)

var (
	ErrCorrelationNotFound = errors.New("audit: correlation state not found")
	ErrCorrelationStale    = errors.New("audit: stale correlation state")
	ErrCorrelationConflict = errors.New("audit: correlation integrity conflict")
)

type SemanticEventID string
type LogicalEventID string
type ConnectorInstanceID string

func NewSemanticEventID() (SemanticEventID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("audit: generate semantic event id: %w", err)
	}
	return SemanticEventID(id.String()), nil
}

func NewConnectorInstanceID() (ConnectorInstanceID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("audit: generate connector instance id: %w", err)
	}
	return ConnectorInstanceID(id.String()), nil
}

type CorrelationRail string

const (
	CorrelationRailHook       CorrelationRail = "hook"
	CorrelationRailNativeOTLP CorrelationRail = "native_otlp"
	CorrelationRailProxy      CorrelationRail = "proxy"
	CorrelationRailStream     CorrelationRail = "stream"
	CorrelationRailInternal   CorrelationRail = "internal"
)

type CorrelationCompleteness string

const (
	CorrelationComplete CorrelationCompleteness = "complete"
	CorrelationPartial  CorrelationCompleteness = "partial"
	CorrelationUnknown  CorrelationCompleteness = "unknown"
)

type CorrelationSignal string

const (
	CorrelationSignalLogs    CorrelationSignal = "logs"
	CorrelationSignalTraces  CorrelationSignal = "traces"
	CorrelationSignalMetrics CorrelationSignal = "metrics"
)

type CorrelationObservationStatus string

const (
	CorrelationObservationConstructed    CorrelationObservationStatus = "constructed"
	CorrelationObservationExportEligible CorrelationObservationStatus = "export_eligible"
)

type CorrelationRelationshipType string

const (
	CorrelationSameAs         CorrelationRelationshipType = "same_as"
	CorrelationDuplicateOf    CorrelationRelationshipType = "duplicate_of"
	CorrelationBelongsTo      CorrelationRelationshipType = "belongs_to"
	CorrelationParentOf       CorrelationRelationshipType = "parent_of"
	CorrelationDelegatedBy    CorrelationRelationshipType = "delegated_by"
	CorrelationCausedBy       CorrelationRelationshipType = "caused_by"
	CorrelationInvokes        CorrelationRelationshipType = "invokes"
	CorrelationRespondsTo     CorrelationRelationshipType = "responds_to"
	CorrelationResumes        CorrelationRelationshipType = "resumes"
	CorrelationCorrelatesWith CorrelationRelationshipType = "correlates_with"
)

type CorrelationRelationshipMethod string

const (
	CorrelationMethodReported   CorrelationRelationshipMethod = "reported"
	CorrelationMethodTraceExact CorrelationRelationshipMethod = "trace_exact"
	CorrelationMethodDerived    CorrelationRelationshipMethod = "derived"
	CorrelationMethodInferred   CorrelationRelationshipMethod = "inferred"
)

type CorrelationRelationshipStatus string

const (
	CorrelationRelationshipActive     CorrelationRelationshipStatus = "active"
	CorrelationRelationshipCandidate  CorrelationRelationshipStatus = "candidate"
	CorrelationRelationshipSuperseded CorrelationRelationshipStatus = "superseded"
	CorrelationRelationshipRejected   CorrelationRelationshipStatus = "rejected"
	CorrelationRelationshipConflicted CorrelationRelationshipStatus = "conflicted"
)

type CorrelationNodeKind string

const (
	CorrelationNodeSemanticEvent CorrelationNodeKind = "semantic_event"
	CorrelationNodeLogicalEvent  CorrelationNodeKind = "logical_event"
	CorrelationNodeRecord        CorrelationNodeKind = "record"
	CorrelationNodeSession       CorrelationNodeKind = "session"
	CorrelationNodeTurn          CorrelationNodeKind = "turn"
	CorrelationNodeAgent         CorrelationNodeKind = "agent"
	CorrelationNodeLifecycle     CorrelationNodeKind = "lifecycle"
	CorrelationNodeExecution     CorrelationNodeKind = "execution"
	CorrelationNodeModelRequest  CorrelationNodeKind = "model_request"
	CorrelationNodeModelResponse CorrelationNodeKind = "model_response"
	CorrelationNodeTool          CorrelationNodeKind = "tool_invocation"
	CorrelationNodeTrace         CorrelationNodeKind = "trace"
	CorrelationNodeSpan          CorrelationNodeKind = "span"
)

type CorrelationIdentifierKind string

const (
	CorrelationIdentifierSourceEvent     CorrelationIdentifierKind = "source_event"
	CorrelationIdentifierSourceSequence  CorrelationIdentifierKind = "source_sequence"
	CorrelationIdentifierSourceTimestamp CorrelationIdentifierKind = "source_timestamp"
	CorrelationIdentifierMessage         CorrelationIdentifierKind = "message"
	CorrelationIdentifierThread          CorrelationIdentifierKind = "thread"
	CorrelationIdentifierPrompt          CorrelationIdentifierKind = "prompt"
	CorrelationIdentifierStep            CorrelationIdentifierKind = "step"
	CorrelationIdentifierSession         CorrelationIdentifierKind = "session"
	CorrelationIdentifierRootSession     CorrelationIdentifierKind = "root_session"
	CorrelationIdentifierParentSession   CorrelationIdentifierKind = "parent_session"
	CorrelationIdentifierChildSession    CorrelationIdentifierKind = "child_session"
	CorrelationIdentifierTurn            CorrelationIdentifierKind = "turn"
	CorrelationIdentifierAgent           CorrelationIdentifierKind = "agent"
	CorrelationIdentifierRootAgent       CorrelationIdentifierKind = "root_agent"
	CorrelationIdentifierParentAgent     CorrelationIdentifierKind = "parent_agent"
	CorrelationIdentifierChildAgent      CorrelationIdentifierKind = "child_agent"
	CorrelationIdentifierLifecycle       CorrelationIdentifierKind = "lifecycle"
	CorrelationIdentifierExecution       CorrelationIdentifierKind = "execution"
	CorrelationIdentifierModelRequest    CorrelationIdentifierKind = "model_request"
	CorrelationIdentifierModelResponse   CorrelationIdentifierKind = "model_response"
	CorrelationIdentifierAction          CorrelationIdentifierKind = "action"
	CorrelationIdentifierTool            CorrelationIdentifierKind = "tool_invocation"
	CorrelationIdentifierTrace           CorrelationIdentifierKind = "trace"
	CorrelationIdentifierSpan            CorrelationIdentifierKind = "span"
)

type CorrelationIdentityOrigin string

const (
	CorrelationOriginReported          CorrelationIdentityOrigin = "reported"
	CorrelationOriginDefenseClawMinted CorrelationIdentityOrigin = "defenseclaw_minted"
	CorrelationOriginDerived           CorrelationIdentityOrigin = "derived"
	CorrelationOriginTraceExact        CorrelationIdentityOrigin = "trace_exact"
)

type CorrelationEvidenceRole string

const (
	CorrelationEvidenceSource        CorrelationEvidenceRole = "source"
	CorrelationEvidenceTarget        CorrelationEvidenceRole = "target"
	CorrelationEvidenceCorroborating CorrelationEvidenceRole = "corroborating"
	CorrelationEvidenceConflicting   CorrelationEvidenceRole = "conflicting"
)

type CorrelationIntegrityState string

const (
	CorrelationIntegrityVerified   CorrelationIntegrityState = "verified"
	CorrelationIntegrityUnverified CorrelationIntegrityState = "unverified"
	CorrelationIntegrityFailed     CorrelationIntegrityState = "failed"
)

type CorrelationOperationType string

const (
	CorrelationOperationModel CorrelationOperationType = "model"
	CorrelationOperationTool  CorrelationOperationType = "tool"
)

type CorrelationOperationStatus string

const (
	CorrelationOperationActive     CorrelationOperationStatus = "active"
	CorrelationOperationCompleted  CorrelationOperationStatus = "completed"
	CorrelationOperationFailed     CorrelationOperationStatus = "failed"
	CorrelationOperationCancelled  CorrelationOperationStatus = "cancelled"
	CorrelationOperationUnresolved CorrelationOperationStatus = "unresolved"
)

type CorrelationOperationScopeKind string

const (
	CorrelationOperationScopeConnectorInstance CorrelationOperationScopeKind = "connector_instance"
	CorrelationOperationScopeSession           CorrelationOperationScopeKind = "session"
	CorrelationOperationScopeThread            CorrelationOperationScopeKind = "thread"
	CorrelationOperationScopeTurn              CorrelationOperationScopeKind = "turn"
	CorrelationOperationScopeExecution         CorrelationOperationScopeKind = "execution"
)

type ConnectorExportCustody string

const (
	ConnectorCustodyDefenseClaw ConnectorExportCustody = "defenseclaw"
	ConnectorCustodyExternal    ConnectorExportCustody = "external"
	ConnectorCustodyHookOnly    ConnectorExportCustody = "hook_only"
)

type CorrelationOccurrenceStatus string

const (
	CorrelationOccurrenceNew      CorrelationOccurrenceStatus = "new"
	CorrelationOccurrenceExisting CorrelationOccurrenceStatus = "existing"
	CorrelationOccurrenceReplay   CorrelationOccurrenceStatus = "replay"
	CorrelationOccurrenceConflict CorrelationOccurrenceStatus = "conflict"
)

type ConnectorInstance struct {
	ConnectorInstanceID ConnectorInstanceID
	Connector           string
	ExportCustody       ConnectorExportCustody
	ProfileVersion      string
	ManagedConfigDigest string
	Default             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type CorrelationEvent struct {
	SemanticEventID     SemanticEventID         `json:"semantic_event_id"`
	LogicalEventID      LogicalEventID          `json:"logical_event_id"`
	Connector           string                  `json:"connector"`
	ConnectorInstanceID ConnectorInstanceID     `json:"connector_instance_id"`
	Rail                CorrelationRail         `json:"source_rail"`
	EventName           string                  `json:"event_name"`
	SourceTime          time.Time               `json:"source_time"`
	ReceivedTime        time.Time               `json:"received_time"`
	SourceEventDigest   string                  `json:"source_event_digest"`
	FingerprintSHA256   string                  `json:"fingerprint_sha256"`
	FirstRequestID      string                  `json:"first_request_id"`
	FirstRecordID       string                  `json:"first_record_id"`
	ProfileVersion      string                  `json:"profile_version"`
	Completeness        CorrelationCompleteness `json:"completeness"`
}

type CorrelationReceiptClaim struct {
	SourceKeyDigest   string
	FingerprintSHA256 string
	ReceivedAt        time.Time
	ExpiresAt         time.Time
}

// CorrelationReceiptLocator is the immutable capability required to finalize
// one exact delivery after canonical persistence succeeds. It prevents a
// connector-wide or semantic-event-wide success from accidentally authorizing
// suppression of another rail's still-pending receipt.
type CorrelationReceiptLocator struct {
	ConnectorInstanceID ConnectorInstanceID
	SemanticEventID     SemanticEventID
	SourceKeyDigest     string
	FingerprintSHA256   string
}

type CorrelationOccurrenceInput struct {
	Event               CorrelationEvent
	Receipt             *CorrelationReceiptClaim
	ExactIdentityClaims []CorrelationExactIdentityClaim
}

type CorrelationOccurrenceResult struct {
	SemanticEventID        SemanticEventID
	LogicalEventID         LogicalEventID
	MatchedSemanticEventID SemanticEventID
	MatchedLogicalEventID  LogicalEventID
	IdentityEvidence       []CorrelationExactIdentityEvidence
	Status                 CorrelationOccurrenceStatus
	ConflictsWith          SemanticEventID
	DeliveryCount          uint64
	SuppressEmission       bool
	Receipt                *CorrelationReceiptLocator
}

// CorrelationExactIdentityClaim is a connector-profile-authorized occurrence
// identity. It is deliberately narrower than CorrelationIdentifier: session,
// turn, agent, execution, trace, and other membership/topology identifiers are
// rejected here and can never collapse logical occurrence groups.
type CorrelationExactIdentityClaim struct {
	Namespace      string
	Kind           CorrelationIdentifierKind
	ValueDigest    string
	EventName      string
	Rail           CorrelationRail
	CompatibleRail CorrelationRail
	RuleID         string
	RuleVersion    string
}

// CorrelationExactIdentityEvidence describes the committed counterpart that
// authorized an exact cross-rail logical merge.
type CorrelationExactIdentityEvidence struct {
	Namespace       string
	Kind            CorrelationIdentifierKind
	ValueDigest     string
	EventName       string
	Rail            CorrelationRail
	CounterpartRail CorrelationRail
	RuleID          string
	RuleVersion     string
	SemanticEventID SemanticEventID
	LogicalEventID  LogicalEventID
}

type CorrelationObservation struct {
	RecordID         string                       `json:"record_id"`
	SemanticEventID  SemanticEventID              `json:"semantic_event_id"`
	Signal           CorrelationSignal            `json:"signal"`
	Bucket           string                       `json:"bucket"`
	EventName        string                       `json:"event_name"`
	ObservedAt       time.Time                    `json:"observed_at"`
	TraceID          string                       `json:"trace_id"`
	SpanID           string                       `json:"span_id"`
	SessionID        string                       `json:"session_id"`
	TurnID           string                       `json:"turn_id"`
	AgentID          string                       `json:"agent_id"`
	LifecycleID      string                       `json:"lifecycle_id"`
	ExecutionID      string                       `json:"execution_id"`
	ModelRequestID   string                       `json:"model_request_id"`
	ModelResponseID  string                       `json:"model_response_id"`
	ToolInvocationID string                       `json:"tool_invocation_id"`
	ProjectionHash   string                       `json:"projection_hash"`
	Status           CorrelationObservationStatus `json:"status"`
}

type CorrelationIdentifier struct {
	SemanticEventID     SemanticEventID
	ConnectorInstanceID ConnectorInstanceID
	Namespace           string
	Kind                CorrelationIdentifierKind
	ValueDigest         string
	NormalizedValue     string
	SourceField         string
	Origin              CorrelationIdentityOrigin
	ProfileVersion      string
	ObservedAt          time.Time
}

type CorrelationRelationship struct {
	RelationshipID string                        `json:"relationship_id"`
	FromKind       CorrelationNodeKind           `json:"from_kind"`
	FromID         string                        `json:"from_id"`
	ToKind         CorrelationNodeKind           `json:"to_kind"`
	ToID           string                        `json:"to_id"`
	Type           CorrelationRelationshipType   `json:"type"`
	Method         CorrelationRelationshipMethod `json:"method"`
	Confidence     int                           `json:"confidence"`
	RuleID         string                        `json:"rule_id"`
	RuleVersion    string                        `json:"rule_version"`
	EvidenceCount  int64                         `json:"evidence_count,omitempty"`
	Status         CorrelationRelationshipStatus `json:"status"`
	CreatedAt      time.Time                     `json:"created_at"`
	LastSeenAt     time.Time                     `json:"last_seen_at"`
}

type CorrelationRelationshipInput struct {
	FromKind    CorrelationNodeKind
	FromID      string
	ToKind      CorrelationNodeKind
	ToID        string
	Type        CorrelationRelationshipType
	Method      CorrelationRelationshipMethod
	RuleID      string
	RuleVersion string
	Status      CorrelationRelationshipStatus
	ObservedAt  time.Time
}

type CorrelationRelationshipEvidence struct {
	EvidenceID      string                    `json:"evidence_id"`
	RelationshipID  string                    `json:"relationship_id"`
	RecordID        string                    `json:"record_id"`
	SemanticEventID SemanticEventID           `json:"semantic_event_id"`
	Role            CorrelationEvidenceRole   `json:"role"`
	Integrity       CorrelationIntegrityState `json:"integrity"`
	CreatedAt       time.Time                 `json:"created_at"`
}

type CorrelationCursor struct {
	ConnectorInstanceID ConnectorInstanceID
	SessionID           string
	AgentID             string
	LifecycleID         string
	ExecutionID         string
	ActiveTurnID        string
	ActivePromptID      string
	Phase               string
	Sequence            uint64
	RootAgentID         string
	ParentAgentID       string
	RootSessionID       string
	ParentSessionID     string
	LastSemanticEventID SemanticEventID
	LastRecordID        string
	ProfileVersion      string
	Active              bool
	UpdatedAt           time.Time
}

type CorrelationPendingOperation struct {
	ConnectorInstanceID     ConnectorInstanceID
	Namespace               string
	Kind                    CorrelationIdentifierKind
	OperationID             string
	Type                    CorrelationOperationType
	ScopeKind               CorrelationOperationScopeKind
	ScopeID                 string
	Name                    string
	SessionID               string
	TurnID                  string
	AgentID                 string
	ExecutionID             string
	StartSemanticEventID    SemanticEventID
	StartedAt               time.Time
	InputDigest             string
	TerminalSemanticEventID SemanticEventID
	TerminalAt              time.Time
	Status                  CorrelationOperationStatus
	UpdatedAt               time.Time
}

type CorrelationPendingLocator struct {
	ConnectorInstanceID ConnectorInstanceID
	Namespace           string
	Kind                CorrelationIdentifierKind
	OperationID         string
	Type                CorrelationOperationType
	ScopeKind           CorrelationOperationScopeKind
	ScopeID             string
}

type CorrelationRepository struct {
	store *Store
}

func (s *Store) CorrelationRepository() (*CorrelationRepository, error) {
	if s == nil || s.db == nil || !s.Ready() {
		return nil, errors.New("audit: ready correlation store is required")
	}
	return &CorrelationRepository{store: s}, nil
}

// ResolveConnectorInstance returns the one implicit instance for a connector,
// creating it atomically on first setup. Explicit setup can use
// UpsertConnectorInstance with Default=false to register additional instances;
// those never make this hot-path resolver ambiguous.
func (repo *CorrelationRepository) ResolveConnectorInstance(
	ctx context.Context,
	connector string,
	profileVersion string,
	custody ConnectorExportCustody,
) (ConnectorInstance, error) {
	if repo == nil || repo.store == nil {
		return ConnectorInstance{}, errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return ConnectorInstance{}, errors.New("audit: correlation context is required")
	}
	if err := validateBoundedIdentifier("connector", connector, true, 64); err != nil {
		return ConnectorInstance{}, err
	}
	if err := validateBoundedIdentifier("profile version", profileVersion, true, maxCorrelationTokenBytes); err != nil {
		return ConnectorInstance{}, err
	}
	if !validCustody(custody) {
		return ConnectorInstance{}, errors.New("audit: invalid connector export custody")
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return ConnectorInstance{}, err
	}
	defer release()
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ConnectorInstance{}, fmt.Errorf("audit: begin connector instance resolution: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	var instance ConnectorInstance
	var digest sql.NullString
	var isDefault int
	var created, updated int64
	err = tx.QueryRowContext(ctx, `SELECT connector_instance_id, connector, export_custody,
		profile_version, managed_config_digest, is_default, created_time_unix_nano,
		updated_time_unix_nano FROM correlation_connector_instances
		WHERE connector=? AND is_default=1`, connector).Scan(
		&instance.ConnectorInstanceID, &instance.Connector, &instance.ExportCustody,
		&instance.ProfileVersion, &digest, &isDefault, &created, &updated)
	now := time.Now().UTC()
	if errors.Is(err, sql.ErrNoRows) {
		id, idErr := NewConnectorInstanceID()
		if idErr != nil {
			return ConnectorInstance{}, idErr
		}
		_, err = txExecContextObserved(ctx, tx, "correlation_connector_resolve_insert",
			repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_connector_instances (
				connector_instance_id, connector, export_custody, profile_version,
				managed_config_digest, is_default, created_time_unix_nano, updated_time_unix_nano
			) VALUES (?, ?, ?, ?, NULL, 1, ?, ?)`, string(id), connector, string(custody),
			profileVersion, unixNano(now), unixNano(now))
		if err != nil {
			return ConnectorInstance{}, fmt.Errorf("audit: create default connector instance: %w", err)
		}
		instance = ConnectorInstance{
			ConnectorInstanceID: id, Connector: connector, ExportCustody: custody,
			ProfileVersion: profileVersion, Default: true, CreatedAt: now, UpdatedAt: now,
		}
	} else if err != nil {
		return ConnectorInstance{}, fmt.Errorf("audit: resolve default connector instance: %w", err)
	} else {
		effectiveCustody := instance.ExportCustody
		// Hot-path observation may promote a connector only after the caller
		// has authenticated a DefenseClaw-managed native stream. Hook traffic
		// must never downgrade that custody, and transitions between external
		// and hook_only remain explicit setup operations through
		// UpsertConnectorInstance.
		if custody == ConnectorCustodyDefenseClaw {
			effectiveCustody = ConnectorCustodyDefenseClaw
		}
		_, err = txExecContextObserved(ctx, tx, "correlation_connector_resolve_update",
			repo.store.sqliteBusyObservabilityV8(), `UPDATE correlation_connector_instances SET
				export_custody=?, profile_version=?, updated_time_unix_nano=?
				WHERE connector_instance_id=?`, string(effectiveCustody), profileVersion, unixNano(now),
			string(instance.ConnectorInstanceID))
		if err != nil {
			return ConnectorInstance{}, fmt.Errorf("audit: refresh default connector instance: %w", err)
		}
		instance.ExportCustody = effectiveCustody
		instance.ProfileVersion = profileVersion
		instance.ManagedConfigDigest = digest.String
		instance.Default = isDefault != 0
		instance.CreatedAt = time.Unix(0, created).UTC()
		instance.UpdatedAt = now
	}
	if err := tx.Commit(); err != nil {
		return ConnectorInstance{}, fmt.Errorf("audit: commit connector instance resolution: %w", err)
	}
	return instance, nil
}

func (repo *CorrelationRepository) UpsertConnectorInstance(
	ctx context.Context,
	instance ConnectorInstance,
) (ConnectorInstance, error) {
	if repo == nil || repo.store == nil {
		return ConnectorInstance{}, errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return ConnectorInstance{}, errors.New("audit: correlation context is required")
	}
	if instance.ConnectorInstanceID == "" {
		id, err := NewConnectorInstanceID()
		if err != nil {
			return ConnectorInstance{}, err
		}
		instance.ConnectorInstanceID = id
	}
	if err := validateConnectorInstance(instance); err != nil {
		return ConnectorInstance{}, err
	}
	if instance.CreatedAt.IsZero() {
		instance.CreatedAt = time.Now().UTC()
	}
	if instance.UpdatedAt.IsZero() {
		instance.UpdatedAt = instance.CreatedAt
	}
	if instance.UpdatedAt.Before(instance.CreatedAt) {
		return ConnectorInstance{}, errors.New("audit: connector instance update precedes creation")
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return ConnectorInstance{}, err
	}
	defer release()
	result, err := repo.store.execDB(ctx, "correlation_connector_upsert", `
		INSERT INTO correlation_connector_instances (
			connector_instance_id, connector, export_custody, profile_version,
			managed_config_digest, is_default, created_time_unix_nano, updated_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector_instance_id) DO UPDATE SET
			export_custody=excluded.export_custody,
			profile_version=excluded.profile_version,
			managed_config_digest=excluded.managed_config_digest,
			updated_time_unix_nano=excluded.updated_time_unix_nano
		WHERE correlation_connector_instances.connector=excluded.connector
		  AND excluded.updated_time_unix_nano >= correlation_connector_instances.updated_time_unix_nano`,
		string(instance.ConnectorInstanceID), instance.Connector, string(instance.ExportCustody),
		instance.ProfileVersion, nullStr(instance.ManagedConfigDigest), boolInt(instance.Default),
		unixNano(instance.CreatedAt), unixNano(instance.UpdatedAt),
	)
	if err != nil {
		return ConnectorInstance{}, fmt.Errorf("audit: upsert connector instance: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ConnectorInstance{}, ErrCorrelationStale
	}
	return repo.GetConnectorInstance(ctx, instance.ConnectorInstanceID)
}

func (repo *CorrelationRepository) GetConnectorInstance(
	ctx context.Context,
	id ConnectorInstanceID,
) (ConnectorInstance, error) {
	if ctx == nil {
		return ConnectorInstance{}, errors.New("audit: correlation context is required")
	}
	if err := validateUUIDv7("connector instance id", string(id)); err != nil {
		return ConnectorInstance{}, err
	}
	var result ConnectorInstance
	var digest sql.NullString
	var created, updated int64
	var isDefault int
	err := repo.store.db.QueryRowContext(ctx, `SELECT connector_instance_id, connector,
		export_custody, profile_version, managed_config_digest, is_default, created_time_unix_nano,
		updated_time_unix_nano FROM correlation_connector_instances
		WHERE connector_instance_id=?`, string(id)).Scan(
		&result.ConnectorInstanceID, &result.Connector, &result.ExportCustody,
		&result.ProfileVersion, &digest, &isDefault, &created, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectorInstance{}, ErrCorrelationNotFound
	}
	if err != nil {
		return ConnectorInstance{}, fmt.Errorf("audit: get connector instance: %w", err)
	}
	result.ManagedConfigDigest = digest.String
	result.Default = isDefault != 0
	result.CreatedAt = time.Unix(0, created).UTC()
	result.UpdatedAt = time.Unix(0, updated).UTC()
	return result, nil
}

func (repo *CorrelationRepository) ListConnectorInstances(
	ctx context.Context,
) ([]ConnectorInstance, error) {
	if ctx == nil {
		return nil, errors.New("audit: correlation context is required")
	}
	rows, err := repo.store.queryDB(ctx, "correlation_connector_list", `SELECT
		connector_instance_id, connector, export_custody, profile_version,
		managed_config_digest, is_default, created_time_unix_nano, updated_time_unix_nano
		FROM correlation_connector_instances ORDER BY connector, connector_instance_id`)
	if err != nil {
		return nil, fmt.Errorf("audit: list connector instances: %w", err)
	}
	defer rows.Close()
	var result []ConnectorInstance
	for rows.Next() {
		var instance ConnectorInstance
		var digest sql.NullString
		var created, updated int64
		var isDefault int
		if err := rows.Scan(&instance.ConnectorInstanceID, &instance.Connector,
			&instance.ExportCustody, &instance.ProfileVersion, &digest, &isDefault, &created, &updated); err != nil {
			return nil, fmt.Errorf("audit: scan connector instance: %w", err)
		}
		instance.ManagedConfigDigest = digest.String
		instance.Default = isDefault != 0
		instance.CreatedAt = time.Unix(0, created).UTC()
		instance.UpdatedAt = time.Unix(0, updated).UTC()
		result = append(result, instance)
	}
	return result, rows.Err()
}

type CorrelationTx struct {
	repo                      *CorrelationRepository
	tx                        *sql.Tx
	release                   func()
	closed                    bool
	existingSemanticEventID   SemanticEventID
	existingConnectorInstance ConnectorInstanceID
}

// BeginExistingOccurrence opens a write transaction scoped to one immutable
// accepted occurrence. It is the attach path for a later native OTLP leaf (or
// another rail) that reports an existing semantic event ID: callers can add
// typed identifiers, observations, relationships, and evidence without
// resubmitting or changing the original event metadata.
func (repo *CorrelationRepository) BeginExistingOccurrence(
	ctx context.Context,
	semanticEventID SemanticEventID,
) (*CorrelationTx, CorrelationEvent, error) {
	var empty CorrelationEvent
	if repo == nil || repo.store == nil {
		return nil, empty, errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return nil, empty, errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	if err := validateUUIDv7("semantic event id", string(semanticEventID)); err != nil {
		return nil, empty, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return nil, empty, err
	}
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		release()
		return nil, empty, fmt.Errorf("audit: begin existing correlation occurrence: %w", err)
	}
	correlationTx := &CorrelationTx{repo: repo, tx: tx, release: release}
	fail := func(cause error) (*CorrelationTx, CorrelationEvent, error) {
		_ = correlationTx.Rollback()
		return nil, empty, cause
	}
	event, err := scanCorrelationEvent(tx.QueryRowContext(ctx, `SELECT semantic_event_id,
		logical_group_id, connector, connector_instance_id, source_rail, event_name,
		source_time_unix_nano, received_time_unix_nano, source_event_digest,
		fingerprint_sha256, first_request_id, first_record_id, profile_version, completeness
		FROM correlation_events WHERE semantic_event_id=?`, string(semanticEventID)))
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrCorrelationNotFound)
	}
	if err != nil {
		return fail(fmt.Errorf("audit: load existing correlation occurrence: %w", err))
	}
	correlationTx.existingSemanticEventID = event.SemanticEventID
	correlationTx.existingConnectorInstance = event.ConnectorInstanceID
	return correlationTx, event, nil
}

// BeginExistingOccurrenceWithReceipt atomically attaches a new exact-delivery
// receipt to an immutable occurrence or advances an existing delivery count.
// A reused source key with different bytes is returned as a conflict and is
// deliberately not inserted here: the caller must roll this transaction back
// and pass a distinct event through BeginOccurrence, whose receipt claim is the
// authoritative race-closing write.
func (repo *CorrelationRepository) BeginExistingOccurrenceWithReceipt(
	ctx context.Context,
	semanticEventID SemanticEventID,
	claim CorrelationReceiptClaim,
) (*CorrelationTx, CorrelationEvent, CorrelationOccurrenceResult, error) {
	var emptyEvent CorrelationEvent
	var emptyResult CorrelationOccurrenceResult
	tx, event, err := repo.BeginExistingOccurrence(ctx, semanticEventID)
	if err != nil {
		return nil, emptyEvent, emptyResult, err
	}
	fail := func(cause error) (*CorrelationTx, CorrelationEvent, CorrelationOccurrenceResult, error) {
		_ = tx.Rollback()
		return nil, emptyEvent, emptyResult, cause
	}
	if err := validateReceiptClaim(claim); err != nil {
		return fail(err)
	}
	result, err := tx.claimReceipt(ctx, event, claim)
	if err != nil {
		return fail(err)
	}
	if result.Status == CorrelationOccurrenceReplay && result.SemanticEventID != event.SemanticEventID {
		return fail(ErrCorrelationConflict)
	}
	if result.Status == CorrelationOccurrenceConflict {
		return tx, event, result, nil
	}
	if result.Status == CorrelationOccurrenceNew {
		if err := tx.insertClaimedReceipt(ctx, event, claim, result); err != nil {
			return fail(err)
		}
		result.Status = CorrelationOccurrenceExisting
	}
	return tx, event, result, nil
}

func (repo *CorrelationRepository) BeginOccurrence(
	ctx context.Context,
	input CorrelationOccurrenceInput,
) (*CorrelationTx, CorrelationOccurrenceResult, error) {
	var empty CorrelationOccurrenceResult
	if repo == nil || repo.store == nil {
		return nil, empty, errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return nil, empty, errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	if input.Event.SemanticEventID == "" {
		id, err := NewSemanticEventID()
		if err != nil {
			return nil, empty, err
		}
		input.Event.SemanticEventID = id
	}
	if input.Event.LogicalEventID == "" {
		input.Event.LogicalEventID = LogicalEventID(input.Event.SemanticEventID)
	}
	if input.Event.ReceivedTime.IsZero() {
		input.Event.ReceivedTime = time.Now().UTC()
	}
	if err := validateCorrelationEvent(input.Event); err != nil {
		return nil, empty, err
	}
	if len(input.ExactIdentityClaims) > maxCorrelationIdentityClaims {
		return nil, empty, fmt.Errorf("audit: at most %d exact identity claims may be submitted", maxCorrelationIdentityClaims)
	}
	seenClaims := make(map[string]struct{}, len(input.ExactIdentityClaims))
	for _, claim := range input.ExactIdentityClaims {
		if err := validateExactIdentityClaim(input.Event, claim); err != nil {
			return nil, empty, err
		}
		key := exactIdentityClaimKey(claim)
		if _, exists := seenClaims[key]; exists {
			return nil, empty, errors.New("audit: duplicate exact identity claim")
		}
		seenClaims[key] = struct{}{}
	}
	if input.Receipt != nil {
		if input.Receipt.ReceivedAt.IsZero() {
			input.Receipt.ReceivedAt = input.Event.ReceivedTime
		}
		if err := validateReceiptClaim(*input.Receipt); err != nil {
			return nil, empty, err
		}
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return nil, empty, err
	}
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		release()
		return nil, empty, fmt.Errorf("audit: begin correlation occurrence: %w", err)
	}
	correlationTx := &CorrelationTx{repo: repo, tx: tx, release: release}
	fail := func(cause error) (*CorrelationTx, CorrelationOccurrenceResult, error) {
		_ = correlationTx.Rollback()
		return nil, empty, cause
	}

	result := CorrelationOccurrenceResult{
		SemanticEventID: input.Event.SemanticEventID,
		LogicalEventID:  input.Event.LogicalEventID,
		Status:          CorrelationOccurrenceNew,
		DeliveryCount:   1,
	}
	if input.Receipt != nil {
		receiptResult, err := correlationTx.claimReceipt(ctx, input.Event, *input.Receipt)
		if err != nil {
			return fail(err)
		}
		result = receiptResult
		if result.Status == CorrelationOccurrenceReplay {
			return correlationTx, result, nil
		}
		input.Event.SemanticEventID = result.SemanticEventID
		if input.Event.LogicalEventID == "" || result.Status == CorrelationOccurrenceConflict {
			input.Event.LogicalEventID = LogicalEventID(result.SemanticEventID)
		}
	}
	// A receipt conflict means the sender reused one exact source key for
	// different bytes. That occurrence must remain isolated even if it also
	// carries an otherwise eligible native mirror ID; weaker identity evidence
	// can never hide or group an integrity conflict.
	if len(input.ExactIdentityClaims) != 0 && result.Status != CorrelationOccurrenceConflict {
		logical, evidence, err := correlationTx.claimExactIdentities(ctx, input.Event, input.ExactIdentityClaims)
		if err != nil {
			return fail(err)
		}
		input.Event.LogicalEventID = logical
		result.LogicalEventID = logical
		result.IdentityEvidence = evidence
		if len(evidence) != 0 {
			result.MatchedSemanticEventID = evidence[0].SemanticEventID
			result.MatchedLogicalEventID = evidence[0].LogicalEventID
		}
	} else {
		result.LogicalEventID = input.Event.LogicalEventID
	}
	created, err := correlationTx.putEvent(ctx, input.Event)
	if err != nil {
		return fail(err)
	}
	if !created && input.Receipt == nil {
		result.Status = CorrelationOccurrenceExisting
	}
	if input.Receipt != nil {
		if err := correlationTx.insertClaimedReceipt(ctx, input.Event, *input.Receipt, result); err != nil {
			return fail(err)
		}
	}
	return correlationTx, result, nil
}

func (tx *CorrelationTx) claimExactIdentities(
	ctx context.Context,
	event CorrelationEvent,
	claims []CorrelationExactIdentityClaim,
) (LogicalEventID, []CorrelationExactIdentityEvidence, error) {
	logical := event.LogicalEventID
	evidence := make([]CorrelationExactIdentityEvidence, 0, len(claims))
	ownedClaims := make([]bool, len(claims))
	for claimIndex, claim := range claims {
		railA, railB := canonicalRailPair(claim.Rail, claim.CompatibleRail)
		result, err := txExecContextObserved(ctx, tx.tx, "correlation_identity_claim_insert",
			tx.repo.store.sqliteBusyObservabilityV8(), `INSERT OR IGNORE INTO correlation_identity_claims (
				connector_instance_id, namespace, identifier_kind, value_digest, event_name,
				rail_a, rail_b, rule_id, rule_version, source_rail, semantic_event_id,
				logical_group_id, created_time_unix_nano
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			string(event.ConnectorInstanceID), claim.Namespace, string(claim.Kind), claim.ValueDigest,
			claim.EventName, string(railA), string(railB), claim.RuleID, claim.RuleVersion,
			string(claim.Rail), string(event.SemanticEventID), string(logical), unixNano(event.ReceivedTime))
		if err != nil {
			return "", nil, fmt.Errorf("audit: claim exact correlation identity: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return "", nil, fmt.Errorf("audit: inspect exact correlation identity claim: %w", err)
		}
		if inserted == 0 {
			var existingSemantic, existingLogical string
			err = tx.tx.QueryRowContext(ctx, `SELECT semantic_event_id, logical_group_id
				FROM correlation_identity_claims WHERE connector_instance_id=? AND namespace=?
				AND identifier_kind=? AND value_digest=? AND event_name=? AND rail_a=? AND rail_b=?
				AND rule_id=? AND rule_version=? AND source_rail=?`,
				string(event.ConnectorInstanceID), claim.Namespace, string(claim.Kind), claim.ValueDigest,
				claim.EventName, string(railA), string(railB), claim.RuleID, claim.RuleVersion,
				string(claim.Rail)).Scan(&existingSemantic, &existingLogical)
			if err != nil {
				return "", nil, fmt.Errorf("audit: inspect existing exact identity claim: %w", err)
			}
			candidate := LogicalEventID(existingLogical)
			if SemanticEventID(existingSemantic) != event.SemanticEventID {
				// A provider-authoritative occurrence ID can be delivered more
				// than once on one rail under distinct source-delivery IDs. Keep
				// both semantic observations, but converge them on the first
				// claimed logical occurrence and retain explicit evidence.
				if logical != candidate && logical != LogicalEventID(event.SemanticEventID) {
					return "", nil, fmt.Errorf("audit: same-rail exact identity resolves to a different logical group: %w", ErrCorrelationConflict)
				}
				logical = candidate
				evidence = append(evidence, CorrelationExactIdentityEvidence{
					Namespace: claim.Namespace, Kind: claim.Kind, ValueDigest: claim.ValueDigest,
					EventName: claim.EventName, Rail: claim.Rail, CounterpartRail: claim.Rail,
					RuleID: "same-rail-exact-identity-repeat", RuleVersion: claim.RuleVersion,
					SemanticEventID: SemanticEventID(existingSemantic), LogicalEventID: candidate,
				})
			} else if candidate != logical {
				if logical != LogicalEventID(event.SemanticEventID) {
					return "", nil, fmt.Errorf("audit: exact identity logical group disagreement: %w", ErrCorrelationConflict)
				}
				logical = candidate
			}
			ownedClaims[claimIndex] = SemanticEventID(existingSemantic) == event.SemanticEventID
		} else {
			ownedClaims[claimIndex] = true
		}

		var counterpartSemantic, counterpartLogical string
		err = tx.tx.QueryRowContext(ctx, `SELECT semantic_event_id, logical_group_id
			FROM correlation_identity_claims WHERE connector_instance_id=? AND namespace=?
			AND identifier_kind=? AND value_digest=? AND event_name=? AND rail_a=? AND rail_b=?
			AND rule_id=? AND rule_version=? AND source_rail=?`,
			string(event.ConnectorInstanceID), claim.Namespace, string(claim.Kind), claim.ValueDigest,
			claim.EventName, string(railA), string(railB), claim.RuleID, claim.RuleVersion,
			string(claim.CompatibleRail)).Scan(&counterpartSemantic, &counterpartLogical)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", nil, fmt.Errorf("audit: resolve exact identity counterpart: %w", err)
		}
		if err == nil {
			candidate := LogicalEventID(counterpartLogical)
			if logical != candidate && logical != LogicalEventID(event.SemanticEventID) {
				return "", nil, fmt.Errorf("audit: exact identity claims resolve to different logical groups: %w", ErrCorrelationConflict)
			}
			logical = candidate
			evidence = append(evidence, CorrelationExactIdentityEvidence{
				Namespace: claim.Namespace, Kind: claim.Kind, ValueDigest: claim.ValueDigest,
				EventName: claim.EventName, Rail: claim.Rail, CounterpartRail: claim.CompatibleRail,
				RuleID: claim.RuleID, RuleVersion: claim.RuleVersion,
				SemanticEventID: SemanticEventID(counterpartSemantic), LogicalEventID: candidate,
			})
		}
	}
	for claimIndex, claim := range claims {
		if !ownedClaims[claimIndex] {
			continue
		}
		railA, railB := canonicalRailPair(claim.Rail, claim.CompatibleRail)
		result, err := txExecContextObserved(ctx, tx.tx, "correlation_identity_claim_group",
			tx.repo.store.sqliteBusyObservabilityV8(), `UPDATE correlation_identity_claims
			SET logical_group_id=? WHERE connector_instance_id=? AND namespace=? AND identifier_kind=?
			AND value_digest=? AND event_name=? AND rail_a=? AND rail_b=? AND rule_id=?
			AND rule_version=? AND source_rail=? AND semantic_event_id=?`,
			string(logical), string(event.ConnectorInstanceID), claim.Namespace, string(claim.Kind),
			claim.ValueDigest, claim.EventName, string(railA), string(railB), claim.RuleID,
			claim.RuleVersion, string(claim.Rail), string(event.SemanticEventID))
		if err != nil {
			return "", nil, fmt.Errorf("audit: update exact identity logical group: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return "", nil, ErrCorrelationConflict
		}
	}
	return logical, evidence, nil
}

func (tx *CorrelationTx) PutEvent(ctx context.Context, event CorrelationEvent) error {
	if err := tx.usable(ctx); err != nil {
		return err
	}
	if tx.existingSemanticEventID != "" {
		return fmt.Errorf("audit: existing correlation occurrence is immutable: %w", ErrCorrelationConflict)
	}
	_, err := tx.putEvent(ctx, event)
	return err
}

func (tx *CorrelationTx) putEvent(ctx context.Context, event CorrelationEvent) (bool, error) {
	if err := tx.usable(ctx); err != nil {
		return false, err
	}
	if err := validateCorrelationEvent(event); err != nil {
		return false, err
	}
	result, err := txExecContextObserved(ctx, tx.tx, "correlation_event_insert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT OR IGNORE INTO correlation_events (
			semantic_event_id, logical_group_id, connector, connector_instance_id, source_rail,
			event_name, source_time_unix_nano, received_time_unix_nano, source_event_digest,
			fingerprint_sha256, first_request_id, first_record_id, profile_version, completeness
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(event.SemanticEventID), string(event.LogicalEventID), event.Connector,
		string(event.ConnectorInstanceID), string(event.Rail), event.EventName,
		nullTimeUnixNano(event.SourceTime), unixNano(event.ReceivedTime), nullStr(event.SourceEventDigest),
		nullStr(event.FingerprintSHA256), nullStr(event.FirstRequestID), nullStr(event.FirstRecordID),
		event.ProfileVersion, string(event.Completeness),
	)
	if err != nil {
		return false, fmt.Errorf("audit: insert correlation event: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("audit: inspect correlation event insert: %w", err)
	}
	if rows == 1 {
		return true, nil
	}
	var logical, connector, instance, rail, eventName, profile string
	err = tx.tx.QueryRowContext(ctx, `SELECT logical_group_id, connector, connector_instance_id, source_rail,
		event_name, profile_version FROM correlation_events WHERE semantic_event_id=?`,
		string(event.SemanticEventID)).Scan(&logical, &connector, &instance, &rail, &eventName, &profile)
	if err != nil {
		return false, fmt.Errorf("audit: verify existing correlation event: %w", err)
	}
	if logical != string(event.LogicalEventID) || connector != event.Connector || instance != string(event.ConnectorInstanceID) ||
		rail != string(event.Rail) || eventName != event.EventName || profile != event.ProfileVersion {
		return false, ErrCorrelationConflict
	}
	return false, nil
}

func (tx *CorrelationTx) claimReceipt(
	ctx context.Context,
	event CorrelationEvent,
	claim CorrelationReceiptClaim,
) (CorrelationOccurrenceResult, error) {
	result := CorrelationOccurrenceResult{
		SemanticEventID: event.SemanticEventID,
		LogicalEventID:  event.LogicalEventID,
		Status:          CorrelationOccurrenceNew,
		DeliveryCount:   1,
		Receipt: &CorrelationReceiptLocator{
			ConnectorInstanceID: event.ConnectorInstanceID,
			SemanticEventID:     event.SemanticEventID,
			SourceKeyDigest:     claim.SourceKeyDigest,
			FingerprintSHA256:   claim.FingerprintSHA256,
		},
	}
	var semantic, logical string
	var deliveries uint64
	var accepted sql.NullInt64
	err := tx.tx.QueryRowContext(ctx, `SELECT receipt.semantic_event_id, event.logical_group_id,
		receipt.delivery_count, receipt.accepted_time_unix_nano
		FROM correlation_receipts receipt JOIN correlation_events event
			ON event.semantic_event_id=receipt.semantic_event_id
		WHERE receipt.connector_instance_id=? AND receipt.source_key_digest=?
		AND receipt.fingerprint_sha256=?`, string(event.ConnectorInstanceID), claim.SourceKeyDigest,
		claim.FingerprintSHA256).Scan(&semantic, &logical, &deliveries, &accepted)
	if err == nil {
		updated, updateErr := txExecContextObserved(ctx, tx.tx, "correlation_receipt_replay",
			tx.repo.store.sqliteBusyObservabilityV8(), `UPDATE correlation_receipts SET
			last_received_time_unix_nano=MAX(last_received_time_unix_nano, ?), delivery_count=delivery_count+1,
			expires_time_unix_nano=MAX(expires_time_unix_nano, ?)
			WHERE connector_instance_id=? AND source_key_digest=? AND fingerprint_sha256=?`,
			unixNano(claim.ReceivedAt), unixNano(claim.ExpiresAt), string(event.ConnectorInstanceID),
			claim.SourceKeyDigest, claim.FingerprintSHA256)
		if updateErr != nil {
			return result, fmt.Errorf("audit: update exact correlation receipt: %w", updateErr)
		}
		changed, _ := updated.RowsAffected()
		if changed != 1 {
			return result, ErrCorrelationConflict
		}
		result.SemanticEventID = SemanticEventID(semantic)
		result.LogicalEventID = LogicalEventID(logical)
		result.Receipt.SemanticEventID = result.SemanticEventID
		result.Status = CorrelationOccurrenceReplay
		result.DeliveryCount = deliveries + 1
		result.SuppressEmission = accepted.Valid
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("audit: query exact correlation receipt: %w", err)
	}
	var conflicting string
	err = tx.tx.QueryRowContext(ctx, `SELECT semantic_event_id FROM correlation_receipts
		WHERE connector_instance_id=? AND source_key_digest=? AND fingerprint_sha256<>?
		ORDER BY first_received_time_unix_nano, semantic_event_id LIMIT 1`,
		string(event.ConnectorInstanceID), claim.SourceKeyDigest, claim.FingerprintSHA256).Scan(&conflicting)
	if err == nil {
		// A reused exact source key with different bytes is a distinct,
		// conflicted occurrence. A sender may also repeat a previously accepted
		// DefenseClaw semantic ID, so do not let INSERT OR IGNORE attach the new
		// payload to that immutable event. This check is inside the receipt
		// transaction; it closes the race between a read-only MatchOccurrence
		// preflight and the authoritative receipt claim.
		var exists int
		existsErr := tx.tx.QueryRowContext(ctx, `SELECT 1 FROM correlation_events
			WHERE semantic_event_id=?`, string(event.SemanticEventID)).Scan(&exists)
		if existsErr == nil {
			fresh, freshErr := NewSemanticEventID()
			if freshErr != nil {
				return result, freshErr
			}
			result.SemanticEventID = fresh
			result.Receipt.SemanticEventID = fresh
		} else if !errors.Is(existsErr, sql.ErrNoRows) {
			return result, fmt.Errorf("audit: check conflicting semantic occurrence: %w", existsErr)
		}
		result.Status = CorrelationOccurrenceConflict
		result.ConflictsWith = SemanticEventID(conflicting)
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("audit: query conflicting correlation receipt: %w", err)
	}
	return result, nil
}

func (tx *CorrelationTx) insertClaimedReceipt(
	ctx context.Context,
	event CorrelationEvent,
	claim CorrelationReceiptClaim,
	result CorrelationOccurrenceResult,
) error {
	_, err := txExecContextObserved(ctx, tx.tx, "correlation_receipt_insert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_receipts (
			connector_instance_id, source_key_digest, fingerprint_sha256, semantic_event_id,
			conflicts_with_semantic_event_id, first_received_time_unix_nano,
			last_received_time_unix_nano, delivery_count, accepted_time_unix_nano, expires_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`, string(event.ConnectorInstanceID),
		claim.SourceKeyDigest, claim.FingerprintSHA256, string(result.SemanticEventID),
		nullStr(string(result.ConflictsWith)), unixNano(claim.ReceivedAt), unixNano(claim.ReceivedAt),
		nil, unixNano(claim.ExpiresAt))
	if err != nil {
		return fmt.Errorf("audit: insert correlation receipt: %w", err)
	}
	return nil
}

func (repo *CorrelationRepository) markReceiptCanonicalPersisted(
	ctx context.Context,
	instance ConnectorInstanceID,
	sourceKeyDigest string,
	fingerprintSHA256 string,
	semantic SemanticEventID,
	acceptedAt time.Time,
) error {
	if repo == nil || repo.store == nil {
		return errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateUUIDv7("connector instance id", string(instance)); err != nil {
		return err
	}
	if err := validateSHA256("receipt source key digest", sourceKeyDigest, true); err != nil {
		return err
	}
	if err := validateSHA256("receipt fingerprint", fingerprintSHA256, true); err != nil {
		return err
	}
	if err := validateUUIDv7("semantic event id", string(semantic)); err != nil {
		return err
	}
	if acceptedAt.IsZero() {
		return errors.New("audit: receipt acceptance time is required")
	}
	const observationGuard = ` AND EXISTS (
            SELECT 1 FROM correlation_observations AS observation
            WHERE observation.semantic_event_id=correlation_receipts.semantic_event_id
              AND observation.status='export_eligible'
              AND observation.bucket<>'telemetry.ingest'
            )`
	result, err := repo.store.execDB(ctx, "correlation_receipt_accept", `
		UPDATE correlation_receipts SET accepted_time_unix_nano=COALESCE(
			accepted_time_unix_nano, MAX(?, first_received_time_unix_nano))
		WHERE connector_instance_id=? AND source_key_digest=? AND fingerprint_sha256=?
		  AND semantic_event_id=?`+observationGuard, unixNano(acceptedAt), string(instance), sourceKeyDigest,
		fingerprintSHA256, string(semantic))
	if err != nil {
		return fmt.Errorf("audit: mark correlation receipt accepted: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect accepted correlation receipt: %w", err)
	}
	if rows != 1 {
		return ErrCorrelationNotFound
	}
	return nil
}

// MarkOccurrenceCanonicalPersisted finalizes exactly one pending receipt.
// Hooks, native OTLP, proxy, and stream coordinators may all use this API only
// after their canonical local observation/export-eligibility commit succeeds.
func (repo *CorrelationRepository) MarkOccurrenceCanonicalPersisted(
	ctx context.Context,
	receipt CorrelationReceiptLocator,
	acceptedAt time.Time,
) error {
	return repo.markReceiptCanonicalPersisted(ctx, receipt.ConnectorInstanceID,
		receipt.SourceKeyDigest, receipt.FingerprintSHA256,
		receipt.SemanticEventID, acceptedAt)
}

func (tx *CorrelationTx) PutObservation(ctx context.Context, observation CorrelationObservation) error {
	if err := tx.usable(ctx); err != nil {
		return err
	}
	if err := tx.requireExistingOccurrenceTarget(observation.SemanticEventID, ""); err != nil {
		return err
	}
	return putCorrelationObservationTx(ctx, tx.tx, tx.repo.store, observation)
}

// RecordObservation durably commits metadata for an already accepted
// occurrence. Runtime trace and metric paths call this before handing a signal
// to a provider/exporter, preserving commit-before-export without storing the
// trace or metric payload in audit.db.
func (repo *CorrelationRepository) RecordObservation(
	ctx context.Context,
	observation CorrelationObservation,
) error {
	if repo == nil || repo.store == nil {
		return errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return errors.New("audit: correlation context is required")
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin correlation observation write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := putCorrelationObservationTx(ctx, tx, repo.store, observation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit correlation observation: %w", err)
	}
	return nil
}

func putCorrelationObservationTx(
	ctx context.Context,
	tx *sql.Tx,
	store *Store,
	observation CorrelationObservation,
) error {
	if ctx == nil || tx == nil || store == nil {
		return errors.New("audit: correlation observation transaction is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = time.Now().UTC()
	}
	if err := validateObservation(observation); err != nil {
		return err
	}
	_, err := txExecContextObserved(ctx, tx, "correlation_observation_insert",
		store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_observations (
			record_id, semantic_event_id, signal, bucket, event_name, observed_time_unix_nano,
			trace_id, span_id, session_id, turn_id, agent_id, lifecycle_id, execution_id,
			model_request_id, model_response_id, tool_invocation_id, projection_hash, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observation.RecordID, string(observation.SemanticEventID), string(observation.Signal),
		observation.Bucket, observation.EventName, unixNano(observation.ObservedAt),
		nullStr(observation.TraceID), nullStr(observation.SpanID), nullStr(observation.SessionID),
		nullStr(observation.TurnID), nullStr(observation.AgentID), nullStr(observation.LifecycleID),
		nullStr(observation.ExecutionID), nullStr(observation.ModelRequestID),
		nullStr(observation.ModelResponseID), nullStr(observation.ToolInvocationID),
		nullStr(observation.ProjectionHash), string(observation.Status))
	if err != nil {
		return fmt.Errorf("audit: insert correlation observation: %w", err)
	}
	return nil
}

func (tx *CorrelationTx) PutIdentifier(ctx context.Context, identifier CorrelationIdentifier) (string, error) {
	if err := tx.usable(ctx); err != nil {
		return "", err
	}
	if err := tx.requireExistingOccurrenceTarget(identifier.SemanticEventID, identifier.ConnectorInstanceID); err != nil {
		return "", err
	}
	if identifier.ObservedAt.IsZero() {
		identifier.ObservedAt = time.Now().UTC()
	}
	if err := validateIdentifier(identifier); err != nil {
		return "", err
	}
	id := deterministicCorrelationID("id_", string(identifier.ConnectorInstanceID),
		identifier.Namespace, string(identifier.Kind), identifier.ValueDigest,
		string(identifier.SemanticEventID))
	result, err := txExecContextObserved(ctx, tx.tx, "correlation_identifier_upsert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_identifiers (
			identifier_id, semantic_event_id, connector_instance_id, namespace, identifier_kind,
			value_digest, normalized_value, source_field, origin, profile_version, created_time_unix_nano,
			last_seen_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(identifier_id) DO UPDATE SET
			last_seen_time_unix_nano=MAX(last_seen_time_unix_nano, excluded.last_seen_time_unix_nano)
		WHERE correlation_identifiers.normalized_value=excluded.normalized_value
		  AND correlation_identifiers.source_field=excluded.source_field
		  AND correlation_identifiers.origin=excluded.origin
		  AND correlation_identifiers.profile_version=excluded.profile_version`,
		id, string(identifier.SemanticEventID), string(identifier.ConnectorInstanceID),
		identifier.Namespace, string(identifier.Kind), identifier.ValueDigest, identifier.NormalizedValue,
		identifier.SourceField, string(identifier.Origin), identifier.ProfileVersion, unixNano(identifier.ObservedAt),
		unixNano(identifier.ObservedAt))
	if err != nil {
		return "", fmt.Errorf("audit: upsert correlation identifier: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("audit: inspect correlation identifier upsert: %w", err)
	}
	if changed != 1 {
		return "", ErrCorrelationConflict
	}
	return id, nil
}

func (tx *CorrelationTx) PutRelationship(
	ctx context.Context,
	input CorrelationRelationshipInput,
) (CorrelationRelationship, error) {
	if err := tx.usable(ctx); err != nil {
		return CorrelationRelationship{}, err
	}
	if input.ObservedAt.IsZero() {
		input.ObservedAt = time.Now().UTC()
	}
	if err := validateRelationshipInput(input); err != nil {
		return CorrelationRelationship{}, err
	}
	confidence := relationshipConfidence(input.Method)
	id := deterministicCorrelationID("rel_", string(input.FromKind), input.FromID,
		string(input.ToKind), input.ToID, string(input.Type), string(input.Method), input.RuleID,
		input.RuleVersion)
	_, err := txExecContextObserved(ctx, tx.tx, "correlation_relationship_upsert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_relationships (
			relationship_id, from_kind, from_id, to_kind, to_id, relationship_type, method,
			confidence, rule_id, rule_version, status, created_time_unix_nano,
			last_seen_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(relationship_id) DO UPDATE SET
			status=excluded.status,
			last_seen_time_unix_nano=MAX(last_seen_time_unix_nano, excluded.last_seen_time_unix_nano)`,
		id, string(input.FromKind), input.FromID, string(input.ToKind), input.ToID,
		string(input.Type), string(input.Method), confidence, input.RuleID, input.RuleVersion,
		string(input.Status), unixNano(input.ObservedAt), unixNano(input.ObservedAt))
	if err != nil {
		return CorrelationRelationship{}, fmt.Errorf("audit: upsert correlation relationship: %w", err)
	}
	return CorrelationRelationship{
		RelationshipID: id, FromKind: input.FromKind, FromID: input.FromID,
		ToKind: input.ToKind, ToID: input.ToID, Type: input.Type, Method: input.Method,
		Confidence: confidence, RuleID: input.RuleID, RuleVersion: input.RuleVersion,
		Status: input.Status, CreatedAt: input.ObservedAt, LastSeenAt: input.ObservedAt,
	}, nil
}

func (tx *CorrelationTx) PutRelationshipEvidence(
	ctx context.Context,
	evidence CorrelationRelationshipEvidence,
) (string, error) {
	if err := tx.usable(ctx); err != nil {
		return "", err
	}
	if evidence.SemanticEventID != "" {
		if err := tx.requireExistingOccurrenceTarget(evidence.SemanticEventID, ""); err != nil {
			return "", err
		}
	}
	if evidence.CreatedAt.IsZero() {
		evidence.CreatedAt = time.Now().UTC()
	}
	if err := validateEvidence(evidence); err != nil {
		return "", err
	}
	evidenceValue := evidence.RecordID
	if evidenceValue == "" {
		evidenceValue = string(evidence.SemanticEventID)
	}
	id := deterministicCorrelationID("ev_", evidence.RelationshipID, evidenceValue, string(evidence.Role))
	_, err := txExecContextObserved(ctx, tx.tx, "correlation_evidence_upsert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_relationship_evidence (
			evidence_id, relationship_id, evidence_record_id, semantic_event_id, evidence_role,
			integrity_state, created_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(evidence_id) DO UPDATE SET integrity_state=excluded.integrity_state`,
		id, evidence.RelationshipID, nullStr(evidence.RecordID),
		nullStr(string(evidence.SemanticEventID)), string(evidence.Role), string(evidence.Integrity),
		unixNano(evidence.CreatedAt))
	if err != nil {
		return "", fmt.Errorf("audit: upsert correlation relationship evidence: %w", err)
	}
	return id, nil
}

// RelationshipEvidenceCount returns the durable number of distinct evidence
// rows supporting a relationship inside the caller-owned transaction. Export
// callers use this after PutRelationshipEvidence so remote relationship-change
// records describe ledger state instead of a per-delivery constant.
func (tx *CorrelationTx) RelationshipEvidenceCount(
	ctx context.Context,
	relationshipID string,
) (int64, error) {
	if err := tx.usable(ctx); err != nil {
		return 0, err
	}
	if err := validateBoundedIdentifier(
		"relationship id", relationshipID, true, maxCorrelationTokenBytes,
	); err != nil {
		return 0, err
	}
	var count int64
	if err := tx.tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM correlation_relationship_evidence WHERE relationship_id = ?`,
		relationshipID).Scan(&count); err != nil {
		return 0, fmt.Errorf("audit: count correlation relationship evidence: %w", err)
	}
	return count, nil
}

func (tx *CorrelationTx) requireExistingOccurrenceTarget(
	semanticEventID SemanticEventID,
	connectorInstanceID ConnectorInstanceID,
) error {
	if tx == nil || tx.existingSemanticEventID == "" {
		return nil
	}
	if semanticEventID != tx.existingSemanticEventID {
		return fmt.Errorf("audit: existing occurrence semantic event mismatch: %w", ErrCorrelationConflict)
	}
	if connectorInstanceID != "" && connectorInstanceID != tx.existingConnectorInstance {
		return fmt.Errorf("audit: existing occurrence connector instance mismatch: %w", ErrCorrelationConflict)
	}
	return nil
}

func (tx *CorrelationTx) PutCursor(ctx context.Context, cursor CorrelationCursor) error {
	if err := tx.usable(ctx); err != nil {
		return err
	}
	if cursor.UpdatedAt.IsZero() {
		cursor.UpdatedAt = time.Now().UTC()
	}
	if err := validateCursor(cursor); err != nil {
		return err
	}
	result, err := txExecContextObserved(ctx, tx.tx, "correlation_cursor_upsert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_cursors (
			connector_instance_id, session_id, agent_id, lifecycle_id, execution_id,
			active_turn_id, active_prompt_id, phase, sequence, root_agent_id, parent_agent_id,
			root_session_id, parent_session_id, last_semantic_event_id, last_record_id,
			profile_version, active, updated_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector_instance_id, session_id, agent_id) DO UPDATE SET
			lifecycle_id=excluded.lifecycle_id, execution_id=excluded.execution_id,
			active_turn_id=excluded.active_turn_id, active_prompt_id=excluded.active_prompt_id,
			phase=excluded.phase, sequence=excluded.sequence, root_agent_id=excluded.root_agent_id,
			parent_agent_id=excluded.parent_agent_id, root_session_id=excluded.root_session_id,
			parent_session_id=excluded.parent_session_id,
			last_semantic_event_id=excluded.last_semantic_event_id,
			last_record_id=excluded.last_record_id, profile_version=excluded.profile_version,
			active=excluded.active, updated_time_unix_nano=excluded.updated_time_unix_nano
		WHERE excluded.sequence >= correlation_cursors.sequence
		  AND excluded.updated_time_unix_nano >= correlation_cursors.updated_time_unix_nano`,
		string(cursor.ConnectorInstanceID), cursor.SessionID, cursor.AgentID,
		nullStr(cursor.LifecycleID), nullStr(cursor.ExecutionID), nullStr(cursor.ActiveTurnID),
		nullStr(cursor.ActivePromptID), cursor.Phase, cursor.Sequence, nullStr(cursor.RootAgentID),
		nullStr(cursor.ParentAgentID), nullStr(cursor.RootSessionID), nullStr(cursor.ParentSessionID),
		nullStr(string(cursor.LastSemanticEventID)), nullStr(cursor.LastRecordID),
		cursor.ProfileVersion, boolInt(cursor.Active), unixNano(cursor.UpdatedAt))
	if err != nil {
		return fmt.Errorf("audit: upsert correlation cursor: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrCorrelationStale
	}
	return nil
}

func (tx *CorrelationTx) PutPendingOperation(
	ctx context.Context,
	operation CorrelationPendingOperation,
) error {
	if err := tx.usable(ctx); err != nil {
		return err
	}
	if operation.Status == "" {
		operation.Status = CorrelationOperationActive
	}
	if operation.UpdatedAt.IsZero() {
		operation.UpdatedAt = operation.StartedAt
	}
	if err := validatePendingOperation(operation); err != nil {
		return err
	}
	result, err := txExecContextObserved(ctx, tx.tx, "correlation_pending_insert",
		tx.repo.store.sqliteBusyObservabilityV8(), `INSERT INTO correlation_pending_operations (
			connector_instance_id, operation_namespace, operation_kind, operation_id,
			operation_type, scope_kind, scope_id, operation_name, session_id, turn_id,
			agent_id, execution_id, start_semantic_event_id, start_time_unix_nano,
			input_digest, terminal_semantic_event_id, terminal_time_unix_nano, status,
			updated_time_unix_nano
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector_instance_id, operation_namespace, operation_kind,
			operation_id, operation_type, scope_kind, scope_id) DO NOTHING`,
		string(operation.ConnectorInstanceID), operation.Namespace, string(operation.Kind),
		operation.OperationID, string(operation.Type), string(operation.ScopeKind), operation.ScopeID,
		nullStr(operation.Name), nullStr(operation.SessionID), nullStr(operation.TurnID),
		nullStr(operation.AgentID), nullStr(operation.ExecutionID),
		string(operation.StartSemanticEventID), unixNano(operation.StartedAt),
		nullStr(operation.InputDigest), nullStr(string(operation.TerminalSemanticEventID)),
		nullTimeUnixNano(operation.TerminalAt), string(operation.Status), unixNano(operation.UpdatedAt))
	if err != nil {
		return fmt.Errorf("audit: insert correlation pending operation: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect correlation pending operation insert: %w", err)
	}
	if inserted == 1 {
		return nil
	}
	existing, err := scanCorrelationPending(tx.tx.QueryRowContext(ctx, correlationPendingSelect+`
		WHERE connector_instance_id=? AND operation_namespace=? AND operation_kind=?
		AND operation_id=? AND operation_type=? AND scope_kind=? AND scope_id=?`,
		string(operation.ConnectorInstanceID), operation.Namespace, string(operation.Kind),
		operation.OperationID, string(operation.Type), string(operation.ScopeKind), operation.ScopeID))
	if err != nil {
		return fmt.Errorf("audit: inspect correlation pending operation collision: %w", err)
	}
	if samePendingOperation(existing, operation) {
		return nil
	}
	if samePendingOperationIdentityContext(existing, operation) {
		var occurrences, groups int
		if err := tx.tx.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
			FROM correlation_events WHERE semantic_event_id IN (?, ?)`,
			string(existing.StartSemanticEventID), string(operation.StartSemanticEventID)).Scan(
			&occurrences, &groups,
		); err != nil {
			return fmt.Errorf("audit: inspect pending operation logical occurrence: %w", err)
		}
		if occurrences == 2 && groups == 1 {
			// Distinct deliveries of one provider-authoritative operation keep
			// distinct semantic observations. The first start remains the
			// durable pending owner while subsequent exact mirrors are no-ops.
			return nil
		}
	}
	return fmt.Errorf("audit: pending operation identity collision: %w", ErrCorrelationConflict)
}

func (tx *CorrelationTx) ResolvePendingOperation(
	ctx context.Context,
	locator CorrelationPendingLocator,
	terminalEventID SemanticEventID,
	status CorrelationOperationStatus,
	terminalAt time.Time,
) error {
	if err := tx.usable(ctx); err != nil {
		return err
	}
	if err := validatePendingLocator(locator); err != nil {
		return err
	}
	if status == CorrelationOperationActive || !validTerminalOperationStatus(status) {
		return errors.New("audit: invalid terminal correlation operation state")
	}
	if err := validateUUIDv7("terminal semantic event id", string(terminalEventID)); err != nil {
		return err
	}
	if terminalAt.IsZero() {
		terminalAt = time.Now().UTC()
	}
	result, err := txExecContextObserved(ctx, tx.tx, "correlation_pending_resolve",
		tx.repo.store.sqliteBusyObservabilityV8(), `UPDATE correlation_pending_operations SET
		terminal_semantic_event_id=?, terminal_time_unix_nano=?, status=?, updated_time_unix_nano=?
		WHERE connector_instance_id=? AND operation_namespace=? AND operation_kind=?
		AND operation_id=? AND operation_type=? AND scope_kind=? AND scope_id=? AND status='active'`,
		string(terminalEventID), unixNano(terminalAt), string(status), unixNano(terminalAt),
		string(locator.ConnectorInstanceID), locator.Namespace, string(locator.Kind), locator.OperationID,
		string(locator.Type), string(locator.ScopeKind), locator.ScopeID)
	if err != nil {
		return fmt.Errorf("audit: resolve correlation pending operation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect resolved correlation pending operation: %w", err)
	}
	if changed == 1 {
		return nil
	}
	var exactStatus string
	err = tx.tx.QueryRowContext(ctx, `SELECT status FROM correlation_pending_operations
		WHERE connector_instance_id=? AND operation_namespace=? AND operation_kind=?
		AND operation_id=? AND operation_type=? AND scope_kind=? AND scope_id=?`,
		string(locator.ConnectorInstanceID), locator.Namespace, string(locator.Kind), locator.OperationID,
		string(locator.Type), string(locator.ScopeKind), locator.ScopeID).Scan(&exactStatus)
	if err == nil {
		return ErrCorrelationStale
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit: inspect unresolved exact pending operation: %w", err)
	}
	var otherScope int
	err = tx.tx.QueryRowContext(ctx, `SELECT 1 FROM correlation_pending_operations
		WHERE connector_instance_id=? AND operation_namespace=? AND operation_kind=?
		AND operation_id=? AND operation_type=? AND status='active' LIMIT 1`,
		string(locator.ConnectorInstanceID), locator.Namespace, string(locator.Kind), locator.OperationID,
		string(locator.Type)).Scan(&otherScope)
	if err == nil {
		return fmt.Errorf("audit: pending operation exists in a different scope: %w", ErrCorrelationConflict)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit: inspect pending operation scope mismatch: %w", err)
	}
	return ErrCorrelationNotFound
}

func (tx *CorrelationTx) Commit() error {
	if tx == nil || tx.tx == nil || tx.closed {
		return errors.New("audit: correlation transaction is closed")
	}
	err := tx.tx.Commit()
	tx.finish()
	if err != nil {
		return fmt.Errorf("audit: commit correlation transaction: %w", err)
	}
	return nil
}

func (tx *CorrelationTx) Rollback() error {
	if tx == nil || tx.closed {
		return nil
	}
	err := tx.tx.Rollback()
	tx.finish()
	if err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("audit: rollback correlation transaction: %w", err)
	}
	return nil
}

func (tx *CorrelationTx) finish() {
	if tx == nil || tx.closed {
		return
	}
	tx.closed = true
	if tx.release != nil {
		tx.release()
		tx.release = nil
	}
}

func (tx *CorrelationTx) usable(ctx context.Context) error {
	if tx == nil || tx.tx == nil || tx.closed {
		return errors.New("audit: correlation transaction is closed")
	}
	if ctx == nil {
		return errors.New("audit: correlation context is required")
	}
	return ctx.Err()
}

func deterministicCorrelationID(prefix string, fields ...string) string {
	digest := sha256.New()
	for _, field := range fields {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(field))
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

func relationshipConfidence(method CorrelationRelationshipMethod) int {
	switch method {
	case CorrelationMethodReported, CorrelationMethodTraceExact:
		return 100
	case CorrelationMethodDerived:
		return 95
	case CorrelationMethodInferred:
		return 50
	default:
		return 0
	}
}

func unixNano(value time.Time) int64 { return value.UTC().UnixNano() }

func nullTimeUnixNano(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return unixNano(value)
}

func validateUUIDv7(field, value string) error {
	if value == "" {
		return fmt.Errorf("audit: %s is required", field)
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.Version() != 7 || parsed.String() != strings.ToLower(value) {
		return fmt.Errorf("audit: %s must be a canonical UUIDv7", field)
	}
	return nil
}

func validateBoundedIdentifier(field, value string, required bool, limit int) error {
	if value == "" {
		if required {
			return fmt.Errorf("audit: %s is required", field)
		}
		return nil
	}
	if !utf8.ValidString(value) || len(value) > limit || strings.TrimSpace(value) == "" {
		return fmt.Errorf("audit: %s is invalid or exceeds %d bytes", field, limit)
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("audit: %s contains a control character", field)
		}
	}
	return nil
}

func validateSHA256(field, value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return fmt.Errorf("audit: %s must be a lowercase full SHA-256 digest", field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("audit: %s must be a lowercase full SHA-256 digest", field)
	}
	return nil
}

func validateProjectionHash(value string) error {
	if value == "" {
		return nil
	}
	digest := value
	if strings.HasPrefix(digest, "sha256:") {
		digest = strings.TrimPrefix(digest, "sha256:")
	}
	return validateSHA256("projection hash", digest, true)
}

func validateTraceID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 32 || strings.ToLower(value) != value {
		return errors.New("audit: trace id must be 32 lowercase hexadecimal characters")
	}
	_, err := hex.DecodeString(value)
	if err != nil {
		return errors.New("audit: trace id must be 32 lowercase hexadecimal characters")
	}
	return nil
}

func validateSpanID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != 16 || strings.ToLower(value) != value {
		return errors.New("audit: span id must be 16 lowercase hexadecimal characters")
	}
	_, err := hex.DecodeString(value)
	if err != nil {
		return errors.New("audit: span id must be 16 lowercase hexadecimal characters")
	}
	return nil
}

func validateConnectorInstance(instance ConnectorInstance) error {
	if err := validateUUIDv7("connector instance id", string(instance.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("connector", instance.Connector, true, 64); err != nil {
		return err
	}
	if !validCustody(instance.ExportCustody) {
		return errors.New("audit: invalid connector export custody")
	}
	if err := validateBoundedIdentifier("profile version", instance.ProfileVersion, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	return validateSHA256("managed config digest", instance.ManagedConfigDigest, false)
}

func validateCorrelationEvent(event CorrelationEvent) error {
	if err := validateUUIDv7("semantic event id", string(event.SemanticEventID)); err != nil {
		return err
	}
	if err := validateUUIDv7("logical event id", string(event.LogicalEventID)); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("connector", event.Connector, true, 64); err != nil {
		return err
	}
	if err := validateUUIDv7("connector instance id", string(event.ConnectorInstanceID)); err != nil {
		return err
	}
	if !validRail(event.Rail) {
		return errors.New("audit: invalid correlation source rail")
	}
	if err := validateBoundedIdentifier("event name", event.EventName, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if event.ReceivedTime.IsZero() {
		return errors.New("audit: correlation received time is required")
	}
	if err := validateSHA256("source event digest", event.SourceEventDigest, false); err != nil {
		return err
	}
	if err := validateSHA256("event fingerprint", event.FingerprintSHA256, false); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"first request id": event.FirstRequestID, "first record id": event.FirstRecordID,
	} {
		if err := validateBoundedIdentifier(field, value, false, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	if err := validateBoundedIdentifier("profile version", event.ProfileVersion, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if !validCompleteness(event.Completeness) {
		return errors.New("audit: invalid correlation completeness")
	}
	return nil
}

func validateReceiptClaim(claim CorrelationReceiptClaim) error {
	if err := validateSHA256("receipt source key digest", claim.SourceKeyDigest, true); err != nil {
		return err
	}
	if err := validateSHA256("receipt fingerprint", claim.FingerprintSHA256, true); err != nil {
		return err
	}
	if claim.ReceivedAt.IsZero() || claim.ExpiresAt.IsZero() || claim.ExpiresAt.Before(claim.ReceivedAt) {
		return errors.New("audit: invalid correlation receipt lifetime")
	}
	return nil
}

func validateObservation(observation CorrelationObservation) error {
	if err := validateBoundedIdentifier("record id", observation.RecordID, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	if err := validateUUIDv7("semantic event id", string(observation.SemanticEventID)); err != nil {
		return err
	}
	if !validSignal(observation.Signal) {
		return errors.New("audit: invalid correlation observation signal")
	}
	if err := validateBoundedIdentifier("bucket", observation.Bucket, true, 64); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("event name", observation.EventName, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if observation.ObservedAt.IsZero() {
		return errors.New("audit: observation time is required")
	}
	if err := validateTraceID(observation.TraceID); err != nil {
		return err
	}
	if err := validateSpanID(observation.SpanID); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"session id": observation.SessionID, "turn id": observation.TurnID,
		"agent id": observation.AgentID, "lifecycle id": observation.LifecycleID,
		"execution id": observation.ExecutionID, "model request id": observation.ModelRequestID,
		"model response id": observation.ModelResponseID, "tool invocation id": observation.ToolInvocationID,
	} {
		if err := validateBoundedIdentifier(field, value, false, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	if err := validateProjectionHash(observation.ProjectionHash); err != nil {
		return err
	}
	if observation.Status != CorrelationObservationConstructed && observation.Status != CorrelationObservationExportEligible {
		return errors.New("audit: invalid correlation observation status")
	}
	return nil
}

func validateIdentifier(identifier CorrelationIdentifier) error {
	if err := validateUUIDv7("semantic event id", string(identifier.SemanticEventID)); err != nil {
		return err
	}
	if err := validateUUIDv7("connector instance id", string(identifier.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("identifier namespace", identifier.Namespace, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if !validIdentifierKind(identifier.Kind) {
		return errors.New("audit: invalid correlation identifier kind")
	}
	if err := validateSHA256("identifier value digest", identifier.ValueDigest, true); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("normalized identifier value", identifier.NormalizedValue, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("identifier source field", identifier.SourceField, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if !validIdentityOrigin(identifier.Origin) {
		return errors.New("audit: invalid correlation identifier origin")
	}
	return validateBoundedIdentifier("profile version", identifier.ProfileVersion, true, maxCorrelationTokenBytes)
}

func validateRelationshipInput(input CorrelationRelationshipInput) error {
	if !validNodeKind(input.FromKind) || !validNodeKind(input.ToKind) {
		return errors.New("audit: invalid correlation relationship node kind")
	}
	if err := validateBoundedIdentifier("relationship source id", input.FromID, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("relationship target id", input.ToID, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	for _, node := range []struct {
		kind CorrelationNodeKind
		id   string
	}{{input.FromKind, input.FromID}, {input.ToKind, input.ToID}} {
		if node.kind == CorrelationNodeSemanticEvent || node.kind == CorrelationNodeLogicalEvent {
			if err := validateUUIDv7("relationship "+string(node.kind)+" id", node.id); err != nil {
				return err
			}
		}
	}
	if !validRelationshipType(input.Type) || !validRelationshipMethod(input.Method) ||
		!validRelationshipStatus(input.Status) {
		return errors.New("audit: invalid correlation relationship vocabulary")
	}
	if input.Method == CorrelationMethodInferred && input.Type != CorrelationCorrelatesWith {
		return errors.New("audit: inferred relationships may only be correlates_with candidates")
	}
	if input.Method == CorrelationMethodInferred && input.Status != CorrelationRelationshipCandidate {
		return errors.New("audit: inferred relationships must remain candidates")
	}
	if err := validateBoundedIdentifier("relationship rule id", input.RuleID, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	return validateBoundedIdentifier("relationship rule version", input.RuleVersion, true, maxCorrelationTokenBytes)
}

func validateEvidence(evidence CorrelationRelationshipEvidence) error {
	if len(evidence.RelationshipID) != 68 || !strings.HasPrefix(evidence.RelationshipID, "rel_") {
		return errors.New("audit: invalid correlation relationship id")
	}
	if (evidence.RecordID == "") == (evidence.SemanticEventID == "") {
		return errors.New("audit: relationship evidence requires exactly one record or semantic event")
	}
	if evidence.RecordID != "" {
		if err := validateBoundedIdentifier("evidence record id", evidence.RecordID, true, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	} else if err := validateUUIDv7("evidence semantic event id", string(evidence.SemanticEventID)); err != nil {
		return err
	}
	if !validEvidenceRole(evidence.Role) || !validIntegrityState(evidence.Integrity) {
		return errors.New("audit: invalid correlation relationship evidence")
	}
	return nil
}

func validateCursor(cursor CorrelationCursor) error {
	if err := validateUUIDv7("connector instance id", string(cursor.ConnectorInstanceID)); err != nil {
		return err
	}
	for field, value := range map[string]string{"session id": cursor.SessionID, "agent id": cursor.AgentID} {
		if err := validateBoundedIdentifier(field, value, true, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"lifecycle id": cursor.LifecycleID, "execution id": cursor.ExecutionID,
		"active turn id": cursor.ActiveTurnID, "active prompt id": cursor.ActivePromptID,
		"root agent id": cursor.RootAgentID, "parent agent id": cursor.ParentAgentID,
		"root session id": cursor.RootSessionID, "parent session id": cursor.ParentSessionID,
		"last record id": cursor.LastRecordID,
	} {
		if err := validateBoundedIdentifier(field, value, false, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	if cursor.LastSemanticEventID != "" {
		if err := validateUUIDv7("last semantic event id", string(cursor.LastSemanticEventID)); err != nil {
			return err
		}
	}
	if err := validateBoundedIdentifier("cursor phase", cursor.Phase, true, 64); err != nil {
		return err
	}
	return validateBoundedIdentifier("profile version", cursor.ProfileVersion, true, maxCorrelationTokenBytes)
}

func validatePendingOperation(operation CorrelationPendingOperation) error {
	if err := validatePendingLocator(CorrelationPendingLocator{
		ConnectorInstanceID: operation.ConnectorInstanceID, Namespace: operation.Namespace,
		Kind: operation.Kind, OperationID: operation.OperationID, Type: operation.Type,
		ScopeKind: operation.ScopeKind, ScopeID: operation.ScopeID,
	}); err != nil {
		return err
	}
	if !validOperationStatus(operation.Status) {
		return errors.New("audit: invalid correlation pending operation state")
	}
	if err := validateBoundedIdentifier("operation name", operation.Name, false, maxCorrelationNameBytes); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"session id": operation.SessionID, "turn id": operation.TurnID,
		"agent id": operation.AgentID, "execution id": operation.ExecutionID,
	} {
		if err := validateBoundedIdentifier(field, value, false, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	if err := validateUUIDv7("start semantic event id", string(operation.StartSemanticEventID)); err != nil {
		return err
	}
	if operation.StartedAt.IsZero() || operation.UpdatedAt.IsZero() {
		return errors.New("audit: operation timestamps are required")
	}
	if err := validateSHA256("operation input digest", operation.InputDigest, false); err != nil {
		return err
	}
	if operation.Status == CorrelationOperationActive {
		if operation.TerminalSemanticEventID != "" || !operation.TerminalAt.IsZero() {
			return errors.New("audit: active operation cannot have terminal state")
		}
		return nil
	}
	if err := validateUUIDv7("terminal semantic event id", string(operation.TerminalSemanticEventID)); err != nil {
		return err
	}
	if operation.TerminalAt.IsZero() {
		return errors.New("audit: terminal operation time is required")
	}
	return nil
}

func validatePendingLocator(locator CorrelationPendingLocator) error {
	if err := validateUUIDv7("connector instance id", string(locator.ConnectorInstanceID)); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("operation namespace", locator.Namespace, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("operation id", locator.OperationID, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	if !validOperationType(locator.Type) || !validPendingOperationKind(locator.Type, locator.Kind) {
		return errors.New("audit: invalid typed pending operation identity")
	}
	if !validOperationScopeKind(locator.ScopeKind) {
		return errors.New("audit: invalid pending operation scope kind")
	}
	if err := validateBoundedIdentifier("operation scope id", locator.ScopeID, true, maxCorrelationIdentifierBytes); err != nil {
		return err
	}
	if locator.ScopeKind == CorrelationOperationScopeConnectorInstance &&
		locator.ScopeID != string(locator.ConnectorInstanceID) {
		return errors.New("audit: connector-instance operation scope must use the connector instance id")
	}
	return nil
}

func validPendingOperationKind(operationType CorrelationOperationType, kind CorrelationIdentifierKind) bool {
	switch operationType {
	case CorrelationOperationModel:
		return kind == CorrelationIdentifierPrompt || kind == CorrelationIdentifierModelRequest
	case CorrelationOperationTool:
		return kind == CorrelationIdentifierTool || kind == CorrelationIdentifierAction
	default:
		return false
	}
}

func validPendingIdentityKind(kind CorrelationIdentifierKind) bool {
	return validPendingOperationKind(CorrelationOperationModel, kind) ||
		validPendingOperationKind(CorrelationOperationTool, kind)
}

func validOperationScopeKind(kind CorrelationOperationScopeKind) bool {
	switch kind {
	case CorrelationOperationScopeConnectorInstance, CorrelationOperationScopeSession,
		CorrelationOperationScopeThread, CorrelationOperationScopeTurn,
		CorrelationOperationScopeExecution:
		return true
	default:
		return false
	}
}

func samePendingOperation(first, second CorrelationPendingOperation) bool {
	return first.ConnectorInstanceID == second.ConnectorInstanceID &&
		first.Namespace == second.Namespace && first.Kind == second.Kind &&
		first.OperationID == second.OperationID && first.Type == second.Type &&
		first.ScopeKind == second.ScopeKind && first.ScopeID == second.ScopeID &&
		first.Name == second.Name && first.SessionID == second.SessionID &&
		first.TurnID == second.TurnID && first.AgentID == second.AgentID &&
		first.ExecutionID == second.ExecutionID &&
		first.StartSemanticEventID == second.StartSemanticEventID &&
		first.StartedAt.Equal(second.StartedAt) && first.InputDigest == second.InputDigest &&
		first.TerminalSemanticEventID == second.TerminalSemanticEventID &&
		first.TerminalAt.Equal(second.TerminalAt) && first.Status == second.Status
}

func samePendingOperationIdentityContext(first, second CorrelationPendingOperation) bool {
	return first.ConnectorInstanceID == second.ConnectorInstanceID &&
		first.Namespace == second.Namespace && first.Kind == second.Kind &&
		first.OperationID == second.OperationID && first.Type == second.Type &&
		first.ScopeKind == second.ScopeKind && first.ScopeID == second.ScopeID &&
		first.Name == second.Name && first.SessionID == second.SessionID &&
		first.TurnID == second.TurnID && first.AgentID == second.AgentID &&
		first.ExecutionID == second.ExecutionID
}

func validateExactIdentityClaim(event CorrelationEvent, claim CorrelationExactIdentityClaim) error {
	if err := validateBoundedIdentifier("exact identity namespace", claim.Namespace, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if !validExactIdentityClaimKind(claim.Kind) {
		return errors.New("audit: exact identity claim kind is not occurrence identity")
	}
	if err := validateSHA256("exact identity value digest", claim.ValueDigest, true); err != nil {
		return err
	}
	if err := validateBoundedIdentifier("exact identity event name", claim.EventName, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if claim.EventName != event.EventName {
		return errors.New("audit: exact identity claim event name does not match occurrence")
	}
	if claim.Rail != event.Rail {
		return errors.New("audit: exact identity claim rail does not match occurrence")
	}
	if !validExactIdentityRail(claim.Rail) || !validExactIdentityRail(claim.CompatibleRail) ||
		claim.Rail == claim.CompatibleRail {
		return errors.New("audit: exact identity claim requires two different external rails")
	}
	if err := validateBoundedIdentifier("exact identity rule id", claim.RuleID, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	return validateBoundedIdentifier("exact identity rule version", claim.RuleVersion, true, maxCorrelationTokenBytes)
}

func validExactIdentityClaimKind(kind CorrelationIdentifierKind) bool {
	switch kind {
	case CorrelationIdentifierSourceEvent, CorrelationIdentifierModelRequest,
		CorrelationIdentifierModelResponse, CorrelationIdentifierTool:
		return true
	default:
		return false
	}
}

func validExactIdentityRail(rail CorrelationRail) bool {
	return validRail(rail) && rail != CorrelationRailInternal
}

func canonicalRailPair(first, second CorrelationRail) (CorrelationRail, CorrelationRail) {
	if string(first) < string(second) {
		return first, second
	}
	return second, first
}

func exactIdentityClaimKey(claim CorrelationExactIdentityClaim) string {
	railA, railB := canonicalRailPair(claim.Rail, claim.CompatibleRail)
	return strings.Join([]string{claim.Namespace, string(claim.Kind), claim.ValueDigest,
		claim.EventName, string(railA), string(railB), claim.RuleID, claim.RuleVersion,
		string(claim.Rail)}, "\x00")
}

func validRail(value CorrelationRail) bool {
	switch value {
	case CorrelationRailHook, CorrelationRailNativeOTLP, CorrelationRailProxy,
		CorrelationRailStream, CorrelationRailInternal:
		return true
	default:
		return false
	}
}

func validCompleteness(value CorrelationCompleteness) bool {
	return value == CorrelationComplete || value == CorrelationPartial || value == CorrelationUnknown
}

func validSignal(value CorrelationSignal) bool {
	return value == CorrelationSignalLogs || value == CorrelationSignalTraces || value == CorrelationSignalMetrics
}

func validCustody(value ConnectorExportCustody) bool {
	return value == ConnectorCustodyDefenseClaw || value == ConnectorCustodyExternal ||
		value == ConnectorCustodyHookOnly
}

func validNodeKind(value CorrelationNodeKind) bool {
	switch value {
	case CorrelationNodeSemanticEvent, CorrelationNodeLogicalEvent, CorrelationNodeRecord,
		CorrelationNodeSession, CorrelationNodeTurn, CorrelationNodeAgent, CorrelationNodeLifecycle,
		CorrelationNodeExecution, CorrelationNodeModelRequest, CorrelationNodeModelResponse,
		CorrelationNodeTool, CorrelationNodeTrace, CorrelationNodeSpan:
		return true
	default:
		return false
	}
}

func validIdentifierKind(value CorrelationIdentifierKind) bool {
	switch value {
	case CorrelationIdentifierSourceEvent, CorrelationIdentifierSourceSequence,
		CorrelationIdentifierSourceTimestamp, CorrelationIdentifierMessage, CorrelationIdentifierThread,
		CorrelationIdentifierPrompt,
		CorrelationIdentifierStep, CorrelationIdentifierSession, CorrelationIdentifierRootSession,
		CorrelationIdentifierParentSession, CorrelationIdentifierChildSession, CorrelationIdentifierTurn,
		CorrelationIdentifierAgent, CorrelationIdentifierRootAgent, CorrelationIdentifierParentAgent,
		CorrelationIdentifierChildAgent,
		CorrelationIdentifierLifecycle, CorrelationIdentifierExecution, CorrelationIdentifierModelRequest,
		CorrelationIdentifierModelResponse, CorrelationIdentifierAction, CorrelationIdentifierTool, CorrelationIdentifierTrace,
		CorrelationIdentifierSpan:
		return true
	default:
		return false
	}
}

func validIdentityOrigin(value CorrelationIdentityOrigin) bool {
	return value == CorrelationOriginReported || value == CorrelationOriginDefenseClawMinted ||
		value == CorrelationOriginDerived || value == CorrelationOriginTraceExact
}

func validRelationshipType(value CorrelationRelationshipType) bool {
	switch value {
	case CorrelationSameAs, CorrelationDuplicateOf, CorrelationBelongsTo, CorrelationParentOf,
		CorrelationDelegatedBy, CorrelationCausedBy, CorrelationInvokes, CorrelationRespondsTo,
		CorrelationResumes, CorrelationCorrelatesWith:
		return true
	default:
		return false
	}
}

func validRelationshipMethod(value CorrelationRelationshipMethod) bool {
	return value == CorrelationMethodReported || value == CorrelationMethodTraceExact ||
		value == CorrelationMethodDerived || value == CorrelationMethodInferred
}

func validRelationshipStatus(value CorrelationRelationshipStatus) bool {
	return value == CorrelationRelationshipActive || value == CorrelationRelationshipCandidate ||
		value == CorrelationRelationshipSuperseded || value == CorrelationRelationshipRejected ||
		value == CorrelationRelationshipConflicted
}

func validEvidenceRole(value CorrelationEvidenceRole) bool {
	return value == CorrelationEvidenceSource || value == CorrelationEvidenceTarget ||
		value == CorrelationEvidenceCorroborating || value == CorrelationEvidenceConflicting
}

func validIntegrityState(value CorrelationIntegrityState) bool {
	return value == CorrelationIntegrityVerified || value == CorrelationIntegrityUnverified ||
		value == CorrelationIntegrityFailed
}

func validOperationType(value CorrelationOperationType) bool {
	return value == CorrelationOperationModel || value == CorrelationOperationTool
}

func validOperationStatus(value CorrelationOperationStatus) bool {
	return value == CorrelationOperationActive || validTerminalOperationStatus(value)
}

func validTerminalOperationStatus(value CorrelationOperationStatus) bool {
	return value == CorrelationOperationCompleted || value == CorrelationOperationFailed ||
		value == CorrelationOperationCancelled || value == CorrelationOperationUnresolved
}
