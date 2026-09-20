// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CorrelationMatchRank is the normative exact-first resolver order. Smaller
// non-zero values are stronger. Similarity is deliberately candidate-only.
type CorrelationMatchRank uint8

const (
	CorrelationMatchNone CorrelationMatchRank = iota
	CorrelationMatchSemanticEvent
	CorrelationMatchReceipt
	CorrelationMatchNativeIdentifier
	CorrelationMatchTraceSpan
	CorrelationMatchProfileComposite
	CorrelationMatchUniquePending
	CorrelationMatchSimilarityCandidate
)

const (
	maxCorrelationMatchIdentifiers = 64
	maxCorrelationSimilarityWindow = 5 * time.Minute
)

// CorrelationMatchIdentifier is an already normalized, installation-keyed
// native identifier. Namespace and kind are both part of identity: values in
// different namespaces or of different kinds can never match.
type CorrelationMatchIdentifier struct {
	Namespace   string
	Kind        CorrelationIdentifierKind
	ValueDigest string
}

// CorrelationCompositeMatch identifies one deterministic, versioned profile
// composite persisted through correlation_identifiers. It is ranked below
// trace+span because it is derived rather than provider-reported evidence.
type CorrelationCompositeMatch struct {
	Namespace   string
	Kind        CorrelationIdentifierKind
	ValueDigest string
	RuleID      string
	RuleVersion string
}

// CorrelationPendingMatch describes a terminal observation that can join an
// active operation only when the compatible pending row is unique.
type CorrelationPendingMatch struct {
	Namespace   string
	Kind        CorrelationIdentifierKind
	OperationID string
	Type        CorrelationOperationType
	ScopeKind   CorrelationOperationScopeKind
	ScopeID     string
	Name        string
	SessionID   string
	TurnID      string
	AgentID     string
	ExecutionID string
}

// CorrelationSimilarityHint is the final, weak resolver input. A unique result
// is returned as CandidateOnly and never supplies a LogicalEventID for merging.
type CorrelationSimilarityHint struct {
	SessionID string
	AgentID   string
	EventName string
	Around    time.Time
	Window    time.Duration
}

type CorrelationReceiptLookup struct {
	SourceKeyDigest   string
	FingerprintSHA256 string
}

// CorrelationMirrorCompatibility is explicit connector-profile evidence that
// the current occurrence has the same semantic phase as a cross-rail record.
// The resolver still enforces equal event names and different source rails.
type CorrelationMirrorCompatibility struct {
	Rail                      CorrelationRail
	EventName                 string
	RuleID                    string
	RuleVersion               string
	EquivalentIdentifierKinds []CorrelationIdentifierKind
}

type CorrelationMatchInput struct {
	ConnectorInstanceID ConnectorInstanceID
	SemanticEventID     SemanticEventID
	Receipt             *CorrelationReceiptLookup
	Identifiers         []CorrelationMatchIdentifier
	TraceID             string
	SpanID              string
	Composite           *CorrelationCompositeMatch
	Pending             *CorrelationPendingMatch
	Similarity          *CorrelationSimilarityHint
	MirrorCompatibility *CorrelationMirrorCompatibility
}

type CorrelationMatchResult struct {
	Rank                   CorrelationMatchRank
	MatchedSemanticEventID SemanticEventID
	LogicalEventID         LogicalEventID
	Method                 CorrelationRelationshipMethod
	RuleID                 string
	RuleVersion            string
	Conflict               bool
	ConflictsWith          SemanticEventID
	Ambiguous              bool
	CandidateOnly          bool
	MergeAllowed           bool
	RelationshipType       CorrelationRelationshipType
	CandidateCount         int
}

type correlationMatchRow struct {
	semantic SemanticEventID
	logical  LogicalEventID
	received time.Time
}

// MatchOccurrence resolves correlation before BeginOccurrence. It never
// mutates state and never collapses ambiguous evidence. Exact receipt conflicts
// stop resolution so weaker evidence cannot hide an integrity disagreement.
func (repo *CorrelationRepository) MatchOccurrence(
	ctx context.Context,
	input CorrelationMatchInput,
) (CorrelationMatchResult, error) {
	if repo == nil || repo.store == nil {
		return CorrelationMatchResult{}, errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return CorrelationMatchResult{}, errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return CorrelationMatchResult{}, err
	}
	if err := validateCorrelationMatchInput(input); err != nil {
		return CorrelationMatchResult{}, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return CorrelationMatchResult{}, err
	}
	defer release()
	var groupingResult *CorrelationMatchResult

	if input.SemanticEventID != "" {
		rows, err := repo.matchEventBySemanticID(ctx, input.ConnectorInstanceID, input.SemanticEventID)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			return classifyCorrelationMatches(rows, CorrelationMatchSemanticEvent,
				CorrelationMethodReported, "semantic-event-id", "v1", CorrelationSameAs, true), nil
		}
	}
	if input.Receipt != nil {
		result, found, err := repo.matchReceipt(ctx, input.ConnectorInstanceID, *input.Receipt)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if found {
			return result, nil
		}
	}
	if len(input.Identifiers) != 0 {
		sourceIdentifiers, groupingIdentifiers := splitCorrelationMatchIdentifiers(input.Identifiers)
		rows, err := repo.matchIdentifiers(ctx, input.ConnectorInstanceID, sourceIdentifiers, nil)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			return classifyCorrelationMatches(rows, CorrelationMatchNativeIdentifier,
				CorrelationMethodReported, "scoped-source-occurrence", "v1", CorrelationSameAs, true), nil
		}
		if len(groupingIdentifiers) != 0 && input.MirrorCompatibility != nil {
			mirrorIdentifiers := mirrorEligibleIdentifiers(groupingIdentifiers,
				input.MirrorCompatibility.EquivalentIdentifierKinds)
			rows, err = repo.matchIdentifiers(ctx, input.ConnectorInstanceID, mirrorIdentifiers, input.MirrorCompatibility)
			if err != nil {
				return CorrelationMatchResult{}, err
			}
			if len(rows) != 0 {
				return classifyCorrelationMatches(rows, CorrelationMatchNativeIdentifier,
					CorrelationMethodReported, input.MirrorCompatibility.RuleID,
					input.MirrorCompatibility.RuleVersion, CorrelationSameAs, true), nil
			}
		}
		if len(groupingIdentifiers) != 0 {
			rows, err = repo.matchIdentifiers(ctx, input.ConnectorInstanceID, groupingIdentifiers, nil)
			if err != nil {
				return CorrelationMatchResult{}, err
			}
			if len(rows) != 0 {
				candidate := classifyCorrelationMatches(rows, CorrelationMatchNativeIdentifier,
					CorrelationMethodReported, "scoped-native-membership", "v1", CorrelationBelongsTo, false)
				groupingResult = &candidate
			}
		}
	}
	if input.TraceID != "" {
		rows, err := repo.matchTraceSpan(ctx, input.ConnectorInstanceID, input.TraceID, input.SpanID)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			return classifyCorrelationMatches(rows, CorrelationMatchTraceSpan,
				CorrelationMethodTraceExact, "exact-trace-span", "v1", CorrelationSameAs, true), nil
		}
	}
	if groupingResult != nil {
		return *groupingResult, nil
	}
	if input.Composite != nil {
		rows, err := repo.matchIdentifiers(ctx, input.ConnectorInstanceID, []CorrelationMatchIdentifier{{
			Namespace: input.Composite.Namespace, Kind: input.Composite.Kind,
			ValueDigest: input.Composite.ValueDigest,
		}}, nil)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			return classifyCorrelationMatches(rows, CorrelationMatchProfileComposite,
				CorrelationMethodDerived, input.Composite.RuleID, input.Composite.RuleVersion,
				CorrelationCorrelatesWith, false), nil
		}
	}
	if input.Pending != nil {
		rows, err := repo.matchUniquePending(ctx, input.ConnectorInstanceID, *input.Pending)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			if len(rows) != 1 {
				return CorrelationMatchResult{
					Rank: CorrelationMatchUniquePending, Method: CorrelationMethodDerived,
					RuleID: "unique-compatible-pending", RuleVersion: "v1",
					Ambiguous: true, CandidateCount: len(rows),
				}, nil
			}
			return classifyCorrelationMatches(rows, CorrelationMatchUniquePending,
				CorrelationMethodDerived, "unique-compatible-pending", "v1", CorrelationBelongsTo, false), nil
		}
	}
	if input.Similarity != nil {
		rows, err := repo.matchSimilarity(ctx, input.ConnectorInstanceID, *input.Similarity)
		if err != nil {
			return CorrelationMatchResult{}, err
		}
		if len(rows) != 0 {
			return classifyCorrelationMatches(rows, CorrelationMatchSimilarityCandidate,
				CorrelationMethodInferred, "bounded-context-time-candidate", "v1",
				CorrelationCorrelatesWith, false), nil
		}
	}
	return CorrelationMatchResult{}, nil
}

func validateCorrelationMatchInput(input CorrelationMatchInput) error {
	if err := validateUUIDv7("connector instance id", string(input.ConnectorInstanceID)); err != nil {
		return err
	}
	if input.SemanticEventID != "" {
		if err := validateUUIDv7("semantic event id", string(input.SemanticEventID)); err != nil {
			return err
		}
	}
	if input.Receipt != nil {
		if err := validateSHA256("receipt source key digest", input.Receipt.SourceKeyDigest, true); err != nil {
			return err
		}
		if err := validateSHA256("receipt fingerprint", input.Receipt.FingerprintSHA256, true); err != nil {
			return err
		}
	}
	if len(input.Identifiers) > maxCorrelationMatchIdentifiers {
		return fmt.Errorf("audit: at most %d correlation identifiers may be matched", maxCorrelationMatchIdentifiers)
	}
	for _, identifier := range input.Identifiers {
		if err := validateMatchIdentifier(identifier); err != nil {
			return err
		}
	}
	if (input.TraceID == "") != (input.SpanID == "") {
		return errors.New("audit: exact trace matching requires both trace and span id")
	}
	if input.TraceID != "" {
		if err := validateLowerHex("trace id", input.TraceID, 32); err != nil {
			return err
		}
		if err := validateLowerHex("span id", input.SpanID, 16); err != nil {
			return err
		}
	}
	if input.Composite != nil {
		if err := validateMatchIdentifier(CorrelationMatchIdentifier{
			Namespace: input.Composite.Namespace, Kind: input.Composite.Kind,
			ValueDigest: input.Composite.ValueDigest,
		}); err != nil {
			return err
		}
		if err := validateBoundedIdentifier("composite rule id", input.Composite.RuleID, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
		if err := validateBoundedIdentifier("composite rule version", input.Composite.RuleVersion, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
	}
	if input.Pending != nil {
		if input.Pending.Namespace == "" || input.Pending.Kind == "" || input.Pending.Type == "" ||
			input.Pending.ScopeKind == "" || input.Pending.ScopeID == "" {
			return errors.New("audit: pending match requires typed identity and scope")
		}
		if !validPendingOperationKind(input.Pending.Type, input.Pending.Kind) ||
			!validOperationScopeKind(input.Pending.ScopeKind) {
			return errors.New("audit: pending match typed identity or scope is invalid")
		}
		if input.Pending.ScopeKind == CorrelationOperationScopeConnectorInstance &&
			input.Pending.ScopeID != string(input.ConnectorInstanceID) {
			return errors.New("audit: pending match connector-instance scope mismatch")
		}
		for field, value := range map[string]string{
			"pending operation namespace": input.Pending.Namespace,
			"pending operation id":        input.Pending.OperationID,
			"pending operation scope id":  input.Pending.ScopeID,
			"pending operation name":      input.Pending.Name, "pending session id": input.Pending.SessionID,
			"pending turn id": input.Pending.TurnID, "pending agent id": input.Pending.AgentID,
			"pending execution id": input.Pending.ExecutionID,
		} {
			limit := maxCorrelationIdentifierBytes
			if field == "pending operation name" {
				limit = maxCorrelationNameBytes
			} else if field == "pending operation namespace" {
				limit = maxCorrelationTokenBytes
			}
			if err := validateBoundedIdentifier(field, value, false, limit); err != nil {
				return err
			}
		}
	}
	if input.Similarity != nil {
		if input.Similarity.SessionID == "" && input.Similarity.AgentID == "" {
			return errors.New("audit: similarity hint requires session or agent id")
		}
		if err := validateBoundedIdentifier("similarity event name", input.Similarity.EventName, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
		if input.Similarity.Around.IsZero() || input.Similarity.Window <= 0 ||
			input.Similarity.Window > maxCorrelationSimilarityWindow {
			return errors.New("audit: similarity hint requires a bounded non-zero time window")
		}
	}
	if input.MirrorCompatibility != nil {
		if !validRail(input.MirrorCompatibility.Rail) {
			return errors.New("audit: mirror compatibility rail is invalid")
		}
		if err := validateBoundedIdentifier("mirror event name", input.MirrorCompatibility.EventName, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
		if err := validateBoundedIdentifier("mirror rule id", input.MirrorCompatibility.RuleID, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
		if err := validateBoundedIdentifier("mirror rule version", input.MirrorCompatibility.RuleVersion, true, maxCorrelationTokenBytes); err != nil {
			return err
		}
		if len(input.MirrorCompatibility.EquivalentIdentifierKinds) == 0 ||
			len(input.MirrorCompatibility.EquivalentIdentifierKinds) > maxCorrelationMatchIdentifiers {
			return errors.New("audit: mirror compatibility requires bounded occurrence-level identifier kinds")
		}
		for _, kind := range input.MirrorCompatibility.EquivalentIdentifierKinds {
			switch kind {
			case CorrelationIdentifierSourceEvent, CorrelationIdentifierMessage,
				CorrelationIdentifierModelRequest, CorrelationIdentifierModelResponse,
				CorrelationIdentifierTool:
			default:
				return errors.New("audit: mirror compatibility kind is not occurrence-level")
			}
		}
	}
	return nil
}

func mirrorEligibleIdentifiers(input []CorrelationMatchIdentifier, allowed []CorrelationIdentifierKind) []CorrelationMatchIdentifier {
	allowedSet := make(map[CorrelationIdentifierKind]bool, len(allowed))
	for _, kind := range allowed {
		allowedSet[kind] = true
	}
	result := make([]CorrelationMatchIdentifier, 0, len(input))
	for _, identifier := range input {
		if allowedSet[identifier.Kind] {
			result = append(result, identifier)
		}
	}
	return result
}

func splitCorrelationMatchIdentifiers(input []CorrelationMatchIdentifier) (source, grouping []CorrelationMatchIdentifier) {
	for _, identifier := range input {
		if identifier.Kind == CorrelationIdentifierSourceEvent {
			source = append(source, identifier)
		} else {
			grouping = append(grouping, identifier)
		}
	}
	return source, grouping
}

func validateMatchIdentifier(identifier CorrelationMatchIdentifier) error {
	if err := validateBoundedIdentifier("identifier namespace", identifier.Namespace, true, maxCorrelationTokenBytes); err != nil {
		return err
	}
	if !validIdentifierKind(identifier.Kind) {
		return errors.New("audit: correlation identifier kind is invalid")
	}
	return validateSHA256("identifier value digest", identifier.ValueDigest, true)
}

func validateLowerHex(field, value string, bytes int) error {
	if len(value) != bytes || strings.ToLower(value) != value {
		return fmt.Errorf("audit: %s must be %d lowercase hexadecimal characters", field, bytes)
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return fmt.Errorf("audit: %s must be %d lowercase hexadecimal characters", field, bytes)
		}
	}
	return nil
}

func (repo *CorrelationRepository) matchEventBySemanticID(ctx context.Context, connector ConnectorInstanceID, semantic SemanticEventID) ([]correlationMatchRow, error) {
	return repo.queryCorrelationMatchRows(ctx, `SELECT semantic_event_id, logical_group_id, received_time_unix_nano
		FROM correlation_events WHERE connector_instance_id=? AND semantic_event_id=?`, string(connector), string(semantic))
}

func (repo *CorrelationRepository) matchReceipt(ctx context.Context, connector ConnectorInstanceID, receipt CorrelationReceiptLookup) (CorrelationMatchResult, bool, error) {
	rows, err := repo.queryCorrelationMatchRows(ctx, `SELECT event.semantic_event_id, event.logical_group_id,
		event.received_time_unix_nano FROM correlation_receipts AS receipt
		JOIN correlation_events AS event ON event.semantic_event_id=receipt.semantic_event_id
		WHERE receipt.connector_instance_id=? AND receipt.source_key_digest=? AND receipt.fingerprint_sha256=?`,
		string(connector), receipt.SourceKeyDigest, receipt.FingerprintSHA256)
	if err != nil {
		return CorrelationMatchResult{}, false, err
	}
	if len(rows) != 0 {
		return classifyCorrelationMatches(rows, CorrelationMatchReceipt, CorrelationMethodReported,
			"exact-source-receipt", "v1", CorrelationSameAs, true), true, nil
	}
	var conflict string
	err = repo.store.db.QueryRowContext(ctx, `SELECT semantic_event_id FROM correlation_receipts
		WHERE connector_instance_id=? AND source_key_digest=? AND fingerprint_sha256<>?
		ORDER BY first_received_time_unix_nano, semantic_event_id LIMIT 1`, string(connector),
		receipt.SourceKeyDigest, receipt.FingerprintSHA256).Scan(&conflict)
	if errors.Is(err, sql.ErrNoRows) {
		return CorrelationMatchResult{}, false, nil
	}
	if err != nil {
		return CorrelationMatchResult{}, false, fmt.Errorf("audit: query correlation receipt conflict: %w", err)
	}
	return CorrelationMatchResult{
		Rank: CorrelationMatchReceipt, Method: CorrelationMethodReported,
		RuleID: "exact-source-receipt", RuleVersion: "v1", Conflict: true,
		ConflictsWith: SemanticEventID(conflict), CandidateCount: 1,
	}, true, nil
}

func (repo *CorrelationRepository) matchIdentifiers(ctx context.Context, connector ConnectorInstanceID, identifiers []CorrelationMatchIdentifier, mirror *CorrelationMirrorCompatibility) ([]correlationMatchRow, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}
	clauses := make([]string, 0, len(identifiers))
	args := []any{string(connector)}
	for _, identifier := range identifiers {
		clauses = append(clauses, "(identifier.namespace=? AND identifier.identifier_kind=? AND identifier.value_digest=?)")
		args = append(args, identifier.Namespace, string(identifier.Kind), identifier.ValueDigest)
	}
	filters := ""
	if mirror != nil {
		filters = " AND event.source_rail<>? AND event.event_name=?"
		args = append(args, string(mirror.Rail), mirror.EventName)
	}
	return repo.queryCorrelationMatchRows(ctx, `SELECT DISTINCT event.semantic_event_id,
		event.logical_group_id, event.received_time_unix_nano
		FROM correlation_identifiers AS identifier
		JOIN correlation_events AS event ON event.semantic_event_id=identifier.semantic_event_id
		WHERE identifier.connector_instance_id=? AND (`+strings.Join(clauses, " OR ")+`)`+filters+`
		ORDER BY event.received_time_unix_nano, event.semantic_event_id`, args...)
}

func (repo *CorrelationRepository) matchTraceSpan(ctx context.Context, connector ConnectorInstanceID, traceID, spanID string) ([]correlationMatchRow, error) {
	return repo.queryCorrelationMatchRows(ctx, `SELECT DISTINCT event.semantic_event_id,
		event.logical_group_id, event.received_time_unix_nano
		FROM correlation_observations AS observation
		JOIN correlation_events AS event ON event.semantic_event_id=observation.semantic_event_id
		WHERE event.connector_instance_id=?
			AND event.source_rail='native_otlp'
			AND observation.signal='traces'
			AND observation.trace_id=? AND observation.span_id=?
		ORDER BY event.received_time_unix_nano, event.semantic_event_id`, string(connector), traceID, spanID)
}

func (repo *CorrelationRepository) matchUniquePending(ctx context.Context, connector ConnectorInstanceID, pending CorrelationPendingMatch) ([]correlationMatchRow, error) {
	clauses := []string{"operation.connector_instance_id=?", "operation.operation_namespace=?",
		"operation.operation_kind=?", "operation.operation_type=?", "operation.scope_kind=?",
		"operation.scope_id=?", "operation.status='active'"}
	args := []any{string(connector), pending.Namespace, string(pending.Kind), string(pending.Type),
		string(pending.ScopeKind), pending.ScopeID}
	for _, filter := range []struct{ column, value string }{
		{"operation_id", pending.OperationID}, {"operation_name", pending.Name},
		{"session_id", pending.SessionID}, {"turn_id", pending.TurnID},
		{"agent_id", pending.AgentID}, {"execution_id", pending.ExecutionID},
	} {
		if filter.value != "" {
			clauses = append(clauses, "operation."+filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	return repo.queryCorrelationMatchRows(ctx, `SELECT event.semantic_event_id,
		event.logical_group_id, event.received_time_unix_nano
		FROM correlation_pending_operations AS operation
		JOIN correlation_events AS event ON event.semantic_event_id=operation.start_semantic_event_id
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY event.received_time_unix_nano, event.semantic_event_id LIMIT 2`, args...)
}

func (repo *CorrelationRepository) matchSimilarity(ctx context.Context, connector ConnectorInstanceID, hint CorrelationSimilarityHint) ([]correlationMatchRow, error) {
	clauses := []string{"event.connector_instance_id=?", "event.event_name=?", "event.received_time_unix_nano BETWEEN ? AND ?"}
	args := []any{string(connector), hint.EventName, unixNano(hint.Around.Add(-hint.Window)), unixNano(hint.Around.Add(hint.Window))}
	if hint.SessionID != "" {
		clauses = append(clauses, "observation.session_id=?")
		args = append(args, hint.SessionID)
	}
	if hint.AgentID != "" {
		clauses = append(clauses, "observation.agent_id=?")
		args = append(args, hint.AgentID)
	}
	return repo.queryCorrelationMatchRows(ctx, `SELECT DISTINCT event.semantic_event_id,
		event.logical_group_id, event.received_time_unix_nano
		FROM correlation_events AS event JOIN correlation_observations AS observation
		ON observation.semantic_event_id=event.semantic_event_id WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY event.received_time_unix_nano, event.semantic_event_id LIMIT 2`, args...)
}

func (repo *CorrelationRepository) queryCorrelationMatchRows(ctx context.Context, statement string, args ...any) ([]correlationMatchRow, error) {
	rows, err := repo.store.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query correlation match evidence: %w", err)
	}
	defer rows.Close()
	result := make([]correlationMatchRow, 0, 2)
	for rows.Next() {
		var row correlationMatchRow
		var received int64
		if err := rows.Scan(&row.semantic, &row.logical, &received); err != nil {
			return nil, fmt.Errorf("audit: scan correlation match evidence: %w", err)
		}
		row.received = time.Unix(0, received).UTC()
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate correlation match evidence: %w", err)
	}
	return result, nil
}

func classifyCorrelationMatches(rows []correlationMatchRow, rank CorrelationMatchRank, method CorrelationRelationshipMethod, ruleID, ruleVersion string, relationshipType CorrelationRelationshipType, mergeAllowed bool) CorrelationMatchResult {
	result := CorrelationMatchResult{
		Rank: rank, Method: method, RuleID: ruleID, RuleVersion: ruleVersion,
		CandidateOnly: !mergeAllowed, MergeAllowed: mergeAllowed,
		RelationshipType: relationshipType, CandidateCount: len(rows),
	}
	if len(rows) == 0 {
		return result
	}
	if rank == CorrelationMatchSimilarityCandidate && len(rows) != 1 {
		result.Ambiguous = true
		return result
	}
	result.MatchedSemanticEventID = rows[0].semantic
	logical := rows[0].logical
	for _, row := range rows[1:] {
		if row.logical != logical {
			result.Ambiguous = true
			result.MatchedSemanticEventID = ""
			return result
		}
	}
	if mergeAllowed {
		result.LogicalEventID = logical
	}
	return result
}
