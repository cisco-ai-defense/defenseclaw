// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type CorrelationAnchor struct {
	ConnectorInstanceID ConnectorInstanceID
	RecordID            string
	SemanticEventID     SemanticEventID
	LogicalEventID      LogicalEventID
	SessionID           string
	TurnID              string
	AgentID             string
	LifecycleID         string
	ExecutionID         string
	ModelRequestID      string
	ModelResponseID     string
	ToolInvocationID    string
	TraceID             string
	SpanID              string
}

type CorrelationPageRequest struct {
	Limit     int
	AfterTime time.Time
	AfterID   string
}

type CorrelationGraphQuery struct {
	Anchor CorrelationAnchor
	Page   CorrelationPageRequest
}

type CorrelationGraph struct {
	Events          []CorrelationEvent                `json:"events"`
	Observations    []CorrelationObservation          `json:"observations"`
	Relationships   []CorrelationRelationship         `json:"relationships"`
	Evidence        []CorrelationRelationshipEvidence `json:"evidence"`
	AsOf            time.Time                         `json:"as_of"`
	IngestWatermark time.Time                         `json:"ingest_watermark"`
	NextAfterTime   time.Time                         `json:"next_after_time"`
	NextAfterID     string                            `json:"next_after_id"`
	Truncated       bool                              `json:"truncated"`
}

type CorrelationExplanation struct {
	Graph               CorrelationGraph `json:"graph"`
	RawObservationCount int              `json:"raw_observation_count"`
	LogicalEventCount   int              `json:"logical_event_count"`
	ConflictCount       int              `json:"conflict_count"`
}

type CorrelationTimelineEntry struct {
	Event       CorrelationEvent        `json:"event"`
	Observation *CorrelationObservation `json:"observation"`
}

type CorrelationTimeline struct {
	Entries         []CorrelationTimelineEntry `json:"entries"`
	AsOf            time.Time                  `json:"as_of"`
	IngestWatermark time.Time                  `json:"ingest_watermark"`
	NextAfterTime   time.Time                  `json:"next_after_time"`
	NextAfterID     string                     `json:"next_after_id"`
	Truncated       bool                       `json:"truncated"`
}

type CorrelationReceiptConflict struct {
	ConnectorInstanceID ConnectorInstanceID `json:"connector_instance_id"`
	SourceKeyDigest     string              `json:"source_key_digest"`
	FingerprintSHA256   string              `json:"fingerprint_sha256"`
	SemanticEventID     SemanticEventID     `json:"semantic_event_id"`
	ConflictsWith       SemanticEventID     `json:"conflicts_with_semantic_event_id"`
	FirstReceivedAt     time.Time           `json:"first_received_at"`
	LastReceivedAt      time.Time           `json:"last_received_at"`
	DeliveryCount       uint64              `json:"delivery_count"`
}

type CorrelationConflictsQuery struct {
	Anchor CorrelationAnchor
	Page   CorrelationPageRequest
}

type CorrelationConflicts struct {
	Relationships   []CorrelationRelationship    `json:"relationships"`
	Receipts        []CorrelationReceiptConflict `json:"receipts"`
	AsOf            time.Time                    `json:"as_of"`
	IngestWatermark time.Time                    `json:"ingest_watermark"`
	Truncated       bool                         `json:"truncated"`
}

func (repo *CorrelationRepository) QueryGraph(
	ctx context.Context,
	query CorrelationGraphQuery,
) (CorrelationGraph, error) {
	var graph CorrelationGraph
	if err := repo.validateQuery(ctx, query.Anchor, query.Page); err != nil {
		return graph, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return graph, err
	}
	defer release()
	graph.AsOf = time.Now().UTC()
	limit := boundedCorrelationLimit(query.Page.Limit)
	eventIDs, truncated, err := repo.anchorEventIDs(ctx, query.Anchor, query.Page, limit)
	if err != nil {
		return graph, err
	}
	graph.Truncated = truncated
	if len(eventIDs) == 0 {
		graph.IngestWatermark, _ = repo.ingestWatermark(ctx)
		return graph, nil
	}
	graph.Events, err = repo.loadEvents(ctx, eventIDs)
	if err != nil {
		return graph, err
	}
	graph.Observations, err = repo.loadObservations(ctx, eventIDs)
	if err != nil {
		return graph, err
	}
	graph.Relationships, err = repo.loadRelationships(ctx, query.Anchor, eventIDs, graph.Observations)
	if err != nil {
		return graph, err
	}
	graph.Evidence, err = repo.loadEvidence(ctx, graph.Relationships)
	if err != nil {
		return graph, err
	}
	graph.IngestWatermark, err = repo.ingestWatermark(ctx)
	if err != nil {
		return graph, err
	}
	if graph.Truncated && len(graph.Events) > 0 {
		last := graph.Events[len(graph.Events)-1]
		graph.NextAfterTime = last.ReceivedTime
		graph.NextAfterID = string(last.SemanticEventID)
	}
	return graph, nil
}

func (repo *CorrelationRepository) Explain(
	ctx context.Context,
	query CorrelationGraphQuery,
) (CorrelationExplanation, error) {
	graph, err := repo.QueryGraph(ctx, query)
	if err != nil {
		return CorrelationExplanation{}, err
	}
	logical := make(map[LogicalEventID]struct{}, len(graph.Events))
	conflicts := 0
	for _, event := range graph.Events {
		logical[event.LogicalEventID] = struct{}{}
	}
	for _, relationship := range graph.Relationships {
		if relationship.Status == CorrelationRelationshipConflicted {
			conflicts++
		}
	}
	return CorrelationExplanation{
		Graph: graph, RawObservationCount: len(graph.Observations),
		LogicalEventCount: len(logical), ConflictCount: conflicts,
	}, nil
}

func (repo *CorrelationRepository) QueryTimeline(
	ctx context.Context,
	query CorrelationGraphQuery,
) (CorrelationTimeline, error) {
	var result CorrelationTimeline
	graph, err := repo.QueryGraph(ctx, query)
	if err != nil {
		return result, err
	}
	result.AsOf = graph.AsOf
	result.IngestWatermark = graph.IngestWatermark
	result.Truncated = graph.Truncated
	result.NextAfterTime = graph.NextAfterTime
	result.NextAfterID = graph.NextAfterID
	events := make(map[SemanticEventID]CorrelationEvent, len(graph.Events))
	observed := make(map[SemanticEventID]bool, len(graph.Events))
	for _, event := range graph.Events {
		events[event.SemanticEventID] = event
	}
	for index := range graph.Observations {
		observation := graph.Observations[index]
		event, ok := events[observation.SemanticEventID]
		if !ok {
			continue
		}
		copyObservation := observation
		result.Entries = append(result.Entries, CorrelationTimelineEntry{
			Event: event, Observation: &copyObservation,
		})
		observed[event.SemanticEventID] = true
	}
	for _, event := range graph.Events {
		if !observed[event.SemanticEventID] {
			result.Entries = append(result.Entries, CorrelationTimelineEntry{Event: event})
		}
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		iTime := result.Entries[i].Event.ReceivedTime
		jTime := result.Entries[j].Event.ReceivedTime
		if result.Entries[i].Observation != nil {
			iTime = result.Entries[i].Observation.ObservedAt
		}
		if result.Entries[j].Observation != nil {
			jTime = result.Entries[j].Observation.ObservedAt
		}
		if iTime.Equal(jTime) {
			return string(result.Entries[i].Event.SemanticEventID) < string(result.Entries[j].Event.SemanticEventID)
		}
		return iTime.Before(jTime)
	})
	return result, nil
}

func (repo *CorrelationRepository) QueryConflicts(
	ctx context.Context,
	query CorrelationConflictsQuery,
) (CorrelationConflicts, error) {
	var result CorrelationConflicts
	if err := repo.validateQuery(ctx, query.Anchor, query.Page); err != nil {
		return result, err
	}
	result.AsOf = time.Now().UTC()
	graph, err := repo.QueryGraph(ctx, CorrelationGraphQuery{Anchor: query.Anchor, Page: query.Page})
	if err != nil {
		return result, err
	}
	for _, relationship := range graph.Relationships {
		if relationship.Status == CorrelationRelationshipConflicted {
			result.Relationships = append(result.Relationships, relationship)
		}
	}
	if len(graph.Events) == 0 {
		result.IngestWatermark = graph.IngestWatermark
		result.Truncated = graph.Truncated
		return result, nil
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return result, err
	}
	defer release()
	clauses := make([]string, 0, len(graph.Events)*2)
	args := make([]any, 0, len(graph.Events)*2+1)
	for _, event := range graph.Events {
		clauses = append(clauses, "semantic_event_id=?", "conflicts_with_semantic_event_id=?")
		args = append(args, string(event.SemanticEventID), string(event.SemanticEventID))
	}
	limit := boundedCorrelationLimit(query.Page.Limit)
	args = append(args, limit+1)
	rows, err := repo.store.queryDB(ctx, "correlation_conflict_receipts", `SELECT
		connector_instance_id, source_key_digest, fingerprint_sha256, semantic_event_id,
		conflicts_with_semantic_event_id, first_received_time_unix_nano,
		last_received_time_unix_nano, delivery_count
		FROM correlation_receipts WHERE conflicts_with_semantic_event_id IS NOT NULL AND (`+
		strings.Join(clauses, " OR ")+`)
		ORDER BY first_received_time_unix_nano, semantic_event_id LIMIT ?`, args...)
	if err != nil {
		return result, fmt.Errorf("audit: query correlation receipt conflicts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var conflict CorrelationReceiptConflict
		var first, last int64
		if err := rows.Scan(&conflict.ConnectorInstanceID, &conflict.SourceKeyDigest,
			&conflict.FingerprintSHA256, &conflict.SemanticEventID, &conflict.ConflictsWith,
			&first, &last, &conflict.DeliveryCount); err != nil {
			return result, fmt.Errorf("audit: scan correlation receipt conflict: %w", err)
		}
		conflict.FirstReceivedAt = time.Unix(0, first).UTC()
		conflict.LastReceivedAt = time.Unix(0, last).UTC()
		result.Receipts = append(result.Receipts, conflict)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.Truncated = graph.Truncated || len(result.Receipts) > limit
	if len(result.Receipts) > limit {
		result.Receipts = result.Receipts[:limit]
	}
	result.IngestWatermark = graph.IngestWatermark
	return result, nil
}

func (repo *CorrelationRepository) validateQuery(
	ctx context.Context,
	anchor CorrelationAnchor,
	page CorrelationPageRequest,
) error {
	if repo == nil || repo.store == nil || !repo.store.Ready() {
		return errors.New("audit: correlation repository is not ready")
	}
	if ctx == nil {
		return errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCorrelationAnchor(anchor); err != nil {
		return err
	}
	if page.Limit < 0 || page.Limit > maxCorrelationQueryLimit {
		return fmt.Errorf("audit: correlation query limit must be between 0 and %d", maxCorrelationQueryLimit)
	}
	if page.AfterID != "" {
		if page.AfterTime.IsZero() {
			return errors.New("audit: correlation pagination requires both after time and id")
		}
		if err := validateBoundedIdentifier("pagination id", page.AfterID, true, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	} else if !page.AfterTime.IsZero() {
		return errors.New("audit: correlation pagination requires both after time and id")
	}
	return nil
}

func validateCorrelationAnchor(anchor CorrelationAnchor) error {
	if anchor.ConnectorInstanceID != "" {
		if err := validateUUIDv7("connector instance id", string(anchor.ConnectorInstanceID)); err != nil {
			return err
		}
	}
	anchors := []struct {
		name  string
		value string
	}{
		{"record id", anchor.RecordID}, {"semantic event id", string(anchor.SemanticEventID)},
		{"logical event id", string(anchor.LogicalEventID)}, {"session id", anchor.SessionID},
		{"turn id", anchor.TurnID}, {"agent id", anchor.AgentID}, {"lifecycle id", anchor.LifecycleID},
		{"execution id", anchor.ExecutionID}, {"model request id", anchor.ModelRequestID},
		{"model response id", anchor.ModelResponseID}, {"tool invocation id", anchor.ToolInvocationID},
		{"trace id", anchor.TraceID},
	}
	count := 0
	for _, candidate := range anchors {
		if candidate.value == "" {
			continue
		}
		count++
		if err := validateBoundedIdentifier(candidate.name, candidate.value, true, maxCorrelationIdentifierBytes); err != nil {
			return err
		}
	}
	if count != 1 {
		return errors.New("audit: correlation query requires exactly one anchor kind")
	}
	if anchor.TraceID != "" {
		if err := validateTraceID(anchor.TraceID); err != nil {
			return err
		}
		if err := validateSpanID(anchor.SpanID); err != nil {
			return err
		}
	} else if anchor.SpanID != "" {
		return errors.New("audit: span id requires a trace id anchor")
	}
	if anchor.SemanticEventID != "" {
		return validateUUIDv7("semantic event id", string(anchor.SemanticEventID))
	}
	if anchor.LogicalEventID != "" {
		return validateUUIDv7("logical event id", string(anchor.LogicalEventID))
	}
	return nil
}

func boundedCorrelationLimit(limit int) int {
	if limit == 0 {
		return defaultCorrelationQueryLimit
	}
	if limit > maxCorrelationQueryLimit {
		return maxCorrelationQueryLimit
	}
	return limit
}

func (repo *CorrelationRepository) anchorEventIDs(
	ctx context.Context,
	anchor CorrelationAnchor,
	page CorrelationPageRequest,
	limit int,
) ([]SemanticEventID, bool, error) {
	column := ""
	value := ""
	from := "correlation_events AS event"
	switch {
	case anchor.SemanticEventID != "":
		column, value = "event.semantic_event_id", string(anchor.SemanticEventID)
	case anchor.LogicalEventID != "":
		column, value = "event.logical_group_id", string(anchor.LogicalEventID)
	case anchor.RecordID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.record_id", anchor.RecordID
	case anchor.SessionID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.session_id", anchor.SessionID
	case anchor.TurnID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.turn_id", anchor.TurnID
	case anchor.AgentID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.agent_id", anchor.AgentID
	case anchor.LifecycleID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.lifecycle_id", anchor.LifecycleID
	case anchor.ExecutionID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.execution_id", anchor.ExecutionID
	case anchor.ModelRequestID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.model_request_id", anchor.ModelRequestID
	case anchor.ModelResponseID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.model_response_id", anchor.ModelResponseID
	case anchor.ToolInvocationID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.tool_invocation_id", anchor.ToolInvocationID
	case anchor.TraceID != "":
		from, column, value = "correlation_events AS event JOIN correlation_observations AS observation ON observation.semantic_event_id=event.semantic_event_id", "observation.trace_id", anchor.TraceID
	}
	statement := `SELECT DISTINCT event.semantic_event_id, event.received_time_unix_nano FROM ` +
		from + ` WHERE ` + column + `=?`
	args := []any{value}
	if anchor.TraceID != "" && anchor.SpanID != "" {
		statement += ` AND observation.span_id=?`
		args = append(args, anchor.SpanID)
	}
	if anchor.ConnectorInstanceID != "" {
		statement += ` AND event.connector_instance_id=?`
		args = append(args, string(anchor.ConnectorInstanceID))
	}
	if !page.AfterTime.IsZero() {
		statement += ` AND (event.received_time_unix_nano > ? OR
			(event.received_time_unix_nano = ? AND event.semantic_event_id > ?))`
		after := unixNano(page.AfterTime)
		args = append(args, after, after, page.AfterID)
	}
	statement += ` ORDER BY event.received_time_unix_nano, event.semantic_event_id LIMIT ?`
	args = append(args, limit+1)
	rows, err := repo.store.queryDB(ctx, "correlation_anchor_events", statement, args...)
	if err != nil {
		return nil, false, fmt.Errorf("audit: query correlation anchor: %w", err)
	}
	defer rows.Close()
	var ids []SemanticEventID
	for rows.Next() {
		var id SemanticEventID
		var ignored int64
		if err := rows.Scan(&id, &ignored); err != nil {
			return nil, false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(ids) > limit
	if truncated {
		ids = ids[:limit]
	}
	return ids, truncated, nil
}

func (repo *CorrelationRepository) loadEvents(
	ctx context.Context,
	eventIDs []SemanticEventID,
) ([]CorrelationEvent, error) {
	placeholders, args := semanticPlaceholders(eventIDs)
	rows, err := repo.store.queryDB(ctx, "correlation_events_load", `SELECT semantic_event_id,
		logical_group_id, connector, connector_instance_id, source_rail, event_name,
		source_time_unix_nano, received_time_unix_nano, source_event_digest,
		fingerprint_sha256, first_request_id, first_record_id, profile_version, completeness
		FROM correlation_events WHERE semantic_event_id IN (`+placeholders+`)
		ORDER BY received_time_unix_nano, semantic_event_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: load correlation events: %w", err)
	}
	defer rows.Close()
	var result []CorrelationEvent
	for rows.Next() {
		event, err := scanCorrelationEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func scanCorrelationEvent(scanner interface{ Scan(...any) error }) (CorrelationEvent, error) {
	var event CorrelationEvent
	var sourceTime sql.NullInt64
	var received int64
	var sourceDigest, fingerprint, requestID, recordID sql.NullString
	err := scanner.Scan(&event.SemanticEventID, &event.LogicalEventID, &event.Connector,
		&event.ConnectorInstanceID, &event.Rail, &event.EventName, &sourceTime, &received,
		&sourceDigest, &fingerprint, &requestID, &recordID, &event.ProfileVersion,
		&event.Completeness)
	if err != nil {
		return CorrelationEvent{}, fmt.Errorf("audit: scan correlation event: %w", err)
	}
	if sourceTime.Valid {
		event.SourceTime = time.Unix(0, sourceTime.Int64).UTC()
	}
	event.ReceivedTime = time.Unix(0, received).UTC()
	event.SourceEventDigest = sourceDigest.String
	event.FingerprintSHA256 = fingerprint.String
	event.FirstRequestID = requestID.String
	event.FirstRecordID = recordID.String
	return event, nil
}

func (repo *CorrelationRepository) loadObservations(
	ctx context.Context,
	eventIDs []SemanticEventID,
) ([]CorrelationObservation, error) {
	placeholders, args := semanticPlaceholders(eventIDs)
	rows, err := repo.store.queryDB(ctx, "correlation_observations_load", `SELECT record_id,
		semantic_event_id, signal, bucket, event_name, observed_time_unix_nano, trace_id,
		span_id, session_id, turn_id, agent_id, lifecycle_id, execution_id, model_request_id,
		model_response_id, tool_invocation_id, projection_hash, status
		FROM correlation_observations WHERE semantic_event_id IN (`+placeholders+`)
		ORDER BY observed_time_unix_nano, record_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: load correlation observations: %w", err)
	}
	defer rows.Close()
	var result []CorrelationObservation
	for rows.Next() {
		observation, err := scanCorrelationObservation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, observation)
	}
	return result, rows.Err()
}

func scanCorrelationObservation(scanner interface{ Scan(...any) error }) (CorrelationObservation, error) {
	var observation CorrelationObservation
	var observed int64
	var traceID, spanID, sessionID, turnID, agentID, lifecycleID, executionID sql.NullString
	var modelRequestID, modelResponseID, toolID, projectionHash sql.NullString
	err := scanner.Scan(&observation.RecordID, &observation.SemanticEventID, &observation.Signal,
		&observation.Bucket, &observation.EventName, &observed, &traceID, &spanID, &sessionID,
		&turnID, &agentID, &lifecycleID, &executionID, &modelRequestID, &modelResponseID,
		&toolID, &projectionHash, &observation.Status)
	if err != nil {
		return CorrelationObservation{}, fmt.Errorf("audit: scan correlation observation: %w", err)
	}
	observation.ObservedAt = time.Unix(0, observed).UTC()
	observation.TraceID, observation.SpanID = traceID.String, spanID.String
	observation.SessionID, observation.TurnID = sessionID.String, turnID.String
	observation.AgentID, observation.LifecycleID = agentID.String, lifecycleID.String
	observation.ExecutionID = executionID.String
	observation.ModelRequestID, observation.ModelResponseID = modelRequestID.String, modelResponseID.String
	observation.ToolInvocationID, observation.ProjectionHash = toolID.String, projectionHash.String
	return observation, nil
}

func (repo *CorrelationRepository) loadRelationships(
	ctx context.Context,
	anchor CorrelationAnchor,
	eventIDs []SemanticEventID,
	observations []CorrelationObservation,
) ([]CorrelationRelationship, error) {
	clauses := make([]string, 0, len(eventIDs)*2+4)
	args := make([]any, 0, len(eventIDs)*2+4)
	for _, eventID := range eventIDs {
		clauses = append(clauses, `(from_kind='semantic_event' AND from_id=?)`,
			`(to_kind='semantic_event' AND to_id=?)`)
		args = append(args, string(eventID), string(eventID))
	}
	for _, observation := range observations {
		clauses = append(clauses, `(from_kind='record' AND from_id=?)`, `(to_kind='record' AND to_id=?)`)
		args = append(args, observation.RecordID, observation.RecordID)
	}
	if kind, id := anchorNode(anchor); kind != "" {
		clauses = append(clauses, `(from_kind=? AND from_id=?)`, `(to_kind=? AND to_id=?)`)
		args = append(args, string(kind), id, string(kind), id)
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	rows, err := repo.store.queryDB(ctx, "correlation_relationships_load", `SELECT
		relationship_id, from_kind, from_id, to_kind, to_id, relationship_type, method,
		confidence, rule_id, rule_version, status, created_time_unix_nano,
		last_seen_time_unix_nano FROM correlation_relationships WHERE `+
		strings.Join(clauses, " OR ")+` ORDER BY created_time_unix_nano, relationship_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: load correlation relationships: %w", err)
	}
	defer rows.Close()
	var result []CorrelationRelationship
	for rows.Next() {
		var relationship CorrelationRelationship
		var created, last int64
		if err := rows.Scan(&relationship.RelationshipID, &relationship.FromKind, &relationship.FromID,
			&relationship.ToKind, &relationship.ToID, &relationship.Type, &relationship.Method,
			&relationship.Confidence, &relationship.RuleID, &relationship.RuleVersion,
			&relationship.Status, &created, &last); err != nil {
			return nil, fmt.Errorf("audit: scan correlation relationship: %w", err)
		}
		relationship.CreatedAt = time.Unix(0, created).UTC()
		relationship.LastSeenAt = time.Unix(0, last).UTC()
		result = append(result, relationship)
	}
	return result, rows.Err()
}

func (repo *CorrelationRepository) loadEvidence(
	ctx context.Context,
	relationships []CorrelationRelationship,
) ([]CorrelationRelationshipEvidence, error) {
	if len(relationships) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(relationships))
	args := make([]any, len(relationships))
	for index, relationship := range relationships {
		placeholders[index] = "?"
		args[index] = relationship.RelationshipID
	}
	rows, err := repo.store.queryDB(ctx, "correlation_evidence_load", `SELECT evidence_id,
		relationship_id, evidence_record_id, semantic_event_id, evidence_role, integrity_state,
		created_time_unix_nano FROM correlation_relationship_evidence WHERE relationship_id IN (`+
		strings.Join(placeholders, ",")+`) ORDER BY created_time_unix_nano, evidence_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: load correlation evidence: %w", err)
	}
	defer rows.Close()
	var result []CorrelationRelationshipEvidence
	for rows.Next() {
		var evidence CorrelationRelationshipEvidence
		var recordID, semanticID sql.NullString
		var created int64
		if err := rows.Scan(&evidence.EvidenceID, &evidence.RelationshipID, &recordID,
			&semanticID, &evidence.Role, &evidence.Integrity, &created); err != nil {
			return nil, fmt.Errorf("audit: scan correlation evidence: %w", err)
		}
		evidence.RecordID = recordID.String
		evidence.SemanticEventID = SemanticEventID(semanticID.String)
		evidence.CreatedAt = time.Unix(0, created).UTC()
		result = append(result, evidence)
	}
	return result, rows.Err()
}

func (repo *CorrelationRepository) ingestWatermark(ctx context.Context) (time.Time, error) {
	var watermark sql.NullInt64
	if err := repo.store.db.QueryRowContext(ctx,
		`SELECT MAX(received_time_unix_nano) FROM correlation_events`).Scan(&watermark); err != nil {
		return time.Time{}, fmt.Errorf("audit: read correlation ingest watermark: %w", err)
	}
	if !watermark.Valid {
		return time.Time{}, nil
	}
	return time.Unix(0, watermark.Int64).UTC(), nil
}

func semanticPlaceholders(ids []SemanticEventID) (string, []any) {
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for index, id := range ids {
		placeholders[index] = "?"
		args[index] = string(id)
	}
	return strings.Join(placeholders, ","), args
}

func anchorNode(anchor CorrelationAnchor) (CorrelationNodeKind, string) {
	switch {
	case anchor.RecordID != "":
		return CorrelationNodeRecord, anchor.RecordID
	case anchor.SemanticEventID != "":
		return CorrelationNodeSemanticEvent, string(anchor.SemanticEventID)
	case anchor.LogicalEventID != "":
		return CorrelationNodeLogicalEvent, string(anchor.LogicalEventID)
	case anchor.SessionID != "":
		return CorrelationNodeSession, anchor.SessionID
	case anchor.TurnID != "":
		return CorrelationNodeTurn, anchor.TurnID
	case anchor.AgentID != "":
		return CorrelationNodeAgent, anchor.AgentID
	case anchor.LifecycleID != "":
		return CorrelationNodeLifecycle, anchor.LifecycleID
	case anchor.ExecutionID != "":
		return CorrelationNodeExecution, anchor.ExecutionID
	case anchor.ModelRequestID != "":
		return CorrelationNodeModelRequest, anchor.ModelRequestID
	case anchor.ModelResponseID != "":
		return CorrelationNodeModelResponse, anchor.ModelResponseID
	case anchor.ToolInvocationID != "":
		return CorrelationNodeTool, anchor.ToolInvocationID
	case anchor.TraceID != "" && anchor.SpanID != "":
		return CorrelationNodeSpan, anchor.TraceID + ":" + anchor.SpanID
	case anchor.TraceID != "":
		return CorrelationNodeTrace, anchor.TraceID
	default:
		return "", ""
	}
}
