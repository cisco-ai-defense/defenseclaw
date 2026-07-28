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

const maxCorrelationStateQueryLimit = 100

type CorrelationPendingQuery struct {
	ConnectorInstanceID ConnectorInstanceID
	Namespace           string
	Kind                CorrelationIdentifierKind
	OperationID         string
	Type                CorrelationOperationType
	ScopeKind           CorrelationOperationScopeKind
	ScopeID             string
	Status              CorrelationOperationStatus
	Name                string
	SessionID           string
	TurnID              string
	AgentID             string
	ExecutionID         string
	Limit               int
}

func (repo *CorrelationRepository) GetCursor(
	ctx context.Context,
	connectorInstanceID ConnectorInstanceID,
	sessionID string,
	agentID string,
) (CorrelationCursor, error) {
	if err := repo.validateStateQuery(ctx, connectorInstanceID); err != nil {
		return CorrelationCursor{}, err
	}
	if err := validateBoundedIdentifier("cursor session id", sessionID, true, maxCorrelationIdentifierBytes); err != nil {
		return CorrelationCursor{}, err
	}
	if err := validateBoundedIdentifier("cursor agent id", agentID, true, maxCorrelationIdentifierBytes); err != nil {
		return CorrelationCursor{}, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return CorrelationCursor{}, err
	}
	defer release()
	return scanCorrelationCursor(repo.store.db.QueryRowContext(ctx, correlationCursorSelect+
		` WHERE connector_instance_id=? AND session_id=? AND agent_id=?`,
		string(connectorInstanceID), sessionID, agentID))
}

// FindActiveCursor permits an omitted agent only when exactly one active
// cursor exists for the connector/session pair. Ambiguity never picks "latest".
func (repo *CorrelationRepository) FindActiveCursor(
	ctx context.Context,
	connectorInstanceID ConnectorInstanceID,
	sessionID string,
) (CorrelationCursor, error) {
	if err := repo.validateStateQuery(ctx, connectorInstanceID); err != nil {
		return CorrelationCursor{}, err
	}
	if err := validateBoundedIdentifier("cursor session id", sessionID, true, maxCorrelationIdentifierBytes); err != nil {
		return CorrelationCursor{}, err
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return CorrelationCursor{}, err
	}
	defer release()
	rows, err := repo.store.db.QueryContext(ctx, correlationCursorSelect+`
		WHERE connector_instance_id=? AND session_id=? AND active=1
		ORDER BY updated_time_unix_nano DESC, agent_id LIMIT 2`, string(connectorInstanceID), sessionID)
	if err != nil {
		return CorrelationCursor{}, fmt.Errorf("audit: find active correlation cursor: %w", err)
	}
	defer rows.Close()
	var result []CorrelationCursor
	for rows.Next() {
		cursor, err := scanCorrelationCursor(rows)
		if err != nil {
			return CorrelationCursor{}, err
		}
		result = append(result, cursor)
	}
	if err := rows.Err(); err != nil {
		return CorrelationCursor{}, fmt.Errorf("audit: iterate active correlation cursors: %w", err)
	}
	if len(result) == 0 {
		return CorrelationCursor{}, ErrCorrelationNotFound
	}
	if len(result) != 1 {
		return CorrelationCursor{}, ErrCorrelationConflict
	}
	return result[0], nil
}

const correlationCursorSelect = `SELECT connector_instance_id, session_id, agent_id,
	lifecycle_id, execution_id, active_turn_id, active_prompt_id, phase, sequence,
	root_agent_id, parent_agent_id, root_session_id, parent_session_id,
	last_semantic_event_id, last_record_id, profile_version, active,
	updated_time_unix_nano FROM correlation_cursors `

func scanCorrelationCursor(scanner interface{ Scan(...any) error }) (CorrelationCursor, error) {
	var cursor CorrelationCursor
	var lifecycle, execution, turn, prompt, rootAgent, parentAgent sql.NullString
	var rootSession, parentSession, semantic, record sql.NullString
	var sequence uint64
	var active int
	var updated int64
	if err := scanner.Scan(&cursor.ConnectorInstanceID, &cursor.SessionID, &cursor.AgentID,
		&lifecycle, &execution, &turn, &prompt, &cursor.Phase, &sequence, &rootAgent,
		&parentAgent, &rootSession, &parentSession, &semantic, &record,
		&cursor.ProfileVersion, &active, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CorrelationCursor{}, ErrCorrelationNotFound
		}
		return CorrelationCursor{}, fmt.Errorf("audit: scan correlation cursor: %w", err)
	}
	cursor.LifecycleID = lifecycle.String
	cursor.ExecutionID = execution.String
	cursor.ActiveTurnID = turn.String
	cursor.ActivePromptID = prompt.String
	cursor.Sequence = sequence
	cursor.RootAgentID = rootAgent.String
	cursor.ParentAgentID = parentAgent.String
	cursor.RootSessionID = rootSession.String
	cursor.ParentSessionID = parentSession.String
	cursor.LastSemanticEventID = SemanticEventID(semantic.String)
	cursor.LastRecordID = record.String
	cursor.Active = active != 0
	cursor.UpdatedAt = time.Unix(0, updated).UTC()
	return cursor, nil
}

func (repo *CorrelationRepository) ListPendingOperations(
	ctx context.Context,
	query CorrelationPendingQuery,
) ([]CorrelationPendingOperation, error) {
	if err := repo.validatePendingQuery(ctx, query); err != nil {
		return nil, err
	}
	limit := query.Limit
	if limit == 0 {
		limit = maxCorrelationStateQueryLimit
	}
	clauses := []string{"connector_instance_id=?"}
	args := []any{string(query.ConnectorInstanceID)}
	for _, filter := range []struct{ column, value string }{
		{"operation_namespace", query.Namespace}, {"operation_kind", string(query.Kind)},
		{"operation_id", query.OperationID}, {"operation_type", string(query.Type)},
		{"scope_kind", string(query.ScopeKind)}, {"scope_id", query.ScopeID}, {"status", string(query.Status)},
		{"operation_name", query.Name}, {"session_id", query.SessionID}, {"turn_id", query.TurnID},
		{"agent_id", query.AgentID}, {"execution_id", query.ExecutionID},
	} {
		if filter.value != "" {
			clauses = append(clauses, filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	args = append(args, limit)
	release, err := repo.store.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := repo.store.db.QueryContext(ctx, correlationPendingSelect+` WHERE `+
		strings.Join(clauses, " AND ")+`
		ORDER BY updated_time_unix_nano DESC, operation_id, operation_type LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list correlation pending operations: %w", err)
	}
	defer rows.Close()
	result := make([]CorrelationPendingOperation, 0, limit)
	for rows.Next() {
		operation, err := scanCorrelationPending(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate correlation pending operations: %w", err)
	}
	return result, nil
}

func (repo *CorrelationRepository) FindUniquePendingOperation(
	ctx context.Context,
	query CorrelationPendingQuery,
) (CorrelationPendingOperation, error) {
	if err := validateUniquePendingQuery(query); err != nil {
		return CorrelationPendingOperation{}, err
	}
	query.Status = CorrelationOperationActive
	query.Limit = 2
	operations, err := repo.ListPendingOperations(ctx, query)
	if err != nil {
		return CorrelationPendingOperation{}, err
	}
	if len(operations) == 0 {
		return CorrelationPendingOperation{}, ErrCorrelationNotFound
	}
	if len(operations) != 1 {
		return CorrelationPendingOperation{}, ErrCorrelationConflict
	}
	return operations[0], nil
}

const correlationPendingSelect = `SELECT connector_instance_id, operation_namespace,
	operation_kind, operation_id, operation_type, scope_kind, scope_id,
	operation_name, session_id, turn_id, agent_id, execution_id,
	start_semantic_event_id, start_time_unix_nano, input_digest,
	terminal_semantic_event_id, terminal_time_unix_nano, status,
	updated_time_unix_nano FROM correlation_pending_operations `

func scanCorrelationPending(scanner interface{ Scan(...any) error }) (CorrelationPendingOperation, error) {
	var operation CorrelationPendingOperation
	var name, session, turn, agent, execution, digest, terminal sql.NullString
	var started, updated int64
	var terminalAt sql.NullInt64
	if err := scanner.Scan(&operation.ConnectorInstanceID, &operation.Namespace,
		&operation.Kind, &operation.OperationID, &operation.Type, &operation.ScopeKind,
		&operation.ScopeID, &name, &session, &turn, &agent, &execution,
		&operation.StartSemanticEventID, &started, &digest, &terminal, &terminalAt,
		&operation.Status, &updated); err != nil {
		return CorrelationPendingOperation{}, fmt.Errorf("audit: scan correlation pending operation: %w", err)
	}
	operation.Name = name.String
	operation.SessionID = session.String
	operation.TurnID = turn.String
	operation.AgentID = agent.String
	operation.ExecutionID = execution.String
	operation.StartedAt = time.Unix(0, started).UTC()
	operation.InputDigest = digest.String
	operation.TerminalSemanticEventID = SemanticEventID(terminal.String)
	if terminalAt.Valid {
		operation.TerminalAt = time.Unix(0, terminalAt.Int64).UTC()
	}
	operation.UpdatedAt = time.Unix(0, updated).UTC()
	return operation, nil
}

func (repo *CorrelationRepository) validateStateQuery(ctx context.Context, connector ConnectorInstanceID) error {
	if repo == nil || repo.store == nil {
		return errors.New("audit: correlation repository is not initialized")
	}
	if ctx == nil {
		return errors.New("audit: correlation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return validateUUIDv7("connector instance id", string(connector))
}

func (repo *CorrelationRepository) validatePendingQuery(ctx context.Context, query CorrelationPendingQuery) error {
	if err := repo.validateStateQuery(ctx, query.ConnectorInstanceID); err != nil {
		return err
	}
	if query.Type != "" && !validOperationType(query.Type) {
		return errors.New("audit: pending operation query type is invalid")
	}
	if query.Kind != "" && !validPendingIdentityKind(query.Kind) {
		return errors.New("audit: pending operation query kind is invalid")
	}
	if query.Kind != "" && query.Type != "" && !validPendingOperationKind(query.Type, query.Kind) {
		return errors.New("audit: pending operation query kind is incompatible with type")
	}
	if query.ScopeKind != "" && !validOperationScopeKind(query.ScopeKind) {
		return errors.New("audit: pending operation query scope kind is invalid")
	}
	if query.Status != "" && !validOperationStatus(query.Status) {
		return errors.New("audit: pending operation query status is invalid")
	}
	if query.Limit < 0 || query.Limit > maxCorrelationStateQueryLimit {
		return fmt.Errorf("audit: pending operation query limit must be between 0 and %d", maxCorrelationStateQueryLimit)
	}
	for field, value := range map[string]string{
		"pending operation namespace": query.Namespace, "pending operation id": query.OperationID,
		"pending operation scope id": query.ScopeID, "pending operation name": query.Name,
		"pending session id": query.SessionID,
		"pending turn id":    query.TurnID, "pending agent id": query.AgentID,
		"pending execution id": query.ExecutionID,
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
	return nil
}

func validateUniquePendingQuery(query CorrelationPendingQuery) error {
	if query.Namespace == "" || query.Kind == "" || query.Type == "" ||
		query.ScopeKind == "" || query.ScopeID == "" {
		return errors.New("audit: unique pending lookup requires typed identity and scope")
	}
	if !validPendingOperationKind(query.Type, query.Kind) || !validOperationScopeKind(query.ScopeKind) {
		return errors.New("audit: unique pending lookup has invalid typed identity or scope")
	}
	if query.ScopeKind == CorrelationOperationScopeConnectorInstance &&
		query.ScopeID != string(query.ConnectorInstanceID) {
		return errors.New("audit: connector-instance pending lookup scope mismatch")
	}
	return nil
}
