// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	// RuntimeAssetSelected is a native selection without a load attestation.
	RuntimeAssetSelected = "selected"
	// RuntimeAssetBlocked is a native selection rejected before load.
	RuntimeAssetBlocked = "blocked"
	// RuntimeAssetLoaded is reserved for WIN-AUD-071's load attestation.
	RuntimeAssetLoaded = "loaded"
)

// RuntimeAssetState is current connector/session asset provenance. Raw hook
// bodies and prompts are intentionally excluded.
type RuntimeAssetState struct {
	Connector      string
	SessionID      string
	TargetType     string
	TargetName     string
	SourcePath     string
	RuntimeSurface string
	HookEvent      string
	Provenance     string
	State          string
	FirstObserved  time.Time
	LastObserved   time.Time
}

func migrateRuntimeAssetState(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS runtime_asset_state (
			connector TEXT NOT NULL, session_id TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL, target_name TEXT NOT NULL,
			source_path TEXT NOT NULL DEFAULT '', runtime_surface TEXT NOT NULL,
			hook_event TEXT NOT NULL, provenance TEXT NOT NULL, state TEXT NOT NULL,
			first_observed_at DATETIME NOT NULL, last_observed_at DATETIME NOT NULL,
			PRIMARY KEY (connector, session_id, target_type, target_name)
		);
		CREATE INDEX IF NOT EXISTS idx_runtime_asset_session
			ON runtime_asset_state(connector, session_id, last_observed_at);
		CREATE INDEX IF NOT EXISTS idx_runtime_asset_target
			ON runtime_asset_state(target_type, target_name, connector);
	`)
	if err != nil {
		return fmt.Errorf("create runtime asset state: %w", err)
	}
	return nil
}

// RecordRuntimeAssetState upserts current state. first_observed_at is
// immutable, and an empty later source path cannot erase stronger provenance.
func (s *Store) RecordRuntimeAssetState(ctx context.Context, input RuntimeAssetState) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit: runtime asset state store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("audit: runtime asset state context is required")
	}
	normalized, err := normalizeRuntimeAssetState(input)
	if err != nil {
		return err
	}
	_, err = s.execDB(ctx, "runtime_asset_state", `
		INSERT INTO runtime_asset_state (
			connector, session_id, target_type, target_name, source_path,
			runtime_surface, hook_event, provenance, state,
			first_observed_at, last_observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector, session_id, target_type, target_name) DO UPDATE SET
			source_path = CASE
				WHEN excluded.source_path <> '' THEN excluded.source_path
				ELSE runtime_asset_state.source_path
			END,
			runtime_surface = excluded.runtime_surface,
			hook_event = excluded.hook_event,
			provenance = excluded.provenance,
			state = excluded.state,
			last_observed_at = excluded.last_observed_at`,
		normalized.Connector, normalized.SessionID, normalized.TargetType,
		normalized.TargetName, normalized.SourcePath, normalized.RuntimeSurface,
		normalized.HookEvent, normalized.Provenance, normalized.State,
		normalized.FirstObserved, normalized.LastObserved,
	)
	if err != nil {
		return fmt.Errorf("audit: record runtime asset state: %w", err)
	}
	return nil
}

// GetRuntimeAssetState returns an exact connector/session/asset projection.
func (s *Store) GetRuntimeAssetState(
	ctx context.Context,
	connector, sessionID, targetType, targetName string,
) (*RuntimeAssetState, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("audit: runtime asset state store is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("audit: runtime asset state context is required")
	}
	connector = strings.TrimSpace(connector)
	targetType = strings.TrimSpace(targetType)
	targetName = strings.TrimSpace(targetName)
	if connector == "" || targetType == "" || targetName == "" {
		return nil, fmt.Errorf("audit: runtime asset state identity is incomplete")
	}
	var state RuntimeAssetState
	err := s.scanRow(ctx, "runtime_asset_state_get", s.db.QueryRowContext(ctx, `
		SELECT connector, session_id, target_type, target_name, source_path,
		       runtime_surface, hook_event, provenance, state,
		       first_observed_at, last_observed_at
		FROM runtime_asset_state
		WHERE connector = ? AND session_id = ? AND target_type = ? AND target_name = ?`,
		connector, strings.TrimSpace(sessionID), targetType, targetName,
	), &state.Connector, &state.SessionID, &state.TargetType, &state.TargetName,
		&state.SourcePath, &state.RuntimeSurface, &state.HookEvent,
		&state.Provenance, &state.State, &state.FirstObserved, &state.LastObserved)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: get runtime asset state: %w", err)
	}
	return &state, nil
}

// ListRuntimeAssetStatesForSession is the connector-scoped handoff for
// WIN-AUD-071. It cannot expose state from another connector or session.
func (s *Store) ListRuntimeAssetStatesForSession(
	ctx context.Context, connector, sessionID string,
) ([]RuntimeAssetState, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("audit: runtime asset state store is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("audit: runtime asset state context is required")
	}
	connector = strings.TrimSpace(connector)
	if connector == "" {
		return nil, fmt.Errorf("audit: runtime asset state connector is required")
	}
	rows, err := s.queryDB(ctx, "runtime_asset_state_list", `
		SELECT connector, session_id, target_type, target_name, source_path,
		       runtime_surface, hook_event, provenance, state,
		       first_observed_at, last_observed_at
		FROM runtime_asset_state
		WHERE connector = ? AND session_id = ?
		ORDER BY last_observed_at DESC, target_type, target_name`,
		connector, strings.TrimSpace(sessionID),
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list runtime asset state: %w", err)
	}
	defer rows.Close()
	var out []RuntimeAssetState
	for rows.Next() {
		var state RuntimeAssetState
		if err := rows.Scan(
			&state.Connector, &state.SessionID, &state.TargetType,
			&state.TargetName, &state.SourcePath, &state.RuntimeSurface,
			&state.HookEvent, &state.Provenance, &state.State,
			&state.FirstObserved, &state.LastObserved,
		); err != nil {
			return nil, fmt.Errorf("audit: scan runtime asset state: %w", err)
		}
		out = append(out, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate runtime asset state: %w", err)
	}
	return out, nil
}

func normalizeRuntimeAssetState(input RuntimeAssetState) (RuntimeAssetState, error) {
	input.Connector = strings.TrimSpace(input.Connector)
	input.SessionID = strings.TrimSpace(input.SessionID)
	input.TargetType = strings.TrimSpace(input.TargetType)
	input.TargetName = strings.TrimSpace(input.TargetName)
	input.SourcePath = strings.TrimSpace(input.SourcePath)
	input.RuntimeSurface = strings.TrimSpace(input.RuntimeSurface)
	input.HookEvent = strings.TrimSpace(input.HookEvent)
	input.Provenance = strings.TrimSpace(input.Provenance)
	input.State = strings.TrimSpace(input.State)
	for _, required := range []struct {
		label string
		value string
	}{
		{"connector", input.Connector},
		{"target_type", input.TargetType},
		{"target_name", input.TargetName},
		{"runtime_surface", input.RuntimeSurface},
		{"hook_event", input.HookEvent},
		{"provenance", input.Provenance},
	} {
		if required.value == "" {
			return RuntimeAssetState{}, fmt.Errorf(
				"audit: runtime asset state %s is required", required.label,
			)
		}
	}
	switch input.State {
	case RuntimeAssetSelected, RuntimeAssetBlocked, RuntimeAssetLoaded:
	default:
		return RuntimeAssetState{}, fmt.Errorf(
			"audit: invalid runtime asset state %q", input.State,
		)
	}
	return normalizeRuntimeAssetStateBoundsAndTime(input)
}

func normalizeRuntimeAssetStateBoundsAndTime(
	input RuntimeAssetState,
) (RuntimeAssetState, error) {
	for _, bounded := range []struct {
		label string
		value string
		max   int
	}{
		{"connector", input.Connector, 64},
		{"session_id", input.SessionID, 512},
		{"target_type", input.TargetType, 64},
		{"target_name", input.TargetName, 255},
		{"source_path", input.SourcePath, 4096},
		{"runtime_surface", input.RuntimeSurface, 128},
		{"hook_event", input.HookEvent, 128},
		{"provenance", input.Provenance, 128},
	} {
		if len(bounded.value) > bounded.max {
			return RuntimeAssetState{}, fmt.Errorf(
				"audit: runtime asset state %s exceeds %d bytes",
				bounded.label, bounded.max,
			)
		}
	}
	now := time.Now().UTC()
	if input.FirstObserved.IsZero() {
		input.FirstObserved = now
	} else {
		input.FirstObserved = input.FirstObserved.UTC()
	}
	if input.LastObserved.IsZero() {
		input.LastObserved = now
	} else {
		input.LastObserved = input.LastObserved.UTC()
	}
	if input.LastObserved.Before(input.FirstObserved) {
		return RuntimeAssetState{}, fmt.Errorf(
			"audit: runtime asset state observation order is invalid",
		)
	}
	return input, nil
}
