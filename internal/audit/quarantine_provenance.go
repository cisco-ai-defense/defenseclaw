// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	QuarantineStatePending   = "pending"
	QuarantineStateActive    = "active"
	QuarantineStateRestoring = "restoring"
)

// QuarantineRecord is the durable write-ahead journal for one physical
// quarantine. Logical install/runtime decisions remain in actions.
type QuarantineRecord struct {
	ID             string
	TargetType     string
	TargetName     string
	OriginalPath   string
	QuarantinePath string
	ContentHash    string
	Reason         string
	State          string
	OwnershipJSON  string
	RestorePath    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Connectors     []string
}

// CreateQuarantineRecordInput describes provenance that must be committed
// before a watcher mutates the filesystem. Connectors includes both physical
// owners and any logical action scopes that completion must reconcile.
type CreateQuarantineRecordInput struct {
	TargetType     string
	TargetName     string
	OriginalPath   string
	QuarantinePath string
	ContentHash    string
	Reason         string
	State          string
	OwnershipJSON  string
	Connectors     []string
}

// CreateQuarantineRecord atomically records physical identity and connector
// ownership. Re-registering the same quarantine path is idempotent, but it
// cannot change the asset or content bound to that path.
func (s *Store) CreateQuarantineRecord(
	ctx context.Context, input CreateQuarantineRecordInput,
) (QuarantineRecord, error) {
	if s == nil || s.db == nil {
		return QuarantineRecord{}, fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return QuarantineRecord{}, fmt.Errorf("audit: quarantine provenance context is required")
	}
	normalized, err := normalizeCreateQuarantineRecord(input)
	if err != nil {
		return QuarantineRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("audit: begin quarantine provenance: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	record, found, err := getQuarantineRecordByPathTx(ctx, tx, normalized.QuarantinePath)
	if err != nil {
		return QuarantineRecord{}, err
	}
	now := time.Now().UTC()
	if !found {
		record = QuarantineRecord{
			ID: uuid.NewString(), TargetType: normalized.TargetType,
			TargetName: normalized.TargetName, OriginalPath: normalized.OriginalPath,
			QuarantinePath: normalized.QuarantinePath, ContentHash: normalized.ContentHash,
			Reason: normalized.Reason, State: normalized.State,
			OwnershipJSON: normalized.OwnershipJSON, CreatedAt: now, UpdatedAt: now,
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO quarantine_records (
				id, target_type, target_name, original_path, quarantine_path,
				content_hash, reason, state, ownership_json, restore_path,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
			record.ID, record.TargetType, record.TargetName, record.OriginalPath,
			record.QuarantinePath, record.ContentHash, nullStr(record.Reason),
			record.State, record.OwnershipJSON, record.CreatedAt, record.UpdatedAt,
		); err != nil {
			return QuarantineRecord{}, fmt.Errorf("audit: insert quarantine provenance: %w", err)
		}
	} else {
		if !sameQuarantineIdentity(record, normalized) {
			return QuarantineRecord{}, fmt.Errorf(
				"audit: quarantine path already belongs to a different asset",
			)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE quarantine_records
			SET reason = CASE WHEN ? <> '' THEN ? ELSE reason END,
			    ownership_json = CASE WHEN ? <> '{}' THEN ? ELSE ownership_json END,
			    updated_at = ?
			WHERE id = ?`,
			normalized.Reason, normalized.Reason,
			normalized.OwnershipJSON, normalized.OwnershipJSON, now, record.ID,
		); err != nil {
			return QuarantineRecord{}, fmt.Errorf("audit: refresh quarantine provenance: %w", err)
		}
		record.UpdatedAt = now
		if normalized.Reason != "" {
			record.Reason = normalized.Reason
		}
		if normalized.OwnershipJSON != "{}" {
			record.OwnershipJSON = normalized.OwnershipJSON
		}
	}
	for _, connector := range normalized.Connectors {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO quarantine_record_connectors
				(quarantine_id, connector, associated_at)
			VALUES (?, ?, ?)`, record.ID, connector, now); err != nil {
			return QuarantineRecord{}, fmt.Errorf("audit: associate quarantine connector: %w", err)
		}
	}
	connectors, err := quarantineConnectorsTx(ctx, tx, record.ID)
	if err != nil {
		return QuarantineRecord{}, err
	}
	record.Connectors = connectors
	if err := tx.Commit(); err != nil {
		return QuarantineRecord{}, fmt.Errorf("audit: commit quarantine provenance: %w", err)
	}
	return record, nil
}

// UpdateQuarantineRecordState advances the durable journal before or after a
// filesystem phase. Restoring always binds the intended destination.
func (s *Store) UpdateQuarantineRecordState(
	ctx context.Context, recordID, state, restorePath string,
) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("audit: quarantine provenance context is required")
	}
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		return fmt.Errorf("audit: quarantine record id is required")
	}
	state = strings.TrimSpace(state)
	if !validQuarantineState(state) {
		return fmt.Errorf("audit: invalid quarantine state %q", state)
	}
	if state == QuarantineStateRestoring {
		var err error
		restorePath, err = normalizeAbsolutePath("restore", restorePath)
		if err != nil {
			return err
		}
	} else {
		restorePath = ""
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_records
		SET state = ?, restore_path = ?, updated_at = ?
		WHERE id = ?`, state, nullStr(restorePath), time.Now().UTC(), recordID)
	if err != nil {
		return fmt.Errorf("audit: update quarantine provenance state: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect quarantine state update: %w", err)
	}
	if changed != 1 {
		return fmt.Errorf("audit: quarantine record does not exist")
	}
	return nil
}

// GetQuarantineRecord returns one physical provenance record by id.
func (s *Store) GetQuarantineRecord(
	ctx context.Context, recordID string,
) (*QuarantineRecord, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("audit: quarantine provenance context is required")
	}
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		return nil, fmt.Errorf("audit: quarantine record id is required")
	}
	record, found, err := scanQuarantineRecord(s.db.QueryRowContext(ctx, `
		SELECT id, target_type, target_name, original_path, quarantine_path,
		       content_hash, reason, state, ownership_json, restore_path,
		       created_at, updated_at
		FROM quarantine_records WHERE id = ?`, recordID))
	if err != nil || !found {
		return nil, err
	}
	record.Connectors, err = quarantineConnectorsDB(ctx, s.db, record.ID)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// ListQuarantineRecordsForConnector returns exact connector-owned physical
// records for an asset. The empty connector is the global action scope.
func (s *Store) ListQuarantineRecordsForConnector(
	ctx context.Context, targetType, targetName, connector string,
) ([]QuarantineRecord, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("audit: quarantine provenance context is required")
	}
	targetType = strings.TrimSpace(targetType)
	targetName = strings.TrimSpace(targetName)
	connector = strings.TrimSpace(connector)
	if targetType == "" || targetName == "" {
		return nil, fmt.Errorf("audit: quarantine target identity is incomplete")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT q.id, q.target_type, q.target_name, q.original_path,
		       q.quarantine_path, q.content_hash, q.reason, q.state,
		       q.ownership_json, q.restore_path, q.created_at, q.updated_at
		FROM quarantine_records q
		WHERE q.target_type = ? AND q.target_name = ?
		  AND EXISTS (
			SELECT 1 FROM quarantine_record_connectors c
			WHERE c.quarantine_id = q.id AND c.connector = ?
		  )
		ORDER BY q.created_at, q.id`, targetType, targetName, connector)
	if err != nil {
		return nil, fmt.Errorf("audit: list quarantine provenance: %w", err)
	}
	var records []QuarantineRecord
	for rows.Next() {
		record, scanErr := scanQuarantineRecordScanner(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("audit: iterate quarantine provenance: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("audit: close quarantine provenance rows: %w", err)
	}
	for i := range records {
		records[i].Connectors, err = quarantineConnectorsDB(ctx, s.db, records[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return records, nil
}

// DeleteQuarantineRecord rolls back a pending journal only when the caller has
// proved that no verified quarantine copy remains.
func (s *Store) DeleteQuarantineRecord(ctx context.Context, recordID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("audit: quarantine provenance context is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin quarantine provenance rollback: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM quarantine_record_connectors
		 WHERE quarantine_id IN (
			SELECT id FROM quarantine_records WHERE id = ? AND state = 'pending'
		 )`, recordID,
	); err != nil {
		return fmt.Errorf("audit: delete quarantine connector provenance: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM quarantine_records WHERE id = ? AND state = 'pending'`, recordID,
	); err != nil {
		return fmt.Errorf("audit: delete quarantine provenance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit quarantine provenance rollback: %w", err)
	}
	return nil
}

// CompleteQuarantineRestore atomically retires physical provenance and clears
// only the file action for every associated action scope. Install blocks and
// runtime disables intentionally survive restore.
func (s *Store) CompleteQuarantineRestore(
	ctx context.Context, recordID, destination string,
) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit: quarantine provenance store is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("audit: quarantine provenance context is required")
	}
	destination, err := normalizeAbsolutePath("restore", destination)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin quarantine restore completion: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	record, found, err := getQuarantineRecordByIDTx(ctx, tx, recordID)
	if err != nil || !found {
		return err
	}
	if record.State != QuarantineStateRestoring || !samePath(record.RestorePath, destination) {
		return fmt.Errorf("audit: quarantine restore journal does not match destination")
	}
	connectors, err := quarantineConnectorsTx(ctx, tx, record.ID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, connector := range connectors {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO actions (
				id, target_type, target_name, source_path, actions_json,
				reason, updated_at, connector
			) VALUES (?, ?, ?, ?, '{}', '', ?, ?)
			ON CONFLICT(target_type, target_name, connector) DO UPDATE SET
				source_path = excluded.source_path,
				actions_json = json_remove(actions_json, '$.file'),
				updated_at = excluded.updated_at`,
			uuid.NewString(), record.TargetType, record.TargetName,
			destination, now, connector,
		); err != nil {
			return fmt.Errorf("audit: reconcile restored action state: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM quarantine_record_connectors WHERE quarantine_id = ?`, record.ID,
	); err != nil {
		return fmt.Errorf("audit: retire quarantine connector provenance: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM quarantine_records WHERE id = ?`, record.ID,
	); err != nil {
		return fmt.Errorf("audit: retire quarantine provenance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit quarantine restore completion: %w", err)
	}
	return nil
}

type quarantineRowScanner interface {
	Scan(dest ...any) error
}

func scanQuarantineRecord(scanner quarantineRowScanner) (QuarantineRecord, bool, error) {
	record, err := scanQuarantineRecordScanner(scanner)
	if err == sql.ErrNoRows {
		return QuarantineRecord{}, false, nil
	}
	if err != nil {
		return QuarantineRecord{}, false, err
	}
	return record, true, nil
}

func scanQuarantineRecordScanner(scanner quarantineRowScanner) (QuarantineRecord, error) {
	var record QuarantineRecord
	var reason, restorePath sql.NullString
	if err := scanner.Scan(
		&record.ID, &record.TargetType, &record.TargetName, &record.OriginalPath,
		&record.QuarantinePath, &record.ContentHash, &reason, &record.State,
		&record.OwnershipJSON, &restorePath, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		return QuarantineRecord{}, err
	}
	record.Reason = reason.String
	record.RestorePath = restorePath.String
	return record, nil
}

func getQuarantineRecordByPathTx(
	ctx context.Context, tx *sql.Tx, path string,
) (QuarantineRecord, bool, error) {
	record, found, err := scanQuarantineRecord(tx.QueryRowContext(ctx, `
		SELECT id, target_type, target_name, original_path, quarantine_path,
		       content_hash, reason, state, ownership_json, restore_path,
		       created_at, updated_at
		FROM quarantine_records WHERE quarantine_path = ?`, path))
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("audit: lookup quarantine provenance: %w", err)
	}
	return record, found, nil
}

func getQuarantineRecordByIDTx(
	ctx context.Context, tx *sql.Tx, recordID string,
) (QuarantineRecord, bool, error) {
	record, found, err := scanQuarantineRecord(tx.QueryRowContext(ctx, `
		SELECT id, target_type, target_name, original_path, quarantine_path,
		       content_hash, reason, state, ownership_json, restore_path,
		       created_at, updated_at
		FROM quarantine_records WHERE id = ?`, recordID))
	if err != nil {
		return QuarantineRecord{}, false, fmt.Errorf("audit: lookup quarantine provenance: %w", err)
	}
	return record, found, nil
}

func quarantineConnectorsTx(
	ctx context.Context, tx *sql.Tx, recordID string,
) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT connector FROM quarantine_record_connectors
		WHERE quarantine_id = ? ORDER BY connector`, recordID)
	return scanQuarantineConnectors(rows, err)
}

func quarantineConnectorsDB(
	ctx context.Context, db *sql.DB, recordID string,
) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT connector FROM quarantine_record_connectors
		WHERE quarantine_id = ? ORDER BY connector`, recordID)
	return scanQuarantineConnectors(rows, err)
}

func scanQuarantineConnectors(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, fmt.Errorf("audit: list quarantine connectors: %w", err)
	}
	defer rows.Close()
	var connectors []string
	for rows.Next() {
		var connector string
		if err := rows.Scan(&connector); err != nil {
			return nil, fmt.Errorf("audit: scan quarantine connector: %w", err)
		}
		connectors = append(connectors, connector)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate quarantine connectors: %w", err)
	}
	return connectors, nil
}

func normalizeCreateQuarantineRecord(
	input CreateQuarantineRecordInput,
) (CreateQuarantineRecordInput, error) {
	input.TargetType = strings.TrimSpace(input.TargetType)
	input.TargetName = strings.TrimSpace(input.TargetName)
	input.ContentHash = strings.ToLower(strings.TrimSpace(input.ContentHash))
	input.Reason = strings.TrimSpace(input.Reason)
	input.State = strings.TrimSpace(input.State)
	input.OwnershipJSON = strings.TrimSpace(input.OwnershipJSON)
	if input.State == "" {
		input.State = QuarantineStatePending
	}
	if input.OwnershipJSON == "" {
		input.OwnershipJSON = "{}"
	}
	if input.TargetType != "skill" && input.TargetType != "plugin" {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: invalid quarantine target type %q", input.TargetType)
	}
	if input.TargetName == "" || len(input.TargetName) > 255 {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: invalid quarantine target name")
	}
	var err error
	input.OriginalPath, err = normalizeAbsolutePath("original", input.OriginalPath)
	if err != nil {
		return CreateQuarantineRecordInput{}, err
	}
	input.QuarantinePath, err = normalizeAbsolutePath("quarantine", input.QuarantinePath)
	if err != nil {
		return CreateQuarantineRecordInput{}, err
	}
	decoded, err := hex.DecodeString(input.ContentHash)
	if err != nil || len(decoded) != 32 {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: quarantine content hash must be SHA-256 hex")
	}
	if !validQuarantineState(input.State) || input.State == QuarantineStateRestoring {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: invalid initial quarantine state %q", input.State)
	}
	var ownership map[string]any
	if len(input.OwnershipJSON) > 4096 ||
		json.Unmarshal([]byte(input.OwnershipJSON), &ownership) != nil || ownership == nil {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: quarantine ownership marker must be a JSON object")
	}
	if len(input.Reason) > 4096 {
		return CreateQuarantineRecordInput{}, fmt.Errorf("audit: quarantine reason exceeds 4096 bytes")
	}
	input.Connectors, err = normalizeQuarantineConnectors(input.Connectors)
	if err != nil {
		return CreateQuarantineRecordInput{}, err
	}
	return input, nil
}

func normalizeQuarantineConnectors(connectors []string) ([]string, error) {
	if len(connectors) == 0 {
		connectors = []string{""}
	}
	seen := make(map[string]struct{}, len(connectors))
	normalized := make([]string, 0, len(connectors))
	for _, connector := range connectors {
		connector = strings.TrimSpace(connector)
		if len(connector) > 64 {
			return nil, fmt.Errorf("audit: quarantine connector exceeds 64 bytes")
		}
		if _, ok := seen[connector]; ok {
			continue
		}
		seen[connector] = struct{}{}
		normalized = append(normalized, connector)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeAbsolutePath(label, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("audit: quarantine %s path must be absolute", label)
	}
	cleaned := filepath.Clean(path)
	if len(cleaned) > 4096 {
		return "", fmt.Errorf("audit: quarantine %s path exceeds 4096 bytes", label)
	}
	return cleaned, nil
}

func validQuarantineState(state string) bool {
	switch state {
	case QuarantineStatePending, QuarantineStateActive, QuarantineStateRestoring:
		return true
	default:
		return false
	}
}

func sameQuarantineIdentity(
	record QuarantineRecord, input CreateQuarantineRecordInput,
) bool {
	return record.TargetType == input.TargetType &&
		record.TargetName == input.TargetName &&
		samePath(record.OriginalPath, input.OriginalPath) &&
		record.ContentHash == input.ContentHash
}

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
