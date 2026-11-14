// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// rejected_records holds the redacted copies of records the v8 schema gate
// refused, written only while observability.local.keep_rejected_records is
// on (#1442). It is ordinary local history: the retention reaper prunes it by
// retention_days and by max_store_mb like the other history tables
// (RetentionRejectedRecords), it lives in audit.db with that file's
// permissions, and the writer keeps at most the configured number of rows.

const rejectedRecordsMigrationDescription = "observability v8: add the opt-in store of records the schema gate refused"

const (
	// RejectedRecordMaxPayloadBytes bounds the redacted payload of one row.
	// A larger payload is replaced by an empty object and the row says
	// payload_state omitted_oversize.
	RejectedRecordMaxPayloadBytes = 16 << 10
	// RejectedRecordMaxBatch bounds the rows one write transaction inserts.
	RejectedRecordMaxBatch = 16
	// RejectedRecordTrimBatch bounds the rows one trim transaction deletes,
	// so lowering the cap from 1000000 to 100 is many short transactions,
	// never one long one holding the writer.
	RejectedRecordTrimBatch = 512
	// RejectedRecordsMinRows and RejectedRecordsMaxRows bound
	// observability.local.rejected_records_max_rows.
	RejectedRecordsMinRows = 100
	RejectedRecordsMaxRows = 1_000_000
	// RejectedRecordsDefaultRows is the row cap when the key is unset.
	RejectedRecordsDefaultRows = 10_000
	// RejectedRecordsMaxListLimit bounds one read.
	RejectedRecordsMaxListLimit = 10_000

	rejectedRecordTextBytes = 1024
)

// Payload states of a stored row.
const (
	RejectedPayloadRedacted        = "redacted"
	RejectedPayloadOmittedOversize = "omitted_oversize"
	RejectedPayloadRedactionFailed = "omitted_redaction_failed"
)

func migrateRejectedRecords(ex dbExecer) error {
	// A Secure Client store keeps main's schema; the store is never on there.
	if form, ok := ex.(interface{ secureClientMigration() bool }); ok && form.secureClientMigration() {
		return nil
	}
	if _, err := ex.Exec(`CREATE TABLE IF NOT EXISTS rejected_records (
		id INTEGER PRIMARY KEY,
		stored_at TEXT NOT NULL,
		retention_timestamp_unix_nano INTEGER NOT NULL,
		observed_at TEXT NOT NULL,
		signal TEXT NOT NULL,
		bucket TEXT NOT NULL,
		event_name TEXT NOT NULL,
		family TEXT NOT NULL,
		family_schema_version INTEGER NOT NULL,
		source TEXT NOT NULL,
		connector TEXT NOT NULL,
		reason_code TEXT NOT NULL,
		field TEXT NOT NULL,
		error_text TEXT NOT NULL,
		payload_state TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		omitted_fields_json TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create rejected_records: %w", err)
	}
	if _, err := ex.Exec(`CREATE INDEX IF NOT EXISTS idx_rejected_records_retention
		ON rejected_records(retention_timestamp_unix_nano, id)`); err != nil {
		return fmt.Errorf("index rejected_records: %w", err)
	}
	return nil
}

// RejectedRecordRow is one stored refused record. Payload is the redacted
// copy of its fields (a JSON object); OmittedFields lists the keys whose
// values were not kept.
type RejectedRecordRow struct {
	ID                  int64           `json:"id"`
	StoredAt            time.Time       `json:"stored_at"`
	ObservedAt          time.Time       `json:"observed_at"`
	Signal              string          `json:"signal"`
	Bucket              string          `json:"bucket"`
	EventName           string          `json:"event_name"`
	Family              string          `json:"family"`
	FamilySchemaVersion int64           `json:"family_schema_version"`
	Source              string          `json:"source,omitempty"`
	Connector           string          `json:"connector,omitempty"`
	ReasonCode          string          `json:"reason_code"`
	Field               string          `json:"field,omitempty"`
	ErrorText           string          `json:"error"`
	PayloadState        string          `json:"payload_state"`
	Payload             json.RawMessage `json:"payload"`
	OmittedFields       []string        `json:"omitted_fields,omitempty"`
}

// InsertRejectedRecords appends up to RejectedRecordMaxBatch rows in one
// short transaction; TrimRejectedRecords then keeps the row cap. maxRows is
// checked here so a caller cannot write without a valid cap. The store must
// be ready; a read-only or Secure Client store is not a writer here. Each
// attempt takes the write baton like the grouped hook writes (GAP-0490), so
// this transaction and the durable hook journal commit take turns instead of
// meeting SQLITE_BUSY.
func (s *Store) InsertRejectedRecords(ctx context.Context, rows []RejectedRecordRow, maxRows int) error {
	if s == nil || s.db == nil {
		return errors.New("audit: rejected records: store is not initialized")
	}
	if ctx == nil || len(rows) == 0 {
		return nil
	}
	if len(rows) > RejectedRecordMaxBatch {
		return fmt.Errorf("audit: rejected records: batch of %d rows exceeds %d", len(rows), RejectedRecordMaxBatch)
	}
	if maxRows < RejectedRecordsMinRows || maxRows > RejectedRecordsMaxRows {
		return fmt.Errorf("audit: rejected records: row cap %d is out of range", maxRows)
	}
	prepared := make([]RejectedRecordRow, len(rows))
	for index, row := range rows {
		prepared[index] = boundRejectedRecordRow(row)
	}
	if err := s.awaitWALHeadroom(ctx); err != nil {
		return err
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	return retryBusy(ctx, "rejected_records_insert", func() error {
		turn, turnErr := s.writeBaton.acquire(ctx)
		if turnErr != nil {
			return turnErr
		}
		defer turn()
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		for _, row := range prepared {
			omitted, encodeErr := json.Marshal(row.OmittedFields)
			if encodeErr != nil {
				return encodeErr
			}
			if _, execErr := tx.ExecContext(ctx, `INSERT INTO rejected_records (
				stored_at, retention_timestamp_unix_nano, observed_at, signal, bucket,
				event_name, family, family_schema_version, source, connector,
				reason_code, field, error_text, payload_state, payload_json, omitted_fields_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				row.StoredAt.Format(time.RFC3339Nano), row.StoredAt.UnixNano(),
				row.ObservedAt.Format(time.RFC3339Nano), row.Signal, row.Bucket,
				row.EventName, row.Family, row.FamilySchemaVersion, row.Source, row.Connector,
				row.ReasonCode, row.Field, row.ErrorText, row.PayloadState, string(row.Payload), string(omitted),
			); execErr != nil {
				return execErr
			}
		}
		return tx.Commit()
	})
}

// TrimRejectedRecords deletes at most limit of the oldest rows past maxRows
// in one short transaction under the write baton, and reports whether rows
// past the cap remain. Rows leave only oldest first (this cap and
// retention), so the kept ids are contiguous and "past the cap" is
// id <= MAX(id) - maxRows; a gap can only make it keep fewer rows. Callers
// loop, yielding between calls.
func (s *Store) TrimRejectedRecords(ctx context.Context, maxRows, limit int) (deleted int64, more bool, err error) {
	if s == nil || s.db == nil {
		return 0, false, errors.New("audit: rejected records: store is not initialized")
	}
	if ctx == nil {
		return 0, false, errors.New("audit: rejected records: context is required")
	}
	if maxRows < RejectedRecordsMinRows || maxRows > RejectedRecordsMaxRows || limit < 1 || limit > RejectedRecordTrimBatch {
		return 0, false, fmt.Errorf("audit: rejected records: trim cap %d / batch %d is out of range", maxRows, limit)
	}
	if err := s.awaitWALHeadroom(ctx); err != nil {
		return 0, false, err
	}
	release, err := s.acquireReady()
	if err != nil {
		return 0, false, err
	}
	defer release()
	err = retryBusy(ctx, "rejected_records_trim", func() error {
		turn, turnErr := s.writeBaton.acquire(ctx)
		if turnErr != nil {
			return turnErr
		}
		defer turn()
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		result, execErr := tx.ExecContext(ctx, `DELETE FROM rejected_records WHERE id IN (
			SELECT id FROM rejected_records
			WHERE id <= (SELECT MAX(id) FROM rejected_records) - ?
			ORDER BY id LIMIT ?
		)`, maxRows, limit)
		if execErr != nil {
			return execErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		deleted = rows
		return nil
	})
	return deleted, err == nil && deleted == int64(limit), err
}

// boundRejectedRecordRow applies the column bounds, so a caller can never
// store more than the documented size per row.
func boundRejectedRecordRow(row RejectedRecordRow) RejectedRecordRow {
	if row.StoredAt.IsZero() {
		row.StoredAt = time.Now()
	}
	row.StoredAt = row.StoredAt.UTC()
	if row.ObservedAt.IsZero() {
		row.ObservedAt = row.StoredAt
	}
	row.ObservedAt = row.ObservedAt.UTC()
	for _, text := range []*string{
		&row.Signal, &row.Bucket, &row.EventName, &row.Family, &row.Source,
		&row.Connector, &row.ReasonCode, &row.Field, &row.ErrorText, &row.PayloadState,
	} {
		*text = truncateValidUTF8(*text, rejectedRecordTextBytes)
	}
	if row.PayloadState == "" {
		row.PayloadState = RejectedPayloadRedacted
	}
	if len(row.Payload) == 0 {
		row.Payload = json.RawMessage(`{}`)
	}
	if len(row.Payload) > RejectedRecordMaxPayloadBytes || !json.Valid(row.Payload) {
		row.Payload = json.RawMessage(`{}`)
		row.PayloadState = RejectedPayloadOmittedOversize
	}
	if len(row.OmittedFields) > 64 {
		row.OmittedFields = row.OmittedFields[:64]
	}
	for index := range row.OmittedFields {
		row.OmittedFields[index] = truncateValidUTF8(row.OmittedFields[index], 256)
	}
	if row.OmittedFields == nil {
		row.OmittedFields = []string{}
	}
	return row
}

func truncateValidUTF8(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && cut < len(value) && value[cut]&0xC0 == 0x80 {
		cut--
	}
	return value[:cut]
}

// RejectedRecordQuery selects stored rows: the newest Limit rows stored at or
// after Since (nil: any time).
type RejectedRecordQuery struct {
	Since *time.Time
	Limit int
}

// ErrRejectedRecordsUnavailable reports a store without the rejected_records
// table: written by a release before 1.0.10 and opened read-only.
var ErrRejectedRecordsUnavailable = errors.New("audit: this audit database has no rejected_records table (written by a release before 1.0.10)")

// ListRejectedRecords returns the newest matching rows, newest first.
func (s *Store) ListRejectedRecords(ctx context.Context, query RejectedRecordQuery) ([]RejectedRecordRow, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit: rejected records: store is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if query.Limit < 1 || query.Limit > RejectedRecordsMaxListLimit {
		return nil, fmt.Errorf("audit: rejected records: limit must be between 1 and %d", RejectedRecordsMaxListLimit)
	}
	present, err := tableExists(s.db, "rejected_records")
	if err != nil {
		return nil, fmt.Errorf("audit: rejected records: %w", err)
	}
	if !present {
		return nil, ErrRejectedRecordsUnavailable
	}
	since := int64(0)
	if query.Since != nil {
		since = query.Since.UnixNano()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, stored_at, observed_at, signal, bucket, event_name,
			family, family_schema_version, source, connector, reason_code, field, error_text,
			payload_state, payload_json, omitted_fields_json
		FROM rejected_records INDEXED BY idx_rejected_records_retention
		WHERE retention_timestamp_unix_nano >= ?
		ORDER BY retention_timestamp_unix_nano DESC, id DESC LIMIT ?`, since, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("audit: rejected records: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	var result []RejectedRecordRow
	for rows.Next() {
		var row RejectedRecordRow
		var stored, observed, payload, omitted string
		if err := rows.Scan(&row.ID, &stored, &observed, &row.Signal, &row.Bucket, &row.EventName,
			&row.Family, &row.FamilySchemaVersion, &row.Source, &row.Connector, &row.ReasonCode,
			&row.Field, &row.ErrorText, &row.PayloadState, &payload, &omitted); err != nil {
			return nil, fmt.Errorf("audit: rejected records: %w", err)
		}
		row.StoredAt, _ = time.Parse(time.RFC3339Nano, stored)
		row.ObservedAt, _ = time.Parse(time.RFC3339Nano, observed)
		if json.Valid([]byte(payload)) {
			row.Payload = json.RawMessage(payload)
		} else {
			row.Payload = json.RawMessage(`{}`)
		}
		if err := json.Unmarshal([]byte(omitted), &row.OmittedFields); err != nil {
			row.OmittedFields = nil
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rejected records: %w", err)
	}
	return result, nil
}

// CountRejectedRecords reports how many rows the table holds, 0 when absent.
func (s *Store) CountRejectedRecords(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("audit: rejected records: store is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	present, err := tableExists(s.db, "rejected_records")
	if err != nil || !present {
		return 0, err
	}
	var count sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rejected_records`).Scan(&count); err != nil {
		return 0, fmt.Errorf("audit: rejected records: %w", err)
	}
	return count.Int64, nil
}
