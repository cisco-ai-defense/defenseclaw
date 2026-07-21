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
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	legacyJudgeTimestampUnixNanoIndex = "idx_judge_timestamp_unix_nano"
	judgeBodyTimestampUnixNanoIndex   = "idx_jb_timestamp_unix_nano"
	judgeTimestampBackfillBatchSize   = 1000
)

// migrateJudgeBodyTimestampUnixNano adds and backfills the numeric instant used
// by retention. The original timestamp text remains authoritative for legacy
// readers and display; the new column is an exact, indexed comparison key.
func migrateJudgeBodyTimestampUnixNano(ex dbExecer, indexName string) error {
	present, err := tableExists(ex, "judge_responses")
	if err != nil || !present {
		return err
	}
	exists, err := hasColumnDB(ex, "judge_responses", "timestamp_unix_nano")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := ex.Exec(`ALTER TABLE judge_responses ADD COLUMN timestamp_unix_nano INTEGER`); err != nil {
			return fmt.Errorf("add judge_responses.timestamp_unix_nano: %w", err)
		}
	}
	// Build the composite index before backfill. SQLite indexes NULL entries,
	// so every bounded `IS NULL ORDER BY id LIMIT` batch is an indexed range
	// rather than repeatedly rescanning already-normalized rows.
	if _, err := ex.Exec(fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS %s ON judge_responses(timestamp_unix_nano, id)`,
		indexName,
	)); err != nil {
		return fmt.Errorf("create judge timestamp retention index: %w", err)
	}

	type backfillRow struct {
		id       string
		unixNano int64
	}
	for {
		rows, err := ex.Query(`SELECT id, CAST(timestamp AS TEXT)
			FROM judge_responses
			WHERE timestamp_unix_nano IS NULL
			ORDER BY id ASC
			LIMIT ?`, judgeTimestampBackfillBatchSize)
		if err != nil {
			return fmt.Errorf("read judge timestamp backfill batch: %w", err)
		}
		backfill := make([]backfillRow, 0, judgeTimestampBackfillBatchSize)
		for rows.Next() {
			var id, encoded string
			if err := rows.Scan(&id, &encoded); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan judge timestamp backfill: %w", err)
			}
			parsed, err := parseJudgeBodyTimestamp(encoded)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("parse judge timestamp for row %q: %w", id, err)
			}
			unixNano, err := judgeBodyUnixNano(parsed)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("normalize judge timestamp for row %q: %w", id, err)
			}
			backfill = append(backfill, backfillRow{id: id, unixNano: unixNano})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("iterate judge timestamp backfill: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close judge timestamp backfill: %w", err)
		}
		if len(backfill) == 0 {
			break
		}
		for _, row := range backfill {
			if _, err := ex.Exec(`UPDATE judge_responses
				SET timestamp_unix_nano = ?
				WHERE id = ? AND timestamp_unix_nano IS NULL`, row.unixNano, row.id); err != nil {
				return fmt.Errorf("backfill judge timestamp for row %q: %w", row.id, err)
			}
		}
	}
	if err := verifyJudgeBodyTimestampUnixNanoReady(ex); err != nil {
		return err
	}
	return nil
}

func verifyJudgeBodyTimestampUnixNanoReady(ex dbExecer) error {
	var missing int
	if err := ex.QueryRow(`SELECT COUNT(*) FROM judge_responses
		WHERE timestamp_unix_nano IS NULL`).Scan(&missing); err != nil {
		return fmt.Errorf("verify judge timestamp backfill: %w", err)
	}
	if missing != 0 {
		return fmt.Errorf("verify judge timestamp backfill: %d rows remain unnormalized", missing)
	}
	return nil
}

// ensureJudgeBodyTimestampUnixNano repairs NULLs left by a previous binary that
// reopened the additive schema and inserted without the new column. It runs on
// every current startup in one transaction, so readers and retention never see a
// partially repaired timestamp index.
func ensureJudgeBodyTimestampUnixNano(db *sql.DB, indexName string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin judge timestamp readiness repair: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := migrateJudgeBodyTimestampUnixNano(tx, indexName); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit judge timestamp readiness repair: %w", err)
	}
	return nil
}

func assignJudgeResponseTimestamp(row *JudgeResponse, encoded string, storedUnixNano int64, scope string) error {
	parsed, err := parseJudgeBodyTimestamp(encoded)
	if err != nil {
		return fmt.Errorf("%s: parse timestamp for row %q: %w", scope, row.ID, err)
	}
	parsedUnixNano, err := judgeBodyUnixNano(parsed)
	if err != nil {
		return fmt.Errorf("%s: normalize timestamp for row %q: %w", scope, row.ID, err)
	}
	if parsedUnixNano != storedUnixNano {
		return fmt.Errorf("%s: timestamp index mismatch for row %q", scope, row.ID)
	}
	row.Timestamp = parsed
	return nil
}

func judgeBodyUnixNano(timestamp time.Time) (int64, error) {
	unixNano := timestamp.UnixNano()
	if !time.Unix(0, unixNano).Equal(timestamp) {
		return 0, errors.New("timestamp is outside the signed Unix-nanosecond range")
	}
	return unixNano, nil
}

func parseJudgeBodyTimestamp(encoded string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999Z07:00",
	} {
		if parsed, err := time.Parse(layout, encoded); err == nil {
			return parsed, nil
		}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.ParseInLocation(layout, encoded, time.UTC); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("unsupported timestamp encoding")
}
