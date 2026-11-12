// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/defenseclaw/defenseclaw/internal/fleet/sqliteperms"
)

// SpendCounter is where budget spend outside this gateway process comes
// from and where this process's spend goes. One interface for every
// counter: the device-local store (LocalCounter, always on while budgets
// exist), a fleet-wide store, and a leader-backed store shared by gateway
// replicas. A counter keys spend by charge key and UTC day; an epoch names
// one writer (a gateway process), so a writer never counts its own live
// spend twice.
type SpendCounter interface {
	// Push records this epoch's spend as absolute per-(key, day) totals
	// (idempotent: a retry or a re-send of the same totals changes nothing).
	Push(ctx context.Context, epoch string, rows []SeedRow) error
	// Totals returns the spend of every other epoch per (key, day) since the
	// given UTC day.
	Totals(ctx context.Context, epoch string, since time.Time) ([]SeedRow, error)
}

// LocalCounterFile is the budget spend file in data_dir.
const LocalCounterFile = "routing_budgets.db"

// LocalCounter keeps budget spend in a small SQLite file of its own (not the
// usage or audit database), so budgets survive a restart and the next
// process reads earlier processes' spend.
type LocalCounter struct {
	path string
	mu   sync.Mutex
	db   *sql.DB
}

// NewLocalCounter returns the counter of dataDir; nothing is created until
// the first Push or Totals.
func NewLocalCounter(dataDir string) *LocalCounter {
	return &LocalCounter{path: filepath.Join(dataDir, "routing", LocalCounterFile)}
}

func (c *LocalCounter) open() (*sql.DB, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db != nil {
		return c.db, nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return nil, fmt.Errorf("budget spend directory: %w", err)
	}
	if err := sqliteperms.Prepare(c.path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", c.path)
	if err != nil {
		return nil, fmt.Errorf("open budget spend: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=2000",
		`CREATE TABLE IF NOT EXISTS budget_spend (
			day TEXT NOT NULL, charge_key TEXT NOT NULL, epoch TEXT NOT NULL, usd REAL NOT NULL,
			PRIMARY KEY (day, charge_key, epoch)
		) WITHOUT ROWID`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("budget spend: %w", err)
		}
	}
	c.db = db
	return db, nil
}

// Push writes this epoch's totals and drops rows older than LedgerDays.
func (c *LocalCounter) Push(ctx context.Context, epoch string, rows []SeedRow) error {
	if c == nil || epoch == "" {
		return errors.New("budget spend: no epoch")
	}
	db, err := c.open()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, row := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO budget_spend (day, charge_key, epoch, usd) VALUES (?, ?, ?, ?)
			ON CONFLICT (day, charge_key, epoch) DO UPDATE SET usd = excluded.usd`, row.Day, row.Key, epoch, row.USD); err != nil {
			return err
		}
	}
	oldest := time.Now().UTC().AddDate(0, 0, -LedgerDays).Format(time.DateOnly)
	if _, err := tx.ExecContext(ctx, `DELETE FROM budget_spend WHERE day < ?`, oldest); err != nil {
		return err
	}
	return tx.Commit()
}

// Totals sums every other epoch's spend per (key, day) since since.
func (c *LocalCounter) Totals(ctx context.Context, epoch string, since time.Time) ([]SeedRow, error) {
	if c == nil {
		return nil, errors.New("budget spend: no counter")
	}
	db, err := c.open()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT day, charge_key, SUM(usd) FROM budget_spend
		WHERE epoch != ? AND day >= ? GROUP BY day, charge_key`, epoch, since.UTC().Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeedRow
	for rows.Next() {
		var r SeedRow
		if err := rows.Scan(&r.Day, &r.Key, &r.USD); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Close releases the file.
func (c *LocalCounter) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.db == nil {
		return nil
	}
	err := c.db.Close()
	c.db = nil
	return err
}
