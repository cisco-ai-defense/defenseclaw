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
	"strings"
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
	// given UTC day, for keys (nil: every key the counter holds; a fleet
	// counter needs the list, a device or replica store may ignore it).
	Totals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
}

// FleetKeys maps this device's charge keys to a fleet counter's form and
// back. Keys of a per-user budget name a person by a uid or SID here and
// by the account join key in the fleet, so no name leaves the device; a
// user without a join key is counted on this device only.
type FleetKeys interface {
	// ToFleet returns the fleet form of a local key (false: none).
	ToFleet(local string) (string, bool)
	// FromFleet returns the local form of a fleet key (false: none).
	FromFleet(fleet string) (string, bool)
	// Wanted lists fleet keys this device needs beyond its own spend
	// (named and group budgets, users who ran agents here).
	Wanted() []string
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

// Totals sums every other epoch's spend per (key, day) since since (all
// keys: the device holds only its own).
func (c *LocalCounter) Totals(ctx context.Context, epoch string, since time.Time, _ []string) ([]SeedRow, error) {
	return c.TotalsPage(ctx, epoch, since, TotalsQuery{})
}

// TotalsQuery selects part of Totals, in (day, key) order (the cluster
// leader answers a replica's read page by page with it).
type TotalsQuery struct {
	// AfterDay and AfterKey start after that (day, key) row; Limit bounds
	// the rows (0: all).
	AfterDay, AfterKey string
	Limit              int
	// ByKey keeps, of the capped keys (actor:, batch:), only those in Keys;
	// KeysOnly keeps only the keys in Keys.
	ByKey, KeysOnly bool
	Keys            []string
	// Over (with ByKey, not KeysOnly) also keeps, per query, the capped keys
	// at or over a budget's limit in its window, so a replica that let a
	// blocked key go (evicted and stored) still reads it as blocked until
	// the next read (GAP-0892). Their rows are only those of the budget's
	// own window (OverQuery.Since), not every day of the read (GAP-0942).
	Over []OverQuery
}

// OverQuery asks for the keys of one budget (Prefix, "<scope>:<id>:") whose
// spend since Since (the first day of the budget's period) is at or over
// Limit: at most Max of them (OverFull reports a budget with more).
type OverQuery struct {
	Prefix string
	Since  time.Time
	Limit  float64
	Max    int
}

// overSQL lists the keys of one OverQuery (args: overArgs).
const overSQL = `SELECT charge_key FROM budget_spend WHERE epoch != ? AND day >= ? AND substr(charge_key, 1, ?) = ?
	GROUP BY charge_key HAVING SUM(usd) >= ? ORDER BY charge_key LIMIT ?`

func overArgs(epoch string, o OverQuery, limit int) []any {
	return []any{epoch, o.Since.UTC().Format(time.DateOnly), len(o.Prefix), o.Prefix, o.Limit, limit}
}

// SumQuery asks for the spend of one budget's keys (Prefix,
// "<scope>:<id>:") since Since, the first day of its period; Limit counts
// the keys at or over it.
type SumQuery struct {
	Prefix string
	Since  time.Time
	Limit  float64
}

// PrefixSum is the stored spend of one budget's keys, every epoch (each
// replica pushes before it reads): Total over all keys, Peak the highest
// key, Subjects the keys, Exceeded the keys at or over the limit (the admin
// view of a cluster, GAP-0894).
type PrefixSum struct {
	Prefix             string
	Total, Peak        float64
	Subjects, Exceeded int
}

// PrefixSums sums each query's keys in SQL over every epoch: one row per
// budget, never a row per key.
func (c *LocalCounter) PrefixSums(ctx context.Context, q []SumQuery) ([]PrefixSum, error) {
	if c == nil {
		return nil, errors.New("budget spend: no counter")
	}
	db, err := c.open()
	if err != nil {
		return nil, err
	}
	out := make([]PrefixSum, 0, len(q))
	for _, s := range q {
		var total, peak sql.NullFloat64
		var subjects, exceeded sql.NullInt64
		err := db.QueryRowContext(ctx, `SELECT COUNT(*), SUM(s), MAX(s), SUM(s >= ?) FROM (
			SELECT SUM(usd) AS s FROM budget_spend WHERE day >= ? AND substr(charge_key, 1, ?) = ?
			GROUP BY charge_key HAVING SUM(usd) > 0)`,
			s.Limit, s.Since.UTC().Format(time.DateOnly), len(s.Prefix), s.Prefix).Scan(&subjects, &total, &peak, &exceeded)
		if err != nil {
			return nil, err
		}
		out = append(out, PrefixSum{Prefix: s.Prefix, Total: total.Float64, Peak: peak.Float64,
			Subjects: int(subjects.Int64), Exceeded: int(exceeded.Int64)})
	}
	return out, nil
}

// OverFull lists the budget ids of over with more than Max over-limit keys:
// the read could not name them all, so a managed deny budget refuses a key
// this process does not hold (Ledger.SetOverFull).
func (c *LocalCounter) OverFull(ctx context.Context, epoch string, over []OverQuery) ([]string, error) {
	if c == nil {
		return nil, errors.New("budget spend: no counter")
	}
	db, err := c.open()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, o := range over {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+overSQL+`)`, overArgs(epoch, o, o.Max+1)...).Scan(&n); err != nil {
			return nil, err
		}
		if n > o.Max {
			ids = append(ids, budgetIDOfKey(o.Prefix))
		}
	}
	return ids, nil
}

// TotalsPage is Totals restricted by q, sorted by (day, key) in SQL.
func (c *LocalCounter) TotalsPage(ctx context.Context, epoch string, since time.Time, q TotalsQuery) ([]SeedRow, error) {
	if c == nil {
		return nil, errors.New("budget spend: no counter")
	}
	db, err := c.open()
	if err != nil {
		return nil, err
	}
	query := `SELECT day, charge_key, SUM(usd) FROM budget_spend WHERE epoch != ? AND day >= ?`
	args := []any{epoch, since.UTC().Format(time.DateOnly)}
	if q.AfterDay != "" {
		query += ` AND (day > ? OR (day = ? AND charge_key > ?))`
		args = append(args, q.AfterDay, q.AfterDay, q.AfterKey)
	}
	if q.ByKey || q.KeysOnly {
		in := "0"
		if len(q.Keys) > 0 {
			in = "charge_key IN (?" + strings.Repeat(",?", len(q.Keys)-1) + ")"
			for _, k := range q.Keys {
				args = append(args, k)
			}
		}
		if q.KeysOnly {
			query += " AND " + in
		} else {
			for _, o := range q.Over {
				in += " OR (day >= ? AND charge_key IN (" + overSQL + "))"
				args = append(args, o.Since.UTC().Format(time.DateOnly))
				args = append(args, overArgs(epoch, o, o.Max)...)
			}
			query += ` AND ((substr(charge_key, 1, 6) != 'actor:' AND substr(charge_key, 1, 6) != 'batch:') OR ` + in + `)`
		}
	}
	query += ` GROUP BY day, charge_key ORDER BY day, charge_key`
	if q.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, q.Limit)
	}
	rows, err := db.QueryContext(ctx, query, args...)
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
