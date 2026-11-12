// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package budgetstore

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/defenseclaw/defenseclaw/internal/fleet/sqliteperms"
)

// Store is the server side: a SQLite file of absolute per-(day, key,
// epoch) totals and the last push sequence of each epoch.
type Store struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex // serialises pushes so seq checks and upserts agree
}

// OpenStore opens (or creates) the store file with owner-only permissions.
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("budget store directory: %w", err)
	}
	if err := sqliteperms.Prepare(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open budget store: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS spend (
			day TEXT NOT NULL, charge_key TEXT NOT NULL, epoch TEXT NOT NULL, usd REAL NOT NULL,
			PRIMARY KEY (day, charge_key, epoch)
		) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS spend_key_day ON spend (charge_key, day)`,
		`CREATE TABLE IF NOT EXISTS writers (
			epoch TEXT PRIMARY KEY, last_seq INTEGER NOT NULL, last_seen INTEGER NOT NULL
		) WITHOUT ROWID`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("budget store: %w", err)
		}
	}
	return &Store{db: db, now: time.Now}, nil
}

// Close closes the file.
func (s *Store) Close() error { return s.db.Close() }

// errReplay is a push whose sequence is not above the epoch's last one.
var errReplay = errors.New("replayed")

// Push stores one epoch's absolute totals.
func (s *Store) Push(ctx context.Context, req PushRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var last uint64
	switch err := tx.QueryRowContext(ctx, `SELECT last_seq FROM writers WHERE epoch = ?`, req.Epoch).Scan(&last); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	case req.Seq <= last:
		return errReplay
	}
	now := s.now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO writers (epoch, last_seq, last_seen) VALUES (?, ?, ?)
		ON CONFLICT (epoch) DO UPDATE SET last_seq = excluded.last_seq, last_seen = excluded.last_seen`, req.Epoch, req.Seq, now); err != nil {
		return err
	}
	for _, row := range req.Rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO spend (day, charge_key, epoch, usd) VALUES (?, ?, ?, ?)
			ON CONFLICT (day, charge_key, epoch) DO UPDATE SET usd = excluded.usd`, row.Day, row.Key, req.Epoch, row.USD); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Totals sums every other epoch's spend for keys since the given day.
func (s *Store) Totals(ctx context.Context, req TotalsRequest) ([]Row, error) {
	if len(req.Keys) == 0 {
		return nil, nil
	}
	var out []Row
	// Bounded IN lists keep each statement under SQLite's variable limit.
	for start := 0; start < len(req.Keys); start += 500 {
		end := min(start+500, len(req.Keys))
		args := []any{req.Epoch, req.Since}
		for _, key := range req.Keys[start:end] {
			args = append(args, key)
		}
		query := `SELECT day, charge_key, SUM(usd) FROM spend WHERE epoch != ? AND day >= ? AND charge_key IN (?` +
			strings.Repeat(",?", end-start-1) + `) GROUP BY day, charge_key`
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r Row
			if err := rows.Scan(&r.Day, &r.Key, &r.USD); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Prune drops days and writers older than RetentionDays.
func (s *Store) Prune(ctx context.Context) error {
	cutoff := s.now().UTC().AddDate(0, 0, -RetentionDays)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM spend WHERE day < ?`, cutoff.Format(time.DateOnly)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM writers WHERE last_seen < ?`, cutoff.Unix())
	return err
}

// Handler serves the protocol over keys.
type Handler struct {
	Store *Store
	Keys  Keys
	Now   func() time.Time
	// Limit admits a request from a remote address (nil admits all).
	Limit func(remote string) bool
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ServeHTTP authenticates and answers one request. Refusals carry a reason
// code only; nothing from the request is logged or echoed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == PathHealth && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != PathPush && r.URL.Path != PathTotals) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	if h.Limit != nil {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !h.Limit(host) {
			writeJSON(w, http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{Error: "too_large"})
		return
	}
	if err := h.Keys.Verify(r.Method, r.URL.Path, r.Header.Get(HeaderTime), r.Header.Get(HeaderSignature), body, h.now()); err != nil {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	switch r.URL.Path {
	case PathPush:
		var req PushRequest
		if err := json.Unmarshal(body, &req); err != nil || req.validate() != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request"})
			return
		}
		switch err := h.Store.Push(r.Context(), req); {
		case errors.Is(err, errReplay):
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "replayed"})
		case err != nil:
			writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "store_unavailable"})
		default:
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}
	case PathTotals:
		var req TotalsRequest
		if err := json.Unmarshal(body, &req); err != nil || req.validate() != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request"})
			return
		}
		rows, err := h.Store.Totals(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "store_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, TotalsResponse{Rows: rows})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// RateLimiter admits at most perMinute requests per remote host.
func RateLimiter(perMinute int) func(string) bool {
	var mu sync.Mutex
	window := map[string][2]int64{} // host -> {minute, count}
	return func(host string) bool {
		minute := time.Now().Unix() / 60
		mu.Lock()
		defer mu.Unlock()
		if len(window) > 10000 {
			window = map[string][2]int64{}
		}
		w := window[host]
		if w[0] != minute {
			w = [2]int64{minute, 0}
		}
		w[1]++
		window[host] = w
		return w[1] <= int64(perMinute)
	}
}

// ServerTLSConfig is the TLS the store serves: TLS 1.2 or later, and the
// certificate and key from files (no plaintext listener exists).
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("budget store TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}

// NewServer returns the HTTPS server of h on addr.
func NewServer(addr string, h http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
	}
}
