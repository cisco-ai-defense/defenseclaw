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
	"log"
	"net"
	"net/http"
	"net/netip"
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

// errWriters is a push from a new writer while the store holds MaxWriters.
var errWriters = errors.New("too_many_writers")

// MaxWriters caps the writers (gateway processes) the store keeps.
const MaxWriters = 100000

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
		var writers int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM writers`).Scan(&writers); err != nil {
			return err
		}
		if writers >= MaxWriters {
			return errWriters
		}
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
			if len(out) > MaxRows {
				rows.Close()
				return nil, errors.New("too_many_rows")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// WriterIdle is how long a writer's sequence is kept after its last push.
// A request older than MaxClockSkew is refused anyway, so a pruned writer's
// pushes cannot be replayed; live writers push every sync interval.
const WriterIdle = 15 * time.Minute

// Prune drops days older than RetentionDays and idle writers (their spend
// rows stay).
func (s *Store) Prune(ctx context.Context) error {
	cutoff := s.now().UTC().AddDate(0, 0, -RetentionDays)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM spend WHERE day < ?`, cutoff.Format(time.DateOnly)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM writers WHERE last_seen < ?`, s.now().Add(-WriterIdle).Unix())
	return err
}

// Handler serves the protocol over keys.
type Handler struct {
	Store *Store
	Keys  Keys
	Now   func() time.Time
	// PreAuth admits a request from a remote address before its signature
	// is checked (a high flood guard; nil admits all). Writer admits an
	// authenticated request of one writer (epoch); nil admits all.
	PreAuth func(remote string) bool
	Writer  func(epoch string) bool
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
	if h.PreAuth != nil {
		if !h.PreAuth(clientKey(r.RemoteAddr)) {
			writeJSON(w, http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
			return
		}
	}
	if r.URL.Path == PathHealth && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != PathPush && r.URL.Path != PathTotals) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{Error: "too_large"})
		return
	}
	sig := r.Header.Get(HeaderSignature)
	if err := h.Keys.Verify(r.Method, r.URL.Path, r.Header.Get(HeaderTime), sig, body, h.now()); err != nil {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	signed := func(status int, v any) { h.writeSigned(w, sig, status, v) }
	switch r.URL.Path {
	case PathPush:
		var req PushRequest
		if err := json.Unmarshal(body, &req); err != nil || req.validate(h.now()) != nil {
			signed(http.StatusBadRequest, ErrorResponse{Error: "bad_request"})
			return
		}
		if h.Writer != nil && !h.Writer(req.Epoch) {
			signed(http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
			return
		}
		switch err := h.Store.Push(r.Context(), req); {
		case errors.Is(err, errReplay):
			signed(http.StatusConflict, ErrorResponse{Error: "replayed"})
		case errors.Is(err, errWriters):
			signed(http.StatusServiceUnavailable, ErrorResponse{Error: "too_many_writers"})
		case err != nil:
			signed(http.StatusServiceUnavailable, ErrorResponse{Error: "store_unavailable"})
		default:
			signed(http.StatusOK, map[string]string{"status": "ok"})
		}
	case PathTotals:
		var req TotalsRequest
		if err := json.Unmarshal(body, &req); err != nil || req.validate() != nil {
			signed(http.StatusBadRequest, ErrorResponse{Error: "bad_request"})
			return
		}
		if h.Writer != nil && !h.Writer(req.Epoch) {
			signed(http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
			return
		}
		rows, err := h.Store.Totals(r.Context(), req)
		if err != nil {
			signed(http.StatusServiceUnavailable, ErrorResponse{Error: "store_unavailable"})
			return
		}
		signed(http.StatusOK, TotalsResponse{Rows: rows})
	}
}

// writeSigned writes an authenticated answer with its response signature.
func (h *Handler) writeSigned(w http.ResponseWriter, requestSig string, status int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set(HeaderResponse, h.Keys.SignResponse(requestSig, status, body))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// RateLimiter admits at most perMinute requests per key (a remote host or
// a writer) in each wall-clock minute. Old minutes are dropped one by one,
// so a burst of new keys cannot reset everyone's count.
func RateLimiter(perMinute int) func(string) bool {
	var mu sync.Mutex
	window := map[string][2]int64{} // key -> {minute, count}
	return func(host string) bool {
		minute := time.Now().Unix() / 60
		mu.Lock()
		defer mu.Unlock()
		w, known := window[host]
		if !known && len(window) >= 50000 {
			for k, old := range window {
				if old[0] != minute {
					delete(window, k)
				}
			}
			if len(window) >= 50000 {
				// Full of keys of this minute: admit uncounted rather than
				// refuse everyone (the limiter is a guard, auth is the gate).
				return true
			}
		}
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

// NewServer returns the HTTPS server of h on addr. Its error log is
// discarded: TLS handshake errors would write client addresses.
func NewServer(addr string, h http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

// clientKey is the rate-limit key of a remote address: the IPv4 address, or
// the /64 of an IPv6 one (a host holds a whole /64).
func clientKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Is4() || addr.Is4In6() {
		return host
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return host
	}
	return prefix.String()
}
