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
	"math"
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

// Device states.
const (
	DeviceActive  = "active"
	DeviceRevoked = "revoked"
)

// DefaultDeviceDailyCapUSD is the spend one device may add per UTC day.
const DefaultDeviceDailyCapUSD = 500

// Budget is a budget limit the store knows (from routing.admin.budgets of its
// config), used to answer pooled keys with exceeded or not.
type Budget struct {
	LimitUSD float64
	Period   string // day, week or month
}

// DeviceRecord is the store's side of one device credential.
type DeviceRecord struct {
	ID               string   `json:"device"`
	Secret           []byte   `json:"secret"`
	Keys             []string `json:"keys"`
	ConnectorBudgets []string `json:"connector_budgets,omitempty"`
	CapUSD           float64  `json:"cap_usd,omitempty"`
}

type device struct {
	key       DeviceKey
	status    string
	keys      map[string]bool
	connector map[string]bool
	capUSD    float64
}

// allows reports whether the device may use key.
func (d *device) allows(key string) bool {
	if d.keys[key] {
		return true
	}
	if rest, ok := strings.CutPrefix(key, "connector:"); ok {
		id, name, _ := strings.Cut(rest, ":")
		return d.connector[id] && name != "" && !strings.Contains(name, ":")
	}
	return false
}

// Store is the server side: devices, absolute per-(day, key, device, epoch)
// spend and the last push sequence of each writer.
type Store struct {
	db         *sql.DB
	now        func() time.Time
	mu         sync.Mutex // serialises pushes so seq, cap and upserts agree
	budgets    map[string]Budget
	defaultCap float64 // guarded by devMu

	devMu     sync.Mutex
	devices   map[string]*device
	devLoaded time.Time
}

// DeviceCacheTTL bounds how long a revoked device keeps working.
const DeviceCacheTTL = 10 * time.Second

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
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY, secret BLOB NOT NULL, status TEXT NOT NULL, keys TEXT NOT NULL,
			connector_budgets TEXT NOT NULL, cap_usd REAL NOT NULL, created INTEGER NOT NULL,
			over_cap_day TEXT NOT NULL DEFAULT ''
		) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS spend (
			day TEXT NOT NULL, charge_key TEXT NOT NULL, device TEXT NOT NULL, epoch TEXT NOT NULL, usd REAL NOT NULL,
			PRIMARY KEY (day, charge_key, device, epoch)
		) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS spend_key_day ON spend (charge_key, day)`,
		`CREATE INDEX IF NOT EXISTS spend_device_day ON spend (device, day)`,
		`CREATE TABLE IF NOT EXISTS writers (
			device TEXT NOT NULL, epoch TEXT NOT NULL, last_seq INTEGER NOT NULL, last_seen INTEGER NOT NULL,
			PRIMARY KEY (device, epoch)
		) WITHOUT ROWID`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("budget store: %w", err)
		}
	}
	_ = sqliteperms.Prepare(path) // the WAL and SHM files exist now
	return &Store{db: db, now: time.Now, budgets: map[string]Budget{}, defaultCap: DefaultDeviceDailyCapUSD}, nil
}

// Close closes the file.
func (s *Store) Close() error { return s.db.Close() }

// SetBudgets installs the budget limits pooled answers use.
func (s *Store) SetBudgets(b map[string]Budget) {
	s.mu.Lock()
	s.budgets = b
	s.mu.Unlock()
}

// SetDefaultCap sets the daily cap of devices issued without their own
// (server.device_daily_cap_usd); 0 keeps DefaultDeviceDailyCapUSD.
func (s *Store) SetDefaultCap(usd float64) {
	if usd <= 0 {
		usd = DefaultDeviceDailyCapUSD
	}
	s.devMu.Lock()
	s.defaultCap, s.devices = usd, nil
	s.devMu.Unlock()
}

// AddDevice registers (or replaces) a device record as active.
func (s *Store) AddDevice(ctx context.Context, rec DeviceRecord) error {
	if _, err := NewDeviceKey(rec.ID, rec.Secret); err != nil {
		return err
	}
	for _, k := range rec.Keys {
		if !ValidKey(k) {
			return errors.New("device record has a malformed key")
		}
	}
	capUSD := max(rec.CapUSD, 0) // 0: the store's default cap
	keys, _ := json.Marshal(rec.Keys)
	connectors, _ := json.Marshal(rec.ConnectorBudgets)
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (id, secret, status, keys, connector_budgets, cap_usd, created) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET secret = excluded.secret, status = excluded.status, keys = excluded.keys,
		connector_budgets = excluded.connector_budgets, cap_usd = excluded.cap_usd`,
		rec.ID, rec.Secret, DeviceActive, string(keys), string(connectors), capUSD, s.now().Unix())
	s.forgetDevices()
	return err
}

// RevokeDevice refuses every later request of the device (within
// DeviceCacheTTL); its spend stays.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET status = ? WHERE id = ?`, DeviceRevoked, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such device")
	}
	s.forgetDevices()
	return nil
}

// DeviceInfo is one row of the device list.
type DeviceInfo struct {
	ID, Status, OverCapDay string
	Keys                   int
	CapUSD                 float64
	Created                time.Time
}

// Devices lists the devices (store host only).
func (s *Store) Devices(ctx context.Context) ([]DeviceInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, keys, cap_usd, created, over_cap_day FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceInfo
	for rows.Next() {
		var d DeviceInfo
		var keys string
		var created int64
		if err := rows.Scan(&d.ID, &d.Status, &keys, &d.CapUSD, &created, &d.OverCapDay); err != nil {
			return nil, err
		}
		var list []string
		_ = json.Unmarshal([]byte(keys), &list)
		d.Keys, d.Created = len(list), time.Unix(created, 0).UTC()
		if d.CapUSD <= 0 {
			s.devMu.Lock()
			d.CapUSD = s.defaultCap
			s.devMu.Unlock()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) forgetDevices() {
	s.devMu.Lock()
	s.devices = nil
	s.devMu.Unlock()
}

// device returns the active device id, nil when unknown or revoked.
func (s *Store) device(ctx context.Context, id string) *device {
	s.devMu.Lock()
	defer s.devMu.Unlock()
	if s.devices == nil || s.now().Sub(s.devLoaded) > DeviceCacheTTL {
		devices := map[string]*device{}
		rows, err := s.db.QueryContext(ctx, `SELECT id, secret, status, keys, connector_budgets, cap_usd FROM devices`)
		if err != nil {
			return nil
		}
		for rows.Next() {
			var id, status, keys, connectors string
			var secret []byte
			var capUSD float64
			if rows.Scan(&id, &secret, &status, &keys, &connectors, &capUSD) != nil {
				continue
			}
			if capUSD <= 0 {
				capUSD = s.defaultCap
			}
			key, err := NewDeviceKey(id, secret)
			if err != nil {
				continue
			}
			d := &device{key: key, status: status, keys: map[string]bool{}, connector: map[string]bool{}, capUSD: capUSD}
			var list []string
			_ = json.Unmarshal([]byte(keys), &list)
			for _, k := range list {
				d.keys[k] = true
			}
			list = nil
			_ = json.Unmarshal([]byte(connectors), &list)
			for _, c := range list {
				d.connector[c] = true
			}
			devices[id] = d
		}
		rows.Close()
		s.devices, s.devLoaded = devices, s.now()
	}
	d := s.devices[id]
	if d == nil || d.status != DeviceActive {
		return nil
	}
	return d
}

var (
	errReplay     = errors.New("replayed")
	errNotAllowed = errors.New("key_not_allowed")
)

// Push stores one writer's absolute totals for keys the device may use,
// clamped to the device's daily cap.
func (s *Store) Push(ctx context.Context, dev *device, req PushRequest) error {
	for _, row := range req.Rows {
		if !dev.allows(row.Key) {
			return errNotAllowed
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	id := dev.key.ID()
	var last uint64
	switch err := tx.QueryRowContext(ctx, `SELECT last_seq FROM writers WHERE device = ? AND epoch = ?`, id, req.Epoch).Scan(&last); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	case req.Seq <= last:
		return errReplay
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO writers (device, epoch, last_seq, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT (device, epoch) DO UPDATE SET last_seq = excluded.last_seq, last_seen = excluded.last_seen`, id, req.Epoch, req.Seq, s.now().Unix()); err != nil {
		return err
	}
	// The cap: one device's spend of a UTC day, over all its writers.
	byDay := map[string]float64{}
	for _, row := range req.Rows {
		byDay[row.Day] += row.USD
	}
	scale := map[string]float64{}
	overDay := ""
	for day, add := range byDay {
		var others float64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(usd), 0) FROM spend WHERE device = ? AND day = ? AND epoch != ?`, id, day, req.Epoch).Scan(&others); err != nil {
			return err
		}
		scale[day] = 1
		if others+add > dev.capUSD && add > 0 {
			scale[day] = math.Max(0, dev.capUSD-others) / add
			overDay = day
		}
	}
	for _, row := range req.Rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO spend (day, charge_key, device, epoch, usd) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (day, charge_key, device, epoch) DO UPDATE SET usd = excluded.usd`, row.Day, row.Key, id, req.Epoch, row.USD*scale[row.Day]); err != nil {
			return err
		}
	}
	if overDay != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET over_cap_day = ? WHERE id = ?`, overDay, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Totals answers a device: other writers' spend of its own user keys, and
// which of its pooled keys are over their limit now.
func (s *Store) Totals(ctx context.Context, dev *device, req TotalsRequest) (TotalsResponse, error) {
	var resp TotalsResponse
	var users []string
	for _, key := range req.Keys {
		if !dev.allows(key) {
			return resp, errNotAllowed
		}
		if pooled(key) {
			over, err := s.exceeded(ctx, key)
			if err != nil {
				return resp, err
			}
			if over {
				resp.Exceeded = append(resp.Exceeded, key)
			}
			continue
		}
		users = append(users, key)
	}
	for start := 0; start < len(users); start += 500 {
		end := min(start+500, len(users))
		args := []any{dev.key.ID(), req.Epoch, req.Since}
		for _, key := range users[start:end] {
			args = append(args, key)
		}
		rows, err := s.db.QueryContext(ctx, `SELECT day, charge_key, SUM(usd) FROM spend
			WHERE NOT (device = ? AND epoch = ?) AND day >= ? AND charge_key IN (?`+strings.Repeat(",?", end-start-1)+`)
			GROUP BY day, charge_key`, args...)
		if err != nil {
			return resp, err
		}
		for rows.Next() {
			var r Row
			if err := rows.Scan(&r.Day, &r.Key, &r.USD); err != nil {
				rows.Close()
				return resp, err
			}
			resp.Rows = append(resp.Rows, r)
			if len(resp.Rows) > MaxRows {
				rows.Close()
				return resp, errors.New("too_many_rows")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// exceeded reports whether a pooled key's fleet spend in the current period
// reached the limit of its budget (false for a budget the store does not
// know).
func (s *Store) exceeded(ctx context.Context, key string) (bool, error) {
	s.mu.Lock()
	b, ok := s.budgets[budgetIDOf(key)]
	s.mu.Unlock()
	if !ok || b.LimitUSD <= 0 {
		return false, nil
	}
	var total float64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(usd), 0) FROM spend WHERE charge_key = ? AND day >= ?`,
		key, periodStart(b.Period, s.now())).Scan(&total)
	return total >= b.LimitUSD, err
}

// periodStart is the first UTC day of the period that contains now.
func periodStart(period string, now time.Time) string {
	t := now.UTC().Truncate(24 * time.Hour)
	switch period {
	case "week":
		t = t.AddDate(0, 0, -((int(t.Weekday()) + 6) % 7))
	case "month":
		t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return t.Format(time.DateOnly)
}

// ReportRow is one key's fleet total (store host only).
type ReportRow struct {
	Key     string
	USD     float64
	Devices int
}

// Report sums every key since a day: the admin rollup, read on the store
// host only (no network API).
func (s *Store) Report(ctx context.Context, since string) ([]ReportRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT charge_key, SUM(usd), COUNT(DISTINCT device) FROM spend WHERE day >= ? GROUP BY charge_key ORDER BY charge_key`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportRow
	for rows.Next() {
		var r ReportRow
		if err := rows.Scan(&r.Key, &r.USD, &r.Devices); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// WriterIdle is how long a writer's sequence is kept after its last push.
// A request older than MaxClockSkew is refused anyway, so a pruned writer's
// pushes cannot be replayed.
const WriterIdle = 15 * time.Minute

// Prune drops days older than RetentionDays and idle writers.
func (s *Store) Prune(ctx context.Context) error {
	cutoff := s.now().UTC().AddDate(0, 0, -RetentionDays)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM spend WHERE day < ?`, cutoff.Format(time.DateOnly)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM writers WHERE last_seen < ?`, s.now().Add(-WriterIdle).Unix())
	return err
}

// Handler serves the protocol.
type Handler struct {
	Store *Store
	Now   func() time.Time
	// PreAuth admits a request from a remote address before its signature
	// is checked (a high flood guard); PerDevice admits an authenticated
	// request of one device. Nil admits all.
	PreAuth   func(remote string) bool
	PerDevice func(device string) bool
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
	if h.PreAuth != nil && !h.PreAuth(clientKey(r.RemoteAddr)) {
		writeJSON(w, http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
		return
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
	id := r.Header.Get(HeaderDevice)
	var dev *device
	if ValidDevice(id) {
		dev = h.Store.device(r.Context(), id)
	}
	sig := r.Header.Get(HeaderSignature)
	if dev == nil || dev.key.Verify(r.Method, r.URL.Path, r.Header.Get(HeaderTime), sig, body, h.now()) != nil {
		// Unknown, revoked and badly signed requests look the same.
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: errUnauthorized.Error()})
		return
	}
	signed := func(status int, v any) { writeSigned(w, dev.key, sig, status, v) }
	if h.PerDevice != nil && !h.PerDevice(id) {
		signed(http.StatusTooManyRequests, ErrorResponse{Error: "rate_limited"})
		return
	}
	switch r.URL.Path {
	case PathPush:
		var req PushRequest
		if err := json.Unmarshal(body, &req); err != nil || req.validate(h.now()) != nil {
			signed(http.StatusBadRequest, ErrorResponse{Error: "bad_request"})
			return
		}
		switch err := h.Store.Push(r.Context(), dev, req); {
		case errors.Is(err, errNotAllowed):
			signed(http.StatusForbidden, ErrorResponse{Error: "key_not_allowed"})
		case errors.Is(err, errReplay):
			signed(http.StatusConflict, ErrorResponse{Error: "replayed"})
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
		resp, err := h.Store.Totals(r.Context(), dev, req)
		switch {
		case errors.Is(err, errNotAllowed):
			signed(http.StatusForbidden, ErrorResponse{Error: "key_not_allowed"})
		case err != nil:
			signed(http.StatusServiceUnavailable, ErrorResponse{Error: "store_unavailable"})
		default:
			signed(http.StatusOK, resp)
		}
	}
}

// writeSigned writes an authenticated answer with its response signature.
func writeSigned(w http.ResponseWriter, key DeviceKey, requestSig string, status int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set(HeaderResponse, key.SignResponse(requestSig, status, body))
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

// RateLimiter admits at most perMinute requests per key (a client address
// or a device) in each wall-clock minute. A known key is never refused for
// the table being full; old minutes are dropped one by one.
func RateLimiter(perMinute int) func(string) bool {
	var mu sync.Mutex
	window := map[string][2]int64{} // key -> {minute, count}
	return func(key string) bool {
		minute := time.Now().Unix() / 60
		mu.Lock()
		defer mu.Unlock()
		w, known := window[key]
		if !known && len(window) >= 50000 {
			for k, old := range window {
				if old[0] != minute {
					delete(window, k)
				}
			}
			if len(window) >= 50000 {
				return true // a guard, not the gate: authentication decides
			}
		}
		if w[0] != minute {
			w = [2]int64{minute, 0}
		}
		w[1]++
		window[key] = w
		return w[1] <= int64(perMinute)
	}
}

// clientKey is the rate-limit key of a remote address: the IPv4 address, or
// the /64 of an IPv6 one.
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

// ServerTLSConfigPEM is the TLS the store serves: TLS 1.2 or later, from PEM
// bytes already read (no plaintext listener exists).
func ServerTLSConfigPEM(certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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
