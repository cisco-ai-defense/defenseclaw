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
	budgetMu   sync.Mutex // guards budgets (never held with mu)
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
	s.budgetMu.Lock()
	s.budgets = b
	s.budgetMu.Unlock()
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

// ErrRevoked refuses to register a revoked device again without reactivate.
var ErrRevoked = errors.New("the device is revoked; issue a new credential, or pass --reactivate to trust this one again")

// AddDevice registers (or replaces) a device record as active. A revoked
// device stays revoked unless reactivate is set.
func (s *Store) AddDevice(ctx context.Context, rec DeviceRecord, reactivate bool) error {
	if _, err := NewDeviceKey(rec.ID, rec.Secret); err != nil {
		return err
	}
	if math.IsNaN(rec.CapUSD) || math.IsInf(rec.CapUSD, 0) || rec.CapUSD > maxUSD {
		return errors.New("device record has a bad cap_usd")
	}
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM devices WHERE id = ?`, rec.ID).Scan(&status); err == nil && status == DeviceRevoked && !reactivate {
		return ErrRevoked
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
// DeviceCacheTTL). Its spend stays unless dropFrom names a first UTC day
// (YYYY-MM-DD): the device's spend from that day on is deleted (forged spend
// of a compromised device). It returns the number of spend rows deleted.
func (s *Store) RevokeDevice(ctx context.Context, id, dropFrom string) (int64, error) {
	if dropFrom != "" && !validDay(dropFrom) {
		return 0, errors.New("the first day to drop must be YYYY-MM-DD")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE devices SET status = ? WHERE id = ?`, DeviceRevoked, id)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, errors.New("no such device")
	}
	var dropped int64
	if dropFrom != "" {
		res, err := tx.ExecContext(ctx, `DELETE FROM spend WHERE device = ? AND day >= ?`, id, dropFrom)
		if err != nil {
			return 0, err
		}
		dropped, _ = res.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.forgetDevices()
	return dropped, nil
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
	errTooMany    = errors.New("too_many")
)

// Per-device bounds, so one device cannot fill the store.
const (
	// MaxWritersPerDevice bounds the gateway processes of one device active
	// within WriterIdle.
	MaxWritersPerDevice = 16
	// MaxEpochsPerDay bounds the writers (gateway processes) of one device
	// that store spend on one UTC day (restarts and reloads stay far below).
	MaxEpochsPerDay = 64
	// MaxOpenKeysPerDay bounds the keys of one device and day beyond its
	// credential's own (connector names of * connector budgets).
	MaxOpenKeysPerDay = 64
)

// Push stores one writer's absolute totals for keys the device may use. A
// row never goes down (so a device cannot probe a pooled limit by lowering
// and raising its spend), only today's and yesterday's rows (UTC, store
// clock) may grow, and the growth is clamped so the device's spend of a day
// over all its writers stays within its daily cap.
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
		var writers int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM writers WHERE device = ?`, id).Scan(&writers); err != nil {
			return err
		}
		if writers >= MaxWritersPerDevice {
			return errTooMany
		}
	case err != nil:
		return err
	case req.Seq <= last:
		return errReplay
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO writers (device, epoch, last_seq, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT (device, epoch) DO UPDATE SET last_seq = excluded.last_seq, last_seen = excluded.last_seen`, id, req.Epoch, req.Seq, s.now().Unix()); err != nil {
		return err
	}
	now := s.now().UTC()
	today, yesterday := now.Format(time.DateOnly), now.AddDate(0, 0, -1).Format(time.DateOnly)
	// The device's open days: spend over all writers, its writers, and the
	// keys in use beyond the credential's own (SQL aggregates, no row scan).
	type dayState struct {
		total  float64
		epochs int
		keys   map[string]bool // keys in use that the credential does not list
		mine   bool            // this writer already stored on this day
	}
	days := map[string]*dayState{today: {keys: map[string]bool{}}, yesterday: {keys: map[string]bool{}}}
	for day, d := range days {
		var mine int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(usd), 0), COUNT(DISTINCT epoch), COUNT(CASE WHEN epoch = ? THEN 1 END)
			FROM spend WHERE device = ? AND day = ?`, req.Epoch, id, day).Scan(&d.total, &d.epochs, &mine); err != nil {
			return err
		}
		d.mine = mine > 0
	}
	mine := map[[2]string]float64{} // (day, key) -> this writer's stored value
	rows, err := tx.QueryContext(ctx, `SELECT day, charge_key, MAX(CASE WHEN epoch = ? THEN usd END) FROM spend
		WHERE device = ? AND day >= ? GROUP BY day, charge_key`, req.Epoch, id, yesterday)
	if err != nil {
		return err
	}
	for rows.Next() {
		var day, key string
		var usd sql.NullFloat64
		if err := rows.Scan(&day, &key, &usd); err != nil {
			rows.Close()
			return err
		}
		if usd.Valid {
			mine[[2]string{day, key}] = usd.Float64
		}
		if d := days[day]; d != nil && !dev.keys[key] {
			d.keys[key] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	type growth struct {
		day, key    string
		stored, add float64
	}
	var grow []growth
	added := map[string]float64{}
	for _, row := range req.Rows {
		d := days[row.Day]
		if d == nil {
			continue // a closed day never grows
		}
		stored := mine[[2]string{row.Day, row.Key}]
		if row.USD <= stored {
			continue // rows never go down; an equal row changes nothing
		}
		if !d.mine {
			if d.epochs >= MaxEpochsPerDay {
				return errTooMany
			}
			d.mine, d.epochs = true, d.epochs+1
		}
		if !dev.keys[row.Key] && !d.keys[row.Key] {
			if len(d.keys) >= MaxOpenKeysPerDay {
				return errTooMany
			}
			d.keys[row.Key] = true
		}
		grow = append(grow, growth{day: row.Day, key: row.Key, stored: stored, add: row.USD - stored})
		added[row.Day] += row.USD - stored
	}
	scale := map[string]float64{}
	overDay := ""
	for day, add := range added {
		scale[day] = 1
		if total := days[day].total; total+add > dev.capUSD {
			scale[day] = math.Max(0, dev.capUSD-total) / add
			overDay = max(overDay, day)
		}
	}
	for _, g := range grow {
		value := g.stored + g.add*scale[g.day]
		if !(value > g.stored) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO spend (day, charge_key, device, epoch, usd) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (day, charge_key, device, epoch) DO UPDATE SET usd = excluded.usd`, g.day, g.key, id, req.Epoch, value); err != nil {
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

// unknownBudgetsError names pooled budgets the store's config lacks: the
// device then counts on its own spend and says why.
type unknownBudgetsError struct{ ids []string }

func (e *unknownBudgetsError) Error() string { return "unknown_budget" }

// Totals answers a device: other writers' spend of its own user keys, and
// which of its pooled keys are over their limit now.
func (s *Store) Totals(ctx context.Context, dev *device, req TotalsRequest) (TotalsResponse, error) {
	var resp TotalsResponse
	var users, pooledKeys []string
	open := 0
	for _, key := range req.Keys {
		if !dev.allows(key) {
			return resp, errNotAllowed
		}
		if !dev.keys[key] {
			if open++; open > MaxOpenKeysPerDay {
				return resp, errTooMany
			}
		}
		if pooled(key) {
			pooledKeys = append(pooledKeys, key)
		} else {
			users = append(users, key)
		}
	}
	exceeded, err := s.exceeded(ctx, pooledKeys)
	if err != nil {
		return resp, err
	}
	resp.Exceeded = exceeded
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

// exceeded returns the pooled keys whose fleet spend in the current period
// reached the limit of their budget. A key of a budget the store's config
// does not know is an error naming the budget, never "not exceeded".
func (s *Store) exceeded(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	s.budgetMu.Lock()
	budgets := s.budgets
	s.budgetMu.Unlock()
	now := s.now()
	today := now.UTC().Format(time.DateOnly)
	byStart := map[string][]string{}
	limit := map[string]float64{}
	var unknown []string
	seen := map[string]bool{}
	for _, key := range keys {
		id := budgetIDOf(key)
		b, ok := budgets[id]
		if !ok {
			if !seen[id] {
				seen[id] = true
				unknown = append(unknown, id)
			}
			continue
		}
		if b.LimitUSD <= 0 {
			continue
		}
		start := periodStart(b.Period, now)
		byStart[start] = append(byStart[start], key)
		limit[key] = b.LimitUSD
	}
	if len(unknown) > 0 {
		return nil, &unknownBudgetsError{ids: unknown}
	}
	var out []string
	for start, list := range byStart {
		for i := 0; i < len(list); i += 500 {
			chunk := list[i:min(i+500, len(list))]
			args := []any{start, today}
			for _, k := range chunk {
				args = append(args, k)
			}
			rows, err := s.db.QueryContext(ctx, `SELECT charge_key, SUM(usd) FROM spend WHERE day >= ? AND day <= ? AND charge_key IN (?`+
				strings.Repeat(",?", len(chunk)-1)+`) GROUP BY charge_key`, args...)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var key string
				var total float64
				if err := rows.Scan(&key, &total); err != nil {
					rows.Close()
					return nil, err
				}
				if total >= limit[key] {
					out = append(out, key)
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
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

// ReportRow is one key's fleet total (store host only). Device is set in a
// per-device report.
type ReportRow struct {
	Key     string
	Device  string
	USD     float64
	Devices int
}

// Report sums every key since a day: the admin rollup, read on the store
// host only (no network API). byDevice splits each key per device.
func (s *Store) Report(ctx context.Context, since string, byDevice bool) ([]ReportRow, error) {
	query := `SELECT charge_key, '', SUM(usd), COUNT(DISTINCT device) FROM spend WHERE day >= ? GROUP BY charge_key ORDER BY charge_key`
	if byDevice {
		query = `SELECT charge_key, device, SUM(usd), 1 FROM spend WHERE day >= ? GROUP BY charge_key, device ORDER BY device, charge_key`
	}
	rows, err := s.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportRow
	for rows.Next() {
		var r ReportRow
		if err := rows.Scan(&r.Key, &r.Device, &r.USD, &r.Devices); err != nil {
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
	// The device and the request time are checked before the body is read.
	id := r.Header.Get(HeaderDevice)
	var dev *device
	if ValidDevice(id) && timely(r.Header.Get(HeaderTime), h.now()) {
		dev = h.Store.device(r.Context(), id)
	}
	if dev == nil {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: errUnauthorized.Error()})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{Error: "too_large"})
		return
	}
	sig := r.Header.Get(HeaderSignature)
	if dev.key.Verify(r.Method, r.URL.Path, r.Header.Get(HeaderTime), sig, body, h.now()) != nil {
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
		case errors.Is(err, errTooMany):
			signed(http.StatusTooManyRequests, ErrorResponse{Error: "too_many_keys_or_writers"})
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
		var unknown *unknownBudgetsError
		switch {
		case errors.Is(err, errNotAllowed):
			signed(http.StatusForbidden, ErrorResponse{Error: "key_not_allowed"})
		case errors.Is(err, errTooMany):
			signed(http.StatusTooManyRequests, ErrorResponse{Error: "too_many_keys_or_writers"})
		case errors.As(err, &unknown):
			signed(http.StatusConflict, ErrorResponse{Error: "unknown_budget", Budgets: unknown.ids})
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
