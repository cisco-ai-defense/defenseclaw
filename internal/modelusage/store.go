// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/defenseclaw/defenseclaw/internal/fleet/sqliteperms"
)

const (
	// storeBucketCap bounds the in-memory aggregate between flushes. A record
	// that would add a new bucket past the cap is dropped and counted.
	storeBucketCap = 20000
	// storeFlushInterval is how often the aggregate is written.
	storeFlushInterval = 15 * time.Second
	storeMaxDim        = 128
	storeBusyMillis    = 5000
)

// Store is the local hourly usage aggregate (model_usage.db). It lives next
// to, not in, the audit database. It exists only while
// observability.tokenomics.local_store.enabled is true: Configure(false)
// flushes and closes it and stops its goroutine.
//
// The aggregate never holds prompt text. Identity is the verified caller id
// with its kind; groups are kept only as an aggregate per group name for the
// admin API and are never exported.
type Store struct {
	path string

	mu       sync.Mutex
	db       *sql.DB
	pend     map[usageKey]*usageAgg
	pendGrp  map[groupKey]*usageAgg
	stop     chan struct{}
	done     chan struct{}
	retDays  int
	lastPrun time.Time
	overflow int64
	now      func() time.Time
	flushDur time.Duration
}

type usageKey struct {
	hour                                                 int64
	owner, connector, provider, model, route, role, prof string
	family, basis                                        string
}

type groupKey struct {
	hour                    int64
	group, connector, model string
}

type usageAgg struct {
	calls, errors, usageCalls                        int64
	input, output, cacheRead, cacheCreate, reasoning int64
	costSum                                          float64
	costCalls                                        int64
	latencyMs                                        float64
}

// NewStore returns a closed store for path. Nothing is created until
// Configure(true).
func NewStore(path string) *Store {
	return &Store{path: path, now: time.Now, flushDur: storeFlushInterval}
}

// Configure turns the store on or off and sets the retention window. It is
// safe to call on every config reload.
func (s *Store) Configure(enabled bool, retentionDays int) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.retDays = retentionDays
	if enabled {
		defer s.mu.Unlock()
		if s.db != nil {
			return nil
		}
		db, err := openUsageDB(s.path)
		if err != nil {
			return err
		}
		s.db = db
		s.pend = map[usageKey]*usageAgg{}
		s.pendGrp = map[groupKey]*usageAgg{}
		s.stop = make(chan struct{})
		s.done = make(chan struct{})
		go s.loop(s.stop, s.done)
		return nil
	}
	if s.db == nil {
		s.mu.Unlock()
		return nil
	}
	stop, done := s.stop, s.done
	s.mu.Unlock()
	close(stop)
	select {
	case <-done:
	case <-time.After(stopDeadline):
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		_ = s.flushLocked()
		_ = s.db.Close()
		s.db, s.pend, s.pendGrp = nil, nil, nil
	}
	return nil
}

// Enabled reports whether the store is open.
func (s *Store) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db != nil
}

// Overflow reports records dropped because the bucket cap was reached.
func (s *Store) Overflow() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflow
}

func openUsageDB(path string) (*sql.DB, error) {
	if err := sqliteperms.Prepare(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open model usage store: %w", err)
	}
	db.SetMaxOpenConns(2)
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		fmt.Sprintf("PRAGMA busy_timeout=%d", storeBusyMillis),
		"PRAGMA journal_size_limit=8388608",
		`CREATE TABLE IF NOT EXISTS model_usage (
			hour_start INTEGER NOT NULL, owner TEXT NOT NULL, connector TEXT NOT NULL, provider TEXT NOT NULL,
			model TEXT NOT NULL, route_decision TEXT NOT NULL, call_role TEXT NOT NULL, profile TEXT NOT NULL,
			api_family TEXT NOT NULL, cost_basis TEXT NOT NULL,
			calls INTEGER NOT NULL, errors INTEGER NOT NULL, usage_calls INTEGER NOT NULL,
			input INTEGER NOT NULL, output INTEGER NOT NULL, cache_read INTEGER NOT NULL,
			cache_creation INTEGER NOT NULL, reasoning INTEGER NOT NULL,
			cost_usd_sum REAL, cost_calls INTEGER NOT NULL, latency_ms_sum REAL NOT NULL,
			PRIMARY KEY (hour_start, owner, connector, provider, model, route_decision, call_role, profile, api_family, cost_basis)
		) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS model_usage_group (
			hour_start INTEGER NOT NULL, group_name TEXT NOT NULL, connector TEXT NOT NULL, model TEXT NOT NULL,
			calls INTEGER NOT NULL, usage_calls INTEGER NOT NULL, input INTEGER NOT NULL, output INTEGER NOT NULL,
			cost_usd_sum REAL, cost_calls INTEGER NOT NULL,
			PRIMARY KEY (hour_start, group_name, connector, model)
		) WITHOUT ROWID`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("model usage store: %w", err)
		}
	}
	return db, nil
}

func (s *Store) loop(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(s.flushDur)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.mu.Lock()
			_ = s.flushLocked()
			s.mu.Unlock()
		}
	}
}

func dim(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "none"
	}
	if len(v) > storeMaxDim {
		v = v[:storeMaxDim]
	}
	return v
}

// OwnerID is the stable owner key of a verified caller: kind and subject.
// An unverified call has the empty owner, which only an admin query reads.
func OwnerID(f CallFacts) string {
	if !f.IdentityVerified || strings.TrimSpace(f.Subject) == "" {
		return ""
	}
	kind := f.SubjectKind
	if kind == "" {
		kind = "id"
	}
	return dim(kind + ":" + f.Subject)
}

// Emit implements Sink: it adds the record to the pending aggregate.
func (s *Store) Emit(_ context.Context, rec Record) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	f, u, c := rec.Facts, rec.Usage, rec.Cost
	hour := rec.EndedAt.UTC().Truncate(time.Hour).Unix()
	k := usageKey{
		hour: hour, owner: OwnerID(f), connector: dim(f.Connector), provider: dim(f.SelectedProvider), model: dim(f.SelectedModel),
		route: dim(f.Route.Decision), role: dim(string(f.CallRole)), prof: dim(f.ProfileName), family: dim(string(f.APIFamily)), basis: dim(c.Basis),
	}
	a := s.pend[k]
	if a == nil {
		if len(s.pend)+len(s.pendGrp) >= storeBucketCap {
			s.overflow++
			return
		}
		a = &usageAgg{}
		s.pend[k] = a
	}
	addRecord(a, rec)
	if len(f.Groups) > 0 && f.IdentityVerified {
		seen := map[string]bool{}
		for _, g := range f.Groups {
			g = dim(g)
			if seen[g] {
				continue
			}
			seen[g] = true
			gk := groupKey{hour: hour, group: g, connector: dim(f.Connector), model: dim(f.SelectedModel)}
			ga := s.pendGrp[gk]
			if ga == nil {
				if len(s.pend)+len(s.pendGrp) >= storeBucketCap {
					s.overflow++
					continue
				}
				ga = &usageAgg{}
				s.pendGrp[gk] = ga
			}
			addRecord(ga, rec)
		}
	}
	_ = u
}

func addRecord(a *usageAgg, rec Record) {
	u, c := rec.Usage, rec.Cost
	a.calls++
	if rec.Outcome != "completed" {
		a.errors++
	}
	if u.Has != 0 {
		a.usageCalls++
	}
	if u.Has&HasInput != 0 {
		a.input += u.Input
	}
	if u.Has&HasOutput != 0 {
		a.output += u.Output
	}
	if u.Has&HasCacheRead != 0 {
		a.cacheRead += u.CacheRead
	}
	if u.Has&HasCacheCreation != 0 {
		a.cacheCreate += u.CacheCreation
	}
	if u.Has&HasReasoning != 0 {
		a.reasoning += u.Reasoning
	}
	if c.USD != nil {
		a.costSum += *c.USD
		a.costCalls++
	}
	a.latencyMs += float64(rec.Total) / float64(time.Millisecond)
}

// Flush writes the pending aggregate now.
func (s *Store) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() error {
	if s.db == nil || (len(s.pend) == 0 && len(s.pendGrp) == 0) {
		s.pruneLocked()
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	const upsert = `INSERT INTO model_usage (hour_start, owner, connector, provider, model, route_decision, call_role, profile, api_family, cost_basis,
		calls, errors, usage_calls, input, output, cache_read, cache_creation, reasoning, cost_usd_sum, cost_calls, latency_ms_sum)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(hour_start, owner, connector, provider, model, route_decision, call_role, profile, api_family, cost_basis) DO UPDATE SET
		calls=calls+excluded.calls, errors=errors+excluded.errors, usage_calls=usage_calls+excluded.usage_calls,
		input=input+excluded.input, output=output+excluded.output, cache_read=cache_read+excluded.cache_read,
		cache_creation=cache_creation+excluded.cache_creation, reasoning=reasoning+excluded.reasoning,
		cost_usd_sum=CASE WHEN excluded.cost_calls>0 THEN COALESCE(cost_usd_sum,0)+excluded.cost_usd_sum ELSE cost_usd_sum END,
		cost_calls=cost_calls+excluded.cost_calls, latency_ms_sum=latency_ms_sum+excluded.latency_ms_sum`
	for k, a := range s.pend {
		var cost any
		if a.costCalls > 0 {
			cost = a.costSum
		}
		if _, err = tx.Exec(upsert, k.hour, k.owner, k.connector, k.provider, k.model, k.route, k.role, k.prof, k.family, k.basis,
			a.calls, a.errors, a.usageCalls, a.input, a.output, a.cacheRead, a.cacheCreate, a.reasoning, cost, a.costCalls, a.latencyMs); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	const gupsert = `INSERT INTO model_usage_group (hour_start, group_name, connector, model, calls, usage_calls, input, output, cost_usd_sum, cost_calls)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(hour_start, group_name, connector, model) DO UPDATE SET
		calls=calls+excluded.calls, usage_calls=usage_calls+excluded.usage_calls, input=input+excluded.input, output=output+excluded.output,
		cost_usd_sum=CASE WHEN excluded.cost_calls>0 THEN COALESCE(cost_usd_sum,0)+excluded.cost_usd_sum ELSE cost_usd_sum END,
		cost_calls=cost_calls+excluded.cost_calls`
	for k, a := range s.pendGrp {
		var cost any
		if a.costCalls > 0 {
			cost = a.costSum
		}
		if _, err = tx.Exec(gupsert, k.hour, k.group, k.connector, k.model, a.calls, a.usageCalls, a.input, a.output, cost, a.costCalls); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.pend = map[usageKey]*usageAgg{}
	s.pendGrp = map[groupKey]*usageAgg{}
	s.pruneLocked()
	return nil
}

func (s *Store) pruneLocked() {
	now := s.now()
	if s.db == nil || now.Sub(s.lastPrun) < time.Hour {
		return
	}
	s.lastPrun = now
	days := s.retDays
	if days <= 0 {
		days = 30
	}
	cutoff := now.UTC().Add(-time.Duration(days) * 24 * time.Hour).Truncate(time.Hour).Unix()
	_, _ = s.db.Exec("DELETE FROM model_usage WHERE hour_start < ?", cutoff)
	_, _ = s.db.Exec("DELETE FROM model_usage_group WHERE hour_start < ?", cutoff)
}

// Query selects usage rolled up by one dimension.
type Query struct {
	By       string    // model | connector | route | profile | role | provider | user | group | hour
	From, To time.Time // To zero = now
	// Owner is the caller whose rows are returned when AllOwners is false. It
	// is applied in the SQL WHERE clause, never after the fetch.
	Owner     string
	AllOwners bool
	Limit     int
}

// Row is one rolled-up line. CostUSD is nil when no call in the bucket had a
// known cost; CostCalls says how many did.
type Row struct {
	Key           string   `json:"key"`
	Calls         int64    `json:"calls"`
	Errors        int64    `json:"errors,omitempty"`
	UsageCalls    int64    `json:"usage_calls"`
	Input         int64    `json:"input_tokens"`
	Output        int64    `json:"output_tokens"`
	CacheRead     int64    `json:"cache_read_tokens"`
	CacheCreation int64    `json:"cache_creation_tokens"`
	Reasoning     int64    `json:"reasoning_tokens"`
	CostUSD       *float64 `json:"cost_usd,omitempty"`
	CostCalls     int64    `json:"cost_calls"`
	LatencyMsSum  float64  `json:"latency_ms_sum"`
}

// ErrAdminOnly is returned for a rollup only an administrator may read.
var ErrAdminOnly = errors.New("this rollup is available to administrators only")

var byColumn = map[string]string{
	"model": "model", "connector": "connector", "route": "route_decision", "profile": "profile",
	"role": "call_role", "provider": "provider", "user": "owner", "hour": "hour_start",
}

// Run executes the query. A non-admin caller gets only their own rows; the
// per-group rollup and the unattributed owner are admin-only.
func (s *Store) Run(ctx context.Context, q Query) ([]Row, error) {
	if s == nil {
		return nil, errors.New("model usage store is off")
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	db := s.db
	s.mu.Unlock()
	if db == nil {
		return nil, errors.New("model usage store is off")
	}
	to := q.To
	if to.IsZero() {
		to = s.now()
	}
	from := q.From
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args := []any{from.UTC().Truncate(time.Hour).Unix(), to.UTC().Unix()}
	if q.By == "group" {
		if !q.AllOwners {
			return nil, ErrAdminOnly
		}
		rows, err := db.QueryContext(ctx, `SELECT group_name, SUM(calls), SUM(usage_calls), SUM(input), SUM(output), SUM(cost_usd_sum), SUM(cost_calls)
			FROM model_usage_group WHERE hour_start >= ? AND hour_start <= ? GROUP BY group_name ORDER BY SUM(COALESCE(cost_usd_sum,0)) DESC, SUM(calls) DESC LIMIT ?`, append(args, limit)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []Row
		for rows.Next() {
			var r Row
			var cost sql.NullFloat64
			if err := rows.Scan(&r.Key, &r.Calls, &r.UsageCalls, &r.Input, &r.Output, &cost, &r.CostCalls); err != nil {
				return nil, err
			}
			if cost.Valid {
				v := cost.Float64
				r.CostUSD = &v
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}
	col, ok := byColumn[q.By]
	if !ok {
		return nil, fmt.Errorf("unknown rollup %q", q.By)
	}
	where := "hour_start >= ? AND hour_start <= ?"
	if !q.AllOwners {
		if strings.TrimSpace(q.Owner) == "" {
			return nil, ErrAdminOnly // an unidentified caller has no own rows
		}
		where += " AND owner = ?"
		args = append(args, q.Owner)
	}
	if q.By == "user" && !q.AllOwners {
		col = "owner" // the caller own bucket only
	}
	query := fmt.Sprintf(`SELECT CAST(%s AS TEXT), SUM(calls), SUM(errors), SUM(usage_calls), SUM(input), SUM(output), SUM(cache_read), SUM(cache_creation),
		SUM(reasoning), SUM(cost_usd_sum), SUM(cost_calls), SUM(latency_ms_sum) FROM model_usage WHERE %s GROUP BY %s
		ORDER BY SUM(COALESCE(cost_usd_sum,0)) DESC, SUM(calls) DESC LIMIT ?`, col, where, col)
	rows, err := db.QueryContext(ctx, query, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		var cost sql.NullFloat64
		if err := rows.Scan(&r.Key, &r.Calls, &r.Errors, &r.UsageCalls, &r.Input, &r.Output, &r.CacheRead, &r.CacheCreation, &r.Reasoning, &cost, &r.CostCalls, &r.LatencyMsSum); err != nil {
			return nil, err
		}
		if cost.Valid {
			v := cost.Float64
			r.CostUSD = &v
		}
		out = append(out, r)
	}
	if q.By == "hour" {
		sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	}
	return out, rows.Err()
}
