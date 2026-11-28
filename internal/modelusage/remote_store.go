// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"errors"
	"math"
	"time"
)

// remoteSchema is the leader's table of what gateway replicas report: one
// row per (epoch, bucket), the replica's absolute totals, replaced on every
// push. A read sums the epochs, so a re-sent push and a restarted replica
// (a new epoch) never count a call twice. model_usage_all is what a read
// queries: the local aggregate (no actor, batch or atespace) and the
// replicas' rows. The local table is unchanged, so a laptop store is not
// migrated.
var remoteSchema = []string{
	`CREATE TABLE IF NOT EXISTS model_usage_remote (
		epoch TEXT NOT NULL,
		hour_start INTEGER NOT NULL, owner TEXT NOT NULL, actor TEXT NOT NULL, batch TEXT NOT NULL, atespace TEXT NOT NULL,
		connector TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, route_decision TEXT NOT NULL,
		call_role TEXT NOT NULL, profile TEXT NOT NULL, api_family TEXT NOT NULL, cost_basis TEXT NOT NULL,
		calls INTEGER NOT NULL, errors INTEGER NOT NULL, usage_calls INTEGER NOT NULL,
		input INTEGER NOT NULL, output INTEGER NOT NULL, cache_read INTEGER NOT NULL,
		cache_creation INTEGER NOT NULL, reasoning INTEGER NOT NULL,
		cost_usd_sum REAL, cost_calls INTEGER NOT NULL, latency_ms_sum REAL NOT NULL,
		PRIMARY KEY (epoch, hour_start, owner, actor, batch, atespace, connector, provider, model, route_decision, call_role, profile, api_family, cost_basis)
	) WITHOUT ROWID`,
	`CREATE VIEW IF NOT EXISTS model_usage_all AS
		SELECT hour_start, owner, '' AS actor, '' AS batch, '' AS atespace, connector, provider, model, route_decision, call_role, profile,
			api_family, cost_basis, calls, errors, usage_calls, input, output, cache_read, cache_creation, reasoning,
			cost_usd_sum, cost_calls, latency_ms_sum FROM model_usage
		UNION ALL
		SELECT hour_start, owner, actor, batch, atespace, connector, provider, model, route_decision, call_role, profile,
			api_family, cost_basis, calls, errors, usage_calls, input, output, cache_read, cache_creation, reasoning,
			cost_usd_sum, cost_calls, latency_ms_sum FROM model_usage_remote`,
}

// RemoteBatchMax is the most rows ApplyRemote takes in one call.
const RemoteBatchMax = 5000

// ErrRemoteBatch is returned for a push that is too large or malformed.
var ErrRemoteBatch = errors.New("usage push is too large or malformed")

// ApplyRemote stores one replica's absolute bucket totals under its epoch,
// replacing what that epoch sent before. Past the row cap only buckets that
// already exist are updated. The store must be configured on.
func (s *Store) ApplyRemote(epoch string, rows []RemoteRow) error {
	if s == nil {
		return errors.New("model usage store is off")
	}
	if epoch == "" || len(epoch) > 64 || len(rows) > RemoteBatchMax {
		return ErrRemoteBatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("model usage store is off")
	}
	oldest := s.now().UTC().Add(-time.Duration(s.retentionDaysLocked()) * 24 * time.Hour).Truncate(time.Hour).Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	_ = tx.QueryRow("SELECT COUNT(*) FROM model_usage_remote").Scan(&total)
	const upsert = `INSERT INTO model_usage_remote (epoch, hour_start, owner, actor, batch, atespace, connector, provider, model, route_decision,
		call_role, profile, api_family, cost_basis, calls, errors, usage_calls, input, output, cache_read, cache_creation, reasoning,
		cost_usd_sum, cost_calls, latency_ms_sum) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(epoch, hour_start, owner, actor, batch, atespace, connector, provider, model, route_decision, call_role, profile, api_family, cost_basis)
		DO UPDATE SET calls=excluded.calls, errors=excluded.errors, usage_calls=excluded.usage_calls, input=excluded.input,
		output=excluded.output, cache_read=excluded.cache_read, cache_creation=excluded.cache_creation, reasoning=excluded.reasoning,
		cost_usd_sum=excluded.cost_usd_sum, cost_calls=excluded.cost_calls, latency_ms_sum=excluded.latency_ms_sum`
	for _, r := range rows {
		r = r.bounded()
		if !r.valid() || r.Hour < oldest {
			continue
		}
		var exists int
		existing := tx.QueryRow(`SELECT 1 FROM model_usage_remote WHERE epoch=? AND hour_start=? AND owner=? AND actor=? AND batch=? AND atespace=?
			AND connector=? AND provider=? AND model=? AND route_decision=? AND call_role=? AND profile=? AND api_family=? AND cost_basis=?`,
			epoch, r.Hour, r.Owner, r.Actor, r.Batch, r.Atespace, r.Connector, r.Provider, r.Model, r.Route, r.Role, r.Profile, r.Family, r.Basis).Scan(&exists) == nil
		if !existing {
			if total >= int64(s.maxRows) {
				s.rowCap++
				continue
			}
			total++
		}
		var cost any
		if r.CostUSD != nil && r.CostCalls > 0 {
			cost = *r.CostUSD
		}
		if _, err := tx.Exec(upsert, epoch, r.Hour, r.Owner, r.Actor, r.Batch, r.Atespace, r.Connector, r.Provider, r.Model, r.Route,
			r.Role, r.Profile, r.Family, r.Basis, r.Calls, r.Errors, r.UsageCalls, r.Input, r.Output, r.CacheRead, r.CacheCreation,
			r.Reasoning, cost, r.CostCalls, r.LatencyMs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) retentionDaysLocked() int {
	if s.retDays <= 0 {
		return 30
	}
	return s.retDays
}

// bounded cuts every dimension to the store's width.
func (r RemoteRow) bounded() RemoteRow {
	cut := func(v string) string {
		if len(v) > storeMaxDim {
			return v[:storeMaxDim]
		}
		return v
	}
	r.Owner, r.Actor, r.Batch, r.Atespace = cut(r.Owner), cut(r.Actor), cut(r.Batch), cut(r.Atespace)
	r.Connector, r.Provider, r.Model, r.Route = cut(r.Connector), cut(r.Provider), cut(r.Model), cut(r.Route)
	r.Role, r.Profile, r.Family, r.Basis = cut(r.Role), cut(r.Profile), cut(r.Family), cut(r.Basis)
	return r
}

// valid refuses a row with a negative or absurd count: a replica adds, never
// subtracts, and a bad value must not poison the sums.
func (r RemoteRow) valid() bool {
	for _, n := range []int64{r.Calls, r.Errors, r.UsageCalls, r.Input, r.Output, r.CacheRead, r.CacheCreation, r.Reasoning, r.CostCalls} {
		if n < 0 || n > maxCount {
			return false
		}
	}
	if r.LatencyMs < 0 || math.IsNaN(r.LatencyMs) || math.IsInf(r.LatencyMs, 0) {
		return false
	}
	if r.CostUSD != nil && (*r.CostUSD < 0 || math.IsNaN(*r.CostUSD) || math.IsInf(*r.CostUSD, 0)) {
		return false
	}
	return r.Connector != "" && r.Provider != "" && r.Model != ""
}
