// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// LedgerDays is how many UTC days of spend the ledger keeps: enough for
// the longest window (a month) plus the store seed.
const LedgerDays = 62

// Ledger is the in-memory spend of the budget charge keys, per UTC day.
// It exists only when budgets are configured and is carried across config
// reloads. Live charges come from the usage recorder (computed cost of
// agent calls, synchronously at the end of each call); the history of
// earlier gateway processes comes from the usage store once (Seed).
type Ledger struct {
	mu sync.Mutex
	// spend[key][day] is USD, day = days since 1970-01-01 UTC.
	spend map[string]map[int32]float64
	// seeded holds the budget ids whose store history has been added.
	seeded    map[string]bool
	lastPrune int32
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{spend: map[string]map[int32]float64{}, seeded: map[string]bool{}}
}

// Charge adds usd to every key on the UTC day of at. Non-positive or
// non-finite amounts are ignored (absent cost adds nothing).
func (l *Ledger) Charge(keys []string, usd float64, at time.Time) {
	if l == nil || len(keys) == 0 || !(usd > 0) || math.IsInf(usd, 0) {
		return
	}
	day := dayNumber(at)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		days := l.spend[key]
		if days == nil {
			days = map[int32]float64{}
			l.spend[key] = days
		}
		days[day] += usd
	}
	if day != l.lastPrune {
		l.pruneLocked(day)
	}
}

// Spend returns the key's spend in the current period window and whether
// its budget's history is loaded. A key of a budget not yet seeded returns
// false.
func (l *Ledger) Spend(key, period string, now time.Time) (float64, bool) {
	if l == nil {
		return 0, false
	}
	today := dayNumber(now)
	from := windowStart(period, now)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.seeded[budgetIDOfKey(key)] {
		return 0, false
	}
	var total float64
	for day, usd := range l.spend[key] {
		if day >= from && day <= today {
			total += usd
		}
	}
	return total, true
}

// SeedRow is the store's spend of one key on one UTC day, from earlier
// gateway processes only (the store excludes this process's epoch, so the
// live charges are never counted twice).
type SeedRow struct {
	Day time.Time
	Key string
	USD float64
}

// SeedFunc reads the store history since the given UTC day.
type SeedFunc func(ctx context.Context, since time.Time) ([]SeedRow, error)

// Seeded reports whether the budget's history is loaded.
func (l *Ledger) Seeded(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seeded[id]
}

// ApplySeed adds rows for the budget ids not yet seeded and marks them
// seeded. Rows of other ids are skipped, so a later seed for a budget added
// by a reload cannot count an earlier budget twice.
func (l *Ledger) ApplySeed(ids []string, rows []SeedRow) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fresh := map[string]bool{}
	for _, id := range ids {
		if !l.seeded[id] {
			fresh[id] = true
		}
	}
	for _, row := range rows {
		if !fresh[budgetIDOfKey(row.Key)] || !(row.USD > 0) || math.IsInf(row.USD, 0) {
			continue
		}
		days := l.spend[row.Key]
		if days == nil {
			days = map[int32]float64{}
			l.spend[row.Key] = days
		}
		days[dayNumber(row.Day)] += row.USD
	}
	for id := range fresh {
		l.seeded[id] = true
	}
}

// SeedLoop seeds ids from fetch, retrying with backoff (1 s doubling to
// 60 s) until it succeeds or ctx ends. It runs only when budgets exist.
func (l *Ledger) SeedLoop(ctx context.Context, ids []string, now func() time.Time, fetch SeedFunc) {
	if l == nil || len(ids) == 0 || fetch == nil {
		return
	}
	delay := time.Second
	for {
		since := time.Unix(int64(dayNumber(now())-LedgerDays)*86400, 0).UTC()
		rows, err := fetch(ctx, since)
		if err == nil {
			l.ApplySeed(ids, rows)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > time.Minute {
			delay = time.Minute
		}
	}
}

func (l *Ledger) pruneLocked(today int32) {
	l.lastPrune = today
	for key, days := range l.spend {
		for day := range days {
			if day <= today-LedgerDays {
				delete(days, day)
			}
		}
		if len(days) == 0 {
			delete(l.spend, key)
		}
	}
}

// budgetIDOfKey returns the budget id of a charge key (<scope>:<id>:...).
func budgetIDOfKey(key string) string {
	_, rest, ok := strings.Cut(key, ":")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, ":")
	return id
}

func dayNumber(t time.Time) int32 {
	return int32(math.Floor(float64(t.UTC().Unix()) / 86400))
}

// windowStart is the first UTC day of the period that contains now.
func windowStart(period string, now time.Time) int32 {
	today := dayNumber(now)
	switch period {
	case config.RoutingBudgetPeriodWeek:
		// 1970-01-01 was a Thursday; Monday is (day+3) % 7 == 0.
		return today - (today+3)%7
	case config.RoutingBudgetPeriodMonth:
		u := now.UTC()
		return dayNumber(time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC))
	default:
		return today
	}
}

// NextReset is when the period window that contains now ends (UTC).
func NextReset(period string, now time.Time) time.Time {
	u := now.UTC()
	switch period {
	case config.RoutingBudgetPeriodWeek:
		start := windowStart(period, now)
		return time.Unix(int64(start+7)*86400, 0).UTC()
	case config.RoutingBudgetPeriodMonth:
		return time.Date(u.Year(), u.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	}
}
