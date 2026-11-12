// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"strings"
	"sync"
	"time"
)

// Spend scopes and periods, for budgets (routing.admin.budgets).
const (
	ScopeUser      = "user"
	ScopeGroup     = "group"
	ScopeConnector = "connector"

	PeriodDay   = "day"
	PeriodWeek  = "week"
	PeriodMonth = "month"

	spendCap = 20000
)

type spendKey struct {
	scope, subject, period string
	start                  int64
}

// spendTracker keeps live per-period spend in memory, independent of the
// local store, so a budget check at request time never waits on SQLite. It
// counts only calls with a known cost: unknown cost adds nothing. It is
// bounded and resets with the process; budgets are a soft control and the
// store is the durable record.
type spendTracker struct {
	mu sync.Mutex
	m  map[spendKey]float64
}

func periodStart(period string, now time.Time) (int64, bool) {
	t := now.UTC()
	switch period {
	case PeriodDay:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).Unix(), true
	case PeriodWeek:
		d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		back := (int(d.Weekday()) + 6) % 7 // Monday start
		return d.AddDate(0, 0, -back).Unix(), true
	case PeriodMonth:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).Unix(), true
	}
	return 0, false
}

func (s *spendTracker) add(f CallFacts, usd float64, now time.Time) {
	subjects := make([]spendKey, 0, 4+len(f.Groups))
	if f.IdentityVerified && strings.TrimSpace(f.Subject) != "" {
		subjects = append(subjects, spendKey{scope: ScopeUser, subject: OwnerID(f)})
		for _, g := range f.Groups {
			subjects = append(subjects, spendKey{scope: ScopeGroup, subject: dim(g)})
		}
	}
	if f.Connector != "" {
		subjects = append(subjects, spendKey{scope: ScopeConnector, subject: dim(f.Connector)})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[spendKey]float64{}
	}
	for _, base := range subjects {
		for _, p := range []string{PeriodDay, PeriodWeek, PeriodMonth} {
			start, _ := periodStart(p, now)
			k := base
			k.period, k.start = p, start
			if _, ok := s.m[k]; !ok && len(s.m) >= spendCap {
				s.pruneLocked(now)
				if len(s.m) >= spendCap {
					continue
				}
			}
			s.m[k] += usd
		}
	}
}

// pruneLocked drops entries of finished periods.
func (s *spendTracker) pruneLocked(now time.Time) {
	for k := range s.m {
		if cur, ok := periodStart(k.period, now); ok && k.start < cur {
			delete(s.m, k)
		}
	}
}

// Spend returns the cost spent so far in the current period by one subject:
// scope user (subject is the owner id from OwnerID), group (the group name) or
// connector. known is false when the engine has seen no priced call for the
// subject in the period, so a budget check can tell no spend from zero.
func (e *Engine) Spend(scope, subject, period string, now time.Time) (usd float64, known bool) {
	if e == nil {
		return 0, false
	}
	start, ok := periodStart(period, now)
	if !ok {
		return 0, false
	}
	sp := &e.spend
	sp.mu.Lock()
	defer sp.mu.Unlock()
	usd, known = sp.m[spendKey{scope: scope, subject: dim(subject), period: period, start: start}]
	return usd, known
}
