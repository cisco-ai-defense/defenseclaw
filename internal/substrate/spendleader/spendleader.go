// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package spendleader is the leader side of cluster cost: the budget spend
// and the model usage of every gateway replica, kept in the leader's store
// volume so they survive a pod restart and add up across replicas.
//
// A replica pushes absolute totals under its own epoch every
// substrate.usage.sync_interval (never per model call) and reads the other
// replicas' spend back. Only gateway replicas may call these methods; the
// callout and the controller are not allowed (leader Permissions). A push
// holds counts, cost and bounded keys, never prompt text.
package spendleader

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Leader methods.
const (
	MethodSpendPush   = "SpendPush"
	MethodSpendTotals = "SpendTotals"
	MethodSpendSums   = "SpendSums"
	// MethodSpendUnknown shares the unknown-cost marks of the replicas
	// (substrate-1:GAP-1118).
	MethodSpendUnknown = "SpendUnknown"
	MethodUsagePush    = "UsagePush"
	MethodUsageQuery   = "UsageQuery"
)

// Methods lists every method Serve registers (the gateway's permission set).
var Methods = []string{MethodSpendPush, MethodSpendTotals, MethodSpendSums, MethodSpendUnknown, MethodUsagePush, MethodUsageQuery}

const (
	// maxSpendRows bounds one spend push or answer (Client pushes in chunks
	// of it and reads answers page by page).
	maxSpendRows = 20000
	// maxPageBytes bounds one push chunk or answer page by size too (well
	// under the leader's 4 MB body, with keys up to maxKeyLen).
	maxPageBytes = 2 << 20
	// maxTotalsPages bounds one totals read (pages of maxSpendRows): past it
	// the read fails, so the budgets read as not loaded, never as partial.
	maxTotalsPages = 50
	maxKeyLen      = 256
	maxKeys        = 5000
	// maxOver bounds the budgets of one read's Over.
	maxOver = 256
	// maxUnknownMarks bounds the unknown-cost marks the leader holds (past
	// it the oldest mark goes) and so one answer of them.
	maxUnknownMarks = maxKeys
)

var epochRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,64}$`)

// SpendRow is the wire form of a routingadmin.SeedRow.
type SpendRow struct {
	Day string  `json:"day"`
	Key string  `json:"key"`
	USD float64 `json:"usd"`
}

// SpendPushRequest is one replica's absolute spend per (day, key).
type SpendPushRequest struct {
	Epoch string     `json:"epoch"`
	Rows  []SpendRow `json:"rows"`
}

// SpendTotalsRequest asks for every other epoch's spend since a UTC day.
type SpendTotalsRequest struct {
	Epoch string   `json:"epoch"`
	Since string   `json:"since"`
	Keys  []string `json:"keys,omitempty"`
	// The answer comes page by page (More): AfterDay and AfterKey ask for
	// the page after that (day, key) row.
	AfterDay string `json:"after_day,omitempty"`
	AfterKey string `json:"after_key,omitempty"`
	// ByKey keeps, of the capped keys (actor:, batch:), only
	// those in Keys, and KeysOnly keeps only the keys in Keys: launcher-
	// minted keys never make a read too large.
	ByKey    bool `json:"by_key,omitempty"`
	KeysOnly bool `json:"keys_only,omitempty"`
	// Over (with ByKey, not KeysOnly) also asks for the keys at or over each
	// budget's limit (GAP-0892).
	Over []SpendOver `json:"over,omitempty"`
}

// SpendOver asks for at most Max keys starting with Prefix ("actor:<id>:"
// or "batch:<id>:") whose spend since Since (a UTC date) is at or over
// Limit.
type SpendOver struct {
	Prefix string  `json:"prefix"`
	Since  string  `json:"since"`
	Limit  float64 `json:"limit"`
	Max    int     `json:"max"`
}

// SpendTotalsAnswer is the sum of the other epochs per (day, key).
type SpendTotalsAnswer struct {
	Rows []SpendRow `json:"rows"`
	// More is set when rows past the last one are left (ask with its day
	// and key as AfterDay and AfterKey).
	More bool `json:"more,omitempty"`
	// OverFull lists, on the first page of a read with Over, the budget ids
	// with more than Max keys at or over the limit.
	OverFull []string `json:"over_full,omitempty"`
}

// SpendSumsRequest asks for the stored spend of each budget's keys, every
// epoch (the admin view, GAP-0894): one answer row per budget.
type SpendSumsRequest struct {
	Epoch string      `json:"epoch"`
	Sums  []SpendOver `json:"sums"` // Prefix, Since, Limit (Max unused)
}

// SpendSum is one budget's answer: Total over its keys, Peak the highest
// key, Subjects the keys, Exceeded the keys at or over Limit.
type SpendSum struct {
	Prefix   string  `json:"prefix"`
	Total    float64 `json:"total"`
	Peak     float64 `json:"peak"`
	Subjects int     `json:"subjects"`
	Exceeded int     `json:"exceeded"`
}

// SpendSumsAnswer holds one SpendSum per requested budget.
type SpendSumsAnswer struct {
	Sums []SpendSum `json:"sums"`
}

// SpendMark is the wire form of a routingadmin.UnknownMark: At is in Unix
// seconds.
type SpendMark struct {
	Key string `json:"key"`
	At  int64  `json:"at"`
}

// SpendUnknownRequest is one replica's unknown-cost marks.
type SpendUnknownRequest struct {
	Epoch string      `json:"epoch"`
	Marks []SpendMark `json:"marks,omitempty"`
}

// SpendUnknownAnswer is every replica's marks within UnknownTTL.
type SpendUnknownAnswer struct {
	Marks []SpendMark `json:"marks,omitempty"`
}

// UsagePushRequest is one replica's absolute hourly usage buckets.
type UsagePushRequest struct {
	Epoch string                 `json:"epoch"`
	Rows  []modelusage.RemoteRow `json:"rows"`
}

// UsageQueryRequest is the usage API's query. Owner and AllOwners come from
// the replica's verified caller, never from the request of the user; the
// leader applies them in the SQL WHERE.
type UsageQueryRequest struct {
	By        string `json:"by"`
	From      int64  `json:"from,omitempty"`
	To        int64  `json:"to,omitempty"`
	Owner     string `json:"owner,omitempty"`
	AllOwners bool   `json:"all_owners,omitempty"`
	Batch     string `json:"batch,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// UsageQueryAnswer is the rolled-up rows.
type UsageQueryAnswer struct {
	Rows []modelusage.Row `json:"rows"`
}

// Service is what the leader keeps: the spend counter file and the usage
// store, both on the store volume.
type Service struct {
	// Counter is store/routing/routing_budgets.db (a routingadmin.LocalCounter
	// on the store dir): one epoch per replica process.
	Counter *routingadmin.LocalCounter
	// Usage is store/usage/usage.db, configured on.
	Usage *modelusage.Store
	// Now replaces the clock (tests).
	Now func() time.Time

	// marks holds the replicas' unknown-cost marks in memory, for
	// UnknownTTL: a leader restart loses them, and each replica then has
	// only its own until the next mark (substrate-1:GAP-1118).
	marksMu sync.Mutex
	marks   map[string]time.Time
}

// Serve registers the spend and usage methods on srv. Pushes are absolute
// totals, so they are registered as reads: a retry writes the same values,
// and the replay cache (which would hold every push body for ten minutes) is
// not used. A nil service registers nothing (substrate.usage.enabled: false:
// the methods do not exist, and a call gets unknown_method).
func Serve(srv *leader.Server, s *Service) {
	if srv == nil || s == nil {
		return
	}
	if s.Counter != nil {
		srv.HandleRead(MethodSpendPush, leader.Typed(s.spendPush))
		srv.HandleRead(MethodSpendTotals, leader.Typed(s.spendTotals))
		srv.HandleRead(MethodSpendSums, leader.Typed(s.spendSums))
		srv.HandleRead(MethodSpendUnknown, leader.Typed(s.spendUnknown))
	}
	if s.Usage != nil {
		srv.HandleRead(MethodUsagePush, leader.Typed(s.usagePush))
		srv.HandleRead(MethodUsageQuery, leader.Typed(s.usageQuery))
	}
}

func bad(msg string) error { return &leader.WireError{Code: leader.CodeBadRequest, Message: msg} }

func (s *Service) spendPush(ctx context.Context, in SpendPushRequest) (struct{}, error) {
	if !epochRE.MatchString(in.Epoch) {
		return struct{}{}, bad("epoch is required")
	}
	if len(in.Rows) > maxSpendRows {
		return struct{}{}, bad("too many rows")
	}
	rows := make([]routingadmin.SeedRow, 0, len(in.Rows))
	for _, r := range in.Rows {
		if _, err := time.Parse(time.DateOnly, r.Day); err != nil || r.Key == "" || len(r.Key) > maxKeyLen ||
			!(r.USD >= 0) || math.IsInf(r.USD, 0) {
			return struct{}{}, bad("a row is malformed")
		}
		rows = append(rows, routingadmin.SeedRow{Day: r.Day, Key: r.Key, USD: r.USD})
	}
	if err := s.Counter.Push(ctx, in.Epoch, rows); err != nil {
		return struct{}{}, err
	}
	return struct{}{}, nil
}

func (s *Service) spendTotals(ctx context.Context, in SpendTotalsRequest) (SpendTotalsAnswer, error) {
	if !epochRE.MatchString(in.Epoch) || len(in.Keys) > maxKeys {
		return SpendTotalsAnswer{}, bad("epoch is required")
	}
	since, err := time.Parse(time.DateOnly, in.Since)
	if err != nil {
		return SpendTotalsAnswer{}, bad("since is a UTC date")
	}
	over, err := overQueries(in)
	if err != nil {
		return SpendTotalsAnswer{}, err
	}
	// One (day, key) row per pair, sorted by the store; a page starts after
	// the cursor, so a push between pages never repeats a row.
	rows, err := s.Counter.TotalsPage(ctx, in.Epoch, since, routingadmin.TotalsQuery{
		AfterDay: in.AfterDay, AfterKey: in.AfterKey, Limit: maxSpendRows + 1,
		ByKey: in.ByKey, KeysOnly: in.KeysOnly, Keys: in.Keys, Over: over})
	if err != nil {
		return SpendTotalsAnswer{}, err
	}
	var full []string
	if len(over) > 0 && in.AfterDay == "" {
		if full, err = s.Counter.OverFull(ctx, in.Epoch, over); err != nil {
			return SpendTotalsAnswer{}, err
		}
	}
	n, size := 0, 0
	for ; n < len(rows) && n < maxSpendRows; n++ {
		if size += rowBytes(rows[n]); n > 0 && size > maxPageBytes {
			break
		}
	}
	return SpendTotalsAnswer{Rows: wireRows(rows[:n]), More: n < len(rows), OverFull: full}, nil
}

func (s *Service) spendSums(ctx context.Context, in SpendSumsRequest) (SpendSumsAnswer, error) {
	if !epochRE.MatchString(in.Epoch) || len(in.Sums) == 0 || len(in.Sums) > maxOver {
		return SpendSumsAnswer{}, bad("epoch and 1 to 256 sums are required")
	}
	q := make([]routingadmin.SumQuery, 0, len(in.Sums))
	for _, o := range in.Sums {
		since, err := time.Parse(time.DateOnly, o.Since)
		if err != nil || !budgetPrefix(o.Prefix) || !(o.Limit > 0) || math.IsInf(o.Limit, 0) {
			return SpendSumsAnswer{}, bad("a sum is a budget prefix, a UTC date and a limit")
		}
		q = append(q, routingadmin.SumQuery{Prefix: o.Prefix, Since: since, Limit: o.Limit})
	}
	sums, err := s.Counter.PrefixSums(ctx, q)
	if err != nil {
		return SpendSumsAnswer{}, err
	}
	out := SpendSumsAnswer{Sums: make([]SpendSum, 0, len(sums))}
	for _, p := range sums {
		out.Sums = append(out.Sums, SpendSum{Prefix: p.Prefix, Total: p.Total, Peak: p.Peak, Subjects: p.Subjects, Exceeded: p.Exceeded})
	}
	return out, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// spendUnknown keeps the marks of one replica (a key keeps its latest mark;
// one dated after the leader's clock counts from now) and answers every
// live mark.
func (s *Service) spendUnknown(_ context.Context, in SpendUnknownRequest) (SpendUnknownAnswer, error) {
	if !epochRE.MatchString(in.Epoch) || len(in.Marks) > maxUnknownMarks {
		return SpendUnknownAnswer{}, bad("epoch is required")
	}
	for _, m := range in.Marks {
		if !markKey(m.Key) || m.At <= 0 {
			return SpendUnknownAnswer{}, bad("a mark is a user, actor or batch key and a time")
		}
	}
	now := s.now()
	s.marksMu.Lock()
	defer s.marksMu.Unlock()
	for key, at := range s.marks {
		if now.Sub(at) >= routingadmin.UnknownTTL {
			delete(s.marks, key)
		}
	}
	for _, m := range in.Marks {
		at := time.Unix(m.At, 0)
		if at.After(now) {
			at = now
		}
		if now.Sub(at) >= routingadmin.UnknownTTL {
			continue
		}
		prev, ok := s.marks[m.Key]
		if ok && !at.After(prev) {
			continue
		}
		if !ok && len(s.marks) >= maxUnknownMarks {
			s.dropOldestMarkLocked()
		}
		if s.marks == nil {
			s.marks = map[string]time.Time{}
		}
		s.marks[m.Key] = at
	}
	out := SpendUnknownAnswer{Marks: make([]SpendMark, 0, len(s.marks))}
	for key, at := range s.marks {
		out.Marks = append(out.Marks, SpendMark{Key: key, At: at.Unix()})
	}
	return out, nil
}

func (s *Service) dropOldestMarkLocked() {
	var oldest string
	var at time.Time
	for key, t := range s.marks {
		if oldest == "" || t.Before(at) {
			oldest, at = key, t
		}
	}
	delete(s.marks, oldest)
}

// markKey is a user:, actor: or batch: key within maxKeyLen.
func markKey(k string) bool {
	return len(k) <= maxKeyLen && (strings.HasPrefix(k, "user:") || strings.HasPrefix(k, "actor:") || strings.HasPrefix(k, "batch:"))
}

// budgetPrefix is "actor:<id>:" or "batch:<id>:" within maxKeyLen.
func budgetPrefix(p string) bool {
	return len(p) <= maxKeyLen && len(p) >= len("actor:x:") && strings.HasSuffix(p, ":") &&
		(strings.HasPrefix(p, "actor:") || strings.HasPrefix(p, "batch:"))
}

// overQueries checks a read's Over (only a by-key read, not KeysOnly, has
// one).
func overQueries(in SpendTotalsRequest) ([]routingadmin.OverQuery, error) {
	if len(in.Over) == 0 || !in.ByKey || in.KeysOnly {
		return nil, nil
	}
	if len(in.Over) > maxOver {
		return nil, bad("too many over budgets")
	}
	out := make([]routingadmin.OverQuery, 0, len(in.Over))
	for _, o := range in.Over {
		since, err := time.Parse(time.DateOnly, o.Since)
		if err != nil || !budgetPrefix(o.Prefix) || !(o.Limit > 0) || math.IsInf(o.Limit, 0) || o.Max < 1 || o.Max > maxKeys {
			return nil, bad("over is a budget prefix, a UTC date, a limit and a max")
		}
		out = append(out, routingadmin.OverQuery{Prefix: o.Prefix, Since: since, Limit: o.Limit, Max: o.Max})
	}
	return out, nil
}

// rowBytes is about what one row takes in a JSON body.
func rowBytes(r routingadmin.SeedRow) int { return len(r.Key) + len(r.Day) + 48 }

func wireRows(rows []routingadmin.SeedRow) []SpendRow {
	out := make([]SpendRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, SpendRow{Day: r.Day, Key: r.Key, USD: r.USD})
	}
	return out
}

func (s *Service) usagePush(_ context.Context, in UsagePushRequest) (struct{}, error) {
	if !epochRE.MatchString(in.Epoch) {
		return struct{}{}, bad("epoch is required")
	}
	if err := s.Usage.ApplyRemote(in.Epoch, in.Rows); err != nil {
		if errors.Is(err, modelusage.ErrRemoteBatch) {
			return struct{}{}, bad(err.Error())
		}
		return struct{}{}, err
	}
	return struct{}{}, nil
}

func (s *Service) usageQuery(ctx context.Context, in UsageQueryRequest) (UsageQueryAnswer, error) {
	q := modelusage.Query{By: strings.TrimSpace(in.By), Owner: in.Owner, AllOwners: in.AllOwners, Batch: in.Batch, Limit: in.Limit}
	if in.From > 0 {
		q.From = time.Unix(in.From, 0).UTC()
	}
	if in.To > 0 {
		q.To = time.Unix(in.To, 0).UTC()
	}
	rows, err := s.Usage.Run(ctx, q)
	if err != nil {
		if errors.Is(err, modelusage.ErrAdminOnly) {
			return UsageQueryAnswer{}, &leader.WireError{Code: leader.CodeForbidden, Message: err.Error()}
		}
		return UsageQueryAnswer{}, bad(err.Error())
	}
	return UsageQueryAnswer{Rows: rows}, nil
}
