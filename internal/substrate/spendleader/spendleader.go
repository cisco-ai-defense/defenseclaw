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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Leader methods.
const (
	MethodSpendPush   = "SpendPush"
	MethodSpendTotals = "SpendTotals"
	MethodUsagePush   = "UsagePush"
	MethodUsageQuery  = "UsageQuery"
)

// Methods lists every method Serve registers (the gateway's permission set).
var Methods = []string{MethodSpendPush, MethodSpendTotals, MethodUsagePush, MethodUsageQuery}

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
	// Page asks for the answer page by page (More, AfterDay, AfterKey); a
	// request without it (a 1.0.10 replica) gets every row in one answer,
	// as before. AfterDay and AfterKey ask for the page after that (day,
	// key) row.
	Page     bool   `json:"page,omitempty"`
	AfterDay string `json:"after_day,omitempty"`
	AfterKey string `json:"after_key,omitempty"`
	// ByKey (with Page) keeps, of the capped keys (actor:, batch:), only
	// those in Keys, and KeysOnly keeps only the keys in Keys: launcher-
	// minted keys never make a read too large.
	ByKey    bool `json:"by_key,omitempty"`
	KeysOnly bool `json:"keys_only,omitempty"`
}

// SpendTotalsAnswer is the sum of the other epochs per (day, key).
type SpendTotalsAnswer struct {
	Rows []SpendRow `json:"rows"`
	// More is set when rows past the last one are left (ask with its day
	// and key as AfterDay and AfterKey).
	More bool `json:"more,omitempty"`
	// Paged says the leader answered Page (an older leader answers every
	// row at once and leaves it unset).
	Paged bool `json:"paged,omitempty"`
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
	if !in.Page {
		rows, err := s.Counter.Totals(ctx, in.Epoch, since, nil)
		if err != nil {
			return SpendTotalsAnswer{}, err
		}
		return SpendTotalsAnswer{Rows: wireRows(rows)}, nil
	}
	// One (day, key) row per pair, sorted by the store; a page starts after
	// the cursor, so a push between pages never repeats a row.
	rows, err := s.Counter.TotalsPage(ctx, in.Epoch, since, routingadmin.TotalsQuery{
		AfterDay: in.AfterDay, AfterKey: in.AfterKey, Limit: maxSpendRows + 1,
		ByKey: in.ByKey, KeysOnly: in.KeysOnly, Keys: in.Keys})
	if err != nil {
		return SpendTotalsAnswer{}, err
	}
	n, size := 0, 0
	for ; n < len(rows) && n < maxSpendRows; n++ {
		if size += rowBytes(rows[n]); n > 0 && size > maxPageBytes {
			break
		}
	}
	return SpendTotalsAnswer{Rows: wireRows(rows[:n]), More: n < len(rows), Paged: true}, nil
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
