// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// Cluster cost: a gateway replica keeps spend and usage in memory and sends
// absolute totals to the leader on a timer; the usage API reads the leader.
// The per-call cost is the in-memory ledger read and one map update in the
// usage sink. Nothing on a model call touches the network or the disk.

// SubstrateSpendLeader is the leader as a gateway replica uses it for cost
// (spendleader.Client): the spend counter, the usage push and the usage
// query.
type SubstrateSpendLeader interface {
	routingadmin.SpendRPC
	UsagePush(ctx context.Context, epoch string, rows []modelusage.RemoteRow) error
	UsageQuery(ctx context.Context, q modelusage.Query) ([]modelusage.Row, error)
}

// SubstrateUsageQuery is what the usage API asks for. Owner is the caller's
// usage owner, set from the verified person; All is an administrator's
// all-owner read.
type SubstrateUsageQuery struct {
	Owner string
	All   bool
	// By is the rollup: model, actor, batch, atespace, day, connector, provider,
	// or person (an administrator's per-person view).
	By    string
	Since time.Duration
	Batch string
	Limit int
}

// SubstrateUsageRow is one rolled-up line; Name is the person's display name
// for an administrator's per-person view.
type SubstrateUsageRow struct {
	modelusage.Row
	Name string `json:"name,omitempty"`
}

// SubstrateUsageAnswer is the usage API's reply.
type SubstrateUsageAnswer struct {
	By      string              `json:"by"`
	From    string              `json:"from"`
	To      string              `json:"to"`
	Rows    []SubstrateUsageRow `json:"rows"`
	Budgets []routingBudgetView `json:"budgets,omitempty"`
}

// Spend usage defaults.
const (
	substrateUsageDefaultSince = 24 * time.Hour
	substrateUsageMaxSince     = 31 * 24 * time.Hour
	substrateUsageTimeout      = 5 * time.Second
)

// substrateUsageBy maps the API's rollup names to the store's.
var substrateUsageBy = map[string]string{
	"": "model", "model": "model", "actor": "actor", "batch": "batch", "atespace": "atespace", "day": "day",
	"connector": "connector", "provider": "provider", "person": "user",
}

// substrateLeaderUsage is the SubstrateUsage over the leader.
type substrateLeaderUsage struct {
	leader SubstrateSpendLeader
	// cfg is the live config (budget lines, user visibility); regs resolves a
	// person key to a display name for an administrator.
	cfg  func() *config.Config
	regs registry.Store
	now  func() time.Time
}

// NewSubstrateLeaderUsage is the usage reader of a gateway replica.
func NewSubstrateLeaderUsage(l SubstrateSpendLeader, cfg func() *config.Config, regs registry.Store) SubstrateUsage {
	return &substrateLeaderUsage{leader: l, cfg: cfg, regs: regs, now: time.Now}
}

func (u *substrateLeaderUsage) Usage(ctx context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
	by, ok := substrateUsageBy[q.By]
	if !ok {
		return SubstrateUsageAnswer{}, errSubstrateUsageBy
	}
	if by == "user" && !q.All {
		return SubstrateUsageAnswer{}, errSubstrateUsageAdminOnly
	}
	since := q.Since
	if since <= 0 {
		since = substrateUsageDefaultSince
	}
	if since > substrateUsageMaxSince {
		since = substrateUsageMaxSince
	}
	now := u.now().UTC()
	ctx, cancel := context.WithTimeout(ctx, substrateUsageTimeout)
	defer cancel()
	rows, err := u.leader.UsageQuery(ctx, modelusage.Query{By: by, From: now.Add(-since), To: now, Owner: q.Owner, AllOwners: q.All, Batch: q.Batch, Limit: q.Limit})
	if err != nil {
		return SubstrateUsageAnswer{}, err
	}
	ans := SubstrateUsageAnswer{By: q.By, From: now.Add(-since).Format(time.RFC3339), To: now.Format(time.RFC3339), Rows: make([]SubstrateUsageRow, 0, len(rows))}
	if ans.By == "" {
		ans.By = "model"
	}
	var names map[string]string
	if by == "user" {
		names = u.personNames(ctx)
	}
	for _, r := range rows {
		row := SubstrateUsageRow{Row: r}
		if by == "user" {
			row.Name = names[r.Key]
		}
		ans.Rows = append(ans.Rows, row)
	}
	if cfg := u.cfg(); cfg != nil {
		personKey := ""
		if !q.All {
			personKey = q.OwnerPersonKey()
		}
		ans.Budgets = routingBudgetViews(cfg, personKey, q.All, routingadmin.Caller{}, now)
		sort.Slice(ans.Budgets, func(i, j int) bool { return ans.Budgets[i].ID < ans.Budgets[j].ID })
	}
	return ans, nil
}

// OwnerPersonKey is the person key inside a usage owner id
// (substrate_person:<key>), "" for any other owner.
func (q SubstrateUsageQuery) OwnerPersonKey() string {
	const prefix = substrateUsageOwnerKind + ":"
	if len(q.Owner) > len(prefix) && q.Owner[:len(prefix)] == prefix {
		return q.Owner[len(prefix):]
	}
	return ""
}

// personNames maps usage owner ids to the display names of the registered
// people, read at request time and for an administrator only. Names are never
// stored in the usage rows.
func (u *substrateLeaderUsage) personNames(ctx context.Context) map[string]string {
	out := map[string]string{}
	if u.regs == nil {
		return out
	}
	regs, err := u.regs.List(ctx, registry.Filter{})
	if err != nil {
		return out
	}
	for _, r := range regs {
		if r.Attributed || r.Person.Key() == "" {
			continue
		}
		name := r.Person.Principal
		if name == "" {
			name = r.Person.Subject
		}
		out[substrateUsageOwner(r.Person)] = name
	}
	return out
}

// startSubstrateSpend moves a cluster replica's budget spend and model usage
// onto the leader. It runs once per process, from the Substrate builder's
// config; with substrate.usage.enabled false (cfg.SpendLeader nil) it does
// nothing: no counter swap, no sink, no goroutine.
//
// Per request: the evaluator reads the in-memory ledger (Spend) and the usage
// engine calls LeaderSink.Emit (one lock, one map update). Both counters run
// on this timer, with a 4 s bound per call.
func (s *Sidecar) startSubstrateSpend(ctx context.Context, cfg SubstrateConfig, interval time.Duration) (started bool) {
	l := cfg.SpendLeader
	if s == nil || l == nil {
		return false
	}
	if interval <= 0 {
		interval = config.DefaultSubstrateUsageSyncInterval
	}
	routingAdminRuntime.SetStaleAfter(3 * interval)
	routingAdminRuntime.SetInterval(interval)
	routingAdminRuntime.SetCounters(ctx, routingadmin.NewLeaderCounter(l), nil, interval)
	var epoch [12]byte
	_, _ = rand.Read(epoch[:])
	sink := modelusage.NewLeaderSink(hex.EncodeToString(epoch[:]))
	s.modelUsage().engine.AddSink(sink)
	go substratePushUsage(ctx, l, sink, interval)
	return true
}

// substratePushUsage sends the buckets the leader has not acknowledged every
// interval, and once more at shutdown. A failed push keeps them for the next.
func substratePushUsage(ctx context.Context, l SubstrateSpendLeader, sink *modelusage.LeaderSink, interval time.Duration) {
	push := func(ctx context.Context) {
		p := sink.Pending()
		if len(p) == 0 {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, routingadmin.LeaderCounterTimeout)
		defer cancel()
		if err := l.UsagePush(pctx, sink.Epoch(), modelusage.Rows(p)); err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] usage push to the leader: %v\n", err)
			return
		}
		sink.Acked(p)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			push(final)
			cancel()
			return
		case <-t.C:
			push(ctx)
		}
	}
}

// substrateActorBudget is the BUDGET cell of one agent in substrate list and
// status: the highest used share among the budgets that count its calls (its
// own actor budget, its batch budget and the per-person * budget of its
// owner), as "NN %", or "over" once one is used up. "" when no budget counts
// it or no spend is known yet. A pooled total is never shown: the fleet store
// answers a pooled budget with over the limit only.
// substrateBudgetActor is the actor and person key a budget charges reg's
// calls to.
func substrateBudgetActor(reg registry.Registration) (*engine.Actor, string) {
	personKey := ""
	actor := &engine.Actor{Key: reg.Key, Atespace: reg.Atespace, BatchID: reg.BatchID}
	if !reg.Attributed {
		personKey = reg.Person.Key()
		actor.Person = personKey != ""
	}
	return actor, personKey
}

// substrateReadBudgetKeys reads, before a list or status view, the actor
// and batch budget keys of regs from the spend leader (in a cluster this
// replica holds only its own keys), so the BUDGET cell shows the cluster's
// spend. One bounded read by key list; nothing on a device.
func substrateReadBudgetKeys(ctx context.Context, cfg *config.Config, regs []registry.Registration) {
	if cfg == nil || cfg.Routing.Admin == nil || len(regs) == 0 {
		return
	}
	var keys []string
	for _, b := range cfg.Routing.Admin.Budgets {
		if b.LimitUSD <= 0 || (b.Scope != config.RoutingBudgetScopeActor && b.Scope != config.RoutingBudgetScopeBatch) {
			continue
		}
		for _, reg := range regs {
			if reg.Key == "" || reg.Deleted {
				continue
			}
			actor, personKey := substrateBudgetActor(reg)
			if k := routingadmin.ActorBudgetKey(b.Scope, b.ID, actor, personKey); k != "" {
				keys = append(keys, k)
			}
		}
	}
	routingAdminRuntime.ReadViewKeys(ctx, keys)
}

func substrateActorBudget(cfg *config.Config, reg registry.Registration, now time.Time) string {
	if cfg == nil || cfg.Routing.Admin == nil || reg.Key == "" {
		return ""
	}
	ledger := routingAdminRuntime.Ledger()
	if ledger == nil {
		return ""
	}
	actor, personKey := substrateBudgetActor(reg)
	best, seen := 0.0, false
	for _, b := range cfg.Routing.Admin.Budgets {
		var key string
		switch b.Scope {
		case config.RoutingBudgetScopeActor, config.RoutingBudgetScopeBatch:
			key = routingadmin.ActorBudgetKey(b.Scope, b.ID, actor, personKey)
		case config.RoutingBudgetScopeUser:
			if b.Subject == config.RoutingBudgetSubjectAll && personKey != "" {
				key = "user:" + b.ID + ":*:" + personKey
			}
		}
		if key == "" || b.LimitUSD <= 0 {
			continue
		}
		// An actor or batch key another replica holds: the list read it
		// from the leader (substrateReadBudgetKeys, GAP-0894).
		spend, known := ledger.ViewSpend(key, b.Period, now)
		if !known {
			continue
		}
		if spend >= b.LimitUSD || spend >= budgetstore.ExceededUSD/2 {
			return "over"
		}
		if p := 100 * spend / b.LimitUSD; !seen || p > best {
			best, seen = p, true
		}
	}
	if !seen {
		return ""
	}
	return fmt.Sprintf("%.0f %%", best)
}
