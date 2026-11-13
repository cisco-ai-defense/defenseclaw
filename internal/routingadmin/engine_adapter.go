// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// OwnerKey is the caller key of the only user of an OSS (per-user)
// gateway when the request carries no verified identity.
const OwnerKey = "owner"

// Runtime is the process-wide state of the admin routing policy: the spend
// ledger and its sync loop (only while budgets are configured) and the
// recent decisions. It is carried across config reloads; For compiles each
// generation's rules.
type Runtime struct {
	decisions Decisions

	mu     sync.Mutex
	ledger *Ledger
	ids    []string // budget ids of the newest generation
	last   *config.Config
	lastEv *evaluator
	ctx    context.Context
	local  SpendCounter // this device's store (per-device budgets and the fallback)
	fleet  SpendCounter // optional: shared by devices or gateway replicas
	keys   FleetKeys    // local <-> fleet key forms (nil: the same keys)
	// feed is true once agent call costs reach Charge (the usage engine
	// records agent calls with a computed cost); until then budgets read
	// as not loaded, so a managed deny budget refuses instead of counting 0.
	feed     bool
	interval time.Duration
	epoch    string
	writer   string // the last fleet writer id (device), kept while no fleet is set
	syncing  bool
	kick     chan struct{}
	pushMu   sync.Mutex // one push at a time: snapshot and send stay in order

	callsMu   sync.Mutex
	calls     map[string]struct{}
	callOrder []string
}

// Kick asks the sync loop to sync now (a new user was seen).
func (rt *Runtime) Kick() {
	if rt == nil {
		return
	}
	select {
	case rt.kick <- struct{}{}:
	default:
	}
}

// SetInterval changes the sync interval (routing.admin.budget_store.sync_interval).
func (rt *Runtime) SetInterval(d time.Duration) {
	if rt == nil || d <= 0 {
		return
	}
	rt.mu.Lock()
	rt.interval = d
	rt.mu.Unlock()
}

// DefaultSyncInterval is how often the ledger stores this process's spend
// and reads everyone else's.
const DefaultSyncInterval = 30 * time.Second

// NewRuntime returns an empty runtime; it costs nothing until a config
// with routing.admin rules or budgets is compiled.
func NewRuntime() *Runtime {
	return &Runtime{interval: DefaultSyncInterval, kick: make(chan struct{}, 1), epoch: newEpoch()}
}

// newEpoch is a random writer id: the store learns nothing about the
// process or host.
func newEpoch() string {
	var id [12]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

// writerOf is the writer identity of a fleet counter (the budget store's
// device id), "" when it has none.
func writerOf(c SpendCounter) string {
	if w, ok := c.(interface{ WriterID() string }); ok {
		return w.WriterID()
	}
	return ""
}

// Decisions returns the recent-decisions ring.
func (rt *Runtime) Decisions() *Decisions {
	if rt == nil {
		return nil
	}
	return &rt.decisions
}

// Ledger returns the spend ledger, nil while no budget is configured.
func (rt *Runtime) Ledger() *Ledger {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.ledger
}

// SetCounters installs the spend counters: local (this device; required for
// budgets to survive a restart) and fleet (optional, nil = per-device
// budgets). The sync loop starts when budgets exist and stops with ctx,
// storing this process's spend one last time. interval 0 keeps the default.
func (rt *Runtime) SetCounters(ctx context.Context, local, fleet SpendCounter, interval time.Duration) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	rt.ctx, rt.local, rt.fleet = ctx, local, fleet
	if interval > 0 {
		rt.interval = interval
	}
	rt.mu.Unlock()
	rt.startSync()
}

// SetFeed says whether agent call costs reach Charge (observability
// tokenomics records agent calls with a computed cost). Generations compile
// again.
func (rt *Runtime) SetFeed(active bool) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	changed := rt.feed != active
	rt.feed = active
	if changed {
		rt.last, rt.lastEv = nil, nil
	}
	rt.mu.Unlock()
}

// SetFleet installs (or, with a nil counter, removes) the fleet counter and
// its key mapping (the device credential maps local keys to fleet keys).
//
// A counter with another writer id (a new device credential) is a new
// writer at the store: this process's spend so far stays with the old
// writer (it is stored on this device and keeps counting there), and the
// process starts a new epoch with no local spend, so the store never counts
// the same spend under two device ids.
func (rt *Runtime) SetFleet(fleet SpendCounter, keys FleetKeys) {
	if rt == nil {
		return
	}
	rt.pushMu.Lock()
	rt.mu.Lock()
	old, oldKeys, ledger, local, epoch, ctx := rt.fleet, rt.keys, rt.ledger, rt.local, rt.epoch, rt.ctx
	// A different writer than the last one this process sent as, even with
	// no fleet in between (a bad CA file, the store off and on again).
	rotate := fleet != nil && rt.writer != "" && writerOf(fleet) != rt.writer
	if rotate {
		rt.epoch = newEpoch()
	}
	if fleet != nil {
		rt.writer = writerOf(fleet)
	}
	rt.fleet, rt.keys = fleet, keys
	rt.last, rt.lastEv = nil, nil
	rt.mu.Unlock()
	if rotate && ledger != nil {
		if rows := ledger.TakeLocal(); len(rows) > 0 {
			if ctx == nil {
				ctx = context.Background()
			}
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var err error
			if local != nil {
				err = local.Push(pctx, epoch, rows)
			}
			if old != nil && old != fleet {
				// The old credential's last word, so other devices see it.
				_ = old.Push(pctx, epoch, toFleet(rows, oldKeys))
			}
			ledger.PushResult(err)
			cancel()
		}
	}
	rt.pushMu.Unlock()
	rt.startSync()
	if rotate {
		rt.Kick()
	}
}

// Charge counts usd against keys (no idempotency; tests and Add use it).
func (rt *Runtime) Charge(keys []string, usd float64, at time.Time) {
	if l := rt.Ledger(); l != nil {
		l.Charge(keys, usd, at)
	}
}

// recentCallsMax bounds the call ids Add remembers for idempotency.
const recentCallsMax = 65536

// Add is the one producer call of budget spend (lead ruling 2026-11-12T23:38Z):
// the usage engine calls it once per finished call with the call id as the
// idempotency key, the budget keys of the routing verdict and the resolved
// cost (computed, else reported). known false is a call whose cost is
// unknown: never counted as 0, the budget reads as unknown for the period.
func (rt *Runtime) Add(callID string, keys []string, usd float64, known bool, at time.Time) {
	if rt == nil || len(keys) == 0 {
		return
	}
	l := rt.Ledger()
	if l == nil {
		return
	}
	if callID != "" {
		rt.callsMu.Lock()
		if rt.calls == nil {
			rt.calls = map[string]struct{}{}
		}
		if _, seen := rt.calls[callID]; seen {
			rt.callsMu.Unlock()
			return
		}
		if len(rt.callOrder) >= recentCallsMax {
			delete(rt.calls, rt.callOrder[0])
			rt.callOrder = rt.callOrder[1:]
		}
		rt.calls[callID] = struct{}{}
		rt.callOrder = append(rt.callOrder, callID)
		rt.callsMu.Unlock()
	}
	if !known {
		l.MarkUnknown(keys, at)
		return
	}
	l.Charge(keys, usd, at)
}

// For returns the admin evaluator of cfg, or nil when cfg has no
// routing.admin rules or budgets (the engine then skips it).
func (rt *Runtime) For(cfg *config.Config) engine.AdminEvaluator {
	if rt == nil || cfg == nil || cfg.Routing.Admin == nil {
		return nil
	}
	rt.mu.Lock()
	if rt.last == cfg {
		ev := rt.lastEv
		rt.mu.Unlock()
		if ev == nil {
			return nil
		}
		return ev
	}
	rt.mu.Unlock()
	a := cfg.Routing.Admin
	policy := Compile(a.Rules, a.Budgets, cfg.StandaloneEnterprise())
	if policy == nil {
		rt.mu.Lock()
		rt.last, rt.lastEv, rt.ids = cfg, nil, nil
		rt.mu.Unlock()
		return nil
	}
	ev := &evaluator{rt: rt, policy: policy, catalog: map[string]Target{}}
	for _, m := range cfg.Routing.Models {
		ev.catalog[m.Name] = Target{Provider: m.Provider, Model: m.Model}
	}
	for _, r := range a.Rules {
		ev.needsCategory = ev.needsCategory || len(r.Match.Categories) > 0
	}
	rt.mu.Lock()
	if len(a.Budgets) > 0 && rt.ledger == nil {
		rt.ledger = NewLedger()
	}
	if rt.feed {
		ev.ledger = rt.ledger
	}
	rt.last, rt.lastEv, rt.ids = cfg, ev, policy.BudgetIDs()
	rt.mu.Unlock()
	rt.startSync()
	return ev
}

// startSync runs the sync loop once budgets and a counter exist, and asks a
// running loop to sync now (new budget ids after a reload).
func (rt *Runtime) startSync() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.ledger == nil || rt.local == nil || rt.ctx == nil || len(rt.ids) == 0 {
		return
	}
	if rt.syncing {
		select {
		case rt.kick <- struct{}{}:
		default:
		}
		return
	}
	rt.syncing = true
	go rt.syncLoop(rt.ctx)
}

func (rt *Runtime) syncLoop(ctx context.Context) {
	defer func() {
		rt.mu.Lock()
		rt.syncing = false
		rt.mu.Unlock()
	}()
	rt.SyncOnce(ctx)
	for {
		rt.mu.Lock()
		interval := rt.interval
		rt.mu.Unlock()
		select {
		case <-ctx.Done():
			// Keep this process's spend for the next one.
			final, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			rt.push(final)
			cancel()
			return
		case <-rt.kick:
		case <-time.After(interval):
		}
		rt.SyncOnce(ctx)
	}
}

// SyncOnce stores this process's spend and reads everyone else's: from the
// fleet counter when one is set and answers, else from this device's store
// (per-device budgets; a fleet outage falls back to them).
func (rt *Runtime) SyncOnce(ctx context.Context) {
	rt.mu.Lock()
	ledger, local, fleet, keys, ids, epoch := rt.ledger, rt.local, rt.fleet, rt.keys, append([]string(nil), rt.ids...), rt.epoch
	rt.mu.Unlock()
	if ledger == nil || local == nil {
		return
	}
	rt.push(ctx)
	since := time.Unix(int64(dayNumber(time.Now())-LedgerDays)*86400, 0).UTC()
	var rows []SeedRow
	var err error
	// This device's earlier processes always count: a fleet answer that
	// leaves them out (a user with no fleet id, a store that lost data) can
	// never lower what this device already knows.
	localRows, localErr := local.Totals(ctx, epoch, since, nil)
	if fleet != nil {
		if rows, err = fleet.Totals(ctx, epoch, since, fleetWanted(ledger, keys)); err == nil {
			ledger.ApplyRemote(ids, maxRows(fromFleet(rows, keys), localRows), time.Now())
			if localErr != nil {
				ledger.SyncFailed(localErr)
			}
			return
		}
		ledger.SyncFailed(err)
	}
	if localErr != nil {
		ledger.SyncFailed(localErr)
		return
	}
	ledger.ApplyRemote(ids, localRows, time.Now())
	if fleet != nil {
		// Keep why: the store down, the device refused, a budget it lacks.
		ledger.SyncFailed(fmt.Errorf("%w (%v)", errFleetFallback, err))
	}
}

// maxRows merges two spend answers per (key, day), keeping the larger.
func maxRows(a, b []SeedRow) []SeedRow {
	type dk struct{ day, key string }
	m := map[dk]float64{}
	for _, rows := range [][]SeedRow{a, b} {
		sum := map[dk]float64{}
		for _, r := range rows {
			sum[dk{r.Day, r.Key}] += r.USD
		}
		for k, v := range sum {
			if v > m[k] {
				m[k] = v
			}
		}
	}
	out := make([]SeedRow, 0, len(m))
	for k, v := range m {
		out = append(out, SeedRow{Day: k.day, Key: k.key, USD: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].Key < out[j].Key
	})
	return out
}

var errFleetFallback = errors.New("fleet spend unavailable; counting this device only")

// Flush stores this process's spend once (the gateway calls it after the
// usage engine drained at shutdown).
func (rt *Runtime) Flush(ctx context.Context) {
	if rt == nil {
		return
	}
	rt.push(ctx)
}

func (rt *Runtime) push(ctx context.Context) {
	rt.pushMu.Lock()
	defer rt.pushMu.Unlock()
	rt.mu.Lock()
	ledger, local, fleet, epoch := rt.ledger, rt.local, rt.fleet, rt.epoch
	rt.mu.Unlock()
	if ledger == nil {
		return
	}
	rows := ledger.LocalRows()
	if len(rows) == 0 {
		return
	}
	var failed error
	if local != nil {
		if err := local.Push(ctx, epoch, rows); err != nil {
			failed = err
		}
	}
	if fleet != nil {
		if err := fleet.Push(ctx, epoch, toFleet(rows, rt.fleetKeys())); err != nil && failed == nil {
			failed = err
		}
	}
	ledger.PushResult(failed)
}

func (rt *Runtime) fleetKeys() FleetKeys {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.keys
}

// toFleet keeps the rows that have a fleet form, in that form.
func toFleet(rows []SeedRow, keys FleetKeys) []SeedRow {
	if keys == nil {
		return rows
	}
	out := make([]SeedRow, 0, len(rows))
	for _, r := range rows {
		if k, ok := keys.ToFleet(r.Key); ok {
			out = append(out, SeedRow{Day: r.Day, Key: k, USD: r.USD})
		}
	}
	return out
}

// fromFleet keeps the rows with a local form, in that form.
func fromFleet(rows []SeedRow, keys FleetKeys) []SeedRow {
	if keys == nil {
		return rows
	}
	out := make([]SeedRow, 0, len(rows))
	for _, r := range rows {
		if k, ok := keys.FromFleet(r.Key); ok {
			out = append(out, SeedRow{Day: r.Day, Key: k, USD: r.USD})
		}
	}
	return out
}

// fleetWanted is every fleet key this device needs: its own spend's keys and
// the mapper's (named budgets, users seen here).
func fleetWanted(ledger *Ledger, keys FleetKeys) []string {
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, r := range ledger.LocalRows() {
		if keys == nil {
			add(r.Key)
		} else if k, ok := keys.ToFleet(r.Key); ok {
			add(k)
		}
	}
	if keys != nil {
		for _, k := range keys.Wanted() {
			add(k)
		}
	}
	sort.Strings(out)
	return out
}

// evaluator implements engine.AdminEvaluator for one config generation.
type evaluator struct {
	rt            *Runtime
	policy        *Policy
	ledger        *Ledger
	catalog       map[string]Target
	needsCategory bool
}

func (e *evaluator) Active() bool        { return e != nil && e.policy != nil }
func (e *evaluator) NeedsCategory() bool { return e != nil && e.needsCategory }

// Policy returns the compiled rules and budgets (for the routing API).
func (e *evaluator) Policy() *Policy { return e.policy }

// Evaluate narrows p by the rules and budgets that apply to r.
func (e *evaluator) Evaluate(_ context.Context, p engine.Policy, r engine.Request, category string, classifierFailed bool) engine.AdminVerdict {
	req := Request{
		Caller:           CallerFromEngine(r.Caller, e.policy.Managed),
		Connector:        config.NormalizeConnectorName(r.Connector),
		Category:         category,
		ClassifierFailed: classifierFailed,
		Severity:         r.Severity,
	}
	v := e.policy.Evaluate(req, e.ledger, time.Now())
	return ToEngineVerdict(p, v)
}

// Gate checks one forwarded exit against the verdict.
func (e *evaluator) Gate(v engine.AdminVerdict, target engine.GateTarget, managed bool) *engine.DenyReason {
	verdict := Verdict{Bind: v.Bind, Force: v.Force, RuleIDs: v.RuleIDs, BindRuleIDs: v.RuleIDs}
	if v.Bind {
		verdict.Allowed = v.Policy.AllowedAliases
	}
	if v.Deny != nil {
		verdict.Deny = &Deny{Code: v.Deny.Code, Message: v.Deny.Message}
	}
	for _, w := range v.Warnings {
		if id, ok := strings.CutPrefix(w, "budget_downgrade:"); ok {
			verdict.ForceBudget = id
		}
	}
	t := Target{Provider: target.Provider, Model: target.Model}
	if target.Alias != "" {
		if c, ok := e.catalog[target.Alias]; ok {
			t = c
		}
	}
	deny, _ := Gate(verdict, t, e.catalog, managed)
	if deny == nil {
		return nil
	}
	return &engine.DenyReason{Code: deny.Code, Message: deny.Message}
}

// CallerFromEngine maps the engine caller. On OSS every request of a
// per-user gateway is its owner's: one key for * budgets, and identity
// selectors (meant for managed multi-user devices) do not match.
func CallerFromEngine(c engine.Caller, managed bool) Caller {
	if !managed {
		return Caller{Verified: true, Key: OwnerKey, Match: func(config.ProfileMatch) MatchState { return No }}
	}
	out := Caller{Verified: c.Verified, Key: c.Key}
	if !c.Verified {
		out.Key = ""
		return out
	}
	switch {
	case c.LookupFailed:
		out.Unconfirmed = "directory"
	case c.GroupsUnknown:
		out.Unconfirmed = "groups"
	}
	if c.Matches != nil {
		match := c.Matches
		out.Match = func(m config.ProfileMatch) MatchState {
			switch match(m) {
			case engine.Yes:
				return Yes
			case engine.No:
				return No
			default:
				return Maybe
			}
		}
	}
	return out
}

func cloneKeepEmpty(s []string) []string {
	if s == nil {
		return nil
	}
	return append(make([]string, 0, len(s)), s...)
}

// ToEngineVerdict narrows the engine policy p by v.
func ToEngineVerdict(p engine.Policy, v Verdict) engine.AdminVerdict {
	narrowed := p
	// nil is "no limit" and an empty list "nothing allowed" (the engine's
	// intersectAliases); a copy must keep that apart.
	narrowed.AllowedAliases = cloneKeepEmpty(p.AllowedAliases)
	if v.Allowed != nil {
		if narrowed.AllowedAliases == nil {
			narrowed.AllowedAliases = cloneKeepEmpty(v.Allowed)
		} else {
			narrowed.AllowedAliases = intersect(narrowed.AllowedAliases, v.Allowed)
		}
	}
	for _, d := range v.Defaults {
		if narrowed.AllowedAliases == nil || contains(narrowed.AllowedAliases, d) {
			narrowed.DefaultAlias = d
			break
		}
	}
	out := engine.AdminVerdict{Policy: narrowed, Bind: v.Bind, Force: clone(v.Force), Warnings: clone(v.Warnings),
		RuleIDs: clone(v.RuleIDs), ChargeKeys: clone(v.ChargeKeys)}
	if v.Deny != nil {
		out.Deny = &engine.DenyReason{Code: v.Deny.Code, Message: v.Deny.Message}
	}
	return out
}
