// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
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
	hash   func(string) string
	// feed is true once agent call costs reach Charge (the usage engine
	// records agent calls with a computed cost); until then budgets read
	// as not loaded, so a managed deny budget refuses instead of counting 0.
	feed     bool
	interval time.Duration
	epoch    string
	syncing  bool
	kick     chan struct{}
}

// DefaultSyncInterval is how often the ledger stores this process's spend
// and reads everyone else's.
const DefaultSyncInterval = 30 * time.Second

// NewRuntime returns an empty runtime; it costs nothing until a config
// with routing.admin rules or budgets is compiled.
func NewRuntime() *Runtime {
	return &Runtime{interval: DefaultSyncInterval, kick: make(chan struct{}, 1),
		epoch: strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)}
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

// SetFleet installs (or, with a nil counter, removes) the fleet counter, its
// key mapping and the subject hash budget keys use (a keyed hash shared by
// the fleet; nil = the device-only hash). Generations compile again.
func (rt *Runtime) SetFleet(fleet SpendCounter, keys FleetKeys, hash func(string) string) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	rt.fleet, rt.keys, rt.hash = fleet, keys, hash
	rt.last, rt.lastEv = nil, nil
	rt.mu.Unlock()
	rt.startSync()
}

// Charge counts a priced agent call against its budget keys (the usage
// engine calls it with the computed cost when the call ends).
func (rt *Runtime) Charge(keys []string, usd float64, at time.Time) {
	if l := rt.Ledger(); l != nil {
		l.Charge(keys, usd, at)
	}
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
	hash := rt.hash
	rt.mu.Unlock()
	a := cfg.Routing.Admin
	policy := CompileWith(a.Rules, a.Budgets, cfg.StandaloneEnterprise(), hash)
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
	if fleet != nil {
		if rows, err = fleet.Totals(ctx, epoch, since, fleetWanted(ledger, keys)); err == nil {
			ledger.ApplyRemote(ids, fromFleet(rows, keys), time.Now())
			return
		}
		ledger.SyncFailed(err)
	}
	if rows, err = local.Totals(ctx, epoch, since, nil); err != nil {
		ledger.SyncFailed(err)
		return
	}
	ledger.ApplyRemote(ids, rows, time.Now())
	if fleet != nil {
		ledger.SyncFailed(errFleetFallback)
	}
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
