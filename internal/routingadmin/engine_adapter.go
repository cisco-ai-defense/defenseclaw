// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	ids    []string       // budget ids of the newest generation
	capped []CappedBudget // its actor and batch budgets (CappedBudgets)
	last   *config.Config
	lastEv *evaluator
	// applied is the newest generation Apply installed (start and every
	// reload). A request still pinned to an older one gets its evaluator from
	// For but never replaces the newest budget ids or restarts the sync loop
	// of budgets the reload removed (GAP-1856). nil (no Apply yet) leaves
	// every generation newest.
	applied *config.Config
	ctx     context.Context
	local   SpendCounter // this device's store (per-device budgets and the fallback)
	fleet   SpendCounter // optional: shared by devices or gateway replicas
	keys    FleetKeys    // local <-> fleet key forms (nil: the same keys)
	// feed is true once agent call costs reach Charge (the usage engine
	// records agent calls with a computed cost); until then budgets read
	// as not loaded, so a managed deny budget refuses instead of counting 0.
	feed     bool
	interval time.Duration
	// staleAfter is the ledger's trust window of remote spend (0: none).
	staleAfter time.Duration
	epoch      string
	writer     string      // the last fleet writer id (device), kept while no fleet is set
	syncW      *syncWorker // the running sync loop (nil: none)
	sumsAt     time.Time   // the last good PrefixSums read
	kick       chan struct{}
	// budgeted mirrors len(ids) > 0, so For with no routing.admin (the
	// per-request default) stays lock-free while no budget ever ran.
	budgeted atomic.Bool
	pushMu   sync.Mutex // one push at a time: snapshot and send stay in order

	callsMu   sync.Mutex
	calls     map[string]struct{}
	callOrder []string

	// now is the clock the ledger, the sync and the evaluator read (nil: the
	// real clock, always so in production).
	now func() time.Time
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

// SetStaleAfter sets how long remote spend is trusted after the last answer
// of the counter (a cluster replica: 3 x the sync interval; 0: for ever).
func (rt *Runtime) SetStaleAfter(d time.Duration) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	rt.staleAfter = d
	ledger := rt.ledger
	rt.mu.Unlock()
	ledger.SetStaleAfter(d)
}

// DefaultSyncInterval is how often the ledger stores this process's spend
// and reads everyone else's.
const DefaultSyncInterval = 30 * time.Second

// NewRuntime returns an empty runtime; it costs nothing until a config
// with routing.admin rules or budgets is compiled.
func NewRuntime() *Runtime {
	return &Runtime{interval: DefaultSyncInterval, kick: make(chan struct{}, 1), epoch: newEpoch()}
}

// NewRuntimeClock returns an empty runtime whose ledger, sync and evaluator read
// now instead of the real clock (nil: the real clock, as NewRuntime). For
// tests and replays that pin a date.
func NewRuntimeClock(now func() time.Time) *Runtime {
	rt := NewRuntime()
	rt.now = now
	return rt
}

// clock is the runtime time source.
func (rt *Runtime) clock() time.Time {
	if rt != nil && rt.now != nil {
		return rt.now()
	}
	return time.Now()
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
	next := rt.epoch
	if fleet != nil {
		rt.writer = writerOf(fleet)
	}
	rt.fleet, rt.keys = fleet, keys
	rt.last, rt.lastEv = nil, nil
	rt.mu.Unlock()
	if rotate && ledger != nil {
		if p := ledger.TakePush(); !p.Empty() {
			if ctx == nil {
				ctx = context.Background()
			}
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			var err error
			if local != nil {
				err = pushTo(pctx, local, ledger, p)
			}
			if old != nil && old != fleet && len(p.Main) > 0 {
				// The old credential's last word, so other devices see it.
				_ = old.Push(pctx, epoch, toFleet(p.Main, oldKeys))
			}
			ledger.PushResult(err)
			cancel()
		}
		ledger.Rotate(next)
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

// Apply makes cfg the newest generation and compiles it (start and every
// reload): its budget ids replace the old ones, so the sync loop stops when a
// reload removes every budget and starts when one adds them. It returns the
// evaluator of cfg, as For.
func (rt *Runtime) Apply(cfg *config.Config) engine.AdminEvaluator {
	if rt == nil || cfg == nil {
		return nil
	}
	rt.mu.Lock()
	rt.applied = cfg
	rt.mu.Unlock()
	return rt.For(cfg)
}

// newestLocked reports whether cfg is the newest generation: the one Apply
// installed last, or any while Apply never ran. rt.mu is held.
func (rt *Runtime) newestLocked(cfg *config.Config) bool {
	return rt.applied == nil || rt.applied == cfg
}

// For returns the admin evaluator of cfg, or nil when cfg has no
// routing.admin rules or budgets (the engine then skips it). Only the newest
// generation sets the budget ids and the sync loop; a request pinned to an
// older one during a reload gets its own evaluator and changes neither.
func (rt *Runtime) For(cfg *config.Config) engine.AdminEvaluator {
	if rt == nil || cfg == nil {
		return nil
	}
	if cfg.Routing.Admin == nil {
		// routing.admin removed: stop the sync loop of the budgets it had.
		if rt.budgeted.Load() {
			rt.mu.Lock()
			if rt.newestLocked(cfg) {
				rt.last, rt.lastEv = cfg, nil
				rt.setIDsLocked(nil)
			}
			rt.mu.Unlock()
		}
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
	policy.SetLauncherAtespaces(cfg.Substrate.LauncherAtespaces)
	if policy == nil {
		rt.mu.Lock()
		if rt.newestLocked(cfg) {
			rt.last, rt.lastEv = cfg, nil
			rt.setIDsLocked(nil)
		}
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
		rt.ledger = NewLedgerClock(rt.now)
		rt.ledger.SetStaleAfter(rt.staleAfter)
		rt.ledger.SetEpoch(rt.epoch)
	}
	if rt.ledger != nil {
		rt.ledger.SetHoldFull(policy.HoldFullIDs())
	}
	if rt.feed {
		ev.ledger = rt.ledger
	}
	if !rt.newestLocked(cfg) {
		// An older generation still in flight: its evaluator only.
		rt.mu.Unlock()
		return ev
	}
	rt.last, rt.lastEv = cfg, ev
	rt.setIDsLocked(policy.BudgetIDs())
	rt.capped = policy.CappedBudgets()
	rt.mu.Unlock()
	rt.startSync()
	return ev
}

// syncWorker is one run of the sync loop; stop ends it after a last push.
type syncWorker struct{ stop context.CancelFunc }

// setIDsLocked installs the budget ids of the newest generation. No ids (a
// reload without budgets or without routing.admin) stops the sync loop, so
// no SQLite read, spend write or fleet request outlives the budgets
// (rel-1-0-10:GAP-1716). rt.mu is held.
func (rt *Runtime) setIDsLocked(ids []string) {
	rt.ids, rt.capped = ids, nil
	rt.budgeted.Store(len(ids) > 0)
	if len(ids) == 0 && rt.syncW != nil {
		rt.syncW.stop()
		rt.syncW = nil
	}
}

// startSync runs the sync loop once budgets and a counter exist, and asks a
// running loop to sync now (new budget ids after a reload).
func (rt *Runtime) startSync() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.ledger == nil || rt.local == nil || rt.ctx == nil || len(rt.ids) == 0 {
		return
	}
	if rt.syncW != nil {
		select {
		case rt.kick <- struct{}{}:
		default:
		}
		return
	}
	ctx, stop := context.WithCancel(rt.ctx)
	w := &syncWorker{stop: stop}
	rt.syncW = w
	go rt.syncLoop(ctx, w)
}

// syncLoop syncs until ctx ends (the gateway stops, or the budgets went),
// then stores this process's spend one last time.
func (rt *Runtime) syncLoop(ctx context.Context, w *syncWorker) {
	defer func() {
		w.stop()
		rt.mu.Lock()
		if rt.syncW == w {
			rt.syncW = nil
		}
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
	capped, interval, sumsAt := rt.capped, rt.interval, rt.sumsAt
	rt.mu.Unlock()
	now := rt.clock()
	if ledger == nil || local == nil {
		return
	}
	rt.push(ctx)
	since := KeepSince(rt.clock())
	var rows []SeedRow
	var err error
	// This device's earlier processes always count: a fleet answer that
	// leaves them out (a user with no fleet id, a store that lost data) can
	// never lower what this device already knows.
	// The capped keys (actor:, batch:) are read by list: only the ones this
	// process holds, so launcher-minted keys never make the read too large
	// (a key new here gets the others' spend at the next sync). A counter
	// that reads by key (the cluster leader) also names the keys at or over
	// a blocking budget's limit, so a blocked key this process let go stays
	// blocked here until the next read (GAP-0892).
	var localRows []SeedRow
	var localErr error
	var overFull []string
	if or, ok := local.(OverReader); ok && len(capped) > 0 {
		localRows, overFull, localErr = or.TotalsOver(ctx, epoch, since, ledger.CappedKeys(), overQueries(capped, ledger.KeyCap(), now))
	} else {
		localRows, localErr = local.Totals(ctx, epoch, since, ledger.CappedKeys())
	}
	if localErr == nil {
		ledger.SetOverFull(overFull)
	}
	// The admin view of an actor or batch budget sums every replica's keys:
	// the leader's per-budget sums, read at most once per interval
	// (GAP-0894). A failed read keeps the last sums until they expire.
	if sr, ok := local.(SumReader); ok && len(capped) > 0 && (sumsAt.IsZero() || now.Sub(sumsAt) >= interval) {
		q := sumQueries(capped, now)
		if sums, err := sr.PrefixSums(ctx, epoch, q); err == nil {
			ledger.SetPrefixSums(q, sums, now.Add(2*interval))
			rt.mu.Lock()
			rt.sumsAt = now
			rt.mu.Unlock()
		}
	}
	// A call of unknown cost on one replica keeps its user, actor or batch
	// key unknown on every replica within about one sync interval, as known
	// spend is: the leader holds the marks for UnknownTTL
	// (substrate-1:GAP-1118). A leader without the method (an older release
	// during an upgrade) leaves each replica its own marks.
	if us, ok := local.(UnknownSharer); ok {
		if marks, err := us.ShareUnknown(ctx, epoch, ledger.UnknownMarks(now)); err == nil {
			ledger.MergeUnknown(marks)
		}
	}
	if fleet != nil {
		if rows, err = fleet.Totals(ctx, epoch, since, fleetWanted(ledger, keys)); err == nil {
			ledger.ApplyRemote(ids, maxRows(fromFleet(rows, keys), localRows), rt.clock())
			ledger.MarkFleetRead(rt.clock())
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
	ledger.ApplyRemote(ids, localRows, rt.clock())
	if fleet != nil {
		// Keep why: the store down, the device refused, a budget it lacks.
		ledger.SyncFailed(fmt.Errorf("%w (%v)", errFleetFallback, err))
	}
}

// OverReader is a counter that answers a by-key read with the keys at or
// over the limits of over too (LeaderCounter), and lists the budgets of
// over with more such keys than OverQuery.Max.
type OverReader interface {
	TotalsOver(ctx context.Context, epoch string, since time.Time, keys []string, over []OverQuery) ([]SeedRow, []string, error)
}

// overQueries asks, per blocking budget, for at most keyCap of its keys at
// or over the limit in the period that contains now.
func overQueries(budgets []CappedBudget, keyCap int, now time.Time) []OverQuery {
	if keyCap <= 0 {
		keyCap = DefaultKeyCap
	}
	out := make([]OverQuery, 0, len(budgets))
	for _, b := range budgets {
		if b.Blocks {
			out = append(out, OverQuery{Prefix: b.Prefix, Since: windowDate(b.Period, now), Limit: b.LimitUSD, Max: keyCap})
		}
	}
	return out
}

// SumReader is a counter that sums the stored spend of a budget's keys,
// every epoch, in the leader (LeaderCounter): the admin view of a cluster.
type SumReader interface {
	PrefixSums(ctx context.Context, epoch string, q []SumQuery) ([]PrefixSum, error)
}

// KeyReader is a counter that reads every other epoch's spend of the listed
// keys only (LeaderCounter): the substrate actor list of a cluster.
type KeyReader interface {
	TotalsKeys(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error)
}

func sumQueries(budgets []CappedBudget, now time.Time) []SumQuery {
	out := make([]SumQuery, 0, len(budgets))
	for _, b := range budgets {
		out = append(out, SumQuery{Prefix: b.Prefix, Since: windowDate(b.Period, now), Limit: b.LimitUSD})
	}
	return out
}

// windowDate is the first UTC day of period's window that contains now.
func windowDate(period string, now time.Time) time.Time {
	return time.Unix(int64(windowStart(period, now))*86400, 0).UTC()
}

// ReadViewKeys reads, for an administrator's view (the substrate actor
// list), every other replica's spend of the listed actor and batch keys
// this replica may not hold, at most maxViewKeys of them, kept for one sync
// interval (Ledger.ViewSpend). A device counter reads every key already: it
// does nothing then.
func (rt *Runtime) ReadViewKeys(ctx context.Context, keys []string) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	ledger, local, epoch, interval := rt.ledger, rt.local, rt.epoch, rt.interval
	rt.mu.Unlock()
	kr, ok := local.(KeyReader)
	if !ok || ledger == nil {
		return
	}
	want := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		if capped(k) && !seen[k] {
			seen[k] = true
			want = append(want, k)
		}
	}
	if len(want) == 0 || len(want) > maxViewKeys {
		return
	}
	sort.Strings(want)
	now := rt.clock()
	rows, err := kr.TotalsKeys(ctx, epoch, KeepSince(now), want)
	if err != nil {
		return
	}
	ledger.SetViewKeys(want, rows, now.Add(interval))
}

// maxViewKeys bounds one ReadViewKeys.
const maxViewKeys = 20000

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
	p := ledger.TakePush()
	if p.Empty() {
		return
	}
	var failed error
	if local != nil {
		failed = pushTo(ctx, local, ledger, p)
	}
	// The retired generation and the evicted keys' rows (Stored, Unstored,
	// Old) are of capped keys (actor:, batch:), which have no fleet form:
	// they stay with this device's or cluster's counter.
	if fleet != nil && len(p.Main) > 0 {
		if err := fleet.Push(ctx, epoch, toFleet(p.Main, rt.fleetKeys())); err != nil && failed == nil {
			failed = err
		}
	}
	ledger.PushResult(failed)
}

// pushTo stores p with c: the frozen generation of evicted keys' spend
// first, under its own epoch, then the process epoch. An evicted key's rows
// there hold what this process still has of it: with the generation stored
// that is its local spend (0 clears what moved), without it the moved
// spend too, so a failed push counts it twice for a sync interval at worst,
// never not at all. The rows under earlier epochs wait for the generation.
func pushTo(ctx context.Context, c SpendCounter, ledger *Ledger, p PushSet) error {
	var failed error
	note := func(err error) {
		if failed == nil {
			failed = err
		}
	}
	retiredOK := true
	if len(p.Retired) > 0 {
		if err := c.Push(ctx, p.RetiredEpoch, p.Retired); err != nil {
			note(err)
			retiredOK = false
		} else {
			ledger.RetiredStored(p)
		}
	}
	rows, tombs := p.Main, p.Unstored
	if retiredOK {
		tombs = p.Stored
	}
	if len(tombs) > 0 {
		rows = append(append(make([]SeedRow, 0, len(p.Main)+len(tombs)), p.Main...), tombs...)
	}
	ok := retiredOK
	if len(rows) > 0 {
		if err := c.Push(ctx, p.Epoch, rows); err != nil {
			note(err)
			ok = false
		}
	}
	if retiredOK {
		for _, epoch := range slices.Sorted(maps.Keys(p.Old)) {
			if err := c.Push(ctx, epoch, p.Old[epoch]); err != nil {
				note(err)
				ok = false
			}
		}
	}
	if ok {
		ledger.TombsStored(p)
	}
	return failed
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
		Caller:           CallerFromEngine(r.Caller, e.policy.Managed || r.Caller.Actor != nil),
		Actor:            r.Caller.Actor,
		Connector:        config.NormalizeConnectorName(r.Connector),
		Category:         category,
		ClassifierFailed: classifierFailed,
		Severity:         r.Severity,
	}
	v := e.policy.Evaluate(req, e.ledger, e.rt.clock())
	return ToEngineVerdict(p, v)
}

// Gate checks one forwarded exit against the verdict.
func (e *evaluator) Gate(v engine.AdminVerdict, target engine.GateTarget, managed bool) *engine.DenyReason {
	verdict := Verdict{Bind: v.Bind, Force: v.Force, RuleIDs: v.RuleIDs, BindRuleIDs: v.BindRuleIDs}
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
// selectors (meant for managed multi-user devices) do not match. perCaller
// is true on a managed device and for an actor call (its person key).
func CallerFromEngine(c engine.Caller, perCaller bool) Caller {
	if !perCaller {
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
		RuleIDs: clone(v.RuleIDs), BindRuleIDs: clone(v.BindRuleIDs), ChargeKeys: clone(v.ChargeKeys), Enforce: v.Enforce}
	if v.Deny != nil {
		out.Deny = &engine.DenyReason{Code: v.Deny.Code, Message: v.Deny.Message}
	}
	return out
}
