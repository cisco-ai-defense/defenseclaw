// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"container/list"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// LedgerDays is how many UTC days of spend a counter file keeps (the
// ledger itself keeps only the days a budget window reads, keepFrom).
const LedgerDays = 62

// Ledger is the budget spend the evaluator reads, per charge key and UTC
// day: local is what this gateway process charged (the usage engine calls
// Charge with the computed cost of each agent call), remote is every other
// writer's spend from the counters (earlier processes on this device, other
// devices or replicas), replaced on each sync. It exists only while budgets
// are configured and is carried across config reloads.
type Ledger struct {
	mu     sync.Mutex
	local  map[string]map[int32]float64
	remote map[string]map[int32]float64
	// unknown holds, per user key, when it last had a call whose usage no
	// price covers (UnknownTTL).
	unknown map[string]time.Time
	// seeded holds the budget ids whose remote spend has been read once.
	seeded map[string]bool
	// lru orders the local keys of each launcher-keyed budget (scope actor and
	// batch), per budget id, so one budget holds at most KeyCap keys in
	// memory; evicted holds the budget ids that lost keys since the verdict
	// last reported it.
	lru     map[string]*keyLRU
	evicted map[string]int
	keyCap  int
	// retired is the spend of keys the cap evicted that no counter has stored
	// yet: it still counts here, and the next push stores it under
	// RetiredEpoch(epoch, retiredGen), an epoch of its own, so a re-charged
	// key adds to it instead of replacing it. retiredDirty is set when it
	// grew after TakePush. tombs holds the evicted keys whose process-epoch
	// rows still carry the moved spend: the next push stores 0 for those
	// days (once the retired rows are stored), so nothing counts twice.
	retired      map[string]map[int32]float64
	retiredGen   int
	retiredDirty bool
	tombs        map[string]tomb
	tombSeq      uint64
	syncErr      string
	pushErr      string
	lastSync     time.Time
	// lastFleet is when the fleet counter last answered (a fallback to this
	// device's own store does not count), for the store gauges.
	lastFleet time.Time
	lastPrune int32
	now       func() time.Time
	// staleAfter, when set, is how long the remote spend stays good after the
	// last answer of its counter: past it the budgets read as not loaded
	// (spend unknown), never as the last totals forever. A cluster replica
	// sets it to 3 x the sync interval, so a lost leader is not a free pass
	// and not a block on a slow answer (D4-2).
	staleAfter time.Duration
}

// SetStaleAfter sets how long remote spend is trusted after the last answer
// (0: for ever, as on a device).
func (l *Ledger) SetStaleAfter(d time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.staleAfter = d
	l.mu.Unlock()
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{local: map[string]map[int32]float64{}, remote: map[string]map[int32]float64{},
		unknown: map[string]time.Time{}, seeded: map[string]bool{}, now: time.Now,
		lru: map[string]*keyLRU{}, evicted: map[string]int{}, keyCap: DefaultKeyCap,
		retired: map[string]map[int32]float64{}, tombs: map[string]tomb{}}
}

// NewLedgerClock returns an empty ledger that reads today from now (nil is the
// real clock). Charge, MarkUnknown and the day pruning use it, so a charge is
// never moved to the real today when now is another date: a test or a replay
// owns its clock and gets the same answer on any day.
func NewLedgerClock(now func() time.Time) *Ledger {
	l := NewLedger()
	if now != nil {
		l.now = now
	}
	return l
}

// Charge adds usd to every key on the UTC day of at. Non-positive or
// non-finite amounts are ignored (absent cost adds nothing); a charge dated
// in the future (a clock step) counts today.
func (l *Ledger) Charge(keys []string, usd float64, at time.Time) {
	if l == nil || len(keys) == 0 || !(usd > 0) || math.IsInf(usd, 0) {
		return
	}
	today := dayNumber(l.now())
	day := dayNumber(at)
	if day > today {
		day = today
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		days := l.local[key]
		if days == nil {
			days = map[int32]float64{}
			l.local[key] = days
		}
		days[day] += usd
		l.touchLocked(key)
	}
	if today != l.lastPrune {
		l.pruneLocked(today)
	}
}

// UnknownTTL is how long one call of unknown cost keeps the caller's own
// budget unknown (a stream cut short, usage no price covers).
const UnknownTTL = 10 * time.Minute

// MarkUnknown records a call whose usage no price covers. Only keys of one
// caller are marked: user: (the person), actor: (one agent) and batch: (one
// person's batch), so an agent that cuts its streams or calls an unpriced
// model is still bounded. One person's unpriced call never blocks a group or
// connector budget others share.
func (l *Ledger) MarkUnknown(keys []string, at time.Time) {
	if l == nil {
		return
	}
	if now := l.now(); at.After(now) {
		at = now
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		if strings.HasPrefix(key, "user:") || capped(key) {
			l.unknown[key] = at
		}
	}
}

// Unknown reports whether the key had a call of unknown cost within
// UnknownTTL (and inside the current period window).
func (l *Ledger) Unknown(key, period string, now time.Time) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	at, ok := l.unknown[key]
	if !ok {
		return false
	}
	return now.Sub(at) < UnknownTTL && dayNumber(at) >= windowStart(period, now)
}

// Spend returns the key's spend (local and remote) in the current period
// window and whether its budget's remote spend is loaded.
func (l *Ledger) Spend(key, period string, now time.Time) (float64, bool) {
	if l == nil {
		return 0, false
	}
	today, from := dayNumber(now), windowStart(period, now)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.seeded[budgetIDOfKey(key)] || l.staleLocked(now) {
		return 0, false
	}
	return l.windowLocked(key, from, today), true
}

// staleLocked is true when the remote spend outlived staleAfter.
func (l *Ledger) staleLocked(now time.Time) bool {
	return l.staleAfter > 0 && !l.lastSync.IsZero() && now.Sub(l.lastSync) > l.staleAfter
}

// SpendPrefix sums the spend of every key that starts with prefix
// (<scope>:<id>: gives all subjects of one budget, for administrators).
func (l *Ledger) SpendPrefix(prefix, period string, now time.Time) (float64, bool) {
	snap, ok := l.Snapshot(prefix, period, 0, now)
	return snap.Total, ok
}

// windowLocked sums in day order, so the same state gives the same total.
func (l *Ledger) windowLocked(key string, from, today int32) float64 {
	var total float64
	local, remote, retired := l.local[key], l.remote[key], l.retired[key]
	for day := from; day <= today; day++ {
		total += local[day] + remote[day] + retired[day]
	}
	return total
}

// SeedRow is the spend of one charge key on one UTC day.
type SeedRow struct {
	Day string // UTC date, YYYY-MM-DD
	Key string
	USD float64
}

// LocalRows returns this process's spend for the counters to store.
func (l *Ledger) LocalRows() []SeedRow {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return rowsOf(l.local)
}

// rowsOf lists m as rows in (day, key) order.
func rowsOf(m map[string]map[int32]float64) []SeedRow {
	var rows []SeedRow
	for key, days := range m {
		for day, usd := range days {
			rows = append(rows, SeedRow{Day: dayDate(day), Key: key, USD: usd})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Day != rows[j].Day {
			return rows[i].Day < rows[j].Day
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

// tomb is one evicted key's process-epoch days to store as 0.
type tomb struct {
	seq  uint64
	days []int32
}

// RetiredEpoch is the epoch the evicted keys' spend of generation gen is
// stored under (it passes every counter's epoch check).
func RetiredEpoch(epoch string, gen int) string {
	return epoch + ".r" + strconv.Itoa(gen)
}

// PushSet is one push of this process's spend (TakePush).
type PushSet struct {
	// Main is the local spend, under the process epoch.
	Main []SeedRow
	// Zero sets the process-epoch rows of evicted keys to 0; it is sent with
	// Main only once Retired is stored.
	Zero []SeedRow
	// Retired is the evicted keys' spend, under RetiredEpoch(epoch, Gen).
	Retired []SeedRow
	Gen     int
	tombs   map[string]uint64
}

// Empty reports whether there is nothing to store.
func (p PushSet) Empty() bool { return len(p.Main) == 0 && len(p.Zero) == 0 && len(p.Retired) == 0 }

// TakePush returns what the next push stores. Call RetiredStored and
// ZeroStored with it after the counter acked each part.
func (l *Ledger) TakePush() PushSet {
	if l == nil {
		return PushSet{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := PushSet{Main: rowsOf(l.local), Retired: rowsOf(l.retired), Gen: l.retiredGen}
	l.retiredDirty = false
	if len(l.tombs) > 0 {
		p.tombs = make(map[string]uint64, len(l.tombs))
		for key, t := range l.tombs {
			p.tombs[key] = t.seq
			for _, day := range t.days {
				if _, charged := l.local[key][day]; !charged {
					p.Zero = append(p.Zero, SeedRow{Day: dayDate(day), Key: key})
				}
			}
		}
	}
	return p
}

// RetiredStored records that the counter stored p.Retired: unless more keys
// were evicted since TakePush (the next push sends the whole generation
// again), that spend counts as remote until the next sync reads it back and
// the next generation starts empty.
func (l *Ledger) RetiredStored(p PushSet) {
	if l == nil || len(p.Retired) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.Gen != l.retiredGen || l.retiredDirty {
		return
	}
	moveLocked(l.remote, l.retired)
	l.retired = map[string]map[int32]float64{}
	l.retiredGen++
}

// ZeroStored records that the counter stored p.Zero (tombs of keys evicted
// again since TakePush stay).
func (l *Ledger) ZeroStored(p PushSet) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, seq := range p.tombs {
		if t, ok := l.tombs[key]; ok && t.seq == seq {
			delete(l.tombs, key)
		}
	}
}

// moveLocked adds src into dst.
func moveLocked(dst, src map[string]map[int32]float64) {
	for key, days := range src {
		d := dst[key]
		if d == nil {
			d = map[int32]float64{}
			dst[key] = d
		}
		for day, usd := range days {
			d[day] += usd
		}
	}
}

// TakeLocal returns this process's spend and moves it to the remote side
// (it keeps counting until the next sync reads it back from the store as
// an earlier writer's), leaving no local spend.
func (l *Ledger) TakeLocal() []SeedRow {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var rows []SeedRow
	for key, days := range l.local {
		for day, usd := range days {
			rows = append(rows, SeedRow{Day: dayDate(day), Key: key, USD: usd})
		}
	}
	moveLocked(l.remote, l.local)
	l.local = map[string]map[int32]float64{}
	l.lru = map[string]*keyLRU{}
	// The old epoch is closed: its rows of evicted keys are no longer
	// written (if their 0 was not stored, they count twice, never not at all).
	l.tombs = map[string]tomb{}
	return rows
}

// ApplyRemote replaces the remote spend with rows and marks ids synced.
func (l *Ledger) ApplyRemote(ids []string, rows []SeedRow, at time.Time) {
	if l == nil {
		return
	}
	remote := map[string]map[int32]float64{}
	for _, row := range rows {
		date, err := time.Parse(time.DateOnly, row.Day)
		if err != nil || !(row.USD > 0) || math.IsInf(row.USD, 0) {
			continue
		}
		days := remote[row.Key]
		if days == nil {
			days = map[int32]float64{}
			remote[row.Key] = days
		}
		days[dayNumber(date)] += row.USD
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.remote = remote
	for _, id := range ids {
		l.seeded[id] = true
	}
	l.syncErr, l.lastSync = "", at
}

// SyncFailed records a failed sync; remote spend already read stays.
func (l *Ledger) SyncFailed(err error) {
	if l == nil || err == nil {
		return
	}
	l.mu.Lock()
	l.syncErr = err.Error()
	l.mu.Unlock()
}

// PushResult records whether this process's spend was stored (an error
// stays until a push succeeds, independent of reads).
func (l *Ledger) PushResult(err error) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if err != nil {
		l.pushErr = err.Error()
	} else {
		l.pushErr = ""
	}
	l.mu.Unlock()
}

// Seeded reports whether the budget's remote spend has been read.
func (l *Ledger) Seeded(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seeded[id]
}

// SeedState is seeded, seeding, failed: <error> (never read) or
// seeded (stale: <error>) (read once, the last sync failed), for doctor and
// status.
func (l *Ledger) SeedState(ids []string) string {
	if l == nil {
		return "seeding"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range ids {
		if !l.seeded[id] {
			if l.syncErr != "" {
				return "failed: " + l.syncErr
			}
			return "seeding"
		}
	}
	if l.syncErr != "" {
		return "seeded (stale: " + l.syncErr + ")"
	}
	if l.pushErr != "" {
		return "seeded (not stored: " + l.pushErr + ")"
	}
	return "seeded"
}

// keepFrom is the first day any budget period window that contains today
// reads (a week can start in the previous month), the oldest day the ledger
// keeps and asks the counters for.
func keepFrom(today int32) int32 {
	t := time.Unix(int64(today)*86400, 0).UTC()
	return min(windowStart(config.RoutingBudgetPeriodWeek, t), windowStart(config.RoutingBudgetPeriodMonth, t))
}

// KeepSince is the UTC midnight of keepFrom for now (the counters' since).
func KeepSince(now time.Time) time.Time {
	return time.Unix(int64(keepFrom(dayNumber(now)))*86400, 0).UTC()
}

func (l *Ledger) pruneLocked(today int32) {
	l.lastPrune = today
	oldest := keepFrom(today)
	for key, t := range l.tombs {
		kept := t.days[:0]
		for _, day := range t.days {
			if day >= oldest {
				kept = append(kept, day)
			}
		}
		if t.days = kept; len(kept) == 0 {
			delete(l.tombs, key)
		} else {
			l.tombs[key] = t
		}
	}
	for i, m := range []map[string]map[int32]float64{l.local, l.remote, l.retired} {
		isLocal := i == 0
		for key, days := range m {
			for day := range days {
				if day < oldest {
					delete(days, day)
				}
			}
			if len(days) == 0 {
				delete(m, key)
				if isLocal {
					l.forgetLocked(key)
				}
			}
		}
	}
	for key, at := range l.unknown {
		if dayNumber(at) < oldest {
			delete(l.unknown, key)
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

func dayDate(day int32) string {
	return time.Unix(int64(day)*86400, 0).UTC().Format(time.DateOnly)
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

// BudgetSnapshot is the spend of every subject of one budget in its current
// window, for the budget gauges: Total is every subject added, Peak the
// highest single subject, Exceeded how many subjects are at or over the limit.
type BudgetSnapshot struct {
	Total, Peak float64
	Subjects    int
	Exceeded    int
}

// Snapshot summarises the spend of every key that starts with prefix
// (<scope>:<id>:). The second result is false while the budget's remote spend
// is still loading, so an absent spend is never reported as 0.
func (l *Ledger) Snapshot(prefix, period string, limit float64, now time.Time) (BudgetSnapshot, bool) {
	var snap BudgetSnapshot
	if l == nil {
		return snap, false
	}
	today, from := dayNumber(now), windowStart(period, now)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.seeded[budgetIDOfKey(prefix)] {
		return snap, false
	}
	keys := map[string]bool{}
	for _, m := range []map[string]map[int32]float64{l.local, l.remote, l.retired} {
		for k := range m {
			if strings.HasPrefix(k, prefix) {
				keys[k] = true
			}
		}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		v := l.windowLocked(k, from, today)
		snap.Total += v
		snap.Subjects++
		if v > snap.Peak {
			snap.Peak = v
		}
		if limit > 0 && v >= limit {
			snap.Exceeded++
		}
	}
	return snap, true
}

// MarkFleetRead records that the fleet counter answered at the given time.
func (l *Ledger) MarkFleetRead(at time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.lastFleet = at
	l.mu.Unlock()
}

// StoreStatus is the state of the fleet counter for the store gauges: how
// long ago the fleet counter last answered (synced false: it never has) and
// whether the last sync and the last push both worked.
func (l *Ledger) StoreStatus(now time.Time) (age time.Duration, synced, healthy bool) {
	if l == nil {
		return 0, false, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	healthy = l.syncErr == "" && l.pushErr == ""
	if l.lastFleet.IsZero() {
		return 0, false, healthy
	}
	return now.Sub(l.lastFleet), true, healthy
}

// DefaultKeyCap is how many keys one launcher-keyed budget (scope actor or
// batch) holds in memory. Those keys follow ids a launcher chooses, one per
// run, so a runaway or hostile launcher could mint them without end; the
// other scopes are bounded by the people, groups and connectors an admin
// lists. Past the cap the least recently charged key of that budget is
// dropped from this process's keys: its spend moves to the retired rows,
// which still count here and are stored under an epoch of their own
// (RetiredEpoch), so the key's total never goes down, here or on the leader.
// The next verdict of the budget carries budget_keys_evicted:<id>.
const DefaultKeyCap = 4096

// keyLRU is the recency order of one budget's local keys.
type keyLRU struct {
	order *list.List // front = most recent; values are charge keys
	at    map[string]*list.Element
}

// capped reports whether the key belongs to a launcher-keyed budget.
func capped(key string) bool {
	return strings.HasPrefix(key, "actor:") || strings.HasPrefix(key, "batch:")
}

// touchLocked marks key as the most recently charged of its budget and drops
// the least recent keys past the cap. The caller holds l.mu.
func (l *Ledger) touchLocked(key string) {
	if !capped(key) || l.keyCap <= 0 {
		return
	}
	id := budgetIDOfKey(key)
	q := l.lru[id]
	if q == nil {
		q = &keyLRU{order: list.New(), at: map[string]*list.Element{}}
		l.lru[id] = q
	}
	if e, ok := q.at[key]; ok {
		q.order.MoveToFront(e)
		return
	}
	q.at[key] = q.order.PushFront(key)
	for q.order.Len() > l.keyCap {
		old := q.order.Back()
		k := old.Value.(string)
		q.order.Remove(old)
		delete(q.at, k)
		l.retireLocked(k)
		l.evicted[id]++
	}
}

// retireLocked moves an evicted key's local spend to the retired rows and
// marks its process-epoch days for 0.
func (l *Ledger) retireLocked(key string) {
	days := l.local[key]
	delete(l.local, key)
	if len(days) == 0 {
		return
	}
	r := l.retired[key]
	if r == nil {
		r = map[int32]float64{}
		l.retired[key] = r
	}
	l.tombSeq++
	t := tomb{seq: l.tombSeq, days: l.tombs[key].days}
	for day, usd := range days {
		r[day] += usd
		if !slices.Contains(t.days, day) {
			t.days = append(t.days, day)
		}
	}
	l.tombs[key] = t
	l.retiredDirty = true
}

// forgetLocked drops key from the recency order (the key left l.local).
func (l *Ledger) forgetLocked(key string) {
	if !capped(key) {
		return
	}
	id := budgetIDOfKey(key)
	if q := l.lru[id]; q != nil {
		if e, ok := q.at[key]; ok {
			q.order.Remove(e)
			delete(q.at, key)
		}
		if q.order.Len() == 0 {
			delete(l.lru, id)
		}
	}
}

// TakeEvicted reports, once, that budget id lost keys to the cap since the
// last call (the evaluator turns it into one warning on the audit row).
func (l *Ledger) TakeEvicted(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.evicted[id] == 0 {
		return false
	}
	delete(l.evicted, id)
	return true
}

// SetKeyCap sets the per-budget key cap (tests; 0 turns the cap off).
func (l *Ledger) SetKeyCap(n int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.keyCap = n
	l.mu.Unlock()
}

// LocalKeys is how many local keys the ledger holds for budget id (tests,
// gauges).
func (l *Ledger) LocalKeys(id string) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k := range l.local {
		if budgetIDOfKey(k) == id {
			n++
		}
	}
	return n
}
