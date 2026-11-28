// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"container/list"
	"maps"
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
	// retired is the spend of keys the cap evicted that no counter has
	// stored yet, in two parts that both still count here: retired takes
	// the evictions since the last push, and pending is the generation a
	// push froze (TakePush), stored under an epoch of its own,
	// RetiredEpoch(epoch, gen), fixed when it was frozen, so a re-charged
	// key adds to it instead of replacing it. Only the ack of that exact
	// generation clears it, and a failed one is sent again unchanged.
	// retiredLRU orders, per budget id, the keys of both parts (at most
	// keyCap of them; past it the oldest is dropped, except for the budgets
	// in holdFull, which refuse new keys instead: CapState). tombs holds the
	// evicted keys whose rows under an epoch of this process still carry
	// moved spend: the push stores there what this process still holds of
	// it, so nothing counts twice or not at all.
	retired    map[string]map[int32]float64
	pending    *retiredSet
	retiredGen int
	retiredLRU map[string]*keyLRU
	holdFull   map[string]bool
	// overFull holds the budget ids whose keys at or over the limit were
	// more than the last read could name (SetOverFull): a key this process
	// does not hold may be one of them (CapState, GAP-0892).
	overFull map[string]bool
	dropped  map[string]int
	// sums is the leader's per-budget sums of every epoch's keys, by
	// prefix, for the admin view until sumsUntil (SetPrefixSums); view the
	// other epochs' spend of keys an administrator listed, until viewUntil
	// (SetViewKeys). Neither is read on the request path (GAP-0894).
	sums      map[string]prefixSum
	sumsUntil time.Time
	view      map[string]map[int32]float64
	viewUntil time.Time
	tombs     map[tombKey]tomb
	tombSeq   uint64
	// epoch is the process epoch Main rows are stored under (SetEpoch,
	// Rotate).
	epoch    string
	syncErr  string
	pushErr  string
	lastSync time.Time
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
		retired: map[string]map[int32]float64{}, retiredLRU: map[string]*keyLRU{}, holdFull: map[string]bool{},
		dropped: map[string]int{}, tombs: map[tombKey]tomb{}}
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

// UnknownMark is the last call of unknown cost of one key. The replicas of
// a cluster share their marks through the leader on each sync, so a key one
// replica marked is unknown on every replica within about one sync
// interval, as known spend is (substrate-1:GAP-1118).
type UnknownMark struct {
	Key string
	At  time.Time
}

// UnknownMarks returns the marks of this ledger within UnknownTTL of now.
func (l *Ledger) UnknownMarks(now time.Time) []UnknownMark {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []UnknownMark
	for key, at := range l.unknown {
		if now.Sub(at) < UnknownTTL {
			out = append(out, UnknownMark{Key: key, At: at})
		}
	}
	return out
}

// MergeUnknown takes the marks other replicas made: a key keeps its latest
// mark, a mark dated after now counts from now, and only the keys
// MarkUnknown marks are taken.
func (l *Ledger) MergeUnknown(marks []UnknownMark) {
	if l == nil || len(marks) == 0 {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range marks {
		if !strings.HasPrefix(m.Key, "user:") && !capped(m.Key) {
			continue
		}
		at := m.At
		if at.After(now) {
			at = now
		}
		if now.Sub(at) >= UnknownTTL {
			continue
		}
		if prev, ok := l.unknown[m.Key]; !ok || at.After(prev) {
			l.unknown[m.Key] = at
		}
	}
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
	var pending map[int32]float64
	if l.pending != nil {
		pending = l.pending.spend[key]
	}
	for day := from; day <= today; day++ {
		total += local[day] + remote[day] + retired[day] + pending[day]
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

// retiredSet is one frozen generation of evicted keys' spend.
type retiredSet struct {
	gen   int
	epoch string // RetiredEpoch(process epoch, gen) when it was frozen
	spend map[string]map[int32]float64
}

// tombKey names one evicted key's rows under one epoch of this process.
type tombKey struct{ epoch, key string }

// tomb is the days of one evicted key whose rows still carry moved spend.
// gen is the retired generation that holds the key's latest moved spend;
// rest is the key's local spend when the epoch closed (Rotate), what its
// rows keep once that spend is stored.
type tomb struct {
	seq  uint64
	gen  int
	days []int32
	rest map[int32]float64
}

// RetiredEpoch is the epoch the evicted keys' spend of generation gen is
// stored under (it passes every counter's epoch check).
func RetiredEpoch(epoch string, gen int) string {
	return epoch + ".r" + strconv.Itoa(gen)
}

// PushSet is one push of this process's spend (TakePush).
type PushSet struct {
	// Epoch is the process epoch of Main, Stored and Unstored.
	Epoch string
	// Main is the local spend of the keys with no evicted spend in flight.
	Main []SeedRow
	// Retired is the frozen generation Gen of evicted keys' spend, under
	// RetiredEpoch (sent again unchanged until it is acked).
	Retired      []SeedRow
	RetiredEpoch string
	Gen          int
	// Stored and Unstored are the process-epoch rows of evicted keys: what
	// this process still holds of each, with Retired stored (Stored) or
	// not (Unstored). Old is the rows of evicted keys under earlier epochs
	// of this process (a writer rotation), sent only once Retired is
	// stored.
	Stored, Unstored []SeedRow
	Old              map[string][]SeedRow
	tombs            map[tombKey]uint64
}

// Empty reports whether there is nothing to store.
func (p PushSet) Empty() bool {
	return len(p.Main) == 0 && len(p.Retired) == 0 && len(p.Stored) == 0 && len(p.Unstored) == 0 && len(p.Old) == 0
}

// TakePush returns what the next push stores: it freezes the evictions
// since the last push into a generation of their own when none is in
// flight. Call RetiredStored once the counter acked p.Retired and
// TombsStored once it acked the rest.
func (l *Ledger) TakePush() PushSet {
	if l == nil {
		return PushSet{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil && len(l.retired) > 0 {
		l.pending = &retiredSet{gen: l.retiredGen, epoch: RetiredEpoch(l.epoch, l.retiredGen), spend: l.retired}
		l.retired = map[string]map[int32]float64{}
		l.retiredGen++
	}
	p := PushSet{Epoch: l.epoch, Gen: -1}
	var pending map[string]map[int32]float64
	if l.pending != nil {
		pending = l.pending.spend
		p.Retired, p.RetiredEpoch, p.Gen = rowsOf(pending), l.pending.epoch, l.pending.gen
	}
	if len(l.tombs) == 0 {
		p.Main = rowsOf(l.local)
		return p
	}
	main := make(map[string]map[int32]float64, len(l.local))
	for key, days := range l.local {
		if _, ok := l.tombs[tombKey{l.epoch, key}]; !ok {
			main[key] = days
		}
	}
	p.Main = rowsOf(main)
	p.tombs = make(map[tombKey]uint64, len(l.tombs))
	stored, unstored := map[string]map[int32]float64{}, map[string]map[int32]float64{}
	for tk, t := range l.tombs {
		// A tomb whose spend is in the open generation stays after this push.
		clears := t.gen < l.retiredGen
		if clears {
			p.tombs[tk] = t.seq
		}
		if tk.epoch != l.epoch {
			if clears {
				for _, day := range t.days {
					p.Old = appendOld(p.Old, tk.epoch, SeedRow{Day: dayDate(day), Key: tk.key, USD: t.rest[day]})
				}
				for day, usd := range t.rest {
					if !slices.Contains(t.days, day) {
						p.Old = appendOld(p.Old, tk.epoch, SeedRow{Day: dayDate(day), Key: tk.key, USD: usd})
					}
				}
			}
			continue
		}
		s, u := map[int32]float64{}, map[int32]float64{}
		for _, day := range t.days {
			s[day], u[day] = 0, 0
		}
		for _, m := range []map[int32]float64{l.local[tk.key], l.retired[tk.key]} {
			for day, usd := range m {
				s[day] += usd
				u[day] += usd
			}
		}
		for day, usd := range pending[tk.key] {
			u[day] += usd
		}
		stored[tk.key], unstored[tk.key] = s, u
	}
	p.Stored, p.Unstored = rowsOf(stored), rowsOf(unstored)
	return p
}

func appendOld(m map[string][]SeedRow, epoch string, r SeedRow) map[string][]SeedRow {
	if m == nil {
		m = map[string][]SeedRow{}
	}
	m[epoch] = append(m[epoch], r)
	return m
}

// RetiredStored records that the counter stored p.Retired: exactly that
// generation counts as remote until the next sync reads it back.
func (l *Ledger) RetiredStored(p PushSet) {
	if l == nil || len(p.Retired) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil || l.pending.gen != p.Gen {
		return
	}
	moveLocked(l.remote, l.pending.spend)
	keys := l.pending.spend
	l.pending = nil
	for key := range keys {
		l.unretireLocked(key)
	}
}

// TombsStored records that the counter stored the rows of p's evicted keys
// (tombs of keys evicted again since TakePush stay).
func (l *Ledger) TombsStored(p PushSet) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for tk, seq := range p.tombs {
		if t, ok := l.tombs[tk]; ok && t.seq == seq {
			delete(l.tombs, tk)
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

// SetEpoch names the process epoch this ledger's local spend is stored
// under.
func (l *Ledger) SetEpoch(epoch string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.epoch = epoch
	l.mu.Unlock()
}

// Rotate closes the process epoch (a writer rotation, after its last push):
// the local spend moves to the remote side (it keeps counting until the
// next sync reads it back from the store as an earlier writer's) and new
// spend goes under epoch. The tombs keep their epoch, so their rows there
// are still set once the moved spend is stored (never left counting twice).
func (l *Ledger) Rotate(epoch string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for tk, t := range l.tombs {
		if tk.epoch == l.epoch && len(l.local[tk.key]) > 0 {
			t.rest = maps.Clone(l.local[tk.key])
			l.tombs[tk] = t
		}
	}
	moveLocked(l.remote, l.local)
	l.local = map[string]map[int32]float64{}
	l.lru = map[string]*keyLRU{}
	l.epoch = epoch
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
	var pending map[string]map[int32]float64
	if l.pending != nil {
		pending = l.pending.spend
	}
	for i, m := range []map[string]map[int32]float64{l.local, l.remote, l.retired, pending} {
		isLocal, isRetired := i == 0, i >= 2
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
				if isRetired {
					l.unretireLocked(key)
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

// prefixSum is one budget's leader sums, the first day they cover and the
// limit its Exceeded counts against.
type prefixSum struct {
	PrefixSum
	from  int32
	limit float64
}

// exceededAt is how many keys the sums show at or over limit. Exceeded
// counts against the read's limit; after a limit change (until the next
// read, at most 2 intervals) it is recomputed from what the sums still
// tell (GAP-0941): none when limit is above the highest key, and else at
// least the highest key, plus every key over a higher old limit.
func (s prefixSum) exceededAt(limit float64) int {
	switch {
	case limit <= 0 || s.Subjects == 0 || s.Peak < limit:
		return 0
	case limit == s.limit:
		return s.Exceeded
	case limit < s.limit:
		return max(s.Exceeded, 1)
	default:
		return 1
	}
}

// SetPrefixSums keeps the leader's per-budget sums of q until until.
func (l *Ledger) SetPrefixSums(q []SumQuery, sums []PrefixSum, until time.Time) {
	if l == nil {
		return
	}
	asked := make(map[string]SumQuery, len(q))
	for _, s := range q {
		asked[s.Prefix] = s
	}
	m := make(map[string]prefixSum, len(sums))
	for _, s := range sums {
		if a, ok := asked[s.Prefix]; ok {
			m[s.Prefix] = prefixSum{PrefixSum: s, from: dayNumber(a.Since), limit: a.Limit}
		}
	}
	l.mu.Lock()
	l.sums, l.sumsUntil = m, until
	l.mu.Unlock()
}

// SetViewKeys keeps the other epochs' spend of keys (rows) until until;
// a listed key with no row has none.
func (l *Ledger) SetViewKeys(keys []string, rows []SeedRow, until time.Time) {
	if l == nil {
		return
	}
	m := make(map[string]map[int32]float64, len(keys))
	for _, k := range keys {
		m[k] = map[int32]float64{}
	}
	for _, r := range rows {
		date, err := time.Parse(time.DateOnly, r.Day)
		if days, ok := m[r.Key]; ok && err == nil && r.USD > 0 && !math.IsInf(r.USD, 0) {
			days[dayNumber(date)] += r.USD
		}
	}
	l.mu.Lock()
	l.view, l.viewUntil = m, until
	l.mu.Unlock()
}

// ownLocked is this process's spend of key in the window (live, retired
// and pending: what the leader's other-epoch sums may not hold yet).
func (l *Ledger) ownLocked(key string, from, today int32) float64 {
	var total float64
	local, retired := l.local[key], l.retired[key]
	var pending map[int32]float64
	if l.pending != nil {
		pending = l.pending.spend[key]
	}
	for day := from; day <= today; day++ {
		total += local[day] + retired[day] + pending[day]
	}
	return total
}

// ViewSpend is Spend for an administrator's view: with a fresh SetViewKeys
// read of key, the larger of this replica's spend and the other epochs'
// spend plus this process's own (a key another replica holds).
func (l *Ledger) ViewSpend(key, period string, now time.Time) (float64, bool) {
	spend, ok := l.Spend(key, period, now)
	if !ok {
		return spend, ok
	}
	today, from := dayNumber(now), windowStart(period, now)
	l.mu.Lock()
	defer l.mu.Unlock()
	if days, in := l.view[key]; in && !now.After(l.viewUntil) {
		var other float64
		for day := from; day <= today; day++ {
			other += days[day]
		}
		spend = max(spend, other+l.ownLocked(key, from, today))
	}
	return spend, true
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
	var pending map[string]map[int32]float64
	if l.pending != nil {
		pending = l.pending.spend
	}
	for _, m := range []map[string]map[int32]float64{l.local, l.remote, l.retired, pending} {
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
	// An actor or batch budget in a cluster: this replica holds only its own
	// keys, so the view takes the leader's sums of every replica's stored
	// spend, read right after this replica's push, once per interval
	// (GAP-0894). Each figure is the larger of both: this replica's newest
	// spend shows at once, the others' within one interval. Exceeded is
	// taken against today's limit, not the one the sums were read with
	// (GAP-0941).
	if s, ok := l.sums[prefix]; ok && s.from == from && !now.After(l.sumsUntil) {
		snap.Total = max(snap.Total, s.Total)
		snap.Peak = max(snap.Peak, s.Peak)
		snap.Subjects = max(snap.Subjects, s.Subjects)
		snap.Exceeded = max(snap.Exceeded, s.exceededAt(limit))
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
// At most DefaultKeyCap retired keys wait per budget too: past it the
// oldest one's spend is dropped (a managed deny budget refuses new keys
// instead). The next verdict of the budget carries budget_keys_evicted:<id>.
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

// retireLocked moves key's local spend to the open retired generation.
// Past keyCap retired keys of the budget, the oldest is dropped (its spend
// no longer counts: the budget's next verdict carries budget_keys_evicted
// and dropped counts it), except for a budget in holdFull, whose new keys
// CapState refuses instead.
func (l *Ledger) retireLocked(key string) {
	days := l.local[key]
	delete(l.local, key)
	if len(days) == 0 {
		return
	}
	id := budgetIDOfKey(key)
	q := l.retiredLRU[id]
	if q == nil {
		q = &keyLRU{order: list.New(), at: map[string]*list.Element{}}
		l.retiredLRU[id] = q
	}
	if e, ok := q.at[key]; ok {
		q.order.MoveToFront(e)
	} else {
		q.at[key] = q.order.PushFront(key)
		for l.keyCap > 0 && q.order.Len() > l.keyCap && !l.holdFull[id] {
			old := q.order.Back()
			k := old.Value.(string)
			q.order.Remove(old)
			delete(q.at, k)
			delete(l.retired, k)
			if l.pending != nil {
				delete(l.pending.spend, k)
			}
			l.dropped[id]++
		}
	}
	r := l.retired[key]
	if r == nil {
		r = map[int32]float64{}
		l.retired[key] = r
	}
	tk := tombKey{l.epoch, key}
	l.tombSeq++
	t := l.tombs[tk]
	t.seq, t.gen = l.tombSeq, l.retiredGen
	for day, usd := range days {
		r[day] += usd
		if !slices.Contains(t.days, day) {
			t.days = append(t.days, day)
		}
	}
	l.tombs[tk] = t
}

// unretireLocked forgets key's retired order once no retired part holds it.
func (l *Ledger) unretireLocked(key string) {
	if _, open := l.retired[key]; open {
		return
	}
	if l.pending != nil {
		if _, ok := l.pending.spend[key]; ok {
			return
		}
	}
	id := budgetIDOfKey(key)
	if q := l.retiredLRU[id]; q != nil {
		if e, ok := q.at[key]; ok {
			q.order.Remove(e)
			delete(q.at, key)
		}
		if q.order.Len() == 0 {
			delete(l.retiredLRU, id)
		}
	}
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

// CapState reports, for a capped key (actor:, batch:), whether its budget
// lost keys to the cap since the last call (once: the evaluator turns it
// into one warning on the audit row) and whether a new key would find both
// the live and the retired keys of the budget full (a managed deny budget
// refuses it, budget_unavailable), as when the last read found more keys
// at or over the limit than it could name (SetOverFull). One lock for all,
// on the request path.
func (l *Ledger) CapState(key string) (evicted, full bool) {
	if l == nil || !capped(key) {
		return false, false
	}
	id := budgetIDOfKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.evicted[id] > 0 {
		evicted = true
		delete(l.evicted, id)
	}
	if l.keyCap > 0 {
		q, r := l.lru[id], l.retiredLRU[id]
		if q != nil && q.order.Len() >= l.keyCap && r != nil && r.order.Len() >= l.keyCap {
			_, live := q.at[key]
			full = !live
		}
	}
	if !full && l.overFull[id] {
		q := l.lru[id]
		full = q == nil || q.at[key] == nil
	}
	return evicted, full
}

// SetOverFull names the budgets whose over-limit keys the last good read
// could not all name (nil: none). It is replaced on each good read.
func (l *Ledger) SetOverFull(ids []string) {
	if l == nil {
		return
	}
	var m map[string]bool
	if len(ids) > 0 {
		m = make(map[string]bool, len(ids))
		for _, id := range ids {
			m[id] = true
		}
	}
	l.mu.Lock()
	l.overFull = m
	l.mu.Unlock()
}

// SetHoldFull names the budgets whose retired keys are never dropped: a
// managed deny budget refuses new keys at the bound instead (CapState).
func (l *Ledger) SetHoldFull(ids []string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.holdFull = make(map[string]bool, len(ids))
	for _, id := range ids {
		l.holdFull[id] = true
	}
}

// RetiredKeys returns how many evicted keys of budget id wait to be stored
// and how many the bound dropped since this process started (the doctor
// row and the budget view).
func (l *Ledger) RetiredKeys(id string) (waiting, dropped int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if q := l.retiredLRU[id]; q != nil {
		waiting = q.order.Len()
	}
	return waiting, l.dropped[id]
}

// KeyCap is the per-budget bound of live keys, and of retired keys
// waiting to be stored (DefaultKeyCap unless SetKeyCap changed it).
func (l *Ledger) KeyCap() int {
	if l == nil {
		return DefaultKeyCap
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyCap
}

// CappedKeys lists, in order, the capped keys this process holds spend of
// (live and retired): the cluster read asks for those capped keys only.
func (l *Ledger) CappedKeys() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := []string{}
	for _, q := range l.lru {
		for k := range q.at {
			keys = append(keys, k)
		}
	}
	for _, q := range l.retiredLRU {
		for k := range q.at {
			if _, live := l.local[k]; !live {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
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
