package modelusage

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func rec(owner string, groups []string, model string, usd *float64, at time.Time) Record {
	r := Record{
		Facts: CallFacts{
			Connector: "claudecode", SelectedProvider: "anthropic", SelectedModel: model, CallRole: RoleAgent, APIFamily: FamilyMessages,
			Subject: owner, SubjectKind: "posix_uid", IdentityVerified: owner != "", Groups: groups,
			Route: RouteFacts{Decision: DecisionApplied}, ProfileName: "eng",
		},
		Usage:   Usage{Input: 100, Output: 10, Has: HasInput | HasOutput},
		Outcome: "completed", EndedAt: at, Total: 50 * time.Millisecond,
	}
	r.Cost.Basis = BasisNone
	if usd != nil {
		r.Cost.USD, r.Cost.Basis = usd, BasisComputed
	}
	return r
}

func openStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "model_usage", "model_usage.db"))
	s.readFlushGap = 0
	if err := s.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Configure(false, 30) })
	return s
}

func TestStoreOwnRowsOnlyAndAdminSeesAll(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	s.Emit(context.Background(), rec("1001", []string{"eng"}, "m1", f(0.5), now))
	s.Emit(context.Background(), rec("1001", []string{"eng"}, "m2", f(0.25), now))
	s.Emit(context.Background(), rec("1002", []string{"ops"}, "m1", f(2), now))
	s.Emit(context.Background(), rec("", nil, "m1", f(9), now)) // unverified caller

	alice := OwnerID(rec("1001", nil, "", nil, now).Facts)
	rows, err := s.Run(context.Background(), Query{By: "model", Owner: alice})
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	var calls int64
	for _, r := range rows {
		total += *r.CostUSD
		calls += r.Calls
	}
	if len(rows) != 2 || calls != 2 || total != 0.75 {
		t.Fatalf("own rows leaked or lost: %+v", rows)
	}
	// the user rollup of a non-admin is the caller own bucket only
	rows, _ = s.Run(context.Background(), Query{By: "user", Owner: alice})
	if len(rows) != 1 || rows[0].Key != alice {
		t.Fatalf("%+v", rows)
	}
	// group rollup and unidentified callers are admin-only
	if _, err := s.Run(context.Background(), Query{By: "group", Owner: alice}); err != ErrAdminOnly {
		t.Fatalf("group rollup for a user: %v", err)
	}
	if _, err := s.Run(context.Background(), Query{By: "model"}); err != ErrAdminOnly {
		t.Fatalf("a caller with no identity must see nothing, got %v", err)
	}
	// admin sees everyone, including the unattributed owner
	rows, _ = s.Run(context.Background(), Query{By: "user", AllOwners: true})
	if len(rows) != 3 {
		t.Fatalf("%+v", rows)
	}
	grows, err := s.Run(context.Background(), Query{By: "group", AllOwners: true})
	if err != nil || len(grows) != 2 {
		t.Fatalf("%+v %v", grows, err)
	}
}

func TestStoreAbsentCostStaysNullAndAccumulates(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	s.Emit(context.Background(), rec("1", nil, "m", nil, now))
	rows, _ := s.Run(context.Background(), Query{By: "model", AllOwners: true})
	if len(rows) != 1 || rows[0].CostUSD != nil || rows[0].CostCalls != 0 || rows[0].Calls != 1 {
		t.Fatalf("a call with no cost must leave the bucket cost NULL: %+v", rows)
	}
	s.Emit(context.Background(), rec("1", nil, "m", f(1.5), now))
	s.Emit(context.Background(), rec("1", nil, "m", f(1.5), now))
	rows, _ = s.Run(context.Background(), Query{By: "model", AllOwners: true})
	if rows[0].CostUSD == nil || *rows[0].CostUSD != 3 || rows[0].CostCalls != 2 || rows[0].Calls != 3 {
		t.Fatalf("%+v", rows[0])
	}
	if rows[0].Input != 300 || rows[0].Output != 30 || rows[0].UsageCalls != 3 {
		t.Fatalf("%+v", rows[0])
	}
}

func TestStoreRetentionPrunesOldHours(t *testing.T) {
	s := openStore(t)
	s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	s.mu.Lock()
	s.retDays = 1
	s.lastPrun = time.Time{}
	s.mu.Unlock()
	s.Emit(context.Background(), rec("1", nil, "old", f(1), time.Now()))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	var n int
	s.mu.Lock()
	_ = s.db.QueryRow("SELECT COUNT(*) FROM model_usage").Scan(&n)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("rows older than retention must be pruned, %d left", n)
	}
}

func TestStoreBucketCapDropsAndCounts(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	for i := 0; i < storeBucketCap+50; i++ {
		s.Emit(context.Background(), rec("1", nil, "model-"+itoa(i), f(1), now))
	}
	if s.Overflow() != 50 {
		t.Fatalf("overflow = %d", s.Overflow())
	}
}

func TestStoreOffHasNoGoroutineAndNoFile(t *testing.T) {
	before := runtime.NumGoroutine()
	path := filepath.Join(t.TempDir(), "model_usage.db")
	s := NewStore(path)
	s.Emit(context.Background(), rec("1", nil, "m", f(1), time.Now())) // off: ignored
	if err := s.Configure(false, 30); err != nil {
		t.Fatal(err)
	}
	if s.Enabled() || runtime.NumGoroutine() > before {
		t.Fatal("a disabled store must not run anything")
	}
	if _, err := filepath.Glob(path + "*"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ { // repeated toggles do not leak
		if err := s.Configure(true, 30); err != nil {
			t.Fatal(err)
		}
		if err := s.Configure(false, 30); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Fatalf("goroutines %d > %d after toggling", n, before)
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model_usage.db")
	s := NewStore(path)
	if err := s.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	s.Emit(context.Background(), rec("1", nil, "m", f(2), time.Now()))
	if err := s.Configure(false, 30); err != nil { // flushes on stop
		t.Fatal(err)
	}
	s2 := NewStore(path)
	if err := s2.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	defer s2.Configure(false, 30)
	rows, _ := s2.Run(context.Background(), Query{By: "model", AllOwners: true})
	if len(rows) != 1 || *rows[0].CostUSD != 2 {
		t.Fatalf("%+v", rows)
	}
}

func TestSpendTrackerPeriodsScopesAndUnknown(t *testing.T) {
	e := NewEngine()
	now := time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC) // Thursday
	cf := CallFacts{Connector: "codex", Subject: "7", SubjectKind: "posix_uid", IdentityVerified: true, Groups: []string{"eng"}}
	e.spend.add(cf, 1.5, now)
	e.spend.add(cf, 0.5, now.Add(-24*time.Hour)) // Wednesday: same week, other day
	e.spend.add(cf, 4, now.AddDate(0, -1, 0))    // last month
	owner := OwnerID(cf)
	if v, ok := e.Spend(ScopeUser, owner, PeriodDay, now); !ok || v != 1.5 {
		t.Fatal(v, ok)
	}
	if v, ok := e.Spend(ScopeUser, owner, PeriodWeek, now); !ok || v != 2 {
		t.Fatal(v, ok)
	}
	if v, ok := e.Spend(ScopeGroup, "eng", PeriodMonth, now); !ok || v != 2 {
		t.Fatal(v, ok)
	}
	if v, ok := e.Spend(ScopeConnector, "codex", PeriodDay, now); !ok || v != 1.5 {
		t.Fatal(v, ok)
	}
	if _, ok := e.Spend(ScopeUser, "posix_uid:nobody", PeriodDay, now); ok {
		t.Fatal("a subject with no priced call must be unknown, not 0")
	}
	if _, ok := e.Spend(ScopeUser, owner, "year", now); ok {
		t.Fatal("unknown period")
	}
	// unverified calls never count toward a user or group
	e.spend.add(CallFacts{Connector: "codex", Subject: "7", Groups: []string{"eng"}}, 100, now)
	if v, _ := e.Spend(ScopeGroup, "eng", PeriodDay, now); v != 1.5 {
		t.Fatalf("unverified identity counted: %v", v)
	}
	var nilEngine *Engine
	if _, ok := nilEngine.Spend(ScopeUser, "x", PeriodDay, now); ok {
		t.Fatal("nil engine")
	}
}

func TestConcurrentConfigureNeverPanicsOrLeavesTheStoreHalfOpen(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "model_usage", "model_usage.db"))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := s.Configure((i+j)%2 == 0, 30); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	if err := s.Configure(true, 30); err != nil || !s.Enabled() {
		t.Fatalf("enabled=%v err=%v", s.Enabled(), err)
	}
	if err := s.Configure(false, 30); err != nil || s.Enabled() {
		t.Fatalf("enabled=%v err=%v", s.Enabled(), err)
	}
}

func TestHourTimelineIsNotCutToTheMostExpensiveHours(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	for h := 0; h < 300; h++ {
		s.Emit(context.Background(), rec("1", nil, "m", f(float64(h+1)), now.Add(-time.Duration(h)*time.Hour)))
	}
	rows, err := s.Run(context.Background(), Query{By: "hour", AllOwners: true, From: now.Add(-400 * time.Hour)})
	if err != nil || len(rows) != 300 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Key > rows[i].Key {
			t.Fatal("a timeline must be in time order")
		}
	}
}

func TestGatewayOwnCallsAreStoredUnderTheGatewaySource(t *testing.T) {
	s := openStore(t)
	r := rec("", nil, "m", f(1), time.Now())
	r.Facts.Connector = ""
	s.Emit(context.Background(), r)
	rows, _ := s.Run(context.Background(), Query{By: "connector", AllOwners: true})
	if len(rows) != 1 || rows[0].Key != "gateway" {
		t.Fatalf("%+v", rows)
	}
}

func TestReadFlushIsThrottled(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "model_usage", "model_usage.db"))
	if err := s.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	defer s.Configure(false, 30)
	s.Emit(context.Background(), rec("1", nil, "m", f(1), time.Now()))
	if rows, _ := s.Run(context.Background(), Query{By: "model", AllOwners: true}); len(rows) != 1 {
		t.Fatalf("the first read flushes: %+v", rows)
	}
	s.Emit(context.Background(), rec("1", nil, "m", f(1), time.Now()))
	rows, _ := s.Run(context.Background(), Query{By: "model", AllOwners: true})
	if rows[0].Calls != 1 {
		t.Fatalf("a read inside the gap must not write: %+v", rows)
	}
}

type fixedSpend struct{ usd float64 }

func (f fixedSpend) Spend(string, string, string, time.Time) (float64, bool) { return f.usd, true }

func TestSpendReaderReplacesTheLocalTrackerForReads(t *testing.T) {
	e := NewEngine()
	now := time.Now()
	cf := CallFacts{Connector: "codex", Subject: "7", SubjectKind: "posix_uid", IdentityVerified: true}
	e.spend.add(cf, 1.5, now)
	owner := OwnerID(cf)
	if v, _ := e.Spend(ScopeUser, owner, PeriodDay, now); v != 1.5 {
		t.Fatalf("local tracker: %v", v)
	}
	e.SetSpendReader(fixedSpend{usd: 42})
	if v, ok := e.Spend(ScopeUser, owner, PeriodDay, now); !ok || v != 42 {
		t.Fatalf("a replica-backed reader must answer: %v %v", v, ok)
	}
	e.SetSpendReader(nil)
	if v, _ := e.Spend(ScopeUser, owner, PeriodDay, now); v != 1.5 {
		t.Fatalf("nil restores the local tracker: %v", v)
	}
}
