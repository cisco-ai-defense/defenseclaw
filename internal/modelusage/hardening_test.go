package modelusage

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOwnerKindIsNormalisedSoWritersAndReadersAgree(t *testing.T) {
	cases := []struct {
		kind, subject, want string
	}{
		{"route_credential", "1001", "posix_uid:1001"},
		{"posix_uid", "1001", "posix_uid:1001"},
		{"", "1001", "posix_uid:1001"},
		{"verified_source", "S-1-5-21-1-2-3-1104", "windows_sid:S-1-5-21-1-2-3-1104"},
		{"windows_sid", "s-1-5-21-1-2-3-1104", "windows_sid:s-1-5-21-1-2-3-1104"},
		{"upn", "alice@corp.test", "upn:alice@corp.test"},
		{"", "alice", "id:alice"},
	}
	for _, c := range cases {
		got := OwnerID(CallFacts{Subject: c.subject, SubjectKind: c.kind, IdentityVerified: true})
		if got != c.want {
			t.Errorf("kind %q subject %q: owner %q, want %q", c.kind, c.subject, got, c.want)
		}
	}
	if OwnerID(CallFacts{Subject: "1001", SubjectKind: "posix_uid"}) != "" {
		t.Fatal("an unverified caller has no owner")
	}
}

func TestStoreKeysOnTheBoundedModelNotTheClientString(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	for i := 0; i < 50; i++ {
		r := rec("1", nil, "client-model-"+itoa(i), f(0.1), now)
		r.ModelKey, r.ProviderKey = "other", "weird provider name that is not an identifier!!"
		r.ProviderKey = providerKey(r.ProviderKey)
		s.Emit(context.Background(), r)
	}
	rows, _ := s.Run(context.Background(), Query{By: "model", AllOwners: true})
	if len(rows) != 1 || rows[0].Key != "other" || rows[0].Calls != 50 {
		t.Fatalf("model strings must collapse to the bounded key: %+v", rows)
	}
	rows, _ = s.Run(context.Background(), Query{By: "provider", AllOwners: true})
	if len(rows) != 1 || rows[0].Key != "other" {
		t.Fatalf("an unusable provider name is other: %+v", rows)
	}
	if providerKey(" Anthropic ") != "anthropic" || providerKey("bedrock") != "bedrock" {
		t.Fatal("plain provider names are kept, lower-cased")
	}
}

func TestStoreRowCapDropsNewRowsAndKeepsUpdatingOld(t *testing.T) {
	s := openStore(t)
	s.maxRows = 3
	now := time.Now()
	hour := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	for h := 0; h < 3; h++ {
		s.Emit(context.Background(), rec("1", nil, "m", f(1), hour(h)))
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if s.DropTotals()["row_cap"] != 0 {
		t.Fatalf("three rows fit the cap: %v", s.DropTotals())
	}
	// at the cap: two new hours are dropped and counted, an existing hour still updates
	s.Emit(context.Background(), rec("1", nil, "m", f(1), hour(3)))
	s.Emit(context.Background(), rec("1", nil, "m", f(1), hour(4)))
	s.Emit(context.Background(), rec("1", nil, "m", f(1), now))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if s.DropTotals()["row_cap"] != 2 {
		t.Fatalf("two new rows past the cap must be dropped and counted: %v", s.DropTotals())
	}
	rows, _ := s.Run(context.Background(), Query{By: "hour", AllOwners: true, From: hour(48)})
	var calls int64
	for _, r := range rows {
		calls += r.Calls
	}
	if len(rows) != 3 || calls != 4 {
		t.Fatalf("rows=%d calls=%d, want 3 rows and 4 calls (3 + the update, not the dropped new rows)", len(rows), calls)
	}
}

func TestOneFlushNeverOvershootsTheRowCap(t *testing.T) {
	s := openStore(t)
	s.maxRows = 3
	now := time.Now()
	for h := 0; h < 10; h++ {
		s.Emit(context.Background(), rec("1", nil, "m", f(1), now.Add(-time.Duration(h)*time.Hour)))
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.Run(context.Background(), Query{By: "hour", AllOwners: true, From: now.Add(-48 * time.Hour)})
	if len(rows) != 3 || s.DropTotals()["row_cap"] != 7 {
		t.Fatalf("rows=%d drops=%v", len(rows), s.DropTotals())
	}
}

type dropFake struct {
	mu    sync.Mutex
	total int64
	got   []int64
}

func (d *dropFake) Emit(context.Context, Record) {}
func (d *dropFake) DropTotals() map[string]int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]int64{"bucket_cap": d.total}
}
func (d *dropFake) ReportDrops(n int64) {
	d.mu.Lock()
	d.got = append(d.got, n)
	d.mu.Unlock()
}

func TestLostRecordsAreReportedOnceNotSilently(t *testing.T) {
	d := &dropFake{}
	e := NewEngine(d)
	e.dropped.Store(5)
	d.total = 2
	e.reportDrops()
	e.reportDrops() // nothing new: no second report
	d.mu.Lock()
	d.total = 3
	d.mu.Unlock()
	e.reportDrops()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.got) != 2 || d.got[0] != 7 || d.got[1] != 1 {
		t.Fatalf("reports = %v, want [7 1] (queue 5 + store 2, then store +1)", d.got)
	}
}

func TestStoreWithNoDataDirIsRefusedNotRelative(t *testing.T) {
	if err := NewStore("").Configure(true, 30); err == nil {
		t.Fatal("an empty path must not create a store relative to the working directory")
	}
	_ = filepath.Join
}
