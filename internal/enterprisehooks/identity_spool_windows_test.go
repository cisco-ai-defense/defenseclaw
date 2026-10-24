// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A Windows identity record names its account, like the Linux and macOS
// records (GAP-0025).
func TestWindowsIdentitySpoolRecordNamesTheAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := strings.ToUpper(user.User.Sid.String())
	dir := t.TempDir()
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[sid] = nil
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	record, err := ReadIdentitySpoolRecord(dir, sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.User, `\`) {
		t.Fatalf("record user = %q, want DOMAIN\\account", record.User)
	}
}

const (
	testSpoolUserA = "S-1-5-21-111111111-222222222-333333333-4001"
	testSpoolUserB = "S-1-5-21-111111111-222222222-333333333-4002"
	testSpoolUserC = "S-1-5-21-111111111-222222222-333333333-4003"
)

// stubWindowsIdentityLookups replaces the directory lookups of a record:
// facts is called once per account in the order the pass takes them.
func stubWindowsIdentityLookups(t *testing.T, facts func(sid string), budgets *[]time.Duration) {
	t.Helper()
	previousFacts, previousNames := windowsIdentityDirectoryFacts, windowsIdentityGroupNames
	t.Cleanup(func() { windowsIdentityDirectoryFacts, windowsIdentityGroupNames = previousFacts, previousNames })
	t.Cleanup(func() { waitIdentityLookupGateIdle(t, &windowsIdentityLookupGate) })
	windowsIdentityDirectoryFacts = func(sid string, _ time.Duration) useridentity.DirectoryFacts {
		if facts != nil {
			facts(sid)
		}
		return useridentity.DirectoryFacts{}
	}
	windowsIdentityGroupNames = func(sids []string, _ int, budget time.Duration) []string {
		if budgets != nil {
			*budgets = append(*budgets, budget)
		}
		return append([]string(nil), sids...)
	}
}

// writeTestIdentityRecord writes the record of a signed-out account (its
// token groups unknown), as a pass writes it for the accounts these tests
// list without a session.
func writeTestIdentityRecord(t *testing.T, dir, sid string, updated time.Time) {
	t.Helper()
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{Key: sid, UpdatedAt: updated, Facts: useridentity.DirectoryFacts{GroupsPartial: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

// The identity pass obeys the enumerator cycle (GAP-1049): it stops at the
// cycle's end, keeps the records of the accounts it did not reach or was
// still resolving, and the next pass starts with the oldest records.
func TestWindowsIdentitySpoolStopsAtTheCycleDeadline(t *testing.T) {
	dir := t.TempDir()
	stale := time.Now().UTC().Add(-50 * time.Minute)
	writeTestIdentityRecord(t, dir, testSpoolUserA, time.Now().UTC().Add(-time.Minute))
	writeTestIdentityRecord(t, dir, testSpoolUserC, stale)
	cache := NewWindowsEnrollmentGroupCache()
	for _, sid := range []string{testSpoolUserA, testSpoolUserB, testSpoolUserC} {
		cache.Users[sid] = []string{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var order []string
	stubWindowsIdentityLookups(t, func(sid string) {
		order = append(order, sid)
		if len(order) == 3 {
			cancel() // the cycle ends while the third account is resolved
		}
	}, nil)
	err := WriteWindowsIdentitySpool(ctx, dir, cache, nil, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the pass stopped by the cycle", err)
	}
	if strings.Join(order, ",") != testSpoolUserB+","+testSpoolUserC+","+testSpoolUserA {
		t.Fatalf("resolved %v, want the account without a record, then the oldest, and none after the cycle ended", order)
	}
	record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
	if readErr != nil || time.Since(record.UpdatedAt) < 30*time.Second {
		t.Fatalf("the record of the account the pass did not reach = %+v (%v), want it kept unchanged", record, readErr)
	}
	for _, sid := range []string{testSpoolUserB, testSpoolUserC} {
		if record, err := ReadIdentitySpoolRecord(dir, sid, nil); err != nil || time.Since(record.UpdatedAt) > 30*time.Second {
			t.Fatalf("record of %s = %+v (%v), want it refreshed", sid, record, err)
		}
	}
}

// No lookup of a pass runs past the cycle's deadline (GAP-1049).
func TestWindowsIdentitySpoolLookupsEndWithTheCycle(t *testing.T) {
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-32-545"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true}
	var budgets []time.Duration
	stubWindowsIdentityLookups(t, nil, &budgets)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WriteWindowsIdentitySpool(ctx, t.TempDir(), cache, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(budgets) != 2 {
		t.Fatalf("lookup budgets = %v, want the group names and the account name", budgets)
	}
	for _, budget := range budgets {
		if budget > 300*time.Millisecond {
			t.Fatalf("lookup budget %s runs past the cycle deadline", budget)
		}
	}
}

// An account the enrollment excluded publishes no identity record, and its
// earlier record goes (GAP-1264).
func TestWindowsIdentitySpoolPublishesNoRecordForAnExcludedAccount(t *testing.T) {
	dir := t.TempDir()
	writeTestIdentityRecord(t, dir, testSpoolUserB, time.Now().UTC())
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-32-545"}
	cache.Users[testSpoolUserB] = []string{"S-1-5-32-545"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true, testSpoolUserB: true}
	stubWindowsIdentityLookups(t, nil, nil)
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, []string{strings.ToLower(testSpoolUserB)}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); err != nil {
		t.Fatalf("the enrolled account's record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testSpoolUserB+".json")); !os.IsNotExist(err) {
		t.Fatalf("the excluded account's record is still published: %v", err)
	}
}

// A failed replacement must withdraw the preceding token-group record. The
// gateway otherwise trusts those old groups for an hour after this cycle.
func TestWindowsIdentitySpoolWriteFailureWithdrawsOldRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestIdentityRecord(t, dir, testSpoolUserA, time.Now().UTC())
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-32-545"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true}
	stubWindowsIdentityLookups(t, nil, nil)
	protect := func(path string) error {
		if path == dir {
			return nil
		}
		return os.ErrPermission
	}
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, protect, nil); err == nil {
		t.Fatal("failed spool publication was reported as successful")
	}
	if _, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old group record remained trusted after failed replacement: %v", err)
	}
}

// Loop round 2, finding 1: a failed publication withdraws the previous
// record only when the pass disproved it. A signed-in user whose token
// groups did not change keeps the record, so the gateway keeps its strict
// group profile; withdrawing it sent the request to default_lookup_failed
// and a possibly weaker default. Changed groups, a sign-out (groups no
// longer known) and another account name still withdraw it.
func TestWindowsIdentitySpoolWriteFailureKeepsARecordItDidNotDisprove(t *testing.T) {
	const strict = "S-1-5-21-111111111-222222222-333333333-7000"
	named := map[string]string{strict: `CORP\strict`, testSpoolUserA: `CORP\alice`}
	for _, tc := range []struct {
		name     string
		previous IdentitySpoolRecord
		groups   []string
		names    map[string]string
		signedIn bool
		wantKept bool
	}{
		{name: "same token groups", previous: IdentitySpoolRecord{User: `CORP\alice`, Facts: useridentity.DirectoryFacts{Groups: []string{strict, `CORP\strict`}}},
			groups: []string{strict}, names: named, signedIn: true, wantKept: true},
		{name: "same token groups, names not resolved this pass", previous: IdentitySpoolRecord{User: `CORP\alice`, Facts: useridentity.DirectoryFacts{Groups: []string{strict, `CORP\strict`}}},
			groups: []string{strict}, signedIn: true, wantKept: true},
		{name: "a group added", previous: IdentitySpoolRecord{Facts: useridentity.DirectoryFacts{Groups: []string{strict}}},
			groups: []string{strict, "S-1-5-32-545"}, signedIn: true},
		{name: "a group removed", previous: IdentitySpoolRecord{Facts: useridentity.DirectoryFacts{Groups: []string{strict, "S-1-5-32-545"}}},
			groups: []string{strict}, signedIn: true},
		{name: "signed out", previous: IdentitySpoolRecord{Facts: useridentity.DirectoryFacts{Groups: []string{strict}}},
			groups: []string{strict}, signedIn: false},
		{name: "another account name", previous: IdentitySpoolRecord{User: `CORP\other`, Facts: useridentity.DirectoryFacts{Groups: []string{strict}}},
			groups: []string{strict}, names: named, signedIn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			previous := tc.previous
			previous.Key, previous.UpdatedAt = testSpoolUserA, time.Now().UTC().Add(-time.Minute)
			data, err := MarshalIdentitySpoolRecord(previous)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, testSpoolUserA+".json"), data, 0o640); err != nil {
				t.Fatal(err)
			}
			cache := NewWindowsEnrollmentGroupCache()
			cache.Users[testSpoolUserA] = tc.groups
			cache.SignedIn = map[string]bool{testSpoolUserA: tc.signedIn}
			stubWindowsIdentityLookups(t, nil, nil)
			windowsIdentityGroupNames = func(sids []string, _ int, _ time.Duration) []string {
				out := make([]string, 0, len(sids))
				for _, sid := range sids {
					if name := tc.names[sid]; name != "" {
						out = append(out, name)
					} else {
						out = append(out, sid)
					}
				}
				return out
			}
			protect := func(path string) error {
				if path == dir {
					return nil
				}
				return os.ErrPermission
			}
			if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, protect, nil); err == nil {
				t.Fatal("failed spool publication was reported as successful")
			}
			_, err = ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
			if tc.wantKept && err != nil {
				t.Fatalf("a record the pass did not disprove was withdrawn: %v", err)
			}
			if !tc.wantKept && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a disproved record stayed after the failed publication: %v", err)
			}
		})
	}
}

// W2B-G-enum review: the pass checked the cycle only between accounts, and
// an account's directory lookup ran synchronously, so a lookup that stalled
// held the pass past the cycle's deadline and the other records went
// unrefreshed. The pass stops waiting at the deadline and keeps the records;
// a lookup that keeps running holds only its own account: the next pass
// starts no second lookup of it and refreshes the others.
func TestWindowsIdentitySpoolStopsWaitingForABlockedLookupAtTheDeadline(t *testing.T) {
	dir := t.TempDir()
	oldA, oldB := time.Now().UTC().Add(-50*time.Minute), time.Now().UTC().Add(-time.Minute)
	writeTestIdentityRecord(t, dir, testSpoolUserA, oldA)
	writeTestIdentityRecord(t, dir, testSpoolUserB, oldB)
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{}
	cache.Users[testSpoolUserB] = []string{}
	release := make(chan struct{})
	var mu sync.Mutex
	var reached []string
	stubWindowsIdentityLookups(t, func(sid string) {
		mu.Lock()
		reached = append(reached, sid)
		mu.Unlock()
		if sid == testSpoolUserA {
			<-release // the directory never answers for the oldest account
		}
	}, nil)
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := WriteWindowsIdentitySpool(ctx, dir, cache, nil, nil, nil, nil)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the pass returned after %s, past its 200ms cycle", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the pass stopped by the cycle deadline", err)
	}
	mu.Lock()
	got := strings.Join(reached, ",")
	mu.Unlock()
	if got != testSpoolUserA {
		t.Fatalf("lookups started for %s, want only the oldest account's", got)
	}
	for sid, want := range map[string]time.Time{testSpoolUserA: oldA, testSpoolUserB: oldB} {
		if record, err := ReadIdentitySpoolRecord(dir, sid, nil); err != nil || !record.UpdatedAt.Equal(want) {
			t.Fatalf("record of %s = %+v (%v), want it kept as it was", sid, record, err)
		}
	}
	if windowsIdentityLookupGate.runningLookups() != 1 {
		t.Fatalf("lookups still running = %d, want the blocked one", windowsIdentityLookupGate.runningLookups())
	}
	err = WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), errIdentityLookupStillRunning.Error()) {
		t.Fatalf("err = %v, want the account whose lookup still runs reported", err)
	}
	mu.Lock()
	got = strings.Join(reached, ",")
	mu.Unlock()
	if got != testSpoolUserA+","+testSpoolUserB {
		t.Fatalf("lookups started for %s, want no second one for the stalled account", got)
	}
	if record, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); err != nil || !record.UpdatedAt.Equal(oldA) {
		t.Fatalf("record of the stalled account = %+v (%v), want it kept", record, err)
	}
	if record, err := ReadIdentitySpoolRecord(dir, testSpoolUserB, nil); err != nil || record.UpdatedAt.Equal(oldB) {
		t.Fatalf("record of the other account = %+v (%v), want it refreshed", record, err)
	}
}

// W2B-G-enum review loop 2: the pass took the oldest record first and waited
// for its lookup until the cycle ended, so an account whose directory never
// answered kept every later account from being refreshed, and after four
// cycles the limit of lookups left running stopped every lookup: the other
// records aged past the gateway's hour and lost their UPN facts. Each
// account now gets at most windowsIdentityAccountWait, an account whose
// lookup still runs is skipped with its record kept, and the others are
// refreshed on every cycle.
func TestWindowsIdentitySpoolRefreshesOtherAccountsWhileOneLookupNeverReturns(t *testing.T) {
	dir := t.TempDir()
	oldA := time.Now().UTC().Add(-50 * time.Minute)
	writeTestIdentityRecord(t, dir, testSpoolUserA, oldA)
	writeTestIdentityRecord(t, dir, testSpoolUserB, time.Now().UTC().Add(-40*time.Minute))
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{}
	cache.Users[testSpoolUserB] = []string{}
	previousWait := windowsIdentityAccountWait
	t.Cleanup(func() { windowsIdentityAccountWait = previousWait })
	windowsIdentityAccountWait = 50 * time.Millisecond
	release := make(chan struct{})
	var callsA, callsB atomic.Int32
	stubWindowsIdentityLookups(t, func(sid string) {
		switch sid {
		case testSpoolUserA:
			callsA.Add(1)
			<-release // the directory never answers for A
		case testSpoolUserB:
			callsB.Add(1)
		}
	}, nil)
	t.Cleanup(func() { close(release) })
	for cycle := 1; cycle <= 6; cycle++ {
		before := time.Now().UTC()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := WriteWindowsIdentitySpool(ctx, dir, cache, nil, nil, nil, nil)
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), testSpoolUserA) {
			t.Fatalf("cycle %d: err = %v, want only A reported unanswered, not the cycle stopped", cycle, err)
		}
		if record, err := ReadIdentitySpoolRecord(dir, testSpoolUserB, nil); err != nil || record.UpdatedAt.Before(before) {
			t.Fatalf("cycle %d: record of B = %+v (%v), want it refreshed", cycle, record, err)
		}
		if record, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); err != nil || !record.UpdatedAt.Equal(oldA) {
			t.Fatalf("cycle %d: record of A = %+v (%v), want it kept", cycle, record, err)
		}
	}
	if callsA.Load() != 1 || callsB.Load() != 6 {
		t.Fatalf("lookups started: A %d, B %d; want one for A while it runs and one for B per cycle", callsA.Load(), callsB.Load())
	}
}

// The variant where the directory answers for A, but after the time a cycle
// has left: once A's lookup has not answered in time, the pass takes A after
// the others, so it cannot use up every cycle.
func TestWindowsIdentitySpoolTakesASlowAccountAfterTheOthers(t *testing.T) {
	dir := t.TempDir()
	writeTestIdentityRecord(t, dir, testSpoolUserA, time.Now().UTC().Add(-50*time.Minute))
	writeTestIdentityRecord(t, dir, testSpoolUserB, time.Now().UTC().Add(-40*time.Minute))
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{}
	cache.Users[testSpoolUserB] = []string{}
	stubWindowsIdentityLookups(t, func(sid string) {
		if sid == testSpoolUserA {
			time.Sleep(300 * time.Millisecond)
		}
	}, nil)
	for cycle := 1; cycle <= 3; cycle++ {
		before := time.Now().UTC()
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		err := WriteWindowsIdentitySpool(ctx, dir, cache, nil, nil, nil, nil)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cycle %d: err = %v, want the cycle ended while A was resolved", cycle, err)
		}
		record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserB, nil)
		if refreshed := readErr == nil && !record.UpdatedAt.Before(before); refreshed != (cycle > 1) {
			t.Fatalf("cycle %d: B refreshed = %v (%+v, %v); want it refreshed once A has been late", cycle, refreshed, record, readErr)
		}
		// A's lookup answers before the next cycle starts.
		for deadline := time.Now().Add(5 * time.Second); windowsIdentityLookupGate.runningLookups() != 0; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("A's lookup did not return")
			}
		}
	}
}

// Loop round 3, finding 2: a failed publication withdrew a previous record
// the pass could not read, without proof that the groups changed, and the
// gateway dropped the strict groups. An unreadable record now stays, as the
// release writer left it.
func TestWindowsIdentitySpoolWriteFailureKeepsAnUnreadableRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testSpoolUserA+".json")
	torn := []byte(`{"version":1,"key":"` + testSpoolUserA + `","facts":{"groups":["S-1-5-21-111111111-222222222-333333333-7000"`)
	if err := os.WriteFile(path, torn, 0o640); err != nil {
		t.Fatal(err)
	}
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{"S-1-5-21-111111111-222222222-333333333-7000"}
	cache.SignedIn = map[string]bool{testSpoolUserA: true}
	stubWindowsIdentityLookups(t, nil, nil)
	protect := func(path string) error {
		if path == dir {
			return nil
		}
		return os.ErrPermission
	}
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, protect, nil); err == nil {
		t.Fatal("failed spool publication was reported as successful")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(torn) {
		t.Fatalf("an unreadable previous record was withdrawn or replaced: %q (%v)", data, err)
	}
}

// Loop round 3, finding 3: a token that gained a strict group kept the old
// record, which named a weaker one, whenever the account's directory
// lookups took longer than windowsIdentityAccountWait, and at every such
// pass until the record aged out. The pass now publishes the token groups,
// which need no lookup, over the previous facts, while the lookup goes on;
// unchanged groups leave the record as it was.
func TestWindowsIdentitySpoolPublishesTheTokenGroupsOfALateLookup(t *testing.T) {
	const weak, strict = "S-1-5-21-111111111-222222222-333333333-7001", "S-1-5-21-111111111-222222222-333333333-7000"
	dir := t.TempDir()
	previousAt := time.Now().UTC().Add(-20 * time.Minute)
	for sid, groups := range map[string][]string{testSpoolUserA: {weak, `CORP\weak`}, testSpoolUserB: {weak, `CORP\weak`}} {
		data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{Key: sid, User: `CORP\user`, UpdatedAt: previousAt,
			Facts: useridentity.DirectoryFacts{UPN: "user@corp.example", Groups: groups}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{weak, strict} // A gained the strict group
	cache.Users[testSpoolUserB] = []string{weak}         // B did not
	cache.SignedIn = map[string]bool{testSpoolUserA: true, testSpoolUserB: true}
	previousWait := windowsIdentityAccountWait
	t.Cleanup(func() { windowsIdentityAccountWait = previousWait })
	windowsIdentityAccountWait = 50 * time.Millisecond
	release := make(chan struct{})
	stubWindowsIdentityLookups(t, func(string) { <-release }, nil) // the directory answers for nobody in time
	t.Cleanup(func() { close(release) })
	err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the late lookups reported", err)
	}
	record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
	if readErr != nil || !slices.Contains(record.Facts.Groups, strict) || record.Facts.GroupsPartial || !record.UpdatedAt.After(previousAt) {
		t.Fatalf("A's record = %+v (%v), want the strict token group published", record, readErr)
	}
	if record.User != `CORP\user` || record.Facts.UPN != "user@corp.example" || !slices.Contains(record.Facts.Groups, `CORP\weak`) {
		t.Fatalf("A's record = %+v, want the previous facts and group names kept", record)
	}
	if record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserB, nil); readErr != nil || !record.UpdatedAt.Equal(previousAt) {
		t.Fatalf("B's record = %+v (%v), want it kept as it was", record, readErr)
	}
	// The lookup of A still runs at the next pass, which also leaves the
	// published groups in place.
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil); err == nil {
		t.Fatal("the still-running lookups were not reported")
	}
	if record, readErr := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil); readErr != nil || !slices.Contains(record.Facts.Groups, strict) {
		t.Fatalf("A's record after the next pass = %+v (%v)", record, readErr)
	}
}
