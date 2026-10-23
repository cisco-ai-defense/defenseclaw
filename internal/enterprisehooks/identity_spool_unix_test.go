// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList pins GAP-0145 and
// GAP-1113: a successful pass removes the record of a local account it no
// longer lists (excluded, out of the manifest or deleted), which nothing
// would refresh again, so status and verify warned identity_records_stale
// about it; it keeps a directory account's record while no directory account
// resolved (the pass could not decide it while the directory was
// unreachable) and the gateway still trusts it. A failed pass removes no
// young record; a record older than IdentitySpoolMaxAge goes.
func TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		record IdentitySpoolRecord
		age    time.Duration
	}{
		{IdentitySpoolRecord{Key: "94401103", User: "dcad-bob", SSSDDomain: "dclab.test", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST",
		}}, 5 * time.Minute},
		{IdentitySpoolRecord{Key: "94401104", User: "dave"}, 2 * IdentitySpoolMaxAge},
		{IdentitySpoolRecord{Key: "94401106", User: "carol", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}}, 5 * time.Minute},
	} {
		data, err := MarshalIdentitySpoolRecord(tc.record)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, tc.record.Key+".json")
		if err := os.WriteFile(path, data, 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-tc.age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(key string) bool {
		_, err := os.Stat(filepath.Join(dir, key+".json"))
		return err == nil
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401107, User: "erin"}}, nil, nil, nil); err == nil {
		t.Fatal("the canceled lookup did not fail the pass")
	}
	if !exists("94401103") || !exists("94401106") || exists("94401104") {
		t.Fatalf("after a failed pass: directory %v, local %v, expired %v; want the young records kept and the expired one gone",
			exists("94401103"), exists("94401106"), exists("94401104"))
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !exists("94401103") {
		t.Error("the record of an unlisted directory account was removed while no directory account resolved")
	}
	if exists("94401106") {
		t.Error("the record of a local account the pass no longer lists was kept")
	}
	const reassigned = "94401105"
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{
		Key: reassigned, User: "alice", UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, reassigned+".json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	// The canceled lookup fails and the pass reports it; the record of the
	// previous owner must be gone either way.
	_ = WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401105, User: "bob"}}, nil, nil, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reassigned uid kept previous account record: %v", err)
	}
	// Loop round 3: the gateway takes no missing record as a withdrawal, so
	// the previous owner's identity is withdrawn explicitly.
	if _, err := ReadIdentitySpoolWithdrawal(dir, reassigned, nil); err != nil {
		t.Fatalf("the reassigned uid's previous identity was not withdrawn: %v", err)
	}
}

// A successful refresh of one SSSD domain cannot establish that a missing
// account from another SSSD domain left enrollment.
func TestIdentitySpoolCleanupRequiresTheRecordsDomainToAnswer(t *testing.T) {
	dir := t.TempDir()
	for _, record := range []IdentitySpoolRecord{
		{Key: "94401103", User: "alice", SSSDDomain: "unreachable.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, UPN: "alice@unreachable.test"}},
		{Key: "94401104", User: "bob", SSSDDomain: "reachable.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, UPN: "bob@reachable.test"}},
	} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	answered := map[string]bool{"sssd:reachable.test": true}
	for _, entry := range entries {
		got, directory := identitySpoolRecordLeft(dir, entry, answered)
		want := entry.Name() == "94401104.json"
		if got != want || !directory {
			t.Errorf("cleanup %s = %v (directory %v), want %v (directory true)", entry.Name(), got, directory, want)
		}
	}
}

// stubIdentitySpoolLookupUID answers the departure lookup: the uids in
// present resolve to their names, any other uid is not found.
func stubIdentitySpoolLookupUID(t *testing.T, present map[int]string) {
	t.Helper()
	previous := identitySpoolLookupUID
	t.Cleanup(func() { identitySpoolLookupUID = previous })
	identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
		if name, ok := present[uid]; ok {
			return unixidentity.Account{Name: name, UID: uid}, nil
		}
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
}

// GAP-1236: one account of a directory resolving does not show that another
// account of it, which the pass did not list, left: its lookup may have
// missed once. The record stays until a second successive pass that also
// does not list it, and a pass that lists it again starts over.
func TestIdentitySpoolKeepsAnOmittedAccountOfAnAnsweringDirectoryUntilASecondPass(t *testing.T) {
	stubIdentitySpoolLookupUID(t, nil) // bob's uid no longer resolves
	dir := t.TempDir()
	directoryRecord := func(uid int, user string) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, UpdatedAt: time.Now().UTC(), SSSDDomain: "dclab.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST"}}
	}
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return directoryRecord(account.UID, account.User), nil
	}
	alice := IdentitySpoolAccount{UID: 94401201, User: "dcad-alice"}
	bob := IdentitySpoolAccount{UID: 94401202, User: "dcad-bob"}
	data, err := MarshalIdentitySpoolRecord(directoryRecord(bob.UID, bob.User))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "94401202.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	for pass, step := range []struct {
		accounts []IdentitySpoolAccount
		wantBob  bool
	}{
		{[]IdentitySpoolAccount{alice}, true},      // bob's lookup missed once
		{[]IdentitySpoolAccount{alice, bob}, true}, // and recovered
		{[]IdentitySpoolAccount{alice}, true},      // a new first omission
		{[]IdentitySpoolAccount{alice}, false},     // confirmed: bob is gone
	} {
		if err := WriteIdentitySpool(context.Background(), dir, step.accounts, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "94401202.json")); (err == nil) != step.wantBob {
			t.Fatalf("pass %d: bob's record present = %v, want %v", pass+1, err == nil, step.wantBob)
		}
	}
}

// GAP-0284: a record that resolved no UPN (a signed-out Windows user) keeps
// the account's last known UPN and principal instead of account@REALM.
func TestIdentitySpoolKeepsTheLastKnownUPN(t *testing.T) {
	const sid = "S-1-5-21-1111-2222-3333-1105"
	previous := IdentitySpoolRecord{Key: sid, UPNSource: UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{
		Principal: "dcad-alice@dclab.test", UPN: "dcad-alice@dclab.test", Domain: "dclab.test", Realm: "DCLAB.TEST",
	}}
	signedOut := IdentitySpoolRecord{Key: sid, Facts: useridentity.DirectoryFacts{
		Principal: useridentity.AccountPrincipal("dcad-alice", "DCLAB.TEST"), Realm: "DCLAB.TEST",
	}}
	got := KeepLastKnownUPN(signedOut, previous)
	if got.Facts.UPN != "dcad-alice@dclab.test" || got.Facts.Principal != "dcad-alice@dclab.test" ||
		got.UPNSource != UPNSourceTranslateName {
		t.Fatalf("record = %+v, want the last known UPN", got)
	}
	if other := KeepLastKnownUPN(IdentitySpoolRecord{Key: "S-1-5-21-1111-2222-3333-1106"}, previous); other.Facts.UPN != "" {
		t.Fatalf("another account took the UPN: %+v", other)
	}
}

// TestIdentitySpoolKeepsAnInfoPipeUPNThroughAnAnswerWithoutIt: InfoPipe
// answering without userPrincipalName (the [ifp] user_attributes lost it) is
// not a verified change, so the record keeps the UPN it verified before, for
// the same account in the same SSSD domain only (GAP-1114).
func TestIdentitySpoolKeepsAnInfoPipeUPNThroughAnAnswerWithoutIt(t *testing.T) {
	const incarnation = "sid:S-1-5-21-4-4-4-1999"
	previous := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceInfoPipe,
		AccountSID: testAccountSID, AccountIncarnation: incarnation,
		Facts: useridentity.DirectoryFacts{UPN: "w4a2.alt@alt.dclab.test", Principal: "w4a2.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	derived := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceDerived,
		AccountSID: testAccountSID, AccountIncarnation: incarnation,
		Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
	got, kept := KeepVerifiedInfoPipeUPN(derived, previous, nil)
	if !kept || got.Facts.UPN != "w4a2.alt@alt.dclab.test" || got.Facts.Principal != got.Facts.UPN || got.UPNSource != UPNSourceInfoPipeKept {
		t.Fatalf("record = %+v, want the verified UPN kept", got)
	}
	moved := derived
	moved.SSSDDomain = "other.test"
	if got, kept := KeepVerifiedInfoPipeUPN(moved, previous, nil); kept || got.Facts.UPN != "" {
		t.Fatalf("an account InfoPipe holds in another domain kept the UPN: %+v", got)
	}
}

// GAP-1235: a UPN InfoPipe stopped reporting was carried into every later
// record, so a UPN removed in the directory kept selecting the account's
// UPN profile for as long as the guardian ran. It is kept for
// IdentitySpoolKeptUPNMaxAge from the first pass that kept it, and the
// GAP-1114 carry-forward still holds inside that bound.
func TestIdentitySpoolKeepsAnInfoPipeUPNOnlyForADay(t *testing.T) {
	start := time.Date(2026, 10, 13, 6, 0, 0, 0, time.UTC)
	const incarnation = "sid:S-1-5-21-4-4-4-1999"
	previous := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceInfoPipe,
		UpdatedAt: start.Add(-time.Minute), AccountSID: testAccountSID, AccountIncarnation: incarnation,
		Facts: useridentity.DirectoryFacts{UPN: "w4a2.alt@alt.dclab.test", Principal: "w4a2.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	pass := func(at time.Time) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceDerived,
			UpdatedAt: at, AccountSID: testAccountSID, AccountIncarnation: incarnation,
			Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
	}
	first, kept := KeepVerifiedInfoPipeUPN(pass(start), previous, nil)
	if !kept || first.Facts.UPN != "w4a2.alt@alt.dclab.test" || !first.UPNKeptSince.Equal(start) {
		t.Fatalf("first pass without the UPN = %+v, want it kept since %s", first, start)
	}
	// The record goes through the spool file between passes.
	data, err := MarshalIdentitySpoolRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	if first, err = ParseIdentitySpoolRecord(data, "94403999"); err != nil {
		t.Fatal(err)
	}
	later, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(23*time.Hour)), first, nil)
	if !kept || later.Facts.UPN == "" || !later.UPNKeptSince.Equal(start) {
		t.Fatalf("a pass inside the bound = %+v, want the UPN kept since %s", later, start)
	}
	gone, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(IdentitySpoolKeptUPNMaxAge)), later, nil)
	if kept || gone.Facts.UPN != "" || gone.UPNSource != UPNSourceDerived || !gone.UPNKeptSince.IsZero() {
		t.Fatalf("a pass a day after InfoPipe dropped the UPN = %+v, want the derived record", gone)
	}
	// A kept record an older build wrote (no UPNKeptSince) starts the bound now.
	legacy := later
	legacy.UPNKeptSince = time.Time{}
	if got, kept := KeepVerifiedInfoPipeUPN(pass(start.Add(30*time.Hour)), legacy, nil); !kept || !got.UPNKeptSince.Equal(start.Add(30*time.Hour)) {
		t.Fatalf("a legacy kept record = %+v, want the bound to start at this pass", got)
	}
}

// A lookup failure must reach the guardian so its next pass uses the short
// retry interval rather than treating partial directory facts as refreshed.
func TestIdentitySpoolReportsFailedAccount(t *testing.T) {
	err := WriteIdentitySpool(context.Background(), t.TempDir(),
		[]IdentitySpoolAccount{{UID: 999999999, User: ""}}, nil, nil, nil)
	if err == nil {
		t.Fatal("failed account lookup was reported as a successful spool pass")
	}
}

// GAP-0921: the gateway trusts a record by its wall-clock age, so a clock
// step forward (records look hours old) or back (records dated in the future)
// makes the records stale, and the guardian rewrites them at its next tick.
func TestIdentitySpoolStaleAfterAClockStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "94401103.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range []struct {
		written time.Time
		stale   bool
	}{{now.Add(-5 * time.Minute), false}, {now.Add(-2 * time.Hour), true}, {now.Add(2 * time.Hour), true}} {
		if err := os.Chtimes(path, tc.written, tc.written); err != nil {
			t.Fatal(err)
		}
		if _, _, stale := IdentitySpoolStale(dir, now, 17*time.Minute); stale != tc.stale {
			t.Errorf("record written %s from now: stale = %v, want %v", tc.written.Sub(now).Round(time.Minute), stale, tc.stale)
		}
	}
	if _, _, stale := IdentitySpoolStale(t.TempDir(), now, 17*time.Minute); stale {
		t.Error("an empty spool is not stale")
	}
}

// One account can stop refreshing while another still succeeds. Status must
// notice the account whose gateway record will age out.
func TestIdentitySpoolStaleWhenOneAccountStopsRefreshing(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for name, age := range map[string]time.Duration{
		"1001.json": 2 * time.Hour,
		"1002.json": 5 * time.Minute,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		written := now.Add(-age)
		if err := os.Chtimes(path, written, written); err != nil {
			t.Fatal(err)
		}
	}
	oldest, key, stale := IdentitySpoolStale(dir, now, 30*time.Minute)
	if !stale || now.Sub(oldest) < time.Hour || key != "1001" {
		t.Fatalf("oldest record = %s (%q), stale = %v; want the stale account reported", oldest, key, stale)
	}
}

// GAP-1116: a record dated in the future is the account named when it alone
// makes the spool stale; an over-age record is still named first.
func TestIdentitySpoolStaleNamesTheFutureDatedRecord(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		ages    map[string]time.Duration
		wantKey string
	}{
		{map[string]time.Duration{"1001": -10 * time.Minute, "1002": 0}, "1001"},
		{map[string]time.Duration{"1001": -10 * time.Minute, "1002": 0, "1003": 2 * time.Hour}, "1003"},
	} {
		dir := t.TempDir()
		for key, age := range tc.ages {
			path := filepath.Join(dir, key+".json")
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			written := now.Add(-age)
			if err := os.Chtimes(path, written, written); err != nil {
				t.Fatal(err)
			}
		}
		when, key, stale := IdentitySpoolStale(dir, now, 5*time.Minute)
		if !stale || key != tc.wantKey || !when.Equal(now.Add(-tc.ages[tc.wantKey])) {
			t.Fatalf("records %v: stale = %v, key %q at %s; want %q", tc.ages, stale, key, when, tc.wantKey)
		}
	}
}

// GAP-1075: a macOS record dscl returned by short name is refused unless its
// UniqueID is the uid the enumerator resolves: another account's verified
// identity must not be spooled under this uid.
func TestMacOSRecordOfAnotherAccountIsRefused(t *testing.T) {
	if err := checkMacOSRecordUID("UniqueID: 501\nAuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n", 501); err != nil {
		t.Fatalf("the account's own record was refused: %v", err)
	}
	err := checkMacOSRecordUID("UniqueID: 1404012345\nAltSecurityIdentities: PlatformSSO:alice@contoso.example\n", 501)
	if err == nil || !strings.Contains(err.Error(), "record belongs to another account") {
		t.Fatalf("another account's record was accepted: %v", err)
	}
	if err := checkMacOSRecordUID("AuthenticationAuthority: ;ShadowHash;\n", 501); err == nil {
		t.Fatal("a record without a UniqueID was accepted")
	}
}

// W2B-G-enum review: a directory listing can omit an account on every pass
// while another account of the directory resolves (SSSD enumerate=false, a
// partial answer). Two such passes removed the omitted account's fresh
// record, and a profile assigned by its UPN fell to the default. The record
// now stays while the account's own uid still resolves to it, until it ages
// out; it goes once the uid stops resolving or names another account, and at
// once for an account the enrollment settings leave out.
func TestIdentitySpoolKeepsAnAccountPartialListingsOmitWhileItResolves(t *testing.T) {
	dir := t.TempDir()
	directoryRecord := func(uid int, user string) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, UpdatedAt: time.Now().UTC(), SSSDDomain: "dclab.test",
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Realm: "DCLAB.TEST", UPN: user + "@dclab.test"}}
	}
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return directoryRecord(account.UID, account.User), nil
	}
	present := map[int]string{94401302: "dcad-bob", 94401303: "dcad-carol"}
	stubIdentitySpoolLookupUID(t, present)
	alice := IdentitySpoolAccount{UID: 94401301, User: "dcad-alice"}
	for _, record := range []IdentitySpoolRecord{directoryRecord(94401302, "dcad-bob"), directoryRecord(94401303, "dcad-carol")} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	has := func(key string) bool {
		_, err := os.Stat(filepath.Join(dir, key+".json"))
		return err == nil
	}
	pass := func(accounts ...IdentitySpoolAccount) {
		t.Helper()
		if err := WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 4 {
		pass(alice)
		if !has("94401302") || !has("94401303") {
			t.Fatalf("partial listing %d removed a record of an account that still resolves: bob %v, carol %v", i+1, has("94401302"), has("94401303"))
		}
	}
	// carol's uid now names another account; bob's still resolves.
	present[94401303] = "dcad-dave"
	pass(alice)
	if has("94401303") || !has("94401302") {
		t.Fatalf("after carol's uid was reassigned: carol %v, bob %v; want carol's record gone and bob's kept", has("94401303"), has("94401302"))
	}
	withdrawn := func(key string) bool {
		_, err := ReadIdentitySpoolWithdrawal(dir, key, nil)
		return err == nil
	}
	if !withdrawn("94401303") || withdrawn("94401302") {
		t.Fatalf("withdrawals: carol %v, bob %v; want carol's departed identity withdrawn and bob's not", withdrawn("94401303"), withdrawn("94401302"))
	}
	// bob's record ages out while every listing still omits him.
	old := time.Now().Add(-IdentitySpoolMaxAge - time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "94401302.json"), old, old); err != nil {
		t.Fatal(err)
	}
	pass(alice)
	if has("94401302") {
		t.Fatal("the record of an account the listings omit outlived its maximum age")
	}
	if !withdrawn("94401303") {
		t.Fatal("a young withdrawal went at the next pass; the gateway trusts the record it withdraws for an hour")
	}
	if err := os.Chtimes(filepath.Join(dir, "94401303"+IdentitySpoolWithdrawalSuffix), old, old); err != nil {
		t.Fatal(err)
	}
	pass(alice)
	if withdrawn("94401303") {
		t.Fatal("a withdrawal outlived its maximum age")
	}
	// An account the enrollment settings leave out goes at once, also while
	// it resolves.
	erin := IdentitySpoolAccount{UID: 94401305, User: "dcad-erin"}
	present[erin.UID] = erin.User
	pass(alice, erin)
	if !has("94401305") {
		t.Fatal("erin's record was not published")
	}
	pass(alice, IdentitySpoolAccount{UID: erin.UID, Left: true})
	if has("94401305") {
		t.Fatal("the record of an account the enrollment leaves out was kept")
	}
}

// testDirectoryRecord is a young SSSD record of an Active Directory account
// in domain (lower case), with its UPN there.
func testDirectoryRecord(uid int, user, domain string) IdentitySpoolRecord {
	return IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, UpdatedAt: time.Now().UTC(), SSSDDomain: domain,
		UPNSource: UPNSourceInfoPipe,
		Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Realm: strings.ToUpper(domain),
			Domain: domain, UPN: user + "@" + domain, Principal: user + "@" + domain}}
}

func writeTestSpoolRecord(t *testing.T, dir string, record IdentitySpoolRecord) {
	t.Helper()
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

// W2B-G-enum review loop 1: a record a partial listing omits was kept while
// its uid resolved to the same name, so a uid reused by the same short name
// in another domain kept the first account's verified UPN and the gateway,
// which checks only the name, selected a profile by it. The record is now
// bound to its directory identity: a uid that names the same name in another
// domain or directory, or a local account, removes the record at once,
// also on a failed pass; an answer that names nothing to compare keeps it.
func TestIdentitySpoolDropsTheRecordOfAUIDReusedBySameNameInAnotherDomain(t *testing.T) {
	const aliceUID, bobUID = 94401401, 94401402
	sameName := map[int]string{aliceUID: "dcad-alice", bobUID: "dcad-bob"}
	partial := func(record IdentitySpoolRecord) (IdentitySpoolRecord, error) {
		record.SSSDDomain, record.UPNSource, record.Facts.UPN, record.Facts.Principal = "", "", "", ""
		return record, errors.New("SSSD InfoPipe lookup: timed out")
	}
	for _, tc := range []struct {
		name string
		// bob is what the directory answers for bob's uid now.
		bob func() (IdentitySpoolRecord, error)
		// alicePassFails makes the listed account's lookup fail, so the
		// pass fails.
		alicePassFails bool
		wantKept       bool
	}{
		{name: "same identity", bob: func() (IdentitySpoolRecord, error) {
			return testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"), nil
		}, wantKept: true},
		{name: "same name in another domain", bob: func() (IdentitySpoolRecord, error) {
			return testDirectoryRecord(bobUID, "dcad-bob", "other.test"), nil
		}},
		{name: "same name in another domain, failed pass", alicePassFails: true, bob: func() (IdentitySpoolRecord, error) {
			return testDirectoryRecord(bobUID, "dcad-bob", "other.test"), nil
		}},
		{name: "same name, now a local account", bob: func() (IdentitySpoolRecord, error) {
			return IdentitySpoolRecord{Key: strconv.Itoa(bobUID), User: "dcad-bob",
				Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}}, nil
		}},
		{name: "same domain, another UPN", bob: func() (IdentitySpoolRecord, error) {
			record := testDirectoryRecord(bobUID, "dcad-bob", "dclab.test")
			record.Facts.UPN = "robert@dclab.test"
			return record, nil
		}},
		{name: "partial answer in the same realm", bob: func() (IdentitySpoolRecord, error) {
			return partial(testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
		}, wantKept: true},
		{name: "partial answer in another realm", bob: func() (IdentitySpoolRecord, error) {
			return partial(testDirectoryRecord(bobUID, "dcad-bob", "other.test"))
		}},
		{name: "no answer", bob: func() (IdentitySpoolRecord, error) {
			return IdentitySpoolRecord{}, errors.New("sssd: backend offline")
		}, wantKept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubIdentitySpoolLookupUID(t, sameName)
			previous := identitySpoolCollect
			t.Cleanup(func() { identitySpoolCollect = previous })
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
				if account.UID == bobUID {
					return tc.bob()
				}
				if tc.alicePassFails {
					return IdentitySpoolRecord{}, errors.New("sssd: backend offline")
				}
				return testDirectoryRecord(account.UID, account.User, "dclab.test"), nil
			}
			dir := t.TempDir()
			writeTestSpoolRecord(t, dir, testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
			for pass := range 2 {
				err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: aliceUID, User: "dcad-alice"}}, nil, nil, nil)
				if (err != nil) != tc.alicePassFails {
					t.Fatalf("pass %d: err = %v, want failed %v", pass+1, err, tc.alicePassFails)
				}
				record, readErr := ReadIdentitySpoolRecord(dir, strconv.Itoa(bobUID), nil)
				if (readErr == nil) != tc.wantKept {
					t.Fatalf("pass %d: bob's record kept = %v (%+v), want %v", pass+1, readErr == nil, record, tc.wantKept)
				}
				if readErr == nil && record.Facts.UPN != "dcad-bob@dclab.test" {
					t.Fatalf("pass %d: bob's record changed: %+v", pass+1, record)
				}
				if _, err := ReadIdentitySpoolWithdrawal(dir, strconv.Itoa(bobUID), nil); (err == nil) == tc.wantKept {
					t.Fatalf("pass %d: bob's identity withdrawn = %v, want %v", pass+1, err == nil, !tc.wantKept)
				}
			}
		})
	}
}

// The same rule for a listed account whose privileged lookup fails: its
// previous record is kept through the failure only while the facts the
// lookup did get name the same directory identity.
func TestIdentitySpoolFailedLookupDoesNotKeepAnotherDomainsUPN(t *testing.T) {
	const bobUID = 94401412
	for _, tc := range []struct {
		domain  string
		wantUPN string
	}{
		{"dclab.test", "dcad-bob@dclab.test"},
		{"other.test", ""},
	} {
		dir := t.TempDir()
		writeTestSpoolRecord(t, dir, testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
		previous := identitySpoolCollect
		identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
			record := testDirectoryRecord(account.UID, account.User, tc.domain)
			record.SSSDDomain, record.UPNSource, record.Facts.UPN, record.Facts.Principal = "", "", "", ""
			return record, errors.New("SSSD InfoPipe lookup: timed out")
		}
		err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: bobUID, User: "dcad-bob"}}, nil, nil, nil)
		identitySpoolCollect = previous
		if err == nil {
			t.Fatalf("%s: the failed lookup was not reported", tc.domain)
		}
		record, readErr := ReadIdentitySpoolRecord(dir, strconv.Itoa(bobUID), nil)
		if readErr != nil || record.Facts.UPN != tc.wantUPN {
			t.Fatalf("%s: record %+v (%v), want UPN %q", tc.domain, record, readErr, tc.wantUPN)
		}
		// The basic facts of the other domain's account name no UPN to
		// contradict the gateway's cached one, so the identity is withdrawn.
		if _, err := ReadIdentitySpoolWithdrawal(dir, strconv.Itoa(bobUID), nil); (err == nil) != (tc.wantUPN == "") {
			t.Fatalf("%s: identity withdrawn = %v, want %v", tc.domain, err == nil, tc.wantUPN == "")
		}
	}
}

// A pre-1.0.4 spool record has no SID. The directory can recreate an account
// with the same uid, name and domain; a partial lookup of the new SID must not
// let the old record's UPN select the new account's profile.
func TestIdentitySpoolFailedLookupDropsSIDLessRecordWhenFreshSIDIsKnown(t *testing.T) {
	const uid = 94401413
	dir := t.TempDir()
	old := testDirectoryRecord(uid, "dcad-bob", "dclab.test")
	writeTestSpoolRecord(t, dir, old)
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		fresh := testDirectoryRecord(account.UID, account.User, "dclab.test")
		fresh.AccountSID = "S-1-5-21-1111-2222-3333-1106"
		fresh.UPNSource, fresh.Facts.UPN, fresh.Facts.Principal = "", "", ""
		return fresh, errors.New("SSSD InfoPipe UPN lookup: timed out")
	}
	if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: uid, User: old.User}}, nil, nil, nil); err == nil {
		t.Fatal("the failed lookup was not reported")
	}
	got, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
	if err != nil || got.AccountSID != "S-1-5-21-1111-2222-3333-1106" || got.Facts.UPN != "" {
		t.Fatalf("old UPN survived an unproven account binding: %+v (%v)", got, err)
	}
}

// W2B-G-enum review loop 1: the departure lookups of omitted records ran
// without the pass context, so a slow NSS or Open Directory lookup held the
// pass, and the spool refreshes after it, past its deadline. They now end
// with the pass; a record whose check did not finish stays with its mark, so
// its removal is only deferred; and a lookup that ignores its deadline
// holds only its own account's checks until it returns.
func TestIdentitySpoolDepartureChecksEndWithThePass(t *testing.T) {
	const aliceUID, bobUID = 94401421, 94401422
	dir := t.TempDir()
	previousCollect, previousLookup := identitySpoolCollect, identitySpoolLookupUID
	release, released := make(chan struct{}), false
	releaseLookups := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(func() {
		releaseLookups()
		waitIdentityLookupGateIdle(t, &identitySpoolDepartureGate)
		identitySpoolCollect, identitySpoolLookupUID = previousCollect, previousLookup
	})
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return testDirectoryRecord(account.UID, account.User, "dclab.test"), nil
	}
	var calls atomic.Int32
	var blocked atomic.Bool
	identitySpoolLookupUID = func(context.Context, int) (unixidentity.Account, error) {
		calls.Add(1)
		if blocked.Load() {
			<-release // a lookup that ignores its deadline
		}
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	writeTestSpoolRecord(t, dir, testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
	alice := []IdentitySpoolAccount{{UID: aliceUID, User: "dcad-alice"}}
	has := func() bool {
		_, err := os.Stat(filepath.Join(dir, strconv.Itoa(bobUID)+".json"))
		return err == nil
	}
	// Pass 1: bob's uid does not resolve; the first omission only marks.
	if err := WriteIdentitySpool(context.Background(), dir, alice, nil, nil, nil); err != nil || !has() {
		t.Fatalf("pass 1: err %v, bob kept %v; want the record marked and kept", err, has())
	}
	// Pass 2: the lookup blocks; the pass ends with its context.
	blocked.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- WriteIdentitySpool(ctx, dir, alice, nil, nil, nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pass 2: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pass 2 waited for a blocked departure lookup past its deadline")
	}
	if running := identitySpoolDepartureGate.runningLookups(); !has() || running != 1 {
		t.Fatalf("pass 2: bob kept %v, lookups left running %d; want the record kept and one lookup counted", has(), running)
	}
	// While that lookup runs, no second lookup of bob starts and his record
	// stays.
	blocked.Store(false)
	before := calls.Load()
	if err := WriteIdentitySpool(context.Background(), dir, alice, nil, nil, nil); err != nil || !has() || calls.Load() != before {
		t.Fatalf("while bob's lookup runs: err %v, bob kept %v, lookups started %d; want none started and the record kept", err, has(), calls.Load()-before)
	}
	releaseLookups()
	waitIdentityLookupGateIdle(t, &identitySpoolDepartureGate)
	// The mark survived both: the next pass that finds the uid gone removes
	// the record.
	if err := WriteIdentitySpool(context.Background(), dir, alice, nil, nil, nil); err != nil || has() {
		t.Fatalf("pass after the cut-short checks: err %v, bob kept %v; want the record removed", err, has())
	}
}

// W2B-G-enum review loop 2: a departure lookup that never returned was
// started again on every pass and counted against one limit shared by every
// account, so after four passes no departure check ran for anyone: a record
// whose uid now names another account kept its UPN facts until it aged out.
// Now a lookup still running holds only its own account: bob's record stays
// with its mark, and carol's uid, which no longer resolves, is still checked
// and her record removed.
func TestIdentitySpoolDepartureLookupThatNeverReturnsHoldsOnlyItsAccount(t *testing.T) {
	const aliceUID, bobUID, carolUID = 94401431, 94401432, 94401433
	dir := t.TempDir()
	previousCollect, previousLookup := identitySpoolCollect, identitySpoolLookupUID
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		waitIdentityLookupGateIdle(t, &identitySpoolDepartureGate)
		identitySpoolCollect, identitySpoolLookupUID = previousCollect, previousLookup
	})
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		return testDirectoryRecord(account.UID, account.User, "dclab.test"), nil
	}
	var bobCalls atomic.Int32
	identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
		if uid == bobUID {
			bobCalls.Add(1)
			<-release // an Open Directory call that ignores its deadline
		}
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	writeTestSpoolRecord(t, dir, testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
	writeTestSpoolRecord(t, dir, testDirectoryRecord(carolUID, "dcad-carol", "dclab.test"))
	alice := []IdentitySpoolAccount{{UID: aliceUID, User: "dcad-alice"}}
	has := func(uid int) bool {
		_, err := os.Stat(filepath.Join(dir, strconv.Itoa(uid)+".json"))
		return err == nil
	}
	for pass := 1; pass <= 6; pass++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := WriteIdentitySpool(ctx, dir, alice, nil, nil, nil)
		cancel()
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if !has(bobUID) {
			t.Fatalf("pass %d: bob's record was removed while his check never finished", pass)
		}
	}
	if has(carolUID) {
		t.Fatal("carol's record stays: her departure check never ran while bob's lookup was stuck")
	}
	if bobCalls.Load() != 1 {
		t.Fatalf("bob's lookups started = %d, want one while it runs", bobCalls.Load())
	}
}

// testAccountSID and testRecreatedAccountSID are the SIDs SSSD holds for one
// uid before and after its account was deleted and recreated in AD under the
// same uid (POSIX uidNumber), name and SSSD domain.
const (
	testAccountSID          = "S-1-5-21-1-2-3-1601"
	testRecreatedAccountSID = "S-1-5-21-1-2-3-1777"
)

// W2B-G-enum review loop 4: an AD account recreated under the same uid,
// short name and SSSD domain kept the old account's UPN for up to a day when
// InfoPipe answered for the new one without userPrincipalName, and the
// gateway selected the old account's UPN profile. Two SIDs now decide.
//
// Review loop 5: a record without a SID on either side (one a build before
// 1.0.4 wrote, or an account of a directory without SIDs) then lost its UPN
// at once, so the first pass after the upgrade sent a UPN assignment to the
// default profile. The directory now decides whether it gives the UPN to
// this account.
//
// r104 identity: a directory that does not answer proves nothing, so the
// UPN goes (GAP-0384). A request whose assignment needs it is refused,
// naming the missing UPN; a request that does not need it uses proven facts.
func TestIdentitySpoolKeepsAnInfoPipeUPNOnlyForTheSameAccount(t *testing.T) {
	record := func(sid string, upn bool) IdentitySpoolRecord {
		// One incarnation on both sides, so the SID alone decides here.
		r := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2", SSSDDomain: "dclab.test", AccountSID: sid, UpdatedAt: time.Now().UTC(),
			AccountIncarnation: testSameIncarnation, UPNSource: UPNSourceDerived, Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
		if upn {
			r.UPNSource, r.Facts.UPN, r.Facts.Principal, r.Facts.Source = UPNSourceInfoPipe, "w4a2.alt@alt.dclab.test", "w4a2.alt@alt.dclab.test", useridentity.SourceSSSDInfoPipe
		}
		return r
	}
	const (
		unknown = UPNBindingUnknown
		bound   = UPNBindingBound
		other   = UPNBindingOther
	)
	for _, tc := range []struct {
		name, previous, fresh string
		binding               UPNBinding
		asked, kept           bool
		// sid is the SID the kept record carries.
		sid string
	}{
		{"same SID", testAccountSID, testAccountSID, other, false, true, testAccountSID},
		{"same SID in another case", testAccountSID, strings.ToLower(testAccountSID), other, false, true, strings.ToLower(testAccountSID)},
		{"recreated account", testAccountSID, testRecreatedAccountSID, bound, false, false, ""},
		{"previous record without a SID, the directory binds the UPN", "", testAccountSID, bound, true, true, testAccountSID},
		{"previous record without a SID, another account holds the UPN", "", testAccountSID, other, true, false, ""},
		{"previous record without a SID, the directory does not answer", "", testAccountSID, unknown, true, false, ""},
		{"no SID now, the directory binds the UPN", testAccountSID, "", bound, true, true, ""},
		{"no SID now, another account holds the UPN", testAccountSID, "", other, true, false, ""},
		{"no SID now, the directory does not answer", testAccountSID, "", unknown, true, false, ""},
		{"no SID on either, the directory binds the UPN", "", "", bound, true, true, ""},
		{"no SID on either, another account holds the UPN", "", "", other, true, false, ""},
		{"no SID on either, the directory does not answer", "", "", unknown, true, false, ""},
	} {
		asked := ""
		got, kept := KeepVerifiedInfoPipeUPN(record(tc.fresh, false), record(tc.previous, true), func(upn string) UPNBinding {
			asked = upn
			return tc.binding
		})
		if (asked != "") != tc.asked || (tc.asked && asked != "w4a2.alt@alt.dclab.test") {
			t.Errorf("%s: directory asked about %q, want asked %v", tc.name, asked, tc.asked)
		}
		if kept != tc.kept || (got.Facts.UPN != "") != tc.kept || (tc.kept && got.AccountSID != tc.sid) {
			t.Errorf("%s: kept %v, record %+v; want kept %v with SID %q", tc.name, kept, got, tc.kept, tc.sid)
		}
	}
	// Without a binding function nothing is proven: the UPN goes.
	if got, kept := KeepVerifiedInfoPipeUPN(record(testAccountSID, false), record("", true), nil); kept || got.Facts.UPN != "" {
		t.Errorf("no binding function: kept %v, record %+v; want the UPN gone", kept, got)
	}
	// T5 integration (w2b-g-enum's SID rule with w2b-g-ident's incarnation
	// rule): the same SID does not keep the UPN of a previous record that
	// names no incarnation (a guardian before 1.0.4 wrote it), nor one whose
	// incarnation differs. Both rules must hold.
	previous := record(testAccountSID, true)
	previous.AccountIncarnation = ""
	if got, kept := KeepVerifiedInfoPipeUPN(record(testAccountSID, false), previous, nil); kept || got.Facts.UPN != "" {
		t.Errorf("same SID, previous record without an incarnation: kept %v, record %+v; want the UPN gone", kept, got)
	}
	previous.AccountIncarnation = "nss:files"
	if got, kept := KeepVerifiedInfoPipeUPN(record(testAccountSID, false), previous, nil); kept || got.Facts.UPN != "" {
		t.Errorf("same SID, another incarnation: kept %v, record %+v; want the UPN gone", kept, got)
	}
}

// testSameIncarnation is the account incarnation of the SID tests: the
// same on both records, so only the SID differs.
const testSameIncarnation = "nss:sss"

// The same account recreated under the same uid, name and SSSD domain, end
// to end through the guardian pass: whether the new account's InfoPipe
// answer lacks the UPN, its lookup fails after NSS answered, or a listing
// omits it, the old account's UPN is gone after the pass. The same SID keeps
// it in each case.
func TestIdentitySpoolDropsTheUPNOfAnAccountRecreatedUnderTheSameUID(t *testing.T) {
	const aliceUID, bobUID = 94401601, 94401602
	stubIdentitySpoolLookupUID(t, map[int]string{aliceUID: "dcad-alice", bobUID: "dcad-bob"})
	withSID := func(record IdentitySpoolRecord, sid string) IdentitySpoolRecord {
		record.AccountSID = sid
		record.AccountIncarnation = testSameIncarnation
		return record
	}
	withoutUPN := func(record IdentitySpoolRecord) IdentitySpoolRecord {
		record.UPNSource, record.Facts.UPN, record.Facts.Principal = UPNSourceDerived, "", "dcad-bob@DCLAB.TEST"
		return record
	}
	for _, tc := range []struct {
		name string
		// listed: bob is listed in the pass (else only alice is).
		listed bool
		// answer is what the directory answers for bob's uid now.
		answer func(sid string) (IdentitySpoolRecord, error)
	}{
		{"InfoPipe answers without the UPN", true, func(sid string) (IdentitySpoolRecord, error) {
			return withoutUPN(withSID(testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"), sid)), nil
		}},
		{"the InfoPipe lookup fails after NSS answered", true, func(sid string) (IdentitySpoolRecord, error) {
			record := withSID(testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"), sid)
			record.SSSDDomain, record.UPNSource, record.Facts.UPN, record.Facts.Principal = "", "", "", ""
			return record, errors.New("SSSD InfoPipe lookup: timed out")
		}},
		{"a listing omits the account", false, func(sid string) (IdentitySpoolRecord, error) {
			return withSID(testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"), sid), nil
		}},
	} {
		for _, sid := range []string{testRecreatedAccountSID, testAccountSID} {
			recreated := sid == testRecreatedAccountSID
			t.Run(fmt.Sprintf("%s, recreated %v", tc.name, recreated), func(t *testing.T) {
				previous := identitySpoolCollect
				t.Cleanup(func() { identitySpoolCollect = previous })
				identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
					if account.UID == bobUID {
						return tc.answer(sid)
					}
					return testDirectoryRecord(account.UID, account.User, "dclab.test"), nil
				}
				dir := t.TempDir()
				writeTestSpoolRecord(t, dir, withSID(testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"), testAccountSID))
				accounts := []IdentitySpoolAccount{{UID: aliceUID, User: "dcad-alice"}}
				if tc.listed {
					accounts = append(accounts, IdentitySpoolAccount{UID: bobUID, User: "dcad-bob"})
				}
				_ = WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil)
				record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(bobUID), nil)
				if hasUPN := err == nil && record.Facts.UPN == "dcad-bob@dclab.test"; hasUPN == recreated {
					t.Fatalf("bob's record %+v (%v): the old account's UPN kept %v, want %v", record, err, hasUPN, !recreated)
				}
			})
		}
	}
}

// W2B-G-enum review loop 4: a pass that omitted an account whose uid still
// resolved to it marked its record all the same, so one transient not-found
// answer at the next omission removed a live account's record, and a profile
// assigned by its UPN fell to the default. Only a not-found answer marks the
// record now; it goes at a second one in a row, and a check that finds the
// uid naming the account again clears the mark, also on a failed pass.
func TestIdentitySpoolRemovesAnOmittedRecordOnlyAfterTwoNotFoundAnswersInARow(t *testing.T) {
	const aliceUID, bobUID = 94401701, 94401702
	for _, tc := range []struct {
		name string
		// answers is what bob's uid gives at each pass that omits him:
		// found, notfound, error (a lookup that fails otherwise), or
		// found-failed (found, while alice's lookup fails the pass).
		answers []string
		// gone is the pass after which bob's record is gone, 0 for none.
		gone int
	}{
		{"found, then one miss", []string{"found", "notfound"}, 0},
		{"found, miss, found, miss", []string{"found", "notfound", "found", "notfound"}, 0},
		{"two misses in a row", []string{"found", "notfound", "notfound"}, 3},
		{"found on a failed pass clears the mark", []string{"notfound", "found-failed", "notfound"}, 0},
		{"a check that fails keeps the mark", []string{"notfound", "error", "notfound"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := ""
			previousLookup := identitySpoolLookupUID
			t.Cleanup(func() { identitySpoolLookupUID = previousLookup })
			identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
				switch {
				case uid == aliceUID:
					return unixidentity.Account{Name: "dcad-alice", UID: uid}, nil
				case answer == "notfound":
					return unixidentity.Account{}, unixidentity.ErrNotFound
				case answer == "error":
					return unixidentity.Account{}, errors.New("sssd: backend offline")
				}
				return unixidentity.Account{Name: "dcad-bob", UID: uid}, nil
			}
			previousCollect := identitySpoolCollect
			t.Cleanup(func() { identitySpoolCollect = previousCollect })
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
				if account.UID == aliceUID && answer == "found-failed" {
					return IdentitySpoolRecord{}, errors.New("sssd: backend offline")
				}
				return testDirectoryRecord(account.UID, account.User, "dclab.test"), nil
			}
			dir := t.TempDir()
			writeTestSpoolRecord(t, dir, testDirectoryRecord(bobUID, "dcad-bob", "dclab.test"))
			for pass, next := range tc.answers {
				answer = next
				_ = WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: aliceUID, User: "dcad-alice"}}, nil, nil, nil)
				_, err := os.Stat(filepath.Join(dir, strconv.Itoa(bobUID)+".json"))
				if wantGone := tc.gone != 0 && pass+1 >= tc.gone; (err != nil) != wantGone {
					t.Fatalf("pass %d (%s): bob's record gone %v, want %v", pass+1, next, err != nil, wantGone)
				}
			}
		})
	}
}
