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
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if err := WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401107, User: "erin"}}, nil, nil); err == nil {
		t.Fatal("the canceled lookup did not fail the pass")
	}
	if !exists("94401103") || !exists("94401106") || exists("94401104") {
		t.Fatalf("after a failed pass: directory %v, local %v, expired %v; want the young records kept and the expired one gone",
			exists("94401103"), exists("94401106"), exists("94401104"))
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil); err != nil {
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
	_ = WriteIdentitySpool(canceled, dir, []IdentitySpoolAccount{{UID: 94401105, User: "bob"}}, nil, nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reassigned uid kept previous account record: %v", err)
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
	previous := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceInfoPipe,
		Facts: useridentity.DirectoryFacts{UPN: "w4a2.alt@alt.dclab.test", Principal: "w4a2.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	derived := IdentitySpoolRecord{Key: "94403999", User: "dcad-w4a2@dclab.test", SSSDDomain: "dclab.test", UPNSource: UPNSourceDerived,
		Facts: useridentity.DirectoryFacts{Principal: "dcad-w4a2@DCLAB.TEST", Source: useridentity.SourceSSSD}}
	got, kept := KeepVerifiedInfoPipeUPN(derived, previous)
	if !kept || got.Facts.UPN != "w4a2.alt@alt.dclab.test" || got.Facts.Principal != got.Facts.UPN || got.UPNSource != UPNSourceInfoPipeKept {
		t.Fatalf("record = %+v, want the verified UPN kept", got)
	}
	moved := derived
	moved.SSSDDomain = "other.test"
	if got, kept := KeepVerifiedInfoPipeUPN(moved, previous); kept || got.Facts.UPN != "" {
		t.Fatalf("an account InfoPipe holds in another domain kept the UPN: %+v", got)
	}
}

// A lookup failure must reach the guardian so its next pass uses the short
// retry interval rather than treating partial directory facts as refreshed.
func TestIdentitySpoolReportsFailedAccount(t *testing.T) {
	err := WriteIdentitySpool(context.Background(), t.TempDir(),
		[]IdentitySpoolAccount{{UID: 999999999, User: ""}}, nil, nil)
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
