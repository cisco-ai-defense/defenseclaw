//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// writeWithdrawTestRecord writes the identity record of uid into dir.
func writeWithdrawTestRecord(t *testing.T, dir string, record enterprisehooks.IdentitySpoolRecord) {
	t.Helper()
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Now().UTC()
	}
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func withdrawTestRecordExists(t *testing.T, dir string, uid int) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, strconv.Itoa(uid)+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// withdrawTestSettings installs a standalone configuration with the given
// exclude_users and exempt_users, and restores the previous one after t.
func withdrawTestSettings(t *testing.T) func(exclude, exempt []string) {
	t.Helper()
	previousCfg, previousAccepted := cfg, enterpriseHookLoadAcceptedTargets
	previousEligible, previousIdentity := enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts
	previousMachine := enterpriseHookLoadMachinePolicyConnectors
	enterpriseHookLeftOutProven.Lock()
	previousProofs := enterpriseHookLeftOutProven.proofs
	enterpriseHookLeftOutProven.proofs = map[string]enterpriseHookLeftOutProof{}
	enterpriseHookLeftOutProven.Unlock()
	t.Cleanup(func() {
		cfg, enterpriseHookLoadAcceptedTargets = previousCfg, previousAccepted
		enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = previousEligible, previousIdentity
		enterpriseHookLoadMachinePolicyConnectors = previousMachine
		enterpriseHookLeftOutProven.Lock()
		enterpriseHookLeftOutProven.proofs = previousProofs
		enterpriseHookLeftOutProven.Unlock()
		enterprisehooks.SetStandaloneResolver(nil)
	})
	return func(exclude, exempt []string) {
		cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Enterprise.Profile = managed.ProfileStandalone
		cfg.Enterprise.Enrollment.ExcludeUsers, cfg.Enterprise.Enrollment.ExemptUsers = exclude, exempt
		// No machine-policy connector: the gateway accepts only enrolled
		// and exempt callers.
		enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return nil, nil }
	}
}

// W2B-G-enum review loop 6 (P1): an exclusion withdrew the identity record
// of an account whose hooks the guardian authorization still accepted. The
// enumerator could not publish the manifest that leaves the account out, so
// the guardian kept reconciling its old row; or an empty or partial manifest
// left it out while the reconcile could not rewrite the authorization. The
// gateway kept accepting the account's hook calls, but without its record
// they no longer selected the profile assigned to its UPN, and the default
// can be less restrictive. A record is now withdrawn only once the
// authorization no longer accepts the account, and an authorization that
// does not read withdraws nothing.
func TestIdentityRecordStaysWhileTheGuardianAuthorizationAcceptsTheAccount(t *testing.T) {
	settings := withdrawTestSettings(t)
	const aliceUID, bobUID = 4242, 4243
	bob := unixidentity.Account{Name: "bob", UID: bobUID, GID: bobUID}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"alice":            {Name: "alice", UID: aliceUID, GID: aliceUID},
		"bob":              bob,
		"bob@corp.example": bob,
	}})
	const manifest = "/etc/defenseclaw/hooks/manifest.json"
	aliceRow := enterpriseHookReconcileRow{User: "alice", UserHome: "/home/alice", Connector: "opencode", OK: true, UID: aliceUID}
	bobRow := enterpriseHookReconcileRow{User: "bob", UserHome: "/home/bob", Connector: "opencode", OK: true, UID: bobUID}
	bobFailed := bobRow
	bobFailed.OK = false
	bobByName := enterpriseHookReconcileRow{User: "bob", UserHome: "/home/bob", Connector: "opencode", OK: true}
	accepts := func(rows ...enterpriseHookReconcileRow) func() ([]enterpriseHookReconcileRow, error) {
		return func() ([]enterpriseHookReconcileRow, error) { return rows, nil }
	}
	unreadable := func() ([]enterpriseHookReconcileRow, error) {
		return nil, errors.New("hook guardian authorization is not a regular file")
	}
	staleBob := []enterprisehooks.UnixEligibleAccount{{User: "bob", UID: bobUID, Home: "/home/bob"}}
	for _, tc := range []struct {
		name          string
		exclude       []string
		rows          []enterpriseHookReconcileRow
		eligible      []enterprisehooks.UnixEligibleAccount
		authorization func() ([]enterpriseHookReconcileRow, error)
		kept          bool
	}{
		{name: "excluded by name, the manifest publish failed", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, authorization: accepts(aliceRow, bobRow), kept: true},
		{name: "excluded by uid, the manifest publish failed", exclude: []string{strconv.Itoa(bobUID)},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, authorization: accepts(aliceRow, bobRow), kept: true},
		{name: "excluded by another spelling, the manifest publish failed", exclude: []string{"bob@corp.example"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, authorization: accepts(aliceRow, bobRow), kept: true},
		{name: "an empty manifest, the authorization not rewritten", exclude: []string{"bob"},
			eligible: staleBob, authorization: accepts(bobRow), kept: true},
		{name: "a partial manifest that omits bob, the authorization not rewritten", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow}, authorization: accepts(aliceRow, bobRow), kept: true},
		{name: "the authorization accepts bob by name", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, authorization: accepts(aliceRow, bobByName), kept: true},
		{name: "the authorization does not read", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, eligible: staleBob, authorization: unreadable, kept: true},
		{name: "the authorization no longer accepts bob", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobRow}, authorization: accepts(aliceRow)},
		{name: "bob's target failed and was not carried forward", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow, bobFailed}, authorization: accepts(aliceRow, bobFailed)},
		{name: "an empty manifest, the authorization rewritten", exclude: []string{"bob"},
			eligible: staleBob, authorization: accepts()},
		{name: "a partial manifest that omits bob, the authorization rewritten", exclude: []string{"bob"},
			rows: []enterpriseHookReconcileRow{aliceRow}, authorization: accepts(aliceRow)},
		{name: "excluded by uid, the authorization rewritten", exclude: []string{strconv.Itoa(bobUID)},
			rows: []enterpriseHookReconcileRow{aliceRow}, authorization: accepts(aliceRow)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings(tc.exclude, nil)
			load := func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return tc.eligible, nil }
			enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = load, load
			enterpriseHookLoadAcceptedTargets = tc.authorization
			dir := t.TempDir()
			writeWithdrawTestRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(bobUID), User: "bob"})
			run := enterpriseHookReconcileRun{Manifest: manifest, Rows: tc.rows}
			accounts, keys, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, run)
			enrolled := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == bobUID && !a.Left })
			left := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == bobUID && a.Left })
			if enrolled != tc.kept || (tc.kept && (left || slices.Contains(keys, "left:"+strconv.Itoa(bobUID)))) {
				t.Fatalf("identity accounts %+v (keys %v): bob enrolled %t, want %t", accounts, keys, enrolled, tc.kept)
			}
			if !tc.kept && !left && !withdraw(bobUID, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(bobUID), User: "bob"}) {
				t.Fatalf("bob is neither left out nor his record withdrawn: accounts %+v", accounts)
			}
			// The pass: a canceled one, so no listed account resolves, and
			// only an exclusion removes bob's record.
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_ = enterprisehooks.WriteIdentitySpool(canceled, dir, accounts, nil, nil, withdraw)
			if got := withdrawTestRecordExists(t, dir, bobUID); got != tc.kept {
				t.Fatalf("bob's identity record exists %t after the pass, want %t", got, tc.kept)
			}
		})
	}
}

// W2B-G-enum review loop 6 (P1): the uid an exclude_users name last resolved
// to kept applying while its lookup did not answer, whoever held that uid
// now. After alice left and charlie got her uid, a lookup timeout withdrew
// charlie's identity record. A last answer now withdraws a record only while
// the account the uid holds now (the account database's answer, or, when it
// does not answer, the uid's identity record) is the one it named, with the
// same SID where both are known. A spelling a stale listing carries is held
// to the same check.
func TestAnExclusionNeverWithdrawsTheRecordOfAnAccountThatReusedTheUID(t *testing.T) {
	settings := withdrawTestSettings(t)
	const uid = 4242
	const sidA, sidB, sidC = "S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1201", "S-1-5-21-1-2-3-1301"
	alice := unixidentity.Account{Name: "alice", UID: uid, GID: uid}
	charlie := unixidentity.Account{Name: "charlie", UID: uid, GID: uid}
	dir := t.TempDir()
	record := func(user, sid string) {
		if user == "" {
			if err := os.Remove(filepath.Join(dir, strconv.Itoa(uid)+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			return
		}
		writeWithdrawTestRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, AccountSID: sid})
	}
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }

	// The directory answers: the alias is alice's, and her record holds her
	// SID. The answer is kept with it.
	settings([]string{"alice-alias"}, nil)
	record("alice", sidA)
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{"alice-alias": alice, "alice": alice}})
	if !enterpriseHookEnrollmentLeftOut(context.Background(), dir).withdraws(uid, "alice") {
		t.Fatal("alice, excluded by an alias the directory resolves, keeps her record")
	}
	enterpriseHookLeftOutProven.Lock()
	answered := maps.Clone(enterpriseHookLeftOutProven.proofs)
	enterpriseHookLeftOutProven.Unlock()
	if got := answered["alice-alias"]; got.uid != uid || got.name != "alice" || got.sid != sidA {
		t.Fatalf("kept answer %+v, want uid %d, alice, %s", got, uid, sidA)
	}

	type directory struct {
		accounts  map[string]unixidentity.Account
		transient []string
	}
	resolver := func(d directory) standaloneTestResolver {
		r := standaloneTestResolver{accounts: d.accounts, transient: map[string]bool{}}
		for _, name := range d.transient {
			r.transient[name] = true
		}
		return r
	}
	for _, tc := range []struct {
		name               string
		exclude            []string
		dir                directory
		recordUser, sid    string
		listed             string
		withdrawn, forgets bool
	}{
		// The alias does not answer; its last answer named alice.
		{name: "the uid now names charlie", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"charlie": charlie}, []string{"alice-alias"}},
			recordUser: "charlie", sid: sidC, listed: "charlie", forgets: true},
		{name: "charlie holds the uid and his lookup does not answer either", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"charlie": charlie}, []string{"alice-alias", "charlie"}},
			recordUser: "charlie", sid: sidC, listed: "charlie"},
		{name: "charlie holds the uid, has no record yet, and nothing answers", exclude: []string{"alice-alias"},
			dir:    directory{map[string]unixidentity.Account{"charlie": charlie}, []string{"alice-alias", "charlie"}},
			listed: "charlie"},
		{name: "an account recreated as alice, with another SID", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice-alias"}},
			recordUser: "alice", sid: sidB, listed: "alice"},
		{name: "an account recreated as alice, with another SID, whose lookup does not answer", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice-alias", "alice"}},
			recordUser: "alice", sid: sidB, listed: "alice"},
		{name: "still alice, the uid lookup answers", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice-alias"}},
			recordUser: "alice", sid: sidA, listed: "alice", withdrawn: true},
		{name: "still alice, nothing answers", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice-alias", "alice"}},
			recordUser: "alice", sid: sidA, listed: "alice", withdrawn: true},
		{name: "still alice, her record has no SID", exclude: []string{"alice-alias"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice-alias", "alice"}},
			recordUser: "alice", listed: "alice", withdrawn: true},
		// A stale listing still spells the uid as alice, the excluded name,
		// which no longer resolves.
		{name: "a stale spelling, the uid now names charlie", exclude: []string{"alice"},
			dir:        directory{map[string]unixidentity.Account{"charlie": charlie}, nil},
			recordUser: "charlie", sid: sidC, listed: "alice"},
		{name: "a stale spelling, charlie's record, nothing answers", exclude: []string{"alice"},
			dir:        directory{map[string]unixidentity.Account{"charlie": charlie}, []string{"alice", "charlie"}},
			recordUser: "charlie", sid: sidC, listed: "alice"},
		{name: "a stale spelling, alice's record, nothing answers", exclude: []string{"alice"},
			dir:        directory{map[string]unixidentity.Account{"alice": alice}, []string{"alice"}},
			recordUser: "alice", sid: sidA, listed: "alice", withdrawn: true},
		{name: "a stale spelling, no record, nothing answers", exclude: []string{"alice"},
			dir:    directory{nil, []string{"alice"}},
			listed: "alice", withdrawn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings(tc.exclude, nil)
			enterpriseHookLeftOutProven.Lock()
			enterpriseHookLeftOutProven.proofs = maps.Clone(answered)
			enterpriseHookLeftOutProven.Unlock()
			enterprisehooks.SetStandaloneResolver(resolver(tc.dir))
			record(tc.recordUser, tc.sid)
			// The record of an account the pass does not list.
			if tc.recordUser != "" {
				if got := enterpriseHookEnrollmentLeftOut(context.Background(), dir).withdraws(uid, tc.recordUser); got != tc.withdrawn {
					t.Fatalf("record path: withdrawn %t, want %t", got, tc.withdrawn)
				}
			}
			// An eligible account of a stale listing.
			eligible := []enterprisehooks.UnixEligibleAccount{{User: tc.listed, UID: uid, Home: "/home/" + tc.listed}}
			load := func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return eligible, nil }
			enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = load, load
			accounts, _, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir,
				enterpriseHookReconcileRun{Manifest: "/etc/defenseclaw/hooks/manifest.json"})
			left := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == uid && a.Left })
			if left != tc.withdrawn {
				t.Fatalf("listing path: accounts %+v, left %t, want %t", accounts, left, tc.withdrawn)
			}
			if !left && withdraw(uid, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: tc.recordUser}) {
				t.Fatal("the pass would withdraw the record of the account it lists")
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_ = enterprisehooks.WriteIdentitySpool(canceled, dir, accounts, nil, nil, withdraw)
			if tc.recordUser != "" && withdrawTestRecordExists(t, dir, uid) == tc.withdrawn {
				t.Fatalf("record exists %t after the pass, want %t", !tc.withdrawn, !tc.withdrawn)
			}
			enterpriseHookLeftOutProven.Lock()
			_, kept := enterpriseHookLeftOutProven.proofs["alice-alias"]
			enterpriseHookLeftOutProven.Unlock()
			if slices.Contains(tc.exclude, "alice-alias") && kept == tc.forgets {
				t.Fatalf("the alias's last answer kept %t, want %t", kept, !tc.forgets)
			}
		})
	}
}

// W2B-G-enum review loop 6 (P2): the identity records were matched against
// exclude_users only up to the first 4096 file names, so an excluded
// account's record beyond them stayed until it aged out (an hour). The pass
// now checks every record it does not list, as it reads the whole spool, and
// a change of exclude_users starts a pass at the next tick.
func TestExclusionWithdrawsAnOmittedRecordWhateverTheSpoolSize(t *testing.T) {
	settings := withdrawTestSettings(t)
	settings([]string{"zed@corp.example"}, []string{"xia@corp.example"})
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{})
	dir := t.TempDir()
	const records = 5000
	for i := range records {
		writeWithdrawTestRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(100000 + i), User: fmt.Sprintf("user%d", i)})
	}
	const zedUID, yanUID, xiaUID = 999999, 999998, 999997
	for uid, user := range map[int]string{zedUID: "zed@corp.example", yanUID: "yan@corp.example", xiaUID: "xia@corp.example"} {
		writeWithdrawTestRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, SSSDDomain: "corp.example"})
	}
	_, before, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	accounts, keys, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if !slices.Contains(keys, "exclude:zed@corp.example") {
		t.Fatalf("keys %v do not follow exclude_users", keys)
	}
	settings(nil, []string{"xia@corp.example"})
	if _, after, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{}); slices.Equal(after, before) {
		t.Fatal("removing an exclude_users entry left the keys as they were")
	}
	settings([]string{"zed@corp.example"}, []string{"xia@corp.example"})
	if err := enterprisehooks.WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, withdraw); err != nil {
		t.Fatal(err)
	}
	if withdrawTestRecordExists(t, dir, zedUID) {
		t.Fatalf("the record of zed, excluded and beyond the first %d of %d records, was not withdrawn", 4096, records+3)
	}
	if !withdrawTestRecordExists(t, dir, yanUID) {
		t.Fatal("the record of yan, a directory account the listing omitted, was withdrawn")
	}
	if !withdrawTestRecordExists(t, dir, xiaUID) {
		t.Fatal("the record of xia, exempt, was withdrawn: the gateway still accepts and inspects her hook calls")
	}
}

// W2B-G-enum review loop round 3 (P2): the uid an exclude_users or
// exempt_users name last resolved to kept an account out of the scans while
// the name's lookup did not answer, whoever held that uid now. After alice
// left and charlie got her uid, an alias lookup timeout dropped charlie's
// scan row, and the pass removed his last scan record. A last answer now
// keeps a uid out of the scans only until the account the uid holds now
// (the account database's answer, or else the uid's identity record) is
// shown to be another account neither entry names; with nothing proven it
// still does.
func TestALastExclusionAnswerNeverDropsTheScanOfTheUIDsNewHolder(t *testing.T) {
	settings := withdrawTestSettings(t)
	const uid = 4242
	const sidA, sidB, sidC = "S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1201", "S-1-5-21-1-2-3-1301"
	alice := unixidentity.Account{Name: "alice", UID: uid, GID: uid}
	charlie := unixidentity.Account{Name: "charlie", UID: uid, GID: uid}
	authDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	dir := enterprisehooks.IdentitySpoolDir(authDir) // enterpriseHookIdentitySpoolDirForConfig under any settings
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	record := func(user, sid string) {
		if user == "" {
			if err := os.Remove(filepath.Join(dir, strconv.Itoa(uid)+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			return
		}
		writeWithdrawTestRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: user, AccountSID: sid})
	}
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }

	// The directory answers: the alias is alice's, and her record holds her
	// SID. Both entries keep the answer.
	answers := map[string]map[string]enterpriseHookLeftOutProof{}
	for _, kind := range []string{"exclude", "exempt"} {
		if kind == "exclude" {
			settings([]string{"alice-alias"}, nil)
		} else {
			settings(nil, []string{"alice-alias"})
		}
		record("alice", sidA)
		enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{"alice-alias": alice, "alice": alice}})
		if !enterpriseHookEnrollmentLeftOut(context.Background(), dir).has(uid, "alice") {
			t.Fatalf("%s: alice, left out by an alias the directory resolves, is scanned", kind)
		}
		enterpriseHookLeftOutProven.Lock()
		answers[kind] = maps.Clone(enterpriseHookLeftOutProven.proofs)
		enterpriseHookLeftOutProven.Unlock()
		if got := answers[kind]["alice-alias"]; got.uid != uid || got.name != "alice" || got.sid != sidA {
			t.Fatalf("%s: kept answer %+v, want uid %d, alice, %s", kind, got, uid, sidA)
		}
	}

	for _, tc := range []struct {
		name            string
		kind            string
		exclude         []string
		accounts        map[string]unixidentity.Account
		transient       []string
		recordUser, sid string
		listed          string
		scanned         bool
		forgets         bool
	}{
		// The alias does not answer; its last answer named alice.
		{name: "the uid lookup names charlie", kind: "exclude",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias"},
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true, forgets: true},
		{name: "the uid lookup names charlie, who has no record yet", kind: "exclude",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias"},
			listed: "charlie", scanned: true, forgets: true},
		{name: "only charlie's record says so", kind: "exclude",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias", "charlie"},
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		{name: "an account recreated as alice, with another SID", kind: "exclude",
			accounts: map[string]unixidentity.Account{"alice": alice}, transient: []string{"alice-alias", "alice"},
			recordUser: "alice", sid: sidB, listed: "alice-new", scanned: true},
		{name: "the exemption: the uid lookup names charlie", kind: "exempt",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias"},
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true, forgets: true},
		{name: "the exemption: only charlie's record says so", kind: "exempt",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias", "charlie"},
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		// Nothing shows another holder: the last answer still applies.
		{name: "charlie holds the uid, has no record, and nothing answers", kind: "exclude",
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias", "charlie"},
			listed: "charlie"},
		{name: "still alice, the uid lookup answers", kind: "exclude",
			accounts: map[string]unixidentity.Account{"alice": alice}, transient: []string{"alice-alias"},
			recordUser: "alice", sid: sidA, listed: "alice"},
		{name: "still alice, nothing answers", kind: "exclude",
			accounts: map[string]unixidentity.Account{"alice": alice}, transient: []string{"alice-alias", "alice"},
			recordUser: "alice", sid: sidA, listed: "alice"},
		{name: "still alice, her record has no SID", kind: "exclude",
			accounts: map[string]unixidentity.Account{"alice": alice}, transient: []string{"alice-alias", "alice"},
			recordUser: "alice", listed: "alice"},
		{name: "the exemption: still alice, nothing answers", kind: "exempt",
			accounts: map[string]unixidentity.Account{"alice": alice}, transient: []string{"alice-alias", "alice"},
			recordUser: "alice", sid: sidA, listed: "alice"},
		{name: "the exemption: nothing answers and there is no record", kind: "exempt",
			transient: []string{"alice-alias"}, listed: "alice"},
		// The new holder is left out by an entry of its own.
		{name: "charlie holds the uid and is excluded too", kind: "exclude", exclude: []string{"alice-alias", "charlie"},
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias", "charlie"},
			recordUser: "charlie", sid: sidC, listed: "charlie.other"},
		// An explicit match by spelling wins whoever the uid holds.
		{name: "a spelling the exclusion names", kind: "exclude", exclude: []string{"alice-alias", "charlie.old"},
			accounts: map[string]unixidentity.Account{"charlie": charlie}, transient: []string{"alice-alias"},
			recordUser: "charlie", sid: sidC, listed: "charlie.old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exclude := tc.exclude
			if exclude == nil {
				exclude = []string{"alice-alias"}
			}
			if tc.kind == "exclude" {
				settings(exclude, nil)
			} else {
				settings(nil, exclude)
			}
			enterpriseHookLeftOutProven.Lock()
			enterpriseHookLeftOutProven.proofs = maps.Clone(answers[tc.kind])
			enterpriseHookLeftOutProven.Unlock()
			r := standaloneTestResolver{accounts: tc.accounts, transient: map[string]bool{}}
			for _, name := range tc.transient {
				r.transient[name] = true
			}
			enterprisehooks.SetStandaloneResolver(r)
			record(tc.recordUser, tc.sid)
			eligible := []enterprisehooks.UnixEligibleAccount{{User: tc.listed, UID: uid, Home: "/home/" + tc.listed}}
			enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return eligible, nil }
			rows := enterpriseHookEnrolledAccountRows(context.Background(), io.Discard,
				enterpriseHookReconcileRun{Manifest: "/etc/defenseclaw/hooks/manifest.json"})
			scanned := slices.ContainsFunc(rows, func(row enterpriseHookReconcileRow) bool { return row.UID == uid })
			if scanned != tc.scanned {
				t.Fatalf("scan rows %+v: uid %d scanned %t, want %t", rows, uid, scanned, tc.scanned)
			}
			enterpriseHookLeftOutProven.Lock()
			_, kept := enterpriseHookLeftOutProven.proofs["alice-alias"]
			enterpriseHookLeftOutProven.Unlock()
			if kept == tc.forgets {
				t.Fatalf("the alias's last answer kept %t, want %t", kept, !tc.forgets)
			}
		})
	}
}

// W2B-G-enum loop round 1 (P1): an account the manifest left out lost its
// identity record at once, and so did an excluded account, although the
// gateway still accepted its hook calls: exempt_users are authorized
// without enrollment, and a machine-policy connector under
// unenrolled_users other than deny is inspected for every account. Their
// calls then no longer selected the profile assigned to the account's UPN,
// and the default can be less restrictive. Every caller the gateway still
// accepts now keeps a refreshed record; only a caller it refuses loses it.
func TestIdentityRecordStaysForEveryCallerTheGatewayStillAccepts(t *testing.T) {
	settings := withdrawTestSettings(t)
	const bobUID = 4243
	bob := unixidentity.Account{Name: "bob", UID: bobUID, GID: bobUID}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"bob": bob, "bob-alias": bob,
	}})
	const manifest = "/etc/defenseclaw/hooks/manifest.json"
	staleBob := []enterprisehooks.UnixEligibleAccount{{User: "bob", UID: bobUID, Home: "/home/bob"}}
	bobRow := enterpriseHookReconcileRow{User: "bob", UserHome: "/home/bob", Connector: "opencode", OK: true, UID: bobUID}
	claude := func() ([]string, error) { return []string{"claudecode"}, nil }
	unreadable := func() ([]string, error) { return nil, errors.New("managed runtime descriptor is not a regular file") }
	for _, tc := range []struct {
		name            string
		exclude, exempt []string
		manifestMode    bool
		unenrolled      string
		machine         func() ([]string, error)
		eligible        []enterprisehooks.UnixEligibleAccount
		rows            []enterpriseHookReconcileRow
		kept            bool
		listed          bool
	}{
		// The gateway still accepts bob's hook calls.
		{name: "exempt by name, out of the manifest", exempt: []string{"bob"},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt by the UPN, out of the manifest", exempt: []string{"bob@corp.example"},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt as DOMAIN\\name, out of the manifest", exempt: []string{`CORP\bob`},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt by uid, out of the manifest", exempt: []string{strconv.Itoa(bobUID)},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt by an alias that resolves to bob, out of the manifest", exempt: []string{"bob-alias"},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt and excluded, out of the manifest", exclude: []string{"bob"}, exempt: []string{"bob"},
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "exempt and excluded, an unlisted record", exclude: []string{"bob"}, exempt: []string{"bob"}, kept: true, listed: true},
		{name: "a machine-policy connector, out of the manifest", machine: claude,
			manifestMode: true, eligible: staleBob, kept: true, listed: true},
		{name: "a machine-policy connector, excluded, an old row", exclude: []string{"bob"}, machine: claude,
			rows: []enterpriseHookReconcileRow{bobRow}, kept: true, listed: true},
		{name: "a machine-policy connector, excluded, an unlisted record", exclude: []string{"bob"}, machine: claude, kept: true, listed: true},
		{name: "a machine-policy connector under unenrolled_users inspect, excluded", exclude: []string{"bob"},
			machine: claude, unenrolled: config.EnterpriseUnenrolledInspect, kept: true, listed: true},
		{name: "the runtime descriptor does not read, excluded", exclude: []string{"bob"}, machine: unreadable, kept: true, listed: true},
		// The gateway refuses bob's hook calls.
		{name: "out of the manifest, not exempt, no machine-policy connector",
			manifestMode: true, eligible: staleBob},
		{name: "out of the manifest, exempt_users names another account", exempt: []string{"carol", "bobby@corp.example"},
			manifestMode: true, eligible: staleBob},
		{name: "a machine-policy connector under unenrolled_users deny, excluded", exclude: []string{"bob"},
			machine: claude, unenrolled: config.EnterpriseUnenrolledDeny, rows: []enterpriseHookReconcileRow{bobRow}},
		{name: "excluded, no machine-policy connector, an unlisted record", exclude: []string{"bob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings(tc.exclude, tc.exempt)
			if tc.manifestMode {
				cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
			}
			cfg.Enterprise.Enrollment.UnenrolledUsers = tc.unenrolled
			enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return nil, nil }
			if tc.machine != nil {
				enterpriseHookLoadMachinePolicyConnectors = tc.machine
			}
			load := func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return tc.eligible, nil }
			enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = load, load
			enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }
			enterpriseHookLeftOutProven.Lock()
			enterpriseHookLeftOutProven.proofs = map[string]enterpriseHookLeftOutProof{}
			enterpriseHookLeftOutProven.Unlock()
			dir := t.TempDir()
			record := enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(bobUID), User: "bob", SSSDDomain: "corp.example"}
			record.Facts.UPN, record.Facts.Principal = "bob@corp.example", "bob@corp.example"
			writeWithdrawTestRecord(t, dir, record)
			run := enterpriseHookReconcileRun{Manifest: manifest, Rows: tc.rows}
			accounts, keys, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, run)
			listed := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == bobUID && !a.Left })
			left := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == bobUID && a.Left })
			if listed != tc.listed || (tc.kept && left) {
				t.Fatalf("identity accounts %+v (keys %v): bob listed %t, left %t; want listed %t, kept %t",
					accounts, keys, listed, left, tc.listed, tc.kept)
			}
			if !listed && !left && withdraw(bobUID, record) == tc.kept {
				t.Fatalf("the pass withdraws bob's unlisted record %t, want %t", tc.kept, !tc.kept)
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_ = enterprisehooks.WriteIdentitySpool(canceled, dir, accounts, nil, nil, withdraw)
			if got := withdrawTestRecordExists(t, dir, bobUID); got != tc.kept {
				t.Fatalf("bob's identity record exists %t after the pass, want %t", got, tc.kept)
			}
		})
	}
}

// staleNameTestResolver answers names and uids from separate tables, as a
// directory cache can: a name can still give the uid of an account that
// has left, while the uid lookup names the account that holds it now.
// transient lists the names, and "uid" for the uid lookups, whose lookup
// fails without an answer.
type staleNameTestResolver struct {
	standaloneTestResolver
	names     map[string]unixidentity.Account
	uids      map[int]unixidentity.Account
	transient map[string]bool
}

func (r staleNameTestResolver) LookupUser(name string) (unixidentity.Account, error) {
	if r.transient[name] {
		return unixidentity.Account{}, errors.New("sssd: backend offline")
	}
	if account, ok := r.names[name]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r staleNameTestResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if r.transient["uid"] {
		return unixidentity.Account{}, errors.New("sssd: backend offline")
	}
	if account, ok := r.uids[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

// W2B-G-enum loop round 1 (P1): a name entry's lookup that answered marked
// the uid it gave as excluded or exempt, whoever held that uid now. A
// directory cache can still answer an alias of alice, who left, with her
// old uid after charlie got it: the uid was then kept out of the scans, so
// charlie got no scan row, and his identity record was withdrawn. A name's
// answer now binds to the account it named: it applies to the uid only
// while the account the uid holds now (the uid lookup, or else the uid's
// identity record) is not shown to be another account no entry names, and
// it withdraws a record only when that account is the one it named. A uid
// entry still binds to the uid.
func TestANameAnswerNeverBindsTheUIDOfAnotherAccount(t *testing.T) {
	settings := withdrawTestSettings(t)
	const uid = 4242
	const sidA, sidC = "S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1301"
	alice := unixidentity.Account{Name: "alice", UID: uid, GID: uid}
	charlie := unixidentity.Account{Name: "charlie", UID: uid, GID: uid}
	authDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	dir := enterprisehooks.IdentitySpoolDir(authDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }
	for _, tc := range []struct {
		name            string
		kind            string
		entries         []string
		holder          *unixidentity.Account
		recordUser, sid string
		listed          string
		scanned         bool
		withdrawn       bool
	}{
		// The alias still answers with alice's old uid; charlie holds it.
		{name: "the uid lookup names charlie", kind: "exclude", holder: &charlie,
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		{name: "the uid lookup names charlie, who has no record yet", kind: "exclude", holder: &charlie,
			listed: "charlie", scanned: true},
		{name: "only charlie's record says so", kind: "exclude",
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		{name: "the exemption: the uid lookup names charlie", kind: "exempt", holder: &charlie,
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		{name: "the exemption: only charlie's record says so", kind: "exempt",
			recordUser: "charlie", sid: sidC, listed: "charlie", scanned: true},
		// The answer names the account the uid holds.
		{name: "the uid lookup names alice", kind: "exclude", holder: &alice,
			recordUser: "alice", sid: sidA, listed: "alice", withdrawn: true},
		{name: "only alice's record says so", kind: "exclude",
			recordUser: "alice", sid: sidA, listed: "alice", withdrawn: true},
		{name: "the exemption: the uid lookup names alice", kind: "exempt", holder: &alice,
			recordUser: "alice", sid: sidA, listed: "alice"},
		// Nothing shows who holds the uid: the scans stay strict, and
		// there is no record to withdraw.
		{name: "no record and the uid lookup does not answer", kind: "exclude", listed: "charlie"},
		// Charlie is left out by an entry of his own.
		{name: "charlie holds the uid and is excluded too", kind: "exclude", entries: []string{"alice-alias", "charlie"},
			holder: &charlie, recordUser: "charlie", sid: sidC, listed: "charlie.other", withdrawn: true},
		{name: "a uid entry binds to the uid", kind: "exclude", entries: []string{strconv.Itoa(uid)},
			holder: &charlie, recordUser: "charlie", sid: sidC, listed: "charlie", withdrawn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := tc.entries
			if entries == nil {
				entries = []string{"alice-alias"}
			}
			if tc.kind == "exclude" {
				settings(entries, nil)
			} else {
				settings(nil, entries)
			}
			enterpriseHookLeftOutProven.Lock()
			enterpriseHookLeftOutProven.proofs = map[string]enterpriseHookLeftOutProof{}
			enterpriseHookLeftOutProven.Unlock()
			r := staleNameTestResolver{
				names:     map[string]unixidentity.Account{"alice-alias": alice},
				uids:      map[int]unixidentity.Account{},
				transient: map[string]bool{},
			}
			if tc.holder != nil {
				r.names[tc.holder.Name] = *tc.holder
				r.uids[uid] = *tc.holder
			} else {
				r.transient["uid"] = true
			}
			enterprisehooks.SetStandaloneResolver(r)
			if err := os.Remove(filepath.Join(dir, strconv.Itoa(uid)+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			record := enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: tc.recordUser, AccountSID: tc.sid}
			if tc.recordUser != "" {
				writeWithdrawTestRecord(t, dir, record)
			}
			eligible := []enterprisehooks.UnixEligibleAccount{{User: tc.listed, UID: uid, Home: "/home/" + tc.listed}}
			load := func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return eligible, nil }
			enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = load, load
			run := enterpriseHookReconcileRun{Manifest: "/etc/defenseclaw/hooks/manifest.json"}

			// The scans.
			rows := enterpriseHookEnrolledAccountRows(context.Background(), io.Discard, run)
			scanned := slices.ContainsFunc(rows, func(row enterpriseHookReconcileRow) bool { return row.UID == uid })
			if scanned != tc.scanned {
				t.Fatalf("scan rows %+v: uid %d scanned %t, want %t", rows, uid, scanned, tc.scanned)
			}
			if tc.kind != "exclude" {
				return
			}
			// The record path: the record of an account the pass does not
			// list.
			if tc.recordUser != "" {
				if got := enterpriseHookEnrollmentLeftOut(context.Background(), dir).withdraws(uid, tc.recordUser); got != tc.withdrawn {
					t.Fatalf("record path: withdrawn %t, want %t", got, tc.withdrawn)
				}
			}
			// The listing path, and the pass.
			accounts, _, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, run)
			left := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == uid && a.Left })
			if left != tc.withdrawn {
				t.Fatalf("listing path: accounts %+v, left %t, want %t", accounts, left, tc.withdrawn)
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			_ = enterprisehooks.WriteIdentitySpool(canceled, dir, accounts, nil, nil, withdraw)
			if tc.recordUser != "" && withdrawTestRecordExists(t, dir, uid) == tc.withdrawn {
				t.Fatalf("record exists %t after the pass, want %t", !tc.withdrawn, !tc.withdrawn)
			}
		})
	}
}
