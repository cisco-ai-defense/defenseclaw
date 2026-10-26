// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func identityCallerTestConfig(t *testing.T) {
	t.Helper()
	previousCfg := cfg
	previousTargets := enterpriseHookLoadAcceptedTargets
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookLoadAcceptedTargets = previousTargets
		enterprisehooks.SetStandaloneResolver(nil)
	})
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }
}

func listedUIDs(accounts []enterprisehooks.IdentitySpoolAccount) (listed, left []int) {
	for _, account := range accounts {
		if account.Left {
			left = append(left, account.UID)
		} else {
			listed = append(listed, account.UID)
		}
	}
	return listed, left
}

// GAP-0677: a machine-policy hook accepts a newly created local login even
// before the per-user enumerator has found an agent or written an eligible
// account row. The root guardian must spool that account's identity proof
// so the service-account gateway can match numeric group assignments on its
// first Codex call, as root profile-explain already can.
func TestMachinePolicyWarmsFreshLocalAccountIdentityWithoutEnrollmentRow(t *testing.T) {
	identityCallerTestConfig(t)
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "numeric", Match: config.ProfileMatch{Groups: []string{"49202"}}}}
	previousMachine, previousLocal := enterpriseHookLoadMachinePolicyConnectors, enterpriseHookLocalAccounts
	t.Cleanup(func() {
		enterpriseHookLoadMachinePolicyConnectors = previousMachine
		enterpriseHookLocalAccounts = previousLocal
	})
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	enterpriseHookLocalAccounts = func(context.Context) (map[string]int, error) {
		return map[string]int{"fresh": 1006, "numeric": 49201, "system": 2}, nil
	}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"fresh":   {Name: "fresh", UID: 1006, GID: 49202},
		"numeric": {Name: "numeric", UID: 49201, GID: 49202},
	}})
	accounts, keys, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, t.TempDir(), enterpriseHookReconcileRun{})
	listed, _ := listedUIDs(accounts)
	if !slices.Contains(listed, 1006) || !slices.Contains(listed, 49201) || slices.Contains(listed, 2) ||
		!slices.Contains(keys, "1006:fresh") || !slices.Contains(keys, "49201:numeric") {
		t.Fatalf("fresh machine-policy callers: accounts %+v keys %v", accounts, keys)
	}
}

// GAP-0399: an exempt account calls the managed hook socket although the
// enumerator gives it no row or eligible-account entry. Its record keeps
// being refreshed, so its UPN profile survives the hourly expiry. An
// exclude_users entry for the same account does not end the gateway's
// acceptance of an exempt caller, so the record stays; without the
// exemption the excluded account's record is withdrawn.
func TestExemptUnlistedCallerKeepsAFreshIdentityRecord(t *testing.T) {
	identityCallerTestConfig(t)
	const uid = 94401104
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"bob":              {Name: "bob@corp.example", UID: uid, GID: uid},
		"bob@corp.example": {Name: "bob@corp.example", UID: uid, GID: uid},
	}})
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"bob"}
	dir := t.TempDir()
	accounts, keys, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, left := listedUIDs(accounts); !slices.Equal(listed, []int{uid}) || len(left) != 0 ||
		!slices.Contains(keys, "94401104:bob@corp.example") {
		t.Fatalf("unlisted exempt caller: accounts %+v keys %v; want a refreshed record", accounts, keys)
	}
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"bob@corp.example"}
	accounts, _, _ = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); !slices.Equal(listed, []int{uid}) {
		t.Fatalf("excluded and exempt caller: accounts %+v; the gateway still accepts it, so its record stays", accounts)
	}
	cfg.Enterprise.Enrollment.ExemptUsers = nil
	accounts, _, _ = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); slices.Contains(listed, uid) {
		t.Fatalf("excluded caller without the exemption: accounts %+v; want no refreshed record", accounts)
	}
}

// GAP-0442: the guardian authorization accepts a target by name only, and
// neither the manifest rows nor eligible-accounts.json list it. Its record
// is refreshed by the uid its name holds now; while the name lookup does
// not answer, by the uid of the record that names it, so the record does
// not age out while the gateway still accepts the caller.
func TestNameOnlyAcceptedCallerKeepsAFreshIdentityRecord(t *testing.T) {
	identityCallerTestConfig(t)
	const uid = 94401105
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) {
		return []enterpriseHookReconcileRow{{User: "carol", OK: true}}, nil
	}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"carol": {Name: "carol", UID: uid, GID: uid},
	}})
	dir := t.TempDir()
	accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); !slices.Equal(listed, []int{uid}) {
		t.Fatalf("name-only accepted caller: accounts %+v; want its uid listed", accounts)
	}

	// The directory does not answer: the record that names carol keeps
	// her uid listed.
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{
		accounts:  map[string]unixidentity.Account{"carol": {Name: "carol", UID: uid, GID: uid}},
		transient: map[string]bool{"carol": true},
	})
	record := enterprisehooks.IdentitySpoolRecord{Version: enterprisehooks.IdentitySpoolRecordVersion, Key: "94401105", User: "carol",
		UpdatedAt: time.Now().UTC(), Facts: useridentity.DirectoryFacts{UPN: "carol@corp.example"}}
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "94401105.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	accounts, _, _ = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); !slices.Equal(listed, []int{uid}) {
		t.Fatalf("name-only accepted caller whose lookup does not answer: accounts %+v; want the record's uid listed", accounts)
	}
	// Once the authorization no longer accepts the target, it is not kept.
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) { return nil, nil }
	accounts, _, _ = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); slices.Contains(listed, uid) {
		t.Fatalf("no longer accepted caller: accounts %+v; want no refreshed record", accounts)
	}
}

// T7-07: enumerate=false omits B from the rows. B is excluded and absent
// from the protected targets. A runtime kiro machine-policy connector under
// inspect still accepts B's hooks; that branch must list and refresh the old
// UPN record. With no such connector, the exclusion withdraws it instead.
func TestExcludedUnlistedKiroCallerFollowsCurrentAuthorization(t *testing.T) {
	identityCallerTestConfig(t)
	const aUID, bUID = 94404135, 94404136
	const bName = "dcad-r103-eng2@dclab.test"
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"dcad-r103-eng1@dclab.test": {Name: "dcad-r103-eng1@dclab.test", UID: aUID, GID: aUID},
		bName:                       {Name: bName, UID: bUID, GID: bUID},
	}})
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{bName}
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	previousMachine := enterpriseHookLoadMachinePolicyConnectors
	t.Cleanup(func() { enterpriseHookLoadMachinePolicyConnectors = previousMachine })
	enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) {
		return []enterpriseHookReconcileRow{{UID: aUID, User: "dcad-r103-eng1@dclab.test", Connector: "kiro", OK: true}}, nil
	}
	dir := t.TempDir()
	record := enterprisehooks.IdentitySpoolRecord{Version: enterprisehooks.IdentitySpoolRecordVersion,
		Key: "94404136", User: bName, UpdatedAt: time.Now().UTC(), Facts: useridentity.DirectoryFacts{UPN: "eng2@dclab.test"}}
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	run := enterpriseHookReconcileRun{Rows: []enterpriseHookReconcileRow{{UID: aUID, User: "dcad-r103-eng1@dclab.test", Connector: "kiro", OK: true}}}
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"kiro"}, nil }
	accounts, _, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, run)
	if listed, _ := listedUIDs(accounts); !slices.Contains(listed, bUID) || withdraw(bUID, record) {
		t.Fatalf("accepted but unlisted B loses its UPN record: accounts %+v", accounts)
	}
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return nil, nil }
	accounts, _, withdraw = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, run)
	if listed, _ := listedUIDs(accounts); slices.Contains(listed, bUID) || !withdraw(bUID, record) {
		t.Fatalf("excluded B is not accepted but retains its record: accounts %+v", accounts)
	}
}

// GAP-0881: an exempt_users entry spells the caller by its UPN, its
// principal, DOMAIN\name, or, where SSSD names accounts fully qualified, its
// bare name. The account database does not resolve that spelling (not
// found, or no answer), and neither the rows nor the eligible accounts list
// the caller. The identity record that spells it by its verified facts
// keeps its uid listed while that account still holds the uid, so the
// record does not age out while the gateway exempts the caller. A spelling
// the facts do not give, or a uid another account holds now, lists nothing.
func TestExemptSpellingTheDirectoryCannotResolveKeepsItsRecord(t *testing.T) {
	const uid = 94408811
	short := enterprisehooks.IdentitySpoolRecord{Version: enterprisehooks.IdentitySpoolRecordVersion, Key: "94408811", User: "bob",
		AccountDomain: "CORP", AccountIncarnation: "sid:S-1-5-21-1-2-3-1111", SSSDDomain: "corp.example.com",
		Facts: useridentity.DirectoryFacts{UPN: "bob.smith@corp.example.com", Principal: "bob@CORP.EXAMPLE.COM", Domain: "corp.example.com"}}
	qualified := short
	qualified.User = "bob@corp.example.com"
	local := enterprisehooks.IdentitySpoolRecord{Version: enterprisehooks.IdentitySpoolRecordVersion, Key: "94408811",
		User: "bob@corp.example.com", AccountIncarnation: "files"}
	plainLocal := local
	plainLocal.User = "bob"
	for _, tc := range []struct {
		name, entry, holder string
		record              enterprisehooks.IdentitySpoolRecord
		transient, want     bool
	}{
		{name: "UPN not found", entry: "bob.smith@corp.example.com", record: short, want: true},
		{name: "UPN in another case", entry: "BOB.SMITH@Corp.Example.com", record: short, want: true},
		{name: "principal", entry: "bob@CORP.EXAMPLE.COM", record: short, want: true},
		{name: "NetBIOS domain", entry: `CORP\bob`, record: short, want: true},
		{name: "DNS domain", entry: `corp.example.com\bob`, record: short, want: true},
		{name: "UPN lookup does not answer", entry: "bob.smith@corp.example.com", record: short, transient: true, want: true},
		{name: "DOMAIN form does not answer", entry: `CORP\bob`, record: short, transient: true, want: true},
		{name: "bare name of a fully qualified account", entry: "bob", record: qualified, want: true},
		{name: "another domain", entry: `OTHER\bob`, record: short},
		{name: "another UPN", entry: "bob@other.example.com", record: short},
		{name: "bare name of a local account", entry: "bob", record: local},
		{name: "local account as .\\name", entry: `.\bob`, record: plainLocal, want: true},
		{name: "directory account as .\\name", entry: `.\bob`, record: short},
		{name: "uid held by another account now", entry: "bob.smith@corp.example.com", holder: "mallory", record: short},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identityCallerTestConfig(t)
			holder := tc.holder
			if holder == "" {
				holder = tc.record.User
			}
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{holder: {Name: holder, UID: uid, GID: uid}}}
			if tc.transient {
				resolver.transient = map[string]bool{tc.entry: true}
			}
			enterprisehooks.SetStandaloneResolver(resolver)
			cfg.Enterprise.Enrollment.ExemptUsers = []string{tc.entry}
			dir := t.TempDir()
			record := tc.record
			record.UpdatedAt = time.Now().UTC()
			data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "94408811.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
			listed, _ := listedUIDs(accounts)
			if got := slices.Contains(listed, uid); got != tc.want {
				t.Fatalf("exempt_users %q, record %q, holder %q: listed %v; want listed=%v", tc.entry, record.User, holder, listed, tc.want)
			}
		})
	}
}
