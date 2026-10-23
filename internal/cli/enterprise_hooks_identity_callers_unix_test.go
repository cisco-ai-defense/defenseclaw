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
