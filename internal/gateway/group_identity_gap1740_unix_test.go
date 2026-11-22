// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-10:GAP-1740: the gateway merges the guardian's identity record into
// a hook call's facts only when it is the record of the account that holds
// the uid now (same name, no other SID: readIdentitySpoolFactsForAccount).
// The group check of config validate must not fold the NetBIOS domain of a
// record the matcher never merges, or it drops the warning for a budget
// that selects nobody.
func TestRoutingGroupWarningMergesOnlyTheHolderRecord(t *testing.T) {
	const uid = "94401740"
	for _, tc := range []struct {
		name                 string
		holder               string
		recordSID, lookupSID string
		wantWarnings         int
	}{
		{name: "holder", holder: "dcad-r102-eng1", wantWarnings: 1},
		{name: "another account holds the uid", holder: "dcad-new-hire", wantWarnings: 2},
		{name: "same name, another SID", holder: "dcad-r102-eng1", recordSID: "S-1-5-21-1-1-1-1105", lookupSID: "S-1-5-21-1-1-1-2207", wantWarnings: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			dir := t.TempDir()
			data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
				Key: uid, User: "dcad-r102-eng1", UpdatedAt: now, AccountDomain: "DCLAB", AccountSID: tc.recordSID,
				Facts: useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Domain: "dclab.test", Realm: "DCLAB.TEST",
					Principal: "dcad-r102-eng1@dclab.test", UPN: "dcad-r102-eng1@dclab.test",
					Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: now},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, uid+".json"), data, 0o640); err != nil {
				t.Fatal(err)
			}
			lookedUp := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Domain: "dclab.test", Realm: "DCLAB.TEST",
				Directory: useridentity.DirectoryActiveDirectory, Groups: []string{`DCLAB\dc-r102-devs`}, AccountSID: tc.lookupSID, ResolvedAt: now}
			validate, cached, lookup := validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts
			exists, qualify, silent := profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent
			holder := profileExplainAccountName
			t.Cleanup(func() {
				validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts = validate, cached, lookup
				profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent = exists, qualify, silent
				profileExplainAccountName = holder
			})
			validateManagedGuardianAuthorization = func(string, string) error { return nil }
			cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
				return useridentity.DirectoryFacts{}, time.Time{}, false
			}
			profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) { return lookedUp, nil }
			profileExplainAccountName = func(id string) (string, bool) { return tc.holder, id == uid }
			profileGroupExists = func(_ context.Context, name string) (bool, error) {
				return name == `DCLAB\dc-r102-devs` || name == `DCLAB\domain users`, nil
			}
			profileGroupQualifiedName = func(context.Context, string) string { return "" }
			bareGroupsDirectorySilent = func(context.Context) bool { return false }

			cfg := &config.Config{DeploymentMode: "managed_enterprise"}
			cfg.Enterprise.Profile = "standalone"
			cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{
				{ID: "b-grp-devs", Scope: config.RoutingBudgetScopeGroup, Subject: "dc-r102-devs@dclab.test", Period: "day", LimitUSD: 1, OnExceed: "deny"},
				{ID: "b-grp-other", Scope: config.RoutingBudgetScopeGroup, Subject: "dc-r102-devs@other.test", Period: "day", LimitUSD: 1, OnExceed: "deny"},
			}}
			got := RoutingAdminGroupWarnings(context.Background(), cfg, dir)
			if len(got) != tc.wantWarnings {
				t.Fatalf("want %d warnings (the record is merged only for its holder), got %d: %q", tc.wantWarnings, len(got), got)
			}
			if tc.wantWarnings == 2 && !gap1541ContainsAll(got[0]+got[1], "b-grp-devs", "b-grp-other") {
				t.Fatalf("both budgets warn when the record is not the holder's: %q", got)
			}
		})
	}
}
