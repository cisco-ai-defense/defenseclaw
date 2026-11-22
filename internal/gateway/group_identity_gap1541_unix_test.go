// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-10:GAP-1541: on a bound Mac the guardian's identity record names
// the NetBIOS domain (account_domain DCLAB, GAP-0635) and Open Directory
// lists the group only as DCLAB\dc-r102-devs. The gateway merges the record
// into the facts of a hook call, so a group budget written
// dc-r102-devs@dclab.test selects the account. config validate looks the
// account up outside the gateway, whose Open Directory answer carries no
// NetBIOS domain: the check must merge the record as the gateway does, or it
// pairs no domain and warns that the budget selects nobody.
func TestRoutingGroupWarningFoldsTheMacRecordAccountDomain(t *testing.T) {
	const uid = "94401541"
	now := time.Now().UTC()
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: uid, User: "dcad-r102-eng1", UpdatedAt: now, AccountDomain: "DCLAB",
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
	// What Open Directory answers outside the gateway: no NetBIOS domain.
	lookedUp := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Domain: "dclab.test", Realm: "DCLAB.TEST",
		Directory: useridentity.DirectoryActiveDirectory, Groups: []string{`DCLAB\dc-r102-devs`}, ResolvedAt: now}
	validate, cached, lookup := validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts
	exists, qualify, silent := profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent
	holder := profileExplainAccountName
	t.Cleanup(func() {
		validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts = validate, cached, lookup
		profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent = exists, qualify, silent
		profileExplainAccountName = holder
	})
	profileExplainAccountName = func(id string) (string, bool) { return "dcad-r102-eng1", id == uid }
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
		return useridentity.DirectoryFacts{}, time.Time{}, false
	}
	profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
		if id != uid {
			t.Fatalf("lookup of an account the records do not name: %q", id)
		}
		return lookedUp, nil
	}
	// Open Directory knows the group by its NetBIOS spelling only.
	profileGroupExists = func(_ context.Context, name string) (bool, error) {
		return name == `DCLAB\dc-r102-devs` || name == `DCLAB\domain users`, nil
	}
	profileGroupQualifiedName = func(context.Context, string) string { return "" }
	bareGroupsDirectorySilent = func(context.Context) bool { return false }

	// The matcher: the gateway's facts carry the merged record.
	merged := mergeSpoolFacts(lookedUp, enterprisehooks.IdentitySpoolRecord{Key: uid, AccountDomain: "DCLAB"})
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: uid, IDKind: useridentity.KindForID(uid),
		UserName: "dcad-r102-eng1", Directory: merged}, false)
	groups := &subjectGroups{list: subject.Groups, domains: groupDomainsOf(&subject)}
	if !groups.has("dc-r102-devs@dclab.test") || groups.has("dc-r102-devs@other.test") {
		t.Fatal("the matcher selects x@dclab.test (own domain) and only it")
	}

	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{
		{ID: "b-grp-devs", Scope: config.RoutingBudgetScopeGroup, Subject: "dc-r102-devs@dclab.test", Period: "day", LimitUSD: 1, OnExceed: "deny"},
		{ID: "b-grp-other", Scope: config.RoutingBudgetScopeGroup, Subject: "dc-r102-devs@other.test", Period: "day", LimitUSD: 1, OnExceed: "deny"},
	}}
	got := RoutingAdminGroupWarnings(context.Background(), cfg, dir)
	if len(got) != 1 {
		t.Fatalf("only the budget of a domain the matcher does not fold keeps a warning, got %d: %q", len(got), got)
	}
	for _, w := range got {
		if !gap1541ContainsAll(w, "b-grp-other", "routing_admin_group_unmatched") {
			t.Fatalf("the own-domain budget must not warn: %q", got)
		}
	}
}

func gap1541ContainsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
