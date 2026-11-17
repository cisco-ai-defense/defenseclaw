// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The verified group lists of one AD account (eng1 of dclab.test, NetBIOS
// DCLAB) as each OS gives them (rel-1-0-10:GAP-1124).
var (
	gap1124Domains = groupDomains{netbios: "DCLAB", dns: "dclab.test"}
	gap1124Lists   = map[string][]string{
		"linux sssd":    {"dcad-r102-eng1@dclab.test", "dc-r102-devs@dclab.test", "domain users@dclab.test"},
		"macos":         {"staff", "DCLAB\\Domain Users", "DCLAB\\dc-r102-devs"},
		"windows names": {"S-1-5-21-1-2-3-513", "DCLAB\\Domain Users", "S-1-5-21-1-2-3-1104", "DCLAB\\dc-r102-devs"},
	}
)

// One AD group written name@domain, DOMAIN\name or with the DNS domain as
// prefix selects the account on every OS, whatever form the OS lists.
func TestSubjectGroupsFoldOneGroupAcrossOSForms(t *testing.T) {
	for os, list := range gap1124Lists {
		for _, want := range []string{"dc-r102-devs@dclab.test", `DCLAB\dc-r102-devs`, `dclab\DC-R102-DEVS`, "DC-R102-Devs@DCLAB.TEST.",
			`dclab.test\dc-r102-devs`, "dc-r102-devs@DCLAB"} {
			if !(&subjectGroups{list: list, domains: gap1124Domains}).has(want) {
				t.Errorf("%s: %q does not select the account in DCLAB\\dc-r102-devs", os, want)
			}
		}
		for _, want := range []string{"dc-r102-dev@dclab.test", `DCLAB\dc-r102-devs2`, "dc-r102-devs@dclab.test.evil.example", `EVIL\dc-r102-devs`} {
			if (&subjectGroups{list: list, domains: gap1124Domains}).has(want) {
				t.Errorf("%s: %q selects the account", os, want)
			}
		}
	}
	// A bare name keeps its rules: the name part of a DOMAIN\name group
	// (macOS, Windows), the exact name on Linux.
	if !(&subjectGroups{list: gap1124Lists["macos"], domains: gap1124Domains}).has("dc-r102-devs") {
		t.Error("macOS: a bare name selects DOMAIN\\name")
	}
}

// Folding never moves an account into a group of another domain, and pairs
// two domain spellings only by the subject's own verified facts.
func TestSubjectGroupsNeverFoldAcrossDomains(t *testing.T) {
	other := []string{`OTHER\dc-r102-devs`, "dc-r102-devs@other.test", "dc-r102-devs@dclab.test.other.test"}
	for _, want := range []string{"dc-r102-devs@dclab.test", `DCLAB\dc-r102-devs`} {
		if (&subjectGroups{list: other, domains: gap1124Domains}).has(want) {
			t.Errorf("a group of another domain selected by %q", want)
		}
	}
	// The OTHER account's own domain pairs OTHER and other.test only.
	otherDomains := groupDomains{netbios: "OTHER", dns: "other.test"}
	if !(&subjectGroups{list: other[:1], domains: otherDomains}).has("dc-r102-devs@other.test") {
		t.Error("OTHER\\name and name@other.test are one group of the OTHER account")
	}
	if (&subjectGroups{list: []string{`DCLAB\dc-r102-devs`}, domains: otherDomains}).has("dc-r102-devs@dclab.test") {
		t.Error("the OTHER account's facts do not pair DCLAB with dclab.test")
	}
	// Facts that name only one spelling pair nothing.
	for _, d := range []groupDomains{{}, {netbios: "DCLAB"}, {dns: "dclab.test"}, {netbios: "dclab.test", dns: "dclab.test"}} {
		if (&subjectGroups{list: []string{`DCLAB\dc-r102-devs`}, domains: d}).has("dc-r102-devs@dclab.test") {
			t.Errorf("%+v: DCLAB\\name selected by name@dclab.test without a verified pair", d)
		}
		if !(&subjectGroups{list: []string{`DCLAB\dc-r102-devs`}, domains: d}).has(`dclab\dc-r102-devs`) {
			t.Errorf("%+v: the exact spelling still selects", d)
		}
	}
}

// A name with both separators, or one twice, is no qualified name: a plain
// LDAP group named DCLAB\dc-r102-devs inside an SSSD domain does not become
// the AD group, and no written name folds into it.
func TestSubjectGroupsDoNotFoldSpoofedNames(t *testing.T) {
	spoofs := []string{`DCLAB\dc-r102-devs@ldap`, `DCLAB\dc-r102-devs@dclab.test`, `X\DCLAB\dc-r102-devs`, "dc-r102-devs@dclab.test@ldap", `DCLAB\`, "@dclab.test"}
	for _, group := range spoofs {
		for _, want := range []string{`DCLAB\dc-r102-devs`, "dc-r102-devs@dclab.test", "dc-r102-devs@ldap", "dc-r102-devs"} {
			if (&subjectGroups{list: []string{group}, domains: gap1124Domains}).has(want) {
				t.Errorf("group %q selected by %q", group, want)
			}
		}
	}
	// The account's own name or principal is not a group.
	subject := profileSubject{UserID: "1001", UserName: "dc-r102-devs", Principal: "dc-r102-devs@DCLAB.TEST", UPN: "dc-r102-devs@dclab.test",
		AccountDomain: "DCLAB", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory}
	m := config.ProfileMatch{Groups: []string{"dc-r102-devs@dclab.test", `DCLAB\dc-r102-devs`, "dc-r102-devs"}}
	if _, _, ok := assignmentMatches(m, &subject, &subjectGroups{domains: groupDomainsOf(&subject)}, true, "", ""); ok {
		t.Error("an account named like the group is not in it")
	}
}

// The gap: a group budget written dc-r102-devs@dclab.test, on_exceed deny.
// The Linux and macOS requests of the same account charge one pooled key,
// and once the group is over its limit the macOS request is refused too.
// An account of another domain in a same-named group is neither charged nor
// refused.
func TestRoutingGroupBudgetPoolsAndDeniesOnEveryOSForm(t *testing.T) {
	now := time.Now()
	budget := config.RoutingBudget{ID: "b-grp-devs", Scope: config.RoutingBudgetScopeGroup, Subject: "dc-r102-devs@dclab.test",
		Period: "day", LimitUSD: 5, OnExceed: config.RoutingBudgetOnExceedDeny}
	policy := routingadmin.Compile(nil, []config.RoutingBudget{budget}, true)
	caller := func(name, accountDomain, domain string, source string, groups []string) routingadmin.Caller {
		ctx := withVerifiedSubject(context.Background(), VerifiedSubject{UserID: "1001", IDKind: useridentity.KindPOSIXUID, UserName: name,
			Source: subjectSourcePeerCredentials, Directory: useridentity.DirectoryFacts{Source: source, Assurance: useridentity.AssuranceVerified,
				Directory: useridentity.DirectoryActiveDirectory, Domain: domain, AccountDomain: accountDomain, Groups: groups, ResolvedAt: now}})
		match := routingCallerMatcher(ctx)
		if match == nil {
			t.Fatal("verified subject: no matcher")
		}
		return routingadmin.CallerFromEngine(engine.Caller{Verified: true, Key: "uid:1001", Matches: match}, true)
	}
	linux := caller("dcad-r102-eng1@dclab.test", "DCLAB", "dclab.test", useridentity.SourceSSSD, gap1124Lists["linux sssd"])
	mac := caller("dcad-r102-eng1", "DCLAB", "dclab.test", useridentity.SourceMacOSOpenDirectory, gap1124Lists["macos"])
	stranger := caller("dcad-r102-eng1", "OTHER", "other.test", useridentity.SourceMacOSOpenDirectory, []string{`OTHER\dc-r102-devs`})

	ledger := routingadmin.NewLedger()
	ledger.ApplyRemote(policy.BudgetIDs(), nil, now)
	fromLinux := policy.Evaluate(routingadmin.Request{Caller: linux, Connector: "claudecode"}, ledger, now)
	fromMac := policy.Evaluate(routingadmin.Request{Caller: mac, Connector: "claudecode"}, ledger, now)
	if len(fromLinux.ChargeKeys) != 1 || !slices.Equal(fromLinux.ChargeKeys, fromMac.ChargeKeys) {
		t.Fatalf("one pooled group key: linux %v, macOS %v", fromLinux.ChargeKeys, fromMac.ChargeKeys)
	}
	if v := policy.Evaluate(routingadmin.Request{Caller: stranger, Connector: "claudecode"}, ledger, now); len(v.ChargeKeys) != 0 || v.Deny != nil {
		t.Fatalf("an OTHER account is not in the group: %+v", v)
	}
	ledger.Charge(fromLinux.ChargeKeys, 6, now)
	for name, c := range map[string]routingadmin.Caller{"linux": linux, "macos": mac} {
		if v := policy.Evaluate(routingadmin.Request{Caller: c, Connector: "claudecode"}, ledger, now); v.Deny == nil || v.Deny.Code != "budget_exceeded:b-grp-devs" {
			t.Errorf("%s: the group is over its deny limit: %+v", name, v)
		}
	}
	if v := policy.Evaluate(routingadmin.Request{Caller: stranger, Connector: "claudecode"}, ledger, now); v.Deny != nil {
		t.Fatalf("an OTHER account is not refused by the DCLAB group budget: %+v", v.Deny)
	}
}

func TestSplitGroupName(t *testing.T) {
	for _, tc := range []struct {
		in, domain, name string
		form             groupNameForm
	}{
		{"devs", "", "devs", groupNameBare},
		{` DCLAB\devs `, "DCLAB", "devs", groupNameQualified},
		{"devs@dclab.test.", "dclab.test", "devs", groupNameQualified},
		{`.\devs`, ".", "devs", groupNameQualified},
		{`DCLAB\devs@ldap`, "", "", groupNameOpaque},
		{`DCLAB\`, "", "", groupNameOpaque},
		{"@dclab.test", "", "", groupNameOpaque},
		{"a@b@c", "", "", groupNameOpaque},
	} {
		domain, name, form := splitGroupName(tc.in)
		if domain != tc.domain || name != tc.name || form != tc.form {
			t.Errorf("splitGroupName(%q) = %q %q %d", tc.in, domain, name, form)
		}
	}
}

// The group checks know a group by its paired spelling, and a respelling
// SSSD answers that the matcher folds is no mismatch.
func TestGroupChecksKnowThePairedSpelling(t *testing.T) {
	pairs := []groupDomains{gap1124Domains}
	if got := pairedGroupSpellings("dc-r102-devs@dclab.test", pairs); !slices.Equal(got, []string{`DCLAB\dc-r102-devs`}) {
		t.Fatalf("paired spellings: %q", got)
	}
	if got := pairedGroupSpellings(`OTHER\dc-r102-devs`, pairs); got != nil {
		t.Fatalf("no pair for OTHER: %q", got)
	}
	macOS := func(_ context.Context, name string) (bool, error) { return name == `DCLAB\dc-r102-devs`, nil }
	exists := foldedGroupExists(macOS, pairs)
	if known, err := exists(context.Background(), "dc-r102-devs@dclab.test"); err != nil || !known {
		t.Fatalf("name@domain on a Mac that lists DOMAIN\\name: %v %v", known, err)
	}
	if known, _ := exists(context.Background(), "dc-r102-devs@other.test"); known {
		t.Fatal("another domain's name is not known by the DCLAB spelling")
	}
	assignments := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: []string{`DCLAB\dc-r102-devs`}}},
		{Match: config.ProfileMatch{Groups: []string{"dc-ml@dclab.test"}}}}
	sssd := func(context.Context, string) (bool, error) { return true, nil }
	respell := func(_ context.Context, name string) string {
		switch name {
		case `DCLAB\dc-r102-devs`:
			return "dc-r102-devs@dclab.test"
		case "dc-ml@dclab.test":
			return "dc-ml" // SSSD switched to short names (GAP-0916)
		}
		return ""
	}
	warnings := unknownAssignmentGroupsForOS(context.Background(), assignments, sssd, respell, nil, "linux")
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "assignment 2:") {
		t.Fatalf("only the short-name respelling is a mismatch: %q", warnings)
	}
}

func TestRoutingAdminGroupWarningsNameTheRuleOrBudget(t *testing.T) {
	selectors := []routingAdminGroupSelector{{label: "routing.admin rule r1"}, {label: "routing.admin budget b-grp-devs"}}
	got := routingAdminGroupWarningsFrom(selectors, []string{
		`assignment 2: group "dc-r102-devs@dclab.test" is not known to this host (renamed or deleted in the directory?), so it selects nobody`,
		`assignment 1: group "x" is listed by this host as "y", the name account group lists carry, so the assignment selects nobody; write "y"`,
	})
	want := []string{
		`routing.admin budget b-grp-devs: group "dc-r102-devs@dclab.test" is not known to this host (renamed or deleted in the directory?), so it selects nobody (routing_admin_group_unmatched)`,
		`routing.admin rule r1: group "x" is listed by this host as "y", the name account group lists carry, so it selects nobody; write "y" (routing_admin_group_unmatched)`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{{ID: "b", Scope: config.RoutingBudgetScopeGroup, Subject: "nosuch-grp"}}}
	if w := RoutingAdminGroupWarnings(context.Background(), cfg, ""); w != nil {
		t.Fatalf("a per-user install gets no group warnings: %q", w)
	}
}

func TestProfileGroupLSANames(t *testing.T) {
	if got := profileGroupLSANames("dc-r102-devs@dclab.test"); !slices.Equal(got, []string{"dc-r102-devs@dclab.test", `dclab.test\dc-r102-devs`}) {
		t.Fatalf("%q", got)
	}
	for _, name := range []string{`DCLAB\dc-r102-devs`, "dc-r102-devs", `DCLAB\x@y`} {
		if got := profileGroupLSANames(name); !slices.Equal(got, []string{name}) {
			t.Fatalf("%q: %q", name, got)
		}
	}
}
