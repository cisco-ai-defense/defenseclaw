// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1312: a managed Linux guardian's identity record carries no NetBIOS
// domain; SSSD confirms it for the account by the SID (AccountDomain), and
// the matcher folds DCLAB\x and x@dclab.test by it. The respelled-group
// warning reads the same facts, so DCLAB\x of the joined domain has no
// "selects nobody" warning, while OTHER\x, which the matcher does not fold,
// keeps it.
func TestRespelledGroupWarningFoldsTheJoinedDomainTheMatcherFolds(t *testing.T) {
	const uid = "94401312"
	now := time.Now().UTC()
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: uid, User: "dcad-r102-eng1", UpdatedAt: now, SSSDDomain: "dclab.test",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", Realm: "DCLAB.TEST",
			Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, uid+".json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	// What SSSD answers for the account: the NetBIOS domain it confirmed.
	facts := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", Realm: "DCLAB.TEST",
		AccountDomain: "DCLAB", Directory: useridentity.DirectoryActiveDirectory,
		Groups: []string{"dc-r102-devs@dclab.test"}, ResolvedAt: now}
	validate, cached, lookup := validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts
	exists, qualify, silent := profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent
	t.Cleanup(func() {
		validateManagedGuardianAuthorization, cachedDirectoryFacts, profileExplainDirectoryFacts = validate, cached, lookup
		profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent = exists, qualify, silent
	})
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) {
		return useridentity.DirectoryFacts{}, time.Time{}, false
	}
	profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
		if id != uid {
			return useridentity.DirectoryFacts{}, errors.New("no such account")
		}
		return facts, nil
	}
	profileGroupExists = func(context.Context, string) (bool, error) { return true, nil }
	profileGroupQualifiedName = func(_ context.Context, name string) string {
		if domain, group, ok := strings.Cut(name, `\`); ok {
			return group + "@" + strings.ToLower(domain) + ".test" // SSSD lists the fully qualified name
		}
		return ""
	}
	bareGroupsDirectorySilent = func(context.Context) bool { return false }

	// The matcher selects the account by the NetBIOS spelling of its own
	// domain, and not by another domain's.
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: uid, IDKind: useridentity.KindForID(uid),
		UserName: "dcad-r102-eng1", Directory: facts}, false)
	groups := &subjectGroups{list: subject.Groups, domains: groupDomainsOf(&subject)}
	if !groups.has(`DCLAB\dc-r102-devs`) || groups.has(`OTHER\dc-r102-devs`) {
		t.Fatal("the matcher folds DCLAB\\x (own domain) and only it")
	}

	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{
		{ID: "r-own", Match: config.RoutingAdminMatch{Groups: []string{`DCLAB\dc-r102-devs`}}},
		{ID: "r-other", Match: config.RoutingAdminMatch{Groups: []string{`OTHER\dc-r102-devs`}}},
	}}
	got := RoutingAdminGroupWarnings(context.Background(), cfg, dir)
	want := `routing.admin rule r-other: group "OTHER\\dc-r102-devs" is listed by this host as "dc-r102-devs@other.test", ` +
		`the name account group lists carry, so it selects nobody; write "dc-r102-devs@other.test" (routing_admin_group_unmatched)`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("only the domain the matcher does not fold keeps its warning: %q", got)
	}
}
