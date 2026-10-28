// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"fmt"
	osuser "os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func init() { directoryUsesWinbind = unixidentity.GroupDirectoryUsesWinbind }

// profileGroupExists asks the platform's account database (NSS on Linux,
// Open Directory on macOS) whether a group named in an assignment exists.
// An error means the answer is unknown, not that the group is absent.
var profileGroupExists = func(ctx context.Context, name string) (bool, error) {
	_, err := unixidentity.Default(ctx).LookupGroup(name)
	var respelled *unixidentity.GroupNameMismatchError
	switch {
	case err == nil, errors.As(err, &respelled):
		// A group the host answers under another spelling exists; the
		// spelling is reported by profileGroupQualifiedName (GAP-0916).
		return true, nil
	case unixidentity.IsNotFound(err) && !unixidentity.GroupNameLookupDefinitive():
		// Himmelblau finds an Entra group only by gid or object id, so its
		// "no such group" by name says nothing (GAP-0292).
		return false, errGroupNameNotSearchable
	case unixidentity.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

// errGroupNameNotSearchable is the unknown answer of a host whose group
// service cannot look groups up by name.
var errGroupNameNotSearchable = errors.New("the group service of this host cannot look groups up by name")

// profileGroupQualifiedName returns the spelling the host lists a group
// under when it is not the one an assignment writes, or "". For a short name
// the host does not know, the name@domain of a joined realm or of an SSSD
// domain the gateway has seen accounts of (an Okta LDAP domain named okta,
// which realmd does not list) that knows it (SSSD with
// use_fully_qualified_names = True, GAP-0332). For a qualified name, the name
// getent answers it with on Linux: after a switch to short names SSSD still
// resolves dc-ml@corp.example.com, but as dc-ml, the name account group lists
// then carry (GAP-0916).
var profileGroupQualifiedName = func(ctx context.Context, name string) string {
	resolver := unixidentity.Default(ctx)
	if strings.ContainsAny(name, `@\`) {
		if runtime.GOOS != "linux" {
			return ""
		}
		var respelled *unixidentity.GroupNameMismatchError
		if _, err := resolver.LookupGroup(name); errors.As(err, &respelled) && !useridentity.EqualFold(respelled.Answered.Name, name) {
			return respelled.Answered.Name
		}
		return ""
	}
	if qualified := unixidentity.QualifiedGroupName(ctx, resolver, name); qualified != "" {
		return qualified
	}
	for _, domain := range observedGroupDomains.list() {
		if listed := unixidentity.GroupSpelling(resolver, name+"@"+domain); listed != "" {
			return listed
		}
	}
	if runtime.GOOS == "darwin" {
		return darwinDirectoryNamesake(ctx, resolver, name)
	}
	return ""
}

// darwinDirectoryNamesake returns DOMAIN\name of the directory group a bare
// name of a local-node group shares, or "": a bound Mac matches a bare
// assignment group to its local group and, by the name part, to the AD group
// DOMAIN\name alike (GAP-0356). The domains are the NetBIOS account domains
// of the guardian's identity records.
func darwinDirectoryNamesake(ctx context.Context, resolver unixidentity.Resolver, name string) string {
	local, err := unixidentity.LocalGroups(ctx)
	if err != nil {
		return ""
	}
	if _, ok := local[name]; !ok {
		return ""
	}
	seen := map[string]bool{}
	for _, record := range enterprisehooks.ReadIdentitySpoolRecords(currentIdentitySpoolDir(), validateManagedGuardianAuthorization, 64) {
		domain := strings.TrimSpace(record.AccountDomain)
		if domain == "" || strings.ContainsAny(domain, `\/@ `) || seen[strings.ToUpper(domain)] || ctx.Err() != nil {
			continue
		}
		seen[strings.ToUpper(domain)] = true
		if listed := unixidentity.GroupSpelling(resolver, domain+`\`+name); listed != "" {
			return listed
		}
	}
	return ""
}

// bareGroupsProbeAccounts bounds the directory accounts one probe looks up.
const bareGroupsProbeAccounts = 3

// bareGroupsDirectorySilent reports whether the directory answers for none
// of the directory accounts the guardian's identity records name (standalone
// enterprise), up to three, looked up by uid. An SSSD that is offline with a
// cold cache answers "no such group" for a group that exists and "no such
// user" for those accounts alike, and a bare group name has no domain whose
// Domain Users group could be asked, so this is what tells a bare name the
// host does not know from a deleted one (GAP-1090). Without such a record (a
// per-user install, no directory account enrolled yet) it cannot tell and
// reports false, as it does when the check runs out of time.
var bareGroupsDirectorySilent = func(ctx context.Context) bool {
	records := enterprisehooks.ReadIdentitySpoolRecords(currentIdentitySpoolDir(), validateManagedGuardianAuthorization, 64)
	resolver := unixidentity.Default(ctx)
	asked := 0
	for _, record := range records {
		uid, err := strconv.Atoi(record.Key)
		if err != nil || uid <= 0 || record.Facts.Directory == "" || record.Facts.Directory == useridentity.DirectoryLocal {
			continue
		}
		if _, err := resolver.LookupUID(uid); err == nil {
			return false
		}
		if ctx.Err() != nil {
			return false
		}
		if asked++; asked == bareGroupsProbeAccounts {
			break
		}
	}
	return asked > 0
}

// matchedGroupSource says whether the group of the account an assignment
// matched by is a local group of this host or a directory group, for explain
// (GAP-0356): a name with a domain is a directory group; a bare name matches
// a DOMAIN\name group by its name part (directory) or a group named exactly
// so, which is local when the local group database holds it. "" when the
// local groups cannot be read.
func matchedGroupSource(_ *guardrailProfileSet, subject *profileSubject, group string) string {
	group = strings.TrimSpace(group)
	if strings.ContainsAny(group, `@\`) {
		return "directory"
	}
	exact, tail := false, false
	if subject != nil {
		for _, have := range subject.Groups {
			have = strings.TrimSpace(have)
			if useridentity.EqualFold(have, group) {
				exact = true
			} else if i := strings.LastIndexByte(have, '\\'); i >= 0 && useridentity.EqualFold(have[i+1:], group) {
				tail = true
			}
		}
	}
	if !exact {
		return "directory"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	local, err := unixidentity.LocalGroups(ctx)
	if err != nil {
		return ""
	}
	for name := range local {
		if useridentity.EqualFold(name, group) {
			if tail {
				return "local and directory"
			}
			return "local"
		}
	}
	// NSS retains an unnamed primary gid as a numeric group. The absence
	// of a local group name does not establish that a directory supplied it.
	if gid, err := strconv.Atoi(group); err == nil && gid >= 0 {
		return ""
	}
	return "directory"
}

// accountGroupIDs lists an OS account's group ids: os/user's listing, which
// on macOS is read again with `id -G` when it failed or filled its 256-group
// buffer (an account in more groups, GAP-0201), and on macOS also each group
// a profile assignment selects by that Open Directory confirms the account's
// uid is in, nested memberships included (GAP-0528).
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	return unixidentity.AccountGroupIDsChecking(context.Background(), account, profileAssignmentGroups())
}

// profileUserEntryUnresolved says why a DOMAIN\user users entry that names
// no account selects nobody (GAP-1095): getent passwd finds no account by
// it, in a domain the host answers for (its Domain Users group resolves) or
// in none; "" when the lookup failed for another reason. It takes the
// lookup when it is made, since the background pass can outlive its caller.
func profileUserEntryUnresolved() func(ctx context.Context, domain string, err error) string {
	groupExists := profileGroupExists
	return func(ctx context.Context, domain string, err error) string {
		if !unixidentity.IsNotFound(err) {
			return ""
		}
		if known, probeErr := groupExists(ctx, domain+`\domain users`); probeErr != nil {
			return ""
		} else if known {
			return "names no account this host knows (getent passwd finds none), so it selects nobody; write the domain this host confirms, or the uid"
		}
		return fmt.Sprintf("names %s, a domain this host does not answer for (another prefix than its NetBIOS or DNS "+
			"name, or the directory is unavailable), so it selects nobody; write the domain this host confirms, or the uid", domain)
	}
}
