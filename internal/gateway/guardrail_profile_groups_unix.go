// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	osuser "os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

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

// accountGroupIDs lists an OS account's group ids: os/user's listing, which
// on macOS is read again with `id -G` when it failed or filled its 256-group
// buffer (an account in more groups, GAP-0201).
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	return unixidentity.AccountGroupIDs(context.Background(), account)
}
