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
	"strings"

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
		if _, err := resolver.LookupGroup(name + "@" + domain); err == nil {
			return name + "@" + domain
		}
	}
	return ""
}

// accountGroupIDs lists an OS account's group ids: os/user's listing, which
// on macOS is read again with `id -G` when it failed or filled its 256-group
// buffer (an account in more groups, GAP-0201).
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	return unixidentity.AccountGroupIDs(context.Background(), account)
}

// profileUserEntryUnmatched returns the check that says why a DOMAIN\user
// users entry selects nobody (GAP-1095): it names an account the host
// resolves the way profile-explain does, but the domain written is neither
// the account's verified NetBIOS account domain nor its DNS domain, which an
// entry must name; or getent passwd finds no account by it, in a domain the
// host answers for (its Domain Users group resolves) or in none. The check
// answers "" when the entry selects its account or a lookup fails. It takes
// the lookups when it is made, since the background pass can outlive its
// caller.
func profileUserEntryUnmatched() func(context.Context, string) string {
	lookupAccount, lookupFacts, groupExists := profileExplainAccount, profileExplainDirectoryFacts, profileGroupExists
	return func(ctx context.Context, entry string) string {
		domain, account, qualified := strings.Cut(strings.TrimSpace(entry), `\`)
		if !qualified || domain == "" || domain == "." || account == "" || ctx.Err() != nil {
			return ""
		}
		id, _, err := lookupAccount(entry)
		if unixidentity.IsNotFound(err) {
			if known, probeErr := groupExists(ctx, domain+`\domain users`); probeErr != nil {
				return ""
			} else if known {
				return "names no account this host knows (getent passwd finds none)"
			}
			return fmt.Sprintf("names %s, a domain this host does not answer for (another prefix than its NetBIOS or DNS "+
				"name, or the directory is unavailable)", domain)
		}
		if err != nil || id == "" {
			return ""
		}
		facts, err := lookupFacts(id)
		if err != nil || facts.ResolvedAt.IsZero() ||
			useridentity.EqualFold(domain, facts.AccountDomain) || useridentity.EqualFold(domain, facts.Domain) {
			return ""
		}
		confirmed := firstNonEmpty(facts.AccountDomain, facts.Domain)
		if confirmed == "" {
			return fmt.Sprintf("names uid %s, but this host confirms no domain for that account", id)
		}
		return fmt.Sprintf("names uid %s, but this host confirms that account's domain as %s, not %s", id, confirmed, domain)
	}
}
