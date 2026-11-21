// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// One group identity on every OS (rel-1-0-10:GAP-1124).
//
// Each OS lists an Active Directory group of the account in its own form:
// SSSD as dc-devs@corp.example.com (use_fully_qualified_names = True), a
// bound Mac and Windows as CORP\dc-devs. A guardrail profile assignment, a
// routing.admin rule or a group budget names the group once, for the whole
// fleet, so a name written in one form selected nobody on the other OSes: a
// deny budget written dc-devs@corp.example.com never acted on a Mac, and the
// Linux and macOS devices never pooled their spend.
//
// A qualified group name is therefore matched as (domain, name). Two
// spellings of the domain are the same domain when they are equal, or when
// they are the NetBIOS and DNS names of the subject's own domain, which the
// subject's verified facts pair (DirectoryFacts.AccountDomain, confirmed by
// SSSD by the SID, by the Mac's directory node or by the Windows token, and
// DirectoryFacts.Domain). Nothing else pairs two domain names: a group of
// another domain, or of a domain the facts do not name, keeps its own domain
// and matches only its own spelling, so folding never puts an account into a
// group of another domain. Only the verified group list is folded; the name
// an assignment writes is the administrator's, and nothing a user or a
// request supplies is a group. A name that carries both separators, or one
// twice (a plain LDAP group spelled CORP\dc-devs inside an SSSD domain,
// CORP\dc-devs@ldap), is not a qualified name and matches only itself.

// groupNameForm is how splitGroupName reads a group name.
type groupNameForm uint8

const (
	// groupNameBare has no domain.
	groupNameBare groupNameForm = iota
	// groupNameQualified is DOMAIN\name or name@domain.
	groupNameQualified
	// groupNameOpaque is any other name with a separator: never folded.
	groupNameOpaque
)

// splitGroupName returns the domain and name part of a qualified group name.
func splitGroupName(s string) (domain, name string, form groupNameForm) {
	s = strings.TrimSpace(s)
	slashes, ats := strings.Count(s, `\`), strings.Count(s, "@")
	switch {
	case slashes == 0 && ats == 0:
		return "", s, groupNameBare
	case slashes+ats != 1:
		return "", "", groupNameOpaque
	}
	sep := `\`
	if ats == 1 {
		sep = "@"
	}
	left, right, _ := strings.Cut(s, sep)
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if sep == `\` {
		domain, name = left, right
	} else {
		domain, name = right, left
	}
	if len(domain) > 1 {
		domain = strings.TrimSuffix(domain, ".")
	}
	if domain == "" || name == "" {
		return "", "", groupNameOpaque
	}
	return domain, name, groupNameQualified
}

// groupDomains is one verified domain by its NetBIOS and DNS names.
type groupDomains struct{ netbios, dns string }

// groupDomainsOf is the subject's own domain, from its verified facts.
func groupDomainsOf(subject *profileSubject) groupDomains {
	if subject == nil {
		return groupDomains{}
	}
	return groupDomains{netbios: strings.TrimSpace(subject.AccountDomain), dns: strings.TrimSuffix(strings.TrimSpace(subject.Domain), ".")}
}

// paired reports whether d names both spellings of one domain.
func (d groupDomains) paired() bool {
	return d.netbios != "" && d.dns != "" && !useridentity.EqualFold(d.netbios, d.dns)
}

// names reports whether domain is one of d's spellings.
func (d groupDomains) names(domain string) bool {
	return d.netbios != "" && useridentity.EqualFold(domain, d.netbios) || d.dns != "" && useridentity.EqualFold(domain, d.dns)
}

// qualifiedKey is the folded identity of the group name in domain: the
// subject's own domain has one key for both of its spellings.
func (d groupDomains) qualifiedKey(domain, name string) string {
	key := foldKey(domain)
	if d.names(domain) {
		key = "\x01"
	}
	return key + "\x00" + foldKey(name)
}

// pairedGroupSpellings lists the other spellings of a qualified group name
// in the verified domains pairs names, for the group checks: CORP\name for
// name@corp.example.com and the reverse. A bare or opaque name has none.
func pairedGroupSpellings(group string, pairs []groupDomains) []string {
	domain, name, form := splitGroupName(group)
	if form != groupNameQualified {
		return nil
	}
	var out []string
	for _, pair := range pairs {
		if !pair.paired() || !pair.names(domain) {
			continue
		}
		for _, spelling := range []string{pair.netbios + `\` + name, name + "@" + pair.dns} {
			if !useridentity.EqualFold(spelling, strings.TrimSpace(group)) {
				out = append(out, spelling)
			}
		}
	}
	return out
}

// groupSpellingsFold reports whether two qualified spellings name the same
// group of one verified domain by its NetBIOS and DNS names (CORP\name and
// name@corp.example.com): what a host answers a group by when its NSS
// service resolves the other spelling, so the matcher folds them. Only a
// pair of one of pairs folds (the matcher folds the subject's own domain and
// no other): a respelling into another domain (CORP\name answered as
// name@trust.example.com) is a mismatch that the warning must keep
// (GAP-1136).
func groupSpellingsFold(written, listed string, pairs []groupDomains) bool {
	wDomain, wName, wForm := splitGroupName(written)
	lDomain, lName, lForm := splitGroupName(listed)
	if wForm != groupNameQualified || lForm != groupNameQualified || !useridentity.EqualFold(wName, lName) ||
		strings.Contains(written, `\`) == strings.Contains(listed, `\`) || useridentity.EqualFold(wDomain, lDomain) {
		return false
	}
	for _, pair := range pairs {
		if pair.paired() && pair.names(wDomain) && pair.names(lDomain) {
			return true
		}
	}
	return false
}

// foldedGroupQualify is qualify for the group checks, without the respelling
// the matcher folds: a group that the host lists under the other spelling of
// a verified domain is selected as written, so it has no respelled warning.
func foldedGroupQualify(qualify func(context.Context, string) string, pairs []groupDomains) func(context.Context, string) string {
	if qualify == nil || len(pairs) == 0 {
		return qualify
	}
	return func(ctx context.Context, name string) string {
		listed := qualify(ctx, name)
		if listed != "" && groupSpellingsFold(name, listed, pairs) {
			return ""
		}
		return listed
	}
}

// verifiedGroupDomainsMax bounds the identity records one pass reads.
const verifiedGroupDomainsMax = 64

// verifiedGroupDomains lists the domains the matcher folds for the accounts
// of this device, for the group checks: for each account the guardian's
// identity records name, the own verified domain (groupDomainsOf) of the
// subject the matcher builds from that account's facts
// (profileSubjectFromVerified), the facts requests of the account carry
// (cachedDirectoryFacts) or, while none are cached (config validate, a
// gateway no hook of the account has reached yet), explain's lookup of them
// (profileExplainDirectoryFacts). The warning thus folds by the very facts
// and function the matcher folds by (GAP-1312): on Linux SSSD (by the SID)
// or winbind confirms the NetBIOS domain, which the Linux records do not
// carry, so reading the records alone paired no domain there and every
// DOMAIN\name of the joined domain kept a respelled warning although the
// matcher selected it; on a Mac the record's account domain (GAP-0635) is
// in the facts. Standalone Windows matches a group by its SID
// (profileGroupSIDs) and folds no spelling, so it has none. One lookup per
// DNS domain is enough: every account of a domain has its pair. ctx bounds
// the lookups.
func verifiedGroupDomains(ctx context.Context, spoolDir string) []groupDomains {
	if strings.TrimSpace(spoolDir) == "" || runtime.GOOS == "windows" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cached, lookup := cachedDirectoryFacts, profileExplainDirectoryFacts
	var out []groupDomains
	known := func(dns string) bool {
		return dns != "" && slices.ContainsFunc(out, func(have groupDomains) bool { return useridentity.EqualFold(have.dns, dns) })
	}
	for _, record := range enterprisehooks.ReadIdentitySpoolRecords(spoolDir, validateManagedGuardianAuthorization, verifiedGroupDomainsMax) {
		if ctx.Err() != nil {
			break
		}
		if known(strings.TrimSuffix(strings.TrimSpace(record.Facts.Domain), ".")) {
			continue
		}
		facts, _, ok := cached(record.Key)
		if !ok {
			var err error
			if facts, err = lookup(record.Key); err != nil {
				continue
			}
		}
		if facts.ResolvedAt.IsZero() {
			continue
		}
		// The gateway merges the guardian record into the facts a hook
		// call of the account carries (mergeSpoolFacts), so the matcher
		// folds the NetBIOS domain the Mac record names (GAP-0635). A
		// lookup outside the gateway (config validate) merges none, and a
		// Mac's Open Directory answer has no NetBIOS domain, so the check
		// paired nothing there and kept a warning for a group the matcher
		// selects (rel-1-0-10:GAP-1541). The gateway merges only the record
		// of the account that holds the uid now (readIdentitySpoolFactsForAccount):
		// merging any record let the warning fold the domain of a record
		// the matcher never reads, such as a removed account's whose uid a
		// new account holds (rel-1-0-10:GAP-1740).
		holder, named := profileExplainAccountName(record.Key)
		if named && spoolRecordNamesAccount(record, holder) && !spoolRecordOfOtherSID(record, facts.AccountSID) {
			facts = mergeSpoolFacts(facts, record)
		}
		subject := profileSubjectFromVerified(VerifiedSubject{
			UserID: record.Key, IDKind: useridentity.KindForID(record.Key), UserName: holder, Directory: facts,
		}, false)
		pair := groupDomainsOf(&subject)
		if strings.ContainsAny(pair.netbios, `\/@ `) || !pair.paired() || known(pair.dns) {
			continue
		}
		out = append(out, pair)
	}
	return out
}

// matcherFoldedGroupChecks is profileGroupExists and profileGroupQualifiedName
// for the group checks, with the respellings the matcher folds
// (foldedGroupExists, foldedGroupQualify) for the domains of spoolDir's
// accounts (verifiedGroupDomains). The domains are read at the first check,
// inside the pass's time budget, which can outlive the caller, so it takes
// the lookups when it is made.
func matcherFoldedGroupChecks(spoolDir string) (func(context.Context, string) (bool, error), func(context.Context, string) string) {
	groupExists, groupQualify := profileGroupExists, profileGroupQualifiedName
	var (
		once    sync.Once
		exists  func(context.Context, string) (bool, error)
		qualify func(context.Context, string) string
	)
	load := func(ctx context.Context) {
		once.Do(func() {
			pairs := verifiedGroupDomains(ctx, spoolDir)
			exists, qualify = foldedGroupExists(groupExists, pairs), foldedGroupQualify(groupQualify, pairs)
		})
	}
	return func(ctx context.Context, name string) (bool, error) {
			load(ctx)
			return exists(ctx, name)
		}, func(ctx context.Context, name string) string {
			load(ctx)
			return qualify(ctx, name)
		}
}

// foldedGroupExists is exists for a group the matcher also selects by its
// paired spelling: it is known when the host knows either spelling, so a
// group name written dc-devs@corp.example.com on a Mac that lists
// CORP\dc-devs is not reported as unknown.
func foldedGroupExists(exists func(context.Context, string) (bool, error), pairs []groupDomains) func(context.Context, string) (bool, error) {
	if len(pairs) == 0 {
		return exists
	}
	return func(ctx context.Context, name string) (bool, error) {
		known, err := exists(ctx, name)
		if known || ctx.Err() != nil {
			return known, err
		}
		for _, spelling := range pairedGroupSpellings(name, pairs) {
			if other, otherErr := exists(ctx, spelling); otherErr == nil && other {
				return true, nil
			}
		}
		return known, err
	}
}

// profileGroupLSANames lists the names the LSA is asked for one assignment
// group, in order: the name as written, then, for name@domain, the
// domain\name form LookupAccountName documents for a DNS domain name, so a
// group written name@corp.example.com resolves on Windows as it does on
// Linux and macOS. The LSA decides; nothing is paired here.
func profileGroupLSANames(name string) []string {
	name = strings.TrimSpace(name)
	domain, account, form := splitGroupName(name)
	if form == groupNameQualified && !strings.Contains(name, `\`) {
		return []string{name, domain + `\` + account}
	}
	return []string{name}
}
