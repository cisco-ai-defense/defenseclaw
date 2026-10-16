// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainLookupTimeout bounds the account lookup of explain.
const profileExplainLookupTimeout = 10 * time.Second

// profileExplainAccount names an account (name or uid) through the platform
// resolver the hook path uses: NSS on Linux, so directory accounts resolve
// even where os/user reads only the local files, and Open Directory on macOS,
// which has no getent.
var profileExplainAccount = func(name string) (id, userName string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	resolver := unixidentity.Default(ctx)
	// name@domain and DOMAIN\name resolve as getent resolves them, when the
	// answer is the same account (GAP-0711).
	account, err := unixidentity.LookupAccountSpelling(resolver, name, func(uid int) (useridentity.DirectoryFacts, bool) {
		facts, err := profileExplainDirectoryFacts(strconv.Itoa(uid))
		return facts, err == nil
	})
	if err != nil {
		uid, convErr := strconv.Atoi(name)
		if convErr != nil {
			return "", "", err
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return "", "", err
		}
	} else if twins := sameNameProfileAccounts(ctx, resolver, name, account); len(twins) > 0 {
		// A bare name a local and a directory account share names both:
		// explaining the one NSS answers first hid the other (GAP-1087).
		return "", "", ambiguousAccount(name, append([]unixidentity.Account{account}, twins...))
	}
	return strconv.Itoa(account.UID), sanitizeLLMEventUser(account.Name), nil
}

// sameNameProfileAccounts lists the other accounts a bare name typed for an
// administrator view also names (unixidentity.SameNameAccounts); none for a
// qualified name or a uid.
var sameNameProfileAccounts = func(ctx context.Context, r unixidentity.Resolver, name string, account unixidentity.Account) []unixidentity.Account {
	if strings.ContainsAny(name, `@\`) || strings.Trim(name, "0123456789") == "" {
		return nil
	}
	twins := unixidentity.SameNameAccounts(ctx, r, account)
	for _, cached := range managedHookPeerHomes.cachedNamesakes(name, account.UID) {
		found := false
		for _, twin := range twins {
			if twin.UID == cached.UID {
				found = true
				break
			}
		}
		if !found {
			twins = append(twins, cached)
		}
	}
	return twins
}

// ambiguousAccount is the refusal of a bare name that names accounts.
func ambiguousAccount(name string, accounts []unixidentity.Account) error {
	refs := make([]useridentity.AccountRef, 0, len(accounts))
	for _, account := range accounts {
		refs = append(refs, useridentity.AccountRef{ID: strconv.Itoa(account.UID), Name: account.Name})
	}
	return &useridentity.AmbiguousAccountError{Name: name, Accounts: refs}
}

// adminViewDomainCouldHold reports whether the domain of a qualified --user
// filter could hold a uid: always, as a uid does not tell a local account
// from a directory one (GAP-1221).
func adminViewDomainCouldHold(string, string) bool { return true }

// profileExplainUnresolved resolves an account the platform resolver cannot
// name through the OS account database (os/user), with its error.
var profileExplainQualifiedName = func(ctx context.Context, name string) string {
	return unixidentity.QualifiedUserName(ctx, unixidentity.Default(ctx), name)
}

func profileExplainUnresolved(name string, lookupErr error) (profileSubject, error) {
	if local, err := lookupLocalProfileSubject(name); err == nil {
		return local, nil
	}
	if cached, ok := profileExplainCachedSubject(name, time.Now()); ok {
		return cached, nil
	}
	if subject, ok := profileExplainUID(strings.TrimSpace(name), lookupErr); ok {
		return subject, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	return profileSubject{UserName: name}, unixidentity.AccountLookupError(name, profileExplainQualifiedName(ctx, name), lookupErr)
}

// profileExplainDirectoryFacts returns the facts a verified request from uid
// carries (the account database plus the guardian identity spool) from the
// cache requests read, after a lookup of explain's own
// (explainDirectoryFacts). The account it resolves is recorded as the holder
// of those facts, as a hook call records it, so explain by name during a
// later outage serves what the hooks keep (profileExplainCachedSubject,
// GAP-0529).
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	if uid, err := strconv.Atoi(id); err == nil && uid >= 0 && strconv.Itoa(uid) == id {
		return managedHookPeerHomes.explainDirectory(uid)
	}
	return explainDirectoryFacts(peerDirectoryCache(), id)
}

// profileExplainUID explains a uid the account database cannot name now as
// a hook call from it is decided: the kernel verifies the uid, so users
// entries naming it still select their profile, from the cached facts if any
// and with default_lookup_failed for the rest. Explain printed
// default_lookup_failed for it while its hook calls got the uid's profile
// (GAP-0361).
func profileExplainUID(name string, lookupErr error) (profileSubject, bool) {
	uid, err := strconv.Atoi(name)
	if err != nil || uid < 0 || strconv.Itoa(uid) != name {
		return profileSubject{}, false
	}
	userName := managedHookPeerHomes.lastName(uid)
	facts, err := profileExplainDirectoryFacts(name)
	if err == nil && !facts.ResolvedAt.IsZero() {
		return profileSubjectFromVerified(VerifiedSubject{
			UserID: name, IDKind: useridentity.KindForID(name), UserName: userName, Directory: facts,
		}, identityLookupBlocking.Load()), true
	}
	reason := "the account database names no account for this uid now"
	if lookupErr != nil {
		reason += " (" + lookupErr.Error() + ")"
	}
	if err != nil {
		reason += "; directory lookup: " + err.Error()
	}
	return profileSubject{
		UserID: name, IDKind: useridentity.KindForID(name), UserName: userName,
		LookupFailed: identityLookupBlocking.Load(), LookupError: reason,
	}, true
}

// profileExplainCachedSubject serves explain for an account the directory
// cannot name now (SSSD stopped, a domain controller away) from what its
// hooks apply: the facts the gateway cached for the uid whose account had
// that name (or that uid), within the hour they are served. Explain then
// shows the hook's profile with the age of the facts, not a spelling error
// (GAP-0899).
var profileExplainCachedSubject = func(name string, now time.Time) (profileSubject, bool) {
	uid, userName, ok := managedHookPeerHomes.cachedHolder(name)
	if !ok {
		return profileSubject{}, false
	}
	id := strconv.Itoa(uid)
	// peek reports only facts a hook call would still get: within the hour,
	// and from a guardian record still trusted.
	facts, fetchedAt, ok := peerDirectoryCache().peek(id)
	if !ok {
		return profileSubject{}, false
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
	}, identityLookupBlocking.Load())
	subject.cachedFactsAge = max(now.Sub(fetchedAt), time.Second)
	return subject, true
}
