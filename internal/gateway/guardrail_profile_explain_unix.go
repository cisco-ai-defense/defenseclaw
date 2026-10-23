// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"fmt"
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
	} else if twins, err := sameNameProfileAccounts(ctx, resolver, name, account); len(twins) > 0 {
		// A bare name a local and a directory account share names both:
		// explaining the one NSS answers first hid the other (GAP-1087).
		return "", "", ambiguousAccount(name, append([]unixidentity.Account{account}, twins...))
	} else if err != nil {
		// Whether a directory account shares the name is unknown: the bare
		// name is refused, not taken for the local account (GAP-1131).
		return "", "", err
	}
	return strconv.Itoa(account.UID), sanitizeLLMEventUser(account.Name), nil
}

// sameNameProfileAccounts lists the other accounts a bare name typed for an
// administrator view also names (unixidentity.SameNameAccounts); none for a
// qualified name or a uid. Its error is that of SameNameAccounts, when no
// twin is known and the joined domains are not.
var sameNameProfileAccounts = func(ctx context.Context, r unixidentity.Resolver, name string, account unixidentity.Account) ([]unixidentity.Account, error) {
	if strings.ContainsAny(name, `@\`) || strings.Trim(name, "0123456789") == "" {
		return nil, nil
	}
	twins, err := unixidentity.SameNameAccounts(ctx, r, account)
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
	if len(twins) > 0 {
		return twins, nil
	}
	return nil, err
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
// filter held a uid no account holds now: a uid does not tell a local account
// from a directory one (GAP-1221), nor one domain from another, so the domain
// must be one the gateway knew the uid's account by (adminViewKnownDomain):
// the name it last resolved to, or the facts its hooks cached (GAP-1263).
func adminViewDomainCouldHold(user, id string) bool {
	_, domain := useridentity.SplitQualifiedName(user)
	var extra []string
	if uid, err := strconv.Atoi(strings.TrimSpace(id)); err == nil && uid >= 0 {
		_, lastDomain := useridentity.SplitQualifiedName(managedHookPeerLastName(uid))
		extra = append(extra, lastDomain)
	}
	return adminViewKnownDomain(domain, id, extra...)
}

// profileExplainQualifiedName is the spelling NSS knows a short name by
// (unixidentity.QualifiedUserName).
var profileExplainQualifiedName = func(ctx context.Context, name string) string {
	return unixidentity.QualifiedUserName(ctx, unixidentity.Default(ctx), name)
}

// profileExplainLocalAccount reports, with nil, that the platform resolver
// shows name to be the local account that holds uid, alone
// (unixidentity.ConfirmLocalAccount).
var profileExplainLocalAccount = func(uid int, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	return unixidentity.ConfirmLocalAccount(unixidentity.Default(ctx), uid, name)
}

// profileExplainUnresolved resolves an account the platform resolver cannot
// name through the OS account database (os/user), with its error.
//
// A lookup that refused the account is final: a uid more than one account
// holds (the hook path gives it no facts), or an NSS answer for another
// account than the one named (a cross-domain spelling). The OS database
// then named a local account of the name and explain printed its profile
// (review of GAP-1087, loop 4). For any other failure the account os/user
// names is taken only when NSS shows it is the local account that holds its
// uid, alone (profileExplainLocalAccount).
func profileExplainUnresolved(name string, lookupErr error) (profileSubject, error) {
	var shared *unixidentity.SharedUIDError
	if errors.As(lookupErr, &shared) {
		return profileSubject{UserName: name}, lookupErr
	}
	var mismatch *unixidentity.NameMismatchError
	if errors.As(lookupErr, &mismatch) {
		return profileSubject{UserName: name}, unixidentity.AccountLookupError(name, "", lookupErr)
	}
	if local, err := lookupLocalProfileSubject(name); err == nil {
		uid, convErr := strconv.Atoi(local.UserID)
		if convErr == nil && profileExplainLocalAccount(uid, local.UserName) == nil {
			return local, nil
		}
	}
	cached, cachedErr := profileExplainCachedSubject(name, time.Now())
	if cachedErr == nil {
		return cached, nil
	}
	if !errors.Is(cachedErr, errNoCachedHolder) {
		return profileSubject{UserName: name}, fmt.Errorf("%w: %w", unixidentity.AccountLookupError(name, "", lookupErr), cachedErr)
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
// (GAP-0899). errNoCachedHolder when there are none; another error says why
// the facts a qualified spelling names are not shown (cachedHolderFor).
var profileExplainCachedSubject = func(name string, now time.Time) (profileSubject, error) {
	uid, userName, err := managedHookPeerHomes.cachedHolderFor(name)
	if err != nil {
		return profileSubject{}, err
	}
	id := strconv.Itoa(uid)
	// peek reports only facts a hook call would still get: within the hour,
	// and from a guardian record still trusted.
	facts, fetchedAt, ok := peerDirectoryCache().peek(id)
	if !ok {
		return profileSubject{}, errNoCachedHolder
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
	}, identityLookupBlocking.Load())
	subject.cachedFactsAge = max(now.Sub(fetchedAt), time.Second)
	return subject, nil
}
