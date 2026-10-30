//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The hook socket, which alone verifies a caller by its peer credentials,
// exists on Linux and macOS.
func trustedConnectorPlatformSupported() bool { return true }

// trustedConnectorLookupBudget bounds one resolution (the service account
// with its groups, or one asserted person).
const trustedConnectorLookupBudget = identityDirectoryBudget

// actingForPersonTTL is how long a complete answer for an asserted person is
// reused. Failures are never kept.
const actingForPersonTTL = 60 * time.Second

// trustedConnectorResolver returns the account database for one resolution.
var trustedConnectorResolver = func(ctx context.Context) unixidentity.Resolver {
	return unixidentity.NewCachingResolver(unixidentity.Default(ctx))
}

// errTrustedConnectorLookupTimeout is a lookup that ran over its budget.
var errTrustedConnectorLookupTimeout = errors.New("account lookup did not finish in time")

// withTrustedConnectorBudget runs fn within the lookup budget.
func withTrustedConnectorBudget[T any](fn func(ctx context.Context, r unixidentity.Resolver) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), trustedConnectorLookupBudget)
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := fn(ctx, trustedConnectorResolver(ctx))
		done <- result{value, err}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		var zero T
		return zero, errTrustedConnectorLookupTimeout
	}
}

// trustedConnectorAdminGroupNames are the bare group names that make an
// account an administrator (compared without case, without a domain).
var trustedConnectorAdminGroupNames = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true,
	"administrators": true, "domain admins": true, "enterprise admins": true, "schema admins": true,
}

func trustedConnectorAdminGroup(name string) bool {
	bare, _ := useridentity.SplitQualifiedName(strings.TrimSpace(name))
	return trustedConnectorAdminGroupNames[strings.ToLower(bare)]
}

// lookupTrustedConnectorAccount resolves a name or uid to one account. A
// bare name another account shares (a local and a directory account), or
// whose namesakes cannot be ruled out, is ambiguous.
func lookupTrustedConnectorAccount(ctx context.Context, r unixidentity.Resolver, name string) (unixidentity.Account, string, error) {
	name = strings.TrimSpace(name)
	if uid, err := strconv.Atoi(name); err == nil && strconv.Itoa(uid) == name && uid >= 0 {
		account, err := r.LookupUID(uid)
		if unixidentity.IsNotFound(err) {
			return unixidentity.Account{}, actingForCauseUnknownUser, err
		}
		return account, "", err
	}
	account, err := unixidentity.LookupAccountSpelling(r, name, nil)
	if err != nil {
		var mismatch *unixidentity.NameMismatchError
		if unixidentity.IsNotFound(err) || errors.As(err, &mismatch) {
			return unixidentity.Account{}, actingForCauseUnknownUser, err
		}
		return unixidentity.Account{}, "", err
	}
	if !strings.ContainsAny(name, `@\`) {
		twins, twinErr := unixidentity.SameNameAccounts(ctx, r, account)
		if len(twins) > 0 {
			return unixidentity.Account{}, actingForCauseAmbiguousUser, fmt.Errorf("the name %q names more than one account", name)
		}
		if twinErr != nil {
			return unixidentity.Account{}, actingForCauseAmbiguousUser, twinErr
		}
	}
	return account, "", nil
}

// accountIsAdministrator reports uid 0 (and every alias of it), or a member
// of root's group or an admin group. An unnamed group fails the check: it
// could be one.
func accountIsAdministrator(r unixidentity.Resolver, account unixidentity.Account) (bool, []int, error) {
	if account.UID == 0 {
		return true, nil, nil
	}
	gids, err := r.GroupIDs(account)
	if err != nil {
		return false, nil, err
	}
	for _, gid := range gids {
		if gid == 0 {
			return true, gids, nil
		}
		group, err := r.LookupGroupID(gid)
		if err != nil {
			return false, nil, fmt.Errorf("group %d did not resolve: %w", gid, err)
		}
		if trustedConnectorAdminGroup(group.Name) {
			return true, gids, nil
		}
	}
	return false, gids, nil
}

// resolveTrustedConnectorEntry resolves one entry's account, users and
// groups to ids.
func resolveTrustedConnectorEntry(entry config.TrustedConnectorConfig) trustedConnectorEntry {
	out := trustedConnectorEntry{
		Name: strings.TrimSpace(entry.Name), AccountSpec: strings.TrimSpace(entry.Account),
		Users: map[string]bool{}, Groups: map[string]bool{},
	}
	type resolved struct {
		account  unixidentity.Account
		disabled string
		users    map[string]bool
		groups   map[string]bool
		warnings []string
	}
	result, err := withTrustedConnectorBudget(func(ctx context.Context, r unixidentity.Resolver) (resolved, error) {
		res := resolved{users: map[string]bool{}, groups: map[string]bool{}}
		account, cause, err := lookupTrustedConnectorAccount(ctx, r, out.AccountSpec)
		if err != nil {
			if cause == "" {
				return res, err
			}
			res.disabled = "account_" + cause
			return res, nil
		}
		res.account = account
		admin, _, err := accountIsAdministrator(r, account)
		if err != nil {
			return res, err
		}
		if admin {
			res.disabled = "account_is_administrator"
			return res, nil
		}
		for _, user := range entry.MayActFor.Users {
			person, cause, err := lookupTrustedConnectorAccount(ctx, r, user)
			switch {
			case err != nil && cause == "":
				return res, err
			case err != nil:
				res.warnings = append(res.warnings, "a may_act_for.users entry did not resolve to one account ("+cause+")")
			case person.UID == 0:
				res.warnings = append(res.warnings, "a may_act_for.users entry is root; dropped")
			case person.UID == account.UID:
				res.warnings = append(res.warnings, "a may_act_for.users entry is the connector's own account; dropped")
			default:
				res.users[strconv.Itoa(person.UID)] = true
			}
		}
		for _, name := range entry.MayActFor.Groups {
			group, err := r.LookupGroup(strings.TrimSpace(name))
			switch {
			case err != nil && !unixidentity.IsNotFound(err):
				return res, err
			case err != nil:
				res.warnings = append(res.warnings, "a may_act_for.groups entry did not resolve")
			case group.GID == 0 || trustedConnectorAdminGroup(group.Name):
				res.warnings = append(res.warnings, "a may_act_for.groups entry is an admin group; dropped")
			default:
				res.groups[strconv.Itoa(group.GID)] = true
			}
		}
		return res, nil
	})
	if err != nil {
		out.Disabled = "lookup_failed"
		out.Warnings = append(out.Warnings, "lookup failed: "+boundedLogText(err.Error()))
		return out
	}
	if result.disabled != "" {
		out.Disabled = result.disabled
		if result.account.Name != "" {
			out.AccountID, out.AccountName = strconv.Itoa(result.account.UID), result.account.Name
		}
		return out
	}
	out.AccountID, out.AccountName = strconv.Itoa(result.account.UID), result.account.Name
	out.Users, out.Groups, out.Warnings = result.users, result.groups, result.warnings
	return out
}

func boundedLogText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > 200 {
		return value[:200]
	}
	return value
}

// actingForPeople caches complete answers for asserted people, keyed by the
// connector account and the spelling it sent.
var actingForPeople = struct {
	sync.Mutex
	entries map[string]actingForPersonAnswer
}{entries: map[string]actingForPersonAnswer{}}

type actingForPersonAnswer struct {
	uid, name string
	gids      []int
	admin     bool
	at        time.Time
}

const actingForPeopleMax = 4096

// actingForDirectory is the directory facts cache of asserted people. It is
// not the hook path's cache: a lookup a connector starts for a person never
// changes what the person's own calls get.
var actingForDirectory = sync.OnceValue(func() *identityDirectoryCache {
	cache := newIdentityDirectoryCache(resolvePeerDirectoryFacts)
	cache.incomplete = func(facts useridentity.DirectoryFacts) bool {
		return hasUnnamedGroup(facts) || awaitingSpoolUPN(facts) || facts.OnlyPrimaryGroup
	}
	return cache
})

// resolveActingFor decides one acting_for for entry's service account.
func resolveActingFor(entry trustedConnectorEntry, user string, now time.Time) (actingFor, actingForRefusal) {
	if entry.Disabled != "" {
		return actingFor{}, actingForRefusal{Code: actingForRefusedConnectorDisabled, Cause: entry.Disabled}
	}
	key := entry.AccountID + "\x00" + user
	actingForPeople.Lock()
	answer, cached := actingForPeople.entries[key]
	if cached && now.Sub(answer.at) >= actingForPersonTTL {
		delete(actingForPeople.entries, key)
		cached = false
	}
	actingForPeople.Unlock()
	if !cached {
		type looked struct {
			answer actingForPersonAnswer
			cause  string
		}
		result, err := withTrustedConnectorBudget(func(ctx context.Context, r unixidentity.Resolver) (looked, error) {
			account, cause, err := lookupTrustedConnectorAccount(ctx, r, user)
			if err != nil {
				if cause != "" {
					return looked{cause: cause}, nil
				}
				return looked{}, err
			}
			admin, gids, err := accountIsAdministrator(r, account)
			if err != nil {
				return looked{}, err
			}
			return looked{answer: actingForPersonAnswer{
				uid: strconv.Itoa(account.UID), name: account.Name, gids: gids, admin: admin,
			}}, nil
		})
		if err != nil {
			return actingFor{}, actingForRefusal{Code: actingForRefusedLookupUnavailable, Cause: "lookup"}
		}
		if result.cause != "" {
			return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: result.cause}
		}
		answer = result.answer
		answer.at = now
		actingForPeople.Lock()
		if len(actingForPeople.entries) >= actingForPeopleMax {
			actingForPeople.entries = map[string]actingForPersonAnswer{}
		}
		actingForPeople.entries[key] = answer
		actingForPeople.Unlock()
	}
	switch {
	case answer.admin || answer.uid == "0":
		return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: actingForCauseAdminTarget}
	case answer.uid == entry.AccountID || trustedConnectorAccountListed(answer.uid):
		return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: actingForCauseConnectorSelf}
	}
	allowed := entry.Users[answer.uid]
	for _, gid := range answer.gids {
		if entry.Groups[strconv.Itoa(gid)] {
			allowed = true
		}
	}
	if !allowed {
		return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: actingForCauseOutOfSet}
	}
	// The person's directory facts, from the connector's own cache. A
	// timeout or an incomplete answer refuses the call.
	cache := actingForDirectory()
	facts, ok := cache.get(answer.uid, true)
	if !ok || facts.ResolvedAt.IsZero() || cache.unsettled(facts) {
		return actingFor{}, actingForRefusal{Code: actingForRefusedLookupUnavailable, Cause: "directory_facts"}
	}
	if _, domain := useridentity.SplitQualifiedName(answer.name); domain != "" && strings.TrimSpace(facts.Domain) == "" &&
		facts.Directory != useridentity.DirectoryLocal {
		// A qualified account whose domain is neither the joined one nor a
		// listed trusted child domain gets no verified domain.
		return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: actingForCauseUntrustedRealm}
	}
	for _, group := range facts.Groups {
		if trustedConnectorAdminGroup(group) {
			return actingFor{}, actingForRefusal{Code: actingForRefusedNotAllowed, Cause: actingForCauseAdminTarget}
		}
	}
	return actingFor{
		Connector:          entry.Name,
		ConnectorAccountID: entry.AccountID,
		ConnectorAccount:   entry.AccountName,
		Person: VerifiedSubject{
			UserID: answer.uid, IDKind: useridentity.KindPOSIXUID, UserName: answer.name,
			Directory: facts, Source: subjectSourceTrustedConnector,
		},
	}, actingForRefusal{}
}
