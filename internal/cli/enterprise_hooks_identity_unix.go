//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Identity spool (standalone profile, Linux and macOS). After a reconcile
// the guardian resolves the privileged directory facts of every enrolled
// account (enterprisehooks.WriteIdentitySpool) in the background, when the
// enrolled accounts changed or the refresh interval elapsed, so the gateway
// can report a verified UPN its sandbox cannot read itself.

// Successful passes refresh before the gateway's identity cache expires.
// Failed passes retry on the guardian's next one-minute reconcile tick.
const enterpriseHookIdentitySpoolInterval = 15 * time.Minute
const enterpriseHookIdentitySpoolRetryInterval = time.Minute

// enterpriseHookLoadIdentityAccounts is replaceable in tests (the record is
// root-only).
var enterpriseHookLoadIdentityAccounts = enterprisehooks.LoadUnixIdentityAccounts

var enterpriseHookIdentitySpoolState struct {
	sync.Mutex
	running     bool
	last        time.Time
	fingerprint string
	failed      bool
}

// The directory's return after an outage (enterprisehooks.DirectoryCachesStale):
// while the system's directory caches list enrolled Active Directory
// accounts without their domain groups, the guardian asks every
// enterpriseHookDirectoryReturnPoll whether a domain controller of each of
// those accounts' domains answers, and flushes the caches when one does, so
// the accounts get their groups at the gateway's next lookup (#1197). Each
// domain is asked and backed off on its own: a domain still away does not
// hold up one that is back, and one domain's flush does not delay another's.
// A flush that did not clear a domain's accounts is repeated for it after
// enterpriseHookDirectoryFlushGap, doubling to
// enterpriseHookDirectoryFlushGapMax. A watch ends once the caches list the
// groups again, or after enterpriseHookDirectoryWatchLimit; the next
// reconcile tick starts another with the accounts enrolled then.
const (
	enterpriseHookDirectoryReturnPoll  = 15 * time.Second
	enterpriseHookDirectoryFlushGap    = 2 * time.Minute
	enterpriseHookDirectoryFlushGapMax = 15 * time.Minute
	enterpriseHookDirectoryWatchLimit  = 10 * time.Minute
)

// enterpriseHookDirectoryReturnDeps are the watch's lookups, flush and
// clock; tests replace them.
type enterpriseHookDirectoryReturnDeps struct {
	stale   func(dir string, accounts []enterprisehooks.IdentitySpoolAccount) []string
	answers func(ctx context.Context, domain string) bool
	flush   func(ctx context.Context) error
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) bool
	// domains lists the enrolled accounts' Active Directory domains, and
	// mark writes the ones whose domain controllers stopped answering
	// (enterpriseHookWatchDirectoryReach).
	domains func(dir string, accounts []enterprisehooks.IdentitySpoolAccount) []string
	mark    func(dir string, domains []string) error
	// awayUnseen counts a domain that does not answer as away even when it
	// never answered since the guardian started: SSSD reports its own
	// offline state (enterprisehooks.DirectoryAwayWithoutAnswer).
	awayUnseen bool
}

var enterpriseHookDirectoryReturn = enterpriseHookDirectoryReturnDeps{
	stale:   enterprisehooks.DirectoryCachesStale,
	answers: enterprisehooks.DirectoryAnswers,
	flush:   enterprisehooks.FlushDirectoryCaches,
	domains: enterprisehooks.DirectoryDomains,
	mark: func(dir string, domains []string) error {
		return enterprisehooks.WriteDirectoryUnreachable(dir, domains, time.Now(), enterpriseHookAuthorizationOwnershipSetter)
	},
	awayUnseen: enterprisehooks.DirectoryAwayWithoutAnswer,
	now:        time.Now,
	sleep: func(ctx context.Context, d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	},
}

var enterpriseHookDirectoryReturnState struct {
	sync.Mutex
	watching bool
	// flushed holds, for each domain whose return flushed the caches while
	// they still listed one of its accounts without its groups, when it did
	// and the gap before its next flush. A domain is dropped once none of
	// its accounts is listed so.
	flushed map[string]enterpriseHookDirectoryFlush
}

// enterpriseHookDirectoryReachState is the domain controller check's
// (enterpriseHookWatchDirectoryReach): the domains whose domain controllers
// answered at least once since the guardian started (seen), those that
// stopped answering after that (away), and whether the guardian last wrote
// a non-empty list (marked).
var enterpriseHookDirectoryReachState struct {
	sync.Mutex
	watching bool
	seen     map[string]bool
	away     map[string]bool
	marked   bool
}

// enterpriseHookDirectoryFlush is one domain's flush backoff.
type enterpriseHookDirectoryFlush struct {
	at  time.Time
	gap time.Duration
}

// enterpriseHookIdentitySpoolAccounts lists the accounts a pass resolves
// identity facts for, the keys that tell whether they changed, and the check
// the pass applies to every record of an account it does not list
// (enterprisehooks.WriteIdentitySpool's withdraw).
//
// An identity fact that is not proven never withdraws a record: a record
// goes at once only for an account the settings leave out (exclude_users,
// or out of the manifest) whose hook calls the gateway no longer accepts in
// any way (caller), and, for a name entry, only when the account its uid
// holds now is shown to be the excluded one (enterpriseHookLeftOutAccounts
// withdraws). A hook call the gateway accepts keeps the profile its UPN
// selects until the gateway stops accepting it, and a reused uid never
// loses its new owner's record to an answer about another account.
func enterpriseHookIdentitySpoolAccounts(ctx context.Context, stderr io.Writer, dir string,
	run enterpriseHookReconcileRun) ([]enterprisehooks.IdentitySpoolAccount, []string, enterprisehooks.IdentitySpoolWithdraw) {
	accounts := []enterprisehooks.IdentitySpoolAccount{}
	keys := []string{}
	seen := map[int]bool{}
	var leftUIDs []int
	// The current exclude_users apply before any row or eligible account:
	// the manifest and eligible-accounts.json the enumerator wrote can be
	// older than them (a later write failed).
	leftOut := enterpriseHookEnrollmentLeftOut(ctx, dir)
	accepted := enterpriseHookAcceptedHookCallers(stderr)
	// caller reports whether the gateway still accepts hook calls from the
	// account: a target the guardian authorization accepts, a
	// machine-policy connector that inspects every account, or
	// exempt_users, which the gateway authorizes without enrollment and
	// inspects under the account's own profile. Such an account keeps a
	// refreshed record.
	caller := func(uid int, names ...string) bool {
		return accepted.has(uid, names...) || leftOut.exempts(uid, names...)
	}
	left := map[int]bool{}
	leave := func(uid int) {
		if !left[uid] {
			left[uid] = true
			leftUIDs = append(leftUIDs, uid)
		}
	}
	// Manifest names may be NSS aliases. Only a name resolved by UID can
	// distinguish a reassigned UID from an alias of the same account in the
	// spool; an unavailable lookup leaves the name empty and preserves the
	// prior record while the gateway validates it independently.
	canonicalUser := func(uid int) string {
		account, err := enterprisehooks.StandaloneResolver().LookupUID(uid)
		if err == nil && account.UID == uid {
			return account.Name
		}
		return ""
	}
	// A key names the account's home inode where the enumerator gives one:
	// an account deleted and created again under the same name and uid gets
	// another home, and its record, whose home proof tells the gateway it is
	// another account (GAP-0422), is rewritten at the next tick instead of
	// after the interval.
	list := func(uid int, user string, homeInode uint64) {
		seen[uid] = true
		accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: uid, User: user})
		key := strconv.Itoa(uid) + ":" + user
		if homeInode != 0 {
			key += ":" + strconv.FormatUint(homeInode, 10)
		}
		keys = append(keys, key)
	}
	for _, row := range run.Rows {
		// A pending row with a resolved uid (its home is not available, or
		// was recreated) stays enrolled: its record keeps being refreshed,
		// since a pass removes the records of the accounts it does not list
		// (GAP-1113).
		if row.UID <= 0 || seen[row.UID] || left[row.UID] {
			continue
		}
		// The manifest's spelling is not proof of the UID's current name.
		// macOS directory collection also needs this canonical name.
		user := canonicalUser(row.UID)
		if !caller(row.UID, row.User, user) && leftOut.withdraws(row.UID, row.User, user) {
			leave(row.UID)
			continue
		}
		list(row.UID, user, row.HomeInode)
	}
	// Eligible accounts without rows, and accounts whose home is untrusted,
	// keep their identity record too: a standard user who makes his home
	// group-writable must not drop the profile assigned to his UPN to the
	// default (GAP-0714).
	if strings.TrimSpace(run.Manifest) != "" {
		extra, err := enterpriseHookLoadIdentityAccounts(enterprisehooks.UnixEligibleAccountsPath(run.Manifest))
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: eligible accounts: %v\n", err)
		}
		if enterpriseHookManifestEnrollment() {
			// An account the manifest leaves out loses its record at once
			// only when the gateway no longer accepts its hook calls; one it
			// still accepts keeps a refreshed record.
			enrolled := enterprisehooks.ManifestEnrolledAccounts(extra, enterprisehooks.Manifest{Targets: run.Targets})
			kept := slices.Clone(enrolled)
			for _, account := range extra {
				if slices.ContainsFunc(enrolled, func(e enterprisehooks.UnixEligibleAccount) bool { return e.UID == account.UID }) {
					continue
				}
				if caller(account.UID, account.User) {
					kept = append(kept, account)
				} else {
					leftUIDs = append(leftUIDs, account.UID)
				}
			}
			extra = kept
		}
		for _, account := range extra {
			if account.UID <= 0 || seen[account.UID] || left[account.UID] {
				continue
			}
			user := canonicalUser(account.UID)
			if !caller(account.UID, account.User, user) && leftOut.withdraws(account.UID, account.User, user) {
				leave(account.UID)
				continue
			}
			list(account.UID, user, account.HomeInode)
		}
	}
	// An account the guardian authorization still accepts hook calls from
	// keeps a refreshed record, also when this run's rows do not name it (the
	// reconcile could not rewrite the authorization).
	for _, uid := range accepted.listedUIDs() {
		if !seen[uid] {
			list(uid, canonicalUser(uid), 0)
		}
	}
	// A machine-policy connector under inspect accepts every account, and an
	// unreadable authorization may still accept any account. Neither state
	// names its callers in listedUIDs. Refresh the records they already hold
	// so a UPN assignment does not disappear at the record's one-hour limit
	// while the gateway continues to inspect that caller (T7-07).
	if accepted.everyone || accepted.unknown {
		for _, uid := range enterpriseHookRecordedCallerUIDs(dir) {
			if !seen[uid] {
				list(uid, canonicalUser(uid), 0)
			}
		}
	}
	// A caller the gateway accepts by name only (an exempt_users entry, or
	// a protected target without a uid) keeps a refreshed record too, by the
	// uid its name holds now, or, while its lookup does not answer, by the
	// uid of the record that names it: a record a pass does not list ages
	// out after an hour, and the gateway then lost the profile its UPN
	// selects while it still accepted the caller (GAP-0399, GAP-0442). An
	// exclude_users entry leaves out the account's enrollment, not the
	// gateway's acceptance of its hooks: an accepted caller keeps its
	// record, as every other accepted caller does.
	for _, uid := range enterpriseHookNameCallerUIDs(ctx, dir, leftOut, accepted) {
		if seen[uid] || left[uid] {
			continue
		}
		user := canonicalUser(uid)
		if !caller(uid, user) && leftOut.withdraws(uid, user) {
			leave(uid)
			continue
		}
		list(uid, user, 0)
	}
	// The accounts the enrollment settings leave out (excluded, out of the
	// manifest) lose their record at once. A directory account the pass
	// merely does not list keeps it until the directory shows that it left,
	// since a listing can be partial (GAP-1113, GAP-1236).
	for _, uid := range leftOut.excludedNumeric {
		if !seen[uid] && !caller(uid) {
			leave(uid)
		}
	}
	for _, uid := range leftUIDs {
		if uid > 0 && !seen[uid] {
			seen[uid] = true
			accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: uid, Left: true})
			// A newly left account changes the keys, so its record goes at
			// the next tick, also when no listing named it before (a
			// partial listing omitted it) and the enrolled keys stay the
			// same.
			keys = append(keys, "left:"+strconv.Itoa(uid))
		}
	}
	// The pass checks every record it does not list against the settings
	// (a record a partial listing omitted carries its account's name), so a
	// change of exclude_users starts a pass at the next tick.
	for _, entry := range leftOut.excludedEntries() {
		keys = append(keys, "exclude:"+entry)
	}
	withdraw := func(uid int, record enterprisehooks.IdentitySpoolRecord) bool {
		return uid > 0 && !seen[uid] && !caller(uid, record.User) && leftOut.withdraws(uid, record.User)
	}
	return accounts, keys, withdraw
}

// enterpriseHookAcceptedAccounts are the accounts whose hook calls the
// gateway accepts by the guardian authorization and the runtime descriptor
// it reads: those holding a protected target, by uid or, for a target
// without one, by name. everyone marks a machine-policy connector while
// enrollment.unenrolled_users is not deny: the gateway then accepts and
// inspects that connector's hook calls from every account, enrolled or not
// (managedHookAuthorizer.decide). unknown marks an authorization or a
// descriptor that could not be read. Either way every account is taken as
// accepted, so no record is withdrawn. Existing records are listed for
// refresh even when the authorization names no individual caller.
type enterpriseHookAcceptedAccounts struct {
	unknown  bool
	everyone bool
	uids     map[int]bool
	names    map[string]bool
}

// enterpriseHookLoadAcceptedTargets reads the protected targets of the
// guardian authorization; tests replace it.
var enterpriseHookLoadAcceptedTargets = func() ([]enterpriseHookReconcileRow, error) {
	if cfg == nil {
		return nil, nil
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	return authorization.ProtectedTargets, err
}

// enterpriseHookLoadMachinePolicyConnectors reads the machine-policy
// connectors of the runtime descriptor the gateway reads; none without a
// descriptor. Tests replace it.
var enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) {
	return enterpriseHooksEnumerateMachinePolicyConnectors("")
}

func enterpriseHookAcceptedHookCallers(stderr io.Writer) enterpriseHookAcceptedAccounts {
	accepted := enterpriseHookAcceptedAccounts{uids: map[int]bool{}, names: map[string]bool{}}
	if cfg != nil && !strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) {
		connectors, err := enterpriseHookLoadMachinePolicyConnectors()
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v; no identity record is withdrawn until it reads\n", err)
			accepted.unknown = true
			return accepted
		}
		if len(connectors) > 0 {
			accepted.everyone = true
			return accepted
		}
	}
	targets, err := enterpriseHookLoadAcceptedTargets()
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v; no identity record is withdrawn until it reads\n", err)
		accepted.unknown = true
		return accepted
	}
	for _, target := range targets {
		// The gateway accepts only a target whose protection succeeded.
		if !target.OK {
			continue
		}
		if target.UID > 0 {
			accepted.uids[target.UID] = true
		} else if user := strings.TrimSpace(target.User); user != "" {
			accepted.names[user] = true
		}
	}
	return accepted
}

// has reports whether the authorization accepts hook calls from the account
// with uid, or from one of names, the spellings it is known by.
func (a enterpriseHookAcceptedAccounts) has(uid int, names ...string) bool {
	if a.unknown || a.everyone || a.uids[uid] {
		return true
	}
	return slices.ContainsFunc(names, func(name string) bool {
		name = strings.TrimSpace(name)
		return name != "" && a.names[name]
	})
}

// enterpriseHookNameCallerUIDs lists, in order, the uids of the callers the
// gateway accepts by name only: exempt_users entries (a uid entry as
// written) and protected targets without a uid. A name resolves through a
// bounded lookup (enterprisehooks.LookupStandaloneUserBounded), and every
// name also keeps the uid of each identity record that spells it by its
// verified facts (enterpriseHookRecordSpells), while no other account holds
// that uid now. The account database often has no entry for the spellings
// the gateway matches an exemption by (a UPN, a principal, DOMAIN\name, a
// bare name where SSSD names accounts fully qualified), and SSSD answers
// not found while its backend is offline. Comparing only the record's
// account name, and skipping the records after a not-found answer, left
// such a caller's record unrefreshed: it aged out after an hour while the
// gateway still exempted the caller, which then lost the profile its UPN
// selects (GAP-0881). One name can exempt two accounts: a bare alice
// exempts the local alice by name and the directory account
// alice@corp.example by its facts (managedHookAuthorizer.exempt). The
// records were read only when the lookup failed, so a local namesake the
// lookup found left the directory account's record to age out (GAP-0937).
// Every record is read, one at a time: the scan stopped after 4,096 records,
// and a caller whose record sorted later lost it (GAP-0964).
func enterpriseHookNameCallerUIDs(ctx context.Context, dir string, leftOut *enterpriseHookLeftOutAccounts,
	accepted enterpriseHookAcceptedAccounts) []int {
	var names []string
	var uids []int
	for uid := range leftOut.exemptUIDs {
		uids = append(uids, uid)
	}
	for entry := range leftOut.exempt {
		if _, err := strconv.Atoi(entry); err != nil {
			names = append(names, entry)
		}
	}
	for name := range accepted.names {
		names = append(names, name)
	}
	if len(names) > 0 {
		if ctx == nil {
			ctx = context.Background()
		}
		waitCtx, cancel := context.WithTimeout(ctx, enterpriseHookLeftOutLookupWait)
		defer cancel()
		for _, name := range names {
			if account, err := enterprisehooks.LookupStandaloneUserBounded(waitCtx, name); err == nil && account.UID > 0 {
				uids = append(uids, account.UID)
			}
		}
		enterprisehooks.WalkIdentitySpoolRecords(dir, nil, func(record enterprisehooks.IdentitySpoolRecord) bool {
			uid, err := strconv.Atoi(record.Key)
			if err != nil || uid <= 0 || !slices.ContainsFunc(names, func(name string) bool { return enterpriseHookRecordSpells(record, name) }) {
				return true
			}
			// The record is the account's last proven identity; the uid is
			// refreshed only while the account database does not give it to
			// another account (a reused uid is its new owner's to scan).
			if holder := leftOut.accountAt(uid); !holder.answered || holder.name == strings.TrimSpace(record.User) {
				uids = append(uids, uid)
			}
			return true
		})
	}
	slices.Sort(uids)
	return slices.Compact(uids)
}

// enterpriseHookRecordSpells reports whether name spells the account of
// record by the facts the guardian verified for it, the spellings the
// gateway's exempt_users matcher accepts for the account
// (managedHookAuthorizer.exempt, userEntryMatches): its account name, its
// UPN or principal, DOMAIN\name with a domain its facts give it (the
// record's NetBIOS account domain, its DNS domain or SSSD domain, or .\ for
// a local account), and, for a directory account, its name without the
// domain. Names compare without regard to case.
func enterpriseHookRecordSpells(record enterprisehooks.IdentitySpoolRecord, name string) bool {
	name, user := strings.TrimSpace(name), strings.TrimSpace(record.User)
	if name == "" || user == "" {
		return false
	}
	if useridentity.EqualFold(name, user) || useridentity.PrincipalsEqual(name, record.Facts.UPN) ||
		useridentity.PrincipalsEqual(name, record.Facts.Principal) {
		return true
	}
	bare := useridentity.BareAccountName(user)
	if domain, account, qualified := strings.Cut(name, `\`); qualified {
		if strings.TrimSpace(domain) == "." {
			// .\name, the Windows form for an account of this computer,
			// names a local account (subjectInDomain).
			return account != "" && record.AccountIncarnation == "files" && useridentity.EqualFold(account, bare)
		}
		return account != "" && useridentity.EqualFold(account, bare) && slices.ContainsFunc(
			[]string{record.AccountDomain, record.Facts.Domain, record.SSSDDomain}, func(own string) bool {
				own = strings.TrimSpace(own)
				return own != "" && useridentity.EqualFold(own, domain)
			})
	}
	return !strings.Contains(name, "@") && record.AccountIncarnation != "files" && useridentity.EqualFold(name, bare)
}

// listedUIDs lists the uids the authorization names, in order.
func (a enterpriseHookAcceptedAccounts) listedUIDs() []int {
	uids := make([]int, 0, len(a.uids))
	for uid := range a.uids {
		if uid > 0 {
			uids = append(uids, uid)
		}
	}
	slices.Sort(uids)
	return uids
}

// enterpriseHookRecordedCallerUIDs lists every existing uid record when the
// authorization accepts callers without listing their uids. It reads names
// only; WriteIdentitySpool resolves the uid again before publishing facts.
func enterpriseHookRecordedCallerUIDs(dir string) []int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	uids := make([]int, 0, len(entries))
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !entry.Type().IsRegular() {
			continue
		}
		uid, err := strconv.Atoi(key)
		if err != nil || uid <= 0 || strconv.Itoa(uid) != key {
			continue
		}
		if _, err := enterprisehooks.ReadIdentitySpoolRecord(dir, key, nil); err == nil {
			uids = append(uids, uid)
		}
	}
	return uids
}

// enterpriseHookLeftOutAccounts is what enterprise.enrollment.exclude_users
// and exempt_users name, matched as the enumerator matches them: an account
// name or its decimal uid. A name is also resolved to its uid, so another
// spelling of the account matches too.
//
// A name entry's answer (this call's, or its last one while it does not
// answer) binds to the account it named, never to the bare uid: a directory
// cache can still give a name the uid of an account that has left, after
// the uid went to another account. Only a uid entry binds to the uid.
//
// has is the strict reading the scans use: a match by uid entry, by a
// spelling, or by a name's answer for the uid while the uid is not shown to
// hold another account, leaves the account out. withdraws is the reading
// that removes an identity record: exclude_users only, and a name entry
// counts only when the account its uid holds now is the excluded one.
//
// The names are resolved only when an account is not already decided by its
// uid or one of its spellings, so a host with no such account asks the
// directory nothing. The lookups end with the reconcile context and after
// enterpriseHookLeftOutLookupWait, and a name or uid whose earlier lookup
// has not returned (an Open Directory call that never answers) starts no
// new one (enterprisehooks.LookupStandaloneUserBounded): a stalled lookup
// never holds the guardian's watch loop. A name whose lookup does not answer
// this pass keeps its last answer (enterpriseHookLeftOutProven); a not-found
// answer forgets it.
type enterpriseHookLeftOutAccounts struct {
	ctx context.Context
	// dir is the identity spool: the record of a uid names the account, and
	// its SID where SSSD holds one, that the uid held at the last pass.
	dir string
	// excluded and exempt hold the entries as written.
	excluded, exempt map[string]bool
	// excludedNumeric lists the exclude_users entries written as a uid.
	excludedNumeric []int
	// excludedUIDs and exemptUIDs hold the uids the entries written as a
	// uid name.
	excludedUIDs, exemptUIDs map[int]bool
	// proofs holds, per uid, the answers of the name entries: this call's,
	// or the last one of a name that did not answer in this call.
	proofs map[int][]enterpriseHookLeftOutProof
	// unresolved lists the name entries resolve has not looked up yet.
	unresolved []string
	resolved   bool
	// holders memoizes accountAt.
	holders map[int]enterpriseHookLeftOutHolder
}

// enterpriseHookLeftOutProof is the last answer a name entry got: the uid,
// the account name and, when the identity spool held one for that account,
// its SID.
type enterpriseHookLeftOutProof struct {
	entry string
	uid   int
	name  string
	sid   string
}

// enterpriseHookLeftOutHolder is the account a uid holds now, as far as one
// call knows: the account database's answer, or, when it does not answer,
// the uid's identity record. An empty name means neither says.
type enterpriseHookLeftOutHolder struct {
	name     string
	sid      string
	answered bool
}

// enterpriseHookLeftOutLookupWait bounds the lookups of one call.
var enterpriseHookLeftOutLookupWait = 3 * time.Second

// enterpriseHookLeftOutProven holds the last answer of each exclude_users or
// exempt_users name, by lower-case name.
var enterpriseHookLeftOutProven = struct {
	sync.Mutex
	proofs map[string]enterpriseHookLeftOutProof
}{proofs: map[string]enterpriseHookLeftOutProof{}}

// enterpriseHookEnrollmentLeftOut reads the current settings' exclude_users
// and exempt_users; their names are resolved on demand. dir is the identity
// spool.
func enterpriseHookEnrollmentLeftOut(ctx context.Context, dir string) *enterpriseHookLeftOutAccounts {
	out := &enterpriseHookLeftOutAccounts{
		ctx: ctx, dir: dir,
		excluded: map[string]bool{}, exempt: map[string]bool{},
		excludedUIDs: map[int]bool{}, exemptUIDs: map[int]bool{},
		proofs: map[int][]enterpriseHookLeftOutProof{}, holders: map[int]enterpriseHookLeftOutHolder{},
	}
	if cfg == nil {
		return out
	}
	add := func(entries []string, names map[string]bool, uids map[int]bool, numeric *[]int) {
		for _, entry := range entries {
			if entry = strings.TrimSpace(entry); entry == "" {
				continue
			}
			names[entry] = true
			if uid, err := strconv.Atoi(entry); err == nil {
				if uid > 0 && !uids[uid] {
					uids[uid] = true
					if numeric != nil {
						*numeric = append(*numeric, uid)
					}
				}
			} else if !slices.Contains(out.unresolved, entry) {
				out.unresolved = append(out.unresolved, entry)
			}
		}
	}
	add(cfg.Enterprise.Enrollment.ExcludeUsers, out.excluded, out.excludedUIDs, &out.excludedNumeric)
	add(cfg.Enterprise.Enrollment.ExemptUsers, out.exempt, out.exemptUIDs, nil)
	return out
}

// excludedEntries lists the exclude_users entries, in order.
func (l *enterpriseHookLeftOutAccounts) excludedEntries() []string {
	entries := make([]string, 0, len(l.excluded))
	for entry := range l.excluded {
		entries = append(entries, entry)
	}
	slices.Sort(entries)
	return entries
}

// has reports whether the settings leave out the account with uid, by uid
// or by one of names (its spelling in a row, an eligible account or an
// identity record, its name by uid), strictly: an entry the account matches
// keeps it out of the scans, proven or not. It resolves the names the first
// time they are needed.
//
// A name's answer, this call's or its last one, is not a match but a fact
// about the account it named: it keeps the uid out until the account the
// uid holds now (the account database's answer, or else the uid's identity
// record) is shown to be another one, which neither entry names. A uid the
// directory gave to another account since then is that account's to scan,
// also while a cache still answers the name with the uid.
func (l *enterpriseHookLeftOutAccounts) has(uid int, names ...string) bool {
	if l.excludedUIDs[uid] || l.exemptUIDs[uid] {
		return true
	}
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" && (l.excluded[name] || l.exempt[name]) {
			return true
		}
	}
	if !l.resolved {
		l.resolve()
	}
	for _, proof := range l.proofs[uid] {
		holder := l.accountAt(uid)
		if !l.otherHolder(holder, proof) || l.excluded[holder.name] || l.exempt[holder.name] {
			return true
		}
		if holder.answered && holder.name != proof.name {
			l.forget(proof)
		}
	}
	return false
}

// otherHolder reports whether holder, the account a uid holds now, is shown
// to be another account than the one proof named: another name, or the same
// name with another SID where both are known. An unknown holder is not.
func (l *enterpriseHookLeftOutAccounts) otherHolder(holder enterpriseHookLeftOutHolder, proof enterpriseHookLeftOutProof) bool {
	if holder.name == "" {
		return false
	}
	return holder.name != proof.name || (proof.sid != "" && holder.sid != "" && !strings.EqualFold(proof.sid, holder.sid))
}

// withdraws reports whether exclude_users takes the identity record of the
// account with uid, known by names. A uid entry does. A spelling the
// account is listed by does unless the account the uid holds now is another
// one. A name's answer, this call's or its last one, does only when the
// account the uid holds now is the one that answer named, with the same SID
// where both are known: a uid the directory gave to another account since
// then keeps its new owner's record.
func (l *enterpriseHookLeftOutAccounts) withdraws(uid int, names ...string) bool {
	if uid <= 0 {
		return false
	}
	if l.excludedUIDs[uid] {
		return true
	}
	if slices.ContainsFunc(names, func(name string) bool {
		name = strings.TrimSpace(name)
		return name != "" && l.excluded[name]
	}) {
		if holder := l.accountAt(uid); holder.name == "" || l.excluded[holder.name] {
			return true
		}
	}
	if !l.resolved {
		l.resolve()
	}
	for _, proof := range l.proofs[uid] {
		if !l.excluded[proof.entry] {
			continue
		}
		holder := l.accountAt(uid)
		if holder.name != "" && (holder.name == proof.name || l.excluded[holder.name]) &&
			(proof.sid == "" || holder.sid == "" || strings.EqualFold(proof.sid, holder.sid)) {
			return true
		}
		if holder.answered && holder.name != proof.name {
			// The account database gives the uid to another account: the
			// last answer no longer holds.
			l.forget(proof)
		}
	}
	return false
}

// exempts reports whether exempt_users may name the account with uid,
// known by names: the gateway authorizes an exempt caller's hook calls
// without enrollment and inspects them under its own profile, so its
// identity record stays. It is generous on purpose, as it only keeps a
// record: the gateway also matches an entry against the account's directory
// facts (managedHookAuthorizer.exempt), which the guardian reads from the
// uid's identity record, so an entry matches a uid entry, any name the
// account is known by, the record's account name, UPN or principal, or the
// account part of any of them (the domain part ignored), and a name's
// answer the uid's holder does not contradict.
func (l *enterpriseHookLeftOutAccounts) exempts(uid int, names ...string) bool {
	if len(l.exempt) == 0 || uid <= 0 {
		return false
	}
	if l.exemptUIDs[uid] {
		return true
	}
	if record, err := enterprisehooks.ReadIdentitySpoolRecord(l.dir, strconv.Itoa(uid), nil); err == nil {
		names = append(slices.Clone(names), record.User, record.Facts.UPN, record.Facts.Principal)
	}
	for _, name := range names {
		for entry := range l.exempt {
			if enterpriseHookEntryMayName(entry, name) {
				return true
			}
		}
	}
	if !l.resolved {
		l.resolve()
	}
	for _, proof := range l.proofs[uid] {
		if l.exempt[proof.entry] && !l.otherHolder(l.accountAt(uid), proof) {
			return true
		}
	}
	return false
}

// enterpriseHookEntryMayName reports whether an enrollment entry may name
// the account known as name: the same name, or the same account part, the
// DOMAIN\ prefix and @domain suffix ignored, compared without regard to case.
func enterpriseHookEntryMayName(entry, name string) bool {
	entry, name = strings.TrimSpace(entry), strings.TrimSpace(name)
	if entry == "" || name == "" {
		return false
	}
	return strings.EqualFold(entry, name) ||
		strings.EqualFold(enterpriseHookAccountPart(entry), enterpriseHookAccountPart(name))
}

// enterpriseHookAccountPart is name without a DOMAIN\ prefix or an @domain
// suffix.
func enterpriseHookAccountPart(name string) string {
	if _, account, ok := strings.Cut(name, `\`); ok {
		name = account
	}
	if account, _, ok := strings.Cut(name, "@"); ok {
		name = account
	}
	return name
}

// accountAt reports the account uid holds now (enterpriseHookLeftOutHolder).
// The uid lookup is bounded as the name lookups are. A not-found answer is
// not taken as an answer: SSSD gives it for a directory account while its
// backend is down.
func (l *enterpriseHookLeftOutAccounts) accountAt(uid int) enterpriseHookLeftOutHolder {
	if holder, ok := l.holders[uid]; ok {
		return holder
	}
	record, recordErr := enterprisehooks.ReadIdentitySpoolRecord(l.dir, strconv.Itoa(uid), nil)
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(ctx, enterpriseHookLeftOutLookupWait)
	account, err := enterprisehooks.LookupStandaloneUIDBounded(waitCtx, uid)
	cancel()
	var holder enterpriseHookLeftOutHolder
	switch {
	case err == nil && account.UID == uid && account.Name != "":
		holder = enterpriseHookLeftOutHolder{name: account.Name, answered: true}
		if recordErr == nil && record.User == account.Name {
			holder.sid = record.AccountSID
		}
	case recordErr == nil && strings.TrimSpace(record.User) != "":
		holder = enterpriseHookLeftOutHolder{name: record.User, sid: record.AccountSID}
	}
	l.holders[uid] = holder
	return holder
}

// recordSID is the SID the identity record of uid holds for the account
// named name, or "".
func (l *enterpriseHookLeftOutAccounts) recordSID(uid int, name string) string {
	record, err := enterprisehooks.ReadIdentitySpoolRecord(l.dir, strconv.Itoa(uid), nil)
	if err != nil || record.User != name {
		return ""
	}
	return record.AccountSID
}

// forget drops a last answer the account database has since contradicted.
func (l *enterpriseHookLeftOutAccounts) forget(proof enterpriseHookLeftOutProof) {
	proven := &enterpriseHookLeftOutProven
	proven.Lock()
	defer proven.Unlock()
	key := strings.ToLower(proof.entry)
	if got, ok := proven.proofs[key]; ok && got.uid == proof.uid && got.name == proof.name {
		delete(proven.proofs, key)
	}
}

// resolve looks the name entries up at once, each at most until the call's
// wait ends.
func (l *enterpriseHookLeftOutAccounts) resolve() {
	l.resolved = true
	if len(l.unresolved) == 0 {
		return
	}
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(ctx, enterpriseHookLeftOutLookupWait)
	defer cancel()
	type answer struct {
		uid   int
		name  string
		found bool
		known bool
	}
	answers := make([]answer, len(l.unresolved))
	var wg sync.WaitGroup
	for i, name := range l.unresolved {
		wg.Add(1)
		go func() {
			defer wg.Done()
			account, err := enterprisehooks.LookupStandaloneUserBounded(waitCtx, name)
			switch {
			case err == nil && account.UID > 0:
				answers[i] = answer{uid: account.UID, name: account.Name, found: true, known: true}
			case unixidentity.IsNotFound(err):
				answers[i] = answer{known: true}
			}
		}()
	}
	wg.Wait()
	// An answer names an account, not just a uid: has and withdraws check it
	// against the account the uid holds now.
	proofs := make([]enterpriseHookLeftOutProof, len(l.unresolved))
	for i, name := range l.unresolved {
		if got := answers[i]; got.found {
			proofs[i] = enterpriseHookLeftOutProof{entry: name, uid: got.uid, name: got.name, sid: l.recordSID(got.uid, got.name)}
		}
	}
	proven := &enterpriseHookLeftOutProven
	proven.Lock()
	defer proven.Unlock()
	for i, name := range l.unresolved {
		key := strings.ToLower(name)
		switch got := answers[i]; {
		case got.found:
			proof := proofs[i]
			if prior, ok := proven.proofs[key]; ok && proof.sid == "" && prior.uid == proof.uid && prior.name == proof.name {
				proof.sid = prior.sid
			}
			proven.proofs[key] = proof
			l.proofs[proof.uid] = append(l.proofs[proof.uid], proof)
		case got.known:
			delete(proven.proofs, key)
		default:
			if proof, ok := proven.proofs[key]; ok && proof.uid > 0 {
				proof.entry = name
				l.proofs[proof.uid] = append(l.proofs[proof.uid], proof)
			}
		}
	}
	l.unresolved = nil
}

// enterpriseHookIdentitySpoolDirForConfig is the identity spool of the
// current settings.
func enterpriseHookIdentitySpoolDirForConfig() string {
	if cfg == nil {
		return ""
	}
	return enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
}

func startEnterpriseHookIdentitySpool(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	dir := enterpriseHookIdentitySpoolDirForConfig()
	if dir == "" {
		return
	}
	// The guardian follows a pushed config's trusted child domains, as the
	// gateway does on reload (GAP-1255).
	useridentity.SetTrustedADChildDomains(cfg.AIDiscovery.TrustedADChildDomains)
	accounts, keys, withdraw := enterpriseHookIdentitySpoolAccounts(ctx, stderr, dir, run)
	enrolled := slices.DeleteFunc(slices.Clone(accounts), func(a enterprisehooks.IdentitySpoolAccount) bool { return a.Left })
	startEnterpriseHookDirectoryReturnWatch(ctx, stderr, dir, enrolled)
	startEnterpriseHookDirectoryReachWatch(ctx, stderr, dir, enrolled)
	sort.Strings(keys)
	fingerprint := strings.Join(keys, ";")
	now := time.Now()
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	interval := enterpriseHookIdentitySpoolInterval
	if state.failed {
		interval = enterpriseHookIdentitySpoolRetryInterval
	}
	// The interval runs on the monotonic clock, but the gateway trusts a
	// record by its wall-clock age: after a clock step the records are
	// rewritten at the next one-minute tick (GAP-0921).
	_, _, stepped := enterprisehooks.IdentitySpoolStale(dir, now, enterpriseHookIdentitySpoolInterval+2*enterpriseHookIdentitySpoolRetryInterval)
	due := !state.running && (fingerprint != state.fingerprint || now.Sub(state.last) >= interval || stepped)
	if due {
		state.running = true
	}
	state.Unlock()
	if !due {
		return
	}
	go func() {
		var passErr error
		defer func() {
			state.Lock()
			state.running = false
			state.last = time.Now()
			state.fingerprint = fingerprint
			state.failed = passErr != nil
			state.Unlock()
		}()
		if err := ensureEnterpriseHookStandaloneAuthDir(managed.HookGuardianAuthorizationDir(cfg.DataDir)); err != nil {
			passErr = err
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", err)
			return
		}
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		passErr = enterprisehooks.WriteIdentitySpool(ctx, dir, accounts, enterpriseHookAuthorizationOwnershipSetter, logf, withdraw)
		if passErr != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", passErr)
		}
	}()
}

// startEnterpriseHookDirectoryReturnWatch starts the watch for the
// directory's return (enterpriseHookWatchDirectoryReturn) unless one runs,
// on a system whose caches keep serving outage answers (a Mac).
func startEnterpriseHookDirectoryReturnWatch(ctx context.Context, stderr io.Writer, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	if !enterprisehooks.DirectoryCachesHoldOutageAnswers {
		return
	}
	state := &enterpriseHookDirectoryReturnState
	state.Lock()
	if state.watching || len(accounts) == 0 {
		state.Unlock()
		return
	}
	state.watching = true
	state.Unlock()
	go func() {
		defer func() {
			state.Lock()
			state.watching = false
			state.Unlock()
		}()
		enterpriseHookWatchDirectoryReturn(ctx, stderr, enterpriseHookDirectoryReturn, dir, accounts)
	}()
}

// enterpriseHookWatchDirectoryReturn flushes the directory caches once the
// domain controller answers again while they still list an Active Directory
// account without its domain groups, and never while it does not answer:
// those caches are then all the Mac has. It returns once the caches list the
// groups (or never lacked them), at the watch limit, or when ctx ends.
func enterpriseHookWatchDirectoryReturn(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	state := &enterpriseHookDirectoryReturnState
	until := deps.now().Add(enterpriseHookDirectoryWatchLimit)
	for {
		domains := deps.stale(dir, accounts)
		now := deps.now()
		var due []string
		state.Lock()
		for domain := range state.flushed {
			if !slices.Contains(domains, domain) {
				delete(state.flushed, domain)
			}
		}
		for _, domain := range domains {
			if last, ok := state.flushed[domain]; !ok || now.Sub(last.at) >= last.gap {
				due = append(due, domain)
			}
		}
		state.Unlock()
		if len(domains) == 0 {
			return
		}
		if back := enterpriseHookDomainsAnswering(ctx, deps.answers, due); len(back) > 0 {
			err := deps.flush(ctx)
			at := deps.now()
			state.Lock()
			if state.flushed == nil {
				state.flushed = map[string]enterpriseHookDirectoryFlush{}
			}
			for _, domain := range back {
				gap := min(max(2*state.flushed[domain].gap, enterpriseHookDirectoryFlushGap), enterpriseHookDirectoryFlushGapMax)
				state.flushed[domain] = enterpriseHookDirectoryFlush{at: at, gap: gap}
			}
			state.Unlock()
			names := strings.Join(back, ", ")
			if err != nil {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again, but the directory caches "+
					"were not flushed: %v\n", names, err)
			} else {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again while the directory caches "+
					"still list an account without its domain groups; flushed the caches, so accounts get their groups at "+
					"their next lookup\n", names)
			}
		}
		if !deps.now().Before(until) || !deps.sleep(ctx, enterpriseHookDirectoryReturnPoll) {
			return
		}
	}
}

// enterpriseHookDomainsAnswering asks each domain at once whether one of its
// domain controllers answers (each probe is bounded on its own), so a domain
// that is away, whose probe runs to its deadline, does not delay the others,
// and returns the domains that answer, in their order.
func enterpriseHookDomainsAnswering(ctx context.Context, answers func(ctx context.Context, domain string) bool, domains []string) []string {
	ok := make([]bool, len(domains))
	var wg sync.WaitGroup
	for i, domain := range domains {
		wg.Go(func() { ok[i] = answers(ctx, domain) })
	}
	wg.Wait()
	var back []string
	for i, domain := range domains {
		if ok[i] {
			back = append(back, domain)
		}
	}
	return back
}

// startEnterpriseHookDirectoryReachWatch starts the domain controller check
// (enterpriseHookWatchDirectoryReach) unless one runs. The guardian's
// reconcile tick calls it about once a minute.
func startEnterpriseHookDirectoryReachWatch(ctx context.Context, stderr io.Writer, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	state := &enterpriseHookDirectoryReachState
	state.Lock()
	if state.watching || len(accounts) == 0 {
		state.Unlock()
		return
	}
	state.watching = true
	state.Unlock()
	go func() {
		defer func() {
			state.Lock()
			state.watching = false
			state.Unlock()
		}()
		enterpriseHookWatchDirectoryReach(ctx, stderr, enterpriseHookDirectoryReturn, dir, accounts)
	}()
}

// enterpriseHookWatchDirectoryReach checks whether a domain controller of
// each enrolled account's Active Directory domain answers (macOS), or whether
// SSSD is online for each enrolled account's SSSD domain (Linux,
// enterprisehooks.DirectoryAnswers). A domain that answered before and no
// longer does is away (on Linux also one SSSD reports offline from the
// start, deps.awayUnseen): the guardian writes the away domains to
// the identity spool (enterprisehooks.DirectoryUnreachableFile), so the
// gateway takes their accounts' lookups as failed instead of trusting the
// groups Open Directory lists then, and checks again every
// enterpriseHookDirectoryReturnPoll. Once a domain answers again, the
// directory caches are flushed: they hold the answers Open Directory or SSSD
// gave while it was away, without the accounts' other domain groups (GAP-0092,
// GAP-0095, GAP-0191). It returns once no domain is away, after one check when none
// was, or when ctx ends.
func enterpriseHookWatchDirectoryReach(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	if deps.domains == nil {
		return
	}
	state := &enterpriseHookDirectoryReachState
	for {
		domains := deps.domains(dir, accounts)
		answering := enterpriseHookDomainsAnswering(ctx, deps.answers, domains)
		if ctx.Err() != nil {
			// A check cut short says nothing about the domain controllers.
			return
		}
		var back, gone, away []string
		state.Lock()
		if state.seen == nil {
			state.seen, state.away = map[string]bool{}, map[string]bool{}
		}
		for domain := range state.away {
			if !slices.Contains(domains, domain) {
				delete(state.away, domain)
			}
		}
		for _, domain := range domains {
			switch {
			case slices.Contains(answering, domain):
				if state.away[domain] {
					back = append(back, domain)
				}
				delete(state.away, domain)
				state.seen[domain] = true
			case (state.seen[domain] || deps.awayUnseen) && !state.away[domain]:
				state.away[domain] = true
				gone = append(gone, domain)
			}
		}
		for domain := range state.away {
			away = append(away, domain)
		}
		slices.Sort(away)
		marked := state.marked
		state.Unlock()
		if len(gone) > 0 {
			fmt.Fprintf(stderr, "[hook-guardian] identity: no domain controller of %s answers; the gateway takes the lookups of "+
				"its accounts as failed until one does\n", strings.Join(gone, ", "))
		}
		if len(back) > 0 {
			enterpriseHookFlushAfterReturn(ctx, stderr, deps, back)
		}
		if deps.mark != nil && (len(away) > 0 || marked) {
			if err := deps.mark(dir, away); err != nil {
				fmt.Fprintf(stderr, "[hook-guardian] identity: record the domains whose domain controllers do not answer: %v\n", err)
			} else {
				state.Lock()
				state.marked = len(away) > 0
				state.Unlock()
			}
		}
		if len(away) == 0 || !deps.sleep(ctx, enterpriseHookDirectoryReturnPoll) {
			return
		}
	}
}

// enterpriseHookFlushAfterReturn flushes the directory caches for the
// domains whose domain controllers answer again after an outage, and starts
// their flush backoff, so the return watch (enterpriseHookWatchDirectoryReturn)
// does not flush them again at once.
func enterpriseHookFlushAfterReturn(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, back []string) {
	err := deps.flush(ctx)
	at := deps.now()
	state := &enterpriseHookDirectoryReturnState
	state.Lock()
	if state.flushed == nil {
		state.flushed = map[string]enterpriseHookDirectoryFlush{}
	}
	for _, domain := range back {
		state.flushed[domain] = enterpriseHookDirectoryFlush{at: at, gap: enterpriseHookDirectoryFlushGap}
	}
	state.Unlock()
	names := strings.Join(back, ", ")
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again after an outage, but the directory "+
			"caches were not flushed: %v\n", names, err)
		return
	}
	fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again after an outage; flushed the directory "+
		"caches, so accounts get their domain groups at their next lookup\n", names)
}
