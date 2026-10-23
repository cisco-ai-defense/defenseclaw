// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Windows the SYSTEM enumerator writes one identity record per user in
// its token-group cache: the directory facts it resolves as SYSTEM (the
// identity store, the join state, TranslateNameW) and, only while the user
// has an active desktop session, its token groups. Each SID is followed by
// its DOMAIN\name where the name resolves. The
// gateway's service account cannot read the SYSTEM-only group cache itself.

const (
	// windowsIdentityGroupNameLimit bounds the group SIDs named per user.
	windowsIdentityGroupNameLimit = 128
	// windowsIdentityGroupNameBudget bounds the time spent naming them.
	windowsIdentityGroupNameBudget = 2 * time.Second
)

// WriteWindowsIdentitySpool replaces dir's records with one per user in the
// group cache, except the users in excluded: the accounts the enrollment
// excluded this cycle publish no record, and an earlier one is removed.
// emails holds each account's connector addresses by upper-case
// SID (WindowsConnectorEmails), nil when ai_discovery.include_user_email is
// off. setOwnership applies the guardian authorization protection (SYSTEM
// and Administrators, read for the gateway service) to the directory and to
// each new file before it is renamed into place.
//
// ctx is the enumerator cycle: the pass stops at its deadline, and no
// lookup holds it past it. The lookups of an account run in the background
// (the native calls cannot be canceled) and the pass waits for them only
// until the deadline, and for one account at most windowsIdentityAccountWait;
// an answer that comes later is not used. An account whose earlier lookup
// still runs is skipped. The accounts it did not reach or refresh keep their
// previous records, with this cycle's token groups when those changed
// (IdentitySpoolTokenGroupRecord), and the next pass starts with the oldest
// records and takes the accounts whose last lookup did not answer in time
// last, so neither a slow directory nor one account it never answers for
// can keep the other accounts from being refreshed.
func WriteWindowsIdentitySpool(ctx context.Context, dir string, cache *WindowsEnrollmentGroupCache, excluded []string,
	emails map[string]map[string]string, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" || cache == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create identity spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set identity spool protection: %w", err)
		}
	}
	skip := map[string]bool{}
	for _, sid := range excluded {
		skip[strings.ToUpper(strings.TrimSpace(sid))] = true
	}
	type account struct {
		sid, key string
		previous IdentitySpoolRecord
		// previousErr is why previous could not be read: os.ErrNotExist
		// when the account has no record.
		previousErr error
		// late: the account's last lookup did not answer in time.
		late bool
	}
	keep := map[string]bool{}
	accounts := make([]account, 0, len(cache.Users))
	for sid := range cache.Users {
		key := strings.ToUpper(strings.TrimSpace(sid))
		if !validIdentitySpoolKey(key) || skip[key] || keep[strings.ToLower(key+".json")] {
			continue
		}
		keep[strings.ToLower(key+".json")] = true
		entry := account{sid: sid, key: key, late: windowsIdentityLookupGate.isLate(key)}
		entry.previous, entry.previousErr = ReadIdentitySpoolRecord(dir, key, nil)
		accounts = append(accounts, entry)
	}
	// Oldest record first (none at all before any), and the accounts whose
	// last lookup did not answer in time after all the others: a pass the
	// cycle deadline stops refreshes the accounts it reached, the next starts
	// with the rest, and a slow account cannot use up every pass.
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].late != accounts[j].late {
			return accounts[j].late
		}
		if !accounts[i].previous.UpdatedAt.Equal(accounts[j].previous.UpdatedAt) {
			return accounts[i].previous.UpdatedAt.Before(accounts[j].previous.UpdatedAt)
		}
		return accounts[i].key < accounts[j].key
	})
	lookups := windowsIdentityLookups{
		facts: windowsIdentityDirectoryFacts, groupNames: windowsIdentityGroupNames, settledName: windowsSettledAccountName,
	}
	var stopped error
	var unanswered []string
	// publish writes record for entry. A failed publication withdraws the
	// previous record only when this pass disproved it: the token groups or
	// the identity changed (GAP-0329). The gateway then stops trusting the
	// old groups at its next spool check instead of for another hour. A
	// record that still says what this pass found stays: withdrawing it
	// dropped the cached groups of a user whose strict groups had not
	// changed, so requests needing them were refused with the missing
	// group fact named. So does one the pass could not read
	// (IdentitySpoolWithdrawnByFailedWrite).
	publish := func(entry account, record IdentitySpoolRecord) {
		name := entry.key + ".json"
		err := writeIdentitySpoolFile(dir, name, record, setOwnership)
		if err == nil {
			return
		}
		if IdentitySpoolWithdrawnByFailedWrite(entry.previous, entry.previousErr, record) {
			if removeErr := os.Remove(filepath.Join(dir, name)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("withdraw previous identity record: %w", removeErr))
			}
		}
		stopped = errors.Join(stopped, fmt.Errorf("identity facts for %s: %w", entry.key, err))
		if logf != nil {
			logf("[hook-enumerator] WARN identity facts for %s: %v", entry.key, err)
		}
	}
	// publishTokenGroups publishes this cycle's token groups of an account
	// whose lookups did not answer in time, when its record names others.
	publishTokenGroups := func(entry account) {
		if record, changed := IdentitySpoolTokenGroupRecord(entry.previous, entry.previousErr, entry.key, cache.Users[entry.sid],
			cache.SignedIn[entry.sid], time.Now().UTC()); changed {
			// Only the token groups are this pass's answer.
			record = MarkWindowsKeptUPN(record, entry.previous, true)
			record.ConnectorEmails = emails[entry.key]
			publish(entry, record)
		}
	}
	for i, entry := range accounts {
		sid, key := entry.sid, entry.key
		now := time.Now().UTC()
		groupSIDs := cache.Users[sid]
		// The enrollment cache retains last-session groups for enrollment
		// decisions, but they cannot verify the membership of a new SSH or
		// task token. Publish groups only from an active session this cycle.
		signedIn := cache.SignedIn[sid]
		// One account gets at most windowsIdentityAccountWait of the cycle,
		// so an account whose directory does not answer leaves time for the
		// others.
		accountCtx, cancel := context.WithTimeout(ctx, windowsIdentityAccountWait)
		resolved, err := windowsIdentityBounded(accountCtx, key, func(ctx context.Context) windowsIdentityResolved {
			facts := lookups.facts(key, 0)
			facts.GroupsPartial = !signedIn
			if signedIn {
				names := lookups.groupNames(groupSIDs, windowsIdentityGroupNameLimit, windowsIdentityLookupBudget(ctx, windowsIdentityGroupNameBudget))
				groups := make([]string, 0, 2*len(groupSIDs))
				for i, groupSID := range groupSIDs {
					groups = append(groups, groupSID)
					if i < len(names) && names[i] != groupSID {
						groups = append(groups, names[i])
					}
				}
				facts.Groups = groups
			}
			return windowsIdentityResolved{facts: facts, user: lookups.spoolUser(ctx, key)}
		})
		cancel()
		if err != nil {
			if cycleErr := ctx.Err(); cycleErr != nil {
				stopped = errors.Join(stopped, fmt.Errorf("identity facts of %d of %d accounts were not refreshed before the enumerator "+
					"cycle ended; their previous records stay, with this cycle's token groups: %w", len(accounts)-i, len(accounts), cycleErr))
				for _, rest := range accounts[i:] {
					publishTokenGroups(rest)
				}
				break
			}
			unanswered = append(unanswered, fmt.Sprintf("%s (%v)", key, err))
			publishTokenGroups(entry)
			continue
		}
		facts := resolved.facts
		if facts.ResolvedAt.IsZero() {
			facts.ResolvedAt = now
		}
		record := IdentitySpoolRecord{Key: key, User: resolved.user, UpdatedAt: now, Facts: facts,
			ConnectorEmails: emails[key]}
		switch {
		case facts.UPN != "" && facts.Source == useridentity.SourceWindowsIdentityStore:
			record.UPNSource = UPNSourceIdentityStore
		case facts.UPN != "":
			record.UPNSource = UPNSourceTranslateName
		}
		carried := false
		if entry.previousErr == nil {
			record = KeepLastKnownUPN(record, entry.previous)
			carried = facts.UPN == "" && record.Facts.UPN != ""
		}
		record = MarkWindowsKeptUPN(record, entry.previous, facts.UPNKept || carried)
		publish(entry, record)
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	if len(unanswered) > 0 {
		stopped = errors.Join(stopped, fmt.Errorf("the directory lookups of %d account(s) did not answer in time; their previous records "+
			"stay, with this cycle's token groups: %s", len(unanswered), strings.Join(unanswered, ", ")))
	}
	return stopped
}

// windowsIdentityLookupBudget is budget, cut to the time left before ctx's
// deadline.
func windowsIdentityLookupBudget(ctx context.Context, budget time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < budget {
			return max(left, 0)
		}
	}
	return budget
}

// The directory lookups of a record; tests replace them.
var (
	windowsIdentityDirectoryFacts = useridentity.WindowsDirectoryFacts
	windowsIdentityGroupNames     = useridentity.WindowsGroupNames
)

// windowsIdentityLookups are the directory lookups one pass uses, read once
// so a lookup still running after the pass ended uses the pass's own.
type windowsIdentityLookups struct {
	facts       func(sid string, wait time.Duration) useridentity.DirectoryFacts
	groupNames  func(sids []string, limit int, budget time.Duration) []string
	settledName func(sid, account, domain string) string
}

// windowsIdentityResolved is what the lookups of one account found.
type windowsIdentityResolved struct {
	facts useridentity.DirectoryFacts
	user  string
}

// windowsIdentityAccountWait bounds the wait for one account's lookups;
// tests replace it.
var windowsIdentityAccountWait = 10 * time.Second

// windowsIdentityLookupGate holds the account lookups of the passes, by SID.
var windowsIdentityLookupGate identityLookupGate

// windowsIdentityBounded runs lookup for the account key in the background
// (identityLookupGated) and waits for it until ctx ends. It returns ctx's
// error when ctx ended first, also when the answer arrived just as it ended:
// the pass does not run past its cycle. While an earlier lookup of key still
// runs it starts none and returns errIdentityLookupStillRunning.
func windowsIdentityBounded(ctx context.Context, key string, lookup func(context.Context) windowsIdentityResolved) (windowsIdentityResolved, error) {
	resolved, err := identityLookupGated(ctx, &windowsIdentityLookupGate, key, func(ctx context.Context) (windowsIdentityResolved, error) {
		return lookup(ctx), nil
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return windowsIdentityResolved{}, err
	}
	return resolved, nil
}

// spoolUser names a record's account DOMAIN\account, as the Linux and macOS
// records name theirs, so a record maps to an account without a SID lookup;
// "" when the SID no longer resolves. While the user is signed in with a
// UPN the LSA names the account by that UPN as typed; the record then takes
// the sAMAccountName the directory translates it to (settledName), which
// the gateway's service account cannot ask for itself (GAP-0382).
func (l windowsIdentityLookups) spoolUser(ctx context.Context, sid string) string {
	names := l.groupNames([]string{sid}, 1, windowsIdentityLookupBudget(ctx, windowsIdentityGroupNameBudget))
	if len(names) != 1 || names[0] == sid {
		return ""
	}
	domain, account, qualified := strings.Cut(names[0], `\`)
	if qualified && strings.Contains(account, "@") {
		if sam := l.settledName(sid, account, domain); sam != "" {
			return domain + `\` + sam
		}
	}
	return names[0]
}

// windowsSettledAccountName is useridentity.SettledWindowsAccountName; tests
// replace it.
var windowsSettledAccountName = useridentity.SettledWindowsAccountName

// windowsConnectorEmailWarned keeps an unreadable connector file from being
// reported at every enumerator cycle.
var windowsConnectorEmailWarned sync.Map

// WindowsConnectorEmails reads, as SYSTEM, the Claude Code and Codex account
// address of each enrolled profile in manifest (ai_discovery.include_user_email),
// keyed by upper-case SID. Each is read from the profile owner's own file and
// only through ordinary folders: a file reached through a link or junction,
// one that cannot be read, or one that is not a regular file gives no address
// and a named warning, logged once per account, connector and reason.
func WindowsConnectorEmails(manifest Manifest, logf func(string, ...any)) map[string]map[string]string {
	out := map[string]map[string]string{}
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if !validIdentitySpoolKey(key) || home == "." || seen[key] {
			continue
		}
		seen[key] = true
		for _, connector := range []string{"claudecode", "codex"} {
			email, err := windowsProfileConnectorEmail(connector, home)
			if err == nil {
				if out[key] == nil {
					out[key] = map[string]string{}
				}
				out[key][connector] = email
				continue
			}
			if !errors.Is(err, useridentity.ErrEmailFileUnreadable) || logf == nil {
				continue
			}
			if _, warned := windowsConnectorEmailWarned.LoadOrStore(key+"\x00"+connector+"\x00"+err.Error(), true); !warned {
				logf("[hook-enumerator] WARN include_user_email: no %s address for %s: %v", connector, key, err)
			}
		}
	}
	return out
}

// windowsProfileConnectorEmail reads one address; tests replace it.
var windowsProfileConnectorEmail = useridentity.ProfileEmailForConnector
