// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainWarnings lists what an administrator should know about the
// decision `guardrail profile explain` reports, and what doctor and status
// repeat: things that are not errors but that the profile decision alone
// does not show.
func profileExplainWarnings(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) []string {
	var warnings []string
	if subject == nil || !subject.LookupFailed {
		warnings = append(warnings, set.unknownGroupWarnings(profileGroupCheckWait)...)
	}
	if note := shortNameUserNote(set, decision, subject); note != "" {
		warnings = append(warnings, note)
	}
	if note := entraShortNameNote(set, subject); note != "" {
		warnings = append(warnings, note)
	}
	if note := unnamedGroupsNote(subject); note != "" {
		warnings = append(warnings, note)
	}
	if runtime.GOOS == "windows" && subject != nil {
		if note := spoolRecordNote(subject.UserID, time.Now()); note != "" {
			warnings = append(warnings, note)
		}
	}
	return warnings
}

// unnamedGroupsNote says when some of the explained account's groups are
// only numbers. The Unix resolver keeps a group id as its number when no
// group answers for it, which is what a directory that does not answer
// leaves behind: the account then has too few groups for its assignments to
// match, and nothing else in the answer shows it (GAP-0212).
func unnamedGroupsNote(subject *profileSubject) string {
	if subject == nil || subject.LookupFailed {
		return ""
	}
	groups := subject.Groups
	isSID := func(group string) bool { return strings.HasPrefix(strings.ToUpper(group), "S-1-") }
	sidForm := slices.ContainsFunc(groups, isSID)
	unnamed, total := 0, len(groups)
	if sidForm {
		// Windows lists each group's SID followed by its DOMAIN\name; a SID
		// followed by another SID (or the end) was not named. The guardian
		// names at most 128 groups per account, within 2 s, so a large token
		// or a slow domain controller leaves the rest as bare SIDs (GAP-0136).
		total = 0
		for i, group := range groups {
			if !isSID(group) {
				continue
			}
			total++
			if i+1 >= len(groups) || isSID(groups[i+1]) {
				unnamed++
			}
		}
	} else {
		for _, group := range groups {
			if group != "" && strings.Trim(group, "0123456789") == "" {
				unnamed++
			}
		}
	}
	if unnamed == 0 {
		return ""
	}
	if sidForm {
		return fmt.Sprintf("%d of this account's %d group(s) have no name, only a SID (the guardian names at most 128 groups per account within 2 s, "+
			"or the SID does not resolve); an assignment that names such a group as DOMAIN\\name cannot match, so name it by its SID", unnamed, total)
	}
	return fmt.Sprintf("%d of this account's %d group(s) are shown by number because no group answered for them; "+
		"the directory may be unreachable or the group missing, and an assignment that names such a group cannot match",
		unnamed, total)
}

// Groups an assignment names that the host does not know.
//
// Renaming or deleting a security group in the directory is routine, and an
// assignment that names the old name then selects nobody without any other
// sign: the users of that group fall through to the next assignment or the
// default profile. The groups the assignments name are looked up in the
// operating system's account database, and each one it answers "no such
// group" for is a warning in explain, status, doctor and `profile list`, and
// a line in the gateway log at start and at each reload (GAP-0135). A lookup
// that fails or runs out of time says nothing: only a definite absence warns.
//
// An SSSD that is offline with a cold cache does not fail: it answers "no such
// group" for groups that exist. So nothing is warned while the directory
// lookups of the gateway fail (the "Directory lookups" warning says so once),
// or for an account whose own lookup failed, and a pass that ran meanwhile
// is not kept (GAP-0229).

const (
	profileGroupCheckTTL    = time.Minute
	profileGroupCheckBudget = 3 * time.Second
	// profileGroupCheckWait is how long a command waits for the first pass of
	// a set; status and doctor give the gateway only 3 s to answer.
	profileGroupCheckWait = 1500 * time.Millisecond
	// profileGroupCheckMax bounds how many distinct groups one pass looks up,
	// so a configuration with thousands of assignments cannot make an
	// administrator's command wait.
	profileGroupCheckMax = 64
)

// profileGroupCheck is the last pass over a set's groups, and the pass in
// flight.
type profileGroupCheck struct {
	mu        sync.Mutex
	checked   bool
	checkedAt time.Time
	warnings  []string
	running   chan struct{}
}

// unknownGroupWarnings returns one warning per assignment group the host
// does not know, from a pass at most profileGroupCheckTTL old. A pass runs in
// the background, so a command never waits for the directory: it gets the last
// pass, or, before the first has finished, waits for it at most wait.
func (set *guardrailProfileSet) unknownGroupWarnings(wait time.Duration) []string {
	return set.unknownGroupWarningsWith(profileGroupExists, profileGroupQualifiedName, directoryCacheHealth, wait)
}

// unknownGroupWarningsWith is unknownGroupWarnings with the group lookup and
// the directory cache health taken from the caller. A pass can outlive the
// caller, so it uses these and never reads the package hooks tests replace.
func (set *guardrailProfileSet) unknownGroupWarningsWith(exists func(context.Context, string) (bool, error), qualify func(context.Context, string) string,
	health func() identityCacheHealth, wait time.Duration) []string {
	if set == nil {
		return nil
	}
	check := &set.groupCheck
	check.mu.Lock()
	if health().Failing > 0 {
		check.warnings, check.checked = nil, false
		check.mu.Unlock()
		return nil
	}
	if (!check.checked || time.Since(check.checkedAt) >= profileGroupCheckTTL) && check.running == nil {
		done := make(chan struct{})
		check.running = done
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), profileGroupCheckBudget)
			warnings := unknownAssignmentGroups(ctx, set.assignments, exists, qualify)
			cancel()
			failing := health().Failing > 0
			if failing {
				warnings = nil
			}
			check.mu.Lock()
			check.warnings, check.checked, check.checkedAt, check.running = warnings, !failing, time.Now(), nil
			check.mu.Unlock()
			close(done)
		}()
	}
	running, checked := check.running, check.checked
	out := append([]string(nil), check.warnings...)
	check.mu.Unlock()
	if checked || running == nil || wait <= 0 {
		return out
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-running:
	case <-timer.C:
	}
	check.mu.Lock()
	defer check.mu.Unlock()
	return append([]string(nil), check.warnings...)
}

// logUnknownGroups writes the unknown-group warnings to the gateway log in the
// background; the gateway calls it for a new set at start and at each reload.
func (set *guardrailProfileSet) logUnknownGroups() {
	exists, qualify, health := profileGroupExists, profileGroupQualifiedName, directoryCacheHealth
	go func() {
		for _, warning := range set.unknownGroupWarningsWith(exists, qualify, health, profileGroupCheckBudget+time.Second) {
			fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
		}
	}()
}

// unknownAssignmentGroups looks up each distinct group the assignments name
// and warns for those exists reports as definitely absent. SIDs and ids are
// not names and are not looked up. qualify, when set, names the qualified
// form the host knows an absent short name by, which the warning then
// suggests (GAP-0332).
func unknownAssignmentGroups(ctx context.Context, assignments []config.ProfileAssignment, exists func(context.Context, string) (bool, error),
	qualify func(context.Context, string) string) []string {
	var warnings []string
	absent := map[string]bool{}      // by folded name; present for every group looked up
	qualified := map[string]string{} // by folded name: the form the host knows an absent group by
	for i, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			group = strings.TrimSpace(group)
			if group == "" || strings.HasPrefix(strings.ToUpper(group), "S-1-") || strings.Trim(group, "0123456789") == "" {
				continue
			}
			key := foldKey(group)
			dead, looked := absent[key]
			if !looked {
				if len(absent) >= profileGroupCheckMax || ctx.Err() != nil {
					continue
				}
				known, err := exists(ctx, group)
				dead = err == nil && !known
				absent[key] = dead
				if dead && qualify != nil {
					qualified[key] = qualify(ctx, group)
				}
			}
			switch {
			case dead && qualified[key] != "":
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not known to this host by that name, so it selects nobody; "+
					"the host knows it as %q (SSSD use_fully_qualified_names = True): write that name, or set "+
					"use_fully_qualified_names = False in sssd.conf", i+1, group, qualified[key]))
			case dead:
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not known to this host (renamed or deleted in the directory?), so it selects nobody", i+1, group))
			}
		}
	}
	return warnings
}

// shortNameUserNote says when a directory account was selected by a users
// entry that is a bare name. A bare name is the account name without its
// domain, so the entry meant for alice@corp.example.com selects a local
// account alice as well, and the reverse (GAP-0182).
func shortNameUserNote(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) string {
	if set == nil || subject == nil || decision.Assignment < 1 || decision.Assignment > len(set.assignments) ||
		subject.Domain == "" || subject.Directory == useridentity.DirectoryLocal {
		return ""
	}
	for _, entry := range set.assignments[decision.Assignment-1].Match.Users {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.ContainsAny(entry, `@\`) || !userEntryMatches(subject, entry) ||
			strings.EqualFold(entry, subject.UserID) {
			continue
		}
		qualified := firstNonEmpty(subject.UPN, subject.Principal, subject.UserID)
		return fmt.Sprintf("assignment %d selects this account by the short name %q, so it selects a local account of that name too; "+
			"write %s (or the uid) to select only this account", decision.Assignment, entry, qualified)
	}
	return ""
}

// entraShortNameNote says when the host names an Entra ID account by its
// short name and reports no UPN for it (Himmelblau's default
// cn_name_mapping = true) while an assignment lists users by UPN: no such
// entry can select an account of this host (GAP-0328).
func entraShortNameNote(set *guardrailProfileSet, subject *profileSubject) string {
	if set == nil || subject == nil || subject.LookupFailed || subject.Directory != useridentity.DirectoryEntraID ||
		subject.UPN != "" || strings.Contains(subject.UserName, "@") {
		return ""
	}
	for i, assignment := range set.assignments {
		for _, entry := range assignment.Match.Users {
			if entry = strings.TrimSpace(entry); strings.Contains(entry, "@") {
				return fmt.Sprintf("this host names the Entra ID account %q by its short name and reports no UPN for it, so a users entry "+
					"written as a UPN (assignment %d: %q) cannot select it; with Himmelblau, set cn_name_mapping = false in "+
					"/etc/himmelblau/himmelblau.conf to name accounts by their UPN, or name the account by its short name or uid",
					subject.UserName, i+1, entry)
			}
		}
	}
	return ""
}

// What requests of the explained account use right now.
//
// `explain --user` resolves the account through the operating system, so it
// reports the profile a request gets after its facts are next refreshed.
// Requests read the gateway's cache instead, which holds an account's facts
// for 15 minutes and serves them stale while one background lookup replaces
// them; so for up to that long after a group changed, explain and the audit
// rows can disagree. explainCacheView puts the cache's side next to the
// answer (GAP-0134).

// cachedDirectoryFacts returns the facts requests of an account use, and when
// they were fetched. Tests replace it.
var cachedDirectoryFacts = func(id string) (useridentity.DirectoryFacts, time.Time, bool) {
	return peerDirectoryCache().peek(id)
}

// cachedDirectoryFailure reports an account the gateway's own lookups fail
// for and holds no facts of. Tests replace it.
var cachedDirectoryFailure = func(id string) (time.Time, string, bool) {
	return peerDirectoryCache().failing(id)
}

// explainCacheView describes the cached facts of the explained account: how
// old they are, and the profile requests currently get from them. warning is
// non-empty when that profile differs from the explained one.
func explainCacheView(set *guardrailProfileSet, explained *profileSubject, decision profileDecision, connectorName, agent string, now time.Time) (view map[string]any, warning string) {
	if set == nil || explained == nil || explained.UserID == "" || explained.LookupFailed {
		return nil, ""
	}
	facts, fetchedAt, ok := cachedDirectoryFacts(explained.UserID)
	if !ok {
		// No facts are cached. When the gateway's own lookups for the account
		// fail, its requests get default_lookup_failed whatever this fresh
		// lookup found (GAP-0212).
		since, reason, failing := cachedDirectoryFailure(explained.UserID)
		if !failing {
			return nil, ""
		}
		failed := profileSubject{UserID: explained.UserID, IDKind: explained.IDKind, UserName: explained.UserName, LookupFailed: true}
		live := set.match(&failed, profileSubjectLookup, connectorName, agent)
		differs := live.Name != decision.Name || live.Match != decision.Match
		view = map[string]any{
			"failing_since": since.UTC().Format(time.RFC3339),
			"last_error":    reason,
			"profile":       live.Name,
			"match":         live.Match,
			"differs":       differs,
		}
		if differs {
			warning = fmt.Sprintf("requests of this account currently get profile %s (match %s): the gateway's directory lookup for it has failed since %s (%s) "+
				"and is retried every %s; the profile above applies once a lookup succeeds",
				firstNonEmpty(live.Name, "none"), live.Match, since.UTC().Format("15:04:05Z"), reason, identityDirectoryRetry)
		}
		return view, warning
	}
	age := now.Sub(fetchedAt).Round(time.Second)
	if age < 0 {
		age = 0
	}
	refresh := max(identityDirectoryTTL-age, 0)
	cached := profileSubjectFromVerified(VerifiedSubject{
		UserID: explained.UserID, IDKind: explained.IDKind, UserName: explained.UserName, Directory: facts,
	}, true)
	live := set.match(&cached, profileSubjectLookup, connectorName, agent)
	differs := live.Name != decision.Name || live.Match != decision.Match || live.MatchedGroup != decision.MatchedGroup
	view = map[string]any{
		"age_seconds":           int(age.Seconds()),
		"refresh_after_seconds": int(refresh.Seconds()),
		"profile":               live.Name,
		"match":                 live.Match,
		"differs":               differs,
	}
	if differs {
		warning = fmt.Sprintf("requests of this account still use the directory facts the gateway fetched %s ago (profile %s, match %s); "+
			"the profile above applies from the next refresh, within %s. Restart the gateway to refresh now",
			age, firstNonEmpty(live.Name, "none"), live.Match, refresh)
	}
	return view, warning
}

// Directory lookups that fail.
//
// A directory that does not answer (a domain controller down, SSSD offline)
// leaves no trace on the tools an administrator uses: the accounts without
// cached facts get the default profile, and the only sign was match
// default_lookup_failed on each record. directoryHealthView reports the
// accounts whose lookups failed in the last cache lifetime, with the reason
// and the age of the facts still served, to explain, status and doctor
// (GAP-0145).

// directoryCacheHealth reads the health of the cache requests use. Tests
// replace it.
var directoryCacheHealth = func() identityCacheHealth { return peerDirectoryCache().health() }

// directoryHealthSummary is the "directory" object of the unauthenticated
// /health document on the standalone profile: how many accounts fail since
// when, and no reason or account, because the reason can name one. The Linux
// and macOS lifecycle turns it into a warning of status and verify (GAP-0216).
func directoryHealthSummary(h identityCacheHealth) map[string]any {
	if h.Failing == 0 {
		return nil
	}
	return map[string]any{"failing": h.Failing, "since": h.Since.UTC().Format(time.RFC3339), "stale": h.Stale}
}

// directoryHealthView returns the "directory" object of the resolve answer
// and its one-line message, or nil when no lookup failed recently.
func directoryHealthView(h identityCacheHealth, now time.Time) (view map[string]any, message string) {
	if h.Failing == 0 {
		return nil, ""
	}
	message = fmt.Sprintf("directory lookups are failing for %d account(s) since %s (last error: %s); accounts without cached facts "+
		"get the default profile (default_lookup_failed)", h.Failing, h.Since.UTC().Format("15:04:05Z"), h.LastError)
	if h.Stale > 0 {
		message += fmt.Sprintf(", and %d account(s) are served facts up to %s old, which are dropped at %s",
			h.Stale, h.OldestAge.Round(time.Minute), identityDirectoryMaxAge)
	}
	view = map[string]any{
		"failing":            h.Failing,
		"since":              h.Since.UTC().Format(time.RFC3339),
		"last_error":         h.LastError,
		"stale":              h.Stale,
		"oldest_age_seconds": int(h.OldestAge.Seconds()),
		"max_age_seconds":    int(identityDirectoryMaxAge.Seconds()),
		"message":            message,
	}
	return view, message
}
