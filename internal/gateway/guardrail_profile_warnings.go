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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"golang.org/x/text/unicode/norm"
)

// profileExplainWarnings lists what an administrator should know about the
// decision `guardrail profile explain` reports, and what doctor and status
// repeat: things that are not errors but that the profile decision alone
// does not show.
func profileExplainWarnings(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) []string {
	warnings := set.assignmentWarnings(subject == nil || !subject.LookupFailed)
	if note := shortNameUserNote(set, decision, subject); note != "" {
		warnings = append(warnings, note)
	}
	if note := shortNameGroupNote(decision); note != "" {
		warnings = append(warnings, note)
	}
	if note := entraShortNameNote(set, subject, runtime.GOOS); note != "" {
		warnings = append(warnings, note)
	}
	if note := unnamedGroupsNote(subject); note != "" {
		warnings = append(warnings, note)
	}
	if subject != nil && subject.cachedFactsAge > 0 {
		warnings = append(warnings, fmt.Sprintf("the directory does not name %s now: this is the profile its hooks apply from the "+
			"identity facts cached %s ago, which they keep for up to an hour while lookups fail", subject.UserName,
			subject.cachedFactsAge.Round(time.Second)))
	}
	if runtime.GOOS == "windows" && subject != nil {
		if note := spoolRecordNote(subject.UserID, time.Now()); note != "" {
			warnings = append(warnings, note)
		}
	}
	return warnings
}

// assignmentWarnings is the shared source for explain, list, status and
// verify. A failed subject lookup may indicate an offline
// directory, so only that request skips directory group checks; per-user
// Windows needs no directory check to know group selectors cannot match.
func (set *guardrailProfileSet) assignmentWarnings(checkGroups bool) []string {
	return set.assignmentWarningsWithWait(checkGroups, profileGroupCheckWait)
}

func (set *guardrailProfileSet) assignmentWarningsWithWait(checkGroups bool, wait time.Duration) []string {
	if set == nil {
		return nil
	}
	warnings := set.unknownConnectorWarnings()
	if checkGroups || runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
		warnings = append(warnings, set.unknownGroupWarnings(wait)...)
	}
	return warnings
}

// unknownConnectorWarnings points out profile selectors and overrides that
// cannot match any built-in connector. Config is a leaf package, so it cannot
// consult the runtime registry; plugin names remain valid, with a warning
// unless the plugin is also in the configured connector roster.
func (set *guardrailProfileSet) unknownConnectorWarnings() []string {
	if set == nil || set.base == nil {
		return nil
	}
	var warnings []string
	for i, assignment := range set.assignments {
		for _, name := range assignment.Match.Connectors {
			if !set.knownConnector(name) {
				warnings = append(warnings, fmt.Sprintf("guardrail.profile_assignments[%d].match.connectors: %q is not a built-in or configured connector; check its spelling or plugin", i, name))
			}
		}
	}
	profiles := make([]string, 0, len(set.base.Guardrail.Profiles))
	for name := range set.base.Guardrail.Profiles {
		profiles = append(profiles, name)
	}
	slices.Sort(profiles)
	for _, profileName := range profiles {
		profile := set.base.Guardrail.Profiles[profileName]
		connectors := make([]string, 0, len(profile.Connectors))
		for name := range profile.Connectors {
			connectors = append(connectors, name)
		}
		slices.Sort(connectors)
		for _, name := range connectors {
			if !set.knownConnector(name) {
				warnings = append(warnings, fmt.Sprintf("guardrail.profiles[%q].connectors: %q is not a built-in or configured connector; check its spelling or plugin", profileName, name))
			}
		}
	}
	return warnings
}

func (set *guardrailProfileSet) knownConnector(name string) bool {
	if set == nil || set.base == nil {
		return false
	}
	norm := config.NormalizeConnectorName(name)
	return connector.IsKnownBuiltinConnector(norm) || set.base.Guardrail.HasConnector(norm)
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
// is not kept (GAP-0229). Neither is it when the gateway's own lookups do not
// show the outage: at start before the first failed lookup, or on a local
// account. A domain none of whose groups the host knows is asked for its
// Domain Users group, which every Active Directory domain has; when the host
// does not know that one either, the directory does not answer, and the pass
// says once that it could not check that domain's groups (GAP-0255).

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
	// profileQuietGroupsNamed bounds the groups one unconfirmed-domain note
	// names.
	profileQuietGroupsNamed = 8
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
	if set != nil && runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
		return perUserWindowsGroupWarnings(set.assignments)
	}
	return set.unknownGroupWarningsWith(profileGroupExists, profileGroupQualifiedName, directoryCacheHealth, wait)
}

// Per-user Windows has no trusted group facts; these assignments cannot match.
func perUserWindowsGroupWarnings(assignments []config.ProfileAssignment) []string {
	var warnings []string
	for i, assignment := range assignments {
		if len(assignment.Match.Groups) > 0 {
			warnings = append(warnings, fmt.Sprintf("assignment %d: groups cannot match on a per-user Windows install; use users or standalone enterprise", i+1))
		}
	}
	return warnings
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
			previous, wasChecked := check.warnings, check.checked
			check.warnings, check.checked, check.checkedAt, check.running = warnings, !failing, time.Now(), nil
			check.mu.Unlock()
			// A group that stops resolving between start and reload (an SSSD
			// naming switch) is logged when a later check finds it, not only
			// at the next start or reload (GAP-0704).
			if wasChecked {
				for _, warning := range warnings {
					if !slices.Contains(previous, warning) {
						fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
					}
				}
			}
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

// logProfileWarnings writes connector warnings and unknown-group warnings to the gateway log in the
// background; the gateway calls it for a new set at start and at each reload.
func (set *guardrailProfileSet) logProfileWarnings() {
	for _, warning := range set.unknownConnectorWarnings() {
		fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
	}
	exists, qualify, health := profileGroupExists, profileGroupQualifiedName, directoryCacheHealth
	go func() {
		if runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
			for _, warning := range perUserWindowsGroupWarnings(set.assignments) {
				fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
			}
			return
		}
		for _, warning := range set.unknownGroupWarningsWith(exists, qualify, health, profileGroupCheckBudget+time.Second) {
			fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
		}
	}()
}

// unknownAssignmentGroups looks up each distinct group the assignments name
// and warns for those exists reports as definitely absent, naming the group
// and its assignment, also when their directory does not answer for the
// domain at all (GAP-0928). Windows SIDs are checked by the LSA; other
// platforms skip SIDs. Numeric group ids are not names. qualify, when set,
// names the spelling the host lists a group under: the qualified form of an
// absent short name, which the warning then suggests (GAP-0332), or, outside
// Windows, the short form a qualified name now resolves to, which account
// group lists carry instead, so the assignment selects nobody (GAP-0916).
func unknownAssignmentGroups(ctx context.Context, assignments []config.ProfileAssignment, exists func(context.Context, string) (bool, error),
	qualify func(context.Context, string) string) []string {
	return unknownAssignmentGroupsForOS(ctx, assignments, exists, qualify, runtime.GOOS)
}

func unknownAssignmentGroupsForOS(ctx context.Context, assignments []config.ProfileAssignment, exists func(context.Context, string) (bool, error),
	qualify func(context.Context, string) string, platform string) []string {
	type unknownGroup struct {
		assignment    int
		group, domain string
	}
	var unknown []unknownGroup
	var warnings []string
	respelled := map[string]string{} // by folded name: the spelling the host lists a known qualified group under
	skippedLimit, skippedDeadline := false, false
	absent := map[string]bool{}   // by folded name; present for every group looked up
	answered := map[string]bool{} // by folded domain: the host knows a group of it
	for i, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			group = strings.TrimSpace(group)
			if group == "" || (platform != "windows" && strings.HasPrefix(strings.ToUpper(group), "S-1-")) || strings.Trim(group, "0123456789") == "" {
				continue
			}
			_, domain := useridentity.SplitQualifiedName(group)
			key := foldKey(group)
			dead, looked := absent[key]
			if !looked {
				if len(absent) >= profileGroupCheckMax {
					skippedLimit = true
					continue
				}
				if ctx.Err() != nil {
					skippedDeadline = true
					continue
				}
				known, err := exists(ctx, norm.NFC.String(group))
				dead = err == nil && !known
				absent[key] = dead
				if known {
					answered[foldKey(domain)] = true
					if qualify != nil && platform != "windows" && domain != "" {
						respelled[key] = qualify(ctx, norm.NFC.String(group))
					}
				}
			}
			if dead {
				unknown = append(unknown, unknownGroup{assignment: i + 1, group: group, domain: domain})
			} else if listed := respelled[key]; listed != "" {
				hint := ""
				if _, listedDomain := useridentity.SplitQualifiedName(listed); listedDomain == "" {
					hint = " (SSSD use_fully_qualified_names = False)"
				}
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is listed by this host as %q%s, the name account "+
					"group lists carry, so the assignment selects nobody; write %q", i+1, group, listed, hint, listed))
			}
		}
	}
	silent := map[string]bool{} // by folded domain, once asked: its directory does not answer
	// One note per such domain, naming its assignments and groups (GAP-0255,
	// GAP-0928).
	quietGroups := map[string][]string{}
	var quietDomains []string
	for _, u := range unknown {
		domainKey := foldKey(u.domain)
		if platform != "windows" && u.domain != "" && !answered[domainKey] {
			quiet, asked := silent[domainKey]
			if !asked {
				quiet = !directoryAnswers(ctx, u.group, u.domain, exists)
				silent[domainKey] = quiet
			}
			if quiet {
				if _, seen := quietGroups[domainKey]; !seen {
					quietDomains = append(quietDomains, u.domain)
				}
				quietGroups[domainKey] = append(quietGroups[domainKey], fmt.Sprintf("assignment %d: group %q", u.assignment, u.group))
				continue
			}
		}
		if qualify != nil {
			if qualified := qualify(ctx, u.group); qualified != "" {
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not known to this host by that name, so it selects nobody; "+
					"the host knows it as %q (SSSD use_fully_qualified_names = True): write that name, or set "+
					"use_fully_qualified_names = False in sssd.conf", u.assignment, u.group, qualified))
				continue
			}
		}
		warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not known to this host (renamed or deleted in the directory?), so it selects nobody", u.assignment, u.group))
	}
	for _, domain := range quietDomains {
		named := quietGroups[foldKey(domain)]
		if len(named) > profileQuietGroupsNamed {
			named = append(named[:profileQuietGroupsNamed:profileQuietGroupsNamed], fmt.Sprintf("%d more", len(named)-profileQuietGroupsNamed))
		}
		warnings = append(warnings, fmt.Sprintf("could not confirm group names written for %s by this spelling (%s): renamed or "+
			"deleted in the directory, another domain prefix, or the lookup is unavailable, so these may select nobody; check the "+
			"qualified name with getent group", domain, strings.Join(named, ", ")))
	}
	if skippedLimit {
		warnings = append(warnings, fmt.Sprintf("group warning check incomplete: only the first %d distinct groups were checked; later assignment groups were not checked", profileGroupCheckMax))
	}
	if skippedDeadline {
		warnings = append(warnings, "group warning check incomplete: the directory check timed out; later assignment groups were not checked")
	}
	return warnings
}

// directoryAnswers reports whether the host knows the Domain Users group of
// the domain of group, spelled the way group is (name@domain or
// DOMAIN\name).
func directoryAnswers(ctx context.Context, group, domain string, exists func(context.Context, string) (bool, error)) bool {
	probe := "domain users@" + domain
	if strings.Contains(group, `\`) {
		probe = domain + `\domain users`
	}
	known, err := exists(ctx, probe)
	return err == nil && known
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

func shortNameGroupNote(decision profileDecision) string {
	group := strings.TrimSpace(decision.MatchedGroup)
	if decision.Match != profileMatchGroup || group == "" || strings.ContainsAny(group, `@\`) ||
		strings.HasPrefix(strings.ToUpper(group), "S-1-") || strings.Trim(group, "0123456789") == "" {
		return ""
	}
	return fmt.Sprintf("assignment %d selects this account by bare group %q, which can also match a same-named group in another domain; use DOMAIN\\name or the group SID to select one domain", decision.Assignment, group)
}

// entraShortNameNote says when the host names an Entra ID account by its
// short name and reports no UPN for it (Himmelblau's default
// cn_name_mapping = true) while an assignment lists users by UPN: no such
// entry can select an account of this host (GAP-0328).
func entraShortNameNote(set *guardrailProfileSet, subject *profileSubject, goos string) string {
	if goos == "windows" || set == nil || subject == nil || subject.LookupFailed || subject.Directory != useridentity.DirectoryEntraID ||
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

// cachedDirectoryLifetime is how long the cache serves facts before it
// refreshes them: shorter for an answer it calls incomplete, such as one with
// a group no name answered for (GAP-0326). Tests replace it.
var cachedDirectoryLifetime = func(facts useridentity.DirectoryFacts) time.Duration {
	return peerDirectoryCache().lifetime(facts)
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
		// fail, directory-dependent assignments get default_lookup_failed
		// whatever this fresh lookup found (GAP-0212).
		since, reason, failing := cachedDirectoryFailure(explained.UserID)
		if !failing {
			return nil, ""
		}
		failed := profileSubject{UserID: explained.UserID, IDKind: explained.IDKind, UserName: explained.UserName, LookupFailed: identityLookupBlocking.Load()}
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
	refresh := max(cachedDirectoryLifetime(facts)-age, 0)
	cached := profileSubjectFromVerified(VerifiedSubject{
		UserID: explained.UserID, IDKind: explained.IDKind, UserName: explained.UserName, Directory: facts,
	}, identityLookupBlocking.Load())
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
// cached facts get default_lookup_failed for directory-dependent assignments,
// and the only sign was that match on each record. directoryHealthView reports the
// accounts whose lookups failed in the last cache lifetime, with the reason
// and the age of the facts still served, to explain, status and doctor
// (GAP-0145).

// directoryCacheHealth reads the health of the cache requests use. Tests
// replace it.
var directoryCacheHealth = func() identityCacheHealth { return peerDirectoryCache().health() }

// directoryHealthSummary is the "directory" object of the unauthenticated
// /health document on the standalone profile: how many accounts fail since
// when, and no reason, because the reason can name an account. The Linux
// and macOS lifecycle turns it into a warning of status and verify
// (GAP-0216); it asks over the hook socket as root, and only then (withIDs)
// gets the uids of the failing accounts, so the warning can name them
// (GAP-0696).
func directoryHealthSummary(h identityCacheHealth, withIDs bool) map[string]any {
	if h.Failing == 0 {
		return nil
	}
	summary := map[string]any{"failing": h.Failing, "since": h.Since.UTC().Format(time.RFC3339), "stale": h.Stale}
	if withIDs && len(h.Accounts) > 0 {
		summary["accounts"] = h.Accounts
	}
	return summary
}

// directoryHealthView returns the "directory" object of the resolve answer
// and its one-line message, or nil when no lookup failed recently.
func directoryHealthView(h identityCacheHealth, now time.Time) (view map[string]any, message string) {
	if h.Failing == 0 {
		return nil, ""
	}
	message = fmt.Sprintf("directory lookups are failing for %d account(s) since %s (last error: %s); accounts without cached facts "+
		"use the default profile for directory-dependent assignments (default_lookup_failed)", h.Failing, h.Since.UTC().Format("15:04:05Z"), h.LastError)
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

// observedGroupDomains are the domains of the name@domain groups of accounts
// whose directory facts the gateway resolved, so a short-name hint also
// names an SSSD domain realmd does not list (GAP-0332).
var observedGroupDomains = &boundedNameSet{max: 16}

// boundedNameSet keeps the first max distinct names, compared without
// regard to case.
type boundedNameSet struct {
	mu    sync.Mutex
	max   int
	names []string
}

func (b *boundedNameSet) add(name string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, `@\/: `) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.names) >= b.max || slices.ContainsFunc(b.names, func(seen string) bool { return strings.EqualFold(seen, name) }) {
		return
	}
	b.names = append(b.names, name)
}

func (b *boundedNameSet) list() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.names)
}

// noteGroupDomains records the domains of an account's name@domain groups.
func noteGroupDomains(groups []string) {
	for _, group := range groups {
		if _, domain := useridentity.SplitQualifiedName(group); domain != "" && strings.Contains(group, "@") {
			observedGroupDomains.add(domain)
		}
	}
}
