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
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
	if note := ambiguousShortNameUserNote(set, decision, subject); note != "" {
		warnings = append(warnings, note)
	}
	if note := shortNameGroupNote(decision); note != "" {
		warnings = append(warnings, note)
	}
	if note := entraShortNameNote(set, subject, runtime.GOOS); note != "" {
		warnings = append(warnings, note)
	}
	var sids *profileGroupSIDs
	if set != nil {
		sids = set.groupSIDs
	}
	if note := unnamedGroupsNote(subject, sids); note != "" {
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
	warnings = append(warnings, staticGroupWarnings(set.assignments, runtime.GOOS)...)
	if checkGroups || runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
		warnings = append(warnings, set.unknownGroupWarnings(wait)...)
	}
	return append(warnings, set.groupSIDs.warnings(set.assignments)...)
}

// healthProfileWarnings is what /health serves to root on the hook socket,
// and /status to the gateway credential, for status and verify: the
// assignment warnings profile-explain lists, with the first group pass
// waited for briefly. Without the wait, a status right after a gateway
// restart listed no unknown group while profile-explain named it (GAP-0830).
func (set *guardrailProfileSet) healthProfileWarnings() []string {
	warnings := set.assignmentWarningsWithWait(true, profileGroupCheckWait)
	if runtime.GOOS == "linux" {
		warnings = append(warnings, shortNameAssignmentWarnings(set.assignments, profileShortNameRecords())...)
	}
	return append(warnings, set.inertHILTWarnings()...)
}

// profileShortNameRecords supplies verified guardian facts for the exact
// qualified-name remedy in status, verify and doctor. Tests replace it.
var profileShortNameRecords = func() []enterprisehooks.IdentitySpoolRecord {
	if dir := currentIdentitySpoolDir(); dir != "" {
		return enterprisehooks.ReadIdentitySpoolRecords(dir, validateManagedGuardianAuthorization, identityDirectoryMax)
	}
	return nil
}

func shortNameAssignmentWarnings(assignments []config.ProfileAssignment, records []enterprisehooks.IdentitySpoolRecord) []string {
	var warnings []string
	for i, assignment := range assignments {
		for _, entry := range assignment.Match.Users {
			entry = strings.TrimSpace(entry)
			if entry == "" || strings.ContainsAny(entry, `@\`) || useridentity.KindForID(entry) != "" {
				continue
			}
			namesakes := sssdADNamesakes(records, entry)
			if len(namesakes) > 1 {
				// One bare entry selects accounts of more than one trusted
				// domain: one warning names them all (GAP-0725).
				names := make([]string, 0, len(namesakes))
				for _, record := range namesakes {
					names = append(names, fmt.Sprintf("%s (uid %s)", firstNonEmpty(record.Facts.UPN, record.Facts.Principal, record.User), record.Key))
				}
				warnings = append(warnings, fmt.Sprintf("assignment %d uses the bare user %q, which selects the SSSD AD accounts %s of different trusted domains; "+
					"write the qualified name or uid of each account it should select (the strict policy tier refuses this entry)", i+1, entry, strings.Join(names, " and ")))
				continue
			}
			for _, record := range namesakes {
				qualified := firstNonEmpty(record.Facts.UPN, record.Facts.Principal)
				if qualified != "" {
					warnings = append(warnings, fmt.Sprintf("assignment %d uses the bare user %q for %s; write %s (or uid %s) to select exactly this SSSD AD account",
						i+1, entry, record.User, qualified, record.Key))
				}
			}
		}
	}
	return warnings
}

// sssdADNamesakes are the guardian records of SSSD Active Directory accounts
// whose bare name is entry.
func sssdADNamesakes(records []enterprisehooks.IdentitySpoolRecord, entry string) []enterprisehooks.IdentitySpoolRecord {
	var out []enterprisehooks.IdentitySpoolRecord
	for _, record := range records {
		facts := record.Facts
		if facts.Directory != useridentity.DirectoryActiveDirectory ||
			(facts.Source != useridentity.SourceSSSD && facts.Source != useridentity.SourceSSSDInfoPipe) ||
			!useridentity.EqualFold(useridentity.BareAccountName(record.User), entry) {
			continue
		}
		out = append(out, record)
	}
	return out
}

// standaloneProfileWarnings is what status and verify list on a standalone
// deployment: the profile set's warnings, or, with no profiles, the inert
// human-approval warnings of the config itself, which config validate and
// profile-explain already gave (id.GAP-1264).
func standaloneProfileWarnings(set *guardrailProfileSet, cfg *config.Config) []string {
	if set != nil {
		return set.healthProfileWarnings()
	}
	return ConfigHILTWarnings(cfg)
}

// inertHILTWarning uses the same resolved threshold as enforcement. Keep
// blocking precedence and explain why an enabled approval cannot fire.
func inertHILTWarning(cfg *config.Config, connector string) string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return ""
	}
	hilt := cfg.EffectiveHILTForConnector(connector)
	block := resolveThresholds(cfg, connector).Block
	if !config.HILTBlockedByThreshold(hilt, block) {
		return ""
	}
	minimum := strings.ToUpper(strings.TrimSpace(hilt.MinSeverity))
	if minimum == "" {
		minimum = "HIGH"
	}
	return fmt.Sprintf("human approval at %s cannot ask: block_at %s blocks those findings first; lower hilt.min_severity or raise block_at", minimum, block)
}

func (set *guardrailProfileSet) inertHILTWarnings() []string {
	if set == nil || set.base == nil || set.base.SecureClientIntegration() {
		return nil
	}
	configs := map[string]*config.Config{"guardrail": set.base}
	for name, profile := range set.profiles {
		configs["guardrail.profiles."+name] = profile.Config
	}
	return inertHILTWarningsForConfigs(configs)
}

// ConfigHILTWarnings is the offline validation view of the same warnings
// used by profile explain and gateway health. It does not change enforcement.
func ConfigHILTWarnings(cfg *config.Config) []string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	configs := map[string]*config.Config{"guardrail": cfg}
	profiles, err := cfg.DeriveGuardrailProfiles()
	if err != nil {
		return nil // the canonical validator reports the error separately
	}
	for name, profile := range profiles {
		configs["guardrail.profiles."+name] = profile.Config
	}
	return inertHILTWarningsForConfigs(configs)
}

func inertHILTWarningsForConfigs(configs map[string]*config.Config) []string {
	var scopes []string
	for scope := range configs {
		scopes = append(scopes, scope)
	}
	slices.Sort(scopes)
	var warnings []string
	for _, scope := range scopes {
		cfg := configs[scope]
		connectors := map[string]bool{"": true}
		for name := range cfg.Guardrail.Connectors {
			connectors[config.NormalizeConnectorName(name)] = true
		}
		if profileName := strings.TrimPrefix(scope, "guardrail.profiles."); profileName != scope {
			for name := range configs["guardrail"].Guardrail.Profiles[profileName].Connectors {
				connectors[config.NormalizeConnectorName(name)] = true
			}
		}
		var names []string
		for name := range connectors {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if note := inertHILTWarning(cfg, name); note != "" {
				path := scope
				if name != "" {
					path += ".connectors." + name
				}
				warnings = append(warnings, path+": "+note)
			}
		}
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

// staticGroupWarnings names the assignment groups and users entries that are
// spelled so they can never match, or match only by accident, without a
// lookup: a pattern (* or ?) in either; a malformed
// SID (S-1-5-21-malformed); outside Windows, any SID, as account group
// lists hold names there; and outside Windows a number, which matches only a
// group the directory left unnamed. Setup and ensure accepted them in
// silence, and everyone fell to default_profile (GAP-0306, GAP-0409).
func staticGroupWarnings(assignments []config.ProfileAssignment, platform string) []string {
	check := "id -Gn <user>"
	if platform == "darwin" {
		check = "id -Gn <user> or dscl . -list /Groups"
	}
	var warnings []string
	for i, assignment := range assignments {
		// A users entry is an account name, compared literally: "*" selected
		// nobody, and ensure accepted it in silence while the same groups
		// entry warned (GAP-0497).
		for _, user := range assignment.Match.Users {
			if user = strings.TrimSpace(user); assignmentWildcard(user) {
				warnings = append(warnings, fmt.Sprintf("assignment %d: users entry %q is not a pattern: entries name accounts "+
					"literally, and no account name holds * or ?, so it selects nobody; list the accounts, name a group they share, "+
					"or set default_profile for everyone no assignment selects", i+1, user))
			}
		}
		for _, group := range assignment.Match.Groups {
			group = strings.TrimSpace(group)
			switch {
			case group == "":
			case assignmentWildcard(group):
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not a pattern: entries name groups literally, "+
					"and no group name holds * or ?, so it selects nobody; name the group, or set default_profile for everyone "+
					"no assignment selects", i+1, group))
			case strings.HasPrefix(strings.ToUpper(group), "S-1-") && !validSIDString(group):
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not a valid SID (S-1-<authority>-<sub-authority>...), "+
					"so it selects nobody; correct it, or name the group", i+1, group))
			case platform != "windows" && strings.HasPrefix(strings.ToUpper(group), "S-1-"):
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is a Windows SID, which selects nobody on this host: "+
					"account groups are names here; write the group name as %s lists it", i+1, group, check))
			case platform != "windows" && strings.Trim(group, "0123456789") == "":
				warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is a group id: it matches only while no name answers "+
					"for that group, so it selects nobody once the directory names it; write the group name as %s lists it", i+1, group, check))
			}
		}
	}
	return warnings
}

// assignmentWildcard reports an assignment entry written as a pattern.
// Directory account and group names cannot hold * or ? (Active Directory
// refuses both, as do Unix account names), so such an entry matches nothing.
func assignmentWildcard(entry string) bool {
	return strings.ContainsAny(entry, "*?")
}

// entraGroupSID reports whether s is an Entra ID group or user SID
// (S-1-12-1-...), which only a host joined to that tenant can name.
func entraGroupSID(s string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), "S-1-12-1-")
}

// validSIDString reports whether s has the SID string form: S-1, an
// identifier authority, and one to fifteen sub-authorities, all decimal.
func validSIDString(s string) bool {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(s)), "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return false
	}
	for _, part := range parts[2:] {
		if part == "" || len(part) > 15 || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

// unnamedGroupsNote says when some of the explained account's groups are
// only numbers. The Unix resolver keeps a group id as its number when no
// group answers for it, which is what a directory that does not answer
// leaves behind: the account then has too few groups for its assignments to
// match, and nothing else in the answer shows it (GAP-0212). On standalone
// Windows (sids, the SIDs of the assignment group names) an assignment
// matches the SID of the group it names, so a group shown only by its SID
// still matches it, and the note does not say otherwise (GAP-1141).
func unnamedGroupsNote(subject *profileSubject, sids *profileGroupSIDs) string {
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
	if sidForm && sids != nil {
		return fmt.Sprintf("%d of this account's %d group(s) have no name, only a SID (the guardian names at most 128 groups per account within 2 s, "+
			"or the SID does not resolve); assignments match groups by SID, so this changes only how they are shown", unnamed, total)
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
// that fails or runs out of time proves no absence: only a definite absence
// warns. Requests whose assignments need an unresolved group are refused and
// name the missing fact.
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
	profileGroupCheckTTL = time.Minute
	// profileGroupCheckRetry is how long a pass the directory did not answer
	// in time is kept: a slow directory at gateway start or reload must not
	// hide the warnings for the whole TTL (GAP-2434).
	profileGroupCheckRetry = 10 * time.Second
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

// profileGroupCheckBudget bounds one pass over a set's groups; a variable so
// tests can give a pass less time.
var profileGroupCheckBudget = 3 * time.Second

// profileGroupCheck is the last pass over a set's groups, and the pass in
// flight.
type profileGroupCheck struct {
	mu        sync.Mutex
	checked   bool
	checkedAt time.Time
	// keep is how long the last pass is kept: profileGroupCheckTTL, or
	// profileGroupCheckRetry for a pass that ran out of time.
	keep     time.Duration
	warnings []string
	running  chan struct{}
}

// unknownGroupWarnings returns one warning per assignment group the host
// does not know, from a pass at most profileGroupCheckTTL old. A pass runs in
// the background, so a command never waits for the directory: it gets the last
// pass, or, before the first has finished, waits for it at most wait.
func (set *guardrailProfileSet) unknownGroupWarnings(wait time.Duration) []string {
	if set != nil && runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
		return perUserWindowsGroupWarnings(set.assignments)
	}
	return set.unknownGroupWarningsWith(profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent, profileUserEntryUnmatched(),
		directoryCacheHealth, wait)
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
	silent func(context.Context) bool, unmatchedUser func(context.Context, string) string, health func() identityCacheHealth,
	wait time.Duration) []string {
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
	if (!check.checked || time.Since(check.checkedAt) >= check.keep) && check.running == nil {
		done := make(chan struct{})
		check.running = done
		budget := profileGroupCheckBudget
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			known := exists
			if set.groupSIDs != nil {
				known = func(ctx context.Context, name string) (bool, error) {
					if sid, ok := set.groupSIDs.sid(name); ok && validSIDString(sid) {
						return true, nil
					}
					return exists(ctx, name)
				}
			}
			warnings := unknownAssignmentGroups(ctx, set.assignments, known, qualify, silent)
			warnings = append(warnings, unmatchedUserEntries(ctx, set.assignments, unmatchedUser)...)
			keep := profileGroupCheckTTL
			if ctx.Err() != nil {
				keep = profileGroupCheckRetry
			}
			cancel()
			warnings = append(warnings, spoolUPNAssignmentWarnings(set.assignments, time.Now())...)
			failing := health().Failing > 0
			if failing {
				warnings = nil
			}
			check.mu.Lock()
			previous, wasChecked := check.warnings, check.checked
			check.warnings, check.checked, check.checkedAt, check.keep, check.running = warnings, !failing, time.Now(), keep, nil
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

// groupCheckPending reports a set whose first group and users check is still
// running, so its warnings are not known yet.
func (set *guardrailProfileSet) groupCheckPending() bool {
	if set == nil {
		return false
	}
	set.groupCheck.mu.Lock()
	defer set.groupCheck.mu.Unlock()
	return !set.groupCheck.checked && set.groupCheck.running != nil
}

// logProfileWarnings writes connector warnings and unknown-group warnings to the gateway log in the
// background; the gateway calls it for a new set at start and at each reload.
func (set *guardrailProfileSet) logProfileWarnings() {
	for _, warning := range set.unknownConnectorWarnings() {
		fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
	}
	exists, qualify, silent, unmatchedUser, health := profileGroupExists, profileGroupQualifiedName, bareGroupsDirectorySilent,
		profileUserEntryUnmatched(), directoryCacheHealth
	go func() {
		if runtime.GOOS == "windows" && set.base != nil && !set.base.StandaloneEnterprise() {
			for _, warning := range perUserWindowsGroupWarnings(set.assignments) {
				fmt.Fprintf(os.Stderr, "[guardrail] %s\n", warning)
			}
			return
		}
		for _, warning := range set.unknownGroupWarningsWith(exists, qualify, silent, unmatchedUser, health, profileGroupCheckBudget+time.Second) {
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
// directorySilent, when set, reports that the directory does not answer at
// all, which is how a bare name the host does not know is told from a deleted
// one: a bare name has no domain whose Domain Users group could be asked
// (GAP-1090).
func unknownAssignmentGroups(ctx context.Context, assignments []config.ProfileAssignment, exists func(context.Context, string) (bool, error),
	qualify func(context.Context, string) string, directorySilent func(context.Context) bool) []string {
	return unknownAssignmentGroupsForOS(ctx, assignments, exists, qualify, directorySilent, runtime.GOOS)
}

func unknownAssignmentGroupsForOS(ctx context.Context, assignments []config.ProfileAssignment, exists func(context.Context, string) (bool, error),
	qualify func(context.Context, string) string, directorySilent func(context.Context) bool, platform string) []string {
	type unknownGroup struct {
		assignment    int
		group, domain string
	}
	var unknown []unknownGroup
	var warnings []string
	respelled := map[string]string{} // by folded name: the spelling the host lists a known qualified group under
	skippedLimit := false
	var unchecked []string        // "assignment N: group ...", for the groups the deadline left unchecked
	absent := map[string]bool{}   // by folded name; present for every group looked up
	answered := map[string]bool{} // by folded domain: the host knows a group of it
	for i, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			group = strings.TrimSpace(group)
			if group == "" || strings.HasPrefix(strings.ToUpper(group), "S-1-") && (platform != "windows" || !validSIDString(group) || entraGroupSID(group)) ||
				strings.Trim(group, "0123456789") == "" || assignmentWildcard(group) {
				// staticGroupWarnings names these. An Entra group SID is left to
				// the sign-in token: the LSA cannot map it on a host outside that
				// tenant, yet the token still carries it, so a failed lookup does
				// not show that the assignment selects nobody. Other SIDs the LSA
				// cannot map (a deleted domain group) are still reported.
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
					unchecked = append(unchecked, fmt.Sprintf("assignment %d: group %q", i+1, group))
					continue
				}
				known, err := exists(ctx, norm.NFC.String(group))
				if err == nil && !known && platform != "windows" {
					// The matcher folds case; a host whose lookup does not
					// still knows the group by its lower-case name (GAP-0495).
					if lower := strings.ToLower(norm.NFC.String(group)); lower != norm.NFC.String(group) {
						if folded, ferr := exists(ctx, lower); ferr == nil && folded {
							known = true
						}
					}
				}
				if err != nil && ctx.Err() != nil {
					// The lookup ran out of time: not an answer, so the group
					// is named as not checked (GAP-2434).
					unchecked = append(unchecked, fmt.Sprintf("assignment %d: group %q", i+1, group))
					continue
				}
				dead = err == nil && !known
				absent[key] = dead
				if known {
					answered[foldKey(domain)] = true
					if qualify != nil && platform != "windows" && domain != "" {
						respelled[key] = qualify(ctx, norm.NFC.String(group))
					}
				}
			}
			if !dead && domain == "" && qualify != nil && platform != "windows" {
				// A bare name the host knows, next to a directory group of the
				// same name: the bare name is the local group (GAP-0356,
				// GAP-0306), and its warning says which group it selects.
				if listed := qualify(ctx, norm.NFC.String(group)); listed != "" && !useridentity.EqualFold(listed, group) {
					selects := "the members of the local group only, not of the directory group"
					if platform == "darwin" {
						selects = "the members of the local group as well as of the directory group"
					}
					warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is a local group of this host, and the directory "+
						"group of that name is listed as %q: the bare name selects %s; write %q to select the directory group only",
						i+1, group, listed, selects, listed))
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
	var quietDomains, quietBare []string
	bareSilent, bareAsked := false, false
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
		if platform != "windows" && u.domain == "" && directorySilent != nil {
			if !bareAsked {
				bareSilent, bareAsked = directorySilent(ctx), true
			}
			if bareSilent {
				quietBare = append(quietBare, fmt.Sprintf("assignment %d: group %q", u.assignment, u.group))
				continue
			}
		}
		warnings = append(warnings, fmt.Sprintf("assignment %d: group %q is not known to this host (renamed or deleted in the directory?), so it selects nobody", u.assignment, u.group))
	}
	if len(quietBare) > 0 {
		if len(quietBare) > profileQuietGroupsNamed {
			quietBare = append(quietBare[:profileQuietGroupsNamed:profileQuietGroupsNamed], fmt.Sprintf("%d more", len(quietBare)-profileQuietGroupsNamed))
		}
		warnings = append(warnings, fmt.Sprintf("could not check the groups %s: the directory does not answer for the directory "+
			"accounts this host knows, so a group it does not know now is not reported as renamed or deleted; %s",
			strings.Join(quietBare, ", "), directoryDownHint(platform)))
	}
	for _, domain := range quietDomains {
		named := quietGroups[foldKey(domain)]
		if len(named) > profileQuietGroupsNamed {
			named = append(named[:profileQuietGroupsNamed:profileQuietGroupsNamed], fmt.Sprintf("%d more", len(named)-profileQuietGroupsNamed))
		}
		warnings = append(warnings, fmt.Sprintf("could not confirm group names written for %s by this spelling (%s): renamed or "+
			"deleted in the directory, another domain prefix, or the lookup is unavailable, so these may select nobody; %s",
			domain, strings.Join(named, ", "), groupNameCheckHint(platform)))
	}
	if skippedLimit {
		warnings = append(warnings, fmt.Sprintf("group warning check incomplete: only the first %d distinct groups were checked; later assignment groups were not checked", profileGroupCheckMax))
	}
	if len(unchecked) > 0 {
		// Name the assignments and groups the check could not reach, as the
		// other notes do (GAP-0928, GAP-2434).
		if len(unchecked) > profileQuietGroupsNamed {
			unchecked = append(unchecked[:profileQuietGroupsNamed:profileQuietGroupsNamed], fmt.Sprintf("%d more", len(unchecked)-profileQuietGroupsNamed))
		}
		warnings = append(warnings, fmt.Sprintf("group warning check incomplete: the directory did not answer in time, so %s "+
			"were not checked and may select nobody; the check runs again within %s", strings.Join(unchecked, ", "), profileGroupCheckRetry))
	}
	return warnings
}

// groupNameCheckHint names the command that shows how this host spells a
// group: getent on Linux. macOS has no getent: an account's groups are listed
// by id -Gn, as DOMAIN\name for an Active Directory group of a bound Mac,
// and one group by dseditgroup (GAP-1107).
func groupNameCheckHint(platform string) string {
	if platform == "darwin" {
		return `check the exact name with id -Gn <user> (an Active Directory group reads DOMAIN\name) or dseditgroup -o read <group>; ` +
			`after a domain controller outage, sudo dscacheutil -flushcache; sudo dsmemberutil flushcache refreshes Open Directory`
	}
	return "check the qualified name with getent group"
}

// directoryUsesWinbind reports a Linux host whose groups come from winbind
// rather than SSSD (unixidentity.GroupDirectoryUsesWinbind on Linux and
// macOS); false elsewhere.
var directoryUsesWinbind = func() bool { return false }

// directoryDownHint says what to check while the directory does not answer:
// the directory service the host uses (GAP-0712: a winbind host was told to
// check SSSD).
func directoryDownHint(platform string) string {
	if platform == "darwin" {
		return "check the directory binding of this Mac (dsconfigad -show) and the domain controller; the groups are checked again once it answers"
	}
	if directoryUsesWinbind() {
		return "check winbind (wbinfo --ping-dc) and the domain controller; the groups are checked again once it answers"
	}
	return "check SSSD (sssctl domain-status <domain>) and its server; the groups are checked again once it answers"
}

// unmatchedUserEntries warns for each users entry that does not select the
// account the host resolves it to (unmatched says why, "" when the entry
// selects it or names no account): a DOMAIN\user whose domain the host does
// not confirm for that account (GAP-1095), or a bare name that names a local
// account, which a bare name never selects (GAP-0305). Its users get the next
// assignment or the default profile, and nothing else showed it.
func unmatchedUserEntries(ctx context.Context, assignments []config.ProfileAssignment, unmatched func(context.Context, string) string) []string {
	if unmatched == nil {
		return nil
	}
	var warnings []string
	checked := 0
	for i, assignment := range assignments {
		for _, entry := range assignment.Match.Users {
			entry = strings.TrimSpace(entry)
			if !userEntryNeedsAccountCheck(entry) {
				continue
			}
			if checked >= profileGroupCheckMax || ctx.Err() != nil {
				return warnings
			}
			checked++
			if why := unmatched(ctx, norm.NFC.String(entry)); why != "" {
				warnings = append(warnings, fmt.Sprintf("assignment %d: users entry %q %s", i+1, entry, why))
			}
		}
	}
	return warnings
}

// ProfileUserEntryWarnings names the users entries of assignments that do
// not select the account this host resolves them to, with the spelling that
// does (unmatchedUserEntries): a bare name of a local account, which a bare
// name never selects (GAP-0305), and a DOMAIN\user whose domain the host does
// not confirm. The running gateway reports the same sentences to status and
// verify (profile_assignment_unmatched); `config validate` reports them for a
// candidate before it is applied (GAP-0197). The lookups are the host's
// account database, bounded like the gateway's background check.
func ProfileUserEntryWarnings(ctx context.Context, assignments []config.ProfileAssignment) []string {
	ctx, cancel := context.WithTimeout(ctx, profileGroupCheckBudget)
	defer cancel()
	return unmatchedUserEntries(ctx, assignments, profileUserEntryUnmatched())
}

// userEntryNeedsAccountCheck reports a users entry that names an account by
// name: a bare name or DOMAIN\user. A uid, a SID, a principal or UPN (the
// spool check covers those) and .\user (a local account by definition) are
// not looked up.
func userEntryNeedsAccountCheck(entry string) bool {
	if entry == "" || useridentity.KindForID(entry) != "" || strings.Contains(entry, "@") || strings.HasPrefix(entry, `.\`) ||
		assignmentWildcard(entry) {
		return false
	}
	domain, account, qualified := strings.Cut(entry, `\`)
	return !qualified || domain != "" && account != ""
}

// profileUserEntryUnmatched returns the check unmatchedUserEntries runs. It
// resolves the entry the way profile-explain resolves an account and asks the
// matcher itself (userEntryMatches) whether the entry selects it, so the
// warning cannot disagree with requests and explain: a dclab.test\ent-alice
// entry was reported as selecting nobody while explain and the hooks selected
// ent-alice by it, because the warning compared the domain with its own rule
// (GAP-0310, GAP-0395). A DOMAIN\user spelling the account database does not
// take is resolved by its account part, the account the matcher compares
// the domain of. It answers "" when the entry selects the account or a lookup
// fails, and takes the lookups when it is made, since the background pass
// can outlive its caller.
func profileUserEntryUnmatched() func(context.Context, string) string {
	lookupAccount, lookupFacts, unresolved := profileExplainAccount, profileExplainDirectoryFacts, profileUserEntryUnresolved()
	resolve := func(name string) (*profileSubject, error) {
		id, userName, err := lookupAccount(name)
		if err != nil || id == "" {
			return nil, err
		}
		facts, err := lookupFacts(id)
		if err != nil || facts.ResolvedAt.IsZero() {
			return nil, nil // the account's facts are unknown: say nothing
		}
		subject := profileSubjectFromVerified(VerifiedSubject{
			UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
		}, false)
		return &subject, nil
	}
	return func(ctx context.Context, entry string) string {
		entry = strings.TrimSpace(entry)
		if !userEntryNeedsAccountCheck(entry) || ctx.Err() != nil {
			return ""
		}
		domain, account, qualified := strings.Cut(entry, `\`)
		subject, err := resolve(entry)
		if err != nil && qualified {
			if bare, bareErr := resolve(account); bareErr == nil && bare != nil {
				subject, err = bare, nil
			}
		}
		if err != nil {
			if qualified {
				return unresolved(ctx, domain, err)
			}
			return ""
		}
		if subject == nil || userEntryMatches(subject, entry) {
			return ""
		}
		return userEntryMismatch(subject, domain, qualified)
	}
}

// userEntryMismatch says why a users entry does not select the account it
// resolves to.
func userEntryMismatch(subject *profileSubject, domain string, qualified bool) string {
	id := "uid " + subject.UserID
	if subject.IDKind == useridentity.KindWindowsSID {
		id = "SID " + subject.UserID
	}
	switch {
	case !qualified && subject.localAccount:
		return fmt.Sprintf("names the local account %s (%s) of this host, which a bare name does not select: a bare name "+
			"selects directory accounts only; write .\\%s or the %s to select the local account",
			subject.UserName, id, subject.UserName, strings.Fields(id)[0])
	case !qualified:
		return fmt.Sprintf("names %s, an account whose domain this host does not confirm, which only its %s selects, so the "+
			"entry selects nobody; write the %s", id, strings.Fields(id)[0], strings.Fields(id)[0])
	}
	confirmed := firstNonEmpty(subject.AccountDomain, subject.Domain)
	if confirmed == "" {
		return fmt.Sprintf("names %s, but this host confirms no domain for that account, so it selects nobody; write the %s",
			id, strings.Fields(id)[0])
	}
	return fmt.Sprintf("names %s, but this host confirms that account's domain as %s, not %s, so it selects nobody; write "+
		"the domain this host confirms, or the %s", id, confirmed, domain, strings.Fields(id)[0])
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
// domain, so the entry meant for alice@corp.example.com also selects an
// alice of another directory domain (GAP-0182); it never selects a local
// account (GAP-0305).
func shortNameUserNote(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) string {
	if set == nil || subject == nil || decision.Assignment < 1 || decision.Assignment > len(set.assignments) ||
		subject.Domain == "" || subject.localAccount {
		return ""
	}
	for _, entry := range set.assignments[decision.Assignment-1].Match.Users {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.ContainsAny(entry, `@\`) || !userEntryMatches(subject, entry) ||
			strings.EqualFold(entry, subject.UserID) || ambiguousBareUserEntry(subject, entry) {
			continue
		}
		qualified := firstNonEmpty(subject.UPN, subject.Principal, subject.UserID)
		return fmt.Sprintf("assignment %d selects this account by the short name %q, so it selects a directory account of that name "+
			"in another domain too (never a local account); write %s (or the uid) to select only this account", decision.Assignment, entry, qualified)
	}
	return ""
}

func ambiguousShortNameUserNote(set *guardrailProfileSet, decision profileDecision, subject *profileSubject) string {
	if set == nil || subject == nil {
		return ""
	}
	qualified := firstNonEmpty(subject.UPN, subject.Principal)
	if qualified == "" {
		qualified = subject.UserID
	}
	refused := slices.Contains(decision.Unproven, "account:ambiguous_short_name")
	for i, assignment := range set.assignments {
		for _, entry := range assignment.Match.Users {
			if !ambiguousBareUserEntry(subject, entry) {
				continue
			}
			entry = strings.TrimSpace(entry)
			// Name every account the entry selects that the guardian has a
			// record for; the namesakes of a domain it has not seen yet are
			// named by their domain only (GAP-0725).
			var accounts []string
			own := false
			for _, record := range sssdADNamesakes(profileShortNameRecords(), entry) {
				own = own || record.Key == subject.UserID
				accounts = append(accounts, fmt.Sprintf("%s (uid %s)", firstNonEmpty(record.Facts.UPN, record.Facts.Principal, record.User), record.Key))
			}
			if !own {
				accounts = append([]string{fmt.Sprintf("%s (uid %s)", firstNonEmpty(subject.UPN, subject.Principal, subject.UserName), subject.UserID)}, accounts...)
			}
			if len(accounts) == 1 {
				accounts = append(accounts, fmt.Sprintf("the account named %s in each other trusted domain", entry))
			}
			if refused {
				return fmt.Sprintf("assignment %d uses the ambiguous short name %q, which names %s; the strict policy tier refuses it: write %s (or uid %s) to select only this account",
					i+1, entry, strings.Join(accounts, " and "), qualified, subject.UserID)
			}
			return fmt.Sprintf("assignment %d uses the ambiguous short name %q, which selects %s; write %s (or uid %s) to select only this account",
				i+1, entry, strings.Join(accounts, " and "), qualified, subject.UserID)
		}
	}
	return ""
}

func shortNameGroupNote(decision profileDecision) string {
	group := strings.TrimSpace(decision.MatchedGroup)
	if decision.Match != profileMatchGroup || group == "" || strings.ContainsAny(group, `@\`) ||
		strings.HasPrefix(strings.ToUpper(group), "S-1-") || strings.Trim(group, "0123456789") == "" {
		return ""
	}
	if runtime.GOOS != "windows" {
		return fmt.Sprintf("assignment %d selects this account by bare group %q, which can also match a same-named group in another domain or a local group of this host (matched_group_source says which this account is in); configure distinct group names and use the exact group name reported by this host", decision.Assignment, group)
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
// `explain --user` takes an account's facts from the cache requests read,
// after a lookup of its own that refreshes them (explainDirectoryFacts), so
// it reports what requests get from then on. explainCacheView puts the
// cache's side next to the answer: the age of the facts, whether the lookup
// failed and requests keep older facts (GAP-0361), and the profile requests
// get when it is not the one above, as when the gateway's lookups fail and
// it holds no facts (GAP-0134, GAP-0212).

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

// cachedDirectoryRefreshFailure reports an account whose latest lookups fail
// while its requests still use the facts cached before them. Tests replace
// it.
var cachedDirectoryRefreshFailure = func(id string) (time.Time, string, bool) {
	return peerDirectoryCache().refreshFailing(id)
}

// explainCacheOutcome is what live gives the account's requests, for an
// explain warning: a refusal and its reason, or a profile and its match.
func explainCacheOutcome(live profileDecision) string {
	if live.Refused != "" {
		return "are refused (" + live.Refused + ")"
	}
	return fmt.Sprintf("get profile %s (match %s)", firstNonEmpty(live.Name, "none"), live.Match)
}

// explainCacheView describes the cached facts of the explained account: how
// old they are, and the profile requests currently get from them. warning is
// non-empty when that profile differs from the explained one.
func explainCacheView(set *guardrailProfileSet, explained *profileSubject, decision profileDecision, connectorName, agent string, now time.Time) (view map[string]any, warning string) {
	return explainCacheViewOf(set, explained, decision, connectorName, agent, nil, now)
}

// explainCacheViewOf is explainCacheView for the agent explain matched and
// its 1.0.3 claim (explainAgent), so the live view decides an agent as the
// hook does (GAP-0019).
func explainCacheViewOf(set *guardrailProfileSet, explained *profileSubject, decision profileDecision, connectorName, agent string, legacy profileAgentLegacy, now time.Time) (view map[string]any, warning string) {
	if set == nil || explained == nil || explained.UserID == "" || explained.LookupFailed {
		return nil, ""
	}
	facts, fetchedAt, ok := cachedDirectoryFacts(explained.UserID)
	if !ok {
		// No facts are cached. When the gateway's own lookups for the account
		// fail, requests whose assignments need the missing facts are refused
		// and name them, regardless of this fresh lookup (GAP-0212).
		since, reason, failing := cachedDirectoryFailure(explained.UserID)
		if !failing {
			return nil, ""
		}
		failed := profileSubject{UserID: explained.UserID, IDKind: explained.IDKind, UserName: explained.UserName, LookupFailed: identityLookupBlocking.Load()}
		live, sandboxRefused := set.explainLiveDecision(&failed, connectorName, agent, legacy)
		differs := live.Name != decision.Name || live.Match != decision.Match || live.Refused != decision.Refused
		view = map[string]any{
			"failing_since": since.UTC().Format(time.RFC3339),
			"last_error":    reason,
			"profile":       live.Name,
			"match":         live.Match,
			"refused":       live.Refused != "",
			"differs":       differs,
		}
		if live.Refused != "" {
			view["refused_reason"] = live.Refused
		}
		if sandboxRefused != "" {
			view["sandbox_refused"] = true
			view["sandbox_refused_reason"] = sandboxRefused
		}
		if differs {
			warning = fmt.Sprintf("requests of this account currently %s: the gateway's directory lookup for it has failed since %s (%s) "+
				"and is retried every %s; rerun explain after a successful lookup to see the proven profile",
				explainCacheOutcome(live), since.UTC().Format("15:04:05Z"), reason, identityDirectoryRetry)
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
	live, sandboxRefused := set.explainLiveDecision(&cached, connectorName, agent, legacy)
	differs := live.Name != decision.Name || live.Match != decision.Match || live.MatchedGroup != decision.MatchedGroup ||
		live.Refused != decision.Refused
	view = map[string]any{
		"age_seconds":           int(age.Seconds()),
		"refresh_after_seconds": int(refresh.Seconds()),
		"profile":               live.Name,
		"match":                 live.Match,
		"refused":               live.Refused != "",
		"differs":               differs,
	}
	if live.Refused != "" {
		view["refused_reason"] = live.Refused
	}
	if sandboxRefused != "" {
		view["sandbox_refused"] = true
		view["sandbox_refused_reason"] = sandboxRefused
	}
	if differs {
		warning = fmt.Sprintf("requests of this account still use the directory facts the gateway fetched %s ago, so they %s; "+
			"rerun explain after the next successful refresh to see the proven profile. The gateway refreshes within %s; restart it to refresh now",
			age, explainCacheOutcome(live), refresh)
	}
	// The lookup explain started failed: the answer above, like the
	// account's requests, comes from the facts cached before (GAP-0361). An
	// account the directory cannot name at all has its own note
	// (cachedFactsAge).
	if since, reason, failing := cachedDirectoryRefreshFailure(explained.UserID); failing && explained.cachedFactsAge == 0 {
		view["stale"] = true
		view["failing_since"] = since.UTC().Format(time.RFC3339)
		view["last_error"] = reason
		// The hour counts from the lookup that fetched the facts, which can
		// be up to a refresh interval before the outage began (GAP-0517).
		note := fmt.Sprintf("the gateway's directory lookup for this account has failed since %s (%s): this answer, like the account's "+
			"requests, uses the identity facts cached %s ago, which are kept for up to %s after that lookup (until %s) while lookups fail",
			since.UTC().Format("15:04:05Z"), reason, age, identityDirectoryMaxAge, fetchedAt.Add(identityDirectoryMaxAge).UTC().Format("15:04:05Z"))
		if runtime.GOOS == "darwin" && currentIdentitySpoolDir() != "" {
			// openDirectoryGroupsUnavailable (GAP-0496, GAP-0517)
			note += ", or until the hook guardian's identity record of the account expires, an hour after the guardian last reached the directory"
		}
		warning = strings.TrimSpace(warning + " " + note)
	}
	return view, warning
}

// Directory lookups that fail.
//
// A directory that does not answer (a domain controller down, SSSD offline)
// leaves no trace on the tools an administrator uses: the accounts without
// cached facts refuse requests whose assignments need the missing facts and
// name them; the only sign was that refusal on each record. directoryHealthView reports the
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
	message = fmt.Sprintf("directory lookups are failing for %d account(s) since %s (last error: %s); requests whose assignments need missing facts "+
		"are refused (default_lookup_failed), and each refusal names the missing fact", h.Failing, h.Since.UTC().Format("15:04:05Z"), h.LastError)
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
