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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// profileListRegistryKey is the Windows registry key that holds one
// subkey per local user profile. Each subkey's name IS a stringified
// SID (e.g. "S-1-5-21-1234-567-89-1001"); its `ProfileImagePath`
// REG_SZ / REG_EXPAND_SZ value is the profile's on-disk home
// directory.
//
// See MS docs:
//
//	https://learn.microsoft.com/en-us/windows/win32/win7appqual/user-profile-service---policy
//
// The macOS analogue is `dscl . -list /Users UniqueID`; the shape is
// identical (one row per profile, keyed on SID vs. uid). Documented
// stable across Windows XP → Windows 11 / Server 2025.
const profileListRegistryKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// windowsHookConnectors is the closed set of hook-based connectors
// the Windows per-user hook installer supports today. The enumerator
// filters `cfg.Guardrail.Connector` + `cfg.Guardrail.Connectors` down
// to this set: an operator can list "openclaw" or "zeptoclaw" in the
// primary Connector field (they are proxy-only connectors) but the
// enumerator has nothing to install per-user for those, so it drops
// them.
//
// Kept in sync with the switch in
// `internal/cli/enterprise_hooks_platform_windows.go:
// windowsEnterpriseDesiredEnrollments` — if a third hook-based
// connector appears there, add it here too.
var windowsHookConnectors = map[string]struct{}{
	"claudecode": {},
	"codex":      {},
	"cursor":     {},
}

// EnumerateOptions controls a single enumeration cycle. All fields
// are optional.
type EnumerateOptions struct {
	// ExistingManifestPath, when non-empty, is loaded before
	// enumeration so per-target `AgentVersion` + `Enabled` state
	// carries over between cycles. This is the primary mechanism by
	// which the enumerator preserves admin-supplied fields it has no
	// independent way to discover: the enumerator DISCOVERS profile
	// membership, but AgentVersion for a given (SID, Connector) is
	// authoritative-in-file. If the file is unreadable / malformed /
	// missing, enumeration proceeds and rows start with empty
	// AgentVersion + `Enabled=false` (safe default — a new row
	// without a discovered agent version does not auto-hook the
	// user; the admin promotes it explicitly).
	//
	// Callers that want to force a from-scratch generation (e.g. a
	// targeted-uninstall regeneration after the target user's rows
	// have been removed) leave this empty.
	ExistingManifestPath string

	// ExcludeSIDs is a list of SID strings to drop from the output.
	// Used by the targeted uninstall to regenerate the
	// manifest with a specific user excluded, without doing per-row
	// surgery on the on-disk file.
	ExcludeSIDs []string

	// Logger receives one line per filter-drop / warn event. Nil
	// silences all diagnostics.
	Logger EnumerationLogger

	// IncludeUsers, ExcludeUsers and ExemptUsers carry
	// enterprise.enrollment for the standalone profile. Entries match a
	// profile by SID, profile directory name, or account name (user or
	// DOMAIN\user), case-insensitively; exclusion wins.
	//
	// IncludeUsers is additive, as on Linux and macOS: it never excludes
	// anyone. Every interactive profile in ProfileList is already a
	// candidate on Windows, so it adds no filtering here.
	//
	// ExcludeUsers drops the profile's rows. ExemptUsers keeps the rows of
	// the machine-policy connectors (claudecode, codex, cursor, copilot),
	// whose hooks fail closed for an unregistered SID, so an exempt user is
	// still inspected and logged there; the per-user connectors that write
	// into the user's own agent configs get no new rows, and rows already
	// enrolled are kept so their registration is not left to fail closed.
	//
	// A name-form entry needs the account name. When LookupAccountSid fails
	// (for example a domain controller outage), the profile's existing rows
	// are kept unchanged and no new rows are added; a lookup failure never
	// revokes a user.
	IncludeUsers []string
	ExcludeUsers []string
	ExemptUsers  []string

	// IncludeGroups and ExcludeGroups carry enterprise.enrollment's group
	// filters for the standalone profile (enrollment_groups_windows.go):
	// exclusion wins, include_groups admits only members, and a profile
	// whose membership is unknown (a directory user who has not signed in
	// since DefenseClaw was installed) is left undecided, like a failed
	// account-name lookup: pending, never revoked.
	IncludeGroups []string
	ExcludeGroups []string
	// GroupCache is the membership cache the caller keeps between cycles;
	// the standalone enumerator updates it in place. Nil starts empty.
	GroupCache *WindowsEnrollmentGroupCache
	// ReportUnprotected receives each agent the standalone enumerator found
	// installed for an eligible profile but could not enroll.
	ReportUnprotected func(UnprotectedAgent)
	// ReportExcluded receives each profile the standalone enrollment
	// excludes (exclude_users or exclude_groups), with its SID and home, so
	// the cycle can take the gateway's inventory read access off it
	// (GAP-1024).
	ReportExcluded func(ManifestTarget)
	// RunningAgents names, by account SID and connector, an agent session
	// the cycle saw running (a label such as "codex (pid 4242)"). The
	// standalone enumerator reports, through ReportUnprotected, a running
	// agent of an enabled connector that no row enrolls and no other report
	// names: an install discovery cannot read is then never a silent gap
	// while status and verify say security_complete (GAP-0226).
	RunningAgents map[string]map[string]string
	// ManifestSubjects, under enterprise.enrollment.mode: manifest, are the
	// administrator's enrolled accounts by canonical SID. Only they are
	// inspected, group filters do not apply to them, and one ProfileList
	// does not list is inspected at its authored home. Nil in auto mode.
	ManifestSubjects map[string]WindowsManifestSubject
}

// EnumerateWindows walks the local user profile registry (ProfileList),
// keeps only interactive-user profiles, and produces a Manifest matching the
// shape the hook-guardian's LoadManifest already accepts.
//
// Filter chain (each step drops the profile with a logf line if opts.Logger is set):
//
//  1. SID must be a syntactically-valid Windows SID string.
//  2. SID must be an interactive-user SID: either `S-1-5-21-…` (local
//     or domain user) or `S-1-12-1-…` (Microsoft Entra ID user).
//     Refuses well-known SIDs (Everyone S-1-1-0, Anonymous S-1-5-7,
//     SYSTEM S-1-5-18, Authenticated Users S-1-5-11, BUILTIN
//     S-1-5-32-*, NT SERVICE S-1-5-80-*, etc.) by construction.
//     Belt-and-braces on top of the CLI's target-SID validation.
//  3. ProfileImagePath registry value must resolve to an absolute
//     path under the local filesystem.
//  4. Home directory must exist as a real directory (not a reparse
//     point, junction, or symlink; `winpath.RejectReparseChain`
//     checks from the volume root down and refuses an ancestor before
//     reading anything below it).
//  5. `opts.ExcludeSIDs`: any SID listed here is dropped. Used by
//     the targeted uninstall.
//
// Deduplication: if two profiles have the same SID (e.g. a
// re-created account whose registry entry conflicts with a stale
// row), the enumerator prefers the one whose `ProfileImagePath`
// mtime is newer.
//
// AgentVersion + Enabled + Deferred preservation: for each (SID, Connector) row
// that already exists in `opts.ExistingManifestPath` (if set), the
// pre-existing AgentVersion + Enabled + Deferred fields are carried over. New
// rows — those discovered by the ProfileList walk that had no
// counterpart in the file — start with `Enabled: false` and empty
// AgentVersion so the guardian's LoadManifest skips schema-validation
// (which requires AgentVersion ≥ Windows minimum on enabled rows).
// An admin / UCB flow promotes the row to enabled by patching
// targets.yaml with a real AgentVersion. This preserves the security
// posture: a new user profile is DISCOVERED by the enumerator but
// only receives hooks when the admin explicitly promotes it.
//
// The standalone profile uses applyStandaloneRowState instead: new rows
// are written deferred, and discovery also covers the native Claude
// installer and machine-scope WinGet packages.
//
// Rows sorted by (SID, Connector) for deterministic YAML output —
// the byte-identical-no-op-no-write invariant in
// `WriteTargetsManifestAtomic` depends on stable serialisation.
func EnumerateWindows(ctx context.Context, cfg *config.Config, opts EnumerateOptions) (Manifest, error) {
	if cfg == nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: enumerate windows: nil config")
	}
	if ctx == nil {
		// A nil context is a caller bug — every real call comes
		// from the CLI subcommand that wraps a cycle in
		// context.WithTimeout. Use context.Background() as a
		// defensive fallback so we don't panic on a stray
		// unit-test invocation.
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	connectors := EffectiveWindowsHookConnectors(cfg)
	if len(connectors) == 0 {
		// No enabled hook-based connector → no per-user rows to
		// emit. Return an empty (but valid) manifest so the atomic
		// write path lands a `version: 1\ntargets: []` document
		// rather than a missing file — the guardian's LoadManifest
		// accepts an empty target list, and this keeps the on-disk
		// state well-defined during a mid-configuration window where
		// the operator has disabled every connector.
		return Manifest{Version: 1, Targets: []ManifestTarget{}}, nil
	}

	exclude := make(map[string]struct{}, len(opts.ExcludeSIDs))
	for _, sid := range opts.ExcludeSIDs {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			exclude[canon] = struct{}{}
		}
	}

	previous := loadPreviousManifestForEnumeration(opts.ExistingManifestPath, opts.Logger)

	// The standalone profile admits Microsoft Entra ID accounts and writes
	// newly discovered rows as deferred; the Secure Client profile keeps its
	// historical filter and row state exactly.
	standalone := cfg.StandaloneEnterprise()
	profiles, err := listWindowsUserProfiles(ctx, opts.Logger, standalone)
	if err != nil {
		return Manifest{}, err
	}
	if err := ctx.Err(); err != nil && !standalone {
		return Manifest{}, err
	}

	lookupAccount := newWindowsEnrollmentAccountLookup()
	// The standalone profile reads each active session's token once per
	// cycle: it tells which users can have a changed agent version followed
	// now, and carries their group membership.
	var sessions map[string][]string
	var sessionErr error
	var groups *windowsEnrollmentGroups
	if standalone {
		sessions, sessionErr = windowsActiveSessionGroups()
		if sessionErr != nil {
			logfSafely(opts.Logger, "sessions", fmt.Sprintf("the groups of some active sessions are unreadable; a user whose group decision rests on groups cached at an earlier sign-in keeps their rows and gets no new ones this cycle, and a user whose session was not listed keeps their agent versions: %v", sessionErr))
			if sessions == nil {
				sessions = map[string][]string{}
			}
		}
		groups = newWindowsEnrollmentGroups(opts.IncludeGroups, opts.ExcludeGroups, sessions, sessionErr, opts.GroupCache, opts.Logger)
		listed := make(map[string]struct{}, len(profiles))
		for _, profile := range profiles {
			listed[canonicalManifestTargetSID(profile.SID)] = struct{}{}
		}
		groups.pruneCache(listed)
	}
	// The users signed in now whose token groups were not read still have an
	// active session.
	unreadSessions, _ := windowsSessionGroupsInDoubt(sessionErr)
	running := map[string]map[string]string{}
	for sid, agents := range opts.RunningAgents {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			for conn, label := range agents {
				if running[canon] == nil {
					running[canon] = map[string]string{}
				}
				running[canon][strings.ToLower(strings.TrimSpace(conn))] = label
			}
		}
	}
	// The accounts whose running agents a profile pass below judged (or left
	// alone by the admin's choice). A running agent of any other account is
	// reported after the loop, so it never drops out of the record.
	judged := map[string]bool{}
	// visited holds the manifest subjects ProfileList listed.
	visited := map[string]bool{}
	signedIn := windowsSignedInCheck(opts.Logger)
	targets := make([]ManifestTarget, 0, len(profiles)*len(connectors))
	for profileIndex, profile := range profiles {
		// Leave time to write the manifest and coverage record. A timed-out
		// profile must never discard rows already decided in this cycle.
		if standalone && windowsPrivateProfileBudget(ctx, len(profiles)-profileIndex) <= 0 {
			reportWindowsProfilesNotInspected(profiles[profileIndex:], connectors, opts, exclude, previous, running, visited, judged, &targets)
			break
		}
		if err := ctx.Err(); err != nil {
			return Manifest{}, err // Secure Client keeps its existing behavior.
		}
		if _, skip := exclude[canonicalManifestTargetSID(profile.SID)]; skip {
			logfSafely(opts.Logger, profile.SID, "excluded by caller (targeted uninstall)")
			judged[canonicalManifestTargetSID(profile.SID)] = true
			continue
		}
		if opts.ManifestSubjects != nil {
			sid := canonicalManifestTargetSID(profile.SID)
			if _, enrolled := opts.ManifestSubjects[sid]; !enrolled {
				// Manifest enrollment: only the administrator's enabled
				// targets are enrolled, so no one else's installs count.
				reportWindowsUnenrolledManifestRunningAgents(profile, connectors, running[sid], opts.ReportUnprotected)
				judged[sid] = true
				continue
			}
			visited[sid] = true
		}
		if standalone && windowsDeletedLocalAccount(profile.SID, lookupAccount) {
			// A deleted local account whose profile folder could not be
			// removed (a hive another process still holds) kept its rows: the
			// guardian could never repair them, status failed and every
			// later Setup /ensure stopped at the activation evidence. No one
			// can sign in as it, so its rows are revoked now (GAP-0430). An
			// agent process that outlives the account is not judged here: it
			// is reported with its owner unknown after the loop (GAP-0556),
			// unless enterprise.enrollment.exclude_users names the account
			// (GAP-0673): the admin chose to leave it alone.
			// An excluded one is reported excluded like any other, so the
			// cycle removes its identity record and the gateway's read
			// access on its profile folder.
			if windowsEnrollmentListMatches(opts.ExcludeUsers, []string{profile.SID, filepath.Base(filepath.Clean(profile.Home))}) {
				judged[canonicalManifestTargetSID(profile.SID)] = true
				if opts.ReportExcluded != nil {
					opts.ReportExcluded(ManifestTarget{SID: profile.SID, UserHome: filepath.Clean(profile.Home)})
				}
			}
			logfSafely(opts.Logger, profile.SID,
				"the local account no longer exists; its rows are revoked although its profile folder remains")
			continue
		}
		decision, reason := windowsProfileEnrollmentDecision(profile, opts.ExcludeUsers, opts.ExemptUsers, lookupAccount)
		// An administrator-authored target is enrolled whatever the group
		// filters say; only exclude_users and exempt_users still apply.
		if (decision == windowsEnrollmentEnrolled || decision == windowsEnrollmentExempt) && groups.active() && opts.ManifestSubjects == nil {
			sid := canonicalManifestTargetSID(profile.SID)
			groupDecision, groupReason, inDoubt := groups.evaluate(sid)
			if inDoubt && (groupDecision != windowsEnrollmentExcluded || windowsHasPreviousRows(previous, sid)) {
				// The decision rests on groups cached at an earlier sign-in,
				// and the user may be signed in now with groups this cycle
				// could not read: nothing changes for them. Their rows stay,
				// they get no new ones, and a user without rows whom the
				// cache excludes stays excluded.
				groupDecision, groupReason = windowsEnrollmentUndecided, groups.inDoubtReason(sid)
			}
			if groupDecision != windowsEnrollmentEnrolled {
				decision, reason = groupDecision, groupReason
			}
		}
		if decision == windowsEnrollmentExcluded {
			logfSafely(opts.Logger, profile.SID, reason)
			judged[canonicalManifestTargetSID(profile.SID)] = true
			if opts.ReportExcluded != nil {
				opts.ReportExcluded(ManifestTarget{SID: profile.SID, UserHome: filepath.Clean(profile.Home)})
			}
			continue
		}
		if decision != windowsEnrollmentEnrolled {
			logfSafely(opts.Logger, profile.SID, reason)
		}
		_, sessionActive := sessions[canonicalManifestTargetSID(profile.SID)]
		sessionActive = sessionActive || unreadSessions[canonicalManifestTargetSID(profile.SID)]
		rowContext := windowsStandaloneRowContext{
			sessionActive: sessionActive,
			user:          filepath.Base(filepath.Clean(profile.Home)),
			report:        opts.ReportUnprotected,
		}
		if standalone && !sessionActive && !windowsRunsConnector(running[canonicalManifestTargetSID(profile.SID)], connectors) &&
			windowsDisabledLocalAccount(profile.SID, lookupAccount) && !signedIn(profile.SID) {
			// A disabled account cannot start a new session, but a session it
			// still has, active or disconnected, can still run its agents.
			// Suppress the stale warning only after the account has signed
			// out of every session (GAP-1034, GAP-1463) and no agent of an
			// enabled connector is left running for it (a scheduled task
			// outlives the sign-out, GAP-0556).
			logfSafely(opts.Logger, profile.SID,
				"the local account is disabled and has no session; its installed agents are not reported as unprotected")
			rowContext.report = nil
		}
		// The connectors this profile got a row or a report for, so a
		// running agent of any other enabled connector is reported below.
		covered := map[string]bool{}
		if report := rowContext.report; report != nil {
			rowContext.report = func(agent UnprotectedAgent) {
				covered[strings.ToLower(strings.TrimSpace(agent.Connector))] = true
				report(agent)
			}
		}
		if standalone && rowContext.report != nil {
			// A selected, supported CLI is not evidence that every copy
			// this account can launch reads the machine policy.
			profileCtx, cancel := context.WithTimeout(ctx, windowsPrivateProfileBudget(ctx, len(profiles)-profileIndex))
			reportWindowsPrivateInstalls(profileCtx, rowContext.report, rowContext.user, profile.SID, profile.Home, connectors)
			cancel()
		}
		for _, conn := range connectors {
			_, known := previous[previousManifestKey(profile.SID, conn)]
			// An exempt user gets no new per-user connector rows, but keeps the
			// ones already enrolled: dropping them would revoke the SID while
			// its hook registration stays in the user's own agent config and
			// fails closed as unregistered.
			if decision == windowsEnrollmentExempt && !windowsStandaloneMachinePolicyConnector(conn) && !known {
				covered[conn] = true
				continue
			}
			dataDir := filepath.Join(filepath.Clean(profile.Home), ".defenseclaw")
			row := ManifestTarget{
				SID:       profile.SID,
				UserHome:  filepath.Clean(profile.Home),
				Connector: conn,
				DataDir:   dataDir,
			}
			if decision == windowsEnrollmentUndecided && !known {
				// Pending: no new row. A signed-in user can run an agent
				// already installed, so it is reported, never a silent gap.
				if standalone {
					rowContext.pending(&row, reason)
				}
				continue
			}
			emit := false
			if standalone {
				emit = applyStandaloneRowStateFor(&row, previous, opts.Logger, rowContext)
			} else {
				emit = applyPreviousRowState(&row, previous, opts.Logger)
			}
			if !emit {
				// New (SID, Connector) row with no discoverable per-user
				// agent-version — dropped for macOS parity. The
				// enumerator's audit-complete summary reflects the
				// skip.
				continue
			}
			covered[conn] = true
			targets = append(targets, row)
		}
		judged[canonicalManifestTargetSID(profile.SID)] = true
		if standalone {
			reportUnenrolledRunningAgents(profile, connectors, running[canonicalManifestTargetSID(profile.SID)], covered, decision, reason, rowContext)
		}
	}
	if standalone {
		reportRunningAgentsOfUnknownOwners(running, judged, connectors, opts.ReportUnprotected)
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].SID != targets[j].SID {
			return targets[i].SID < targets[j].SID
		}
		return targets[i].Connector < targets[j].Connector
	})

	// A manifest subject ProfileList does not list as an interactive
	// profile is still enrolled: its authored home is inspected directly,
	// and an unreadable one is reported incomplete (GAP-0906).
	if opts.ReportUnprotected != nil {
		for _, sid := range sortedManifestSubjects(opts.ManifestSubjects) {
			if visited[sid] || windowsEnrollmentListMatches(opts.ExcludeUsers, []string{sid}) || windowsEnrollmentListMatches(opts.ExemptUsers, []string{sid}) {
				continue
			}
			subject := opts.ManifestSubjects[sid]
			user := filepath.Base(subject.Home)
			if windowsEnrollmentListMatches(opts.ExcludeUsers, []string{user}) || windowsEnrollmentListMatches(opts.ExemptUsers, []string{user}) {
				continue
			}
			judged[sid] = true
			if windowsPrivateProfileBudget(ctx, 1) <= 0 {
				for _, conn := range subject.Connectors {
					opts.ReportUnprotected(UnprotectedAgent{User: user, SID: sid, Connector: conn, Code: UnprotectedCodeInstallScanIncomplete,
						Reason: privateInstallIncompleteReason(PrivateInstallSkippedUnresolved)})
				}
				continue
			}
			if info, err := os.Lstat(subject.Home); err != nil || !info.IsDir() {
				if err == nil || !os.IsNotExist(err) {
					for _, conn := range subject.Connectors {
						opts.ReportUnprotected(UnprotectedAgent{User: user, SID: sid, Connector: conn, Code: UnprotectedCodeInstallScanIncomplete,
							Reason: privateInstallIncompleteReason(PrivateInstallSkippedHome)})
					}
				}
				continue // no profile folder yet: nothing the account could run
			}
			profileCtx, cancel := context.WithTimeout(ctx, windowsPrivateProfileBudget(ctx, 1))
			reportWindowsPrivateInstalls(profileCtx, opts.ReportUnprotected, user, sid, subject.Home, subject.Connectors)
			cancel()
		}
	}
	return Manifest{Version: 1, Targets: targets}, nil
}

// Reserve time for publishing targets and the coverage record. Divide the
// remaining inspection time among the profiles still in this cycle, so one
// large home cannot consume the entire 60-second Setup budget.
func windowsPrivateProfileBudget(ctx context.Context, profilesLeft int) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	const maximum = 20 * time.Second
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return maximum
	}
	available := time.Until(deadline) - 10*time.Second
	if available <= 0 {
		return 0
	}
	if profilesLeft < 1 {
		profilesLeft = 1
	}
	share := available / time.Duration(profilesLeft)
	if share > maximum {
		return maximum
	}
	return share
}

// Preserve rows already published for profiles the cycle could not reach,
// and name their incomplete inspection in the protected coverage record.
func reportWindowsProfilesNotInspected(profiles []windowsUserProfile, connectors []string, opts EnumerateOptions,
	exclude map[string]struct{}, previous map[string]ManifestTarget, running map[string]map[string]string,
	visited, judged map[string]bool, targets *[]ManifestTarget) {
	for _, profile := range profiles {
		sid := canonicalManifestTargetSID(profile.SID)
		user := filepath.Base(filepath.Clean(profile.Home))
		if _, skip := exclude[sid]; skip || windowsEnrollmentListMatches(opts.ExcludeUsers, []string{sid, user}) {
			judged[sid] = true
			continue
		}
		profileConnectors := connectors
		if opts.ManifestSubjects != nil {
			subject, enrolled := opts.ManifestSubjects[sid]
			if !enrolled {
				reportWindowsUnenrolledManifestRunningAgents(profile, connectors, running[sid], opts.ReportUnprotected)
				judged[sid] = true
				continue
			}
			visited[sid] = true
			profileConnectors = subject.Connectors
		}
		for _, conn := range profileConnectors {
			if row, known := previous[previousManifestKey(sid, conn)]; known {
				*targets = append(*targets, row)
			}
			if opts.ReportUnprotected != nil {
				opts.ReportUnprotected(UnprotectedAgent{User: user, SID: sid, Connector: conn,
					Code:   UnprotectedCodeInstallScanIncomplete,
					Reason: privateInstallIncompleteReason(PrivateInstallSkippedUnresolved)})
			}
		}
		judged[sid] = true
	}
}

// A manifest subject check does not inspect unselected profiles. A running
// agent there still needs an explicit coverage report before the SID is
// marked judged, including when the cycle has no profile time left.
func reportWindowsUnenrolledManifestRunningAgents(profile windowsUserProfile, connectors []string,
	running map[string]string, report func(UnprotectedAgent)) {
	if report == nil {
		return
	}
	for _, conn := range connectors {
		if label := strings.TrimSpace(running[conn]); label != "" {
			report(UnprotectedAgent{
				User: filepath.Base(filepath.Clean(profile.Home)), SID: profile.SID, Connector: conn,
				Code: UnprotectedCodeAgentUnprotected,
				Reason: fmt.Sprintf("%s runs for this account, which has no enabled enrollment manifest target; %s",
					label, windowsUnenrolledConsequence(conn)),
			})
		}
	}
}

// windowsHasPreviousRows reports whether the previous manifest has a row of
// the canonical SID sid.
func windowsHasPreviousRows(previous map[string]ManifestTarget, sid string) bool {
	prefix := sid + "\x00"
	for key := range previous {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// reportUnenrolledRunningAgents reports each agent session running for the
// profile whose connector is enabled but got no row and no other report this
// cycle: DefenseClaw found no install of it under the profile that it can
// read, so nothing enrolls the account and its tool calls are not decided by
// DefenseClaw.
func reportUnenrolledRunningAgents(
	profile windowsUserProfile,
	connectors []string,
	running map[string]string,
	covered map[string]bool,
	decision windowsEnrollmentDecision,
	decisionReason string,
	rowContext windowsStandaloneRowContext,
) {
	if len(running) == 0 || rowContext.report == nil {
		return
	}
	for _, conn := range connectors {
		label := strings.TrimSpace(running[conn])
		if label == "" || covered[conn] {
			continue
		}
		row := ManifestTarget{SID: profile.SID, UserHome: filepath.Clean(profile.Home), Connector: conn}
		reason := fmt.Sprintf("%s runs for this account, but no %s install DefenseClaw can read was found in this profile; %s",
			label, conn, windowsStandaloneInstallFix(conn))
		if decision == windowsEnrollmentUndecided {
			reason = fmt.Sprintf("%s runs for this account and its enrollment is pending: %s", label, decisionReason)
		}
		rowContext.unprotected(&row, "", reason)
	}
}

// windowsRunsConnector reports whether running lists an agent of one of
// connectors, the enabled ones.
func windowsRunsConnector(running map[string]string, connectors []string) bool {
	for _, conn := range connectors {
		if strings.TrimSpace(running[conn]) != "" {
			return true
		}
	}
	return false
}

// windowsSignedInCheck returns a check of whether a user has a session now,
// active or disconnected. The sessions are read once per cycle, at the first
// check; when they cannot be read, or a session's user cannot be identified,
// every user counts as signed in, so no warning is suppressed on a guess.
func windowsSignedInCheck(logf EnumerationLogger) func(sid string) bool {
	var users map[string]bool
	read, unreadable := false, false
	return func(sid string) bool {
		if !read {
			read = true
			var err error
			if users, err = windowsSignedInSessionUsers(); err != nil {
				unreadable = true
				logfSafely(logf, "sessions", fmt.Sprintf("signed-in sessions are unreadable; disabled accounts keep their unprotected-agent warnings this cycle: %v", err))
			}
		}
		return unreadable || users[canonicalManifestTargetSID(sid)]
	}
}

// windowsUnknownOwnerUser names the owner of a running agent whose account
// SID names no account a profile pass judged.
const windowsUnknownOwnerUser = "unknown"

// reportRunningAgentsOfUnknownOwners reports each running agent of an enabled
// connector whose interactive-user SID no profile pass judged: the account was
// deleted while the process kept running (its rows are revoked, GAP-0430), or
// no listed profile belongs to it. No row enrolls such an account, so the
// agent is recorded as unprotected with the owner unknown on every cycle the
// process is seen, and it drops out only when the process exits (GAP-0556).
// Service and other well-known SIDs are not user agent sessions.
func reportRunningAgentsOfUnknownOwners(running map[string]map[string]string, judged map[string]bool, connectors []string, report func(UnprotectedAgent)) {
	if report == nil || len(running) == 0 {
		return
	}
	sids := make([]string, 0, len(running))
	for sid := range running {
		if judged[sid] {
			continue
		}
		if !WindowsInteractiveUserSID(sid) {
			continue
		}
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	for _, sid := range sids {
		for _, conn := range connectors {
			label := strings.TrimSpace(running[sid][conn])
			if label == "" {
				continue
			}
			report(UnprotectedAgent{
				User:      windowsUnknownOwnerUser,
				SID:       sid,
				Connector: conn,
				Code:      UnprotectedCodeAgentUnprotected,
				Reason: fmt.Sprintf("%s runs as this SID, but it names no account DefenseClaw enrolls (the account was deleted while the process kept running, or no user profile is listed for it), so no row enrolls it; %s; it counts as unprotected until the process exits",
					label, windowsUnenrolledConsequence(conn)),
			})
		}
	}
}

// WriteTargetsManifestAtomic serialises `m` to YAML, compares it
// byte-for-byte to the on-disk file at `path`, and — if the two
// differ — writes the serialised bytes through a protected staging file and
// publishes it with the Windows replacement primitive that preserves the
// destination's exact protected DACL.
//
// Returns `changed=false, err=nil` when the on-disk file is
// byte-identical to the newly-serialised manifest. This is the
// no-op-no-write invariant: without it, every
// 5-min interval tick on a stable box would fsnotify-wake the
// guardian and force it to re-reconcile identical rows (288
// wakes/day on a stable 50-user fleet).
//
// Returns `changed=true, err=nil` on a successful atomic replace. Any staging
// or pre-publication failure returns changed=false and leaves a known-good
// destination untouched. A post-publication verification error returns
// changed=true with the error so callers do not mistake the durable byte
// change for a no-op.
//
// Both the parent and every published leaf must match the installer contract:
// Administrators owner/group and a protected, exact SYSTEM + Administrators
// FullControl DACL. Reparse points and multiply-linked files are rejected.
func WriteTargetsManifestAtomic(path string, m Manifest) (changed bool, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: empty path")
	}
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: path must be absolute: %s", path)
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := windowsTargetsManifestAncestorTrust(dir); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate hook guardian manifest parent ancestry: %w", err)
	}
	if err := ensureWindowsTargetsManifestParentProtected(dir); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate protected hook guardian manifest parent: %w", err)
	}

	serialised, err := marshalTargetsManifest(m)
	if err != nil {
		return false, err
	}

	destinationExists := false
	if _, statErr := os.Lstat(path); statErr == nil {
		destinationExists = true
		if err := validateWindowsTargetsManifestObject(path, false); err != nil {
			// Bulldoze: an existing manifest with a non-canonical owner or
			// DACL (left behind by a prior unsigned certification install
			// whose scoped guardian wrote it under a different token) must
			// be re-protected before the reconcile cycle gives up. Call
			// the authenticated protect helper (which has SeTakeOwnership /
			// SeRestore privilege from the LocalSystem guardian token) to
			// transfer ownership to Administrators and stamp the exact
			// AdminFile DACL. If the second validate still fails after
			// repair, propagate the original error.
			fmt.Fprintf(os.Stderr,
				"[enterprise-hooks] hook guardian manifest %s failed canonical "+
					"validation (%v); re-stamping before replace\n",
				path, err)
			if protectErr := windowsTargetsManifestProtect(path, false); protectErr != nil {
				return false, fmt.Errorf(
					"enterprise hooks: validate existing hook guardian manifest: %w (repair also failed: %v)",
					err, protectErr,
				)
			}
			if revalidateErr := validateWindowsTargetsManifestObject(path, false); revalidateErr != nil {
				return false, fmt.Errorf(
					"enterprise hooks: validate existing hook guardian manifest: %w (after repair: %v)",
					err, revalidateErr,
				)
			}
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: inspect existing manifest %s: %w", path, statErr)
	}
	current, readErr := os.ReadFile(path)
	if destinationExists && readErr == nil && bytes.Equal(current, serialised) {
		// Byte-identical: skip the write entirely so the guardian's
		// fsnotify watch does not wake. This is the primary
		// steady-state code path — a stable box hits it every tick.
		return false, nil
	}
	if destinationExists && readErr != nil {
		return false, fmt.Errorf("enterprise hooks: read existing manifest %s: %w", path, readErr)
	}
	if !destinationExists && readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: observe absent manifest %s: %w", path, readErr)
	}

	tmp, err := os.CreateTemp(dir, ".defenseclaw-targets-*.new")
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: create temp manifest under %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup is unconditional. A successful replacement consumes
	// tmpPath, and removing that now-absent name is harmless.
	defer func() { _ = os.Remove(tmpPath) }()
	if closeErr := tmp.Close(); closeErr != nil {
		return false, fmt.Errorf("enterprise hooks: close new temp manifest %s: %w", tmpPath, closeErr)
	}
	// Protect the empty staging object before prompt-adjacent manifest bytes
	// are written. The exact protected parent prevents an untrusted name swap.
	if err := windowsTargetsManifestProtect(tmpPath, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: protect temp manifest %s: %w", tmpPath, err)
	}
	tmp, err = os.OpenFile(tmpPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: reopen protected temp manifest %s: %w", tmpPath, err)
	}
	if _, writeErr := tmp.Write(serialised); writeErr != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: write temp manifest %s: %w", tmpPath, writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: sync temp manifest %s: %w", tmpPath, syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return false, fmt.Errorf("enterprise hooks: close temp manifest %s: %w", tmpPath, closeErr)
	}
	if err := validateWindowsTargetsManifestObject(tmpPath, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate protected temp manifest %s: %w", tmpPath, err)
	}
	if err := windowsTargetsManifestAncestorTrust(dir); err != nil {
		return false, fmt.Errorf("enterprise hooks: revalidate hook guardian manifest parent ancestry: %w", err)
	}
	if err := ensureWindowsTargetsManifestParentProtected(dir); err != nil {
		return false, fmt.Errorf("enterprise hooks: revalidate protected hook guardian manifest parent: %w", err)
	}
	// A destination can appear between the initial absence check and staging.
	// It must already be an exact AdminFile before ReplaceFileW may preserve it.
	if _, statErr := os.Lstat(path); statErr == nil {
		if err := validateWindowsTargetsManifestObject(path, false); err != nil {
			return false, fmt.Errorf("enterprise hooks: validate hook guardian manifest immediately before replace: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: inspect hook guardian manifest immediately before replace: %w", statErr)
	}
	if err := windowsTargetsManifestReplace(tmpPath, path); err != nil {
		return false, fmt.Errorf("enterprise hooks: atomic replace %s: %w", path, err)
	}
	if err := validateWindowsTargetsManifestObject(path, false); err != nil {
		return true, fmt.Errorf("enterprise hooks: validate published hook guardian manifest %s: %w", path, err)
	}
	return true, nil
}

// ensureWindowsTargetsManifestParentProtected is deliberately repair-on-drift,
// not stamp-on-every-tick. AVC may replace the DefenseClaw-owned parent ACL
// after installation; the LocalSystem enumerator can restore the exact
// AdminDirectory contract after first proving the ancestry and object shape.
// The no-op manifest path therefore remains a true no-write operation.
func ensureWindowsTargetsManifestParentProtected(path string) error {
	driftErr := validateWindowsTargetsManifestObject(path, true)
	if driftErr == nil {
		return nil
	}

	if err := windowsTargetsManifestProtect(path, true); err != nil {
		return fmt.Errorf(
			"repair protected hook guardian manifest parent: %w",
			errors.Join(driftErr, err),
		)
	}

	// Repair is never taken on trust: the caller previously reached staging only
	// behind a passing validation, so reconfirm the contract and surface the
	// original drift when the object still does not satisfy it.
	if err := validateWindowsTargetsManifestObject(path, true); err != nil {
		return fmt.Errorf(
			"repaired hook guardian manifest parent is still unprotected: %w",
			errors.Join(err, driftErr),
		)
	}

	return nil
}

// marshalTargetsManifest serialises the manifest to YAML with
// deterministic field ordering. yaml.Marshal is not guaranteed
// stable across releases, but for a struct with tagged fields the
// output is a function of the field-declaration order — which we
// control. `Manifest.Targets` is pre-sorted by (SID, Connector) in
// EnumerateWindows so this function is deterministic for the same
// input.
func marshalTargetsManifest(m Manifest) ([]byte, error) {
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Targets == nil {
		m.Targets = []ManifestTarget{}
	}
	raw, err := yaml.Marshal(&m)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: marshal manifest: %w", err)
	}
	return raw, nil
}

// loadPreviousManifestForEnumeration reads the on-disk manifest at
// `path`, returning a fast per-(SID, Connector) lookup that lets
// EnumerateWindows preserve `AgentVersion` + `Enabled` fields for
// rows that already exist. A missing file, a malformed body, and a
// well-formed empty file all return a nil map — the caller falls
// back to "new row" defaults for every discovered profile.
func loadPreviousManifestForEnumeration(path string, logf EnumerationLogger) map[string]ManifestTarget {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	m, err := LoadManifest(path)
	if err != nil {
		// Not fatal — an operator-hand-edited targets.yaml that
		// fails validation shouldn't crash the enumerator; we log
		// and treat every discovered row as new.
		logfSafely(logf, path, fmt.Sprintf("existing manifest failed to load; treating every row as new: %v", err))
		return nil
	}
	previous := make(map[string]ManifestTarget, len(m.Targets))
	for _, t := range m.Targets {
		key := previousManifestKey(t.SID, t.Connector)
		if key != "" {
			previous[key] = t
		}
	}
	return previous
}

// applyPreviousRowState resolves `row`'s AgentVersion + Enabled +
// Deferred + User/UID/GID for either a known-from-prior-manifest
// (SID, Connector) pair or a newly-discovered one.
//
// Returns `true` when the row should be emitted, `false` when the
// caller should drop it.
//
//   - Previously-known (SID, Connector): copy AgentVersion +
//     Enabled + Deferred + User/UID/GID from the prior row and
//     return true. Preserving the operator's prior Enabled
//     decision means a disabled prior row stays disabled, and an
//     enabled prior row stays enabled with its recorded
//     AgentVersion.
//   - Newly-discovered (SID, Connector): consult
//     `discoverWindowsAgentVersion` to see whether this user's
//     profile contains a supported per-user install of the
//     connector's CLI.
//   - If a version is discoverable: emit the row with
//     `Enabled: true`, `Deferred: false`, `AgentVersion: <found>`.
//     This is the auto-authorize path — parity with macOS
//     render-targets.sh, which emits enabled rows for any
//     (user × connector) whose CLI is present.
//   - If no version is discoverable: return false. The caller
//     drops the row entirely — parity with macOS, which never
//     emits a row for a user whose CLI is not installed.
//
// The historical "emit disabled, wait for admin Repair" branch is
// gone. Managed-enterprise deployments are admin-driven at the
// policy layer (which connectors are pushed, which SID
// membership), not the per-device authorization layer; the
// enumerator's job is discovery. See
// docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md residual-risk section for
// the new posture.
func applyPreviousRowState(row *ManifestTarget, previous map[string]ManifestTarget, logf EnumerationLogger) bool {
	if row == nil {
		return false
	}
	key := previousManifestKey(row.SID, row.Connector)
	version, reason := windowsAgentVersionExplain(row.UserHome, row.Connector)
	if version == "" && row.Connector == "copilot" {
		if copilot := windowsSecureClientCopilotVersion(row.UserHome, row.SID); copilot != "" {
			version, reason = copilot, ""
		}
	}
	if prev, ok := previous[key]; ok {
		// Secure Client preserves authorization, not stale compatibility
		// evidence (#1163). Every other profile keeps the recorded version,
		// so a version change goes through the install's contract gate.
		row.AgentVersion = prev.AgentVersion
		if secureClientHookDelivery() {
			row.AgentVersion = version
		}
		row.Enabled = prev.Enabled
		row.Deferred = prev.Deferred
		row.User = prev.User
		row.UID = prev.UID
		row.GID = prev.GID
		return true
	}
	// Secure Client admits an unversioned row on static presence evidence and
	// installs best-effort hooks for it (#1163); every other profile skips a
	// user × connector without version evidence.
	if version == "" && (!secureClientHookDelivery() || !windowsAgentPresence(row.UserHome, row.Connector)) {
		logfSafely(
			logf,
			row.SID,
			fmt.Sprintf(
				"newly-discovered (SID, %s) row skipped: %s",
				row.Connector,
				reason,
			),
		)
		return false
	}
	enabled := true
	row.AgentVersion = version
	row.Enabled = &enabled
	row.Deferred = false
	versionEvidence := version
	if versionEvidence == "" {
		versionEvidence = "unverified (static presence detected; best-effort hooks)"
	}
	logfSafely(
		logf,
		row.SID,
		fmt.Sprintf(
			"newly-discovered (SID, %s) row auto-authorized at version %s",
			row.Connector,
			versionEvidence,
		),
	)
	return true
}

// windowsEnrollmentDecision is enterprise.enrollment's verdict for one
// profile.
type windowsEnrollmentDecision int

const (
	windowsEnrollmentEnrolled windowsEnrollmentDecision = iota
	windowsEnrollmentExcluded
	windowsEnrollmentExempt
	// windowsEnrollmentUndecided means a name-form entry could not be
	// evaluated because the account name did not resolve: keep the
	// profile's existing rows, add none.
	windowsEnrollmentUndecided
)

// windowsStandaloneMachinePolicyConnector reports whether a connector's hook
// is machine policy on Windows, where an unregistered SID fails closed. An
// exempt user keeps these rows so they are inspected rather than blocked.
func windowsStandaloneMachinePolicyConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex", "cursor", "copilot":
		return true
	case "opencode":
		// The managed plugin runs for every user once OpenCode's machine
		// policy is in force.
		return windowsOpenCodeMachinePolicyInForce()
	default:
		return false
	}
}

// windowsEnrollmentAccountLookup resolves a profile SID to its account and
// domain names.
type windowsEnrollmentAccountLookup func(sid string) (account, domain string, err error)

var (
	// windowsEnrollmentLookupAccountSID is the LookupAccountSid seam.
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		parsed, err := windows.StringToSid(sid)
		if err != nil {
			return "", "", err
		}
		account, domain, _, err := parsed.LookupAccount("")
		return account, domain, err
	}
	// windowsEnrollmentLookupTimeout bounds one lookup, and
	// windowsEnrollmentLookupBudget all lookups of one cycle, so an
	// unreachable domain controller cannot stall the enumerator cycle.
	windowsEnrollmentLookupTimeout = 3 * time.Second
	windowsEnrollmentLookupBudget  = 15 * time.Second
)

// newWindowsEnrollmentAccountLookup returns one cycle's bounded lookup. The
// budget counts only time spent waiting on lookups, not the profile probing
// between them, so a slow host does not starve later profiles of a lookup a
// healthy domain controller would answer. Once the budget is spent, further
// lookups fail at once and their profiles keep their existing rows. A SID
// whose lookup of an earlier cycle has not returned fails at once without a
// new one (windowsEnrollmentAccountLookupGate), so one account the domain
// controller never answers for neither uses up every cycle's budget nor piles
// up native calls.
func newWindowsEnrollmentAccountLookup() windowsEnrollmentAccountLookup {
	var spent time.Duration
	return func(sid string) (string, string, error) {
		remaining := windowsEnrollmentLookupBudget - spent
		if remaining <= 0 {
			return "", "", errors.New("account name lookup budget for this cycle is exhausted")
		}
		if remaining > windowsEnrollmentLookupTimeout {
			remaining = windowsEnrollmentLookupTimeout
		}
		started := time.Now()
		defer func() { spent += time.Since(started) }()
		type result struct {
			account, domain string
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		defer cancel()
		lookup := windowsEnrollmentLookupAccountSID
		r, err := identityLookupGated(ctx, &windowsEnrollmentAccountLookupGate, strings.ToUpper(strings.TrimSpace(sid)), func(context.Context) (result, error) {
			account, domain, err := lookup(sid)
			if err == nil {
				// The sAMAccountName, also while its user is signed in with a
				// UPN, as the gateway names the account (GAP-0533).
				account = useridentity.CanonicalWindowsAccountName(sid, account, domain)
			}
			return result{account, domain}, err
		})
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return "", "", errors.New("account name lookup timed out")
		case err != nil:
			return "", "", err
		case strings.TrimSpace(r.account) == "":
			return "", "", errors.New("account name lookup returned no name")
		}
		return r.account, r.domain, nil
	}
}

// windowsEnrollmentAccountLookupGate holds the enrollment account name
// lookups, by SID.
var windowsEnrollmentAccountLookupGate identityLookupGate

// windowsDeletedLocalAccount reports a local account SID that no longer
// names an account. A domain or Entra account lookup also fails while its
// directory is unreachable, so only local accounts are judged, and only by
// ERROR_NONE_MAPPED (a timeout or a spent budget is not proof).
func windowsDeletedLocalAccount(sid string, lookup windowsEnrollmentAccountLookup) bool {
	if !WindowsLocalAccountSID(sid) {
		return false
	}
	_, _, err := lookup(sid)
	return errors.Is(err, windows.ERROR_NONE_MAPPED)
}

// windowsUserInfo1 is USER_INFO_1, the NetUserGetInfo level that carries
// the account flags.
type windowsUserInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// windowsUFAccountDisable is UF_ACCOUNTDISABLE.
const windowsUFAccountDisable = 0x0002

// windowsLocalAccountDisabled reports whether the local account named
// account is disabled (NetUserGetInfo); tests replace it.
var windowsLocalAccountDisabled = func(account string) (bool, error) {
	name, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return false, err
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, name, 1, &buf); err != nil {
		return false, err
	}
	defer windows.NetApiBufferFree(buf)
	return (*windowsUserInfo1)(unsafe.Pointer(buf)).Flags&windowsUFAccountDisable != 0, nil
}

// windowsDisabledLocalAccount reports a local account that exists but is
// disabled. Only local accounts are judged, and a failed lookup is no proof.
func windowsDisabledLocalAccount(sid string, lookup windowsEnrollmentAccountLookup) bool {
	if !WindowsLocalAccountSID(sid) {
		return false
	}
	account, _, err := lookup(sid)
	if err != nil || strings.TrimSpace(account) == "" {
		return false
	}
	disabled, err := windowsLocalAccountDisabled(account)
	return err == nil && disabled
}

// windowsProfileEnrollmentDecision applies enterprise.enrollment to one
// profile. Exclusion wins over exemption. SID and profile-directory entries
// are decided without a lookup; a name-form entry that did not already match
// needs the account name, and a failed lookup leaves the profile undecided
// instead of treating it as a non-match.
func windowsProfileEnrollmentDecision(
	profile windowsUserProfile,
	exclude, exempt []string,
	lookup windowsEnrollmentAccountLookup,
) (windowsEnrollmentDecision, string) {
	names := []string{profile.SID, filepath.Base(filepath.Clean(profile.Home))}
	if windowsEnrollmentListMatches(exclude, names) {
		return windowsEnrollmentExcluded, "excluded by enterprise.enrollment.exclude_users"
	}
	if windowsEnrollmentListNeedsAccountName(exclude, names) || windowsEnrollmentListNeedsAccountName(exempt, names) {
		account, domain, err := lookup(profile.SID)
		if err != nil {
			return windowsEnrollmentUndecided, fmt.Sprintf(
				"account name lookup failed (%v); enterprise.enrollment names cannot be evaluated, keeping the existing rows unchanged",
				err,
			)
		}
		names = append(names, account)
		if domain = strings.TrimSpace(domain); domain != "" {
			names = append(names, domain+`\`+account)
		}
		if windowsEnrollmentListMatches(exclude, names) {
			return windowsEnrollmentExcluded, "excluded by enterprise.enrollment.exclude_users"
		}
	}
	if windowsEnrollmentListMatches(exempt, names) {
		return windowsEnrollmentExempt, "exempt by enterprise.enrollment.exempt_users: machine-policy connectors only"
	}
	return windowsEnrollmentEnrolled, ""
}

func windowsEnrollmentListMatches(list, names []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		for _, name := range names {
			if strings.EqualFold(entry, strings.TrimSpace(name)) {
				return true
			}
		}
	}
	return false
}

// windowsEnrollmentListNeedsAccountName reports whether an entry that is not
// a SID string matched none of the names known without a lookup.
func windowsEnrollmentListNeedsAccountName(list, names []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(strings.ToUpper(entry), "S-1-") {
			continue
		}
		if !windowsEnrollmentListMatches([]string{entry}, names) {
			return true
		}
	}
	return false
}

func previousManifestKey(sid, connector string) string {
	sid = canonicalManifestTargetSID(sid)
	connector = strings.ToLower(strings.TrimSpace(connector))
	if sid == "" || connector == "" {
		return ""
	}
	return sid + "\x00" + connector
}

// windowsUserProfile is the trimmed view of a `ProfileList` subkey
// the enumerator needs. Kept package-private so the filter chain can
// vary without leaking implementation details into the exported API.
type windowsUserProfile struct {
	SID  string
	Home string
	// HomeMtime disambiguates duplicate-SID rows (newest wins); the
	// registry doesn't have direct time-of-registration for a
	// profile, but the ProfileImagePath directory's mtime is a
	// reasonable proxy (it changes whenever the profile is
	// materialised / logged into).
	HomeMtime int64
}

// WindowsStandaloneEligibleProfilesFor lists the interactive user profiles
// the standalone profile's enrollment admits, for guardian work that needs no
// per-user manifest row: a user whose connectors are all machine policy
// still gets foreign hooks removed from their user-level config. It applies
// the same decision EnumerateWindows does (windowsProfileEnrollmentDecision)
// with opts' user lists and group filters: include_users is additive and
// filters nothing, excluded profiles are skipped, and exempt profiles are
// kept because their machine-policy hooks still run the foreign-hook guard.
// A profile whose name-form entries cannot be evaluated (the account lookup
// failed), or whose group decision rests on cached groups an unreadable
// session token puts in doubt, is skipped this pass, so neither a directory
// outage nor a stale cache ever touches a user who may be excluded.
// opts.GroupCache is read, never changed: the enumerator is its only writer.
func WindowsStandaloneEligibleProfilesFor(ctx context.Context, opts EnumerateOptions) ([]TargetCredentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	profiles, err := listWindowsUserProfiles(ctx, nil, true)
	if err != nil {
		return nil, err
	}
	var groups *windowsEnrollmentGroups
	if len(opts.IncludeGroups)+len(opts.ExcludeGroups) > 0 {
		sessions, sessionErr := windowsActiveSessionGroups()
		if sessions == nil {
			sessions = map[string][]string{}
		}
		cache := NewWindowsEnrollmentGroupCache()
		if opts.GroupCache != nil {
			for sid, members := range opts.GroupCache.Users {
				cache.Users[sid] = append([]string(nil), members...)
			}
			for name, sid := range opts.GroupCache.Names {
				cache.Names[name] = sid
			}
		}
		groups = newWindowsEnrollmentGroups(opts.IncludeGroups, opts.ExcludeGroups, sessions, sessionErr, cache, nil)
	}
	lookupAccount := newWindowsEnrollmentAccountLookup()
	out := make([]TargetCredentials, 0, len(profiles))
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		decision, _ := windowsProfileEnrollmentDecision(profile, opts.ExcludeUsers, opts.ExemptUsers, lookupAccount)
		if (decision == windowsEnrollmentEnrolled || decision == windowsEnrollmentExempt) && groups.active() {
			if groupDecision, _ := groups.decide(canonicalManifestTargetSID(profile.SID)); groupDecision != windowsEnrollmentEnrolled {
				decision = groupDecision
			}
		}
		if decision != windowsEnrollmentEnrolled && decision != windowsEnrollmentExempt {
			continue
		}
		out = append(out, TargetCredentials{UserHome: filepath.Clean(profile.Home), UID: -1, GID: -1, SID: profile.SID})
	}
	return out, nil
}

// listWindowsUserProfiles walks the ProfileList registry key and
// returns one row per surviving profile. Profiles that fail any step
// of the filter chain (parse, well-known-SID, path-not-absolute,
// missing/reparse-point home) are dropped with a WARN via logf.
//
// Duplicate SIDs are deduplicated in-place — the newest
// ProfileImagePath mtime wins.
//
// ctx bounds the walk: a per-subkey ctx.Err() check ensures a
// wedged os.Stat on one profile cannot starve the interval-loop's
// 60 s cycle timeout.
func listWindowsUserProfiles(ctx context.Context, logf EnumerationLogger, standalone bool) ([]windowsUserProfile, error) {
	subkeyNames, err := windowsProfileListSubkeyReader()
	if err != nil {
		return nil, err
	}

	byCanonSID := make(map[string]windowsUserProfile, len(subkeyNames))
	for _, name := range subkeyNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sid, err := windows.StringToSid(name)
		if err != nil || sid == nil {
			logfSafely(logf, name, fmt.Sprintf("not a syntactically-valid SID: %v", err))
			continue
		}
		if !sidIsInteractiveUser(sid) {
			if standalone {
				logfSafely(logf, name, "not an interactive-user SID (S-1-5-21-… or S-1-12-1-…); refusing well-known / machine-scoped principals")
			} else {
				logfSafely(logf, name, "not an interactive-user SID (S-1-5-21-…); refusing well-known / machine-scoped principals")
			}
			continue
		}
		// The Secure Client profile keeps its historical filter: Microsoft
		// Entra ID principals (S-1-12-1-…) are refused with the pre-
		// standalone reason text so DART forensics stay stable. The
		// standalone profile admits them (handled in sidIsInteractiveUser
		// above).
		if !standalone && sidIsEntraIDUser(sid) {
			logfSafely(logf, name, "not an interactive-user SID (S-1-5-21-…)")
			continue
		}
		home, err := windowsProfileImagePathReader(name)
		if err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath unresolvable: %v", err))
			continue
		}
		if home == "" || !filepath.IsAbs(home) {
			logfSafely(logf, name, "ProfileImagePath is empty or not absolute")
			continue
		}
		info, err := os.Stat(home)
		if err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath does not resolve to an existing directory: %v", err))
			continue
		}
		if !info.IsDir() {
			logfSafely(logf, name, "ProfileImagePath is not a directory")
			continue
		}
		if err := winpath.RejectReparseChain(home); err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath contains a reparse point in its ancestor chain: %v", err))
			continue
		}
		mtime := info.ModTime().UnixNano()

		canon := canonicalManifestTargetSID(name)
		if canon == "" {
			logfSafely(logf, name, "SID canonicalisation returned empty")
			continue
		}
		if prev, dup := byCanonSID[canon]; dup {
			if mtime <= prev.HomeMtime {
				logfSafely(logf, name, fmt.Sprintf("duplicate SID; older ProfileImagePath mtime %d ≤ existing %d — kept existing", mtime, prev.HomeMtime))
				continue
			}
			logfSafely(logf, name, fmt.Sprintf("duplicate SID; newer ProfileImagePath mtime %d > existing %d — replacing", mtime, prev.HomeMtime))
		}
		byCanonSID[canon] = windowsUserProfile{
			SID:       name,
			Home:      filepath.Clean(home),
			HomeMtime: mtime,
		}
	}

	out := make([]windowsUserProfile, 0, len(byCanonSID))
	for _, p := range byCanonSID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, nil
}

// readAndExpandProfileImagePath opens the per-SID ProfileList subkey
// and reads its ProfileImagePath value, expanding any %SystemDrive%
// prefix the OS may embed.
//
// Mirrors the shape of
// `internal/cli/enterprise_hooks_platform_windows.go:
// windowsEnterpriseHookSIDProfilePath` but does NOT re-parse the SID
// (the caller already did) and does NOT enforce interactive-user
// filtering (the caller applies that separately for consistent error
// reporting).
// windowsProfileListSubkeyReader and windowsProfileImagePathReader are the
// registry seams of the ProfileList walk, so tests can inject rows (for
// example Entra ID SIDs) without editing HKLM.
var (
	windowsProfileListSubkeyReader = readProfileListSubkeyNames
	windowsProfileImagePathReader  = readAndExpandProfileImagePath
)

func readProfileListSubkeyNames() ([]string, error) {
	rootKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		profileListRegistryKey,
		registry.ENUMERATE_SUB_KEYS,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open ProfileList registry: %w", err)
	}
	defer rootKey.Close()

	subkeyNames, err := rootKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: enumerate ProfileList subkeys: %w", err)
	}
	return subkeyNames, nil
}

func readAndExpandProfileImagePath(sidString string) (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		profileListRegistryKey+`\`+sidString,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	profile, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valueType == registry.EXPAND_SZ {
		expanded, err := expandProfileImagePathSystemDrive(profile)
		if err != nil {
			return "", err
		}
		profile = expanded
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return "", fmt.Errorf("ProfileImagePath is empty")
	}
	return filepath.Clean(profile), nil
}

// expandProfileImagePathSystemDrive resolves a `%SystemDrive%`-
// prefixed ProfileImagePath. Only that specific expansion is
// permitted; anything else with a `%` in it is refused so a
// malicious environment substitution cannot escape into an unrelated
// volume.
func expandProfileImagePathSystemDrive(profile string) (string, error) {
	const systemDrive = `%SystemDrive%`
	profile = strings.TrimSpace(profile)
	if len(profile) < len(systemDrive) || !strings.EqualFold(profile[:len(systemDrive)], systemDrive) {
		if strings.Contains(profile, "%") {
			return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
		}
		return profile, nil
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Windows system directory: %w", err)
	}
	drive := filepath.VolumeName(filepath.Clean(systemDir))
	if drive == "" {
		return "", fmt.Errorf("resolve trusted Windows system drive from %q", systemDir)
	}
	expanded := drive + profile[len(systemDrive):]
	if strings.Contains(expanded, "%") {
		return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
	}
	return expanded, nil
}

// sidIsInteractiveUser reports whether `sid` is an interactive local,
// domain, or Microsoft Entra ID user SID. Local and domain users have
// the shape `S-1-5-21-A-B-C-RID`; the bare domain SID without the RID
// (`S-1-5-21-A-B-C`) is rejected. Entra ID users have the canonical
// shape `S-1-12-1-A-B-C-D`, where A-D encode the account identifier.
// Classification depends only on SID shape, not administrator group
// membership or token elevation.
//
// Every well-known / machine-scoped principal (SYSTEM S-1-5-18,
// Authenticated Users S-1-5-11, Everyone S-1-1-0, Anonymous
// S-1-5-7, BUILTIN S-1-5-32-*, NT SERVICE S-1-5-80-*, LocalService
// S-1-5-19, NetworkService S-1-5-20, IIS_IUSRS S-1-5-17, etc.) fails
// both accepted authority-and-shape checks.
//
// Together with the CLI's target-SID validator
// (validateWindowsEnterpriseTargetSID) this provides belt-and-braces
// coverage. Same discipline as `sidIsNTService` (in
// internal/ipc/acl_windows.go), inverted: this filter admits ONLY
// interactive users; that one admits ONLY NT SERVICE principals.
// WindowsInteractiveUserSID reports whether sid is the SID of an
// interactive user account (local, domain or Microsoft Entra ID), the only
// accounts the enumerator enrolls. Service, virtual (including IIS
// application pool) and other well-known SIDs are not.
func WindowsInteractiveUserSID(sid string) bool {
	parsed, err := windows.StringToSid(strings.TrimSpace(sid))
	return err == nil && sidIsInteractiveUser(parsed)
}

func sidIsInteractiveUser(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	authority := sid.IdentifierAuthority().Value
	switch authority {
	case [6]byte{0, 0, 0, 0, 0, 5}:
		const securityNTNonUnique uint32 = 21
		return sid.SubAuthorityCount() >= 5 && sid.SubAuthority(0) == securityNTNonUnique
	case [6]byte{0, 0, 0, 0, 0, 12}:
		const entraIDUserSubAuthority uint32 = 1
		return sid.SubAuthorityCount() == 5 && sid.SubAuthority(0) == entraIDUserSubAuthority
	default:
		return false
	}
}

// sidIsEntraIDUser reports whether `sid` carries the Microsoft Entra ID
// user shape `S-1-12-1-A-B-C-D`. The Secure Client profile refuses this
// shape; the standalone profile admits it.
func sidIsEntraIDUser(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IdentifierAuthority().Value != ([6]byte{0, 0, 0, 0, 0, 12}) {
		return false
	}
	const entraIDUserSubAuthority uint32 = 1
	return sid.SubAuthorityCount() == 5 && sid.SubAuthority(0) == entraIDUserSubAuthority
}

// EffectiveWindowsHookConnectors returns the connector names for
// which the enumerator emits per-user rows. Filters the operator-
// configured connector list down to those the Windows per-user
// installer actually supports (see `windowsHookConnectors`),
// deduplicating and dropping explicitly-disabled entries.
//
// Resolution order:
//
//  1. `cfg.Guardrail.Connectors` map — each key is a candidate; a
//     PerConnectorGuardrailConfig with `Enabled != nil && !*Enabled`
//     is dropped. This matches the boot-loop precedence in
//     internal/gateway/config.go.
//  2. `cfg.Guardrail.Connector` scalar — added if not already
//     present in the map. Legacy single-connector configs surface
//     here.
//
// Return value is sorted alphabetically for deterministic output.
//
// Precedence: an explicit `Connectors[name].Enabled=false` in the map
// beats the scalar `Connector` field. A config that sets
// `guardrail.connector: claudecode` together with
// `guardrail.connectors.claudecode.enabled: false` emits ZERO
// per-user rows for claudecode — the disabled map entry is
// authoritative.
//
// The per-user connectors count only in a standalone process (one that
// carries the profile pin); use EffectiveWindowsStandaloneHookConnectors
// where the caller already knows the config is a standalone one.
func EffectiveWindowsHookConnectors(cfg *config.Config) []string {
	return effectiveWindowsHookConnectors(cfg, windowsEnterpriseStandaloneProcess())
}

// EffectiveWindowsStandaloneHookConnectors is EffectiveWindowsHookConnectors
// for a config the caller loaded from the standalone layout. A standalone
// config also counts every connector its enterprise.machine_policy.connectors
// names (GAP-0904). A CLI or Setup
// lifecycle process does not carry the profile pin, so without this its
// per-user-only config (opencode, copilot, hermes) counted no connector and
// verify failed no_connectors_enabled (GAP-1230).
func EffectiveWindowsStandaloneHookConnectors(cfg *config.Config) []string {
	return effectiveWindowsHookConnectors(cfg, true)
}

func effectiveWindowsHookConnectors(cfg *config.Config, standalone bool) []string {
	seen := make(map[string]struct{})
	// disabledNames captures every name the operator explicitly
	// disabled in cfg.Guardrail.Connectors. The scalar-connector
	// pass then refuses to re-add any name in this set, so the
	// map's `Enabled=false` decision cannot be silently reversed
	// by a stale scalar. Populated only by the map pass — the
	// scalar branch never adds to it, matching the semantic
	// "map is authoritative for explicit disables".
	disabledNames := make(map[string]struct{})
	ordered := make([]string, 0, len(cfg.Guardrail.Connectors)+1)
	consider := func(name string, explicitlyDisabled bool) {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if standalone {
			trimmed = windowsStandaloneHookConnectorName(trimmed)
		}
		if trimmed == "" {
			return
		}
		if !windowsEnumeratorHookConnector(trimmed, standalone) {
			return
		}
		if explicitlyDisabled {
			disabledNames[trimmed] = struct{}{}
			return
		}
		if _, off := disabledNames[trimmed]; off {
			return
		}
		if _, dup := seen[trimmed]; dup {
			return
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}
	for name, perConn := range cfg.Guardrail.Connectors {
		disabled := perConn.Enabled != nil && !*perConn.Enabled
		consider(name, disabled)
	}
	consider(cfg.Guardrail.Connector, false)
	if standalone && cfg.StandaloneEnterprise() {
		// A connector named only under enterprise.machine_policy.connectors
		// is protected too, as Linux and macOS protect it
		// (enterprisepolicy.StandaloneConnectors): Windows publication, the
		// enumerator and both verifiers use one roster, so policy verify
		// never expects a machine hook the runtime does not publish
		// (GAP-0904). guardrail.connectors.<name>.enabled: false still
		// turns it off.
		for name := range cfg.Enterprise.MachinePolicy.Connectors {
			if cfg.Guardrail.EffectiveEnabled(name) {
				consider(name, false)
			}
		}
	}
	sort.Strings(ordered)
	return ordered
}

// logfSafely is a nil-safe wrapper around EnumerationLogger. The
// enumerator's filter chain is peppered with logf calls; a single
// nil check up front is easier to read than a nil check per call
// site.
func logfSafely(logf EnumerationLogger, subject, reason string) {
	if logf != nil {
		logf(subject, reason)
	}
}

// WindowsManifestSubject is one account the administrator's manifest
// enrolls: its authored profile folder and the connectors of its enabled
// rows.
type WindowsManifestSubject struct {
	Home       string
	Connectors []string
}

// WindowsManifestSubjects maps each canonical SID with an enabled row in
// manifest to its subject.
func WindowsManifestSubjects(manifest Manifest) map[string]WindowsManifestSubject {
	out := map[string]WindowsManifestSubject{}
	for _, target := range manifest.Targets {
		sid := canonicalManifestTargetSID(target.SID)
		if sid == "" || !target.IsEnabled() {
			continue
		}
		subject := out[sid]
		if subject.Home == "" {
			subject.Home = filepath.Clean(strings.TrimSpace(target.UserHome))
		}
		if conn := strings.ToLower(strings.TrimSpace(target.Connector)); conn != "" && !containsPrivateConnector(subject.Connectors, conn) {
			subject.Connectors = append(subject.Connectors, conn)
		}
		out[sid] = subject
	}
	return out
}

func sortedManifestSubjects(subjects map[string]WindowsManifestSubject) []string {
	out := make([]string, 0, len(subjects))
	for sid := range subjects {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}

// reportWindowsPrivateInstalls reports each unsupported, unversioned or
// uninspected agent copy the profile at home can run.
var windowsPrivateInstallsForEnumeration = DiscoverWindowsPrivateAgentInstalls

func reportWindowsPrivateInstalls(ctx context.Context, report func(UnprotectedAgent), user, sid, home string, connectors []string) {
	installs := windowsPrivateInstallsForEnumeration(ctx, home, connectors)
	if ctx.Err() == nil {
		installs = append(installs, discoverWindowsWinGetCopies(sid, connectors)...)
	} else {
		// The WinGet pass was not reached. The home walk already marks its
		// connectors incomplete; name any other connector the skipped pass
		// could have covered so the deadline never looks like a clean scan.
		incomplete := make(map[string]bool, len(installs))
		for _, install := range installs {
			if install.Incomplete {
				incomplete[install.Connector] = true
			}
		}
		for _, conn := range connectors {
			if (conn == "claudecode" || conn == "codex" || conn == "copilot") && !incomplete[conn] {
				installs = append(installs, PrivateAgentInstall{Connector: conn, Incomplete: true, Skipped: PrivateInstallSkippedHome})
			}
		}
	}
	for _, install := range installs {
		if agent, ok := privateInstallUnprotected(install); ok {
			agent.User, agent.SID = user, sid
			report(agent)
		}
	}
}

// discoverWindowsWinGetCopies lists the unsupported WinGet installs of the
// connectors the account can run, machine-scope and its own: the version
// probe may select another copy first, so an old WinGet copy would
// otherwise be hidden by a supported npm one.
func discoverWindowsWinGetCopies(sid string, connectors []string) []PrivateAgentInstall {
	var out []PrivateAgentInstall
	for _, name := range connectors {
		if name != "claudecode" && name != "codex" && name != "copilot" {
			continue
		}
		for _, packageID := range windowsWinGetPackageIDs[name] {
			machine, _ := windowsMachineWinGetPackageVersion(packageID)
			own := ""
			if strings.TrimSpace(sid) != "" {
				own, _ = windowsUserWinGetPackageVersion(sid, packageID)
			}
			for scope, version := range map[string]string{"machine": machine, "user": own} {
				if version != "" && privateInstallReason(name, version) != "" {
					out = append(out, PrivateAgentInstall{Connector: name, Version: version, Path: "WinGet " + packageID + " (" + scope + " scope)"})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
