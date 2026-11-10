// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	windowsManagedHooksTeardownSchema        = 4
	windowsManagedHooksTeardownJournalSchema = 6
	windowsManagedHooksTeardownJournalMax    = 32 << 20
	windowsManagedHooksTeardownJournalFile   = "managed-hooks-teardown-journal.json"
	windowsManagedHooksTeardownTargetMax     = 384
	windowsManagedHooksNeverActivated        = "never_activated"
	windowsManagedHooksActivated             = "activated"
)

type windowsManagedHooksTeardownTarget struct {
	Connector    string `json:"connector"`
	SID          string `json:"sid"`
	DataDir      string `json:"data_dir"`
	AgentVersion string `json:"agent_version"`
	Deferred     bool   `json:"deferred,omitempty"`
}

type windowsManagedHooksTeardownJournal struct {
	SchemaVersion          int                                 `json:"schema_version"`
	Phase                  string                              `json:"phase"`
	ManifestPath           string                              `json:"manifest_path"`
	ManifestSHA256         string                              `json:"manifest_sha256"`
	ManifestFingerprint    string                              `json:"manifest_fingerprint"`
	ActivationState        string                              `json:"activation_state"`
	DeploymentGenerationID string                              `json:"deployment_generation_id"`
	HookBinary             string                              `json:"hook_binary"`
	GatewayAddr            string                              `json:"gateway_addr"`
	GatewayServiceName     string                              `json:"gateway_service_name"`
	Targets                []windowsManagedHooksTeardownTarget `json:"targets"`
	PendingTargets         []windowsManagedHooksTeardownTarget `json:"pending_targets,omitempty"`
	// FailedTargets are targets a degraded Guardian reported as failed;
	// teardown treats them as possibly wired. Omitted when empty, so a
	// healthy deployment's journal is unchanged. A journal that carries it is
	// not readable by an older helper or installer (both reject unknown
	// fields), which is acceptable: before this field existed a degraded
	// Guardian could not prepare a teardown at all.
	FailedTargets     []windowsManagedHooksTeardownTarget                           `json:"failed_targets,omitempty"`
	ClaudeTargetSIDs  []string                                                      `json:"claude_target_sids"`
	Claude            enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot    `json:"claude"`
	CodexPolicyActive bool                                                          `json:"codex_policy_active"`
	CodexTargets      []connector.WindowsCodexManagedRuntimeTarget                  `json:"codex_targets"`
	CursorTargets     []enterprisehooks.WindowsCursorManagedRuntimeTarget           `json:"cursor_targets"`
	Cursor            enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot    `json:"cursor"`
	SelectorTargets   []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot `json:"selector_targets"`
}

type windowsManagedHooksTeardownMachineCapture struct {
	claudeOpts     enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions
	claudeSnapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
	cursorOpts     enterprisehooks.WindowsCursorManagedPolicyTeardownOptions
	cursorSnapshot enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot
}

type windowsManagedHooksTeardownResult struct {
	Connector string `json:"connector"`
	SID       string `json:"sid"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// windowsManagedHooksTeardownReport is the helper's JSON contract with the
// lifecycle. The user_registrations_* fields are set only by a standalone
// finalize: DefenseClaw registrations removed from users' agent
// configurations, and the users it could not reach.
type windowsManagedHooksTeardownReport struct {
	SchemaVersion                int                                 `json:"schema_version"`
	Action                       string                              `json:"action"`
	OK                           bool                                `json:"ok"`
	ManifestPath                 string                              `json:"manifest_path"`
	JournalPath                  string                              `json:"journal_path"`
	TargetCount                  int                                 `json:"target_count"`
	EnrollmentTargetCount        int                                 `json:"enrollment_target_count"`
	SucceededCount               int                                 `json:"succeeded_count"`
	VerifiedCleanCount           int                                 `json:"verified_clean_count"`
	VerifiedInstalledCount       int                                 `json:"verified_installed_count"`
	FailedCount                  int                                 `json:"failed_count"`
	SurvivingOwnedPathReferences int                                 `json:"surviving_owned_path_references"`
	RollbackReady                bool                                `json:"rollback_ready"`
	SafeToRemoveBinary           bool                                `json:"safe_to_remove_binary"`
	RollbackCompleted            bool                                `json:"rollback_completed"`
	FinalizationCompleted        bool                                `json:"finalization_completed"`
	CollectedGenerationCount     int                                 `json:"collected_generation_count"`
	UserRegistrationsRemoved     int                                 `json:"user_registrations_removed"`
	UserRegistrationsPending     []string                            `json:"user_registrations_pending,omitempty"`
	UserRegistrationsFailed      []string                            `json:"user_registrations_failed,omitempty"`
	UserStateRemaining           []string                            `json:"user_state_remaining,omitempty"`
	UserStatePurged              []string                            `json:"user_state_purged,omitempty"`
	UserSettingsEdited           []string                            `json:"user_settings_edited,omitempty"`
	UserSettingsHooksLeft        []string                            `json:"user_settings_hooks_left,omitempty"`
	MachineStateRemaining        []string                            `json:"machine_state_remaining,omitempty"`
	Results                      []windowsManagedHooksTeardownResult `json:"results"`
	Error                        string                              `json:"error,omitempty"`
}

// windowsManagedHooksKeptUntrustedPolicyFiles lists the vendor policy files
// the uninstall kept because another account can change them; replaceable in
// tests.
var windowsManagedHooksKeptUntrustedPolicyFiles = func() []string {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return nil
	}
	return enterprisepolicy.KeptUntrustedPolicyFiles(enterprisepolicy.Options{GOOS: "windows", WindowsProgramData: programData})
}

// windowsManagedHooksStandaloneUserRegistrationRemover is replaceable in
// tests.
var windowsManagedHooksStandaloneUserRegistrationRemover = removeWindowsManagedHooksStandalonePerUserRegistrations

// windowsManagedHooksStandaloneInventoryACERevoker is replaceable in tests.
var windowsManagedHooksStandaloneInventoryACERevoker = enterprisehooks.RevokeGatewayInventoryReadForManifest

// completeWindowsManagedHooksTeardownUserCleanup runs after a successful
// standalone finalize: the uninstall has committed, so DefenseClaw's own
// registrations are removed from users' agent configurations and the
// outcome is reported. It never fails finalize. Secure Client finalize is
// unchanged.
func completeWindowsManagedHooksTeardownUserCleanup(
	report *windowsManagedHooksTeardownReport,
	runtimeDir string,
	manifest enterprisehooks.Manifest,
) {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return
	}
	// The gateway's AI-discovery read ACEs go first: on folders that are
	// also on a managed hook path (~\.config, ~\.gemini) the removal trust
	// check refuses a DACL that still carries them (GAP-1765).
	revokeErr := windowsManagedHooksStandaloneInventoryACERevoker(manifest)
	cleanup := windowsManagedHooksStandaloneUserRegistrationRemover(context.Background(), runtimeDir, manifest)
	// The settings cleanups are done, so their transaction folder in this
	// token's cache goes too, also without purge. One that stays is named in
	// machine_state_remaining ("path: kept: reason"), which the lifecycle
	// reports as machine_state_kept (sidecar-r107:GAP-0007).
	if err := windowsManagedClaudeTransactionLeftoverRemover(); err != nil {
		report.MachineStateRemaining = append(report.MachineStateRemaining, boundedEnterpriseHookUserCleanupText(err.Error()))
	}
	// A link at a vendor folder stays (GAP-0758): name it, so the uninstall
	// result says so instead of leaving it unmentioned.
	report.MachineStateRemaining = append(report.MachineStateRemaining, windowsManagedHooksKeptLinkedFolders()...)
	// A vendor policy file another account can change stays byte for byte
	// (the removal never writes through it) and may still name DefenseClaw's
	// hook: the result says so once (GAP-0761).
	for _, entry := range windowsManagedHooksKeptUntrustedPolicyFiles() {
		report.MachineStateRemaining = append(report.MachineStateRemaining, boundedEnterpriseHookUserCleanupText(entry))
	}
	report.UserRegistrationsRemoved = len(cleanup.Removed)
	report.UserRegistrationsPending = cleanup.Pending
	report.UserRegistrationsFailed = cleanup.Failed
	report.UserSettingsEdited = cleanup.SettingsEdited
	report.UserSettingsHooksLeft = cleanup.SettingsLeft
	if revokeErr != nil {
		report.UserRegistrationsFailed = append(report.UserRegistrationsFailed,
			"gateway/AI discovery read access on users' agent folders: "+boundedEnterpriseHookUserCleanupText(revokeErr.Error()))
	}
	purge := os.Getenv(windowsManagedHooksPurgeUserStateEnv) == "1"
	var accountLinks []windowsManagedHooksAccountLink
	report.UserStateRemaining, report.UserStatePurged, accountLinks = windowsManagedHooksStandaloneUserState(manifest, purge, windowsManagedHooksAccountsKeepingRegistrations(cleanup))
	if purge {
		remaining, purged := windowsManagedHooksStandaloneACPUserState(accountLinks)
		report.UserStateRemaining = append(report.UserStateRemaining, remaining...)
		report.UserStatePurged = append(report.UserStatePurged, purged...)
		if err := windowsManagedHooksStandaloneFloorPurger(); err != nil {
			report.UserRegistrationsFailed = append(report.UserRegistrationsFailed,
				"claudecode/machine policy: the Claude Code version floor: "+boundedEnterpriseHookUserCleanupText(err.Error()))
		}
	}
	if report.Action == "finalize" || report.Action == windowsManagedHooksUserStatePurgeAction {
		finishWindowsCursorTombstoneCleanup(report, cleanup.Pending, cleanup.Failed, purge)
	}
}

var windowsManagedHooksCursorTombstoneFiles = enterprisehooks.WindowsCursorManagedTombstoneFilePaths

// A pending Cursor registration can still invoke a cached hook command.
// Keep its allow-only adapter until that registration is cleared or purge
// is requested. Other connectors' pending registrations do not need a
// Cursor adapter and must not leave that machine file behind.
func finishWindowsCursorTombstoneCleanup(report *windowsManagedHooksTeardownReport, pending, failed []string, purge bool) {
	cursorPending := false
	for _, entry := range append(append([]string(nil), pending...), failed...) {
		if strings.HasPrefix(strings.ToLower(entry), "cursor/") {
			cursorPending = true
			break
		}
	}
	if cursorPending && !purge {
		paths, err := windowsManagedHooksCursorTombstoneFiles()
		if err != nil {
			report.MachineStateRemaining = append(report.MachineStateRemaining,
				"Cursor hook tombstone: "+boundedEnterpriseHookUserCleanupText(err.Error()))
		} else {
			for _, path := range paths {
				report.MachineStateRemaining = append(report.MachineStateRemaining,
					path+": kept: pending Cursor registration; clear it with "+windowsEnterpriseSetupCommand("/ensure")+" and "+windowsEnterpriseSetupCommand("/uninstall")+
						" in an active session, or use "+windowsEnterpriseSetupCommand("/uninstall", "PURGE=1")+" ("+managed.WindowsSetupSource+")")
			}
		}
	} else if err := windowsManagedHooksStandaloneCursorTombstonePurger(); err != nil {
		report.UserRegistrationsFailed = append(report.UserRegistrationsFailed,
			"cursor/machine policy: the Cursor hook tombstone in ProgramData\\Cursor: "+boundedEnterpriseHookUserCleanupText(err.Error()))
	}
}

type windowsManagedHooksAccountLink struct {
	home string
	sid  string
}

// windowsManagedHooksStandaloneACPUserState removes, with purge, the managed
// ACP folder (token copies and editor contract locks) of every account that
// still has one: signed out, revoked, ACP-only or kept for its
// connector_backups (GAP-0773). An account-owned link already reported at
// the parent folder also covers its ACP path. It returns what stays
// ("SID: path: reason") and what went ("SID: path").
func windowsManagedHooksStandaloneACPUserState(accountLinks []windowsManagedHooksAccountLink) ([]string, []string) {
	if err := enterpriseHookWindowsUserCleanupIdentity(); err != nil {
		return nil, nil
	}
	copies, err := windowsManagedHooksStandaloneACPUserCopies()
	if err != nil {
		return []string{"managed ACP user copies: " + boundedEnterpriseHookUserCleanupText(err.Error())}, nil
	}
	var remaining, purged []string
	for _, copy := range copies {
		covered := false
		for _, link := range accountLinks {
			if strings.EqualFold(copy.SID, link.sid) && sameWindowsEnterprisePathCLI(copy.Home, link.home) {
				covered = true
				break
			}
		}
		if covered && windowsManagedHooksAccountOwnedRootLink(copy.Home, copy.SID) {
			continue
		}
		label := copy.SID + ": " + filepath.Join(copy.Home, ".defenseclaw", "acp")
		if err := windowsManagedHooksStandaloneACPUserPurger(copy.Home, copy.SID); err != nil {
			remaining = append(remaining, label+": "+boundedEnterpriseHookUserCleanupText(err.Error()))
			continue
		}
		// The purge keeps what it does not own (a personal .token, an
		// account file); the result names it, as for the data directory.
		if kept := connector.RemainingUserStateEntries(filepath.Join(copy.Home, ".defenseclaw", "acp")); len(kept) > 0 {
			for i, name := range kept {
				kept[i] = "acp/" + name
			}
			label += windowsManagedHooksKeptEntriesMarker + strings.Join(kept, ", ")
		}
		purged = append(purged, label)
	}
	sort.Strings(remaining)
	sort.Strings(purged)
	return remaining, purged
}

// windowsManagedHooksStandaloneACPUserCopies and
// windowsManagedHooksStandaloneACPUserPurger are replaceable in tests.
var (
	windowsManagedHooksStandaloneACPUserCopies = enterprisehooks.WindowsManagedACPUserCopies
	windowsManagedHooksStandaloneACPUserPurger = enterprisehooks.PurgeWindowsACPUserState
	windowsManagedHooksAccountOwnedRootLink    = enterprisehooks.WindowsAccountOwnedRootDataDirLink
)

// windowsManagedHooksStandaloneCursorTombstonePurger is replaceable in tests.
var windowsManagedHooksStandaloneCursorTombstonePurger = enterprisehooks.PurgeWindowsCursorManagedTombstone

// windowsManagedHooksNotLocalSystemReason ends a user_state_remaining entry
// whose folder a purge left because it did not run as LocalSystem; the
// lifecycle result fails on it.
const windowsManagedHooksNotLocalSystemReason = "the uninstall did not run as LocalSystem"

// windowsManagedHooksSignedOutPathEntryReason ends a user_state_remaining
// entry of an account whose DefenseClaw data and binaries a purge removed
// but whose user Path entry for %USERPROFILE%\.local\bin stays: the account
// is signed out, so its registry hive is not loaded and its Path cannot be
// changed. The docs call that a warning, so the lifecycle result warns and
// the purge does not fail on it (GAP-2231).
const windowsManagedHooksSignedOutPathEntryReason = "only its user Path entry for .local\\bin stays: the account is signed out, so its registry hive is not loaded"

// windowsManagedHooksKeptForRegistrationsReason marks, in user_state_remaining,
// the DefenseClaw folder of an account whose agent registrations stay (it
// had no active session, or their removal failed): its connector_backups
// restore them, so the purge keeps it on purpose.
const windowsManagedHooksKeptForRegistrationsReason = "kept: the account's agent registrations were not all removed, and its connector_backups restore them"

const windowsManagedHooksAccountLinkKeptReason = "kept: the account owns a link at its DefenseClaw folder; the link and its contents were left as found"

// windowsManagedHooksUserBinariesReason is the user_state_remaining reason of
// a failed per-user binaries purge.
func windowsManagedHooksUserBinariesReason(err error) string {
	if errors.Is(err, enterprisehooks.ErrWindowsUserHiveNotLoaded) {
		return windowsManagedHooksSignedOutPathEntryReason
	}
	return boundedEnterpriseHookUserCleanupText(err.Error())
}

// windowsManagedHooksPurgeUserStateEnv is set to 1 by the lifecycle for an
// uninstall with purge (Setup PURGE=1, --purge). A flag would fail the
// finalize of an installed helper from before it; that helper ignores the
// environment value and only names the per-user folders.
const windowsManagedHooksPurgeUserStateEnv = "DEFENSECLAW_WINDOWS_UNINSTALL_PURGE_USER_STATE"

// windowsManagedHooksStandaloneUserStatePurger and
// windowsManagedHooksStandaloneUserBinariesPurger are replaceable in tests.
var (
	windowsManagedHooksStandaloneUserStatePurger    = enterprisehooks.PurgeWindowsUserState
	windowsManagedHooksStandaloneUserBinariesPurger = enterprisehooks.PurgeWindowsUserBinaries
	// windowsManagedHooksStandaloneUserRuntimeRemover removes, without purge,
	// what the managed runtime wrote into an account's folder (GAP-0045).
	windowsManagedHooksStandaloneUserRuntimeRemover = enterprisehooks.RemoveWindowsManagedUserRuntime
)

// windowsManagedHooksAccountsKeepingRegistrations reports whether an
// account's registrations may have stayed after cleanup: it is named in a
// pending or failed entry ("connector/SID"), or a failure names no account.
// Such an account's folder holds the connector_backups that restore its
// agent configurations, so a purge keeps it.
func windowsManagedHooksAccountsKeepingRegistrations(cleanup enterpriseHookUserCleanupResult) func(sid string) bool {
	accounts := map[string]bool{}
	unknown := false
	for _, entry := range append(append([]string(nil), cleanup.Pending...), cleanup.Failed...) {
		label, _, _ := strings.Cut(entry, ": ")
		_, account, found := strings.Cut(label, "/")
		if account = strings.TrimSpace(account); !found || account == "" {
			unknown = true
			continue
		}
		accounts[strings.ToLower(account)] = true
	}
	return func(sid string) bool { return unknown || accounts[strings.ToLower(strings.TrimSpace(sid))] }
}

// windowsManagedHooksStandaloneUserState handles the DefenseClaw per-user
// folder of each enrolled account once the uninstall has removed the
// registrations it could. With purge it removes, as LocalSystem and
// signed-out accounts included, each folder (all of it, hook scripts and
// foreign-hooks-backup included) and then the account's per-user binaries in
// %USERPROFILE%\.local\bin with that folder's user Path entry. It returns
// each account it could not purge ("user (SID): path: reason") and each one
// it purged ("user (SID): path"), so the result names every account whose
// data went. An account that keeps registrations (keepsRegistrations) keeps
// its folder. Without purge, as LocalSystem, it removes from the folder of
// each account whose registrations all went what DefenseClaw's managed
// runtime wrote there (hooks, logs, the hook contract lock, the foreign-hook
// policy's files; enterprisehooks.RemoveWindowsManagedUserRuntime), and the
// folder once nothing else is in it: a plain uninstall kept those files with
// their managed DACL, and a later per-user install of the account failed its
// first run on them (cowork-1-0-8 GAP-0045). It lists each folder that stays
// ("user (SID): path", with why it stays when the cleanup ran) and purges no
// data or binaries.
func windowsManagedHooksStandaloneUserState(
	manifest enterprisehooks.Manifest,
	purge bool,
	keepsRegistrations func(sid string) bool,
) ([]string, []string, []windowsManagedHooksAccountLink) {
	identityErr := enterpriseHookWindowsUserCleanupIdentity()
	seen := map[string]bool{}
	var remaining, purged []string
	var accountLinks []windowsManagedHooksAccountLink
	for _, target := range manifest.Targets {
		home, sid := strings.TrimSpace(target.UserHome), strings.TrimSpace(target.SID)
		dataDir := strings.TrimSpace(target.DataDir)
		if dataDir == "" && home != "" {
			dataDir = filepath.Join(home, ".defenseclaw")
		}
		if dataDir == "" || seen[strings.ToLower(dataDir)] {
			continue
		}
		seen[strings.ToLower(dataDir)] = true
		label := sid
		if user := strings.TrimSpace(target.User); user != "" {
			label = user + " (" + sid + ")"
		}
		label += ": " + dataDir
		_, statErr := os.Lstat(dataDir)
		accountLink := purge && sameWindowsEnterprisePathCLI(dataDir, filepath.Join(home, ".defenseclaw")) &&
			windowsManagedHooksAccountOwnedRootLink(home, sid)
		accountLinkReported := false
		addRemaining := func(entry string) {
			remaining = append(remaining, entry)
			if accountLink && !accountLinkReported {
				accountLinks = append(accountLinks, windowsManagedHooksAccountLink{home: home, sid: sid})
				accountLinkReported = true
			}
		}
		var reason string
		switch {
		case !purge:
			if statErr != nil {
				continue
			}
			if identityErr != nil || keepsRegistrations(sid) {
				// An account whose registrations stay keeps the folder: its
				// connector_backups restore them.
				addRemaining(label)
				continue
			}
			kept, err := windowsManagedHooksStandaloneUserRuntimeRemover(home, sid, target.DataDir)
			if err != nil {
				addRemaining(label + ": " + boundedEnterpriseHookUserCleanupText(err.Error()))
			} else if kept != "" {
				addRemaining(label + ": " + boundedEnterpriseHookUserCleanupText(kept))
			}
			continue
		case errors.Is(statErr, os.ErrNotExist) && !accountLink:
			// Nothing to remove, unless the account has a roaming or container
			// profile, which is off the computer while the account is signed
			// out and brings the folder back at its next sign-in.
			if _, err := os.Lstat(home); home == "" || !errors.Is(err, os.ErrNotExist) || enterpriseHookWindowsUserProfileRemoved(sid) {
				if home != "" && !errors.Is(err, os.ErrNotExist) && identityErr == nil && !keepsRegistrations(sid) {
					// The folder is gone; the binaries may still be there.
					if _, err := windowsManagedHooksStandaloneUserBinariesPurger(home, sid); err != nil {
						addRemaining(label + ": " + windowsManagedHooksUserBinariesReason(err))
					}
				}
				continue
			}
			reason = "the account's profile folder is not on this computer while it is signed out"
		case identityErr != nil:
			reason = windowsManagedHooksNotLocalSystemReason
		case keepsRegistrations(sid):
			reason = windowsManagedHooksKeptForRegistrationsReason
		default:
			err := windowsManagedHooksStandaloneUserStatePurger(home, sid, target.DataDir)
			if errors.Is(err, enterprisehooks.ErrWindowsUserStateOnlyLink) &&
				sameWindowsEnterprisePathCLI(dataDir, filepath.Join(home, ".defenseclaw")) &&
				windowsEnterpriseAccountOwnedDataDirLink(home, sid) {
				accountLink = true
				if _, binaryErr := windowsManagedHooksStandaloneUserBinariesPurger(home, sid); binaryErr != nil {
					addRemaining(label + ": " + windowsManagedHooksUserBinariesReason(binaryErr))
				}
				addRemaining(label + ": " + windowsManagedHooksAccountLinkKeptReason)
				continue
			}
			var binaries []string
			if err == nil {
				binaries, err = windowsManagedHooksStandaloneUserBinariesPurger(home, sid)
			}
			if err == nil {
				if kept := connector.RemainingUserStateEntries(dataDir); len(kept) > 0 {
					label += windowsManagedHooksKeptEntriesMarker + strings.Join(kept, ", ")
				}
				purged = append(purged, windowsManagedHooksPurgedLabel(label, binaries))
				continue
			}
			if errors.Is(err, enterprisehooks.ErrWindowsUserHiveNotLoaded) {
				// The data and binaries went; only the Path entry of a
				// signed-out account stays (GAP-2231).
				purged = append(purged, windowsManagedHooksPurgedLabel(label, binaries))
			}
			reason = windowsManagedHooksUserBinariesReason(err)
		}
		addRemaining(label + ": " + reason)
	}
	sort.Strings(remaining)
	sort.Strings(purged)
	return remaining, purged, accountLinks
}

func newWindowsManagedHooksTeardownCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "teardown-managed-hooks",
		Short:  "Transactionally revoke managed hook machine wiring",
		Hidden: true,
	}
	for _, action := range []string{"prepare", "verify", "rollback", "finalize", "check"} {
		action := action
		var jsonOutput bool
		var purgeContractLocks bool
		var contractCleanupReceipt string
		var contractCleanupScope string
		child := &cobra.Command{
			Use:          action,
			Short:        action + " managed hook machine-wiring teardown",
			Hidden:       true,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				report, err := runWindowsManagedHooksTeardown(
					action,
					purgeContractLocks,
					contractCleanupReceipt,
					contractCleanupScope,
				)
				if jsonOutput {
					if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil {
						if err == nil {
							return encodeErr
						}
						return fmt.Errorf(
							"managed-hook teardown %s failed and its JSON report could not be encoded",
							action,
						)
					}
				} else if err == nil {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"Windows managed-hook teardown %s: targets=%d, succeeded=%d\n",
						action,
						report.TargetCount,
						report.SucceededCount,
					)
				}
				if err != nil {
					// Wrap the underlying err so both the non-JSON operator
					// path and the MSI log receive the real cause. The prior
					// fixed "managed-hook teardown <action> failed" string
					// collapsed distinct failure classes (e.g. rollback
					// required vs noncanonical ownership vs unavailable state
					// root) into one, making 1603-recovery guidance guess-work.
					// The --json branch already surfaces this via report.Error;
					// this ensures the non-JSON caller gets it too.
					return fmt.Errorf("managed-hook teardown %s failed: %w", action, err)
				}
				return nil
			},
		}
		child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
		if action == "prepare" || action == "finalize" {
			child.Flags().StringVar(
				&contractCleanupReceipt,
				"contract-cleanup-receipt",
				"",
				"pre-created protected connector-contract cleanup receipt",
			)
			child.Flags().StringVar(
				&contractCleanupScope,
				"contract-cleanup-scope",
				"",
				"exact lifecycle scope SHA-256",
			)
		}
		if action == "finalize" {
			child.Flags().BoolVar(
				&purgeContractLocks,
				"purge-contract-locks",
				false,
				"clear manifest-owned per-user hook contract locks",
			)
		}
		command.AddCommand(child)
	}
	command.AddCommand(newWindowsManagedHooksTeardownCapabilitiesCommand())
	command.AddCommand(newWindowsManagedHooksUserStatePurgeCommand())
	command.AddCommand(newWindowsManagedHooksOwnerRightsRestoreCommand())
	return command
}

// windowsManagedHooksUserStatePurgeAction is the teardown-managed-hooks
// action a standalone Setup /uninstall PURGE=1 runs over a committed
// uninstall tombstone whose hook teardown already finalized without the
// per-user purge: a plain uninstall that was interrupted after its finalize,
// or one whose InstallRoot is already gone (GAP-2094, GAP-0867). Nothing else
// removes each enrolled account's per-user data and binaries then, and the
// installed helper that ran the finalize may be gone, so Setup runs this
// action with its own authenticated gateway.
const windowsManagedHooksUserStatePurgeAction = "purge-user-state"

func newWindowsManagedHooksUserStatePurgeCommand() *cobra.Command {
	var jsonOutput bool
	child := &cobra.Command{
		Use:          windowsManagedHooksUserStatePurgeAction,
		Short:        "remove enrolled accounts' per-user state after a committed standalone uninstall",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, err := runWindowsManagedHooksUserStatePurge()
			if jsonOutput {
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil && err == nil {
					return encodeErr
				}
			} else if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "per-user state purged: %d, remaining: %d\n",
					len(report.UserStatePurged), len(report.UserStateRemaining))
			}
			if err != nil {
				return fmt.Errorf("managed-hook teardown %s failed: %w", windowsManagedHooksUserStatePurgeAction, err)
			}
			return nil
		},
	}
	child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return child
}

// runWindowsManagedHooksUserStatePurge does what the finalize of a purge
// does for users: it removes the DefenseClaw registrations still in their
// agent configurations and each enrolled account's per-user data and
// binaries. It accepts only an authenticated standalone uninstall tombstone
// with no pending transaction and no unfinished hook teardown (a prepared
// journal is the finalize's own work), and only the target manifest that the
// tombstone's preserved activation binds. It reports what went and what
// stays as the finalize does.
func runWindowsManagedHooksUserStatePurge() (windowsManagedHooksTeardownReport, error) {
	report := windowsManagedHooksTeardownReport{
		SchemaVersion: windowsManagedHooksTeardownSchema,
		Action:        windowsManagedHooksUserStatePurgeAction,
		Results:       []windowsManagedHooksTeardownResult{},
	}
	fail := func(err error) (windowsManagedHooksTeardownReport, error) {
		report.OK = false
		report.Error = err.Error()
		return report, err
	}
	if !enterprisehooks.WindowsStandaloneProcess() {
		return fail(errors.New("the per-user purge of a committed uninstall requires the standalone profile"))
	}
	if os.Getenv(windowsManagedHooksPurgeUserStateEnv) != "1" {
		return fail(errors.New("the per-user purge of a committed uninstall requires an uninstall with purge"))
	}
	if err := enterpriseHooksPlatformPreflight(); err != nil {
		return fail(err)
	}
	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return fail(err)
	}
	stateRoot := filepath.Dir(runtimeDir)
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") || stateRoot == filepath.Dir(stateRoot) {
		return fail(errors.New("the per-user purge received a noncanonical protected runtime directory"))
	}
	if err := managed.ValidateTrustedRuntimeDir(stateRoot, "Windows enterprise managed-hook teardown state root"); err != nil {
		return fail(err)
	}
	installDir := filepath.Join(stateRoot, "install")
	report.ManifestPath = filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	report.JournalPath = filepath.Join(installDir, windowsManagedHooksTeardownJournalFile)
	if err := managed.ValidateTrustedFilePath(report.ManifestPath, "Windows enterprise hook target manifest"); err != nil {
		return fail(err)
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(report.ManifestPath)
	if err != nil {
		return fail(err)
	}
	targets, _, _, _, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return fail(err)
	}
	metadata, exists, err := readWindowsCodexDeploymentMetadata(filepath.Join(installDir, "deployment.json"))
	if err != nil {
		return fail(err)
	}
	if !exists {
		return fail(errors.New("the per-user purge requires protected deployment metadata"))
	}
	if _, err := os.Lstat(filepath.Join(installDir, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fail(errors.New("the per-user purge requires transaction retirement"))
		}
		return fail(fmt.Errorf("inspect pending managed-hook transaction: %w", err))
	}
	// The finalize rule: an inactive tombstone whose preserved activation
	// binds this manifest.
	if _, err := validateWindowsManagedHooksTeardownDeployment(metadata, "finalize", manifestSHA256, len(targets)); err != nil {
		return fail(err)
	}
	journal, err := readWindowsManagedHooksTeardownJournal(report.JournalPath)
	switch {
	case err == nil && journal.Phase != "finalized":
		return fail(fmt.Errorf("the per-user purge refuses an unfinished managed-hook teardown (phase %s): its finalize removes the per-user state", journal.Phase))
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fail(err)
	}
	completeWindowsManagedHooksTeardownUserCleanup(&report, runtimeDir, manifest)
	report.OK = true
	report.FinalizationCompleted = true
	return report, nil
}

// windowsManagedHooksOwnerRightsRestoreAction is the teardown-managed-hooks
// action a standalone Setup runs with its own authenticated gateway before
// the installed helper prepares, collects or purges the per-user state of
// the enrolled accounts: it puts back the OWNER RIGHTS entry an owner write
// (icacls /setowner, takeown, a profile backup and restore) took out of their
// managed folders and files. The helper of an older release refuses that
// shape, and a host that release left half-uninstalled could not finish an
// uninstall or a reinstall (rel-1-0-6:GAP-0303).
const windowsManagedHooksOwnerRightsRestoreAction = "restore-owner-rights"

// windowsManagedHooksOwnerRightsRestorer is replaceable in tests.
var windowsManagedHooksOwnerRightsRestorer = enterprisehooks.RestoreWindowsManagedUserStateOwnerRights
var windowsManagedHooksOwnerRightsProber = enterprisehooks.ProbeWindowsManagedUserStateOwnerRights

func newWindowsManagedHooksOwnerRightsRestoreCommand() *cobra.Command {
	var jsonOutput, probe, upgradeOnly bool
	child := &cobra.Command{
		Use:          windowsManagedHooksOwnerRightsRestoreAction,
		Short:        "restore the OWNER RIGHTS entry on enrolled accounts managed state after an owner change",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, err := runWindowsManagedHooksOwnerRightsRestoreMode(probe, upgradeOnly)
			if jsonOutput {
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(report); encodeErr != nil && err == nil {
					return encodeErr
				}
			} else if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "OWNER RIGHTS restored on %d object(s) of %d account(s)\n",
					report.SucceededCount, report.TargetCount)
			}
			if err != nil {
				return fmt.Errorf("managed-hook teardown %s failed: %w", windowsManagedHooksOwnerRightsRestoreAction, err)
			}
			return nil
		},
	}
	child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	child.Flags().BoolVar(&probe, "probe", false, "count exact owner-rewritten objects without changing them")
	child.Flags().BoolVar(&upgradeOnly, "upgrade-only", false, "consider only signed-out accounts with owner-rewritten state")
	return child
}

// runWindowsManagedHooksOwnerRightsRestore restores the managed state of
// every enrolled account the protected target manifest names. It changes
// only objects in the exact owner-rewritten shape
// (enterprisehooks.RestoreWindowsManagedUserStateOwnerRights). SucceededCount
// is the number of objects restored and TargetCount the number of accounts;
// an account it could not restore is a failed result, never an error: the
// trust check that follows still decides.
func runWindowsManagedHooksOwnerRightsRestore() (windowsManagedHooksTeardownReport, error) {
	return runWindowsManagedHooksOwnerRightsRestoreMode(false, false)
}

func runWindowsManagedHooksOwnerRightsRestoreMode(probe, upgradeOnly bool) (windowsManagedHooksTeardownReport, error) {
	report := windowsManagedHooksTeardownReport{
		SchemaVersion: windowsManagedHooksTeardownSchema,
		Action:        windowsManagedHooksOwnerRightsRestoreAction,
		Results:       []windowsManagedHooksTeardownResult{},
	}
	fail := func(err error) (windowsManagedHooksTeardownReport, error) {
		report.OK = false
		report.Error = err.Error()
		return report, err
	}
	if !enterprisehooks.WindowsStandaloneProcess() {
		return fail(errors.New("the OWNER RIGHTS restore requires the standalone profile"))
	}
	if err := enterpriseHooksPlatformPreflight(); err != nil {
		return fail(err)
	}
	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return fail(err)
	}
	stateRoot := filepath.Dir(runtimeDir)
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") || stateRoot == filepath.Dir(stateRoot) {
		return fail(errors.New("the OWNER RIGHTS restore received a noncanonical protected runtime directory"))
	}
	if err := managed.ValidateTrustedRuntimeDir(stateRoot, "Windows enterprise managed-hook teardown state root"); err != nil {
		return fail(err)
	}
	report.ManifestPath = filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	if _, err := os.Lstat(report.ManifestPath); errors.Is(err, os.ErrNotExist) {
		report.OK = true
		return report, nil
	}
	if err := managed.ValidateTrustedFilePath(report.ManifestPath, "Windows enterprise hook target manifest"); err != nil {
		return fail(err)
	}
	manifest, _, err := enterprisehooks.LoadManifestWithSHA256(report.ManifestPath)
	if err != nil {
		return fail(err)
	}
	targets, _, _, _, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return fail(err)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		key := strings.ToUpper(target.SID) + "\x00" + strings.ToLower(filepath.Clean(target.DataDir))
		if seen[key] {
			continue
		}
		seen[key] = true
		report.TargetCount++
		var restored int
		var err error
		if upgradeOnly {
			var signedOut bool
			signedOut, err = enterprisehooks.WindowsTargetHasNoSession(target.SID)
			if err == nil && signedOut {
				restored, err = windowsManagedHooksOwnerRightsProber(target.SID, target.DataDir)
			}
			if err == nil && (!signedOut || restored == 0) {
				continue
			}
		}
		if err == nil && !probe {
			restored, err = windowsManagedHooksOwnerRightsRestorer(target.SID, target.DataDir)
		} else if err == nil && !upgradeOnly {
			restored, err = windowsManagedHooksOwnerRightsProber(target.SID, target.DataDir)
		}
		report.SucceededCount += restored
		result := windowsManagedHooksTeardownResult{Connector: target.Connector, SID: target.SID, OK: err == nil}
		if err != nil {
			result.Error = err.Error()
			report.FailedCount++
		}
		report.Results = append(report.Results, result)
	}
	report.OK = true
	return report, nil
}

// windowsManagedHooksTeardownCapabilities is the report of
// "teardown-managed-hooks capabilities --json": what this helper accepts.
// A standalone Setup removes the hooks after the uninstall tombstone commits
// only with a helper that prepares that removal against the tombstone
// (windowsManagedHooksTeardownValidationAction). The helpers of 1.0.0 to
// 1.0.3 and of earlier 1.0.4 builds have no capabilities command and refuse
// that preparation, so Setup asks first and, without this report, prepares
// the removal before the commit, as those releases did (GAP-1443,
// GAP-1447). The command reads nothing and changes nothing.
type windowsManagedHooksTeardownCapabilities struct {
	SchemaVersion              int    `json:"schema_version"`
	Action                     string `json:"action"`
	OK                         bool   `json:"ok"`
	CommittedStandalonePrepare bool   `json:"committed_standalone_prepare"`
	// PrecommitCheck says the helper accepts the read-only "check" action:
	// a standalone uninstall asks it before its tombstone commits whether
	// the post-commit prepare would accept this deployment (GAP-0571).
	PrecommitCheck bool `json:"precommit_check"`
	// CodexRequirementsUninstall says "codex-requirements remove" accepts
	// --uninstall, the uninstall's removal that keeps a link at the Codex
	// machine-policy folder (GAP-0773). Setup passes the flag only to a
	// helper that reports this; the helpers of 1.0.3 and 1.0.8 define only
	// --json and refuse the flag, and Setup runs their plain removal.
	CodexRequirementsUninstall bool `json:"codex_requirements_uninstall"`
	// CodexRequirementsBaseFile says "codex-requirements reconcile" accepts
	// --base-file, the document the managed policy is rendered into instead of
	// the file on disk (GAP-1001). Setup rebuilds a hand-edited requirements
	// file only through a helper that reports this; an older helper leaves
	// the file as it is and the recovery says so.
	CodexRequirementsBaseFile bool `json:"codex_requirements_base_file"`
}

func newWindowsManagedHooksTeardownCapabilitiesCommand() *cobra.Command {
	var jsonOutput bool
	child := &cobra.Command{
		Use:          "capabilities",
		Short:        "report the managed hook teardown actions this helper accepts",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := windowsManagedHooksTeardownCapabilities{
				SchemaVersion:              windowsManagedHooksTeardownSchema,
				Action:                     "capabilities",
				OK:                         true,
				CommittedStandalonePrepare: true,
				PrecommitCheck:             true,
				CodexRequirementsUninstall: true,
				CodexRequirementsBaseFile:  true,
			}
			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "committed standalone prepare: %v\n", report.CommittedStandalonePrepare)
			return nil
		},
	}
	child.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return child
}

func runWindowsManagedHooksTeardown(
	action string,
	purgeContractLocks bool,
	contractCleanupReceipt string,
	contractCleanupScope string,
) (windowsManagedHooksTeardownReport, error) {
	report := windowsManagedHooksTeardownReport{
		SchemaVersion: windowsManagedHooksTeardownSchema,
		Action:        action,
		Results:       []windowsManagedHooksTeardownResult{},
	}
	var finalizeNotes map[string]string
	fail := func(err error) (windowsManagedHooksTeardownReport, error) {
		report.OK = false
		report.Error = err.Error()
		report.SucceededCount = 0
		report.VerifiedCleanCount = 0
		if !report.RollbackCompleted {
			report.VerifiedInstalledCount = 0
		}
		report.FailedCount = report.TargetCount
		for index := range report.Results {
			report.Results[index].OK = false
			report.Results[index].Error = err.Error()
		}
		return report, err
	}
	if action != "prepare" && action != "verify" && action != "rollback" &&
		action != "finalize" && action != "check" {
		return fail(fmt.Errorf("unsupported managed-hook teardown action %q", action))
	}
	// Authorization intentionally precedes protected layout discovery.
	if err := enterpriseHooksPlatformPreflight(); err != nil {
		return fail(err)
	}
	opts, err := resolveWindowsCodexRequirementsLayout("remove")
	if err != nil {
		return fail(err)
	}
	ownershipPath := opts.OwnershipPath
	installDir := filepath.Dir(ownershipPath)
	stateRoot := filepath.Dir(installDir)
	if ownershipPath == "" || !filepath.IsAbs(ownershipPath) ||
		strings.TrimSpace(ownershipPath) != ownershipPath ||
		filepath.Clean(ownershipPath) != ownershipPath ||
		!strings.EqualFold(filepath.Base(ownershipPath), "codex-requirements-ownership.json") ||
		!strings.EqualFold(filepath.Base(installDir), "install") ||
		stateRoot == installDir || stateRoot == filepath.Dir(stateRoot) {
		return fail(errors.New("managed-hook teardown received a noncanonical protected ownership path"))
	}
	runtimeDir, err := exactWindowsCodexLayoutEnv("DEFENSECLAW_HOME")
	if err != nil {
		return fail(err)
	}
	expectedStateRoot := filepath.Dir(runtimeDir)
	if !strings.EqualFold(filepath.Base(runtimeDir), "runtime") ||
		!sameWindowsEnterprisePathCLI(stateRoot, expectedStateRoot) {
		return fail(errors.New("managed-hook teardown ownership path does not match the protected state root"))
	}
	// Uninstall runs whether or not the guardian is healthy, so state-root
	// drift is repaired here and residual drift accepted and logged.
	if err := validateWindowsManagedHooksTrustedDir(
		stateRoot,
		managed.ObjectStateDirectory,
		"Windows enterprise managed-hook teardown state root",
	); err != nil {
		return fail(err)
	}
	report.ManifestPath = filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	report.JournalPath = filepath.Join(
		stateRoot,
		"install",
		windowsManagedHooksTeardownJournalFile,
	)
	if !sameWindowsEnterprisePathCLI(
		report.JournalPath,
		filepath.Join(installDir, windowsManagedHooksTeardownJournalFile),
	) {
		return fail(errors.New("managed-hook teardown derived a noncanonical protected layout"))
	}
	// The guardian's manifest check: repair, then accept and log what
	// survives. The manifest is hash-bound to the deployment below.
	if err := enterpriseHookManifestFileTrustCheck(report.ManifestPath); err != nil {
		return fail(err)
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(report.ManifestPath)
	if err != nil {
		return fail(err)
	}
	targets, claudeTargets, codexTargets, cursorTargets, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		return fail(err)
	}
	metadata, exists, err := readWindowsCodexDeploymentMetadata(
		filepath.Join(installDir, "deployment.json"),
	)
	if err != nil {
		return fail(err)
	}
	if !exists {
		return fail(errors.New("managed-hook teardown requires protected deployment metadata"))
	}
	validationAction, committedStandalone, err := windowsManagedHooksTeardownValidationAction(
		metadata,
		action,
		enterprisehooks.WindowsStandaloneProcess(),
		filepath.Join(installDir, "pending.json"),
	)
	if err != nil {
		return fail(err)
	}
	activation, err := validateWindowsManagedHooksTeardownDeployment(
		metadata,
		validationAction,
		manifestSHA256,
		len(targets),
	)
	if err != nil {
		return fail(err)
	}
	report.TargetCount = len(targets)
	report.Results = make([]windowsManagedHooksTeardownResult, 0, len(targets))
	for _, target := range targets {
		report.Results = append(report.Results, windowsManagedHooksTeardownResult{
			Connector: target.Connector,
			SID:       target.SID,
		})
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		return fail(err)
	}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		ManifestPath:           report.ManifestPath,
		ManifestSHA256:         manifestSHA256,
		ManifestFingerprint:    fingerprint,
		ActivationState:        activation.State,
		DeploymentGenerationID: activation.DeploymentGenerationID,
		HookBinary:             opts.HookBinary,
		GatewayAddr:            opts.GatewayAddr,
		GatewayServiceName:     opts.GatewayServiceName,
		Targets:                targets,
	}
	if activation.State == windowsManagedHooksActivated {
		identity.PendingTargets, identity.FailedTargets, err = windowsManagedHooksTargetsFromGuardian(
			runtimeDir,
			report.ManifestPath,
			manifestSHA256,
			targets,
		)
		if err != nil {
			return fail(err)
		}
	}
	identity.ClaudeTargetSIDs,
		identity.CodexPolicyActive,
		identity.CodexTargets,
		identity.CursorTargets = windowsManagedHooksTeardownExpectedEnrollment(
		activation.State,
		opts.CodexTargetEnabled,
		claudeTargets,
		codexTargets,
		cursorTargets,
	)
	if action == "prepare" {
		if err := captureWindowsManagedHooksTeardownCodexPolicy(&identity); err != nil {
			return fail(err)
		}
	}
	var cleanupReceiptPath string
	if strings.TrimSpace(contractCleanupReceipt) != "" ||
		strings.TrimSpace(contractCleanupScope) != "" {
		cleanupReceiptPath, err = requireWindowsManagedHookContractCleanupReceiptPath(
			contractCleanupReceipt,
			"managed hook contract cleanup receipt",
			action == "prepare",
		)
		if err != nil {
			return fail(err)
		}
		if !validWindowsManagedHookContractCleanupScope(contractCleanupScope) {
			return fail(errors.New("managed hook contract cleanup scope is invalid"))
		}
	}
	switch action {
	case "prepare":
		if cleanupReceiptPath != "" {
			reusePrepared := false
			if _, statErr := os.Lstat(cleanupReceiptPath); statErr == nil {
				var existing windowsManagedHookContractCleanupReceipt
				existing, err = readWindowsManagedHookContractCleanupReceipt(cleanupReceiptPath)
				if err == nil {
					reusePrepared, err = windowsManagedHookContractCleanupPrepareReuses(
						existing,
						identity,
						contractCleanupScope,
						enterprisehooks.WindowsStandaloneProcess(),
					)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				err = statErr
			}
			if err == nil && !reusePrepared {
				var cleanupReceipt windowsManagedHookContractCleanupReceipt
				cleanupReceipt, err = captureWindowsManagedHookContractCleanupReceipt(
					identity,
					contractCleanupScope,
				)
				if err == nil {
					err = writeWindowsManagedHookContractCleanupReceipt(
						cleanupReceiptPath,
						cleanupReceipt,
					)
				}
			}
			if err != nil {
				break
			}
		}
		report.EnrollmentTargetCount = len(identity.ClaudeTargetSIDs) +
			len(identity.CodexTargets) + len(identity.CursorTargets)
		var rollbackCompleted bool
		var surviving int
		rollbackCompleted, surviving, err = prepareWindowsManagedHooksTeardown(
			opts,
			windowsManagedHooksClaudeOptions(opts, identity.ClaudeTargetSIDs),
			windowsManagedHooksCursorOptions(opts, identity.CursorTargets),
			identity,
			report.JournalPath,
			committedStandalone,
		)
		report.SurvivingOwnedPathReferences = surviving
		if rollbackCompleted {
			report.RollbackCompleted = true
			report.VerifiedInstalledCount = report.EnrollmentTargetCount
		}
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = false
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "check":
		// Read-only (GAP-0571): the guardian evidence above, the installed
		// enrollment and the runtime selectors are what the post-commit
		// prepare authenticates. A standalone uninstall asks this before its
		// tombstone commits, so a deployment that prepare would refuse stays
		// fully installed instead of being left half-uninstalled.
		err = windowsManagedHooksTeardownCheckReady(opts, identity)
		if err == nil {
			report.VerifiedInstalledCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "verify":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = windowsManagedHooksTeardownJournalNamed(
				validateWindowsManagedHooksTeardownJournal(journal, identity), report.JournalPath)
		}
		if err == nil {
			report.EnrollmentTargetCount =
				len(journal.ClaudeTargetSIDs) + len(journal.CodexTargets) + len(journal.CursorTargets)
		}
		if err == nil && journal.Phase != "prepared" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase is %q, expected prepared",
				journal.Phase,
			)
		}
		if err == nil {
			var surviving int
			surviving, err = verifyWindowsManagedHooksTeardownClean(opts, journal.Targets)
			report.SurvivingOwnedPathReferences = surviving
		}
		if err == nil {
			report.RollbackReady = true
			report.SafeToRemoveBinary = false
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	case "rollback":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = windowsManagedHooksTeardownJournalNamed(
				validateWindowsManagedHooksTeardownJournal(journal, identity), report.JournalPath)
		}
		if err == nil {
			report.EnrollmentTargetCount =
				len(journal.ClaudeTargetSIDs) + len(journal.CodexTargets) + len(journal.CursorTargets)
		}
		if err == nil && journal.Phase != "captured" &&
			journal.Phase != "prepared" && journal.Phase != "rolled_back" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase %q cannot be rolled back",
				journal.Phase,
			)
		}
		if err == nil {
			err = rollbackWindowsManagedHooksTeardown(
				opts,
				windowsManagedHooksClaudeOptions(opts, journal.ClaudeTargetSIDs),
				windowsManagedHooksCursorOptions(opts, journal.CursorTargets),
				journal,
				report.JournalPath,
			)
		}
		if err == nil {
			report.RollbackCompleted = true
			report.VerifiedInstalledCount = report.EnrollmentTargetCount
			report.SucceededCount = report.TargetCount
		}
	case "finalize":
		var journal windowsManagedHooksTeardownJournal
		journal, err = readWindowsManagedHooksTeardownJournal(report.JournalPath)
		if err == nil {
			err = windowsManagedHooksTeardownJournalNamed(
				validateWindowsManagedHooksTeardownJournal(journal, identity), report.JournalPath)
		}
		if err == nil && journal.Phase != "prepared" && journal.Phase != "finalized" {
			err = fmt.Errorf(
				"managed-hook teardown journal phase %q cannot be finalized",
				journal.Phase,
			)
		}
		if err == nil && purgeContractLocks && cleanupReceiptPath == "" {
			err = errors.New("managed hook contract purge requires its protected cleanup receipt")
		}
		if err == nil && cleanupReceiptPath != "" {
			var cleanupReceipt windowsManagedHookContractCleanupReceipt
			cleanupReceipt, err = readWindowsManagedHookContractCleanupReceipt(
				cleanupReceiptPath,
			)
			if err == nil {
				err = validateWindowsManagedHookContractCleanupReceiptBinding(
					cleanupReceipt,
					journal,
					contractCleanupScope,
				)
			}
			if err == nil && purgeContractLocks {
				_, _, _, err = applyWindowsManagedHookContractCleanupReceipt(
					cleanupReceiptPath,
					cleanupReceipt,
				)
			}
		}
		if err == nil {
			var surviving int
			surviving, err = verifyWindowsManagedHooksTeardownClean(opts, journal.Targets)
			report.SurvivingOwnedPathReferences = surviving
		}
		if err == nil {
			// The users' registrations and, with purge, their per-user folders
			// go before the journal records the phase finalized: a rerun of
			// an uninstall interrupted while they were removed finds the
			// phase still prepared and runs finalize, and so this cleanup,
			// again. Once the phase is finalized, a rerun skips finalize.
			report.CollectedGenerationCount, finalizeNotes, err = finalizeWindowsManagedHooksTeardown(
				journal,
				report.JournalPath,
				&report,
				runtimeDir,
				manifest,
			)
		}
		if err == nil {
			report.FinalizationCompleted = true
			report.SafeToRemoveBinary = true
			report.VerifiedCleanCount = report.TargetCount
			report.SucceededCount = report.TargetCount
		}
	}
	if err != nil {
		return fail(err)
	}
	for index := range report.Results {
		report.Results[index].OK = true
		// A completed target can still carry a note, such as runtime
		// generations a failed target's drifted data directory kept.
		key := report.Results[index].Connector + "\x00" + strings.ToUpper(report.Results[index].SID)
		if note, ok := finalizeNotes[key]; ok {
			report.Results[index].Error = note
		}
	}
	report.FailedCount = 0
	// SurvivingOwnedPathReferences is intentionally NOT reset here. The
	// prepare / verify / finalize phases each write the current surviving
	// count into the report (lines 302 / 332 / 386); the field is only
	// ever observed via fail(), so clobbering it on the success tail loses
	// the diagnostic without gaining anything. If the caller reaches this
	// line the report is being returned OK, which already implies zero
	// blocking references. Preserve whatever earlier phase wrote so a
	// future readback (audit dump, test) can see the observation trail.
	report.OK = true
	return report, nil
}

// windowsManagedHooksTeardownCodexRegistryReader reads the protected Codex
// registry for a prepare; tests replace it. A link at the Codex folder is not
// read through (GAP-0773): the result is empty and names the link in Kept.
var windowsManagedHooksTeardownCodexRegistryReader = connector.ResolveWindowsCodexManagedRuntimeRegistryForTeardown

// windowsManagedHooksTeardownCodexRemover is the Codex machine-requirements
// removal of an uninstall, the only caller that keeps a link at the Codex
// machine-policy folder (GAP-0773). Every other caller of the removal (the
// disabled Codex reconcile, the hidden remove action, the guardian) is strict
// and refuses the link. Replaceable in tests.
var windowsManagedHooksTeardownCodexRemover = connector.RemoveWindowsCodexMachineRequirementsForTeardown

// The Codex machine-policy reads of the teardown's rollback and clean check.
// Replaceable in tests.
var (
	windowsManagedHooksCodexFolderKept = connector.WindowsCodexMachineFolderKept
	windowsManagedHooksCodexVerifier   = connector.VerifyWindowsCodexMachineRequirements
	windowsManagedHooksCodexReconciler = connector.ReconcileWindowsCodexMachineRequirements
	windowsManagedHooksCodexPublisher  = connector.PublishWindowsCodexManagedRuntimeTargets
)

// windowsManagedHooksConnectorFolderKept names the link that keeps a
// connector's machine folder (the folder of its runtime selector and, for a
// per-user connector, its enrollment), or "" when there is none (GAP-0773,
// GAP-0829). Replaceable in tests. The Codex folder is named by the Codex
// machine-policy walk, with its own wording.
var windowsManagedHooksConnectorFolderKept = func(connectorName string) (string, error) {
	if connectorName == "codex" {
		return windowsManagedHooksCodexFolderKept()
	}
	return enterprisehooks.WindowsManagedConnectorFolderKept(connectorName)
}

// windowsManagedHooksTeardownConnectorKept reports whether a link keeps the
// machine folder of a connector. The teardown reads nothing behind the link, so
// the activation-binding checks leave that connector's machine state out of
// their comparison with the manifest: the mismatch is the link, not a change.
// A mismatch no kept link explains still refuses.
func windowsManagedHooksTeardownConnectorKept(connectorName string) (bool, error) {
	kept, err := windowsManagedHooksConnectorFolderKept(connectorName)
	return kept != "", err
}

// windowsManagedHooksTeardownSelectorExpectedLive is
// windowsManagedHooksTeardownSelectorExpected for the machine as it is now: a
// selector entry lives in the connector's machine folder, and behind a kept
// link nothing is read, so no entry is expected there.
func windowsManagedHooksTeardownSelectorExpectedLive(
	target windowsManagedHooksTeardownTarget,
	pendingTargets []windowsManagedHooksTeardownTarget,
	activationState string,
) (bool, error) {
	if !windowsManagedHooksTeardownSelectorExpected(target, pendingTargets, activationState) {
		return false, nil
	}
	kept, err := windowsManagedHooksTeardownConnectorKept(target.Connector)
	return !kept, err
}

// captureWindowsManagedHooksTeardownCodexPolicy journals the Codex policy bit
// a zero-target prepare finds. Configuration expects a configured connector's
// guard to be active, but a 1.0.2 or 1.0.3 deployment with no enrolled account
// has no Codex requirements. Prepare records the authenticated registry's
// actual bit, so that preimage does not block teardown and rollback restores
// what was installed; a 1.0.4 empty guard stays active. Enrolled targets, or a
// connector that is not configured, keep the expected bit.
func captureWindowsManagedHooksTeardownCodexPolicy(identity *windowsManagedHooksTeardownJournal) error {
	if !identity.CodexPolicyActive || len(identity.CodexTargets) != 0 {
		return nil
	}
	registry, err := windowsManagedHooksTeardownCodexRegistryReader(identity.HookBinary)
	if err != nil {
		return err
	}
	if registry.Kept != "" {
		// A link at the Codex folder: nothing behind it is read, so the
		// journal keeps the expected bit and the removal keeps the link.
		return nil
	}
	if len(registry.Targets) != 0 {
		return errors.New("codex machine enrollment does not match the protected manifest")
	}
	identity.CodexPolicyActive = registry.Active
	return nil
}

// A standalone uninstall keeps its hooks installed until pending.json is
// retired. Only its inactive tombstone, in the same protected state tree,
// can authorize the subsequent hook removal. Secure Client keeps its
// existing precommit teardown contract.
func windowsManagedHooksTeardownValidationAction(
	metadata windowsCodexDeploymentMetadata,
	action string,
	standalone bool,
	pendingPath string,
) (string, bool, error) {
	if metadata.Installed == nil || *metadata.Installed ||
		(action != "prepare" && action != "verify") {
		return action, false, nil
	}
	if !standalone {
		return "", false, errors.New("committed managed-hook teardown preparation requires standalone profile")
	}
	if _, err := os.Lstat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return "", false, errors.New("committed managed-hook teardown preparation requires transaction retirement")
		}
		return "", false, fmt.Errorf("inspect pending managed-hook transaction: %w", err)
	}
	return "finalize", true, nil
}

// windowsManagedHooksTeardownCheckReady runs, without any write, the
// installed-state checks prepareWindowsManagedHooksTeardown makes before its
// first mutation (GAP-0571). Tests replace it.
var windowsManagedHooksTeardownCheckReady = checkWindowsManagedHooksTeardownReady

func checkWindowsManagedHooksTeardownReady(
	opts connector.WindowsCodexMachineRequirementsOptions,
	identity windowsManagedHooksTeardownJournal,
) error {
	if err := verifyWindowsManagedHooksTeardownInstalled(opts, identity, nil); err != nil {
		return err
	}
	selectorTargets, err := captureWindowsManagedHooksRuntimeSelectors(
		identity.Targets,
		identity.PendingTargets,
		identity.FailedTargets,
		identity.HookBinary,
		identity.ActivationState,
	)
	if err != nil {
		return err
	}
	return verifyWindowsManagedHooksTeardownInstalled(opts, identity, selectorTargets)
}

// windowsManagedHooksTeardownCodexRemovalClean says whether the uninstall may
// go on after the Codex requirements removal. A kept link is the one removal
// that does not attest SafeToRemoveBinary: it was not read, so it is accepted
// by name, as kept and not verified. Every other report needs OK and
// SafeToRemoveBinary, and none may leave a reference to the owned binary tree.
func windowsManagedHooksTeardownCodexRemovalClean(report connector.WindowsCodexMachineRequirementsReport) bool {
	linkKept := report.OK && report.Disposition == "link_kept" && report.LinkKept != ""
	if !linkKept && (!report.OK || !report.SafeToRemoveBinary) {
		return false
	}
	return report.SurvivingOwnedPathReferences == 0
}

func prepareWindowsManagedHooksTeardown(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	identity windowsManagedHooksTeardownJournal,
	journalPath string,
	committedStandalone bool,
) (bool, int, error) {
	if existing, err := readWindowsManagedHooksTeardownJournal(journalPath); err == nil {
		if validateErr := validateWindowsManagedHooksTeardownJournal(existing, identity); validateErr != nil {
			// Name the file: the refusal named no path (GAP-1041).
			return false, 0, fmt.Errorf("%w: %s (phase %s)", validateErr, journalPath, existing.Phase)
		}
		switch existing.Phase {
		case "prepared":
			surviving, verifyErr := verifyWindowsManagedHooksTeardownClean(
				opts,
				existing.Targets,
			)
			if verifyErr == nil {
				return false, surviving, nil
			}
			// A committed uninstall can crash after transaction completion but
			// before PowerShell retires this protected journal. If a later
			// reinstall has restored the exact manifest enrollment, treat the
			// old prepared record as stale and capture a fresh preimage below.
			// Partial or mismatched enrollment still fails the installed-state
			// verification before any mutation.
		case "captured":
			if !committedStandalone {
				return false, 0, errors.New(
					"managed-hook teardown has an incomplete captured transaction; rollback is required",
				)
			}
			// A process-tree kill or reboot after the uninstall commit can
			// interrupt post-commit removal. Restore the captured preimage
			// first, then start a fresh, authenticated removal attempt.
			if err := rollbackWindowsManagedHooksTeardown(
				opts,
				claudeOpts,
				cursorOpts,
				existing,
				journalPath,
			); err != nil {
				return false, 0, fmt.Errorf("restore interrupted committed hook teardown: %w", err)
			}
		case "rolled_back", "finalized":
			// A subsequent lifecycle attempt may safely replace a completed
			// journal after the active set is verified below.
		default:
			return false, 0, fmt.Errorf("unsupported managed-hook teardown journal phase %q", existing.Phase)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, 0, err
	}
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		identity,
		nil,
	); err != nil {
		return false, 0, err
	}
	selectorTargets, err := captureWindowsManagedHooksRuntimeSelectors(
		identity.Targets,
		identity.PendingTargets,
		identity.FailedTargets,
		identity.HookBinary,
		identity.ActivationState,
	)
	if err != nil {
		return false, 0, err
	}
	identity.SelectorTargets = selectorTargets
	if err := verifyWindowsManagedHooksTeardownInstalled(
		opts,
		identity,
		identity.SelectorTargets,
	); err != nil {
		return false, 0, err
	}

	var captured enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot
	var capturedCursor enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot
	persisted := false
	captured, err = enterprisehooks.PrepareWindowsClaudeManagedPolicyTeardown(
		claudeOpts,
		func(snapshot enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot) error {
			var cursorErr error
			capturedCursor, cursorErr = enterprisehooks.PrepareWindowsCursorManagedPolicyTeardown(
				cursorOpts,
				func(cursorSnapshot enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot) error {
					journal := identity
					journal.Phase = "captured"
					journal.Claude = snapshot
					journal.Cursor = cursorSnapshot
					if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
						return err
					}
					persisted = true
					return nil
				},
			)
			return cursorErr
		},
	)
	restoreOnFailure := func(cause error, surviving int) (bool, int, error) {
		journal := identity
		journal.Phase = "captured"
		journal.Claude = captured
		journal.Cursor = capturedCursor
		if rollbackErr := rollbackWindowsManagedHooksTeardown(
			opts,
			claudeOpts,
			cursorOpts,
			journal,
			journalPath,
		); rollbackErr != nil {
			return false, surviving, fmt.Errorf(
				"%v (managed-hook teardown rollback failed: %v)",
				cause,
				rollbackErr,
			)
		}
		return true, surviving, cause
	}
	if err != nil {
		if persisted {
			return restoreOnFailure(err, 0)
		}
		return false, 0, err
	}
	if !persisted {
		return false, 0, errors.New("managed-hook teardown did not durably publish its rollback journal")
	}

	removeReport, err := windowsManagedHooksTeardownCodexRemover(opts)
	if err != nil {
		return restoreOnFailure(err, removeReport.SurvivingOwnedPathReferences)
	}
	if !windowsManagedHooksTeardownCodexRemovalClean(removeReport) {
		return restoreOnFailure(
			errors.New("Codex managed-hook removal was not reference-clean"),
			removeReport.SurvivingOwnedPathReferences,
		)
	}
	if err := removeWindowsManagedHooksStandalonePerUserWiring(identity); err != nil {
		return restoreOnFailure(err, 0)
	}
	if err := removeWindowsManagedHooksRuntimeSelectors(
		identity.Targets,
		identity.HookBinary,
		identity.SelectorTargets,
	); err != nil {
		return restoreOnFailure(err, 0)
	}
	surviving, err := verifyWindowsManagedHooksTeardownClean(opts, identity.Targets)
	if err != nil {
		return restoreOnFailure(err, surviving)
	}
	journal := identity
	journal.Phase = "prepared"
	journal.Claude = captured
	journal.Cursor = capturedCursor
	if err := writeWindowsManagedHooksTeardownJournal(journalPath, journal); err != nil {
		return restoreOnFailure(err, surviving)
	}
	return false, surviving, nil
}

func completeWindowsManagedHooksTeardownRollback(
	journal windowsManagedHooksTeardownJournal,
	restore func() error,
	verify func() error,
	persist func(windowsManagedHooksTeardownJournal) error,
) error {
	switch journal.Phase {
	case "captured", "prepared", "rolled_back":
	default:
		return fmt.Errorf(
			"managed-hook teardown journal phase %q cannot be rolled back",
			journal.Phase,
		)
	}
	verificationErr := verify()
	if verificationErr != nil {
		if journal.Phase == "rolled_back" {
			return verificationErr
		}
		if err := restore(); err != nil {
			return err
		}
		if err := verify(); err != nil {
			return err
		}
	}
	if journal.Phase == "rolled_back" {
		// A failed prepare may already have restored and authenticated every
		// target. Revalidate that state without repeating file replacement.
		return nil
	}
	journal.Phase = "rolled_back"
	return persist(journal)
}

func rollbackWindowsManagedHooksTeardown(
	opts connector.WindowsCodexMachineRequirementsOptions,
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	journal windowsManagedHooksTeardownJournal,
	journalPath string,
) error {
	return completeWindowsManagedHooksTeardownRollback(
		journal,
		func() error {
			if err := restoreWindowsManagedHooksRuntimeSelectors(
				journal.Targets,
				journal.HookBinary,
				journal.SelectorTargets,
			); err != nil {
				return err
			}
			if err := restoreWindowsManagedHooksStandalonePerUserEnrollments(journal); err != nil {
				return err
			}
			current, err := captureWindowsManagedHooksTeardownMachineState(
				claudeOpts,
				cursorOpts,
				journal,
			)
			if err != nil {
				return err
			}
			return restoreWindowsManagedHooksTeardownComposite(
				func() error {
					return enterprisehooks.RestoreWindowsClaudeManagedPolicyTeardown(
						claudeOpts,
						journal.Claude,
					)
				},
				func() error {
					if current.cursorSnapshot.PolicyActive {
						return enterprisehooks.RestoreWindowsCursorManagedPolicySnapshot(
							cursorOpts,
							current.cursorOpts,
							journal.Cursor,
						)
					}
					return enterprisehooks.RestoreWindowsCursorManagedPolicyTeardown(
						cursorOpts,
						journal.Cursor,
					)
				},
				func() error {
					return restoreWindowsCodexManagedHooks(
						opts,
						journal.CodexPolicyActive,
						journal.CodexTargets,
					)
				},
				func() error {
					return enterprisehooks.RestoreWindowsClaudeManagedPolicySnapshot(
						current.claudeOpts,
						claudeOpts,
						current.claudeSnapshot,
					)
				},
				func() error {
					return enterprisehooks.RestoreWindowsCursorManagedPolicySnapshot(
						current.cursorOpts,
						cursorOpts,
						current.cursorSnapshot,
					)
				},
			)
		},
		func() error {
			return verifyWindowsManagedHooksTeardownInstalled(
				opts,
				journal,
				journal.SelectorTargets,
			)
		},
		func(updated windowsManagedHooksTeardownJournal) error {
			return writeWindowsManagedHooksTeardownJournal(journalPath, updated)
		},
	)
}

func captureWindowsManagedHooksTeardownMachineState(
	claudeOpts enterprisehooks.WindowsClaudeManagedPolicyTeardownOptions,
	cursorOpts enterprisehooks.WindowsCursorManagedPolicyTeardownOptions,
	journal windowsManagedHooksTeardownJournal,
) (windowsManagedHooksTeardownMachineCapture, error) {
	var result windowsManagedHooksTeardownMachineCapture
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return result, fmt.Errorf("capture current Claude teardown enrollment: %w", err)
	}
	currentClaude, err = windowsManagedHooksPartialClaudeTargets(
		claudeOpts.TargetSIDs,
		currentClaude,
		claudeActive,
	)
	if err != nil {
		return result, err
	}
	result.claudeOpts = claudeOpts
	result.claudeOpts.TargetSIDs = append([]string(nil), currentClaude...)
	result.claudeSnapshot, err = enterprisehooks.CaptureWindowsClaudeManagedPolicySnapshot(
		result.claudeOpts,
	)
	if err != nil {
		return result, fmt.Errorf("capture current Claude teardown policy: %w", err)
	}

	captureCursor := func() error {
		currentCursor, cursorActive, cursorErr := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
		if cursorErr != nil {
			return fmt.Errorf("capture current Cursor teardown enrollment: %w", cursorErr)
		}
		currentCursor, cursorErr = windowsManagedHooksPartialCursorTargets(
			cursorOpts.Targets,
			currentCursor,
			cursorActive,
		)
		if cursorErr != nil {
			return cursorErr
		}
		result.cursorOpts = cursorOpts
		result.cursorOpts.Targets = append(
			[]enterprisehooks.WindowsCursorManagedRuntimeTarget(nil),
			currentCursor...,
		)
		result.cursorSnapshot, cursorErr = enterprisehooks.CaptureWindowsCursorManagedPolicySnapshot(
			result.cursorOpts,
		)
		if cursorErr != nil {
			return fmt.Errorf("capture current Cursor teardown policy: %w", cursorErr)
		}
		return nil
	}
	initialCursorErr := captureCursor()
	// Cursor deactivation is journaled before Claude is removed. A process
	// crash can therefore leave Cursor at a recognized write prefix while
	// Claude is still the exact installed preimage. Only in that state may the
	// authenticated Cursor teardown restore normalize the partial transaction
	// before we recapture both sides for composite compensation.
	if err := recoverWindowsManagedHooksCursorTeardownCapture(
		initialCursorErr,
		journal.Cursor.PolicyActive &&
			windowsManagedHooksClaudeSnapshotsEqual(result.claudeSnapshot, journal.Claude),
		func() error {
			return enterprisehooks.RestoreWindowsCursorManagedPolicyTeardown(
				cursorOpts,
				journal.Cursor,
			)
		},
		captureCursor,
	); err != nil {
		return result, err
	}
	return result, nil
}

func recoverWindowsManagedHooksCursorTeardownCapture(
	initialCaptureErr error,
	allowJournalHeal bool,
	heal func() error,
	recapture func() error,
) error {
	if initialCaptureErr == nil {
		return nil
	}
	if !allowJournalHeal {
		return initialCaptureErr
	}
	if healErr := heal(); healErr != nil {
		return errors.Join(
			initialCaptureErr,
			fmt.Errorf("heal partial Cursor teardown before rollback: %w", healErr),
		)
	}
	if recaptureErr := recapture(); recaptureErr != nil {
		return errors.Join(
			initialCaptureErr,
			fmt.Errorf("recapture healed Cursor teardown policy: %w", recaptureErr),
		)
	}
	return nil
}

func windowsManagedHooksClaudeSnapshotsEqual(
	left, right enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot,
) bool {
	return left.PolicyExisted == right.PolicyExisted &&
		bytes.Equal(left.Policy, right.Policy) &&
		left.StateExisted == right.StateExisted &&
		bytes.Equal(left.State, right.State)
}

func restoreWindowsManagedHooksTeardownComposite(
	restoreClaude func() error,
	restoreCursor func() error,
	restoreCodex func() error,
	compensateClaude func() error,
	compensateCursor func() error,
) error {
	if err := restoreClaude(); err != nil {
		return err
	}
	if err := restoreCursor(); err != nil {
		if compensateErr := compensateClaude(); compensateErr != nil {
			return errors.Join(
				err,
				fmt.Errorf("restore pre-rollback Claude policy after Cursor failure: %w", compensateErr),
			)
		}
		return err
	}
	if err := restoreCodex(); err != nil {
		failures := []error{err}
		if compensateErr := compensateCursor(); compensateErr != nil {
			failures = append(failures, fmt.Errorf(
				"restore pre-rollback Cursor policy after Codex failure: %w",
				compensateErr,
			))
		}
		if compensateErr := compensateClaude(); compensateErr != nil {
			failures = append(failures, fmt.Errorf(
				"restore pre-rollback Claude policy after Codex failure: %w",
				compensateErr,
			))
		}
		return errors.Join(failures...)
	}
	return nil
}

func restoreWindowsCodexManagedHooks(
	opts connector.WindowsCodexMachineRequirementsOptions,
	policyActive bool,
	targets []connector.WindowsCodexManagedRuntimeTarget,
) error {
	// The removal kept a link at the Codex folder and changed nothing behind
	// it, so there is nothing to restore (GAP-0773).
	kept, err := windowsManagedHooksCodexFolderKept()
	if err != nil {
		return err
	}
	if kept != "" {
		return nil
	}
	opts.CodexTargetEnabled = policyActive
	if !policyActive {
		if len(targets) != 0 {
			return errors.New("inactive Codex rollback preimage contains targets")
		}
		report, err := windowsManagedHooksCodexVerifier(opts)
		if err != nil {
			return err
		}
		if !report.OK || !report.SafeToRemoveBinary ||
			report.SurvivingOwnedPathReferences != 0 {
			return errors.New("Codex machine policy is not clean after teardown rollback")
		}
		return nil
	}
	report, err := windowsManagedHooksCodexReconciler(opts)
	if err != nil {
		return err
	}
	if !report.OK {
		return errors.New("Codex requirements rollback reconcile did not complete")
	}
	if err := windowsManagedHooksCodexPublisher(opts, targets); err != nil {
		return err
	}
	report, err = windowsManagedHooksCodexVerifier(opts)
	if err != nil {
		return err
	}
	if !report.OK {
		return errors.New("Codex requirements rollback verification did not complete")
	}
	return nil
}

func windowsManagedHooksRuntimeSelectorOptions(
	target windowsManagedHooksTeardownTarget,
	hookBinary string,
) enterprisehooks.WindowsManagedRuntimeSelectorSnapshotOptions {
	return enterprisehooks.WindowsManagedRuntimeSelectorSnapshotOptions{
		Connector:      target.Connector,
		TargetSID:      target.SID,
		DataDir:        target.DataDir,
		HookExecutable: hookBinary,
	}
}

func captureWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	pendingTargets []windowsManagedHooksTeardownTarget,
	failedTargets []windowsManagedHooksTeardownTarget,
	hookBinary string,
	activationState string,
) ([]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot, error) {
	snapshots := make(
		[]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
		0,
		len(targets),
	)
	for _, target := range targets {
		snapshot, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"capture %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		expectedPresent, err := windowsManagedHooksTeardownSelectorExpectedLive(
			target,
			pendingTargets,
			activationState,
		)
		if err != nil {
			return nil, err
		}
		if windowsManagedHooksTeardownTargetIn(target, failedTargets) {
			// A failed target may or may not have been wired before it failed;
			// capture whichever state it is in, as long as it is consistent.
			expectedPresent = snapshot.Existed
		}
		if snapshot.Existed != expectedPresent || snapshot.CAS.Exists != expectedPresent {
			state := "absent"
			if expectedPresent {
				state = "present"
			}
			return nil, fmt.Errorf(
				"managed runtime selector for %s target %s is not exactly %s",
				target.Connector,
				target.SID,
				state,
			)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func removeWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	hookBinary string,
	snapshots []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
) error {
	if len(snapshots) != len(targets) {
		return errors.New("managed runtime selector snapshot count does not match the teardown manifest")
	}
	for _, snapshot := range snapshots {
		target, ok := windowsManagedHooksTeardownTargetForSelector(snapshot, targets)
		if !ok {
			return errors.New("managed runtime selector snapshot does not match the teardown manifest")
		}
		if !snapshot.Existed && !snapshot.CAS.Exists {
			current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
				windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
			)
			if err != nil {
				return err
			}
			if current.Existed || current.CAS.Exists {
				return enterprisehooks.ErrWindowsManagedRuntimeGenerationConflict
			}
			continue
		}
		_, err := enterprisehooks.RemoveWindowsManagedRuntimeGenerationEnrollment(
			enterprisehooks.WindowsManagedRuntimeGenerationRemovalOptions{
				Connector:                target.Connector,
				TargetSID:                target.SID,
				DataDir:                  target.DataDir,
				HookExecutable:           hookBinary,
				PrimaryEnrollmentRemoved: true,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"remove %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return err
		}
		if current.Existed || current.CAS.Exists {
			return fmt.Errorf(
				"%s managed runtime selector target %s survived removal",
				target.Connector,
				target.SID,
			)
		}
	}
	return nil
}

func restoreWindowsManagedHooksRuntimeSelectors(
	targets []windowsManagedHooksTeardownTarget,
	hookBinary string,
	snapshots []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
) error {
	if len(snapshots) != len(targets) {
		return errors.New("managed runtime selector snapshot count does not match the teardown manifest")
	}
	for _, snapshot := range snapshots {
		target, ok := windowsManagedHooksTeardownTargetForSelector(snapshot, targets)
		if !ok {
			return errors.New("managed runtime selector snapshot does not match the teardown manifest")
		}
		current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, hookBinary),
		)
		if err != nil {
			return err
		}
		if current.CAS != snapshot.CAS && current.CAS.Exists {
			return enterprisehooks.ErrWindowsManagedRuntimeGenerationConflict
		}
		if err := enterprisehooks.RestoreWindowsManagedRuntimeSelectorTargetCAS(
			enterprisehooks.WindowsManagedRuntimeSelectorRestoreOptions{
				Snapshot:        snapshot,
				ExpectedCurrent: current.CAS,
			},
		); err != nil {
			return fmt.Errorf(
				"restore %s managed runtime selector target %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
	}
	return nil
}

// finalizeWindowsManagedHooksTeardown runs after the uninstall has committed:
// the hooks are already removed. It collects unreferenced runtime
// generations, retires the machine wiring the prepared journal records,
// removes the users' registrations and, with purge, their per-user folders,
// and only then records the phase finalized, so a rerun after an
// interruption finds the phase prepared and retries that cleanup. A target
// the Guardian reported as failed may have failed because its data directory
// drifted, which also makes its generation collection refuse; that target's
// generations are left behind and reported as a note instead of failing a
// committed uninstall on every retry.
func finalizeWindowsManagedHooksTeardown(
	journal windowsManagedHooksTeardownJournal,
	journalPath string,
	report *windowsManagedHooksTeardownReport,
	runtimeDir string,
	manifest enterprisehooks.Manifest,
) (int, map[string]string, error) {
	collected := 0
	notes := map[string]string{}
	for _, target := range journal.Targets {
		removed, err := enterprisehooks.GarbageCollectWindowsManagedRuntimeGenerations(
			enterprisehooks.WindowsManagedRuntimeGenerationGCOptions{
				Connector:      target.Connector,
				TargetSID:      target.SID,
				DataDir:        target.DataDir,
				HookExecutable: journal.HookBinary,
				Retired:        true,
			},
		)
		if err != nil {
			if windowsManagedHooksTeardownTargetIn(target, journal.FailedTargets) {
				notes[target.Connector+"\x00"+strings.ToUpper(target.SID)] = fmt.Sprintf(
					"hooks removed; runtime generations left in place: %v", err,
				)
				continue
			}
			return collected, notes, fmt.Errorf(
				"finalize %s managed runtime generations for %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		collected += removed
	}
	if err := windowsManagedHooksTeardownStandaloneMachineFinalizer(); err != nil {
		return collected, notes, err
	}
	completeWindowsManagedHooksTeardownUserCleanup(report, runtimeDir, manifest)
	journal.Phase = "finalized"
	if err := windowsManagedHooksTeardownJournalWriter(journalPath, journal); err != nil {
		return collected, notes, err
	}
	return collected, notes, nil
}

// The standalone machine steps of finalize and the journal writer are
// replaceable in tests.
var (
	windowsManagedHooksTeardownStandaloneMachineFinalizer = finalizeWindowsManagedHooksTeardownStandaloneMachineState
	windowsManagedHooksTeardownJournalWriter              = writeWindowsManagedHooksTeardownJournal
	// Which activation-drift rule teardown applies (GAP-0583); tests pin it.
	windowsManagedHooksTeardownStandaloneProcess = enterprisehooks.WindowsStandaloneProcess
)

func finalizeWindowsManagedHooksTeardownStandaloneMachineState() error {
	// Standalone: a local account deleted with its profile has left the
	// manifest, so the teardown never reached its selector entries.
	// They go now, before the selector locks below. Failing to drop one only
	// leaves that stale entry, so it does not fail the uninstall.
	if err := enterprisehooks.RemoveWindowsStandaloneDeletedAccountSelectorTargets(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: stale runtime selector entries were kept: %v\n", err)
	}
	// Standalone: the per-user connector directories and the hook runtime
	// root hold only lock files by now (verification proved enrollments,
	// selectors and the summary gone), so an uninstall leaves none behind.
	if _, err := enterprisehooks.RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil {
		return fmt.Errorf("finalize standalone hook runtime directories: %w", err)
	}
	// Finalize's garbage collection was the last selector transaction, so the
	// selector locks in the vendor machine-policy directories can go too.
	if err := enterprisehooks.RemoveWindowsStandaloneMachinePolicySelectorLocks(); err != nil {
		return fmt.Errorf("finalize standalone machine-policy selector locks: %w", err)
	}
	// Secure Client: DefenseClaw's folder in Copilot's machine folder holds
	// only lock files by now.
	if _, err := enterprisehooks.RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil {
		return fmt.Errorf("finalize the GitHub Copilot runtime folder: %w", err)
	}
	if err := finalizeWindowsManagedHooksTeardownAmpFolder(); err != nil {
		return fmt.Errorf("finalize the Setup-created Amp machine folder: %w", err)
	}
	return nil
}

var windowsManagedHooksTeardownAmpFolderCleaner = func() error {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return fmt.Errorf("resolve standalone machine policy for Amp cleanup: %w", err)
	}
	return enterprisepolicy.RemoveWindowsAmpMachineFolderIfCreated(
		enterprisepolicy.LayoutOptions(layout, programFiles, programData))
}

func finalizeWindowsManagedHooksTeardownAmpFolder() error {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	return windowsManagedHooksTeardownAmpFolderCleaner()
}

func windowsManagedHooksTeardownTargetForSelector(
	snapshot enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
	targets []windowsManagedHooksTeardownTarget,
) (windowsManagedHooksTeardownTarget, bool) {
	for _, target := range targets {
		if target.Connector == snapshot.Connector && target.SID == snapshot.TargetSID {
			return target, true
		}
	}
	return windowsManagedHooksTeardownTarget{}, false
}

func windowsManagedHooksTeardownSelectorExpected(
	target windowsManagedHooksTeardownTarget,
	pendingTargets []windowsManagedHooksTeardownTarget,
	activationState string,
) bool {
	if activationState != windowsManagedHooksActivated {
		return false
	}
	if hookBinary, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector); perUser && !hookBinary {
		// Plugin connectors never execute the hook binary and never publish a
		// runtime selector.
		return false
	}
	for _, pending := range pendingTargets {
		if pending.Connector == target.Connector &&
			strings.EqualFold(pending.SID, target.SID) {
			return false
		}
	}
	return true
}

// windowsManagedHooksTeardownTargetIn reports whether target is in set.
func windowsManagedHooksTeardownTargetIn(
	target windowsManagedHooksTeardownTarget,
	set []windowsManagedHooksTeardownTarget,
) bool {
	for _, candidate := range set {
		if candidate.Connector == target.Connector && strings.EqualFold(candidate.SID, target.SID) {
			return true
		}
	}
	return false
}

// validateWindowsManagedHooksFailedTargetSubset binds the failed targets a
// degraded Guardian reported to the protected manifest: each one must be an
// exact manifest target, appear once, and not also be pending.
func validateWindowsManagedHooksFailedTargetSubset(
	targets []windowsManagedHooksTeardownTarget,
	pendingTargets []windowsManagedHooksTeardownTarget,
	failedTargets []windowsManagedHooksTeardownTarget,
	activationState string,
) error {
	if activationState != windowsManagedHooksActivated && len(failedTargets) != 0 {
		return errors.New("never-activated teardown journal contains failed target evidence")
	}
	allowed := make(map[string]windowsManagedHooksTeardownTarget, len(targets))
	for _, target := range targets {
		allowed[target.Connector+"\x00"+strings.ToUpper(target.SID)] = target
	}
	seen := make(map[string]struct{}, len(failedTargets))
	for _, failed := range failedTargets {
		key := failed.Connector + "\x00" + strings.ToUpper(failed.SID)
		if target, ok := allowed[key]; !ok || target != failed {
			return errors.New("failed teardown target is outside the protected manifest")
		}
		if windowsManagedHooksTeardownTargetIn(failed, pendingTargets) {
			return errors.New("failed teardown target is also pending")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("failed teardown target set contains a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateWindowsManagedHooksPendingTargetSubset(
	targets []windowsManagedHooksTeardownTarget,
	pendingTargets []windowsManagedHooksTeardownTarget,
	activationState string,
) error {
	if activationState != windowsManagedHooksActivated && len(pendingTargets) != 0 {
		return errors.New("never-activated teardown journal contains pending target evidence")
	}
	allowed := make(map[string]windowsManagedHooksTeardownTarget, len(targets))
	for _, target := range targets {
		key := target.Connector + "\x00" + strings.ToUpper(target.SID)
		allowed[key] = target
	}
	seen := make(map[string]struct{}, len(pendingTargets))
	for _, pending := range pendingTargets {
		key := pending.Connector + "\x00" + strings.ToUpper(pending.SID)
		target, ok := allowed[key]
		if !ok || target != pending {
			return errors.New("pending teardown target is outside the protected manifest")
		}
		if !pending.Deferred {
			return errors.New("pending teardown target is not authorized for deferred enrollment")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pending teardown target set contains a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func verifyWindowsManagedHooksTeardownClean(
	opts connector.WindowsCodexMachineRequirementsOptions,
	targets []windowsManagedHooksTeardownTarget,
) (int, error) {
	if err := enterprisehooks.VerifyWindowsClaudeManagedPolicyTeardown(); err != nil {
		return 0, err
	}
	if err := enterprisehooks.VerifyWindowsCursorManagedPolicyTeardown(); err != nil {
		return 0, err
	}
	if surviving, err := verifyWindowsManagedHooksCodexClean(opts); err != nil {
		return surviving, err
	}
	if err := verifyWindowsManagedHooksStandalonePerUserClean(); err != nil {
		return 0, err
	}
	for _, target := range targets {
		snapshot, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
			windowsManagedHooksRuntimeSelectorOptions(target, opts.HookBinary),
		)
		if err != nil {
			return 0, fmt.Errorf(
				"verify %s selector teardown for %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		if snapshot.Existed || snapshot.CAS.Exists {
			return 0, fmt.Errorf(
				"managed runtime selector still enrolls %s target %s",
				target.Connector,
				target.SID,
			)
		}
	}
	return 0, nil
}

// verifyWindowsManagedHooksCodexClean verifies the Codex machine policy holds
// nothing of DefenseClaw after a teardown. Behind a kept link nothing is read,
// so there is nothing to verify (GAP-0773).
func verifyWindowsManagedHooksCodexClean(opts connector.WindowsCodexMachineRequirementsOptions) (int, error) {
	disabled := opts
	disabled.CodexTargetEnabled = false
	kept, err := windowsManagedHooksCodexFolderKept()
	if err != nil {
		return 0, err
	}
	if kept != "" {
		return 0, nil
	}
	report, err := windowsManagedHooksCodexVerifier(disabled)
	if err != nil {
		return report.SurvivingOwnedPathReferences, err
	}
	if !report.OK || !report.SafeToRemoveBinary ||
		report.SurvivingOwnedPathReferences != 0 {
		return report.SurvivingOwnedPathReferences, errors.New(
			"the Codex machine requirements are not clean after managed-hook teardown",
		)
	}
	return 0, nil
}

func verifyWindowsManagedHooksTeardownInstalled(
	opts connector.WindowsCodexMachineRequirementsOptions,
	identity windowsManagedHooksTeardownJournal,
	selectorTargets []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot,
) error {
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return err
	}
	registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistryForTeardown(opts.HookBinary)
	if err != nil {
		return err
	}
	currentCursor, cursorActive, err := enterprisehooks.ReadWindowsCursorManagedPolicyTargets()
	if err != nil {
		return err
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(
		identity,
		currentClaude,
		claudeActive,
		registry,
		currentCursor,
		cursorActive,
	); err != nil {
		return err
	}
	if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err != nil {
		return err
	}
	if selectorTargets != nil {
		if len(selectorTargets) != len(identity.Targets) {
			return errors.New("managed runtime selector snapshot count does not match the teardown manifest")
		}
		for _, expected := range selectorTargets {
			target, ok := windowsManagedHooksTeardownTargetForSelector(expected, identity.Targets)
			if !ok {
				return errors.New("managed runtime selector snapshot does not match the teardown manifest")
			}
			expectedPresent, err := windowsManagedHooksTeardownSelectorExpectedLive(
				target,
				identity.PendingTargets,
				identity.ActivationState,
			)
			if err != nil {
				return err
			}
			if windowsManagedHooksTeardownTargetIn(target, identity.FailedTargets) {
				expectedPresent = expected.Existed
			}
			if expected.Existed != expectedPresent || expected.CAS.Exists != expectedPresent {
				return fmt.Errorf(
					"managed runtime selector snapshot has the wrong activation state for %s target %s",
					expected.Connector,
					expected.TargetSID,
				)
			}
			current, err := enterprisehooks.CaptureWindowsManagedRuntimeSelectorTarget(
				windowsManagedHooksRuntimeSelectorOptions(target, opts.HookBinary),
			)
			if err != nil {
				return err
			}
			if current.CAS != expected.CAS ||
				current.Existed != expected.Existed ||
				current.TargetSHA256 != expected.TargetSHA256 ||
				!bytes.Equal(current.Target, expected.Target) {
				return fmt.Errorf(
					"managed runtime selector changed for %s target %s",
					expected.Connector,
					expected.TargetSID,
				)
			}
		}
	}
	return nil
}

func validateWindowsManagedHooksTeardownEnrollment(
	identity windowsManagedHooksTeardownJournal,
	currentClaude []string,
	claudeActive bool,
	currentCodex connector.WindowsCodexManagedRuntimeRegistry,
	currentCursor []enterprisehooks.WindowsCursorManagedRuntimeTarget,
	cursorActive bool,
) error {
	// A connector whose machine folder a link keeps has nothing readable to
	// compare (GAP-0773, GAP-0829): the reads above returned empty for it.
	claudeKept, err := windowsManagedHooksTeardownConnectorKept("claudecode")
	if err != nil {
		return err
	}
	if !claudeKept && ((len(identity.ClaudeTargetSIDs) != 0 && !claudeActive) ||
		!equalWindowsEnterpriseStringSet(currentClaude, identity.ClaudeTargetSIDs)) {
		return errors.New("Claude machine enrollment does not match the authenticated activation state")
	}
	if currentCodex.Kept != "" {
		// A link at the Codex folder is kept and not read through (GAP-0773),
		// so there is no Codex enrollment to compare.
		currentCodex = connector.WindowsCodexManagedRuntimeRegistry{
			Active:  identity.CodexPolicyActive,
			Targets: identity.CodexTargets,
		}
	}
	if currentCodex.Active != identity.CodexPolicyActive ||
		len(currentCodex.Targets) != len(identity.CodexTargets) {
		return errors.New("Codex machine enrollment does not match the authenticated activation state")
	}
	currentCodexTargets := append(
		[]connector.WindowsCodexManagedRuntimeTarget(nil),
		currentCodex.Targets...,
	)
	sort.Slice(currentCodexTargets, func(i, j int) bool {
		return currentCodexTargets[i].SID < currentCodexTargets[j].SID
	})
	for index := range identity.CodexTargets {
		if currentCodexTargets[index].SID != identity.CodexTargets[index].SID ||
			!sameWindowsEnterprisePathCLI(
				currentCodexTargets[index].DataDir,
				identity.CodexTargets[index].DataDir,
			) {
			return errors.New("Codex machine enrollment does not match the authenticated activation state")
		}
	}
	cursorKept, err := windowsManagedHooksTeardownConnectorKept("cursor")
	if err != nil {
		return err
	}
	if cursorKept {
		return nil
	}
	if (len(identity.CursorTargets) != 0 && !cursorActive) ||
		len(currentCursor) != len(identity.CursorTargets) {
		return errors.New("Cursor machine enrollment does not match the authenticated activation state")
	}
	for index := range identity.CursorTargets {
		if !strings.EqualFold(currentCursor[index].SID, identity.CursorTargets[index].SID) ||
			!sameWindowsEnterprisePathCLI(
				currentCursor[index].DataDir,
				identity.CursorTargets[index].DataDir,
			) {
			return errors.New("Cursor machine enrollment does not match the authenticated activation state")
		}
	}
	return nil
}

// acceptWindowsManagedHooksActivationDrift logs, and tolerates, an
// activation record whose manifest digest or target count no longer matches
// the live manifest. The enumerator republishes the manifest for agent
// version bumps and new users after the installer pinned it; the deployment
// generation and the Guardian's row-level evidence still authenticate
// teardown.
func acceptWindowsManagedHooksActivationDrift(
	activation windowsManagedHooksActivationRecord,
	manifestSHA256 string,
	targetCount int,
) {
	if activation.ManifestSHA256 == manifestSHA256 && activation.TargetCount == targetCount {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
		"reason":           "managed-hook activation evidence predates the current manifest",
		"pinned_sha256":    activation.ManifestSHA256,
		"manifest_sha256":  manifestSHA256,
		"pinned_targets":   strconv.Itoa(activation.TargetCount),
		"manifest_targets": strconv.Itoa(targetCount),
	})
}

func validateWindowsManagedHooksTeardownActivation(
	record *windowsManagedHooksActivationRecord,
	manifestSHA256 string,
	targetCount int,
) (windowsManagedHooksActivationRecord, error) {
	if record == nil {
		return windowsManagedHooksActivationRecord{}, errors.New(
			"protected deployment metadata is missing managed-hook activation evidence",
		)
	}
	activation := *record
	if activation.SchemaVersion != 1 ||
		!validEnterpriseHookHex(activation.DeploymentGenerationID, 16) ||
		(activation.State != windowsManagedHooksNeverActivated &&
			activation.State != windowsManagedHooksActivated) ||
		!validEnterpriseHookHex(activation.ManifestSHA256, sha256.Size) ||
		activation.TargetCount < 0 ||
		activation.TargetCount > windowsManagedHooksTeardownTargetMax ||
		targetCount < 0 || targetCount > windowsManagedHooksTeardownTargetMax {
		return windowsManagedHooksActivationRecord{}, errors.New(
			"protected managed-hook activation evidence does not match the current manifest",
		)
	}
	// rel-1-0-6:GAP-0583: standalone refuses the drift, as the standalone
	// lifecycle binding does (windowsManagedHooksLifecycleCommittedTransactionID)
	// and as 1.0.7 did. The PowerShell side pins the teardown journal and the
	// contract cleanup receipt to the deployment's activation manifest, so a
	// teardown that accepted a republished manifest (an enumerator pass that
	// dropped a deleted enrolled account) let the uninstall pre-commit check
	// pass, committed the tombstone, then wrote a journal and receipt the
	// tombstone could never authenticate: every retry and Setup /ensure failed
	// 1603 until /uninstall FORCE=1. The refusal is the catch-up refusal the
	// uninstall check waits on (GAP-0319/GAP-0346): it rebinds the activation
	// evidence to the manifest the guardian adopted, then commits. Secure
	// Client keeps the 26.8.4 accept-and-log handling.
	if windowsManagedHooksTeardownStandaloneProcess() {
		if activation.ManifestSHA256 != manifestSHA256 || activation.TargetCount != targetCount {
			return windowsManagedHooksActivationRecord{}, errors.New(
				"protected managed-hook activation evidence does not match the current manifest",
			)
		}
		return activation, nil
	}
	acceptWindowsManagedHooksActivationDrift(activation, manifestSHA256, targetCount)
	return activation, nil
}

func validateWindowsManagedHooksTeardownDeployment(
	metadata windowsCodexDeploymentMetadata,
	action string,
	manifestSHA256 string,
	targetCount int,
) (windowsManagedHooksActivationRecord, error) {
	switch action {
	case "prepare", "verify", "rollback", "check":
		// A rollback runs only after the transaction restore has put the exact
		// installed metadata preimage back in place. Accept the legacy omitted
		// installed flag as active, but never let an inactive tombstone authorize
		// mutation or restoration of machine enrollment.
		if metadata.Installed != nil && !*metadata.Installed {
			return windowsManagedHooksActivationRecord{}, fmt.Errorf(
				"managed-hook teardown %s requires active deployment metadata",
				action,
			)
		}
	case "finalize":
		// Finalization crosses the uninstall commit boundary. Require the
		// explicit inactive tombstone as well as its preserved activation
		// binding; legacy metadata with an omitted installed flag is active.
		if metadata.Installed == nil || *metadata.Installed {
			return windowsManagedHooksActivationRecord{}, errors.New(
				"managed-hook teardown finalize requires an inactive deployment tombstone",
			)
		}
	default:
		return windowsManagedHooksActivationRecord{}, fmt.Errorf(
			"unsupported managed-hook teardown action %q",
			action,
		)
	}
	return validateWindowsManagedHooksTeardownActivation(
		metadata.ManagedHooksActivation,
		manifestSHA256,
		targetCount,
	)
}

func windowsManagedHooksTeardownExpectedEnrollment(
	activationState string,
	codexConfigured bool,
	claudeTargets []string,
	codexTargets []connector.WindowsCodexManagedRuntimeTarget,
	cursorTargets []enterprisehooks.WindowsCursorManagedRuntimeTarget,
) (
	[]string,
	bool,
	[]connector.WindowsCodexManagedRuntimeTarget,
	[]enterprisehooks.WindowsCursorManagedRuntimeTarget,
) {
	codexPolicyActive := codexConfigured || len(codexTargets) != 0
	if activationState == windowsManagedHooksNeverActivated {
		return []string{}, codexPolicyActive,
			[]connector.WindowsCodexManagedRuntimeTarget{},
			[]enterprisehooks.WindowsCursorManagedRuntimeTarget{}
	}
	// append([]T(nil), src...) returns nil when src has length zero, which
	// then marshals as JSON `null` and used to trip the reader's presence
	// check on retry. Guarantee an empty-non-nil slice for each connector
	// target list so the journal always writes `[]` even for connectors
	// that had no eligible interactive users at install time on a given
	// box (single-user VMs, deployments with connector-uses-nobody, etc.).
	claudeCopy := append([]string{}, claudeTargets...)
	codexCopy := append(
		[]connector.WindowsCodexManagedRuntimeTarget{},
		codexTargets...,
	)
	cursorCopy := append(
		[]enterprisehooks.WindowsCursorManagedRuntimeTarget{},
		cursorTargets...,
	)
	return claudeCopy, codexPolicyActive, codexCopy, cursorCopy
}

func equalWindowsManagedHooksCodexTargets(
	left, right []connector.WindowsCodexManagedRuntimeTarget,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].SID != right[index].SID ||
			!sameWindowsEnterprisePathCLI(left[index].DataDir, right[index].DataDir) {
			return false
		}
	}
	return true
}

func equalWindowsManagedHooksCursorTargets(
	left, right []enterprisehooks.WindowsCursorManagedRuntimeTarget,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index].SID, right[index].SID) ||
			!sameWindowsEnterprisePathCLI(left[index].DataDir, right[index].DataDir) {
			return false
		}
	}
	return true
}

func windowsManagedHooksTeardownTargets(
	manifest enterprisehooks.Manifest,
) (
	[]windowsManagedHooksTeardownTarget,
	[]string,
	[]connector.WindowsCodexManagedRuntimeTarget,
	[]enterprisehooks.WindowsCursorManagedRuntimeTarget,
	error,
) {
	targets := make([]windowsManagedHooksTeardownTarget, 0, len(manifest.Targets))
	claude := make([]string, 0, len(manifest.Targets))
	codex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(manifest.Targets))
	cursor := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		sid, err := windows.StringToSid(strings.TrimSpace(target.SID))
		if err != nil || sid == nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid managed-hook teardown SID %q", target.SID)
		}
		connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
		if connectorName != "claudecode" && connectorName != "codex" && connectorName != "cursor" &&
			!windowsManagedHooksStandalonePerUserTarget(connectorName) {
			return nil, nil, nil, nil, fmt.Errorf(
				"managed-hook teardown does not support connector %q",
				target.Connector,
			)
		}
		dataDir := filepath.Join(filepath.Clean(target.UserHome), ".defenseclaw")
		if configured := strings.TrimSpace(target.DataDir); configured != "" {
			configured, err = filepath.Abs(configured)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			configured = filepath.Clean(configured)
			if !sameWindowsEnterprisePathCLI(configured, dataDir) {
				return nil, nil, nil, nil, fmt.Errorf(
					"managed-hook teardown target %s data_dir does not equal canonical %s",
					sid,
					dataDir,
				)
			}
		}
		row := windowsManagedHooksTeardownTarget{
			Connector:    connectorName,
			SID:          sid.String(),
			DataDir:      dataDir,
			AgentVersion: strings.TrimSpace(target.AgentVersion),
			Deferred:     target.IsDeferred(),
		}
		targets = append(targets, row)
		switch connectorName {
		case "claudecode":
			claude = append(claude, row.SID)
		case "codex":
			codex = append(codex, connector.WindowsCodexManagedRuntimeTarget{
				SID:     row.SID,
				DataDir: row.DataDir,
			})
		case "cursor":
			cursor = append(cursor, enterprisehooks.WindowsCursorManagedRuntimeTarget{
				SID: row.SID, DataDir: row.DataDir,
			})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Connector == targets[j].Connector {
			return targets[i].SID < targets[j].SID
		}
		return targets[i].Connector < targets[j].Connector
	})
	sort.Strings(claude)
	sort.Slice(codex, func(i, j int) bool { return codex[i].SID < codex[j].SID })
	sort.Slice(cursor, func(i, j int) bool { return cursor[i].SID < cursor[j].SID })
	return targets, claude, codex, cursor, nil
}

func windowsManagedHooksTeardownFingerprint(
	targets []windowsManagedHooksTeardownTarget,
) (string, error) {
	body, err := json.Marshal(targets)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// windowsManagedHooksTeardownJournalNamed adds the journal path to a
// validation failure, which named no file (GAP-1041).
func windowsManagedHooksTeardownJournalNamed(err error, path string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", err, path)
}

func validateWindowsManagedHooksTeardownJournal(
	journal, identity windowsManagedHooksTeardownJournal,
) error {
	if !validWindowsManagedHooksTeardownJournalSchema(journal, identity) ||
		journal.ManifestPath != identity.ManifestPath ||
		journal.ManifestSHA256 != identity.ManifestSHA256 ||
		journal.ManifestFingerprint != identity.ManifestFingerprint ||
		journal.ActivationState != identity.ActivationState ||
		journal.DeploymentGenerationID != identity.DeploymentGenerationID ||
		journal.HookBinary != identity.HookBinary ||
		journal.GatewayAddr != identity.GatewayAddr ||
		journal.GatewayServiceName != identity.GatewayServiceName ||
		(journal.CodexPolicyActive != identity.CodexPolicyActive &&
			(len(journal.CodexTargets) != 0 || len(identity.CodexTargets) != 0)) ||
		len(journal.Targets) != len(identity.Targets) ||
		len(journal.PendingTargets) != len(identity.PendingTargets) ||
		len(journal.FailedTargets) != len(identity.FailedTargets) ||
		len(journal.ClaudeTargetSIDs) != len(identity.ClaudeTargetSIDs) ||
		len(journal.CodexTargets) != len(identity.CodexTargets) ||
		len(journal.CursorTargets) != len(identity.CursorTargets) {
		return errors.New("managed-hook teardown journal does not match the protected deployment")
	}
	if !validEnterpriseHookHex(journal.ManifestSHA256, sha256.Size) ||
		!validEnterpriseHookHex(journal.DeploymentGenerationID, 16) ||
		(journal.ActivationState != windowsManagedHooksNeverActivated &&
			journal.ActivationState != windowsManagedHooksActivated) {
		return errors.New("managed-hook teardown journal has invalid activation evidence")
	}
	for index := range identity.Targets {
		if journal.Targets[index] != identity.Targets[index] {
			return errors.New("managed-hook teardown journal target set changed")
		}
	}
	for index := range identity.PendingTargets {
		if journal.PendingTargets[index] != identity.PendingTargets[index] {
			return errors.New("managed-hook teardown journal pending target set changed")
		}
	}
	for index := range identity.FailedTargets {
		if journal.FailedTargets[index] != identity.FailedTargets[index] {
			return errors.New("managed-hook teardown journal failed target set changed")
		}
	}
	if err := validateWindowsManagedHooksPendingTargetSubset(
		journal.Targets,
		journal.PendingTargets,
		journal.ActivationState,
	); err != nil {
		return err
	}
	if err := validateWindowsManagedHooksFailedTargetSubset(
		journal.Targets,
		journal.PendingTargets,
		journal.FailedTargets,
		journal.ActivationState,
	); err != nil {
		return err
	}
	for index := range identity.ClaudeTargetSIDs {
		if journal.ClaudeTargetSIDs[index] != identity.ClaudeTargetSIDs[index] {
			return errors.New("managed-hook teardown journal Claude target set changed")
		}
	}
	for index := range identity.CodexTargets {
		if journal.CodexTargets[index] != identity.CodexTargets[index] {
			return errors.New("managed-hook teardown journal Codex target set changed")
		}
	}
	for index := range identity.CursorTargets {
		if journal.CursorTargets[index] != identity.CursorTargets[index] {
			return errors.New("managed-hook teardown journal Cursor target set changed")
		}
	}
	if len(journal.SelectorTargets) != len(identity.Targets) {
		return errors.New("managed-hook teardown journal selector target set changed")
	}
	for index, target := range identity.Targets {
		snapshot := journal.SelectorTargets[index]
		if snapshot.SchemaVersion != 1 ||
			snapshot.Connector != target.Connector ||
			snapshot.TargetSID != target.SID {
			return errors.New("managed-hook teardown journal contains an invalid selector snapshot")
		}
		expectedPresent, err := windowsManagedHooksTeardownSelectorExpectedLive(
			target,
			journal.PendingTargets,
			journal.ActivationState,
		)
		if err != nil {
			return err
		}
		if windowsManagedHooksTeardownTargetIn(target, journal.FailedTargets) {
			// Validate a failed target's snapshot in whichever shape it was
			// captured: an exact enrollment, or an exact absence.
			expectedPresent = snapshot.Existed || snapshot.CAS.Exists
		}
		if !expectedPresent {
			if snapshot.Existed || snapshot.CAS.Exists || len(snapshot.Target) != 0 ||
				snapshot.TargetSHA256 != "" || snapshot.CAS.GenerationID != "" ||
				snapshot.CAS.BundleSHA256 != "" || snapshot.CAS.TargetSHA256 != "" {
				return errors.New("pending or never-activated teardown target contains a selector enrollment")
			}
			continue
		}
		digest := sha256.Sum256(snapshot.Target)
		targetDigest := "sha256:" + hex.EncodeToString(digest[:])
		if !snapshot.Existed || !snapshot.CAS.Exists ||
			len(snapshot.Target) == 0 ||
			len(snapshot.Target) > windowsManagedHooksTeardownJournalMax ||
			snapshot.TargetSHA256 != targetDigest ||
			snapshot.CAS.TargetSHA256 != targetDigest ||
			!windowsManagedHooksValidGenerationID(snapshot.CAS.GenerationID) ||
			!windowsManagedHooksValidSHA256(snapshot.CAS.BundleSHA256) {
			return errors.New("managed-hook teardown journal contains an invalid selector snapshot")
		}
	}
	allowedClaudeTargets := make([]string, 0, len(identity.Targets))
	allowedCodexTargets := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(identity.Targets))
	for _, target := range identity.Targets {
		if target.Connector == "claudecode" {
			allowedClaudeTargets = append(allowedClaudeTargets, target.SID)
		} else if target.Connector == "codex" {
			allowedCodexTargets = append(allowedCodexTargets, connector.WindowsCodexManagedRuntimeTarget{
				SID: target.SID, DataDir: target.DataDir,
			})
		}
	}
	if journal.ActivationState == windowsManagedHooksActivated {
		if !equalWindowsEnterpriseStringSet(allowedClaudeTargets, identity.ClaudeTargetSIDs) ||
			!equalWindowsManagedHooksCodexTargets(allowedCodexTargets, identity.CodexTargets) ||
			(len(allowedCodexTargets) != 0 && !identity.CodexPolicyActive) {
			return errors.New("activated teardown journal does not contain the exact manifest enrollment")
		}
	} else if len(identity.ClaudeTargetSIDs) != 0 || len(identity.CodexTargets) != 0 ||
		(len(allowedCodexTargets) != 0 && !identity.CodexPolicyActive) {
		return errors.New("never-activated teardown journal contains an invalid machine enrollment")
	}
	// A snapshot taken behind a kept link is empty: nothing was read there
	// (GAP-0773, GAP-0829), so an empty snapshot is valid for that connector.
	claudeSnapshotKept, err := windowsManagedHooksTeardownConnectorKept("claudecode")
	if err != nil {
		return err
	}
	cursorSnapshotKept, err := windowsManagedHooksTeardownConnectorKept("cursor")
	if err != nil {
		return err
	}
	if journal.Claude.PolicyExisted != journal.Claude.StateExisted ||
		len(journal.Claude.Policy) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Claude.State) > windowsManagedHooksTeardownJournalMax ||
		(len(journal.ClaudeTargetSIDs) != 0 && !journal.Claude.PolicyExisted && !claudeSnapshotKept) {
		return errors.New("managed-hook teardown journal contains an invalid Claude snapshot")
	}
	allowedCursorTargets := make([]enterprisehooks.WindowsCursorManagedRuntimeTarget, 0, len(identity.Targets))
	for _, target := range identity.Targets {
		if target.Connector == "cursor" {
			allowedCursorTargets = append(allowedCursorTargets, enterprisehooks.WindowsCursorManagedRuntimeTarget{
				SID: target.SID, DataDir: target.DataDir,
			})
		}
	}
	if journal.ActivationState == windowsManagedHooksActivated &&
		!equalWindowsManagedHooksCursorTargets(allowedCursorTargets, identity.CursorTargets) {
		return errors.New("activated teardown journal does not contain the exact Cursor manifest enrollment")
	} else if journal.ActivationState == windowsManagedHooksNeverActivated &&
		len(identity.CursorTargets) != 0 {
		return errors.New("never-activated teardown journal contains a Cursor enrollment")
	}
	cursorSnapshotActive := journal.Cursor.PolicyActive
	if journal.Cursor.StateExisted != cursorSnapshotActive ||
		journal.Cursor.ReceiptExisted != cursorSnapshotActive ||
		(cursorSnapshotActive && (!journal.Cursor.AdapterExisted || !journal.Cursor.HooksExisted)) ||
		len(journal.Cursor.Hooks) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.Adapter) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.State) > windowsManagedHooksTeardownJournalMax ||
		len(journal.Cursor.Receipt) > windowsManagedHooksTeardownJournalMax ||
		(journal.Cursor.HooksExisted != (journal.Cursor.HooksSecurityDescriptor != "" && journal.Cursor.HooksAttributes != 0)) ||
		(journal.Cursor.AdapterExisted != (journal.Cursor.AdapterSecurityDescriptor != "" && journal.Cursor.AdapterAttributes != 0)) ||
		(journal.Cursor.StateExisted != (journal.Cursor.StateSecurityDescriptor != "" && journal.Cursor.StateAttributes != 0)) ||
		(journal.Cursor.ReceiptExisted != (journal.Cursor.ReceiptSecurityDescriptor != "" && journal.Cursor.ReceiptAttributes != 0)) ||
		(len(journal.CursorTargets) != 0 && !cursorSnapshotActive && !cursorSnapshotKept) {
		return errors.New("managed-hook teardown journal contains an invalid Cursor snapshot")
	}
	return nil
}

func validWindowsManagedHooksTeardownJournalSchema(
	journal, identity windowsManagedHooksTeardownJournal,
) bool {
	if journal.SchemaVersion == windowsManagedHooksTeardownJournalSchema {
		return true
	}
	// Schema 5 predates deferred enrollment. It remains valid only for an
	// exact legacy deployment whose manifest and transaction carry no deferred
	// or pending target state. This preserves authenticated interrupted-uninstall
	// recovery without letting an old journal authorize the new exception.
	if journal.SchemaVersion != 5 || len(journal.PendingTargets) != 0 ||
		len(identity.PendingTargets) != 0 {
		return false
	}
	for _, target := range journal.Targets {
		if target.Deferred {
			return false
		}
	}
	for _, target := range identity.Targets {
		if target.Deferred {
			return false
		}
	}
	return true
}

func windowsManagedHooksValidGenerationID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func windowsManagedHooksValidSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") ||
		value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func readWindowsManagedHooksTeardownJournal(
	path string,
) (windowsManagedHooksTeardownJournal, error) {
	var journal windowsManagedHooksTeardownJournal
	info, err := os.Lstat(path)
	if err != nil {
		return journal, err
	}
	if !info.Mode().IsRegular() || info.Size() > windowsManagedHooksTeardownJournalMax {
		return journal, errors.New(
			"managed-hook teardown journal is not a bounded regular non-link file",
		)
	}
	// Hold a no-follow handle across validation and read from it, then
	// confirm the path still names that same file: the bytes parsed are the
	// object whose owner and DACL were just checked, not a swapped-in one.
	file, before, err := openWindowsManagedHooksTeardownJournalNoFollow(path)
	if err != nil {
		return journal, err
	}
	defer file.Close()
	if err := validateWindowsManagedHooksTeardownJournalFile(path); err != nil {
		return journal, err
	}
	body, err := io.ReadAll(io.LimitReader(
		file,
		windowsManagedHooksTeardownJournalMax+1,
	))
	if err != nil {
		return journal, err
	}
	if len(body) > windowsManagedHooksTeardownJournalMax {
		return journal, errors.New("managed-hook teardown journal exceeds its size limit")
	}
	if err := sameWindowsManagedHooksTeardownJournalObject(path, before); err != nil {
		return journal, err
	}
	return parseWindowsManagedHooksTeardownJournalBody(body)
}

// openWindowsManagedHooksTeardownJournalNoFollow opens the journal without
// following a reparse point and returns its identity.
func openWindowsManagedHooksTeardownJournalNoFollow(
	path string,
) (*os.File, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, info, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, info, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, info, errors.New("wrap managed-hook teardown journal handle")
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = file.Close()
		return nil, info, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 {
		_ = file.Close()
		return nil, info, errors.New(
			"managed-hook teardown journal is not a single-link no-follow regular file",
		)
	}
	return file, info, nil
}

// sameWindowsManagedHooksTeardownJournalObject fails unless path still names
// the file whose identity was taken when the journal was opened.
func sameWindowsManagedHooksTeardownJournalObject(
	path string,
	opened windows.ByHandleFileInformation,
) error {
	current, info, err := openWindowsManagedHooksTeardownJournalNoFollow(path)
	if err != nil {
		return err
	}
	_ = current.Close()
	if windowsManagedHooksLifecycleFileIdentity(info) !=
		windowsManagedHooksLifecycleFileIdentity(opened) {
		return errors.New("managed-hook teardown journal was replaced while it was read")
	}
	return nil
}

// parseWindowsManagedHooksTeardownJournalBody is the ACL-independent
// JSON layer of readWindowsManagedHooksTeardownJournal. Split out so
// the schema/tolerance contract can be unit-tested without the
// trusted-owner ACL walk, which requires SYSTEM/Admins ownership on
// the input file — impractical inside a Go test running under a CI
// runner user. readWindowsManagedHooksTeardownJournal is the only
// production entry point and always enforces the ACL walk first via
// managed.ValidateTrustedFilePath before calling this helper.
func parseWindowsManagedHooksTeardownJournalBody(
	body []byte,
) (windowsManagedHooksTeardownJournal, error) {
	var journal windowsManagedHooksTeardownJournal
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(body, &properties); err != nil {
		return journal, err
	}
	// Trust-critical identity fields: presence-required and non-null.
	// These bind the journal to a specific activation record and manifest
	// bytes; a missing or nulled value would let a foreign journal pass
	// validation and redirect subsequent teardown/rollback at attacker-
	// controlled state.
	for _, name := range []string{
		"manifest_sha256",
		"activation_state",
		"deployment_generation_id",
	} {
		value, ok := properties[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return journal, fmt.Errorf("managed-hook teardown journal is missing %s", name)
		}
	}
	// Connector-optional fields (codex_policy_active, codex_targets,
	// cursor_targets, claude_target_sids) were previously strict-required
	// too. The current writer emits "[]" for an empty target list
	// (windowsManagedHooksTeardownExpectedEnrollment), but journals written
	// by earlier releases used append([]T(nil), src...) and carry "null"
	// whenever a connector had no eligible interactive users at install
	// time. Keep reading those legacy journals: downstream code paths use
	// nil-safe len() semantics, so decoding a null field into a nil slice
	// is functionally identical to decoding an empty array. Do not require
	// presence here, and do not drop the writer fix; json.Decoder below still
	// enforces DisallowUnknownFields, so a foreign extra key still fails
	// closed, and validateWindowsManagedHooksTeardownJournal still binds
	// every target list to the recomputed activation identity.
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return journal, errors.New("managed-hook teardown journal contains trailing JSON")
		}
		return journal, err
	}
	return journal, nil
}

// windowsManagedHooksTeardownJournalForWrite writes the empty Codex
// enrollment of a standalone deployment as [], not null: the reader takes a
// null codex_targets as missing, so an activated deployment that enrolled no
// Codex user could not uninstall (GAP-0248). A Secure Client journal is
// written as before.
func windowsManagedHooksTeardownJournalForWrite(
	journal windowsManagedHooksTeardownJournal,
) windowsManagedHooksTeardownJournal {
	if journal.CodexTargets == nil && enterprisehooks.WindowsStandaloneProcess() {
		journal.CodexTargets = []connector.WindowsCodexManagedRuntimeTarget{}
	}
	return journal
}

func writeWindowsManagedHooksTeardownJournal(
	path string,
	journal windowsManagedHooksTeardownJournal,
) error {
	body, err := json.MarshalIndent(windowsManagedHooksTeardownJournalForWrite(journal), "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > windowsManagedHooksTeardownJournalMax {
		return fmt.Errorf(
			"managed-hook teardown journal exceeds %d-byte limit",
			windowsManagedHooksTeardownJournalMax,
		)
	}
	parent := filepath.Dir(path)
	if err := validateWindowsManagedHooksTrustedDir(
		parent,
		managed.ObjectAdminDirectory,
		"managed-hook teardown journal parent",
	); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("managed-hook teardown journal is not a regular non-link file")
		}
		if err := validateWindowsManagedHooksTeardownJournalFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".managed-hooks-teardown-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := setEnterpriseWindowsManagedProtection(
		tmpPath,
		administrators,
		nil,
		0,
		false,
	); err != nil {
		return err
	}
	if err := safefile.ReplaceFile(tmpPath, path); err != nil {
		return err
	}
	if err := setEnterpriseWindowsManagedProtection(
		path,
		administrators,
		nil,
		0,
		false,
	); err != nil {
		return err
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(persisted, body) {
		return errors.New("managed-hook teardown journal changed during publication")
	}
	return validateWindowsManagedHooksTeardownJournalFile(path)
}
