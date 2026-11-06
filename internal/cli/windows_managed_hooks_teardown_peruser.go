// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Windows SYSTEM can open an enrolled user's profile even when that user has
// no logon token. An elevated owner can clean its own profile too. The profile
// root is checked against the recorded SID; the connector transaction then
// pins the settings identity, converges unsafe protection for a foreign
// enrolled owner, and preserves that owner and the converged DACL.
//
// It also returns, from the same transaction, each hook command the settings
// it committed (or found unchanged) still hold that names a DefenseClaw
// launcher, described without its arguments (#1286). A file it cannot
// inspect fails the cleanup instead of reporting none.
func removeWindowsManagedClaudeUserSettings(home, sid string) (int, []string, error) {
	if _, err := enterprisehooks.ValidateWindowsEnterpriseHome(home, sid); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	path := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	// The managed runtime is owned by Builtin Administrators, including after
	// Setup runs as SYSTEM. safefile requires its transaction directory to be
	// owned by the current token, so keep these receipts in that token's
	// private cache. The path is stable across retries and independent of the
	// runtime directory, which uninstall may already have retired.
	transactionDir, err := windowsManagedClaudeTransactionDir()
	if err != nil {
		return 0, nil, err
	}
	var left []string
	removed, err := connector.TransformWindowsClaudeSettingsForUninstall(path, transactionDir, sid, func(raw []byte) ([]byte, int, error) {
		left = nil
		out, count, err := removeWindowsManagedClaudeCommands(raw, launcher)
		if err != nil {
			return nil, 0, err
		}
		if left, err = windowsClaudeHooksNamingDefenseClaw(out); err != nil {
			return nil, 0, err
		}
		return out, count, nil
	})
	if err != nil {
		return 0, nil, err
	}
	return removed, left, nil
}

func windowsManagedClaudeTransactionDir() (string, error) {
	cache, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", fmt.Errorf("resolve current-token Claude cleanup transaction directory: %w", err)
	}
	return filepath.Join(cache, "DefenseClaw", "claude-settings-teardown"), nil
}

// windowsManagedClaudeTransactionLock is the connector's protocol lock, the
// one file a settings transaction that finished leaves in its folder.
const windowsManagedClaudeTransactionLock = ".defenseclaw-v2-protocol.lock"

// windowsManagedClaudeTransactionLeftoverRemover is replaceable in tests.
var windowsManagedClaudeTransactionLeftoverRemover = func() error {
	dir, err := windowsManagedClaudeTransactionDir()
	if err != nil {
		return fmt.Errorf(`%%LOCALAPPDATA%%\DefenseClaw\claude-settings-teardown: kept: %w`, err)
	}
	return removeWindowsManagedClaudeTransactionFolder(dir)
}

// windowsManagedClaudeTransactionKept is the error, and the
// machine_state_remaining entry ("path: kept: reason"), for a transaction
// folder that stays.
func windowsManagedClaudeTransactionKept(dir, reason string) error {
	return fmt.Errorf("%s: kept: %s", dir, reason)
}

// removeWindowsManagedClaudeTransactionFolder removes the Claude cleanup
// transaction folder when all it holds is the empty protocol lock, and then
// the DefenseClaw folder above it once that is empty. The guardian and a
// Setup or bundle uninstall run the cleanup as LocalSystem, so the uninstall
// left this behind (sidecar-r107:GAP-0007), as it left the lifecycle lock
// before (sidecar-aispg-retest:GAP-0022):
//
//	C:\Windows\System32\config\systemprofile\AppData\Local\DefenseClaw\claude-settings-teardown
//
// The folder stays in the token's own cache, not under ProgramData: the
// transaction needs a folder the current token owns, and its receipts must
// outlive the StateRoot an uninstall retires. A folder that holds anything
// else (the receipts of an unfinished transaction), a lock with content or
// one another process holds open, and any link or junction stay, with a
// windowsManagedClaudeTransactionKept error.
func removeWindowsManagedClaudeTransactionFolder(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return windowsManagedClaudeTransactionKept(dir, err.Error())
	}
	if info.Mode()&os.ModeType != os.ModeDir {
		return windowsManagedClaudeTransactionKept(dir, "it is not a plain folder")
	}
	parent := filepath.Dir(dir)
	if parentInfo, err := os.Lstat(parent); err != nil || parentInfo.Mode()&os.ModeType != os.ModeDir {
		return windowsManagedClaudeTransactionKept(dir, "its DefenseClaw folder is not a plain folder")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return windowsManagedClaudeTransactionKept(dir, err.Error())
	}
	if len(entries) > 1 || (len(entries) == 1 && !strings.EqualFold(entries[0].Name(), windowsManagedClaudeTransactionLock)) {
		return windowsManagedClaudeTransactionKept(dir, "it holds an unfinished Claude Code settings cleanup")
	}
	if len(entries) == 1 {
		lock := filepath.Join(dir, entries[0].Name())
		lockInfo, err := os.Lstat(lock)
		if err != nil {
			return windowsManagedClaudeTransactionKept(dir, err.Error())
		}
		if !lockInfo.Mode().IsRegular() || lockInfo.Size() != 0 {
			return windowsManagedClaudeTransactionKept(dir, entries[0].Name()+" is not an empty lock file")
		}
		// The connector opens the lock without delete sharing, so a
		// transaction still running makes this fail and keeps it.
		if err := os.Remove(lock); err != nil {
			return windowsManagedClaudeTransactionKept(dir, "its lock is in use: "+err.Error())
		}
	}
	if err := os.Remove(dir); err != nil {
		return windowsManagedClaudeTransactionKept(dir, err.Error())
	}
	if left, err := os.ReadDir(parent); err == nil && len(left) == 0 {
		_ = os.Remove(parent)
	}
	return nil
}

// windowsManagedClaudeGuardianLeftoverRemover runs after each Claude
// settings migration pass of the guardian, so its LocalSystem copy of the
// transaction folder exists only while a cleanup runs: that copy's DACL
// grants LocalSystem alone, so an uninstall from an elevated prompt could
// not remove it. It also takes a copy an earlier release left. Replaceable
// in tests.
var windowsManagedClaudeGuardianLeftoverRemover = func() error {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	dir, err := windowsManagedClaudeTransactionDir()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return err
	}
	return removeWindowsManagedClaudeTransactionFolderOutsideLifecycle(dir, filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
}

// windowsManagedClaudeLifecycleLock is replaceable in tests. It never waits:
// the guardian's pass gives the folder up while a lifecycle run holds the lock
// (GAP-0646 review 2).
var windowsManagedClaudeLifecycleLock = tryWindowsEnterpriseLifecycleLock

// removeWindowsManagedClaudeTransactionFolderOutsideLifecycle removes the
// transaction folder holding the lifecycle lock, and does nothing while a
// lifecycle run (install, upgrade, repair, uninstall) holds it or the lock is
// absent: that run's own cleanups use the folder, and its finalize removes it.
func removeWindowsManagedClaudeTransactionFolderOutsideLifecycle(dir, lifecycleLock string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	release, err := windowsManagedClaudeLifecycleLock(lifecycleLock)
	if err != nil {
		return nil
	}
	defer release()
	return removeWindowsManagedClaudeTransactionFolder(dir)
}

var windowsManagedClaudeSettingsRemover = removeWindowsManagedClaudeUserSettings

// The current Claude enrollment uses machine policy. An older per-user hook
// warrants a pending warning only when its exact launcher is still present.
// When none is, it also returns, read-only, each hook command that still
// names a DefenseClaw launcher (an edited guard, another form of the profile
// path, defenseclaw-gateway), so a file holding only hooks the remover keeps
// is reported rather than passed over.
func windowsManagedClaudeRegistrationPresent(home, sid string) (bool, []string, error) {
	raw, err := windowsManagedClaudeUserSettingsReader(home, sid)
	if err != nil || raw == nil {
		return false, nil, err
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	_, count, err := removeWindowsManagedClaudeCommands(raw, launcher)
	if err != nil || count > 0 {
		return count > 0, nil, err
	}
	left, err := windowsClaudeHooksNamingDefenseClaw(raw)
	return false, left, err
}

var windowsManagedClaudeRegistrationProbe = windowsManagedClaudeRegistrationPresent

// readWindowsManagedClaudeUserSettings reads the account's Claude Code user
// settings after checking the profile against the recorded SID; nil, with no
// error, when the profile or the file is absent.
func readWindowsManagedClaudeUserSettings(home, sid string) ([]byte, error) {
	if _, err := enterprisehooks.ValidateWindowsEnterpriseHome(home, sid); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	// Match the connector's 32 MiB atomic settings limit.
	raw, err := safefile.ReadRegularFileBounded(filepath.Join(home, ".claude", "settings.json"), 32<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

var windowsManagedClaudeUserSettingsReader = readWindowsManagedClaudeUserSettings

// An elevated Setup can edit its own Claude settings without impersonating
// another account. All other user profiles still require LocalSystem.
var windowsManagedClaudeCurrentUserSID = func() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("current Windows user SID is unavailable")
	}
	return user.User.Sid.String(), nil
}

// Standalone per-user connectors (Copilot, Antigravity, Devin, Hermes,
// OpenCode, Amp) are part of the managed-hook teardown in a process pinned to
// the standalone profile, and Copilot alone in a Secure Client process. Their
// machine wiring is the per-user enrollment and runtime selector of each
// hook-binary connector, plus the Go-owned Copilot machine policy (and, on
// the standalone profile, the public summary). After the uninstall commits,
// a standalone finalize also removes DefenseClaw's own registration or
// plugin from each user's agent configuration, as that user (see
// removeWindowsManagedHooksStandalonePerUserRegistrations); Secure Client
// writes none. Per-user runtime files stay, like every other connector.

// windowsEnterpriseKeptLinkReason is the reason of a machine_state_remaining
// entry for a link a purge kept. The psm1 purge steps write the same text.
const windowsEnterpriseKeptLinkReason = "kept: a link sits here; DefenseClaw does not follow, change or remove it"

// windowsEnterpriseCodexKeptLinkReason is the reason for the link at the Codex
// machine-policy folder: the entry starts with windowsEnterpriseKeptLinkReason
// and says what a kept link cannot promise. Nothing behind the link is read,
// so a Codex requirement there may still name the hook binary the uninstall
// removes (GAP-0773). The psm1 purge steps write only the shorter text for a
// link they meet, and the first entry for a path wins.
const windowsEnterpriseCodexKeptLinkReason = windowsEnterpriseKeptLinkReason +
	"; what is behind it was not checked, so a Codex requirement there may still name the DefenseClaw hook binary that the uninstall removes"

// windowsManagedHooksKeptLinkedFolders names, as machine_state_remaining
// entries (path: kept: reason), each vendor folder a teardown kept because a
// link sits there: the ones the Cursor, Claude Code, selector and per-user
// teardown steps of this process met, and the ones on the Go-owned policy
// paths (Copilot, OpenCode, Devin), which an earlier step of the uninstall
// may have kept. It only reads. Replaceable in tests.
var windowsManagedHooksKeptLinkedFolders = func() []string {
	var goOwned []string
	if layout, programFiles, programData, err := standaloneEnterprisePolicyLayout(); err == nil {
		opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
		goOwned = enterprisepolicy.WindowsGoOwnedLinkedFolders(opts)
	}
	return windowsManagedHooksNameKeptLinksOnce(
		connector.WindowsCodexMachineFoldersKept(),
		enterprisehooks.WindowsManagedPolicyFoldersKept(),
		goOwned,
	)
}

// windowsManagedHooksNameKeptLinksOnce builds the kept-link entries from the
// links the Codex walk, the vendor-folder steps and the Go-owned policy scan
// met. A link is named once, whichever step met it: the selector step names the
// Codex folder as well when an enrolled Codex account has a selector entry to
// look for (GAP-0773), so the Codex entries go first and keep their wording.
func windowsManagedHooksNameKeptLinksOnce(codex, vendor, goOwned []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(folder, text string) {
		key := strings.ToLower(filepath.Clean(folder))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, folder+": "+text)
	}
	for _, folder := range codex {
		add(folder, windowsEnterpriseCodexKeptLinkReason)
	}
	for _, folder := range vendor {
		add(folder, windowsEnterpriseKeptLinkReason)
	}
	for _, folder := range goOwned {
		add(folder, windowsEnterpriseKeptLinkReason)
	}
	return out
}

// The per-user enrollment reads and the rollback republication, replaceable in
// tests. A teardown makes none of them for a connector whose machine folder a
// link keeps: the read follows a link on the parent, so an enrollment.json
// behind an administrator link would fail the check after the uninstall
// committed.
var (
	windowsManagedHooksPerUserEnrollmentReader   = enterprisehooks.ReadWindowsPerUserManagedEnrollmentTargets
	windowsManagedHooksPerUserEnrollmentRestorer = enterprisehooks.RestoreWindowsPerUserManagedEnrollment
)

func windowsManagedHooksStandalonePerUserTarget(connectorName string) bool {
	return enterprisehooks.IsWindowsProfilePerUserConnector(connectorName)
}

// windowsManagedHooksStandalonePerUserExpected is the enrollment an
// activated deployment carries: every activated, non-pending target of each
// hook-binary per-user connector.
func windowsManagedHooksStandalonePerUserExpected(
	identity windowsManagedHooksTeardownJournal,
) map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget {
	expected := map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget{}
	for _, target := range identity.Targets {
		hookBinary, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector)
		if !perUser || !hookBinary {
			continue
		}
		expected[target.Connector] = expected[target.Connector]
		if !windowsManagedHooksTeardownSelectorExpected(target, identity.PendingTargets, identity.ActivationState) {
			continue
		}
		expected[target.Connector] = append(expected[target.Connector],
			enterprisehooks.WindowsPerUserManagedEnrollmentTarget{SID: target.SID, DataDir: target.DataDir})
	}
	return expected
}

func validateWindowsManagedHooksStandalonePerUserEnrollment(identity windowsManagedHooksTeardownJournal) error {
	for connectorName, want := range windowsManagedHooksStandalonePerUserExpected(identity) {
		// A link at the connector's machine folder keeps it out of the
		// comparison: nothing behind the link is read (GAP-0773, GAP-0829).
		if kept, err := windowsManagedHooksTeardownConnectorKept(connectorName); err != nil {
			return err
		} else if kept {
			continue
		}
		current, exists, err := windowsManagedHooksPerUserEnrollmentReader(connectorName)
		if err != nil {
			return err
		}
		if exists != (len(want) != 0) || !equalWindowsPerUserEnrollmentTargets(current, want) {
			return fmt.Errorf("%s machine enrollment does not match the authenticated activation state", connectorName)
		}
	}
	return nil
}

func equalWindowsPerUserEnrollmentTargets(left, right []enterprisehooks.WindowsPerUserManagedEnrollmentTarget) bool {
	if len(left) != len(right) {
		return false
	}
	index := map[string]string{}
	for _, target := range left {
		index[strings.ToUpper(target.SID)] = target.DataDir
	}
	for _, target := range right {
		dataDir, ok := index[strings.ToUpper(target.SID)]
		if !ok || !sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			return false
		}
	}
	return true
}

func removeWindowsManagedHooksStandalonePerUserWiring(identity windowsManagedHooksTeardownJournal) error {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return removeWindowsSecureClientCopilotWiring(identity.HookBinary)
	}
	// Revoke every per-user enrollment, not only the manifest connectors, so
	// an uninstall leaves no enrolled SID behind.
	if err := enterprisehooks.RemoveWindowsPerUserManagedEnrollments(
		identity.HookBinary,
		enterprisehooks.WindowsStandalonePerUserConnectorNames(),
	); err != nil {
		return err
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
	removed, err := enterprisepolicy.RemoveWindowsGoOwned(opts)
	// A vendor folder that does not protect DefenseClaw's file is named, and
	// the uninstall goes on (g582 review 7 S1).
	for _, state := range removed.States {
		for _, warning := range state.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", state.Connector, warning)
		}
	}
	if err != nil {
		return err
	}
	// The Claude Code version floor drop-in goes with the rest of the
	// standalone machine policy. A rollback does not put it back: the
	// guardian's next reconcile does, once the rolled-back services start.
	if _, err := enterprisepolicy.RemoveWindowsClaudeVersionFloor(opts); err != nil {
		return err
	}
	// So do the WSL registry values DefenseClaw wrote.
	_, err = enterprisepolicy.RemoveWindowsWSL(opts)
	return err
}

// windowsManagedHooksStandaloneFloorPurger is replaceable in tests.
var windowsManagedHooksStandaloneFloorPurger = purgeWindowsManagedHooksUnrecordedClaudeFloor

// purgeWindowsManagedHooksUnrecordedClaudeFloor is the purge step for a
// Claude Code version floor drop-in that holds DefenseClaw's floor but whose
// ownership record is gone (a rolled-back install left it), which the
// teardown's recorded removal keeps.
//
// It removes the drop-in only. The ClaudeCode and managed-settings.d folders
// it leaves are not removed here: the purge removes a vendor folder only when
// the created-folder record names it (the lifecycle's record-driven removal,
// Remove-DefenseClawStandaloneCreatedFolder, and enterprisehooks.
// RemoveWindowsCreatedFolderIfEmpty), so an empty ClaudeCode folder an
// administrator made before the install stays and the purge names it
// (GAP-0758 round 2, the g091 record-only rule). A by-name removal used to
// run here.
func purgeWindowsManagedHooksUnrecordedClaudeFloor() error {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	_, err = enterprisepolicy.PurgeWindowsUnrecordedClaudeVersionFloor(
		enterprisepolicy.LayoutOptions(layout, programFiles, programData),
	)
	return err
}

func restoreWindowsManagedHooksStandalonePerUserEnrollments(journal windowsManagedHooksTeardownJournal) error {
	var errs []error
	for connectorName, targets := range windowsManagedHooksStandalonePerUserExpected(journal) {
		if len(targets) == 0 {
			continue
		}
		// Nothing was removed behind a kept link, so there is nothing to put back.
		if kept, err := windowsManagedHooksTeardownConnectorKept(connectorName); err != nil {
			errs = append(errs, err)
			continue
		} else if kept {
			continue
		}
		if err := windowsManagedHooksPerUserEnrollmentRestorer(connectorName, journal.HookBinary, targets); err != nil {
			errs = append(errs, err)
		}
	}
	// The Go-owned Copilot policy and summary are republished by the
	// guardian's next reconcile once the rolled-back services start.
	return errors.Join(errs...)
}

func verifyWindowsManagedHooksStandalonePerUserClean() error {
	for _, connectorName := range enterprisehooks.WindowsProfilePerUserConnectorNames() {
		// A link at the machine folder of the connector is kept and was never read.
		if kept, err := windowsManagedHooksTeardownConnectorKept(connectorName); err != nil {
			return err
		} else if kept {
			continue
		}
		_, exists, err := windowsManagedHooksPerUserEnrollmentReader(connectorName)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%s machine enrollment survived managed-hook teardown", connectorName)
		}
	}
	if !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	recorded, err := enterprisepolicy.ClaudeVersionFloorRecorded(enterprisepolicy.LayoutOptions(layout, programFiles, programData))
	if err != nil {
		return err
	}
	if recorded {
		return errors.New("the Claude Code version floor drop-in survived managed-hook teardown")
	}
	return nil
}

// windowsManagedHooksStandaloneUserCleanups lists the per-user registrations
// an uninstall removes: the guardian's protected per-user rows, the
// cleanups it recorded for signed-out users, and enabled manifest rows that
// were not deferred. A deferred row the guardian never protected has
// nothing to remove unless an earlier install enrolled that user, which
// left the user's DefenseClaw data folder, and DefenseClaw's registration
// is still in the user's agent configuration: then it is attempted and,
// without an active session, reported as pending instead of silently kept
// (GAP-1795, GAP-2023).
func windowsManagedHooksStandaloneUserCleanups(
	runtimeDir string,
	manifest enterprisehooks.Manifest,
	now time.Time,
) ([]enterpriseHookUserCleanup, []string) {
	var problems []string
	var rows []enterpriseHookReconcileRow
	if authorization, _, err := loadEnterpriseHookGuardianAuthorization(runtimeDir); err != nil {
		problems = append(problems, "guardian records: "+boundedEnterpriseHookUserCleanupText(err.Error()))
	} else {
		rows = append(rows, authorization.ProtectedTargets...)
	}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() || (target.IsDeferred() && !windowsManagedHooksStandaloneRegistrationMayRemain(target)) {
			continue
		}
		rows = append(rows, enterpriseHookReconcileRow{
			User:      target.User,
			UserHome:  target.UserHome,
			SID:       target.SID,
			Connector: target.Connector,
			Result:    &enterprisehooks.InstallResult{DataDir: target.DataDir},
		})
	}
	pending, err := loadEnterpriseHookUserCleanups(runtimeDir)
	if err != nil {
		problems = append(problems, "pending cleanups: "+boundedEnterpriseHookUserCleanupText(err.Error()))
	}
	// Every entry is attempted now, whatever its retry state.
	for index := range pending {
		pending[index].Attempts = 0
		pending[index].LastAttemptAt = ""
		pending[index].LastError = ""
	}
	nobody := func(string, string) bool { return false }
	return planEnterpriseHookUserCleanups(pending, rows, nobody, windowsStandalonePerUserCleanupConnector, now), problems
}

// windowsManagedHooksStandaloneRegistrationMayRemain reports whether a
// deferred row may still hold an earlier install's registration: the user's
// DefenseClaw data folder is there and a read of the user's agent
// configuration finds DefenseClaw's registration, or cannot tell. A user
// whose registrations an earlier uninstall already removed has nothing to
// report (GAP-2023).
func windowsManagedHooksStandaloneRegistrationMayRemain(target enterprisehooks.ManifestTarget) bool {
	if !windowsManagedHooksStandaloneEnrolledBefore(target) {
		return false
	}
	return !windowsManagedHooksStandaloneRegistrationGone(target)
}

// windowsManagedHooksStandaloneRegistrationGone reports whether a read of the
// user's agent configuration finds no DefenseClaw registration for the
// target. A read that cannot tell keeps the row.
func windowsManagedHooksStandaloneRegistrationGone(target enterprisehooks.ManifestTarget) bool {
	present, err := windowsManagedHooksStandaloneRegistrationPresent(target)
	return err == nil && !present
}

// windowsManagedHooksStandaloneRegistrationPresent is replaceable in tests.
var windowsManagedHooksStandaloneRegistrationPresent = func(target enterprisehooks.ManifestTarget) (bool, error) {
	name := strings.ToLower(strings.TrimSpace(target.Connector))
	present, err := enterprisehooks.WindowsStandalonePerUserRegistrationPresent(enterprisehooks.InstallOptions{
		ConnectorName: name,
		UserHome:      strings.TrimSpace(target.UserHome),
		OwnerSID:      strings.TrimSpace(target.SID),
		DataDir:       strings.TrimSpace(target.DataDir),
		Registry:      enterpriseHooksCertifiedRegistryFactory(),
	})
	if err != nil || present || name != "copilot" {
		return present, err
	}
	// Copilot's registration is also the VS Code Local hook file and plugin,
	// whose encoded bridge the hook-command search cannot read (GAP-2098).
	return windowsCopilotVSCodeUserFilesLeft(strings.TrimSpace(target.UserHome))
}

// windowsManagedHooksStandaloneEnrolledBefore reports whether the target's
// DefenseClaw data folder exists, which an enrollment creates and a default
// uninstall keeps.
func windowsManagedHooksStandaloneEnrolledBefore(target enterprisehooks.ManifestTarget) bool {
	dataDir := strings.TrimSpace(target.DataDir)
	if dataDir == "" && strings.TrimSpace(target.UserHome) != "" {
		dataDir = filepath.Join(strings.TrimSpace(target.UserHome), ".defenseclaw")
	}
	if dataDir == "" {
		return false
	}
	info, err := os.Lstat(dataDir)
	return err == nil && info.IsDir()
}

// windowsManagedHooksRegistrationsNotRemovedPrefix starts the failure an
// uninstall that is not LocalSystem records for every user registration.
const windowsManagedHooksRegistrationsNotRemovedPrefix = "per-user registrations were not removed: "

// removeWindowsManagedHooksStandalonePerUserRegistrations runs, after a
// committed uninstall, each per-user connector's teardown as the user for
// every registration DefenseClaw made. It is best effort: the uninstall has
// already revoked every enrollment, so a leftover registration can no longer
// reach a gateway. Registrations that require another user's token when the
// uninstall does not run as LocalSystem are reported as pending; there is no
// guardian left to clean them at their next sign-in.
func removeWindowsManagedHooksStandalonePerUserRegistrations(
	ctx context.Context,
	runtimeDir string,
	manifest enterprisehooks.Manifest,
) enterpriseHookUserCleanupResult {
	now := time.Now()
	entries, problems := windowsManagedHooksStandaloneUserCleanups(runtimeDir, manifest, now)
	result := enterpriseHookUserCleanupResult{Failed: problems}
	// Claude's current enrollment is machine policy, but older native hook
	// registrations can remain in user settings. Remove only this profile's
	// exact launcher path before a purge deletes the launcher. Every enrolled
	// account is cleaned, not only those enrolled for Claude Code now: an
	// account enrolled for another connector kept a DefenseClaw Claude hook
	// that named a launcher the purge removed, and no result named it
	// (mgmt-p1:GAP-0089).
	identityErr := enterpriseHookWindowsUserCleanupIdentity()
	seen := map[string]bool{}
	blockedClaude := false
	for _, target := range manifest.Targets {
		if target.UserHome == "" || target.SID == "" || seen[target.SID] {
			continue
		}
		seen[target.SID] = true
		if identityErr != nil {
			callerSID, callerErr := windowsManagedClaudeCurrentUserSID()
			if callerErr != nil || !strings.EqualFold(callerSID, target.SID) {
				present, left, err := windowsManagedClaudeRegistrationProbe(target.UserHome, target.SID)
				if err != nil {
					result.Failed = append(result.Failed, "claudecode/"+target.SID+": "+boundedEnterpriseHookUserCleanupText(err.Error()))
				} else if present {
					result.Pending = append(result.Pending, "claudecode/"+target.SID)
					blockedClaude = true
				}
				settings := filepath.Join(target.UserHome, ".claude", "settings.json")
				for _, hook := range left {
					result.SettingsLeft = append(result.SettingsLeft, settings+": "+boundedEnterpriseHookUserCleanupText(hook))
				}
				continue
			}
		}
		settings := filepath.Join(target.UserHome, ".claude", "settings.json")
		n, left, err := windowsManagedClaudeSettingsRemover(target.UserHome, target.SID)
		if err != nil {
			result.Failed = append(result.Failed, "claudecode/"+target.SID+": "+boundedEnterpriseHookUserCleanupText(err.Error()))
			continue
		}
		if n > 0 {
			result.Removed = append(result.Removed, "claudecode/"+target.SID)
			// The result named only the per-user data a purge removed, so an
			// MDM report could not see that users' files were edited (#1290).
			result.SettingsEdited = append(result.SettingsEdited, fmt.Sprintf(
				"removed %d DefenseClaw hook command(s) from %s", n, settings))
		}
		// The leftovers come from the same settings transaction as the
		// removal, so a later read failure or a concurrent change cannot
		// hide one (#1286). Each names the hook event and the launcher, never
		// the command's arguments.
		for _, hook := range left {
			result.SettingsLeft = append(result.SettingsLeft, settings+": "+boundedEnterpriseHookUserCleanupText(hook))
		}
	}
	if identityErr != nil && blockedClaude && len(entries) == 0 {
		result.Failed = append(result.Failed,
			windowsManagedHooksRegistrationsNotRemovedPrefix+boundedEnterpriseHookUserCleanupText(identityErr.Error()))
	}
	if len(entries) == 0 {
		return result
	}
	if identityErr != nil {
		for _, entry := range entries {
			result.Pending = append(result.Pending, enterpriseHookUserCleanupLabel(entry))
		}
		result.Pending = windowsManagedHooksStandaloneRegistrationsLeft(entries, result.Pending)
		if len(result.Pending) > 0 {
			result.Failed = append(result.Failed,
				windowsManagedHooksRegistrationsNotRemovedPrefix+boundedEnterpriseHookUserCleanupText(identityErr.Error()))
		}
		return result
	}
	_, attempted := runEnterpriseHookUserCleanups(ctx, entries, enterpriseHookWindowsUserCleanupAttempt, now)
	result.Removed = append(result.Removed, attempted.Removed...)
	result.Pending = windowsManagedHooksStandaloneRegistrationsLeft(entries, append(result.Pending, attempted.Pending...))
	result.Failed = append(result.Failed, attempted.Failed...)
	return result
}

// windowsManagedHooksStandaloneRegistrationsLeft drops from the pending labels
// every entry whose user's agent configuration holds no DefenseClaw
// registration: there is nothing left to remove once the user signs in, so
// naming it in user_registrations_pending is wrong (GAP-2098: an enrolled
// OpenCode row without the plugin). An entry the read cannot tell about
// stays pending.
func windowsManagedHooksStandaloneRegistrationsLeft(entries []enterpriseHookUserCleanup, pending []string) []string {
	if len(pending) == 0 {
		return pending
	}
	byLabel := make(map[string]enterpriseHookUserCleanup, len(entries))
	for _, entry := range entries {
		byLabel[enterpriseHookUserCleanupLabel(entry)] = entry
	}
	left := make([]string, 0, len(pending))
	for _, label := range pending {
		if entry, ok := byLabel[label]; ok && windowsManagedHooksStandaloneRegistrationGone(enterprisehooks.ManifestTarget{
			User: entry.User, UserHome: entry.UserHome, SID: entry.SID, Connector: entry.Connector, DataDir: entry.DataDir,
		}) {
			continue
		}
		left = append(left, label)
	}
	return left
}
