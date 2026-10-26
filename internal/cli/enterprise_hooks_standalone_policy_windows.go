// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The Windows standalone guardian owns the machine policy targets that the
// Windows lifecycle does not (GitHub Copilot, and OpenCode once its managed
// plugin ships) and the public summary the hook-side foreign-hook guard
// reads. It republishes them before every reconcile, so a removed or edited
// DefenseClaw entry is repaired within one cycle.

func init() {
	enterprisehooks.SetWindowsOpenCodeMachinePolicy(windowsOpenCodeMachinePolicy)
	enterprisehooks.SetWindowsClaudeManagedHooksOnlyPolicy(windowsClaudeManagedHooksOnlyEnforced)
	enterprisehooks.SetWindowsCopilotVSCodeUser(windowsCopilotVSCodeUser)
}

// windowsCopilotVSCodeUser places, checks (verify) or removes DefenseClaw's
// VS Code Local hook file and Copilot plugin in home, from the loaded
// config. The install and remove calls run under the target user's
// impersonation. The uninstall's teardown runs without a loaded config, so a
// standalone removal falls back to the deployment's own hook launcher, the
// one the files were rendered for.
func windowsCopilotVSCodeUser(home string, verify, remove bool) error {
	opts, ok, err := windowsCopilotVSCodeUserOptions(remove && !verify)
	if err != nil || !ok {
		return err
	}
	hookFile, plugin := enterprisepolicy.CopilotVSCodeUserWant(opts)
	if remove {
		hookFile, plugin = false, false
	}
	result, err := enterprisepolicy.EnsureCopilotVSCodeUser(enterprisepolicy.CopilotVSCodeUserRequest{
		Home:       home,
		GOOS:       "windows",
		HookBinary: opts.HookBinary,
		HookFile:   hookFile,
		Plugin:     plugin,
		DryRun:     verify,
	})
	if err != nil {
		return err
	}
	if !remove && len(result.Kept) > 0 {
		return fmt.Errorf("copilot hook files under %s hold handlers DefenseClaw did not write: %s; DefenseClaw leaves them in place and does not claim Local hook coverage", home, strings.Join(result.Kept, ", "))
	}
	if verify && len(result.Changed)+len(result.Removed) > 0 {
		return fmt.Errorf("DefenseClaw's VS Code Local hooks under %s are not current: %s", home, strings.Join(append(result.Changed, result.Removed...), ", "))
	}
	return nil
}

// windowsCopilotVSCodeUserOptions resolves the hook binary the user files
// are rendered for: the loaded config's, or, for a standalone removal
// without one, the deployment's own launcher. ok is false when there is
// nothing to do.
func windowsCopilotVSCodeUserOptions(removal bool) (enterprisepolicy.Options, bool, error) {
	opts, _, standalone, err := enterpriseHookWindowsGuardianOptions()
	if standalone {
		return opts, err == nil, err
	}
	if !removal || !enterprisehooks.WindowsStandaloneProcess() {
		return opts, false, nil
	}
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return opts, false, err
	}
	return enterprisepolicy.Options{HookBinary: enterprisepolicy.HookBinaryPath(layout)}, true, nil
}

// windowsCopilotVSCodeUserFilesLeft reports, read-only, whether home still
// holds DefenseClaw's VS Code Local hook file or Copilot plugin (GAP-2098).
func windowsCopilotVSCodeUserFilesLeft(home string) (bool, error) {
	opts, ok, err := windowsCopilotVSCodeUserOptions(true)
	if err != nil || !ok {
		return false, err
	}
	return enterprisepolicy.CopilotVSCodeUserFilesLeft(home, "windows", opts.HookBinary)
}

// windowsClaudeManagedHooksOnlyEnforced reports whether the loaded config's
// claudecode machine policy keeps the managed-hooks-only lock: everything
// but an explicit managed_hooks_only: preserve (the default is enforce). The
// standalone lifecycle renders allowManagedHooksOnly into the machine-wide
// Claude Code drop-in from it.
func windowsClaudeManagedHooksOnlyEnforced() bool {
	if cfg == nil {
		return true
	}
	return cfg.Enterprise.MachinePolicy.PolicyFor(enterprisepolicy.ConnectorClaudeCode).ManagedHooksOnly != config.ManagedHooksOnlyPreserve
}

// windowsOpenCodeMachinePolicy is the OpenCode machine policy check the
// guardian and enumerator route OpenCode rows by: OpenCode's managed config
// path, and whether the trusted managed plugin is installed and named there.
// Replaced in tests.
var windowsOpenCodeMachinePolicy = func() (string, bool) {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return "", false
	}
	opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
	path, err := enterprisepolicy.OpenCodeManagedConfigPath(opts)
	if err != nil {
		return "", false
	}
	present, err := enterprisepolicy.MachinePolicyPresent(opts, enterprisepolicy.ConnectorOpenCode)
	return path, err == nil && present
}

// windowsStandaloneGuardianOptions is the guardian's machine policy options
// from the loaded config.
func windowsStandaloneGuardianOptions() (enterprisepolicy.Options, []string, bool, error) {
	return standaloneGuardianOptionsFor(cfg)
}

// enterpriseHookStandalonePlatformPrepare publishes the Go-owned Windows
// machine policy and summary, re-checks the Claude Code version floor
// drop-in (inside the lifecycle's Claude Code policy lock), reconciles
// the WSL agent-session registry policy and retires the runtime selections
// of users the machine policies no longer enroll. Failure is
// reported, not fatal: rows that depend on the policy (Copilot) fail their
// own verification, and `enterprise policy verify` reports a missing floor.
func enterpriseHookStandalonePlatformPrepare(stderr io.Writer) {
	if cfg != nil && cfg.SecureClientIntegration() {
		enterpriseHookSecureClientPlatformPrepare(stderr)
		return
	}
	opts, connectors, standalone, err := enterpriseHookWindowsGuardianOptions()
	if !standalone {
		return
	}
	// After this pass's revocations and before any row: a deferred row
	// whose SID kept a selection would fail its pending proof (GAP-0262).
	if retireErr := enterprisehooks.RetireWindowsUnregisteredRuntimeSelections(); retireErr != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise hooks (Windows): runtime selections of unenrolled users: %v\n", retireErr)
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise machine policy (Windows): %v\n", err)
		return
	}
	windowsStandaloneGoOwnedPolicyMu.Lock()
	_, err = enterprisepolicy.PublishWindowsGoOwned(opts, connectors)
	windowsStandaloneGoOwnedPolicyMu.Unlock()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise machine policy (Windows): %v\n", err)
	}
	if _, err := enterpriseHookWindowsClaudeVersionFloor(opts, connectors); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise machine policy (Windows): Claude Code version floor: %v\n", err)
	}
	if _, err := enterpriseHookWindowsWSL(opts); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise machine policy (Windows): WSL agent sessions: %v\n", err)
	}
	if refreshed, err := enterpriseHookWindowsCursorAdapterRefresh(opts.HookBinary); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise machine policy (Windows): Cursor enterprise adapter: %v\n", err)
	} else if refreshed {
		fmt.Fprintf(stderr, "[hook-guardian] rewrote the Cursor enterprise adapter for this release\n")
	}
}

// enterpriseHookWindowsCursorAdapterRefresh is replaceable in tests.
var enterpriseHookWindowsCursorAdapterRefresh = enterprisehooks.RefreshWindowsCursorManagedAdapter

// windowsStandaloneGoOwnedPolicyMu serializes the guardian's writers of the
// Go-owned machine policy: the reconcile's publish and the OpenCode plugin
// watch.
var windowsStandaloneGoOwnedPolicyMu sync.Mutex

// enterpriseHookStandalonePlatformWatch starts, for the life of the watch
// loop, the guardian's hook binary check and its managed OpenCode plugin
// watch, which restores the plugin right after a standard account changes
// its attributes instead of at the next pass.
func enterpriseHookStandalonePlatformWatch(ctx context.Context, stderr io.Writer) {
	go watchWindowsStandaloneHookBinary(ctx, stderr)
	opts, _, standalone, err := enterpriseHookWindowsGuardianOptions()
	if !standalone || err != nil || strings.TrimSpace(opts.OpenCodePluginPath) == "" {
		return
	}
	go enterprisepolicy.WatchOpenCodeManagedPlugin(ctx, opts, &windowsStandaloneGoOwnedPolicyMu, func(format string, args ...any) {
		fmt.Fprintf(stderr, "[hook-guardian] "+format+"\n", args...)
	})
}

// enterpriseHookWindowsClaudeVersionFloor is replaceable in tests.
var enterpriseHookWindowsClaudeVersionFloor = enterprisepolicy.PublishWindowsClaudeVersionFloor

// windowsStandalonePerUserEnrollmentKeep builds the manifest predicate the
// per-user enrollment pruning uses.
func windowsStandalonePerUserEnrollmentKeep(manifest enterprisehooks.Manifest) func(string, string) bool {
	allowed := map[string]bool{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		allowed[strings.ToLower(strings.TrimSpace(target.Connector))+"\x00"+strings.ToUpper(strings.TrimSpace(target.SID))] = true
	}
	return func(connectorName, sid string) bool {
		return allowed[connectorName+"\x00"+strings.ToUpper(strings.TrimSpace(sid))]
	}
}

// pruneWindowsStandalonePerUserEnrollments revokes per-user connector
// enrollment (Copilot's alone on Secure Client) for SIDs the manifest no
// longer authorizes, so a removed user or disabled connector fails closed
// before any target runtime is touched.
func pruneWindowsStandalonePerUserEnrollments(manifest enterprisehooks.Manifest, hookBinary string) error {
	if cfg == nil || (!cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration()) {
		return nil
	}
	return enterprisehooks.PruneWindowsPerUserManagedEnrollments(
		filepath.Clean(hookBinary),
		windowsStandalonePerUserEnrollmentKeep(manifest),
	)
}

// enterpriseHookWindowsUserCleanupAttempt removes one user's DefenseClaw
// registration; replaceable in tests.
var enterpriseHookWindowsUserCleanupAttempt enterpriseHookUserCleanupAttempt = attemptWindowsStandaloneUserCleanup

// enterpriseHookWindowsRequireTargetSession and
// enterpriseHookWindowsUserCleanupIdentity are replaceable in tests.
var (
	enterpriseHookWindowsRequireTargetSession = enterprisehooks.RequireWindowsEnterpriseTargetSession
	enterpriseHookWindowsUserCleanupIdentity  = enterprisehooks.RequireWindowsEnterpriseTargetImpersonationIdentity
)

func windowsStandalonePerUserCleanupConnector(name string) bool {
	_, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(name)
	return perUser
}

// enterpriseHookStandalonePlatformRevokeUsers removes DefenseClaw's own hook
// registrations and plugins (Amp, Antigravity, Copilot, Devin, Hermes,
// OpenCode) from the agent configuration of every user whose row the
// manifest no longer enrolls. Each removal is the connector's teardown run
// as that user, so the user's own hooks and settings stay. A signed-out
// user's cleanup is recorded and retried on every reconcile; the sign-in
// notification starts one.
func enterpriseHookStandalonePlatformRevokeUsers(ctx context.Context, stderr io.Writer, manifest enterprisehooks.Manifest) error {
	if cfg == nil || !cfg.StandaloneEnterprise() || !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	return reconcileEnterpriseHookUserCleanups(
		ctx,
		stderr,
		cfg.DataDir,
		manifest,
		windowsStandalonePerUserCleanupConnector,
		enterpriseHookWindowsUserCleanupAttempt,
		time.Now(),
	)
}

// enterpriseHookWindowsUserProfileRemoved is replaceable in tests.
var enterpriseHookWindowsUserProfileRemoved = windowsStandaloneUserProfileRemoved

// windowsStandaloneUserProfileRemoved reports whether a user whose profile
// folder is missing can never sign in again: the SID has no ProfileList
// entry and resolves to no account. A missing folder alone does not say
// that. A roaming profile whose cached copy is deleted at sign-out, or an
// FSLogix profile container, has no local folder (and often no ProfileList
// entry) while the user is signed out, and the user's agent configuration
// comes back with the profile at the next sign-in. Any answer other than
// "no such account" keeps the cleanup waiting.
func windowsStandaloneUserProfileRemoved(rawSID string) bool {
	sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
	if err != nil {
		return false
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(),
		registry.QUERY_VALUE,
	)
	if err == nil {
		key.Close()
		return false
	}
	if !errors.Is(err, registry.ErrNotExist) {
		return false
	}
	_, _, _, err = sid.LookupAccount("")
	return errors.Is(err, windows.ERROR_NONE_MAPPED)
}

// attemptWindowsStandaloneUserCleanup runs the per-user removal for one
// entry under the user's own session token. No session means pending, and
// so does a missing profile folder while the account can still sign in; a
// profile removed with its account leaves nothing to clean.
func attemptWindowsStandaloneUserCleanup(
	ctx context.Context,
	entry enterpriseHookUserCleanup,
) (enterpriseHookUserCleanupOutcome, error) {
	home := filepath.Clean(strings.TrimSpace(entry.UserHome))
	if !filepath.IsAbs(home) {
		return enterpriseHookUserCleanupFailed, fmt.Errorf("user home %q is not absolute", entry.UserHome)
	}
	if _, err := os.Lstat(home); errors.Is(err, os.ErrNotExist) {
		if enterpriseHookWindowsUserProfileRemoved(entry.SID) {
			return enterpriseHookUserCleanupDone, nil
		}
		return enterpriseHookUserCleanupPending, nil
	}
	if err := enterpriseHookWindowsRequireTargetSession(entry.SID, home); err != nil {
		if enterprisehooks.IsWindowsTargetSessionUnavailable(err) {
			return enterpriseHookUserCleanupPending, nil
		}
		return enterpriseHookUserCleanupFailed, err
	}
	err := enterpriseHooksRemoveManagedPolicy(ctx, enterprisehooks.InstallOptions{
		ConnectorName: strings.ToLower(strings.TrimSpace(entry.Connector)),
		UserHome:      home,
		OwnerSID:      strings.TrimSpace(entry.SID),
		DataDir:       strings.TrimSpace(entry.DataDir),
		Registry:      enterpriseHooksCertifiedRegistryFactory(),
	})
	switch {
	case err == nil:
		return enterpriseHookUserCleanupDone, nil
	case enterprisehooks.IsWindowsTargetSessionUnavailable(err):
		// The user signed out between the session check and the removal.
		return enterpriseHookUserCleanupPending, nil
	default:
		return enterpriseHookUserCleanupFailed, err
	}
}

var enterpriseHookWindowsForeignCleanupState struct {
	sync.Mutex
	last        time.Time
	fingerprint string
}

var enterpriseHookWindowsForeignCleanupInterval = 5 * time.Minute

// enterpriseHookWindowsGuardianOptions and enterpriseHookWindowsEligibleProfiles
// are replaceable in tests.
var enterpriseHookWindowsGuardianOptions = windowsStandaloneGuardianOptions

// enterpriseHookWindowsEligibleProfiles lists the profiles enrollment admits
// (exclude_users, exempt_users and the group filters, as the enumerator
// applies them; include_users is additive), so users without a per-user
// manifest row are cleaned too. The group filters read the enumerator's
// membership cache; a profile whose membership is unknown is skipped.
var enterpriseHookWindowsEligibleProfiles = func(ctx context.Context) ([]enterprisehooks.TargetCredentials, error) {
	return enterpriseHookWindowsEligibleProfilesFor(ctx, cfg, enterpriseHookManifest)
}

// The membership cache reader and the profile decision; tests replace them.
var (
	enterpriseHookWindowsGroupCacheLoader       = enterprisehooks.LoadWindowsEnrollmentGroupCache
	enterpriseHookWindowsStandaloneEligibleList = enterprisehooks.WindowsStandaloneEligibleProfilesFor
)

func enterpriseHookWindowsEligibleProfilesFor(ctx context.Context, current *config.Config, manifestPath string) ([]enterprisehooks.TargetCredentials, error) {
	opts := standaloneWindowsEnumerateOptions(current, enterprisehooks.EnumerateOptions{})
	if len(opts.IncludeGroups)+len(opts.ExcludeGroups) > 0 {
		// An unreadable cache decides from the signed-in sessions alone.
		if cache, err := enterpriseHookWindowsGroupCacheLoader(enterprisehooks.WindowsEnrollmentGroupsCachePath(manifestPath)); err == nil {
			opts.GroupCache = cache
		}
	}
	return enterpriseHookWindowsStandaloneEligibleList(ctx, opts)
}

// migrateWindowsClaudeUserHooks removes DefenseClaw's own older per-user
// Claude Code hooks (those running the per-user launcher in ~/.local/bin,
// directly or through the launcher guard) from the user's Claude settings,
// as the Unix guardian removes its leftover registrations each pass. Claude
// Code is enrolled by machine policy; left in place, the old hooks make every
// agent that reads the file (Copilot CLI in a project under the home) block
// as on a foreign hook (GAP-0587). A read-only probe runs first, so a file
// without such a hook is never rewritten or re-protected; the hooks that
// still name DefenseClaw are reported, after the removal or, when nothing
// was removable, from the probe. Passes run once per cleanup interval, so
// the report repeats at most that often.
//
// It runs for every user, also one with a Claude Code manifest row: that row
// is the machine policy registration and its verify does not touch the user's
// settings, so skipping such users left the older hooks of every Claude Code
// user in place and Copilot blocked every tool call in a home project after
// a 1.0.x per-user to managed upgrade and after a fresh managed install over
// a retained profile (GAP-0587, T11 TST-28276, T12 TST-29537/29865/29921).
func migrateWindowsClaudeUserHooks(stderr io.Writer, target enterprisehooks.TargetCredentials) {
	settings := filepath.Join(target.UserHome, ".claude", "settings.json")
	present, left, err := windowsManagedClaudeRegistrationProbe(target.UserHome, target.SID)
	removed := 0
	if err == nil && present {
		removed, left, err = windowsManagedClaudeSettingsRemover(target.UserHome, target.SID, "")
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: older DefenseClaw hooks in %s: %v\n", settings, err)
		return
	}
	if removed > 0 {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: removed %d older DefenseClaw hook command(s) from %s\n", removed, settings)
	}
	for _, hook := range left {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %s still holds %s; remove it so other agents do not block on it\n",
			settings, boundedEnterpriseHookUserCleanupText(hook))
	}
}

// enterpriseHookStandalonePlatformFinish removes unapproved foreign hooks
// for every verified Windows user and every eligible profile without rows
// (a user whose connectors are all machine policy, such as Cursor, has
// none), for each guarded connector the user has no manifest row for; rows
// run the cleanup for their own connector as they verify. Cleanup runs as
// the user and is best effort: the hook-side guard still denies tool calls
// while an unapproved hook remains.
func enterpriseHookStandalonePlatformFinish(ctx context.Context, stderr io.Writer, rows []enterpriseHookReconcileRow, now time.Time) {
	_, connectors, standalone, err := enterpriseHookWindowsGuardianOptions()
	if !standalone || err != nil || len(connectors) == 0 {
		return
	}
	type user struct {
		creds   enterprisehooks.TargetCredentials
		dataDir string
		rows    map[string]bool
	}
	users := map[string]*user{}
	order := []string{}
	for _, row := range rows {
		if !row.OK || strings.TrimSpace(row.SID) == "" || strings.TrimSpace(row.UserHome) == "" {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(row.SID))
		current, ok := users[key]
		if !ok {
			dataDir := filepath.Join(filepath.Clean(row.UserHome), ".defenseclaw")
			if row.Result != nil && strings.TrimSpace(row.Result.DataDir) != "" {
				dataDir = row.Result.DataDir
			}
			current = &user{
				creds:   enterprisehooks.TargetCredentials{UserHome: row.UserHome, UID: -1, GID: -1, SID: row.SID},
				dataDir: dataDir,
				rows:    map[string]bool{},
			}
			users[key] = current
			order = append(order, key)
		}
		current.rows[strings.ToLower(strings.TrimSpace(row.Connector))] = true
	}
	profiles, profilesErr := enterpriseHookWindowsEligibleProfiles(ctx)
	if profilesErr != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: eligible profiles: %v\n", profilesErr)
	}
	for _, profile := range profiles {
		key := strings.ToUpper(strings.TrimSpace(profile.SID))
		if key == "" || strings.TrimSpace(profile.UserHome) == "" {
			continue
		}
		if _, ok := users[key]; ok {
			continue
		}
		users[key] = &user{
			creds:   enterprisehooks.TargetCredentials{UserHome: profile.UserHome, UID: -1, GID: -1, SID: profile.SID},
			dataDir: filepath.Join(filepath.Clean(profile.UserHome), ".defenseclaw"),
			rows:    map[string]bool{},
		}
		order = append(order, key)
	}
	fingerprint := strings.Join(order, ",") + "|" + strings.Join(connectors, ",")
	enterpriseHookWindowsForeignCleanupState.Lock()
	due := now.Sub(enterpriseHookWindowsForeignCleanupState.last) >= enterpriseHookWindowsForeignCleanupInterval ||
		fingerprint != enterpriseHookWindowsForeignCleanupState.fingerprint
	if due {
		enterpriseHookWindowsForeignCleanupState.last = now
		enterpriseHookWindowsForeignCleanupState.fingerprint = fingerprint
	}
	enterpriseHookWindowsForeignCleanupState.Unlock()
	// The Codex IDE extension's WSL switch is reset every pass, so a session
	// the user moves into WSL comes back within a pass; reports wait for the
	// cleanup interval.
	for _, key := range order {
		enterpriseHookWSLEditorPass(stderr, users[key].creds, now, due)
	}
	if !due {
		return
	}
	for _, key := range order {
		current := users[key]
		blocks, dropped, blocksErr := enterpriseForeignHookCollectBlocks(current.creds)
		blocksError := ""
		if blocksErr != nil {
			blocksError = blocksErr.Error()
		}
		logEnterpriseForeignHookBlocks(stderr, current.creds.UserHome, blocks, dropped, blocksError)
		migrateWindowsClaudeUserHooks(stderr, current.creds)
		for _, name := range connectors {
			if current.rows[name] {
				continue
			}
			// The cleanup holds the cleanup fence only for each removal and
			// records it in the removal ledger.
			result, err := enterpriseForeignHookCleanup(current.creds, name, current.dataDir)
			for _, finding := range result.Removed {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: removed %s %s hook from %s (sha256:%s); backup in %s\n",
					finding.Connector, dashIfEmpty(finding.Event), finding.Path, finding.Digest, result.BackupDir)
			}
			if err != nil {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s %s: %v\n", name, current.creds.UserHome, err)
			}
		}
	}
}
