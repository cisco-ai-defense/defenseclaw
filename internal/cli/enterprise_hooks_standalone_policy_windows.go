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
// impersonation.
func windowsCopilotVSCodeUser(home string, verify, remove bool) error {
	opts, _, standalone, err := enterpriseHookWindowsGuardianOptions()
	if !standalone {
		return nil
	}
	if err != nil {
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
	if verify && len(result.Changed)+len(result.Removed) > 0 {
		return fmt.Errorf("DefenseClaw's VS Code Local hooks under %s are not current: %s", home, strings.Join(append(result.Changed, result.Removed...), ", "))
	}
	return nil
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

func windowsStandaloneGuardianOptions() (enterprisepolicy.Options, []string, bool, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return enterprisepolicy.Options{}, nil, false, nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return enterprisepolicy.Options{}, nil, true, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return enterprisepolicy.Options{}, nil, true, err
	}
	return opts, enterprisepolicy.StandaloneConnectors(cfg), true, nil
}

// enterpriseHookStandalonePlatformPrepare publishes the Go-owned Windows
// machine policy and summary, re-checks the Claude Code version floor
// drop-in (inside the lifecycle's Claude Code policy lock) and reconciles
// the WSL agent-session registry policy. Failure is
// reported, not fatal: rows that depend on the policy (Copilot) fail their
// own verification, and `enterprise policy verify` reports a missing floor.
func enterpriseHookStandalonePlatformPrepare(stderr io.Writer) {
	opts, connectors, standalone, err := enterpriseHookWindowsGuardianOptions()
	if !standalone {
		return
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
}

// windowsStandaloneGoOwnedPolicyMu serializes the guardian's writers of the
// Go-owned machine policy: the reconcile's publish and the OpenCode plugin
// watch.
var windowsStandaloneGoOwnedPolicyMu sync.Mutex

// enterpriseHookStandalonePlatformWatch starts, for the life of the watch
// loop, the guardian's managed OpenCode plugin watch, which restores the
// plugin right after a standard account changes its attributes instead of
// at the next pass.
func enterpriseHookStandalonePlatformWatch(ctx context.Context, stderr io.Writer) {
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
// enrollment for SIDs the manifest no longer authorizes, so a removed user
// or disabled connector fails closed before any target runtime is touched.
func pruneWindowsStandalonePerUserEnrollments(manifest enterprisehooks.Manifest, hookBinary string) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
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
		for _, name := range connectors {
			if current.rows[name] {
				continue
			}
			result, err := enterpriseForeignHookCleanup(current.creds, name, current.dataDir)
			for _, finding := range result.Removed {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: removed %s %s hook from %s (sha256:%s); backup in %s\n",
					finding.Connector, dashIfEmpty(finding.Event), finding.Path, finding.Digest, result.BackupDir)
			}
			recordEnterpriseForeignHookRemovals(stderr, current.creds.SID, current.creds.UserHome, name, removedForeignHookPaths(result))
			if err != nil {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s %s: %v\n", name, current.creds.UserHome, err)
			}
		}
	}
}
