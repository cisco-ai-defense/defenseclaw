// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// windowsManagedHooksLifecycleFirstInstall reports whether the pending
// transaction installs where no DefenseClaw gateway existed (a first install,
// or one after an uninstall). Rolling one back leaves nothing of DefenseClaw
// behind.
func windowsManagedHooksLifecycleFirstInstall(
	ctx windowsManagedHooksLifecycleContext,
	pending *windowsManagedHooksLifecycleTransaction,
) bool {
	if pending == nil {
		return false
	}
	for _, file := range pending.Snapshot.Files {
		if sameWindowsEnterprisePathCLI(file.Path, ctx.gatewayPath) {
			return !file.Existed
		}
	}
	return false
}

// Replaceable in tests.
var (
	windowsFirstInstallRollbackUserConfigRestorer = enterprisehooks.RestoreWindowsStandaloneUserAgentConfigs
	windowsFirstInstallRollbackFootprintRemover   = rollbackWindowsStandaloneFirstInstallFootprint
)

// rollbackWindowsStandaloneFirstInstallFootprint runs when a rolled-back
// first standalone install retires its lifecycle journal: the services are
// stopped, and the accounts' DefenseClaw folders, with the connector backups
// in them, still exist (the target-runtime cleanup after it removes the
// folders the install created). The guardian may already have registered
// DefenseClaw in the accounts' agent configurations and published machine
// policy. This puts each account's agent files back the way the install
// found them and removes that policy: the per-user enrollments and runtime
// selectors, the Copilot and OpenCode policy, the Claude Code version floor,
// the hook runtime folder and the vendor lock files. Each step is best
// effort, so a leftover never keeps the rollback from finishing; it returns
// each leftover.
func rollbackWindowsStandaloneFirstInstallFootprint(ctx windowsManagedHooksLifecycleContext) []string {
	var leftovers []string
	note := func(format string, args ...any) {
		leftovers = append(leftovers, fmt.Sprintf(format, args...))
	}
	manifest, err := enterprisehooks.LoadManifest(ctx.manifestPath)
	if err != nil {
		note("the agent configurations of the enrolled accounts, which could not be listed: %v", err)
	}
	accountKey := func(target enterprisehooks.ManifestTarget) string {
		return strings.ToUpper(strings.TrimSpace(target.SID)) + "\x00" + strings.ToLower(strings.TrimSpace(target.DataDir))
	}
	// Each leftover names the account and the connectors enrolled for it.
	connectors := map[string][]string{}
	for _, target := range manifest.Targets {
		key := accountKey(target)
		if name := strings.TrimSpace(target.Connector); name != "" && !slices.Contains(connectors[key], name) {
			connectors[key] = append(connectors[key], name)
		}
	}
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		sid, home := strings.TrimSpace(target.SID), strings.TrimSpace(target.UserHome)
		key := accountKey(target)
		if sid == "" || home == "" || seen[key] {
			continue
		}
		seen[key] = true
		account := sid
		if user := strings.TrimSpace(target.User); user != "" {
			account = user + " (" + sid + ")"
		}
		if names := connectors[key]; len(names) > 0 {
			account += " [" + strings.Join(names, ", ") + "]"
		}
		_, kept, err := windowsFirstInstallRollbackUserConfigRestorer(home, sid, target.DataDir)
		for _, path := range kept {
			note("%s: %s, which changed after DefenseClaw wrote it", account, path)
		}
		if leftover := windowsFirstInstallRollbackAccountLeftover(account, err); leftover != "" {
			leftovers = append(leftovers, leftover)
		}
	}
	if err := enterprisehooks.RemoveWindowsPerUserManagedEnrollments(
		ctx.opts.HookBinary,
		enterprisehooks.WindowsStandalonePerUserConnectorNames(),
	); err != nil {
		note("per-user enrollments: %v", err)
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		note("Copilot and OpenCode machine policy and the Claude Code version floor: %v", err)
	} else {
		opts := enterprisepolicy.LayoutOptions(layout, programFiles, programData)
		if _, err := enterprisepolicy.RemoveWindowsGoOwned(opts); err != nil {
			note("Copilot and OpenCode machine policy: %v", err)
		}
		if _, err := enterprisepolicy.RemoveWindowsClaudeVersionFloor(opts); err != nil {
			note("the Claude Code version floor: %v", err)
		}
		if _, err := enterprisepolicy.RemoveWindowsWSL(opts); err != nil {
			note("the WSL agent-session policy: %v", err)
		}
	}
	if err := enterprisehooks.RemoveWindowsStandalonePerUserRuntimeSelectors(); err != nil {
		note("per-user runtime selectors: %v", err)
	}
	if kept, err := enterprisehooks.RemoveWindowsStandaloneHookRuntimeDirectories(); err != nil {
		note("the hook runtime folder: %v", err)
	} else {
		for _, directory := range kept {
			note("%s", directory)
		}
	}
	if err := enterprisehooks.RemoveWindowsStandaloneMachinePolicySelectorLocks(); err != nil {
		note("runtime selector locks: %v", err)
	}
	if err := enterprisehooks.RemoveWindowsStandaloneManagedPolicyLocks(ctx.opts.RequirementsPath); err != nil {
		note("managed policy locks: %v", err)
	}
	return leftovers
}

// windowsFirstInstallRollbackAccountLeftover names why the rollback left an
// account's agent registrations, or "" when it removed them. Only
// LocalSystem can act as an account: Setup run from an elevated
// administrator prompt leaves every account's registrations, which the
// guardian (a LocalSystem service) wrote during the install.
func windowsFirstInstallRollbackAccountLeftover(account string, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, enterprisehooks.ErrWindowsEnterpriseNotLocalSystem):
		return fmt.Sprintf("%s: DefenseClaw's agent registrations, because Setup did not run as LocalSystem", account)
	case enterprisehooks.IsWindowsTargetSessionUnavailable(err):
		return fmt.Sprintf("%s: DefenseClaw's agent registrations, because the account is not signed in", account)
	default:
		return fmt.Sprintf("%s: DefenseClaw's agent registrations: %s", account, boundedEnterpriseHookUserCleanupText(err.Error()))
	}
}
