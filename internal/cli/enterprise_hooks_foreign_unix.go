// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone Unix guardian removes unapproved foreign hooks from every
// eligible user's USER-level vendor config, not only from users with
// per-user manifest rows: a user whose connectors are all machine policy
// (Cursor, Copilot) has no rows but can still add a rewriting hook. The
// enumerator publishes the eligible accounts; the cleanup itself runs in
// the per-user worker with the user's own credentials.
//
// The same worker removes the guardian's per-user registration of a
// machine-policy connector (Codex, Claude Code, Cursor, Copilot) that the
// manifest does not enroll the user for per user: one an earlier route
// left, for example the per-user Claude Code hooks that ownership: "off"
// used to write into every home.

// enterpriseHookForeignCleanupInterval bounds how often the guardian spawns
// the per-user cleanup workers (the reconcile loop runs every minute).
var enterpriseHookForeignCleanupInterval = 5 * time.Minute

// enterpriseHookLoadEligibleAccounts is replaceable in tests (the record's
// trust checks need root-owned directories).
var enterpriseHookLoadEligibleAccounts = enterprisehooks.LoadUnixEligibleAccounts

// enterpriseHookLoadCopilotVSCodeAccounts and
// enterpriseHookWriteCopilotVSCodeAccounts read and publish the record of the
// accounts the guardian wrote VS Code Local hooks for; tests replace them.
var (
	enterpriseHookLoadCopilotVSCodeAccounts  = enterprisehooks.LoadUnixEligibleAccounts
	enterpriseHookWriteCopilotVSCodeAccounts = enterprisehooks.WriteUnixEligibleAccounts
)

var enterpriseHookForeignCleanupState struct {
	sync.Mutex
	last        time.Time
	fingerprint string
	// leftoversClean records that the last pass removed or ruled out every
	// leftover registration, so a pass with nothing but leftovers to check
	// runs again only when the accounts or routes change.
	leftoversClean bool
	// unrepaired names the accounts whose Copilot VS Code Local hook file
	// the last pass could not rewrite: they wait for the interval, so only
	// a newly drifted account makes the next pass due.
	unrepaired map[string]bool
}

// enterpriseHookForeignCleanupConnectors resolves the connectors whose
// policy removes foreign hooks, with the request each worker needs.
func enterpriseHookForeignCleanupConnectors() ([]enterpriseHookWorkerForeignCleanup, *enterpriseHookWorkerCopilotVSCode, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, nil, nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return nil, nil, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return nil, nil, err
	}
	names := enterprisepolicy.StandaloneConnectors(cfg)
	// The VS Code Local harness file and plugin follow the Copilot row:
	// placed while Copilot is governed, removed when it is off or the
	// Local harness is retired, untouched when Copilot is not deployed.
	var vscode *enterpriseHookWorkerCopilotVSCode
	for _, name := range names {
		if name == enterprisepolicy.ConnectorCopilot {
			hookFile, plugin := enterprisepolicy.CopilotVSCodeUserWant(opts)
			vscode = &enterpriseHookWorkerCopilotVSCode{HookBinary: opts.HookBinary, HookFile: hookFile, Plugin: plugin}
		}
	}
	summary := enterprisepolicy.BuildPublicPolicy(opts, names)
	out := []enterpriseHookWorkerForeignCleanup{}
	for _, name := range names {
		policy, ok := summary.Connectors[name]
		if !ok || !policy.Guard || policy.ForeignHooks != config.ForeignHooksRemove {
			continue
		}
		out = append(out, enterpriseHookWorkerForeignCleanup{Connector: name, HookBinary: opts.HookBinary, Policy: policy})
	}
	return out, vscode, nil
}

// enterpriseHookPerUserEnrolled names, per user, the connectors the
// manifest keeps on the per-user route (every row whose connector is not
// published through machine policy, enabled or not): their registrations
// are the guardian's to repair or the administrator's to leave, never
// leftovers.
func enterpriseHookPerUserEnrolled(manifest enterprisehooks.Manifest, machinePolicy map[string]struct{}) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, target := range manifest.Targets {
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		if _, published := machinePolicy[name]; published || name == "" {
			continue
		}
		user := strings.TrimSpace(target.User)
		if out[user] == nil {
			out[user] = map[string]bool{}
		}
		out[user][name] = true
	}
	return out
}

// copilotVSCodeScopedAccounts selects the accounts that may receive the
// managed Local hook. Auto enrollment with inspect has no per-user Copilot
// rows, while manifest enrollment and unenrolled_users: deny require one.
// The eligible-accounts record can lag an exclude_users or exempt_users
// edit, so apply those current settings before writing into a home.
func copilotVSCodeScopedAccounts(ctx context.Context, accounts []enterprisehooks.UnixEligibleAccount, manifest enterprisehooks.Manifest) []enterprisehooks.UnixEligibleAccount {
	if enterpriseHookManifestEnrollment() || cfg.Enterprise.Enrollment.UnenrolledUsers == config.EnterpriseUnenrolledDeny {
		targets := make([]enterprisehooks.ManifestTarget, 0, len(manifest.Targets))
		for _, target := range manifest.Targets {
			if strings.EqualFold(strings.TrimSpace(target.Connector), enterprisepolicy.ConnectorCopilot) &&
				(target.Enabled == nil || *target.Enabled) {
				targets = append(targets, target)
			}
		}
		accounts = enterprisehooks.ManifestEnrolledAccounts(accounts, enterprisehooks.Manifest{Targets: targets})
	}
	leftOut := enterpriseHookEnrollmentLeftOut(ctx, enterpriseHookIdentitySpoolDirForConfig())
	scoped := make([]enterprisehooks.UnixEligibleAccount, 0, len(accounts))
	for _, account := range accounts {
		if !leftOut.has(account.UID, account.User) {
			scoped = append(scoped, account)
		}
	}
	return scoped
}

// runEnterpriseHookStandaloneForeignCleanup is called at the end of every
// standalone reconcile; it does the work at most once per interval unless
// the eligible accounts or policies changed. Cleanup is best effort: the
// hook-side guard still denies tool calls while an unapproved hook remains.
// perUser is enterpriseHookPerUserEnrolled for this pass.
func runEnterpriseHookStandaloneForeignCleanup(ctx context.Context, stderr io.Writer, now time.Time, manifest enterprisehooks.Manifest, perUser map[string]map[string]bool, hookSocket string) int {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return 0
	}
	cleanups, vscode, err := enterpriseHookForeignCleanupConnectors()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %v\n", err)
		return 0
	}
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(enterpriseHookManifest))
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: eligible accounts: %v\n", err)
		return 0
	}
	if enterpriseHookManifestEnrollment() {
		accounts = enterprisehooks.ManifestEnrolledAccounts(accounts, manifest)
	}
	var vscodeAccounts []enterprisehooks.UnixEligibleAccount
	if vscode != nil && (vscode.HookFile || vscode.Plugin) {
		vscodeAccounts = copilotVSCodeScopedAccounts(ctx, accounts, manifest)
	}
	vscodeScoped := make(map[int]bool, len(vscodeAccounts))
	for _, account := range vscodeAccounts {
		vscodeScoped[account.UID] = true
	}
	// Accounts the guardian wrote VS Code Local hooks for that are no
	// longer eligible (excluded, removed from the groups): their files call
	// the hook for an account DefenseClaw no longer covers, and remove-all
	// would not reach them through the eligible accounts alone.
	vscodeRecordPath, recorded, recordErr := loadEnterpriseHookCopilotVSCodeAccounts(enterpriseHookManifest)
	if recordErr != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: VS Code Local accounts record: %v\n", recordErr)
		recorded = nil
	}
	// A removed Copilot connector still has per-user files to reconcile.
	// Check every eligible home, including installations from before the
	// accounts record, and the recorded homes that became ineligible.
	var vscodeRemovalErr error
	if vscode == nil {
		vscode, vscodeRemovalErr = enterpriseHookCopilotVSCodeRemoval()
		if vscodeRemovalErr != nil {
			fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: VS Code Local removal: %v\n", vscodeRemovalErr)
		}
	}
	recordedDirs := copilotVSCodeCreatedDirs(recorded)
	// vscodeFor is the account's VS Code Local request: what its home should
	// hold, and the folders the guardian created there, which go once empty.
	vscodeFor := func(want *enterpriseHookWorkerCopilotVSCode, uid int) *enterpriseHookWorkerCopilotVSCode {
		if want == nil {
			return nil
		}
		request := *want
		if !vscodeScoped[uid] {
			request.HookFile, request.Plugin = false, false
		}
		request.RemoveDirs = recordedDirs[uid]
		return &request
	}
	stale := staleCopilotVSCodeAccounts(recorded, accounts)
	var staleRemoval *enterpriseHookWorkerCopilotVSCode
	if len(stale) > 0 && vscode != nil && strings.TrimSpace(vscode.HookBinary) != "" {
		staleRemoval = &enterpriseHookWorkerCopilotVSCode{HookBinary: vscode.HookBinary}
	}
	vendor := enterprisepolicy.VendorMachinePolicyConnectors(runtime.GOOS)
	// The descriptor names policy actually published by the lifecycle;
	// config alone can name Claude with ownership turned off.
	_, claudeManaged := enterpriseHookStandaloneMachinePolicySet()[enterprisepolicy.ConnectorClaudeCode]
	leftovers := func(user string) []string {
		out := []string{}
		for _, name := range vendor {
			if !perUser[user][name] {
				out = append(out, name)
			}
		}
		return out
	}
	fingerprint := enterpriseHookForeignCleanupFingerprint(cleanups, accounts)
	fingerprint += fmt.Sprintf("claude-managed:%t;", claudeManaged)
	if vscode != nil {
		fingerprint += fmt.Sprintf("copilot-vscode|%s|%t|%t;", vscode.HookBinary, vscode.HookFile, vscode.Plugin)
	}
	// A governed Local harness is re-checked every interval; a removal runs
	// once per change. The Local hook file is the guardian's own, so one a
	// user deleted or edited is rewritten on the next pass, like a per-user
	// registration, not after the interval. One the last pass could not
	// rewrite waits for the interval.
	governed := vscode != nil && (vscode.HookFile || vscode.Plugin)
	for _, account := range accounts {
		fingerprint += account.User + "=" + strings.Join(leftovers(account.User), ",") + ";"
	}
	for _, account := range vscodeAccounts {
		fingerprint += fmt.Sprintf("vscode-enrolled:%s:%d;", account.User, account.UID)
	}
	for _, account := range stale {
		fingerprint += fmt.Sprintf("vscode-stale:%s:%d;", account.User, account.UID)
	}
	hookFileDrift := func() map[string]bool {
		if vscode == nil || !vscode.HookFile {
			return nil
		}
		return enterpriseHookCopilotVSCodeHookFileDrift(vscodeAccounts, vscode.HookBinary)
	}
	drifted := hookFileDrift()
	recordedByUID := map[int]enterprisehooks.UnixEligibleAccount{}
	for _, account := range recorded {
		recordedByUID[account.UID] = account
	}
	recordedFiles := map[int]bool{}
	for _, account := range accounts {
		previous, ok := recordedByUID[account.UID]
		if ok && previous.User == account.User && filepath.Clean(previous.Home) == filepath.Clean(account.Home) &&
			(previous.HomeInode == 0 || account.HomeInode == 0 || previous.HomeInode == account.HomeInode) {
			recordedFiles[account.UID] = true
		}
	}
	enterpriseHookForeignCleanupState.Lock()
	newDrift := false
	stillUnrepaired := map[string]bool{}
	for user := range drifted {
		if enterpriseHookForeignCleanupState.unrepaired[user] {
			stillUnrepaired[user] = true
		} else {
			newDrift = true
		}
	}
	enterpriseHookForeignCleanupState.unrepaired = stillUnrepaired
	due := newDrift || fingerprint != enterpriseHookForeignCleanupState.fingerprint ||
		((len(cleanups) > 0 || governed || claudeManaged || !enterpriseHookForeignCleanupState.leftoversClean) &&
			now.Sub(enterpriseHookForeignCleanupState.last) >= enterpriseHookForeignCleanupInterval)
	if due {
		enterpriseHookForeignCleanupState.last = now
		enterpriseHookForeignCleanupState.fingerprint = fingerprint
	}
	enterpriseHookForeignCleanupState.Unlock()
	if !due {
		return 0
	}

	jobs := []enterpriseHookWorkerJob{}
	clean := vscodeRemovalErr == nil && recordErr == nil
	for _, account := range accounts {
		check := enterpriseHookCheckHome(account.Home, account.UID)
		if check.State != enterprisehooks.HomeAvailable {
			clean = false
			continue
		}
		if account.HomeInode != 0 && check.Inode != 0 && account.HomeInode != check.Inode {
			// The home was recreated since enumeration; the next cycle
			// re-publishes the account.
			clean = false
			continue
		}
		request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, CopilotVSCode: vscodeFor(vscode, account.UID)}
		for _, cleanup := range cleanups {
			cleanup.OwnedCommands = perUserOwnedHookCommands(cleanup.Connector, account.Home, filepath.Join(account.Home, ".defenseclaw"))
			request.ForeignCleanup = append(request.ForeignCleanup, cleanup)
		}
		if len(request.ForeignCleanup) > 0 && cfg != nil && cfg.StandaloneEnterprise() {
			// The worker takes the account's removal lock only for each
			// removal, and this session commits that removal to the ledger
			// before the worker reads on.
			request.cleanupFence = newEnterpriseForeignHookFenceSession(request.ForeignCleanup, stderr, strconv.Itoa(account.UID), account.Home)
		}
		names := leftovers(account.User)
		if len(cleanups) == 0 && len(names) == 0 && vscode == nil && !accountHasRemovedConnectorFiles(account.Home) {
			continue
		}
		for index, name := range names {
			request.Targets = append(request.Targets, enterpriseHookWorkerTarget{
				Index: index,
				Mode:  enterpriseHookWorkerModeRemoveLeftover,
				Options: enterpriseHookWorkerOptions{
					ConnectorName: name,
					UserHome:      account.Home,
					OwnerUID:      account.UID,
					OwnerGID:      account.GID,
					DataDir:       filepath.Join(account.Home, ".defenseclaw"),
				},
			})
		}
		if claudeManaged {
			// Machine policy covers eligible users even when they have no
			// manifest row. An old personal settings.json can still invoke
			// its script, so make that script deny as the target user.
			request.Targets = append(request.Targets, enterpriseHookWorkerTarget{
				Index: len(names), Mode: enterpriseHookWorkerModeBlockPersonalClaude,
				Options: enterpriseHookWorkerOptions{ConnectorName: "claudecode", UserHome: account.Home,
					OwnerUID: account.UID, OwnerGID: account.GID},
			})
		}
		jobs = append(jobs, enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: account.Home},
			Request: request,
		})
	}
	// Stale VS Code Local accounts dropped from the record: removed, or
	// their home was recreated since the files were written.
	dropped := map[int]bool{}
	if staleRemoval == nil && len(stale) > 0 {
		clean = false
	}
	for _, account := range stale {
		if staleRemoval == nil {
			break
		}
		check := enterpriseHookCheckHome(account.Home, account.UID)
		if check.State != enterprisehooks.HomeAvailable {
			clean = false
			continue
		}
		if account.HomeInode != 0 && check.Inode != 0 && account.HomeInode != check.Inode {
			dropped[account.UID] = true
			continue
		}
		jobs = append(jobs, enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: account.Home},
			Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, CopilotVSCode: vscodeFor(staleRemoval, account.UID)},
		})
	}
	staleUIDs := map[int]bool{}
	for _, account := range stale {
		staleUIDs[account.UID] = true
	}
	// Each account's removals are recorded for the gateway so its agent
	// processes that started before them stay denied
	// (recordEnterpriseForeignHookRemovals): through the worker's commit,
	// or here, as soon as its worker ends, for what no commit recorded. A
	// commit the worker opened and never finished is ended first (its files
	// are recorded with the mark of now, and the account's lock is let go),
	// so the record of the rest can take the lock. Only the connectors the
	// job asked for count: the worker runs as the user.
	recordRemovals := func(outcome enterpriseHookWorkerOutcome) {
		// The mark is taken once, as the worker ended, before any lock
		// wait: a commit that waits never makes a later agent look old.
		mark := agentprocess.Now()
		session := outcome.Job.Request.cleanupFence
		if session != nil {
			session.releaseAt(mark)
		}
		for _, cleanup := range outcome.Job.Request.ForeignCleanup {
			report, ok := outcome.Response.Cleanup[cleanup.Connector]
			if !ok {
				continue
			}
			removed := boundedStrings(report.Removed, 32)
			if session != nil {
				removed = session.uncommitted(cleanup.Connector, removed)
			}
			recordEnterpriseForeignHookRemovalsAt(stderr, mark, strconv.Itoa(outcome.Job.Account.UID), outcome.Job.Account.Home,
				cleanup.Connector, removed)
		}
	}
	removed := 0
	createdDirs := map[int][]string{}
	var auditRepairs []enterpriseHookGuardianAuditReport
	reportedUIDs := map[int]bool{}
	outcomes := runEnterpriseHookWorkerPoolReporting(ctx, jobs, enterpriseHookWorkerParallelism, recordRemovals)
	for _, outcome := range outcomes {
		user := outcome.Job.Account.User
		if outcome.Err != nil {
			clean = false
			fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s: %v\n", user, outcome.Err)
			continue
		}
		answered := map[int]enterpriseHookWorkerTargetResult{}
		for _, result := range outcome.Response.Targets {
			answered[result.Index] = result
		}
		for _, target := range outcome.Job.Request.Targets {
			name := target.Options.ConnectorName
			result, ok := answered[target.Index]
			if target.Mode == enterpriseHookWorkerModeBlockPersonalClaude {
				if !ok || !result.OK {
					clean = false
					fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: could not block the personal Claude Code hook for %s: %s\n", user,
						boundedString(firstNonEmpty(result.Error, errEnterpriseHookWorkerNoResult.Error()), 512))
				}
				continue
			}
			switch {
			case ok && result.Removed:
				removed++
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: removed DefenseClaw's per-user %s hooks for %s, which the manifest does not enroll per user\n", name, user)
			case ok && result.OK:
			case ok && result.Pending:
				clean = false
			default:
				clean = false
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: could not remove DefenseClaw's per-user %s hooks for %s: %s\n", name, user, boundedString(firstNonEmpty(result.Error, errEnterpriseHookWorkerNoResult.Error()), 512))
			}
		}
		logEnterpriseForeignHookBlocks(stderr, user, outcome.Response.Blocks, outcome.Response.BlocksDropped, outcome.Response.BlocksError)
		if report := outcome.Response.CopilotVSCode; report != nil {
			// A changed file is a repair only if this account already had a
			// guardian-written file, it drifted before the pass, and the
			// worker restored that exact hook file without an error.
			if report.Error == "" && outcome.Job.Request.CopilotVSCode != nil &&
				outcome.Job.Request.CopilotVSCode.HookFile && recordedFiles[outcome.Job.Account.UID] && drifted[user] {
				hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(outcome.Job.Account.Home)
				for _, path := range report.Changed {
					if filepath.Clean(path) == filepath.Clean(hookFile) {
						if !reportedUIDs[outcome.Job.Account.UID] {
							auditRepairs = append(auditRepairs, enterpriseHookGuardianAuditReport{
								User: user, UID: outcome.Job.Account.UID, Connector: "copilot",
							})
							reportedUIDs[outcome.Job.Account.UID] = true
						}
						break
					}
				}
			}
			if dirs := enterprisehooks.UnixCreatedDirsBelow(filepath.Clean(outcome.Job.Account.Home), report.Created); len(dirs) > 0 {
				createdDirs[outcome.Job.Account.UID] = dirs
			}
			for _, path := range boundedStrings(report.Changed, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: wrote DefenseClaw's VS Code Local hooks for %s at %s\n", user, boundedString(path, 512))
			}
			for _, path := range boundedStrings(report.Removed, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: removed DefenseClaw's VS Code Local hooks for %s at %s\n", user, boundedString(path, 512))
			}
			for _, path := range boundedStrings(report.Kept, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: left %s for %s in place: it holds hooks DefenseClaw did not write\n", boundedString(path, 512), user)
			}
			requestedCoverageKept := false
			if request := outcome.Job.Request.CopilotVSCode; request != nil {
				localPath := filepath.Clean(enterprisepolicy.CopilotVSCodeLocalHookFilePath(outcome.Job.Account.Home))
				pluginDir := filepath.Clean(enterprisepolicy.CopilotPluginDir(outcome.Job.Account.Home))
				for _, path := range report.Kept {
					path = filepath.Clean(path)
					if request.HookFile && path == localPath ||
						request.Plugin && (path == pluginDir || strings.HasPrefix(path, pluginDir+string(filepath.Separator))) {
						requestedCoverageKept = true
						break
					}
				}
			}
			if requestedCoverageKept {
				clean = false
				dropped[outcome.Job.Account.UID] = true
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: cannot claim VS Code Local coverage for %s while independent handlers occupy DefenseClaw's hook files\n", user)
			}
			if report.Error != "" {
				clean = false
				if request := outcome.Job.Request.CopilotVSCode; request != nil && (request.HookFile || request.Plugin) {
					dropped[outcome.Job.Account.UID] = true
				}
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: VS Code Local hooks for %s: %s\n", user, boundedString(report.Error, 512))
			} else if !requestedCoverageKept && (!governed || staleUIDs[outcome.Job.Account.UID] || !vscodeScoped[outcome.Job.Account.UID]) {
				dropped[outcome.Job.Account.UID] = true
			}
		}
		for _, name := range sortedCleanupConnectors(outcome.Response.Cleanup) {
			report := outcome.Response.Cleanup[name]
			for _, path := range boundedStrings(report.Removed, 32) {
				removed++
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: removed a %s hook for %s from %s; backup in %s\n",
					name, user, path, boundedString(report.BackupDir, 512))
			}
			for _, reason := range boundedStrings(report.Reported, 32) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %s hook for %s left in place: %s\n", name, user, reason)
			}
			if report.Error != "" {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %s cleanup for %s: %s\n", name, user, boundedString(report.Error, 512))
			}
		}
	}
	reportEnterpriseHookGuardianRepairs(ctx, hookSocket, auditRepairs)
	if recordErr == nil {
		next := nextCopilotVSCodeAccounts(recorded, vscodeAccounts, governed, dropped, createdDirs)
		if !sameCopilotVSCodeAccounts(recorded, next) {
			var err error
			if len(next) == 0 {
				err = removeEnterpriseHookCopilotVSCodeAccounts(vscodeRecordPath, enterpriseHookManifest)
			} else {
				err = enterpriseHookWriteCopilotVSCodeAccounts(vscodeRecordPath, next)
			}
			if err != nil {
				clean = false
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: VS Code Local accounts record: %v\n", err)
			}
		}
	}
	unrepaired := hookFileDrift()
	enterpriseHookForeignCleanupState.Lock()
	enterpriseHookForeignCleanupState.leftoversClean = clean
	enterpriseHookForeignCleanupState.unrepaired = unrepaired
	enterpriseHookForeignCleanupState.Unlock()
	return removed
}

// staleCopilotVSCodeAccounts are the recorded accounts that are no longer
// eligible.
func staleCopilotVSCodeAccounts(recorded, eligible []enterprisehooks.UnixEligibleAccount) []enterprisehooks.UnixEligibleAccount {
	current := map[int]bool{}
	for _, account := range eligible {
		current[account.UID] = true
	}
	out := []enterprisehooks.UnixEligibleAccount{}
	for _, account := range recorded {
		if !current[account.UID] {
			out = append(out, account)
		}
	}
	return out
}

// nextCopilotVSCodeAccounts is the record after a pass: while the Local
// harness is governed every enrolled account may hold its files; an account
// is dropped once its files are removed (dropped). Each account keeps the
// folders the guardian created in its home (the recorded ones plus this
// pass's created), so the removal can take them out again.
func nextCopilotVSCodeAccounts(recorded, eligible []enterprisehooks.UnixEligibleAccount, governed bool, dropped map[int]bool, created map[int][]string) []enterprisehooks.UnixEligibleAccount {
	byUID := map[int]enterprisehooks.UnixEligibleAccount{}
	for _, account := range recorded {
		byUID[account.UID] = account
	}
	if governed {
		for _, account := range eligible {
			account.CreatedDirs = byUID[account.UID].CreatedDirs
			byUID[account.UID] = account
		}
	}
	out := []enterprisehooks.UnixEligibleAccount{}
	for uid, account := range byUID {
		if dropped[uid] {
			continue
		}
		account.CreatedDirs = enterprisehooks.UnixCreatedDirsBelow(account.Home, append(append([]string(nil), account.CreatedDirs...), created[uid]...))
		out = append(out, account)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

func sameCopilotVSCodeAccounts(a, b []enterprisehooks.UnixEligibleAccount) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(accounts []enterprisehooks.UnixEligibleAccount) map[string]bool {
		out := map[string]bool{}
		for _, account := range accounts {
			dirs := append([]string(nil), account.CreatedDirs...)
			sort.Strings(dirs)
			out[fmt.Sprintf("%s|%d|%d|%s|%d|%s", account.User, account.UID, account.GID, account.Home, account.HomeInode, strings.Join(dirs, "\x00"))] = true
		}
		return out
	}
	left, right := key(a), key(b)
	for account := range left {
		if !right[account] {
			return false
		}
	}
	return len(left) == len(right)
}

// copilotVSCodeCreatedDirs maps each recorded account's uid to the folders
// the guardian created in its home.
func copilotVSCodeCreatedDirs(recorded []enterprisehooks.UnixEligibleAccount) map[int][]string {
	out := map[int][]string{}
	for _, account := range recorded {
		if len(account.CreatedDirs) > 0 {
			out[account.UID] = account.CreatedDirs
		}
	}
	return out
}

// enterpriseHookCopilotVSCodeAccountsPath is the guardian's VS Code Local
// accounts record. It lives in the guardian's authorization directory
// (/var/lib/defenseclaw-hook-guardian on Linux), which the guardian service
// may write: the manifest folder is read-only to it (ReadOnlyPaths=
// /etc/defenseclaw under ProtectSystem=strict), so a record there was never
// written. Without a data directory it is the old place next to the manifest.
func enterpriseHookCopilotVSCodeAccountsPath(manifestPath string) string {
	if cfg != nil && strings.TrimSpace(cfg.DataDir) != "" {
		if dir := managed.HookGuardianAuthorizationDir(cfg.DataDir); filepath.IsAbs(dir) {
			return filepath.Join(dir, enterprisehooks.UnixCopilotVSCodeAccountsFileName)
		}
	}
	return enterprisehooks.UnixCopilotVSCodeAccountsPath(manifestPath)
}

// loadEnterpriseHookCopilotVSCodeAccounts reads the VS Code Local accounts
// record, merged with one an earlier build left next to the manifest, and
// returns the path the record is written to.
func loadEnterpriseHookCopilotVSCodeAccounts(manifestPath string) (string, []enterprisehooks.UnixEligibleAccount, error) {
	path := enterpriseHookCopilotVSCodeAccountsPath(manifestPath)
	accounts, err := enterpriseHookLoadCopilotVSCodeAccounts(path)
	if err != nil {
		return path, nil, err
	}
	if legacy := enterprisehooks.UnixCopilotVSCodeAccountsPath(manifestPath); legacy != path {
		if old, legacyErr := enterpriseHookLoadCopilotVSCodeAccounts(legacy); legacyErr == nil {
			known := map[int]bool{}
			for _, account := range accounts {
				known[account.UID] = true
			}
			for _, account := range old {
				if !known[account.UID] {
					accounts = append(accounts, account)
				}
			}
		}
	}
	return path, accounts, nil
}

// removeEnterpriseHookCopilotVSCodeAccounts deletes the record at path and
// the earlier build's copy next to the manifest (best effort: the guardian
// service cannot write there).
func removeEnterpriseHookCopilotVSCodeAccounts(path, manifestPath string) error {
	if legacy := enterprisehooks.UnixCopilotVSCodeAccountsPath(manifestPath); legacy != path {
		_ = os.Remove(legacy)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// enterpriseForeignHookAsGuardian runs fn from inside an in-process cleanup
// only while the process still has its own identity. A root guardian's
// in-process cleanup changes the effective uid of the whole process, so
// there fn is refused: the hook stays and the guard keeps denying. The
// standalone Unix guardian cleans in its per-user worker, which opens each
// removal's commit over its pipes instead.
func enterpriseForeignHookAsGuardian(fn func() error) error {
	if os.Geteuid() != os.Getuid() {
		return errors.New("foreign-hook removal: an in-process cleanup cannot act as the guardian while it runs as the user")
	}
	return fn()
}

// enterpriseForeignHookUserEnvRedirects adds nothing on Unix: the per-user
// worker cleans with its own environment and the redirects the user's hooks
// recorded.
func enterpriseForeignHookUserEnvRedirects(enterprisehooks.TargetCredentials, enterprisepolicy.GuardRequest) ([]enterprisepolicy.EnvRedirect, error) {
	return nil, nil
}

// runEnterpriseHookWorkerForeignCleanup runs inside the worker as the user.
// With a fence, each removal asks for it right before it changes a file and
// commits that removal before the cleanup reads on, so the fence never
// covers a scan or another task of the worker.
func runEnterpriseHookWorkerForeignCleanup(request enterpriseHookWorkerRequest, now time.Time, fence enterpriseForeignHookCleanupFence) map[string]enterpriseHookWorkerCleanupReport {
	out := map[string]enterpriseHookWorkerCleanupReport{}
	home := filepath.Clean(request.Home)
	for _, cleanup := range request.ForeignCleanup {
		name := strings.ToLower(strings.TrimSpace(cleanup.Connector))
		if name == "" {
			continue
		}
		// The worker's environment is not the user's session: the user's
		// hooks recorded the config locations their agents' environment
		// redirects to (XDG_CONFIG_HOME, COPILOT_HOME, CODEX_HOME, ...).
		redirects, redirectErr := enterprisepolicy.LoadEnvRedirects(home, name)
		guard := enterprisepolicy.GuardRequest{
			Connector:     name,
			GOOS:          runtime.GOOS,
			Home:          home,
			AccountHome:   home,
			HookBinary:    cleanup.HookBinary,
			Policy:        cleanup.Policy,
			Getenv:        os.Getenv,
			OwnedCommands: cleanup.OwnedCommands,
		}
		switch {
		case fence != nil:
			guard.GuardRemoval = enterpriseForeignHookRemovalGuard(name, fence)
		case request.Standalone:
			// A standalone removal is recorded, under the account's removal
			// lock and after the key rotation, before the file changes; a
			// worker the guardian gave no commit channel removes nothing.
			guard.GuardRemoval = func([]string, func() error) error {
				return errors.New("foreign-hook removal refused: the guardian passed no removal commit channel")
			}
		}
		result, err := enterprisepolicy.CleanUserForeignHooksWithRedirects(guard, redirects, now)
		err = errors.Join(err, redirectErr)
		report := enterpriseHookWorkerCleanupReport{BackupDir: result.BackupDir}
		for _, finding := range result.Removed {
			report.Removed = append(report.Removed, finding.Path)
		}
		for _, finding := range result.Reported {
			report.Reported = append(report.Reported, finding.Path+" ("+finding.Reason+")")
		}
		if err != nil {
			report.Error = err.Error()
		}
		out[name] = report
	}
	return out
}

// enterpriseHookCopilotVSCodeHookFileDrift names the available accounts
// whose home lacks DefenseClaw's current VS Code Local hook file. It only
// compares the file's bytes (CopilotVSCodeUserState, a bounded no-follow
// read); the worker, running as the user, writes it.
func enterpriseHookCopilotVSCodeHookFileDrift(accounts []enterprisehooks.UnixEligibleAccount, hookBinary string) map[string]bool {
	drifted := map[string]bool{}
	for _, account := range accounts {
		if enterpriseHookCheckHome(account.Home, account.UID).State != enterprisehooks.HomeAvailable {
			continue
		}
		if file, _ := enterprisepolicy.CopilotVSCodeUserState(account.Home, runtime.GOOS, hookBinary); !file {
			drifted[account.User] = true
		}
	}
	return drifted
}

// runEnterpriseHookWorkerCopilotVSCode runs inside the worker as the user.
func runEnterpriseHookWorkerCopilotVSCode(request enterpriseHookWorkerRequest) *enterpriseHookWorkerCopilotVSCodeReport {
	want := request.CopilotVSCode
	result, err := enterprisepolicy.EnsureCopilotVSCodeUser(enterprisepolicy.CopilotVSCodeUserRequest{
		Home:       filepath.Clean(request.Home),
		GOOS:       runtime.GOOS,
		HookBinary: want.HookBinary,
		HookFile:   want.HookFile,
		Plugin:     want.Plugin,
		RemoveDirs: want.RemoveDirs,
	})
	report := &enterpriseHookWorkerCopilotVSCodeReport{Changed: result.Changed, Removed: result.Removed, Kept: result.Kept, Created: result.CreatedDirs}
	if err != nil {
		report.Error = err.Error()
	}
	return report
}

func enterpriseHookForeignCleanupFingerprint(cleanups []enterpriseHookWorkerForeignCleanup, accounts []enterprisehooks.UnixEligibleAccount) string {
	var b strings.Builder
	for _, cleanup := range cleanups {
		fmt.Fprintf(&b, "%s|%s|%s|%s;", cleanup.Connector, cleanup.Policy.ForeignHooks, cleanup.HookBinary, strings.Join(cleanup.Policy.AllowedHooks, ","))
	}
	for _, account := range accounts {
		fmt.Fprintf(&b, "%s:%d:%d:%s:%d;", account.User, account.UID, account.GID, account.Home, account.HomeInode)
	}
	return b.String()
}

func sortedCleanupConnectors(reports map[string]enterpriseHookWorkerCleanupReport) []string {
	names := make([]string, 0, len(reports))
	for name := range reports {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func boundedStrings(values []string, limit int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, boundedString(value, 512))
	}
	return out
}

func boundedString(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
