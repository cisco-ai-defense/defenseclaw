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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
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

var enterpriseHookForeignCleanupState struct {
	sync.Mutex
	last        time.Time
	fingerprint string
	// leftoversClean records that the last pass removed or ruled out every
	// leftover registration, so a pass with nothing but leftovers to check
	// runs again only when the accounts or routes change.
	leftoversClean bool
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

// runEnterpriseHookStandaloneForeignCleanup is called at the end of every
// standalone reconcile; it does the work at most once per interval unless
// the eligible accounts or policies changed. Cleanup is best effort: the
// hook-side guard still denies tool calls while an unapproved hook remains.
// perUser is enterpriseHookPerUserEnrolled for this pass.
func runEnterpriseHookStandaloneForeignCleanup(ctx context.Context, stderr io.Writer, now time.Time, perUser map[string]map[string]bool) int {
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
	vendor := enterprisepolicy.VendorMachinePolicyConnectors(runtime.GOOS)
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
	if vscode != nil {
		fingerprint += fmt.Sprintf("copilot-vscode|%s|%t|%t;", vscode.HookBinary, vscode.HookFile, vscode.Plugin)
	}
	// A governed Local harness is re-checked every interval (a user can
	// delete the file); a removal runs once per change.
	governed := vscode != nil && (vscode.HookFile || vscode.Plugin)
	for _, account := range accounts {
		fingerprint += account.User + "=" + strings.Join(leftovers(account.User), ",") + ";"
	}
	enterpriseHookForeignCleanupState.Lock()
	due := fingerprint != enterpriseHookForeignCleanupState.fingerprint ||
		((len(cleanups) > 0 || governed || !enterpriseHookForeignCleanupState.leftoversClean) &&
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
	clean := true
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
		request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, CopilotVSCode: vscode}
		for _, cleanup := range cleanups {
			cleanup.OwnedCommands = perUserOwnedHookCommands(cleanup.Connector, account.Home, filepath.Join(account.Home, ".defenseclaw"))
			request.ForeignCleanup = append(request.ForeignCleanup, cleanup)
		}
		names := leftovers(account.User)
		if len(cleanups) == 0 && len(names) == 0 && vscode == nil {
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
		jobs = append(jobs, enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: account.Home},
			Request: request,
		})
	}
	// Each account's removals are recorded for the gateway as soon as its
	// worker ends, so its agent processes that started before them stay
	// denied (recordEnterpriseForeignHookRemovals). Only the connectors the
	// job asked for count: the worker runs as the user.
	recordRemovals := func(outcome enterpriseHookWorkerOutcome) {
		for _, cleanup := range outcome.Job.Request.ForeignCleanup {
			if report, ok := outcome.Response.Cleanup[cleanup.Connector]; ok {
				recordEnterpriseForeignHookRemovals(stderr, strconv.Itoa(outcome.Job.Account.UID), outcome.Job.Account.Home,
					cleanup.Connector, boundedStrings(report.Removed, 32))
			}
		}
	}
	removed := 0
	for _, outcome := range runEnterpriseHookWorkerPoolReporting(ctx, jobs, enterpriseHookWorkerParallelism, recordRemovals) {
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
			for _, path := range boundedStrings(report.Changed, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: wrote DefenseClaw's VS Code Local hooks for %s at %s\n", user, boundedString(path, 512))
			}
			for _, path := range boundedStrings(report.Removed, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: removed DefenseClaw's VS Code Local hooks for %s at %s\n", user, boundedString(path, 512))
			}
			for _, path := range boundedStrings(report.Kept, 8) {
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: left %s for %s in place: it holds hooks DefenseClaw did not write\n", boundedString(path, 512), user)
			}
			if report.Error != "" {
				clean = false
				fmt.Fprintf(stderr, "defenseclaw: enterprise hooks: VS Code Local hooks for %s: %s\n", user, boundedString(report.Error, 512))
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
	enterpriseHookForeignCleanupState.Lock()
	enterpriseHookForeignCleanupState.leftoversClean = clean
	enterpriseHookForeignCleanupState.Unlock()
	return removed
}

// enterpriseForeignHookUserEnvRedirects adds nothing on Unix: the per-user
// worker cleans with its own environment and the redirects the user's hooks
// recorded.
func enterpriseForeignHookUserEnvRedirects(enterprisehooks.TargetCredentials, enterprisepolicy.GuardRequest) ([]enterprisepolicy.EnvRedirect, error) {
	return nil, nil
}

// runEnterpriseHookWorkerForeignCleanup runs inside the worker as the user.
func runEnterpriseHookWorkerForeignCleanup(request enterpriseHookWorkerRequest, now time.Time) map[string]enterpriseHookWorkerCleanupReport {
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
		result, err := enterprisepolicy.CleanUserForeignHooksWithRedirects(enterprisepolicy.GuardRequest{
			Connector:     name,
			GOOS:          runtime.GOOS,
			Home:          home,
			AccountHome:   home,
			HookBinary:    cleanup.HookBinary,
			Policy:        cleanup.Policy,
			Getenv:        os.Getenv,
			OwnedCommands: cleanup.OwnedCommands,
		}, redirects, now)
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

// runEnterpriseHookWorkerCopilotVSCode runs inside the worker as the user.
func runEnterpriseHookWorkerCopilotVSCode(request enterpriseHookWorkerRequest) *enterpriseHookWorkerCopilotVSCodeReport {
	want := request.CopilotVSCode
	result, err := enterprisepolicy.EnsureCopilotVSCodeUser(enterprisepolicy.CopilotVSCodeUserRequest{
		Home:       filepath.Clean(request.Home),
		GOOS:       runtime.GOOS,
		HookBinary: want.HookBinary,
		HookFile:   want.HookFile,
		Plugin:     want.Plugin,
	})
	report := &enterpriseHookWorkerCopilotVSCodeReport{Changed: result.Changed, Removed: result.Removed, Kept: result.Kept}
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
