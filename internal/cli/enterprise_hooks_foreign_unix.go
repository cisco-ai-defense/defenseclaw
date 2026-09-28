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
}

// enterpriseHookForeignCleanupConnectors resolves the connectors whose
// policy removes foreign hooks, with the request each worker needs.
func enterpriseHookForeignCleanupConnectors() ([]enterpriseHookWorkerForeignCleanup, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return nil, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return nil, err
	}
	names := enterprisepolicy.StandaloneConnectors(cfg)
	summary := enterprisepolicy.BuildPublicPolicy(opts, names)
	out := []enterpriseHookWorkerForeignCleanup{}
	for _, name := range names {
		policy, ok := summary.Connectors[name]
		if !ok || !policy.Guard || policy.ForeignHooks != config.ForeignHooksRemove {
			continue
		}
		out = append(out, enterpriseHookWorkerForeignCleanup{Connector: name, HookBinary: opts.HookBinary, Policy: policy})
	}
	return out, nil
}

// runEnterpriseHookStandaloneForeignCleanup is called at the end of every
// standalone reconcile; it does the work at most once per interval unless
// the eligible accounts or policies changed. Cleanup is best effort: the
// hook-side guard still denies tool calls while an unapproved hook remains.
func runEnterpriseHookStandaloneForeignCleanup(ctx context.Context, stderr io.Writer, now time.Time) int {
	cleanups, err := enterpriseHookForeignCleanupConnectors()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %v\n", err)
		return 0
	}
	if len(cleanups) == 0 {
		return 0
	}
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(enterpriseHookManifest))
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: eligible accounts: %v\n", err)
		return 0
	}
	fingerprint := enterpriseHookForeignCleanupFingerprint(cleanups, accounts)
	enterpriseHookForeignCleanupState.Lock()
	due := now.Sub(enterpriseHookForeignCleanupState.last) >= enterpriseHookForeignCleanupInterval ||
		fingerprint != enterpriseHookForeignCleanupState.fingerprint
	if due {
		enterpriseHookForeignCleanupState.last = now
		enterpriseHookForeignCleanupState.fingerprint = fingerprint
	}
	enterpriseHookForeignCleanupState.Unlock()
	if !due {
		return 0
	}

	jobs := []enterpriseHookWorkerJob{}
	for _, account := range accounts {
		check := enterpriseHookCheckHome(account.Home, account.UID)
		if check.State != enterprisehooks.HomeAvailable {
			continue
		}
		if account.HomeInode != 0 && check.Inode != 0 && account.HomeInode != check.Inode {
			// The home was recreated since enumeration; the next cycle
			// re-publishes the account.
			continue
		}
		request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true}
		for _, cleanup := range cleanups {
			cleanup.OwnedCommands = perUserOwnedHookCommands(cleanup.Connector, account.Home, filepath.Join(account.Home, ".defenseclaw"))
			request.ForeignCleanup = append(request.ForeignCleanup, cleanup)
		}
		jobs = append(jobs, enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: account.Home},
			Request: request,
		})
	}
	removed := 0
	for _, outcome := range runEnterpriseHookWorkerPool(ctx, jobs, enterpriseHookWorkerParallelism) {
		user := outcome.Job.Account.User
		if outcome.Err != nil {
			fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s: %v\n", user, outcome.Err)
			continue
		}
		logEnterpriseForeignHookBlocks(stderr, user, outcome.Response.Blocks, outcome.Response.BlocksDropped, outcome.Response.BlocksError)
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
