//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

// until 1.1: the managed Linux/macOS removal point for OpenHands and
// OmniGent (GAP-1845). A 1.0.2-1.0.4 standalone guardian set them up in a
// user's home; 1.0.5 no longer ships them. Every apply job of the standalone
// guardian (install, verify, repair, remove, purge: the package upgrade, the
// verify timer and uninstall all run one) first runs their teardown as the
// account, which removes what DefenseClaw wrote, by identity, and nothing
// else. It never fails the job and blocks nothing; what it cannot remove is
// logged under the one removal notice. Delete with
// internal/gateway/connector/removed.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// enterpriseHookWorkerRemovedLog receives the removal notice and leftovers
// (the worker's stderr, which the parent forwards to the guardian log).
var enterpriseHookWorkerRemovedLog io.Writer = os.Stderr

// removeRetiredConnectorsForAccount tears OpenHands and OmniGent down once
// for each DefenseClaw data directory of the request's targets. The Secure
// Client guardian is left alone.
func removeRetiredConnectorsForAccount(ctx context.Context, request enterpriseHookWorkerRequest) {
	if !request.Standalone || strings.TrimSpace(request.Home) == "" {
		return
	}
	seen := map[string]bool{}
	for _, target := range request.Targets {
		dataDir := strings.TrimSpace(target.Options.DataDir)
		if dataDir == "" || !filepath.IsAbs(dataDir) || seen[filepath.Clean(dataDir)] {
			continue
		}
		seen[filepath.Clean(dataDir)] = true
		removeRetiredConnectorsIn(ctx, request.Home, connector.SetupOpts{
			DataDir:           filepath.Clean(dataDir),
			WorkspaceDir:      strings.TrimSpace(target.Options.WorkspaceDir),
			ManagedEnterprise: true,
		})
	}
	if len(seen) == 0 && filepath.IsAbs(request.Home) {
		// An account with no target (the foreign-cleanup job of an account
		// whose row is gone) has its data in the default place (GAP-1916).
		removeRetiredConnectorsIn(ctx, request.Home, connector.SetupOpts{
			DataDir:           filepath.Join(filepath.Clean(request.Home), ".defenseclaw"),
			ManagedEnterprise: true,
		})
	}
}

// accountHasRemovedConnectorFiles reports whether the account's default data
// folder still holds an OpenHands hook script or OmniGent policy module (the
// 1.0.4 deny stubs), so the guardian starts a job for an account it has no
// other work for (GAP-1916). Existence only: the job reads them as the account.
func accountHasRemovedConnectorFiles(home string) bool {
	if !filepath.IsAbs(home) {
		return false
	}
	hooks := filepath.Join(filepath.Clean(home), ".defenseclaw", "hooks")
	for _, name := range []string{"openhands-hook.sh", "defenseclaw_omnigent_policy.py"} {
		if _, err := os.Lstat(filepath.Join(hooks, name)); err == nil {
			return true
		}
	}
	return false
}

// removedConnectorsLoggedName is the file in the account's data folder that
// holds a digest of the leftovers each removed connector last logged. The
// first job that finds a leftover always logs it, also when the teardown could
// remove nothing (GAP-2016: an account whose only leftover is the copy 1.0.4
// saved of an edited module); later jobs log only a change (GAP-1917). The
// purge removes it with the data folder.
const removedConnectorsLoggedName = "removed-connectors-logged.json"

func removeRetiredConnectorsIn(ctx context.Context, home string, opts connector.SetupOpts) {
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		return
	}
	defer restore()
	logged := readRemovedConnectorsLogged(opts.DataDir)
	changedLog := false
	noticed := false
	for _, name := range []string{"openhands", "omnigent"} {
		before, _ := connector.RemovedConnectorLeftovers(name, opts)
		if len(before) == 0 {
			if _, ok := logged[name]; ok {
				delete(logged, name)
				changedLog = true
			}
			continue
		}
		if retired, ok := connector.RetiredConnector(name); ok {
			_ = retired.Teardown(ctx, opts)
		}
		left, _ := connector.RemovedConnectorLeftovers(name, opts)
		digest := removedLeftoversDigest(left)
		if removedLeftoversDigest(before) == digest && logged[name] == digest {
			// Logged already and nothing changed since (a copy 1.0.4 saved
			// stays by design): log nothing again (GAP-1917).
			continue
		}
		if !noticed {
			fmt.Fprintf(enterpriseHookWorkerRemovedLog, "[enterprise-hooks] %s\n", connector.RemovedConnectorNotice)
			noticed = true
		}
		for _, item := range left {
			fmt.Fprintf(enterpriseHookWorkerRemovedLog, "[enterprise-hooks] removed connector %s left %s: %s; to remove it: %s\n", name, item.Path, item.What, item.Step)
		}
		if len(left) == 0 {
			delete(logged, name)
		} else {
			logged[name] = digest
		}
		changedLog = true
	}
	if changedLog {
		writeRemovedConnectorsLogged(opts.DataDir, logged)
	}
}

func removedLeftoversDigest(items []connector.RemovedLeftover) string {
	if len(items) == 0 {
		return ""
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, item.Path+"\x00"+item.What)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

func readRemovedConnectorsLogged(dataDir string) map[string]string {
	logged := map[string]string{}
	if strings.TrimSpace(dataDir) == "" {
		return logged
	}
	path := filepath.Join(dataDir, removedConnectorsLoggedName)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return logged
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &logged) != nil {
		return map[string]string{}
	}
	return logged
}

// writeRemovedConnectorsLogged records what was logged. Best effort, and only
// in a data folder that exists: when it cannot be written, a later job logs
// the same leftovers again, which is the safe side.
func writeRemovedConnectorsLogged(dataDir string, logged map[string]string) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	if info, err := os.Lstat(dataDir); err != nil || !info.IsDir() {
		return
	}
	path := filepath.Join(dataDir, removedConnectorsLoggedName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return
	}
	if len(logged) == 0 {
		_ = os.Remove(path)
		return
	}
	data, err := json.Marshal(logged)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dataDir, "."+removedConnectorsLoggedName+".*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(name, 0o600) != nil || os.Rename(name, path) != nil {
		_ = os.Remove(name)
	}
}

// withoutRemovedConnectorTargets drops the OpenHands and OmniGent rows from
// the targets of a guardian pass. A 1.0.2-1.0.4 enumerator enrolled them, and
// until the 1.0.5 enumerator rewrites the manifest (its next cycle, about a
// minute after a package upgrade) the guardian read them as enrolled: it
// verified each with a registry that no longer has the connector, failed it
// with "unknown connector", and the postinstall of the upgrade failed on
// guardian_target_failed (GAP-2504). Not enrolled, a row the guardian
// protected is due for its per-user cleanup, which the job teardown
// completes (GAP-1915): the same path as a rewritten manifest.
func withoutRemovedConnectorTargets(targets []enterprisehooks.ManifestTarget) []enterprisehooks.ManifestTarget {
	kept := make([]enterprisehooks.ManifestTarget, 0, len(targets))
	for _, target := range targets {
		if connector.IsRemovedConnector(strings.ToLower(strings.TrimSpace(target.Connector))) {
			continue
		}
		kept = append(kept, target)
	}
	return kept
}
