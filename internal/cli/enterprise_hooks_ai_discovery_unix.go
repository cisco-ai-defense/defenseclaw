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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// Per-user AI discovery (standalone profile, Linux and macOS). The gateway's
// sandbox hides every user home and every other account's processes, so the
// guardian runs the static scan in each enrolled user's worker, as that
// user, on the ai_discovery interval. It validates each report and writes it
// with the account it started the worker for to a spool in the
// authorization directory (root-owned, readable by the gateway's group),
// which the gateway ingests on its full scans.

var enterpriseHookAIDiscoveryState struct {
	sync.Mutex
	running     bool
	last        time.Time
	fingerprint string
}

func init() {
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
		run.Rows = enterpriseHookEnrolledAccountRows(stderr, run)
		startEnterpriseHookAIDiscovery(ctx, stderr, run)
		startEnterpriseHookIdentitySpool(ctx, stderr, run)
	}
}

// enterpriseHookEnrolledAccountRows is the run's rows plus one row for each
// eligible account the enumerator published that has none. Rows exist only
// for per-user hook connectors: a deployment that selects only the
// machine-policy connectors (Claude Code, Codex) has none, and its enrolled
// accounts still need their identity records and per-user scans (GAP-0021).
func enterpriseHookEnrolledAccountRows(stderr io.Writer, run enterpriseHookReconcileRun) []enterpriseHookReconcileRow {
	rows := append([]enterpriseHookReconcileRow(nil), run.Rows...)
	manifest := strings.TrimSpace(run.Manifest)
	if manifest == "" {
		return rows
	}
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(manifest))
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] eligible accounts: %v\n", err)
		return rows
	}
	seen := map[int]bool{}
	for _, row := range rows {
		seen[row.UID] = true
	}
	for _, account := range accounts {
		if account.UID <= 0 || seen[account.UID] {
			continue
		}
		seen[account.UID] = true
		rows = append(rows, enterpriseHookReconcileRow{
			User: account.User, UserHome: account.Home, UID: account.UID, HomeInode: account.HomeInode, OK: true,
		})
	}
	return rows
}

// startEnterpriseHookAIDiscovery starts a pass in the background when one is
// due (interval elapsed or the enrolled accounts changed), so a slow home
// never delays hook repair.
func startEnterpriseHookAIDiscovery(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
	dir := inventory.UserScanDirForConfig(cfg)
	if dir == "" {
		return
	}
	if !cfg.AIDiscovery.Enabled {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] ai discovery is disabled; remove %s: %v\n", dir, err)
		}
		return
	}
	interval := time.Duration(cfg.AIDiscovery.ScanIntervalMin) * time.Minute
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	fingerprint := enterpriseHookAIDiscoveryFingerprint(run.Rows)
	now := time.Now()
	state := &enterpriseHookAIDiscoveryState
	state.Lock()
	due := !state.running && (fingerprint != state.fingerprint || now.Sub(state.last) >= interval)
	if due {
		state.running, state.last, state.fingerprint = true, now, fingerprint
	}
	state.Unlock()
	if !due {
		return
	}
	rows := append([]enterpriseHookReconcileRow(nil), run.Rows...)
	go func() {
		defer func() {
			state.Lock()
			state.running = false
			state.Unlock()
		}()
		runEnterpriseHookAIDiscoveryPass(ctx, stderr, dir, rows)
	}()
}

func enterpriseHookAIDiscoveryFingerprint(rows []enterpriseHookReconcileRow) string {
	keys := []string{}
	for _, row := range rows {
		if row.UID > 0 {
			keys = append(keys, fmt.Sprintf("%d:%s:%t", row.UID, filepath.Clean(row.UserHome), row.Pending))
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

// runEnterpriseHookAIDiscoveryPass scans every enrolled account whose home is
// available and keeps the records of enrolled accounts only: a pending home
// keeps its last record until the gateway ages it out.
func runEnterpriseHookAIDiscoveryPass(ctx context.Context, stderr io.Writer, dir string, rows []enterpriseHookReconcileRow) {
	if err := ensureEnterpriseHookStandaloneAuthDir(dir); err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] ai discovery spool: %v\n", err)
		return
	}
	enrolled := map[string]bool{inventory.UserScanPassName: true}
	accounts := []enterpriseHookWorkerAccount{}
	resolver := enterprisehooks.StandaloneResolver()
	for _, row := range rows {
		uid := strconv.Itoa(row.UID)
		if row.UID <= 0 || enrolled[uid+".json"] {
			continue
		}
		enrolled[uid+".json"] = true
		if row.Pending {
			continue
		}
		account, err := resolver.LookupUID(row.UID)
		home := filepath.Clean(row.UserHome)
		if err != nil || account.UID != row.UID || (strings.TrimSpace(account.Home) != "" && filepath.Clean(account.Home) != home) {
			continue
		}
		if enterpriseHookCheckHome(home, row.UID).State != enterprisehooks.HomeAvailable {
			continue
		}
		accounts = append(accounts, enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.Name, Home: home})
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !enrolled[entry.Name()] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	if len(accounts) == 0 {
		return
	}
	// The administrator's packs only: packs in the gateway's data directory
	// would let the service account choose what is read in user homes.
	catalog, err := inventory.LoadAISignaturesWithOptions(inventory.AISignatureLoadOptions{
		SignaturePacks:       cfg.AIDiscovery.SignaturePacks,
		PackDigests:          cfg.AIDiscovery.SignaturePackDigests,
		RequireDigests:       cfg.StandaloneEnterprise(),
		DisabledSignatureIDs: cfg.AIDiscovery.DisabledSignatureIDs,
	})
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] ai discovery signatures: %v\n", err)
		return
	}
	// The pass record tells the gateway a pass is on its way, and how long
	// the last one took, so records do not expire during a slow pass.
	started := time.Now()
	pass, _ := inventory.ReadUserScanPass(filepath.Join(dir, inventory.UserScanPassName))
	pass = inventory.UserScanPass{Version: inventory.UserScanRecordVersion, StartedAt: started.UTC(), Running: true, LastPassSeconds: pass.LastPassSeconds}
	if err := writeEnterpriseHookAIDiscoveryPass(dir, pass); err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] ai discovery pass record: %v\n", err)
	}
	defer func() {
		pass.Running, pass.LastPassSeconds = false, int64(time.Since(started).Round(time.Second)/time.Second)
		if err := writeEnterpriseHookAIDiscoveryPass(dir, pass); err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] ai discovery pass record: %v\n", err)
		}
	}()
	options := inventory.UserScanOptionsFromConfig(cfg)
	jobs := make([]enterpriseHookWorkerJob, 0, len(accounts))
	for _, account := range accounts {
		jobs = append(jobs, enterpriseHookWorkerJob{Account: account, Request: enterpriseHookWorkerRequest{
			Operation:   enterpriseHookWorkerOpAIDiscovery,
			Standalone:  true,
			AIDiscovery: &enterpriseHookWorkerAIDiscovery{Options: options, Catalog: catalog},
		}})
	}
	for _, outcome := range runEnterpriseHookWorkerPool(ctx, jobs, enterpriseHookWorkerParallelism) {
		err := outcome.Err
		if err == nil && outcome.Response.AIDiscovery == nil {
			err = errors.New("the worker returned no report")
		}
		if err == nil {
			report := *outcome.Response.AIDiscovery
			if err = inventory.SanitizeUserScanReport(&report, catalog, options.StoreRawLocalPaths); err == nil {
				err = writeEnterpriseHookAIDiscoveryRecord(dir, outcome.Job.Account, report, time.Now())
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] ai discovery for %s: %s\n", outcome.Job.Account.User, boundedString(err.Error(), 512))
		}
	}
}

// writeEnterpriseHookAIDiscoveryRecord replaces <uid>.json atomically, with
// its final mode and group set before the rename so the gateway never sees
// a partial or unreadable record.
func writeEnterpriseHookAIDiscoveryRecord(dir string, account enterpriseHookWorkerAccount, report inventory.AIDiscoveryReport, now time.Time) error {
	data, err := json.Marshal(inventory.UserScanRecord{
		Version:   inventory.UserScanRecordVersion,
		UID:       account.UID,
		User:      account.User,
		UpdatedAt: now.UTC(),
		Report:    report,
	})
	if err != nil {
		return err
	}
	return writeEnterpriseHookAIDiscoverySpoolFile(dir, strconv.Itoa(account.UID)+".json", data)
}

func writeEnterpriseHookAIDiscoveryPass(dir string, pass inventory.UserScanPass) error {
	data, err := json.Marshal(pass)
	if err != nil {
		return err
	}
	return writeEnterpriseHookAIDiscoverySpoolFile(dir, inventory.UserScanPassName, data)
}

func writeEnterpriseHookAIDiscoverySpoolFile(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".scan-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = enterpriseHookAuthorizationOwnershipSetter(tmpName)
	}
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	return err
}
