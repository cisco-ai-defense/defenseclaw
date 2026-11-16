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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// enterpriseHookAIDiscoveryBreaker pauses the scans of an account whose
// worker failed three passes in a row (timed out, ended at its memory
// ceiling or crashed), so one home that cannot be scanned does not cost a
// worker on every pass (GAP-0694). The pause starts at an hour and doubles
// up to a day; the pass after a pause tries once, and a good scan closes the
// breaker. The account keeps its last record meanwhile, kept current and
// marked partial so the gateway does not age it out as removed (GAP-1224).
// The state belongs to the account that failed, not to its uid: an account
// that is given the uid later starts with none (GAP-1074).
var enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)

type enterpriseHookScanBreaker struct {
	mu        sync.Mutex
	threshold int
	base, max time.Duration
	accounts  map[int]*enterpriseHookScanBreakerState
}

type enterpriseHookScanBreakerState struct {
	// holder is the account the failures are of (enterpriseHookScanHolder).
	holder   string
	failures int
	pause    time.Duration
	until    time.Time
}

func newEnterpriseHookScanBreaker(threshold int, base, max time.Duration) *enterpriseHookScanBreaker {
	return &enterpriseHookScanBreaker{threshold: threshold, base: base, max: max, accounts: map[int]*enterpriseHookScanBreakerState{}}
}

// enterpriseHookScanHolder names the account that holds a row's uid: its
// name, home and home inode. A removed account's uid handed to a new one
// gives another holder.
func enterpriseHookScanHolder(row enterpriseHookReconcileRow) string {
	return fmt.Sprintf("%s\x00%s\x00%d", row.User, filepath.Clean(row.UserHome), row.HomeInode)
}

// enterpriseHookAIDiscoveryHolder is the holder a spool record names: a
// digest of the row's account name, as qualified as the host gives it, and
// home, then the home's inode. The record carries no path.
func enterpriseHookAIDiscoveryHolder(row enterpriseHookReconcileRow) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(row.User)) + "\x00" + filepath.Clean(row.UserHome)))
	return hex.EncodeToString(sum[:16]) + ":" + strconv.FormatUint(row.HomeInode, 10)
}

// enterpriseHookAIDiscoveryHolderMatches reports whether a record made for
// recorded is current's: the same name and home, and the same home inode
// unless one side could not read it (0).
func enterpriseHookAIDiscoveryHolderMatches(recorded, current string) bool {
	recordedID, recordedInode, ok := strings.Cut(recorded, ":")
	currentID, currentInode, currentOK := strings.Cut(current, ":")
	return ok && currentOK && recordedID == currentID &&
		(recordedInode == currentInode || recordedInode == "0" || currentInode == "0")
}

// allow reports whether the home of uid, held by holder, may be scanned at
// now. Another holder's pause is dropped.
func (b *enterpriseHookScanBreaker) allow(uid int, holder string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.accounts[uid]
	if state != nil && state.holder != holder {
		delete(b.accounts, uid)
		return true
	}
	return state == nil || !now.Before(state.until)
}

// record notes one scan of uid, held by holder, and returns the pause a
// failure opened, or 0.
func (b *enterpriseHookScanBreaker) record(uid int, holder string, now time.Time, failed bool) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !failed {
		delete(b.accounts, uid)
		return 0
	}
	state := b.accounts[uid]
	if state == nil || state.holder != holder {
		state = &enterpriseHookScanBreakerState{holder: holder}
		b.accounts[uid] = state
	}
	if state.failures++; state.failures < b.threshold {
		return 0
	}
	state.pause = min(max(state.pause*2, b.base), b.max)
	state.until = now.Add(state.pause)
	return state.pause
}

// keep forgets the accounts that are no longer enrolled, keyed by uid with
// the holder each uid is enrolled for now.
func (b *enterpriseHookScanBreaker) keep(enrolled map[int]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for uid, state := range b.accounts {
		if holder, ok := enrolled[uid]; !ok || holder != state.holder {
			delete(b.accounts, uid)
		}
	}
}

func init() {
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
		run.Rows = enterpriseHookEnrolledAccountRows(ctx, stderr, run)
		restoreEnterprisePolicyDirs(stderr)
		startEnterpriseHookAIDiscovery(ctx, stderr, run)
		startEnterpriseHookIdentitySpool(ctx, stderr, run)
	}
}

// restoreEnterprisePolicyDirs gives the vendor directories DefenseClaw
// publishes machine policy into back the mode every user's agent needs to
// read it (GAP-0913), and takes away the write of other accounts (GAP-0410). The guardian may write these directories: the
// lifecycle lists them in its sandbox.
func restoreEnterprisePolicyDirs(stderr io.Writer) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, "", "", cfg)
	if err != nil {
		return
	}
	restored, err := enterprisepolicy.RestorePublishedPolicyDirs(opts)
	if len(restored) > 0 {
		fmt.Fprintf(stderr, "[hook-guardian] restored the access of %s: users could not read DefenseClaw's machine policy there, or other accounts could change it\n", strings.Join(restored, ", "))
	}
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] machine policy directories: %v\n", err)
	}
}

// enterpriseHookManifestEnrollment reports a standalone deployment whose
// administrator publishes the targets (enterprise.enrollment.mode manifest).
// Its enumerator is idle, so the eligible-accounts record is what the last
// auto pass left, and only the accounts the manifest enrolls count
// (GAP-0761).
func enterpriseHookManifestEnrollment() bool {
	return cfg != nil && cfg.StandaloneEnterprise() &&
		strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest)
}

// enterpriseHookEnrolledAccountRows is the run's rows plus one row for each
// eligible account the enumerator published that has none. Rows exist only
// for per-user hook connectors: a deployment that selects only the
// machine-policy connectors (Claude Code, Codex) has none, and its enrolled
// accounts still need their identity records and per-user scans (GAP-0021).
// An eligible account the current exclude_users or exempt_users name gets
// none: eligible-accounts.json can be older than the settings and the
// manifest, when its write failed after the manifest's.
func enterpriseHookEnrolledAccountRows(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) []enterpriseHookReconcileRow {
	rows := append([]enterpriseHookReconcileRow(nil), run.Rows...)
	manifest := strings.TrimSpace(run.Manifest)
	if manifest == "" || enterpriseHookManifestEnrollment() {
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
	leftOut := enterpriseHookEnrollmentLeftOut(ctx, enterpriseHookIdentitySpoolDirForConfig())
	for _, account := range accounts {
		if account.UID <= 0 || seen[account.UID] || leftOut.has(account.UID, account.User) {
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
	enrolledUIDs := map[int]string{}
	recordHolders := map[int]string{}
	accounts := []enterpriseHookWorkerAccount{}
	resolver := enterprisehooks.StandaloneResolver()
	breaker := enterpriseHookAIDiscoveryBreaker
	for _, row := range rows {
		uid := strconv.Itoa(row.UID)
		if row.UID <= 0 || enrolled[uid+".json"] {
			continue
		}
		enrolled[uid+".json"] = true
		holder := enterpriseHookScanHolder(row)
		enrolledUIDs[row.UID] = holder
		recordHolders[row.UID] = enterpriseHookAIDiscoveryHolder(row)
		if row.Pending {
			keepEnterpriseHookAIDiscoveryRecord(stderr, dir, row.UID, row.User, recordHolders[row.UID], false, time.Now())
			continue
		}
		if !breaker.allow(row.UID, holder, time.Now()) {
			keepEnterpriseHookAIDiscoveryRecord(stderr, dir, row.UID, row.User, recordHolders[row.UID], true, time.Now())
			continue
		}
		account, err := resolver.LookupUID(row.UID)
		home := filepath.Clean(row.UserHome)
		if err != nil || account.UID != row.UID || (strings.TrimSpace(account.Home) != "" && filepath.Clean(account.Home) != home) ||
			enterpriseHookCheckHome(home, row.UID).State != enterprisehooks.HomeAvailable {
			keepEnterpriseHookAIDiscoveryRecord(stderr, dir, row.UID, row.User, recordHolders[row.UID], false, time.Now())
			continue
		}
		accounts = append(accounts, enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.Name, Home: home})
	}
	breaker.keep(enrolledUIDs)
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
		holder := enrolledUIDs[outcome.Job.Account.UID]
		if pause := breaker.record(outcome.Job.Account.UID, holder, time.Now(), err != nil); pause > 0 {
			fmt.Fprintf(stderr, "[hook-guardian] ai discovery for %s: the scan failed %d times in a row; the next scan of this home is in %s\n",
				outcome.Job.Account.User, breaker.threshold, pause)
		}
		recordHolder := recordHolders[outcome.Job.Account.UID]
		if err != nil {
			// A failed scan keeps the account's last record current, as a
			// pause does, so a failing home is not reported as emptied.
			keepEnterpriseHookAIDiscoveryRecord(stderr, dir, outcome.Job.Account.UID, outcome.Job.Account.User, recordHolder, true, time.Now())
		}
		if err == nil {
			report := *outcome.Response.AIDiscovery
			if err = inventory.SanitizeUserScanReport(&report, catalog, options.StoreRawLocalPaths, options.IncludeUserEmail); err == nil {
				err = writeEnterpriseHookAIDiscoveryRecord(dir, outcome.Job.Account, recordHolder, report, time.Now())
			}
			// A connector account file the scan could not use is named,
			// not silently left out (GAP-0961).
			for _, note := range sortedUserEmailNotes(report.Summary.DetectorNotes) {
				fmt.Fprintf(stderr, "[hook-guardian] ai discovery for %s: WARN include_user_email: %s\n", outcome.Job.Account.User, boundedString(note, 512))
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] ai discovery for %s: %s\n", outcome.Job.Account.User, boundedString(err.Error(), 512))
		}
	}
}

// enterpriseHookAIDiscoveryRecordReader reads a spool record with the
// gateway's checks; tests replace it.
var enterpriseHookAIDiscoveryRecordReader = inventory.ReadUserScanRecord

// enterpriseHookAIDiscoveryRetainedNote is the detector error a retained
// record carries: the inventory shown is the last good scan's.
const enterpriseHookAIDiscoveryRetainedNote = "the last scans of this home failed; showing the last complete scan until a scan succeeds"

// keepEnterpriseHookAIDiscoveryRecord checks the last record of uid, an
// enrolled account held by holder that this pass does not scan, or whose
// scan failed. A record that does not name holder goes: it was made for an
// account that held the uid before (a namesake from another domain
// included) or by a build that named none, and must not show that
// account's inventory as this one's. With refresh, the account's own
// record is kept current for the gateway, which otherwise drops it after
// three scan intervals and reports every item in it as removed while a
// pause lasts (GAP-1224): it keeps its report and is marked partial, naming
// why. An account with no record yet has nothing to keep.
func keepEnterpriseHookAIDiscoveryRecord(stderr io.Writer, dir string, uid int, user, holder string, refresh bool, now time.Time) {
	name := strconv.Itoa(uid) + ".json"
	path := filepath.Join(dir, name)
	record, err := enterpriseHookAIDiscoveryRecordReader(path)
	if errors.Is(err, os.ErrNotExist) || (err != nil && !refresh) {
		return
	}
	if err == nil && (record.UID != uid || !enterpriseHookAIDiscoveryHolderMatches(record.Holder, holder)) {
		if err = os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
	}
	if err == nil && !refresh {
		return
	}
	if err == nil {
		record.UpdatedAt = now.UTC()
		record.Report.Summary.Result = "partial"
		if record.Report.Summary.DetectorErrors == nil {
			record.Report.Summary.DetectorErrors = map[string]string{}
		}
		record.Report.Summary.DetectorErrors["user_scan"] = enterpriseHookAIDiscoveryRetainedNote
		var data []byte
		if data, err = json.Marshal(record); err == nil {
			err = writeEnterpriseHookAIDiscoverySpoolFile(dir, name, data)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] ai discovery for %s: could not update the last record: %s\n", user, boundedString(err.Error(), 512))
	}
}

// writeEnterpriseHookAIDiscoveryRecord replaces <uid>.json atomically, with
// its final mode and group set before the rename so the gateway never sees
// a partial or unreadable record.
func writeEnterpriseHookAIDiscoveryRecord(dir string, account enterpriseHookWorkerAccount, holder string, report inventory.AIDiscoveryReport, now time.Time) error {
	data, err := json.Marshal(inventory.UserScanRecord{
		Version:   inventory.UserScanRecordVersion,
		UID:       account.UID,
		User:      account.User,
		Holder:    holder,
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

// sortedUserEmailNotes are a per-user report's include_user_email notes in a
// stable order.
func sortedUserEmailNotes(notes map[string]string) []string {
	var out []string
	for name, note := range notes {
		if strings.HasPrefix(name, "user_email:") {
			out = append(out, note)
		}
	}
	sort.Strings(out)
	return out
}
