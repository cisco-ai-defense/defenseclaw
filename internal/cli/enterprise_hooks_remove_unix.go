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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The standalone Unix uninstall removes DefenseClaw's own per-user hook
// registrations before the binaries they name disappear. Each user's
// teardown runs in the per-user worker with that user's credentials; the
// connectors edit only DefenseClaw-owned entries, so the user's own hooks
// and settings stay. The eligible accounts are checked too, for per-user
// registrations of machine-policy connectors that no manifest row names
// any more (ones an earlier route left), and the guardian's pending per-user
// cleanups (targets the manifest stopped enrolling) are finished. With
// --purge (uninstall --purge) each enrolled user's worker then removes that
// user's DefenseClaw per-user state, once every removal for the user
// succeeded. Every account also loses DefenseClaw's VS Code Local hook
// file and Copilot plugin: both run the administrator's hook binary, and
// the Copilot CLI denies every tool call once that binary is gone.

var (
	enterpriseHooksRemoveAllManifest string
	enterpriseHooksRemoveAllPurge    bool
)

var enterpriseHooksRemoveAllCmd = &cobra.Command{
	Use:    "remove-all",
	Short:  "Internal: remove DefenseClaw's per-user hooks for every manifest target",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runEnterpriseHooksRemoveAll,
}

func init() {
	enterpriseHooksRemoveAllCmd.Flags().StringVar(&enterpriseHooksRemoveAllManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksRemoveAllCmd.Flags().BoolVar(&enterpriseHooksRemoveAllPurge, "purge", false,
		"Also remove each enrolled user's ~/.defenseclaw, per-user binaries in ~/.local/bin and DefenseClaw's entries in ~/.cache/uv, after stopping its per-user gateway")
	enterpriseHooksRemoveAllCmd.Flags().BoolVar(&enterpriseHookJSON, "json", false, "Emit machine-readable JSON")
	enterpriseHooksCmd.AddCommand(enterpriseHooksRemoveAllCmd)
}

// enterpriseHooksRemoveAllReport is the command's result.
type enterpriseHooksRemoveAllReport struct {
	OK      bool     `json:"ok"`
	Removed int      `json:"removed"`
	Pending []string `json:"pending,omitempty"`
	Failed  []string `json:"failed,omitempty"`
	// Purged names the users whose per-user state --purge removed, and
	// StateFailed ("user: reason") the ones whose state stayed.
	Purged      []string `json:"purged,omitempty"`
	StateFailed []string `json:"state_failed,omitempty"`
	// PurgedDetail is what the purge found and removed for each user in
	// Purged, so the uninstall names only that.
	PurgedDetail map[string]enterpriseHookPurgeDetail `json:"purged_detail,omitempty"`
}

func runEnterpriseHooksRemoveAll(cmd *cobra.Command, _ []string) error {
	report, err := removeAllEnterpriseHookTargets(cmd)
	if enterpriseHookJSON {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
	} else if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "removed %d per-user registrations; %d pending, %d failed\n", report.Removed, len(report.Pending), len(report.Failed))
		for _, user := range report.Purged {
			fmt.Fprintf(cmd.OutOrStdout(), "purged %s: ~/.defenseclaw and the per-user binaries in ~/.local/bin are gone\n", user)
		}
		for _, entry := range report.StateFailed {
			fmt.Fprintf(cmd.OutOrStdout(), "not purged %s\n", entry)
		}
	}
	if err != nil {
		return err
	}
	if !report.OK {
		return errors.New("enterprise hooks remove-all: some per-user registrations were not removed")
	}
	return nil
}

func removeAllEnterpriseHookTargets(cmd *cobra.Command) (enterpriseHooksRemoveAllReport, error) {
	report := enterpriseHooksRemoveAllReport{}
	if !enterpriseHooksStandaloneUnixActive() {
		return report, errors.New("enterprise hooks remove-all runs only for the standalone Unix profile")
	}
	if os.Geteuid() != 0 {
		return report, errors.New("enterprise hooks remove-all must run as root")
	}
	manifestPath := strings.TrimSpace(enterpriseHooksRemoveAllManifest)
	if err := enterpriseHookManifestFileTrustCheck(manifestPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.OK = true
			return report, nil
		}
		return report, fmt.Errorf("manifest trust check failed: %w", err)
	}
	manifest, _, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		return report, err
	}
	jobs, pending, failed := enterpriseHookRemoveJobs(manifest)
	report.Pending, report.Failed = pending, failed
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(manifestPath))
	if err != nil {
		report.Failed = append(report.Failed, "eligible accounts: "+boundedString(err.Error(), 256))
	}
	addEnterpriseHookLeftoverRemovals(jobs, manifest, accounts)
	// The VS Code Local files also go from the accounts the guardian wrote
	// them for that are no longer eligible.
	vscodeRecordPath, recorded, recordErr := loadEnterpriseHookCopilotVSCodeAccounts(manifestPath)
	if recordErr != nil {
		report.Failed = append(report.Failed, "copilot vscode accounts record: "+boundedString(recordErr.Error(), 256))
	}
	vscodeAccounts := append(append([]enterprisehooks.UnixEligibleAccount{}, accounts...), staleCopilotVSCodeAccounts(recorded, accounts)...)
	if vscode, err := enterpriseHookCopilotVSCodeRemoval(); err != nil {
		report.Failed = append(report.Failed, "copilot vscode hooks: "+boundedString(err.Error(), 256))
	} else {
		addEnterpriseHookCopilotVSCodeRemovals(jobs, vscodeAccounts, vscode, copilotVSCodeCreatedDirs(recorded))
	}
	cleanupFailed := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if enterpriseHooksRemoveAllPurge {
		report.StateFailed = append(report.StateFailed, addEnterpriseHookStatePurges(jobs, manifest, accounts, cleanupFailed)...)
	}
	for _, run := range runEnterpriseHookWorkerPool(cmd.Context(), sortedWorkerJobs(jobs), enterpriseHookWorkerParallelism) {
		answered := map[int]enterpriseHookWorkerTargetResult{}
		for _, result := range run.Response.Targets {
			answered[result.Index] = result
		}
		for _, target := range run.Job.Request.Targets {
			label := run.Job.Account.User + "/" + target.Options.ConnectorName
			result, ok := answered[target.Index]
			if target.Mode == enterpriseHookWorkerModePurge {
				switch {
				case ok && result.OK:
					report.Purged = append(report.Purged, run.Job.Account.User)
					if result.Purged != nil {
						if report.PurgedDetail == nil {
							report.PurgedDetail = map[string]enterpriseHookPurgeDetail{}
						}
						report.PurgedDetail[run.Job.Account.User] = *result.Purged
					}
				case ok && result.Pending:
					report.StateFailed = append(report.StateFailed, run.Job.Account.User+": the home is not available")
				case ok:
					report.StateFailed = append(report.StateFailed, run.Job.Account.User+": "+boundedWorkerError(result.Error))
				case run.Err != nil:
					report.StateFailed = append(report.StateFailed, run.Job.Account.User+": "+boundedWorkerError(run.Err.Error()))
				default:
					report.StateFailed = append(report.StateFailed, run.Job.Account.User+": the worker did not answer")
				}
				continue
			}
			switch {
			case !ok && run.Err != nil:
				report.Failed = append(report.Failed, label+": "+boundedWorkerError(run.Err.Error()))
			case !ok:
				report.Failed = append(report.Failed, label+": the worker did not answer")
			case result.Pending:
				report.Pending = append(report.Pending, label)
			case !result.OK:
				report.Failed = append(report.Failed, label+": "+boundedWorkerError(result.Error))
			case target.Mode == enterpriseHookWorkerModeRemoveLeftover && !result.Removed:
				// Nothing of DefenseClaw's was registered there.
			default:
				report.Removed++
			}
		}
		if vscode := run.Response.CopilotVSCode; vscode != nil {
			report.Removed += len(vscode.Removed)
			if vscode.Error != "" {
				report.Failed = append(report.Failed, run.Job.Account.User+"/copilot: "+boundedWorkerError(vscode.Error))
			}
		} else if run.Job.Request.CopilotVSCode != nil && run.Err != nil && len(run.Job.Request.Targets) == 0 {
			report.Failed = append(report.Failed, run.Job.Account.User+"/copilot: "+boundedWorkerError(run.Err.Error()))
		}
	}
	sort.Strings(report.Pending)
	sort.Strings(report.Failed)
	sort.Strings(report.Purged)
	sort.Strings(report.StateFailed)
	report.OK = len(report.Failed) == 0
	if report.OK && len(report.Pending) == 0 && recordErr == nil {
		if err := removeEnterpriseHookCopilotVSCodeAccounts(vscodeRecordPath, manifestPath); err != nil {
			report.Failed = append(report.Failed, "copilot vscode accounts record: "+boundedString(err.Error(), 256))
			report.OK = false
		}
	}
	return report, nil
}

// newEnterpriseHookRemoveJob is one account's worker job; its targets are
// added by the callers.
func newEnterpriseHookRemoveJob(account enterpriseHookWorkerAccount) *enterpriseHookWorkerJob {
	return &enterpriseHookWorkerJob{
		Account: account,
		Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true},
	}
}

// enterpriseHookRemoveJobs groups the manifest targets into one worker job
// per account. Rows without a usable uid or with an unavailable home are
// reported instead of guessed at.
func enterpriseHookRemoveJobs(manifest enterprisehooks.Manifest) (map[int]*enterpriseHookWorkerJob, []string, []string) {
	jobs := map[int]*enterpriseHookWorkerJob{}
	var pending, failed []string
	index := 0
	for _, target := range manifest.Targets {
		user := strings.TrimSpace(target.User)
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		label := user + "/" + name
		if target.UID == nil || target.GID == nil || *target.UID <= 0 || !filepath.IsAbs(home) || name == "" {
			failed = append(failed, label+": the manifest row has no usable uid, gid or home")
			continue
		}
		uid, gid := *target.UID, *target.GID
		switch enterpriseHookCheckHome(home, uid).State {
		case enterprisehooks.HomeAvailable:
		case enterprisehooks.HomePending:
			pending = append(pending, label)
			continue
		default:
			failed = append(failed, label+": the home is not trusted")
			continue
		}
		job := jobs[uid]
		if job == nil {
			job = newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: uid, GID: gid, User: user, Home: home})
			jobs[uid] = job
		}
		if job.Account.Home != home || job.Account.GID != gid {
			failed = append(failed, label+": the uid has rows with different homes")
			continue
		}
		dataDir := strings.TrimSpace(target.DataDir)
		if dataDir == "" {
			dataDir = filepath.Join(home, ".defenseclaw")
		}
		job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
			Index: index,
			Mode:  enterpriseHookWorkerModeRemove,
			Options: enterpriseHookWorkerOptions{
				ConnectorName: name,
				UserHome:      home,
				OwnerUID:      uid,
				OwnerGID:      gid,
				DataDir:       dataDir,
				AgentVersion:  strings.TrimSpace(target.AgentVersion),
			},
		})
		index++
	}
	return jobs, pending, failed
}

// addEnterpriseHookLeftoverRemovals adds to jobs, for every eligible
// account with an available home, the removal of the guardian's per-user
// registration of each machine-policy connector that no manifest row names
// for that user. The worker changes nothing where the user's hook contract
// lock records no such registration.
func addEnterpriseHookLeftoverRemovals(jobs map[int]*enterpriseHookWorkerJob, manifest enterprisehooks.Manifest, accounts []enterprisehooks.UnixEligibleAccount) {
	named := enterpriseHookPerUserEnrolled(manifest, nil)
	index := len(manifest.Targets)
	for _, account := range accounts {
		home := filepath.Clean(account.Home)
		var leftovers []string
		for _, name := range enterprisepolicy.VendorMachinePolicyConnectors(runtime.GOOS) {
			if !named[account.User][name] {
				leftovers = append(leftovers, name)
			}
		}
		if len(leftovers) == 0 || account.UID <= 0 || enterpriseHookCheckHome(home, account.UID).State != enterprisehooks.HomeAvailable {
			continue
		}
		job := jobs[account.UID]
		if job == nil {
			job = newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: home})
			jobs[account.UID] = job
		}
		if job.Account.Home != home || job.Account.GID != account.GID {
			continue
		}
		for _, name := range leftovers {
			job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
				Index: index,
				Mode:  enterpriseHookWorkerModeRemoveLeftover,
				Options: enterpriseHookWorkerOptions{
					ConnectorName: name,
					UserHome:      job.Account.Home,
					OwnerUID:      account.UID,
					OwnerGID:      account.GID,
					DataDir:       filepath.Join(job.Account.Home, ".defenseclaw"),
				},
			})
			index++
		}
	}
}

// enterpriseHookCopilotVSCodeRemoval is the worker request that removes
// DefenseClaw's VS Code Local hook file and Copilot plugin, recognized by
// the administrator's hook binary.
func enterpriseHookCopilotVSCodeRemoval() (*enterpriseHookWorkerCopilotVSCode, error) {
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return nil, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.HookBinary) == "" {
		return nil, errors.New("the hook binary is not configured")
	}
	return &enterpriseHookWorkerCopilotVSCode{HookBinary: opts.HookBinary}, nil
}

// addEnterpriseHookCopilotVSCodeRemovals asks the worker of every account
// in jobs, and of every eligible account with an available home, to remove
// DefenseClaw's VS Code Local hook file and Copilot plugin. They are
// rendered for eligible accounts whether or not a manifest row names them,
// and only DefenseClaw's exact renders are removed.
func addEnterpriseHookCopilotVSCodeRemovals(jobs map[int]*enterpriseHookWorkerJob, accounts []enterprisehooks.UnixEligibleAccount, vscode *enterpriseHookWorkerCopilotVSCode, createdDirs map[int][]string) {
	if vscode == nil {
		return
	}
	for _, account := range accounts {
		home := filepath.Clean(account.Home)
		if account.UID <= 0 || jobs[account.UID] != nil || enterpriseHookCheckHome(home, account.UID).State != enterprisehooks.HomeAvailable {
			continue
		}
		jobs[account.UID] = &enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: home},
			Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true},
		}
	}
	for uid, job := range jobs {
		removal := *vscode
		removal.HookFile, removal.Plugin = false, false
		removal.RemoveDirs = createdDirs[uid]
		job.Request.CopilotVSCode = &removal
	}
}

// runEnterpriseHookPendingCleanups finishes the guardian's pending per-user
// cleanups (registrations of targets the manifest no longer enrolls, which
// the guardian retries while it runs; the uninstall stopped it), as each
// user, and returns the uids whose cleanup failed.
func runEnterpriseHookPendingCleanups(cmd *cobra.Command, report *enterpriseHooksRemoveAllReport, jobs map[int]*enterpriseHookWorkerJob) map[int]bool {
	failed := map[int]bool{}
	if cfg == nil {
		return failed
	}
	pending, err := loadEnterpriseHookUserCleanups(cfg.DataDir)
	if err != nil {
		report.Failed = append(report.Failed, "pending per-user cleanups: "+boundedString(err.Error(), 256))
		return failed
	}
	resolver := enterprisehooks.StandaloneResolver()
	for _, entry := range pending {
		name := strings.ToLower(strings.TrimSpace(entry.Connector))
		if job := jobs[entry.UID]; job != nil && enterpriseHookJobRemoves(job, name) {
			continue // a manifest row still names it
		}
		label := strings.TrimSpace(entry.User) + "/" + name
		outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(cmd.Context(), enterpriseHookWorkerLog, entry, resolver)
		switch outcome {
		case enterpriseHookUserCleanupDone:
			report.Removed++
		case enterpriseHookUserCleanupPending:
			report.Pending = append(report.Pending, label)
		default:
			reason := "the cleanup failed"
			if err != nil {
				reason = boundedString(err.Error(), 256)
			}
			report.Failed = append(report.Failed, label+": "+reason)
			failed[entry.UID] = true
		}
	}
	return failed
}

// enterpriseHookJobRemoves reports whether job already removes connector.
func enterpriseHookJobRemoves(job *enterpriseHookWorkerJob, connector string) bool {
	for _, target := range job.Request.Targets {
		if target.Mode == enterpriseHookWorkerModeRemove && target.Options.ConnectorName == connector {
			return true
		}
	}
	return false
}

// addEnterpriseHookStatePurges ends the job of every account the manifest
// enrolls with the purge of that account's DefenseClaw per-user state (each
// data directory its rows name) and per-user binaries, except for the
// accounts in skip, whose pending cleanup failed and whose backups a retry
// still needs. Eligible accounts without a manifest row are not proof of
// managed enrollment. It returns every enrolled account it did not add a purge
// for, as "user: reason", so the report names each account whose data stays.
func addEnterpriseHookStatePurges(jobs map[int]*enterpriseHookWorkerJob, manifest enterprisehooks.Manifest, _ []enterprisehooks.UnixEligibleAccount, skip map[int]bool) []string {
	dataDirs := map[int][]string{}
	notPurged := map[string]string{}
	for _, target := range manifest.Targets {
		user := strings.TrimSpace(target.User)
		if target.UID == nil || *target.UID <= 0 {
			notPurged[user] = "its manifest row has no usable uid"
			continue
		}
		job := jobs[*target.UID]
		if job == nil {
			reason := "its home is not trusted"
			home := filepath.Clean(strings.TrimSpace(target.UserHome))
			if filepath.IsAbs(home) && enterpriseHookCheckHome(home, *target.UID).State == enterprisehooks.HomePending {
				reason = "its home is not available; rerun the purge when it is"
			}
			notPurged[user] = reason
			continue
		}
		if skip[*target.UID] {
			notPurged[job.Account.User] = "its pending hook cleanup failed; the state stays for a retry"
			continue
		}
		dataDir := strings.TrimSpace(target.DataDir)
		if dataDir == "" {
			dataDir = filepath.Join(job.Account.Home, ".defenseclaw")
		}
		if !slices.Contains(dataDirs[*target.UID], dataDir) {
			dataDirs[*target.UID] = append(dataDirs[*target.UID], dataDir)
		}
	}
	index := 0
	for _, job := range jobs {
		for _, target := range job.Request.Targets {
			index = max(index, target.Index+1)
		}
	}
	for uid, dirs := range dataDirs {
		if skip[uid] {
			continue
		}
		job := jobs[uid]
		for _, dataDir := range dirs {
			job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
				Index: index,
				Mode:  enterpriseHookWorkerModePurge,
				Options: enterpriseHookWorkerOptions{
					UserHome: job.Account.Home,
					OwnerUID: job.Account.UID,
					OwnerGID: job.Account.GID,
					DataDir:  dataDir,
				},
			})
			index++
		}
	}
	for uid := range dataDirs {
		delete(notPurged, jobs[uid].Account.User)
	}
	var out []string
	for user, reason := range notPurged {
		out = append(out, user+": "+reason)
	}
	sort.Strings(out)
	return out
}

// workerErrorMaxBytes bounds one worker error in the remove-all report.
const workerErrorMaxBytes = 512

// boundedWorkerError bounds a worker's error for the report. A wrapped error
// ends with its cause (the OS error), so an oversized one keeps its start and
// its end, cut at rune boundaries, instead of stopping in the middle of a
// path before the cause.
func boundedWorkerError(value string) string {
	value = boundedString(value, len(value))
	if len(value) <= workerErrorMaxBytes {
		return value
	}
	const gap = " ... "
	head := (workerErrorMaxBytes - len(gap)) / 3
	tail := len(value) - (workerErrorMaxBytes - len(gap) - head)
	for head > 0 && !utf8.RuneStart(value[head]) {
		head--
	}
	for tail < len(value) && !utf8.RuneStart(value[tail]) {
		tail++
	}
	return value[:head] + gap + value[tail:]
}
