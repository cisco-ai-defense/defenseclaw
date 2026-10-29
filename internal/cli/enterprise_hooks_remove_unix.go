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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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
	enterpriseHooksRemoveAllCheck    bool
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
		"Also remove each enrolled user's ~/.defenseclaw, per-user binaries in ~/.local/bin and DefenseClaw's entries in ~/.cache/uv, after stopping its per-user gateway; an account's own per-user install from before the enrollment is kept as it is")
	enterpriseHooksRemoveAllCmd.Flags().BoolVar(&enterpriseHooksRemoveAllCheck, "check", false,
		"Only check that every manifest row resolves to an account whose registrations can be removed; change nothing")
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
	// ClaudeHookUnblocked names the users whose Claude Code blocker (the
	// enrollment wrote it over the account's own hook script) was removed:
	// their own Claude Code hook needs `defenseclaw setup claude-code`
	// again (GAP-1828).
	ClaudeHookUnblocked []string `json:"claude_hook_unblocked,omitempty"`
}

// enterpriseHookClaudeUnblockedNote is what the uninstall says about an
// account whose Claude Code blocker it removed.
const enterpriseHookClaudeUnblockedNote = "its Claude Code hook script (~/.defenseclaw/hooks/claude-code-hook.sh), which the enrollment had replaced, was removed, so its own Claude Code hook reports a missing script and does not guard Claude Code; run `defenseclaw setup claude-code` as that user to restore it"

const (
	enterpriseHookPurgeSkipFailed           = "its pending hook cleanup failed; the state stays for a retry"
	enterpriseHookPurgeSkipKeptHome         = "its recorded home may still hold a hook registration; the state stays while cleanup is unresolved"
	enterpriseHookPurgeSkipPending          = "its hook cleanup is still pending; the state stays until it finishes"
	enterpriseHookPurgeSkipUnreadableLedger = "the pending cleanup ledger could not be read; the state stays until it can be checked"
	enterpriseHookPurgeSkipRehomed          = "the account was re-homed after the manifest named it, so the purge does not pick a home; its state stays in the recorded and the current home: remove ~/.defenseclaw in each by hand once its hooks are gone"
)

func runEnterpriseHooksRemoveAll(cmd *cobra.Command, _ []string) error {
	report, err := removeAllEnterpriseHookTargets(cmd)
	if enterpriseHookJSON {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
	} else if err == nil && enterpriseHooksRemoveAllCheck {
		for _, entry := range report.Failed {
			fmt.Fprintf(cmd.OutOrStdout(), "cannot remove %s\n", entry)
		}
	} else if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "removed %d per-user registrations; %d pending, %d failed\n", report.Removed, len(report.Pending), len(report.Failed))
		for _, user := range report.Purged {
			line := "purged " + user + ": ~/.defenseclaw and the per-user binaries in ~/.local/bin are gone"
			if report.PurgedDetail[user].Kept {
				line = "kept " + user + ": ~/.defenseclaw holds its own DefenseClaw install from before the managed deployment, which stays as it is"
			}
			fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		for _, entry := range report.StateFailed {
			fmt.Fprintf(cmd.OutOrStdout(), "not purged %s\n", entry)
		}
		for _, user := range report.ClaudeHookUnblocked {
			fmt.Fprintf(cmd.OutOrStdout(), "unblocked %s: %s\n", user, enterpriseHookClaudeUnblockedNote)
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
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pending, failed := enterpriseHookRemoveJobs(rows)
	report.Pending, report.Failed = pending, failed
	if enterpriseHooksRemoveAllCheck {
		// uninstall asks before it stops a service or removes the machine
		// policy, so a row it cannot resolve leaves the deployment intact
		// (GAP-1101). The guardian's pending cleanups are checked too
		// (GAP-2377).
		checkEnterpriseHookPendingCleanups(&report, jobs, enterprisehooks.StandaloneResolver(), enterpriseHookRehomedRowCleanups(rows)...)
		sort.Strings(report.Pending)
		sort.Strings(report.Failed)
		report.OK = len(report.Failed) == 0
		return report, nil
	}
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
	addEnterpriseHookPersonalClaudeUnblocks(jobs, vscodeAccounts)
	purgeSkip := runEnterpriseHookPendingCleanups(cmd, &report, jobs, enterpriseHookRehomedRowCleanups(rows)...)
	if enterpriseHooksRemoveAllPurge {
		report.StateFailed = append(report.StateFailed, addEnterpriseHookStatePurges(jobs, rows, purgeSkip)...)
	}
	runs := retryTimedOutWorkers(cmd.Context(), runEnterpriseHookWorkerPool(cmd.Context(), sortedWorkerJobs(jobs), enterpriseHookWorkerParallelism))
	addEnterpriseHookRemoveRuns(&report, runs)
	sort.Strings(report.Pending)
	sort.Strings(report.Failed)
	sort.Strings(report.Purged)
	sort.Strings(report.StateFailed)
	sort.Strings(report.ClaudeHookUnblocked)
	report.OK = len(report.Failed) == 0
	if report.OK && len(report.Pending) == 0 && recordErr == nil {
		if err := removeEnterpriseHookCopilotVSCodeAccounts(vscodeRecordPath, manifestPath); err != nil {
			report.Failed = append(report.Failed, "copilot vscode accounts record: "+boundedString(err.Error(), 256))
			report.OK = false
		}
	}
	return report, nil
}

// addEnterpriseHookRemoveRuns adds the per-user workers' answers of a
// remove-all to its report.
func addEnterpriseHookRemoveRuns(report *enterpriseHooksRemoveAllReport, runs []enterpriseHookWorkerOutcome) {
	for _, run := range runs {
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
			case !ok && run.Err != nil && target.Mode == enterpriseHookWorkerModeUnblockPersonalClaude && run.Job.Request.CopilotVSCode != nil:
				// The worker of a job for the VS Code Local files ended
				// without an answer: the copilot entry below names it, not
				// claudecode (GAP-1830).
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
			case target.Mode == enterpriseHookWorkerModeUnblockPersonalClaude && !result.Removed:
				// The enrollment wrote no Claude Code blocker there.
			case target.Mode == enterpriseHookWorkerModeUnblockPersonalClaude:
				report.Removed++
				report.ClaudeHookUnblocked = append(report.ClaudeHookUnblocked, run.Job.Account.User)
			case target.Mode == enterpriseHookWorkerModeRemove && result.Remaining != "":
				// The teardown ran, but the agent still loads a DefenseClaw
				// entry (a copied home's plugin, say): not removed (GAP-0632).
				report.Failed = append(report.Failed, label+": DefenseClaw entries remain after the removal ("+boundedWorkerError(result.Remaining)+
					"); remove them from that agent's config and rerun")
			default:
				report.Removed++
			}
		}
		if vscode := run.Response.CopilotVSCode; vscode != nil {
			report.Removed += len(vscode.Removed)
			if vscode.Error != "" {
				report.Failed = append(report.Failed, run.Job.Account.User+"/copilot: "+boundedWorkerError(vscode.Error))
			}
		} else if run.Job.Request.CopilotVSCode != nil && run.Err != nil {
			report.Failed = append(report.Failed, run.Job.Account.User+"/copilot: "+boundedWorkerError(run.Err.Error()))
		}
	}
}

// newEnterpriseHookRemoveJob is one account's worker job; its targets are
// added by the callers.
func newEnterpriseHookRemoveJob(account enterpriseHookWorkerAccount) *enterpriseHookWorkerJob {
	return &enterpriseHookWorkerJob{
		Account: account,
		Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true},
	}
}

// enterpriseHookRemoveRow is one manifest row and the account it resolved
// to. A row that names only a user, a uid or a user_home, as enrollment.mdx
// documents, gets its uid, gid and home from the directory exactly as
// reconcile resolves it; uninstall required them in the row and stopped
// halfway on such a manifest (GAP-1101). A row with all three keeps them, so
// it is removed while the directory does not answer. problem says why a row
// did not resolve. rehomed is the home the directory now gives the account
// of such a row when that is another real home of the same account (a copied
// or moved home): its removal then runs as a re-homed cleanup, which must
// find both homes clean (GAP-0073).
type enterpriseHookRemoveRow struct {
	target  enterprisehooks.ManifestTarget
	who     string
	problem string
	// gone is a row that names only a home, which no longer exists: its
	// registrations went with the home, and no account is left to act as
	// (#1287).
	gone    bool
	rehomed string
}

func resolveEnterpriseHookRemoveRows(manifest enterprisehooks.Manifest) []enterpriseHookRemoveRow {
	resolver := enterprisehooks.StandaloneResolver()
	rows := make([]enterpriseHookRemoveRow, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		user, home := strings.TrimSpace(target.User), strings.TrimSpace(target.UserHome)
		row := enterpriseHookRemoveRow{target: target, who: firstNonEmpty(user, home)}
		if row.who == "" && target.UID != nil {
			row.who = "uid " + strconv.Itoa(*target.UID)
		}
		if target.UID != nil && target.GID != nil && *target.UID > 0 && filepath.IsAbs(filepath.Clean(home)) {
			if current, name := enterpriseHookRemoveRowDirectoryHome(target, resolver); current != "" {
				row.rehomed, row.target.User, row.who = current, name, name
			}
			rows = append(rows, row)
			continue
		}
		account, pendingReason, err := resolveEnterpriseHookStandaloneAccount(target, resolver)
		switch {
		case err != nil:
			row.problem = strings.TrimPrefix(err.Error(), "enterprise hooks: ")
		case pendingReason != "" && user == "" && target.UID == nil && enterpriseHookRecordedHomeGone(home):
			row.gone = true
		case pendingReason != "":
			row.problem = pendingReason + "; rerun once it is available"
		default:
			uid, gid := account.UID, account.GID
			row.target.UID, row.target.GID = &uid, &gid
			row.target.User, row.target.UserHome = account.User, account.Home
			row.who = account.User
		}
		rows = append(rows, row)
	}
	return rows
}

// enterpriseHookHomeGoneEntry is the pending entry of a manifest row whose
// home no longer exists: nothing is left to remove, and the uninstall warns
// with this reason and goes on.
func enterpriseHookHomeGoneEntry(label, home, connector string) string {
	return fmt.Sprintf("%s: its home %s no longer exists, so no DefenseClaw hook registration is left there; if that home is restored, remove DefenseClaw's entries from the %s config in it", label, home, connector)
}

// enterpriseHookRemoveRowDirectoryHome returns the home the directory now
// gives the account of a row that names its own uid, gid and home, and the
// account's name, when that home is another real home of the same account.
// The published home stays the target while the directory does not answer,
// gives no home, or gives the uid to another name.
func enterpriseHookRemoveRowDirectoryHome(target enterprisehooks.ManifestTarget, resolver unixidentity.Resolver) (string, string) {
	account, err := resolver.LookupUID(*target.UID)
	if err != nil || account.UID != *target.UID || strings.TrimSpace(account.Name) == "" || enterpriseHookDirectoryNoHome(account.Home) {
		return "", ""
	}
	if name := strings.TrimSpace(target.User); name != "" && name != account.Name {
		return "", ""
	}
	current := filepath.Clean(strings.TrimSpace(account.Home))
	if current == filepath.Clean(strings.TrimSpace(target.UserHome)) {
		return "", ""
	}
	return current, account.Name
}

// enterpriseHookRehomedRowCleanups is the re-homed cleanup of each manifest
// row whose account the directory now gives another home. A Remove in the
// recorded home alone found nothing there and counted the row removed while
// the copied current home still loaded the plugin (GAP-0073).
func enterpriseHookRehomedRowCleanups(rows []enterpriseHookRemoveRow) []enterpriseHookUserCleanup {
	var out []enterpriseHookUserCleanup
	for _, row := range rows {
		target := row.target
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		if row.rehomed == "" || row.problem != "" || name == "" {
			continue
		}
		out = append(out, enterpriseHookUserCleanup{
			Connector: name,
			UID:       *target.UID,
			User:      strings.TrimSpace(target.User),
			UserHome:  filepath.Clean(strings.TrimSpace(target.UserHome)),
			DataDir:   strings.TrimSpace(target.DataDir),
		})
	}
	return out
}

// enterpriseHookRemoveJobs groups the manifest rows into one worker job per
// account. Rows that did not resolve or whose home is unavailable are
// reported, as "who/connector: reason", instead of guessed at.
func enterpriseHookRemoveJobs(rows []enterpriseHookRemoveRow) (map[int]*enterpriseHookWorkerJob, []string, []string) {
	jobs := map[int]*enterpriseHookWorkerJob{}
	var pending, failed []string
	index := 0
	for _, row := range rows {
		target := row.target
		user := strings.TrimSpace(target.User)
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		label := row.who + "/" + name
		switch {
		case row.gone:
			pending = append(pending, enterpriseHookHomeGoneEntry(label, home, name))
			continue
		case row.problem != "":
			failed = append(failed, label+": "+row.problem)
			continue
		case target.UID == nil || target.GID == nil || *target.UID <= 0 || !filepath.IsAbs(home) || name == "":
			failed = append(failed, label+": the manifest row has no usable uid, gid, home or connector")
			continue
		}
		if row.rehomed != "" {
			continue // enterpriseHookRehomedRowCleanups removes it, in both homes
		}
		uid, gid := *target.UID, *target.GID
		switch enterpriseHookCheckHome(home, uid).State {
		case enterprisehooks.HomeAvailable:
		case enterprisehooks.HomePending:
			if enterpriseHookLiveHomeGone(home, uid) {
				// The home folder of a live account was deleted (#1287):
				// the registrations went with it, so the account is
				// already clean. The uninstall warns with this reason and
				// goes on. A home moved aside next to it is only not
				// available (GAP-2482).
				pending = append(pending, enterpriseHookHomeGoneEntry(label, home, name))
				continue
			}
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

// addEnterpriseHookPersonalClaudeUnblocks asks the worker of every account
// in jobs, and of every eligible account with an available home, to remove
// the Claude Code blocker the enrollment wrote over the account's own hook
// script (rel-1-0-4 RB1-1). It runs after the account's removals and before
// its purge, whatever the manifest names: the blocker is written for every
// eligible account while the machine policy covers Claude Code.
func addEnterpriseHookPersonalClaudeUnblocks(jobs map[int]*enterpriseHookWorkerJob, accounts []enterprisehooks.UnixEligibleAccount) {
	for _, account := range accounts {
		home := filepath.Clean(account.Home)
		if jobs[account.UID] != nil || account.UID <= 0 || enterpriseHookCheckHome(home, account.UID).State != enterprisehooks.HomeAvailable {
			continue
		}
		jobs[account.UID] = newEnterpriseHookRemoveJob(enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: home})
	}
	index := 0
	for _, job := range jobs {
		for _, target := range job.Request.Targets {
			index = max(index, target.Index+1)
		}
	}
	for _, job := range jobs {
		job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
			Index: index,
			Mode:  enterpriseHookWorkerModeUnblockPersonalClaude,
			Options: enterpriseHookWorkerOptions{
				ConnectorName: "claudecode",
				UserHome:      job.Account.Home,
				OwnerUID:      job.Account.UID,
				OwnerGID:      job.Account.GID,
				DataDir:       filepath.Join(job.Account.Home, ".defenseclaw"),
			},
		})
		index++
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
// user, and returns the uids whose state must not be purged, each with the
// reason the purge report gives: cleanup failed, the recorded home of an
// account that looks removed was kept, or cleanup is still pending (the
// strongest reason wins when an account has several). An unreadable cleanup
// ledger blocks the purge of every worker job's account. A cleanup of a
// removed account is reported pending as "user/connector: reason", so the
// uninstall warns and goes on. rehomed are the cleanups of the manifest rows
// whose account was re-homed (enterpriseHookRehomedRowCleanups). They run
// like a pending cleanup, once even when the ledger holds the same one, and
// keep the account's state from the purge.
func runEnterpriseHookPendingCleanups(cmd *cobra.Command, report *enterpriseHooksRemoveAllReport, jobs map[int]*enterpriseHookWorkerJob, rehomed ...enterpriseHookUserCleanup) map[int]string {
	return runEnterpriseHookPendingCleanupsWith(cmd, report, jobs, enterprisehooks.StandaloneResolver(), rehomed...)
}

func runEnterpriseHookPendingCleanupsWith(cmd *cobra.Command, report *enterpriseHooksRemoveAllReport, jobs map[int]*enterpriseHookWorkerJob, resolver unixidentity.Resolver, rehomed ...enterpriseHookUserCleanup) map[int]string {
	skip := map[int]string{}
	var pending []enterpriseHookUserCleanup
	if cfg != nil {
		loaded, err := loadEnterpriseHookUserCleanups(cfg.DataDir)
		if err != nil {
			report.Failed = append(report.Failed, "pending per-user cleanups: "+boundedString(err.Error(), 256))
			for uid := range jobs {
				skip[uid] = enterpriseHookPurgeSkipUnreadableLedger
			}
		} else {
			pending = loaded
		}
	}
	key := func(entry enterpriseHookUserCleanup) string {
		return fmt.Sprintf("%d\x00%s\x00%s", entry.UID, strings.ToLower(strings.TrimSpace(entry.Connector)), filepath.Clean(strings.TrimSpace(entry.UserHome)))
	}
	ran := map[string]bool{}
	finished := map[string]bool{}
	for _, entry := range pending {
		name := strings.ToLower(strings.TrimSpace(entry.Connector))
		if enterpriseHookPendingCleanupCoveredByJob(jobs[entry.UID], name, entry, resolver) {
			continue // a manifest row still names it, in the same home
		}
		ran[key(entry)] = true
		if finishEnterpriseHookRemoveAllCleanup(cmd, report, skip, entry, resolver) {
			finished[key(entry)] = true
		}
	}
	for _, entry := range rehomed {
		if !ran[key(entry)] {
			ran[key(entry)] = true
			if finishEnterpriseHookRemoveAllCleanup(cmd, report, skip, entry, resolver) {
				finished[key(entry)] = true
			}
		}
		if skip[entry.UID] == "" {
			skip[entry.UID] = enterpriseHookPurgeSkipRehomed
		}
	}
	if len(finished) != 0 && cfg != nil {
		if err := dropEnterpriseHookFinishedCleanups(cmd.Context(), finished, key); err != nil {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: the finished per-user cleanups stay in the guardian's ledger until its next pass: %v\n", err)
		}
	}
	return skip
}

// checkEnterpriseHookPendingCleanups is the --check side of
// runEnterpriseHookPendingCleanupsWith: it reads the guardian's pending
// cleanups (and the cleanups of re-homed manifest rows) and reports, without
// running a worker, each one the real remove-all would leave pending or
// failed. Without it a pending cleanup of an account the manifest no longer
// names, whose home is not available, passed the uninstall precheck; the
// real run then stopped on it after the services had stopped, the machine
// policy had gone and the other users' Claude Code blockers had been
// removed (GAP-2377). A cleanup the worker would run is left to the real run.
func checkEnterpriseHookPendingCleanups(report *enterpriseHooksRemoveAllReport, jobs map[int]*enterpriseHookWorkerJob, resolver unixidentity.Resolver, rehomed ...enterpriseHookUserCleanup) {
	var pending []enterpriseHookUserCleanup
	if cfg != nil {
		loaded, err := loadEnterpriseHookUserCleanups(cfg.DataDir)
		if err != nil {
			report.Failed = append(report.Failed, "pending per-user cleanups: "+boundedString(err.Error(), 256))
		} else {
			pending = loaded
		}
	}
	key := func(entry enterpriseHookUserCleanup) string {
		return fmt.Sprintf("%d\x00%s\x00%s", entry.UID, strings.ToLower(strings.TrimSpace(entry.Connector)), filepath.Clean(strings.TrimSpace(entry.UserHome)))
	}
	seen := map[string]bool{}
	skip := map[int]string{}
	check := func(entry enterpriseHookUserCleanup) {
		if seen[key(entry)] {
			return
		}
		seen[key(entry)] = true
		account, _, outcome, err := planEnterpriseHookStandaloneUnixCleanup(context.Background(), io.Discard, entry, resolver)
		if account != nil || (outcome == enterpriseHookUserCleanupDone && err == nil) {
			return // the worker runs it, or nothing is left to remove
		}
		addEnterpriseHookRemoveAllCleanupOutcome(report, skip, entry, outcome, err)
	}
	for _, entry := range pending {
		if !enterpriseHookPendingCleanupCoveredByJob(jobs[entry.UID], strings.ToLower(strings.TrimSpace(entry.Connector)), entry, resolver) {
			check(entry)
		}
	}
	for _, entry := range rehomed {
		check(entry)
	}
}

// dropEnterpriseHookFinishedCleanups removes the ledger rows of the cleanups
// remove-all just finished, under the reconcile lock. Without it the
// guardian's ledger kept a done cleanup pending, with its old error, until
// the guardian retried it after its retry interval (rel-1-0-3 GAP-0204). A
// lock that is not free within a short wait leaves the rows for that retry.
func dropEnterpriseHookFinishedCleanups(ctx context.Context, finished map[string]bool, key func(enterpriseHookUserCleanup) string) error {
	ctx, cancel := context.WithTimeout(ctx, enterpriseHookFinishedCleanupLockWait)
	defer cancel()
	unlock, err := lockEnterpriseHookReconcile(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	pending, err := loadEnterpriseHookUserCleanups(cfg.DataDir)
	if err != nil {
		return err
	}
	kept := make([]enterpriseHookUserCleanup, 0, len(pending))
	for _, entry := range pending {
		if !finished[key(entry)] {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(pending) {
		return nil
	}
	return saveEnterpriseHookUserCleanups(cfg.DataDir, kept, time.Now())
}

// enterpriseHookFinishedCleanupLockWait bounds how long remove-all waits for
// a running reconcile before it leaves its finished rows to the guardian.
var enterpriseHookFinishedCleanupLockWait = 20 * time.Second

// finishEnterpriseHookRemoveAllCleanup runs one per-user cleanup for
// remove-all and adds its outcome to report, and to skip the reason the
// account's state must stay. It reports whether the cleanup is done, so its
// ledger row can go.
func finishEnterpriseHookRemoveAllCleanup(cmd *cobra.Command, report *enterpriseHooksRemoveAllReport, skip map[int]string, entry enterpriseHookUserCleanup, resolver unixidentity.Resolver) bool {
	outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(cmd.Context(), enterpriseHookWorkerLog, entry, resolver)
	return addEnterpriseHookRemoveAllCleanupOutcome(report, skip, entry, outcome, err)
}

// addEnterpriseHookRemoveAllCleanupOutcome adds the outcome of one per-user
// cleanup to report, and to skip the reason the account's state must stay.
// It reports whether the cleanup is done.
func addEnterpriseHookRemoveAllCleanupOutcome(report *enterpriseHooksRemoveAllReport, skip map[int]string, entry enterpriseHookUserCleanup, outcome enterpriseHookUserCleanupOutcome, err error) bool {
	name := strings.ToLower(strings.TrimSpace(entry.Connector))
	label := strings.TrimSpace(entry.User) + "/" + name
	var kept *enterpriseHookCleanupHomeKeptError
	var oldKept *enterpriseHookCleanupOldHomeKeptError
	switch {
	case outcome == enterpriseHookUserCleanupDone && errors.Is(err, errEnterpriseHookCleanupHomeGone):
		// Nothing was removed: the home is gone. The uninstall warns
		// for that user and agent and goes on (GAP-0553).
		report.Pending = append(report.Pending, fmt.Sprintf("%s: its recorded home %s is gone, so nothing was left to remove; if that home is restored, remove DefenseClaw's entries from the %s config in it",
			label, filepath.Clean(strings.TrimSpace(entry.UserHome)), name))
	case errors.As(err, &oldKept):
		report.Pending = append(report.Pending, fmt.Sprintf("%s: the account was re-homed to %s and cleaned there, but its recorded home %s still exists or cannot be confirmed gone and may still hold DefenseClaw's entries; remove them from the %s config in %s, or delete that home if unused",
			label, oldKept.currentHome, oldKept.home, name, oldKept.home))
		if skip[entry.UID] != enterpriseHookPurgeSkipFailed {
			skip[entry.UID] = enterpriseHookPurgeSkipKeptHome
		}
	case errors.As(err, &kept):
		// A removed account whose home folder was kept: no one to
		// remove it as, and the uninstall must not stop for it.
		report.Pending = append(report.Pending, fmt.Sprintf("%s: the directory gives the account no home (%s), so it looks removed, but its recorded home %s is not gone and may still hold DefenseClaw's entries; remove them from the %s config in %s, or delete that home if the account is gone",
			label, kept.directoryHome, kept.home, name, kept.home))
		if skip[entry.UID] != enterpriseHookPurgeSkipFailed {
			skip[entry.UID] = enterpriseHookPurgeSkipKeptHome
		}
	case outcome == enterpriseHookUserCleanupDone:
		report.Removed++
		return true
	case outcome == enterpriseHookUserCleanupPending:
		report.Pending = append(report.Pending, label)
		if skip[entry.UID] == "" {
			skip[entry.UID] = enterpriseHookPurgeSkipPending
		}
	default:
		reason := "the cleanup failed"
		if err != nil {
			var rehomed *enterpriseHookTargetHomeChangedError
			if errors.As(err, &rehomed) {
				reason = enterpriseHookRehomedReportReason(err)
			} else {
				reason = boundedString(err.Error(), 256)
			}
		}
		report.Failed = append(report.Failed, label+": "+reason)
		skip[entry.UID] = enterpriseHookPurgeSkipFailed
	}
	return outcome == enterpriseHookUserCleanupDone
}

func init() {
	enterpriseHookUserCleanupFailureText = func(err error) string {
		var changed *enterpriseHookTargetHomeChangedError
		var oldKept *enterpriseHookCleanupOldHomeKeptError
		var unverified *enterpriseHookCleanupUnverifiedError
		if errors.As(err, &changed) || errors.As(err, &oldKept) || errors.As(err, &unverified) {
			return enterpriseHookRehomeFailureText(err, enterpriseHookUserCleanupErrorMax)
		}
		return boundedEnterpriseHookUserCleanupText(err.Error())
	}
}

// enterpriseHookRehomedReportReason and the ledger formatter share path
// shortening. Short errors preserve their prior bytes.
func enterpriseHookRehomedReportReason(err error) string {
	return enterpriseHookRehomeFailureText(err, 768)
}

func enterpriseHookRehomeFailureText(err error, maxBytes int) string {
	raw := err.Error()
	if len(raw) <= enterpriseHookUserCleanupErrorMax {
		return boundedEnterpriseHookUserCleanupText(raw)
	}
	var paths []string
	var changed *enterpriseHookTargetHomeChangedError
	if errors.As(err, &changed) {
		paths = append(paths, changed.home, changed.directoryHome)
	}
	var oldKept *enterpriseHookCleanupOldHomeKeptError
	if errors.As(err, &oldKept) {
		paths = append(paths, oldKept.home, oldKept.currentHome)
		if maxBytes == enterpriseHookUserCleanupErrorMax {
			reason := strings.TrimPrefix(oldKept.reason, "user home "+oldKept.home+" ")
			reason = strings.ReplaceAll(reason, oldKept.home, "the recorded home")
			raw = fmt.Sprintf("enterprise hooks: old home %s for %q unverified (%s); new home %s cleaned; remove %s entries in old home, delete it if unused, or fix owner/permissions and rerun",
				oldKept.home, oldKept.name, reason, oldKept.currentHome, oldKept.connector)
		}
	}
	var unverified *enterpriseHookCleanupUnverifiedError
	keepConfigPath := ""
	keepReceiptPath := ""
	if errors.As(err, &unverified) {
		receiptPath := enterpriseHookUnverifiedReceiptPath(unverified.reason)
		paths = append(paths, unverified.path, unverified.dataDir, unverified.home, unverified.configPath)
		if unverified.configPath != unverified.home && len(unverified.configPath) <= 180 {
			keepConfigPath = unverified.configPath
		}
		if maxBytes == enterpriseHookUserCleanupErrorMax {
			receiptDir := filepath.Join(unverified.dataDir, "connector_backups", unverified.connector) + string(filepath.Separator)
			location := "in the home " + unverified.home
			if unverified.configPath != unverified.home {
				location = "at " + unverified.configPath
			}
			reason := boundedString(unverified.reason, 96)
			if receiptPath != "" {
				reason = "receipt " + shortEnterpriseHookReportPath(receiptPath) + " could not be checked"
			}
			raw = fmt.Sprintf("enterprise hooks: cleanup report unverified at %s (%s); remove DefenseClaw's entries from that agent's config %s, delete the stale copied receipt under %s if it keeps naming the other home, and rerun",
				unverified.path, reason, location, receiptDir)
		} else if receiptPath != "" && len(receiptPath) <= 180 {
			keepReceiptPath = receiptPath
			receiptDir := filepath.Join(unverified.dataDir, "connector_backups", unverified.connector) + string(filepath.Separator)
			location := "in the home " + unverified.home
			if unverified.configPath != unverified.home {
				location = "at " + unverified.configPath
			}
			raw = fmt.Sprintf("enterprise hooks: re-homed cleanup report unverified at %s (receipt %s could not be checked); remove DefenseClaw's entries from that agent's config %s, delete the stale copied receipt under %s if it keeps naming the other home, and rerun",
				unverified.path, receiptPath, location, receiptDir)
		}
		if keepConfigPath != "" {
			raw = strings.Replace(raw, "config at "+keepConfigPath, "config at <current-config-path>", 1)
		}
	}
	if oldKept != nil && unverified == nil && len(raw) <= maxBytes {
		return raw
	}
	if keepReceiptPath != "" {
		raw = strings.Replace(raw, keepReceiptPath, "<unverified-receipt-path>", 1)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		if path != "" && filepath.IsAbs(path) {
			raw = strings.ReplaceAll(raw, path, shortEnterpriseHookReportPath(path))
		}
	}
	// A worker or home check can add another absolute config path to the
	// reason. Keep its basename visible without letting it hide the remedy.
	words := strings.Fields(raw)
	for i, word := range words {
		path := strings.Trim(word, `"'(),;:`)
		if filepath.IsAbs(path) && len(path) > 96 {
			words[i] = strings.Replace(word, path, shortEnterpriseHookReportPath(path), 1)
		}
	}
	raw = strings.Join(words, " ")
	if len(raw)+len(keepConfigPath)+len(keepReceiptPath) > maxBytes {
		// Still too long, as with homes deep below a long folder: every path
		// that is not the kept config or receipt goes by its last element
		// first, so the reason and the remedy after the paths are not cut
		// (rel-1-0-3 GAP-0212).
		raw = enterpriseHookCompactReportPaths(raw, paths)
	}
	if keepConfigPath != "" {
		raw = strings.Replace(raw, "<current-config-path>", keepConfigPath, 1)
	}
	if keepReceiptPath != "" {
		raw = strings.Replace(raw, "<unverified-receipt-path>", keepReceiptPath, 1)
	}
	if len(raw) <= maxBytes {
		return raw
	}
	// In the home-check form (enterpriseHookRehomedCleanupError) the
	// clearing instruction precedes "current home check". Only the trailing
	// reason may be clipped after all paths have been shortened. The other
	// forms carry a worker reason that can hold the same words before their
	// remedy, so they never clip here (GAP-0634).
	const reasonSeparator = "then rerun; current home check: "
	if index := strings.Index(raw, reasonSeparator); oldKept == nil && unverified == nil && index >= 0 && index+len(reasonSeparator) < maxBytes {
		end := maxBytes - 3
		for end > 0 && !utf8.RuneStart(raw[end]) {
			end--
		}
		return raw[:end] + "..."
	}
	for _, marker := range []string{"; remove DefenseClaw's entries", "; remove the entries"} {
		if index := strings.Index(raw, marker); index >= 0 {
			remedy := raw[index:]
			if len(remedy)+3 < maxBytes {
				end := maxBytes - len(remedy) - 3
				for end > 0 && !utf8.RuneStart(raw[end]) {
					end--
				}
				if end < index {
					return raw[:end] + "..." + remedy
				}
			}
		}
	}
	// Other re-home failures put their remedy at the end. Preserve that
	// ending as well as the target named at the start.
	const gap = " ... "
	head, tail := (maxBytes-len(gap))/2, len(raw)-(maxBytes-len(gap))/2
	for head > 0 && !utf8.RuneStart(raw[head]) {
		head--
	}
	for tail < len(raw) && !utf8.RuneStart(raw[tail]) {
		tail++
	}
	return raw[:head] + gap + raw[tail:]
}

// enterpriseHookUnverifiedReceiptPath is display-only: the worker's
// validated reason may name an unreadable or misplaced backup receipt.
func enterpriseHookUnverifiedReceiptPath(reason string) string {
	for _, prefix := range []string{"load managed backup ", "managed backup "} {
		index := strings.Index(reason, prefix)
		if index < 0 {
			continue
		}
		candidate := reason[index+len(prefix):]
		candidate, _, _ = strings.Cut(candidate, ": ")
		candidate, _, _ = strings.Cut(candidate, " does not match")
		if filepath.IsAbs(candidate) {
			return candidate
		}
	}
	return ""
}

// enterpriseHookCompactReportPaths names each absolute path in raw longer
// than enterpriseHookCompactPathMax by its last element.
func enterpriseHookCompactReportPaths(raw string, paths []string) string {
	sorted := append([]string(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, path := range sorted {
		if path != "" && filepath.IsAbs(path) && len(path) > enterpriseHookCompactPathMax {
			raw = strings.ReplaceAll(raw, path, shortEnterpriseHookReportPathOver(path, enterpriseHookCompactPathMax))
		}
	}
	words := strings.Fields(raw)
	for i, word := range words {
		path := strings.Trim(word, `"'(),;:`)
		if filepath.IsAbs(path) && len(path) > enterpriseHookCompactPathMax {
			words[i] = strings.Replace(word, path, shortEnterpriseHookReportPathOver(path, enterpriseHookCompactPathMax), 1)
		}
	}
	return strings.Join(words, " ")
}

const enterpriseHookCompactPathMax = 40

func shortEnterpriseHookReportPath(path string) string {
	return shortEnterpriseHookReportPathOver(path, 96)
}

func shortEnterpriseHookReportPathOver(path string, limit int) string {
	if len(path) <= limit {
		return path
	}
	base := filepath.Base(path)
	if len(base) > 48 {
		head, tail := 24, len(base)-20
		for head > 0 && !utf8.RuneStart(base[head]) {
			head--
		}
		for tail < len(base) && !utf8.RuneStart(base[tail]) {
			tail++
		}
		base = base[:head] + "..." + base[tail:]
	}
	return filepath.Join(string(filepath.Separator), "...", base)
}

// enterpriseHookPendingCleanupCoveredByJob reports whether a manifest row's
// removal covers a pending cleanup: the same connector, and the recorded home
// of the cleanup is the home both the row and the directory give the
// account. A re-homed account runs its own cleanup, which checks both homes;
// skipped, a copied home kept loading the plugin while remove-all counted the
// row removed (GAP-0632).
func enterpriseHookPendingCleanupCoveredByJob(job *enterpriseHookWorkerJob, connector string, entry enterpriseHookUserCleanup, resolver unixidentity.Resolver) bool {
	if job == nil || !enterpriseHookJobRemoves(job, connector) {
		return false
	}
	home := filepath.Clean(strings.TrimSpace(entry.UserHome))
	if filepath.Clean(job.Account.Home) != home {
		return false
	}
	account, err := resolver.LookupUID(entry.UID)
	return err == nil && filepath.Clean(strings.TrimSpace(account.Home)) == home
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
// accounts in skip (uid -> the reason its state stays), whose pending cleanup
// still needs its state or backups.
// Eligible accounts without a manifest row are not proof of
// managed enrollment. It returns every enrolled account it did not add a purge
// for, as "user: reason", so the report names each account whose data stays.
func addEnterpriseHookStatePurges(jobs map[int]*enterpriseHookWorkerJob, rows []enterpriseHookRemoveRow, skip map[int]string) []string {
	dataDirs := map[int][]string{}
	notPurged := map[string]string{}
	for _, row := range rows {
		target, user := row.target, row.who
		if row.gone {
			continue // its ~/.defenseclaw went with the home
		}
		if row.problem != "" {
			notPurged[user] = row.problem
			continue
		}
		if target.UID == nil || *target.UID <= 0 {
			notPurged[user] = "its manifest row has no usable uid"
			continue
		}
		if reason, skipped := skip[*target.UID]; skipped {
			notPurged[user] = reason
			continue
		}
		job := jobs[*target.UID]
		if job == nil {
			reason := "its home is not trusted"
			home := filepath.Clean(strings.TrimSpace(target.UserHome))
			if filepath.IsAbs(home) && enterpriseHookCheckHome(home, *target.UID).State == enterprisehooks.HomePending {
				if enterpriseHookLiveHomeGone(home, *target.UID) {
					// Its ~/.defenseclaw went with the home (#1287):
					// nothing is left to purge, and its manifest rows
					// already warn that the home is gone.
					continue
				}
				reason = "its home is not available; rerun the purge when it is"
			}
			notPurged[user] = reason
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
		if _, skipped := skip[uid]; skipped {
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
