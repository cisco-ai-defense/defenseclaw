// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// codeGuardianRepairPending names a target whose DefenseClaw-only hook files
// (hook scripts, connector-scoped token, runtime records) no longer hold what
// the hook guardian left there at its last pass. Its hook calls may not be
// inspected until the guardian puts them back, so security_complete is false
// meanwhile (GAP-0044).
const codeGuardianRepairPending = "guardian_repair_pending"

// guardianOwnedFilesCheckBudget bounds how long status waits for the hook
// files of the enrolled accounts; a home that does not answer in time leaves
// the check unconfirmed, which reads as not complete.
var guardianOwnedFilesCheckBudget = 5 * time.Second

// guardianOwnedFolderAnswers looks a hook folder up in a stat(1) child,
// bounded; guardianOwnedFileFingerprint reads a hook file in this process.
// Tests replace them.
var (
	guardianOwnedFolderAnswers   = enterprisestatus.PathAnswers
	guardianOwnedFileFingerprint = enterprisehooks.OwnedFileFingerprint
)

type changedGuardianTarget struct {
	user, connector, first, nonExecutable, unanswered string
	count                                             int
}

// describeChangedGuardianFiles compares each verified target's hook files
// with the fingerprints the guardian recorded at its last pass
// (enterprisehooks.GuardianOwnedFilesFile). Between two passes a user can
// overwrite one, for example the scoped token, and the guardian's last
// report alone read as protected. No record (Secure Client, or before the
// first standalone pass) is no check: the guardian report checks cover it.
func (l *lifecycle) describeChangedGuardianFiles() {
	env, r := l.env, l.result
	record, err := enterprisehooks.ReadGuardianOwnedFilesRecord(env.P(filepath.Join(env.Layout.DataDir, enterprisehooks.GuardianOwnedFilesFile)))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		r.AddWarning(codeGuardianRepairPending, "the hook guardian's record of the hook files it verified cannot be read ("+boundedGuardianReason(err.Error())+
			"), so changes to them since its last pass are not checked; the guardian writes it again on its next pass")
		r.SecurityComplete = false
		return
	}
	done := make(chan []changedGuardianTarget, 1)
	go func() {
		var changes []changedGuardianTarget
		for _, target := range record.Targets {
			// A hook folder on a stalled mount is not read in this process:
			// a thread stuck in the kernel kept status and verify from
			// exiting after they had answered (GAP-1751).
			if folder := unansweredGuardianFolder(env.P, target); folder != "" {
				changes = append(changes, changedGuardianTarget{user: target.User, connector: target.Connector, unanswered: folder})
				continue
			}
			changed := target.ChangedFiles(func(path string) string { return guardianOwnedFileFingerprint(env.P(path)) })
			change := changedGuardianTarget{user: target.User, connector: target.Connector, count: len(changed)}
			if len(changed) > 0 {
				change.first = changed[0]
			}
			if target.Connector == "hermes" && (l.opts.Action == ActionVerify || l.opts.Action == ActionEnsure) {
				for _, file := range target.Files {
					if filepath.Base(file.Path) != "hermes-hook.sh" {
						continue
					}
					if !hermesHookRunnable(env.P(file.Path)) {
						change.nonExecutable = file.Path
						break
					}
				}
			}
			if change.count > 0 || change.nonExecutable != "" {
				changes = append(changes, change)
			}
		}
		done <- changes
	}()
	var changes []changedGuardianTarget
	select {
	case changes = <-done:
	case <-time.After(guardianOwnedFilesCheckBudget):
		r.AddWarning(codeGuardianRepairPending, fmt.Sprintf(
			"the DefenseClaw hook files of the enrolled accounts could not all be read within %s, so changes to them since the hook guardian's last pass are not confirmed",
			guardianOwnedFilesCheckBudget))
		r.SecurityComplete = false
		return
	}
	for _, change := range changes {
		if change.unanswered != "" {
			r.AddWarning(codeGuardianRepairPending, fmt.Sprintf(
				"the DefenseClaw hook files of user %s for %s are not confirmed: their folder %s did not answer a lookup within %s (a stalled home mount?), so changes to them since the hook guardian's last pass are not checked",
				boundedGuardianReason(change.user), change.connector, boundedGuardianReason(change.unanswered), enterprisestatus.LaunchPathLookupTimeout()))
		}
		if change.count > 0 {
			r.AddWarning(codeGuardianRepairPending, fmt.Sprintf(
				"%d DefenseClaw hook file(s) of user %s for %s changed since the hook guardian last verified them (%s); that agent's hook calls may not be inspected until the guardian puts them back on its next pass. Run `%s` again in a minute",
				change.count, boundedGuardianReason(change.user), change.connector, boundedGuardianReason(change.first), env.lifecycleCommand("status")))
		}
		if change.nonExecutable != "" {
			r.AddError(codeVerify, fmt.Sprintf("registered Hermes hook is not executable for user %s (its owner must be able to read and run it): %s",
				boundedGuardianReason(change.user), boundedGuardianReason(change.nonExecutable)))
		}
	}
	if len(changes) > 0 {
		r.SecurityComplete = false
	}
}

// hermesHookLstat is replaceable in tests, which do not run as root: root
// reads a hook below a folder its owner cannot search.
var hermesHookLstat = os.Lstat

// hermesHookRunnable reports whether the owner of a registered Hermes hook
// can run it. Hermes runs the script through its shell, which must read it:
// owner execute alone (0100) runs nothing (GAP-1484). The owner must also
// be able to reach it: an unsearchable hooks folder or data folder
// (~/.defenseclaw/hooks, ~/.defenseclaw) hides a hook whose own mode is
// intact (GAP-1628).
func hermesHookRunnable(path string) bool {
	info, err := hermesHookLstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o500 != 0o500 {
		return false
	}
	dir := path
	for range 2 {
		dir = filepath.Dir(dir)
		info, err := hermesHookLstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o100 == 0 {
			return false
		}
	}
	return true
}

// unansweredGuardianFolder returns the first folder of the target's hook
// files (as recorded, p maps it to the file system) that does not answer a
// bounded lookup made in a child process, or "" when all of them answer.
func unansweredGuardianFolder(p func(string) string, target enterprisehooks.GuardianOwnedTarget) string {
	seen := map[string]bool{}
	for _, file := range target.Files {
		folder := filepath.Dir(file.Path)
		if seen[folder] {
			continue
		}
		seen[folder] = true
		if !guardianOwnedFolderAnswers(p(folder)) {
			return folder
		}
	}
	return ""
}
