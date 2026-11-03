// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strconv"
	"time"
)

type enterpriseHookTargetRetry struct {
	delay time.Duration
	due   time.Time
}

// enterpriseHookWatchRetries keeps the retry deadline of each failed target.
// An unrelated filesystem pass does not move that target's deadline or make
// its backoff apply to a healthy target.
type enterpriseHookWatchRetries struct {
	targets map[string]enterpriseHookTargetRetry
}

const enterpriseHookWatchGlobalRetry = "\x00guardian-state"

func enterpriseHookWatchRetryKey(row enterpriseHookReconcileRow, index int) string {
	if key := enterpriseHookProtectedTargetKey(row); key != "" {
		return key
	}
	// An incomplete row still gets its own retry slot. Its index is stable
	// until the manifest changes, at which point the next pass rebuilds it.
	return enterpriseHookReconcileRowLabel(row) + "\x00" + strconv.Itoa(index)
}

func (retries *enterpriseHookWatchRetries) observe(reason string, run enterpriseHookReconcileRun, runErr error, now time.Time) {
	if retries.targets == nil {
		retries.targets = make(map[string]enterpriseHookTargetRetry)
	}
	markFailed := func(key string) {
		state, present := retries.targets[key]
		if !present || (reason == "retry" && !now.Before(state.due)) {
			state.delay = enterpriseHookWatchNextRepairRetryDelay(state.delay)
			state.due = now.Add(state.delay)
		}
		retries.targets[key] = state
	}
	if runErr != nil {
		// A failed reconcile did not inspect its targets, so keep their
		// previous deadlines and retry the pass itself independently.
		markFailed(enterpriseHookWatchGlobalRetry)
		return
	}
	seen := make(map[string]struct{}, len(run.Rows)+1)
	for index, row := range run.Rows {
		key := enterpriseHookWatchRetryKey(row, index)
		if row.OK || row.Pending {
			continue
		}
		seen[key] = struct{}{}
		markFailed(key)
	}
	if run.StateErr != nil {
		seen[enterpriseHookWatchGlobalRetry] = struct{}{}
		markFailed(enterpriseHookWatchGlobalRetry)
	}
	for key := range retries.targets {
		if _, stillFailed := seen[key]; !stillFailed {
			delete(retries.targets, key)
		}
	}
}

func (retries *enterpriseHookWatchRetries) nextDue() (time.Time, bool) {
	var first time.Time
	for _, state := range retries.targets {
		if first.IsZero() || state.due.Before(first) {
			first = state.due
		}
	}
	return first, !first.IsZero()
}

func enterpriseHookWatchAddPathOwner(owners map[string][]string, path, key string) {
	if key == "" {
		return
	}
	path = filepath.Clean(path)
	for _, owner := range owners[path] {
		if owner == key {
			return
		}
	}
	owners[path] = append(owners[path], key)
}

func enterpriseHookWatchAddExclusiveOwnedFiles(exclusive map[string]struct{}, owners map[string][]string, files []string, owner string) {
	for _, path := range files {
		path = filepath.Clean(path)
		exclusive[path] = struct{}{}
		if owners != nil {
			enterpriseHookWatchAddPathOwner(owners, path, owner)
		}
	}
}

// enterpriseHookWatchFailedOwnedPaths marks files only when all their owners
// failed. A healthy owner can still repair a shared file during another
// target's backoff.
func enterpriseHookWatchFailedOwnedPaths(run enterpriseHookReconcileRun) map[string]bool {
	failed := make(map[string]bool, len(run.WatchPathOwners))
	failedTargets := make(map[string]bool, len(run.Rows))
	for index, row := range run.Rows {
		if !row.OK && !row.Pending {
			failedTargets[enterpriseHookWatchRetryKey(row, index)] = true
		}
	}
	for path, owners := range run.WatchPathOwners {
		allFailed := len(owners) > 0
		for _, owner := range owners {
			if !failedTargets[owner] {
				allFailed = false
				break
			}
		}
		if allFailed {
			failed[filepath.Clean(path)] = true
		}
	}
	return failed
}
