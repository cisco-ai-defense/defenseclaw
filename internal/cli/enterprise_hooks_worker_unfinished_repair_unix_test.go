// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0754: a worker that put a protected hook back but did not return from
// the install (it outlived its limit, died, or failed after it published)
// still leaves the restore for the parent to count, audit and record. A later
// clean pass cannot reconstruct it.

// runUnfinishedRepairWorker runs one tampered hermes target. A worker that
// hangs needs a limit to hit; the limit is long enough for a loaded machine to
// start the worker and let it write, so the others keep the default.
func runUnfinishedRepairWorker(t *testing.T, mode string, limit time.Duration) (enterpriseHookWorkerResponse, string, error) {
	t.Helper()
	useEnterpriseHookWorkerHelper(t, mode)
	if limit > 0 {
		old := enterpriseHookWorkerTimeout
		enterpriseHookWorkerTimeout = limit
		t.Cleanup(func() { enterpriseHookWorkerTimeout = old })
	}
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(withEnterpriseHookWorkerInterruptDrain(context.Background()), account,
		enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true,
			Targets: []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)}})
	return response, filepath.Join(account.Home, ".defenseclaw", "hooks", "hermes-hook.sh"), err
}

func requireRestoredAndKept(t *testing.T, response enterpriseHookWorkerResponse, script string) {
	t.Helper()
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the worker did not restore %s: %v", script, err)
	}
	if len(response.Targets) != 1 || response.Targets[0].Index != 1 || !response.Targets[0].OK ||
		!response.Targets[0].Repaired || response.Targets[0].Result == nil || response.Targets[0].Result.Connector != "hermes" {
		t.Fatalf("kept targets = %+v, want the hermes restore", response.Targets)
	}
}

// requireRestoredButFailed: the files show the worker put the script back, and
// the target is still failed, because the worker never said it is healthy.
func requireRestoredButFailed(t *testing.T, response enterpriseHookWorkerResponse, script string) {
	t.Helper()
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the worker did not restore %s: %v", script, err)
	}
	if len(response.Targets) != 1 || response.Targets[0].Index != 1 || response.Targets[0].OK ||
		!response.Targets[0].Repaired || response.Targets[0].Result != nil || response.Targets[0].Error == "" {
		t.Fatalf("kept targets = %+v, want the hermes restore on a failed target", response.Targets)
	}
}

func TestEnterpriseHookWorkerTimedOutInsideInstallKeepsTheRestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "hang-after-write", 10*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the worker reported as timed out", err)
	}
	requireRestoredButFailed(t, response, script)
}

func TestEnterpriseHookWorkerExitedInsideInstallKeepsTheRestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "exit-after-write", 0)
	if err == nil {
		t.Fatal("a worker that exited without its answer was reported as fine")
	}
	requireRestoredButFailed(t, response, script)
}

// An install that fails after it published has put the target back: the
// worker checks and answers the restore.
func TestEnterpriseHookWorkerInstallFailedAfterPublishingIsARestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "fail-after-write", 0)
	if err != nil {
		t.Fatal(err)
	}
	requireRestoredAndKept(t, response, script)
}

// The twin: an install that fails and leaves the target broken keeps its
// error and reports no restore.
func TestEnterpriseHookWorkerInstallFailedWithoutPublishingIsNotARestore(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "fail")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(withEnterpriseHookWorkerInterruptDrain(context.Background()), account,
		enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true,
			Targets: []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)}})
	if err != nil || len(response.Targets) != 1 || response.Targets[0].OK || response.Targets[0].Repaired ||
		response.Targets[0].Error != "install refused" {
		t.Fatalf("err = %v, answer = %+v, want the install error and no restore", err, response.Targets)
	}
}

// A worker that died or failed before it wrote anything restored nothing, and
// its target is not healthy.
func TestEnterpriseHookWorkerExitedBeforeWritingKeepsNoRestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "exit-before-write", 0)
	if err == nil {
		t.Fatal("a worker that exited without its answer was reported as fine")
	}
	if _, statErr := os.Stat(script); !os.IsNotExist(statErr) {
		t.Fatalf("script = %v, want absent", statErr)
	}
	if len(response.Targets) != 0 {
		t.Fatalf("kept targets = %+v, want none", response.Targets)
	}
}

// A worker that died after it wrote only part of the target put a file back:
// that is a restore, and the target stays failed so the next pass checks it.
func TestEnterpriseHookWorkerExitedAfterPartialWriteKeepsTheRestoreAsFailed(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "exit-after-partial-write", 0)
	if err == nil {
		t.Fatal("a worker that exited without its answer was reported as fine")
	}
	requireRestoredButFailed(t, response, script)
}

// An install that returns an error after it wrote the script, with the
// configuration still broken, answers a failed target; the script it put back
// is still a restore.
func TestEnterpriseHookWorkerFailedPartialInstallKeepsTheRestoreAsFailed(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "fail-after-partial-write", 0)
	if err != nil {
		t.Fatal(err)
	}
	requireRestoredButFailed(t, response, script)
	if response.Targets[0].Error != "install failed after it wrote the script" {
		t.Fatalf("error = %q, want the install error kept", response.Targets[0].Error)
	}
}

// Dispatched as the guardian does: a target that is not healthy is never
// claimed healthy, whatever the worker left, and a restore is reported with
// its failure.
func TestDispatchedHookWorkerOutcomeKeepsHealthSeparateFromRestore(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantRepaired bool
		wantScript   bool
	}{
		{"exit-before-write", false, false},
		{"exit-after-partial-write", true, true},
		{"fail-after-partial-write", true, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, tc.mode)
			account := selfWorkerAccount(t)
			jobs := map[int]*enterpriseHookWorkerJob{account.UID: {Account: account, Request: enterpriseHookWorkerRequest{
				Operation: enterpriseHookWorkerOpApply, Standalone: true,
				Targets: []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)},
			}}}
			got, ok := dispatchEnterpriseHookStandaloneJobs(withEnterpriseHookWorkerInterruptDrain(context.Background()), jobs)[1]
			if !ok {
				t.Fatal("the dispatcher omitted the protected hermes target")
			}
			script := filepath.Join(account.Home, ".defenseclaw", "hooks", "hermes-hook.sh")
			if _, err := os.Stat(script); (err == nil) != tc.wantScript {
				t.Fatalf("script present = %v, want %v", err == nil, tc.wantScript)
			}
			if got.ok || got.pending || got.err == "" || got.repaired != tc.wantRepaired {
				t.Fatalf("outcome = %+v, want a failed target, repaired = %v", got, tc.wantRepaired)
			}
		})
	}
}
