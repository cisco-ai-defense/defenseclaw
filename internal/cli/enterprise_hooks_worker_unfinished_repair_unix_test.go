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

func TestEnterpriseHookWorkerTimedOutInsideInstallKeepsTheRestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "hang-after-write", 10*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the worker reported as timed out", err)
	}
	requireRestoredAndKept(t, response, script)
}

func TestEnterpriseHookWorkerExitedInsideInstallKeepsTheRestore(t *testing.T) {
	response, script, err := runUnfinishedRepairWorker(t, "exit-after-write", 0)
	if err == nil {
		t.Fatal("a worker that exited without its answer was reported as fine")
	}
	requireRestoredAndKept(t, response, script)
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
