// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A writer rewrites a Hermes hooks block between its DefenseClaw hooks and
// none every 200 ms. A pass armed by those events read the file once, met
// the intact phase in most passes and repaired nothing: the first repair
// came 5-15 s into the burst on managed macOS (GAP-1825, r103 GAP-0045). A
// pass a filesystem event armed keeps the target under check for its
// recheck window and repairs the damaged phase it meets.
func TestWorkerRepairsATargetDamagedWithinTheRecheckWindow(t *testing.T) {
	previousVerifier, previousInstaller := enterpriseHookWorkerVerifier, enterpriseHookWorkerInstaller
	t.Cleanup(func() {
		enterpriseHookWorkerVerifier, enterpriseHookWorkerInstaller = previousVerifier, previousInstaller
	})
	start := time.Now()
	// Intact for the first 100 ms, then damaged.
	enterpriseHookWorkerVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if time.Since(start) < 100*time.Millisecond {
			return enterprisehooks.InstallResult{Connector: "hermes"}, nil
		}
		return enterprisehooks.InstallResult{}, errors.New("hermes hooks block is missing the DefenseClaw hooks")
	}
	var installs atomic.Int32
	enterpriseHookWorkerInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs.Add(1)
		return enterprisehooks.InstallResult{Connector: "hermes"}, nil
	}
	request := enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true, RecheckMillis: 300,
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true, Options: enterpriseHookWorkerOptions{ConnectorName: "hermes"}}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].Repaired || installs.Load() != 1 {
		t.Fatalf("a target damaged 100 ms into a 300 ms recheck window: response %+v, installs %d; want one repair", response.Targets, installs.Load())
	}
	// Without a window (interval and startup passes) one check decides.
	start = time.Now()
	installs.Store(0)
	request.RecheckMillis = 0
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || response.Targets[0].Repaired || installs.Load() != 0 {
		t.Fatalf("a pass without a window repaired a target that verified: %+v", response.Targets)
	}
}

// Only a pass a filesystem event armed gets the window.
func TestEnterpriseHookWatchRecheckOnlyForFilesystemPasses(t *testing.T) {
	if enterpriseHookWatchRecheckFor("fsnotify") <= 200*time.Millisecond {
		t.Fatalf("fsnotify recheck window %s does not outlast a 200 ms rewrite phase", enterpriseHookWatchRecheckFor("fsnotify"))
	}
	for _, reason := range []string{"interval", "startup", "retry", "session sign-in"} {
		if got := enterpriseHookWatchRecheckFor(reason); got != 0 {
			t.Fatalf("%s pass recheck window = %s, want none", reason, got)
		}
	}
}

// The windows of a pass's targets run together (GAP-1825 refix). One window
// per target in turn made a pass 300 ms longer per target: with six targets
// the sixth was checked first about 1.6 s in, so a burst on it was repaired
// past 3 s. Six previously protected targets, the last one damaged 100 ms
// in: it is repaired inside the one window and the worker ends with it.
func TestWorkerRecheckWindowIsSharedByAllTargets(t *testing.T) {
	previousVerifier, previousInstaller := enterpriseHookWorkerVerifier, enterpriseHookWorkerInstaller
	t.Cleanup(func() {
		enterpriseHookWorkerVerifier, enterpriseHookWorkerInstaller = previousVerifier, previousInstaller
	})
	connectors := []string{"amp", "claudecode", "codex", "cursor", "devin", "hermes"}
	start := time.Now()
	enterpriseHookWorkerVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if opts.ConnectorName == "hermes" && time.Since(start) >= 100*time.Millisecond {
			return enterprisehooks.InstallResult{}, errors.New("hermes hooks block is missing the DefenseClaw hooks")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	var repairedAt atomic.Int64
	enterpriseHookWorkerInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		repairedAt.Store(int64(time.Since(start)))
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName}, nil
	}
	request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true, RecheckMillis: 300}
	for index, name := range connectors {
		request.Targets = append(request.Targets, enterpriseHookWorkerTarget{
			Index: index, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
			Options: enterpriseHookWorkerOptions{ConnectorName: name},
		})
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	took := time.Since(start)
	repaired := 0
	for _, target := range response.Targets {
		if target.Repaired {
			repaired++
			if target.Index != len(connectors)-1 || !target.OK {
				t.Fatalf("repaired target %+v, want only the last (hermes), ok", target)
			}
		}
	}
	if repaired != 1 || len(response.Targets) != len(connectors) {
		t.Fatalf("targets %+v: want %d results and one repair", response.Targets, len(connectors))
	}
	if at := time.Duration(repairedAt.Load()); at > 400*time.Millisecond {
		t.Fatalf("the sixth target, damaged 100 ms in, was repaired %s in; want within the one 300 ms window", at)
	}
	if took > 600*time.Millisecond {
		t.Fatalf("a pass of six targets with a 300 ms window took %s; want about one window", took)
	}
}
