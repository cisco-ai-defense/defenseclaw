// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/spf13/cobra"
)

// GAP-0754: a tampered managed hook file was put back within a second, but
// the guardian recorded no repair (repairs=0, no connector-hook-repaired
// audit row). The repair rewrites the owned file while its pass is still
// running, and that write was taken for a new change: the watch loop
// cancelled the pass, so the repair the worker had just made was never
// accounted, and the next pass found the file already in order. A write that
// leaves an owned file as the last pass verified it is the pass finishing its
// own repair; only a file that differs from that still interrupts the pass.
type gap0754Guardian struct {
	script     string
	inPass     chan struct{}
	repaired   chan struct{}
	cancelled  chan struct{}
	cleanPass  atomic.Int32
	repairHold time.Duration
	onRepair   func()
}

const gap0754Verified = "#!/bin/sh\nexec defenseclaw-hook\n"

func startGAP0754Guardian(t *testing.T, g *gap0754Guardian) {
	restoreEnterpriseHooksLifecycleTestState(t)
	previousReconcile := enterpriseHookWatchReconcileOnce
	previousPlatformWatch := enterpriseHookWatchPlatformWatch
	previousTargetScoped := enterpriseHookWatchTargetScoped
	previousManifest := enterpriseHookManifest
	previousInterval, previousDebounce, previousSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	t.Cleanup(func() {
		enterpriseHookWatchReconcileOnce = previousReconcile
		enterpriseHookWatchPlatformWatch = previousPlatformWatch
		enterpriseHookWatchTargetScoped = previousTargetScoped
		enterpriseHookManifest = previousManifest
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = previousInterval, previousDebounce, previousSettle
	})
	dir := t.TempDir()
	g.script = filepath.Join(dir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(g.script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g.script, []byte(gap0754Verified), 0o700); err != nil {
		t.Fatal(err)
	}
	g.inPass, g.repaired, g.cancelled = make(chan struct{}, 4), make(chan struct{}, 4), make(chan struct{}, 4)
	cfg = &config.Config{DataDir: dir}
	enterpriseHookManifest = filepath.Join(dir, "targets.yaml")
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 50 * time.Millisecond
	enterpriseHookWatchSettle = 50 * time.Millisecond
	ready := make(chan struct{})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { close(ready) }
	enterpriseHookWatchTargetScoped = func() bool { return true }
	row := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", OK: true}
	owners := map[string][]string{g.script: {enterpriseHookProtectedTargetKey(row)}}
	calls := 0
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		calls++
		run := enterpriseHookReconcileRun{
			Rows: []enterpriseHookReconcileRow{row}, ManifestSHA256: "same",
			WatchDirs: []string{filepath.Dir(g.script)}, WatchExclusiveFiles: []string{g.script}, WatchPathOwners: owners,
		}
		if calls == 1 {
			return run, nil
		}
		body, _ := os.ReadFile(g.script)
		if string(body) == gap0754Verified {
			g.cleanPass.Add(1)
			return run, nil
		}
		// The worker puts the file back as the user, then spends its hold
		// finishing (recording its answer).
		if err := os.WriteFile(g.script, []byte(gap0754Verified), 0o700); err != nil {
			return run, err
		}
		g.inPass <- struct{}{}
		if g.onRepair != nil {
			g.onRepair()
		}
		select {
		case <-ctx.Done():
			g.cancelled <- struct{}{}
			return run, ctx.Err()
		case <-time.After(g.repairHold):
		}
		run.Repairs = 1
		g.repaired <- struct{}{}
		return run, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- runEnterpriseHooksWatch(cmd, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("guardian did not stop")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("guardian exited before events: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("watcher did not start")
	}
	// Past the settle window of the startup pass: the tamper is not its tail.
	time.Sleep(600 * time.Millisecond)
}

func TestGAP0754RepairWriteDoesNotCancelTheRepairingPass(t *testing.T) {
	g := &gap0754Guardian{repairHold: 400 * time.Millisecond}
	startGAP0754Guardian(t, g)
	if err := os.WriteFile(g.script, []byte(gap0754Verified+"#\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.repaired:
	case <-g.cancelled:
		t.Fatal("the pass that put the hook script back was cancelled by its own write, so its repair was never reported (GAP-0754)")
	case <-time.After(5 * time.Second):
		t.Fatal("the tampered hook script was not repaired")
	}
}

// A change that leaves the file different from what the pass verified still
// interrupts it: the running worker may already have checked the file.
func TestGAP0754ANewChangeStillInterruptsTheRunningPass(t *testing.T) {
	g := &gap0754Guardian{repairHold: 2 * time.Second}
	g.onRepair = func() {
		// A second tamper lands while the first repair is running.
		_ = os.WriteFile(g.script, []byte("#!/bin/sh\nexit 0\n"), 0o700)
	}
	startGAP0754Guardian(t, g)
	if err := os.WriteFile(g.script, []byte(gap0754Verified+"#\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("a second change to the hook script did not interrupt the running pass")
	}
	g.onRepair = nil
	select {
	case <-g.repaired:
	case <-time.After(6 * time.Second):
		t.Fatal("the second change was not repaired afterwards")
	}
}

// Nothing changed, nothing is reported: a pass over an intact script repairs
// and reports nothing.
func TestGAP0754AnUnchangedScriptReportsNoRepair(t *testing.T) {
	g := &gap0754Guardian{repairHold: 50 * time.Millisecond}
	startGAP0754Guardian(t, g)
	if err := os.WriteFile(g.script, []byte(gap0754Verified), 0o700); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.repaired:
		t.Fatal("a rewrite with the verified bytes was reported as a repair")
	case <-time.After(1500 * time.Millisecond):
	}
}
