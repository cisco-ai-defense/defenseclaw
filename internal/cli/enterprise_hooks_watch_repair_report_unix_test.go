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

// GAP-0754 guards on the guardian watch loop, driven with a stand-in
// reconcile. The repair accounting itself (a worker write never cancels its
// own pass) is covered through the production worker path in
// enterprise_hooks_watch_repair_real_unix_test.go.
type gap0754Guardian struct {
	script     string
	holdClean  bool
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
			if g.holdClean && calls == 2 {
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
			}
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

// A clean interval pass has no self-write to mask a protected replacement.
// Even if its metadata matches the prior snapshot, the rename needs a replay.
func TestGAP0754SameMetadataReplacementDuringCleanPassReplays(t *testing.T) {
	ticks := make(chan time.Time, 1)
	previousTicker := enterpriseHookWatchIntervalTicker
	enterpriseHookWatchIntervalTicker = func(time.Duration) (<-chan time.Time, func()) {
		return ticks, func() {}
	}
	t.Cleanup(func() { enterpriseHookWatchIntervalTicker = previousTicker })
	g := &gap0754Guardian{holdClean: true, repairHold: 1500 * time.Millisecond}
	previousFingerprint := enterpriseHookOwnedFileFingerprint
	enterpriseHookOwnedFileFingerprint = func(path string) string {
		if path == g.script {
			return "meta:same-size-time-mode"
		}
		return previousFingerprint(path)
	}
	t.Cleanup(func() { enterpriseHookOwnedFileFingerprint = previousFingerprint })
	replaced := make(chan struct{})
	var replacedOnce atomic.Bool
	g.onRepair = func() {
		if replacedOnce.Swap(true) {
			return
		}
		defer close(replaced)
		info, err := os.Stat(g.script)
		if err != nil {
			t.Error(err)
			return
		}
		malicious := []byte(gap0754Verified)
		malicious[len(malicious)-2] = 'x'
		tmp := g.script + ".replacement"
		if err := os.WriteFile(tmp, malicious, 0o700); err != nil {
			t.Error(err)
			return
		}
		if err := os.Chtimes(tmp, info.ModTime(), info.ModTime()); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(tmp, g.script); err != nil {
			t.Error(err)
		}
	}
	startGAP0754Guardian(t, g)
	ticks <- time.Now()
	select {
	case <-replaced:
	case <-time.After(4 * time.Second):
		t.Fatal("the clean pass did not see the replacement")
	}
	deadline := time.After(3 * time.Second)
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		body, err := os.ReadFile(g.script)
		if err == nil && string(body) == gap0754Verified {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("same-metadata replacement stayed in the protected hook script: %v", err)
		case <-poll.C:
		}
	}
}
