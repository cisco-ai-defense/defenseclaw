// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/spf13/cobra"
)

// A queued fsnotify event can arrive after a retry pass's snapshot. The
// other account is still failing, but the healthy account's token must be
// repaired before that failure's next backoff pass.
func TestEnterpriseHookWatchRepairsHealthyTokenWhileOtherTargetFails(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "target_token"
		if shared {
			name = "shared_hook"
		}
		t.Run(name, func(t *testing.T) {
			testEnterpriseHookWatchRepairBeforeOtherRetry(t, shared, 0, false)
		})
	}
}

func TestGAP0523QueuedHealthyEventPreemptsSlowRetry(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "target_token"
		if shared {
			name = "shared_hook"
		}
		t.Run(name, func(t *testing.T) {
			testEnterpriseHookWatchRepairBeforeOtherRetry(t, shared, 5200*time.Millisecond, false)
		})
	}
}

func TestGAP0523FailedFilePassPreemptsHealthyEvent(t *testing.T) {
	testEnterpriseHookWatchRepairBeforeOtherRetry(t, false, 5200*time.Millisecond, true)
}

func TestGAP0523MixedBurstReplaysRecoveredTargetEvent(t *testing.T) {
	testGAP0523MixedBurstReplaysRecoveredTargetEvent(t, false, false)
}

func TestR108CIBatch3MixedBurstRetainsFailedPathWithoutItsEvent(t *testing.T) {
	testGAP0523MixedBurstReplaysRecoveredTargetEvent(t, true, false)
}

func TestR108CIBatch7WindowsFailedPathCaseVariant(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows directory event spelling")
	}
	testGAP0523MixedBurstReplaysRecoveredTargetEvent(t, false, true)
}

func testGAP0523MixedBurstReplaysRecoveredTargetEvent(t *testing.T, missedFailedEvent, failedCaseVariant bool) {
	restoreEnterpriseHooksLifecycleTestState(t)
	previousReconcile := enterpriseHookWatchReconcileOnce
	previousPlatformWatch := enterpriseHookWatchPlatformWatch
	previousTargetScoped := enterpriseHookWatchTargetScoped
	previousManifest := enterpriseHookManifest
	previousInterval, previousDebounce, previousSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	previousRetryMin, previousRetryMax := enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax
	t.Cleanup(func() {
		enterpriseHookWatchReconcileOnce = previousReconcile
		enterpriseHookWatchPlatformWatch = previousPlatformWatch
		enterpriseHookWatchTargetScoped = previousTargetScoped
		enterpriseHookManifest = previousManifest
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = previousInterval, previousDebounce, previousSettle
		enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax = previousRetryMin, previousRetryMax
	})
	dir := t.TempDir()
	failedDir, healthyDir := dir, dir
	if missedFailedEvent {
		failedDir, healthyDir = filepath.Join(dir, "failed"), filepath.Join(dir, "healthy")
		for _, path := range []string{failedDir, healthyDir} {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	failedToken := filepath.Join(failedDir, ".hook-failed.token")
	healthyToken := filepath.Join(healthyDir, ".hook-healthy.token")
	failedStoredToken := failedToken
	if failedCaseVariant {
		failedStoredToken = filepath.Join(failedDir, ".HOOK-FAILED.TOKEN")
	}
	const issued = "issued\n"
	for _, path := range []string{failedStoredToken, healthyToken} {
		if err := os.WriteFile(path, []byte(issued), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg = &config.Config{DataDir: dir}
	enterpriseHookManifest = filepath.Join(dir, "targets.yaml")
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 250 * time.Millisecond
	enterpriseHookWatchSettle = 2 * time.Second
	enterpriseHookWatchRepairRetryMin = 20 * time.Second
	enterpriseHookWatchRepairRetryMax = 20 * time.Second
	ready := make(chan struct{})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { close(ready) }
	enterpriseHookWatchTargetScoped = func() bool { return true }
	failed := enterpriseHookReconcileRow{User: "bob", Connector: "hermes", Error: "home unavailable"}
	healthy := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", OK: true}
	owners := map[string][]string{
		failedToken:  {enterpriseHookProtectedTargetKey(failed)},
		healthyToken: {enterpriseHookProtectedTargetKey(healthy)},
	}
	watchDirs := []string{dir}
	if missedFailedEvent {
		// The failed target's file changes without a directory event;
		// the healthy target still supplies the wakeup for both.
		watchDirs = []string{healthyDir}
	}
	healthyRepaired := make(chan time.Time, 1)
	failedRepaired := make(chan time.Time, 1)
	calls := 0
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		calls++
		run := enterpriseHookReconcileRun{
			Rows: []enterpriseHookReconcileRow{failed, healthy}, Failures: 1,
			ManifestSHA256: "same", WatchDirs: watchDirs,
			WatchExclusiveFiles: []string{failedToken, healthyToken}, WatchPathOwners: owners,
		}
		if calls >= 2 {
			for _, path := range enterpriseHookReconcileRecheckPaths {
				switch path {
				case healthyToken:
					if err := os.WriteFile(healthyToken, []byte(issued), 0o600); err != nil {
						return run, err
					}
					run.Repairs++
					select {
					case healthyRepaired <- time.Now():
					default:
					}
				case failedToken:
					if err := os.WriteFile(failedToken, []byte(issued), 0o600); err != nil {
						return run, err
					}
					run.Rows[0].Error = ""
					run.Rows[0].OK = true
					run.Failures = 0
					run.Repairs++
					select {
					case failedRepaired <- time.Now():
					default:
					}
				}
			}
		}
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
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("guardian exit: %v", err)
			}
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
	writtenAt := time.Now()
	if err := os.WriteFile(failedStoredToken, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(healthyToken, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for label, repaired := range map[string]<-chan time.Time{"healthy": healthyRepaired, "recovered": failedRepaired} {
		select {
		case at := <-repaired:
			if elapsed := at.Sub(writtenAt); elapsed >= 5*time.Second {
				t.Errorf("%s token repair took %s", label, elapsed)
			}
		case <-time.After(time.Until(writtenAt.Add(5 * time.Second))):
			t.Errorf("%s token event was not replayed within five seconds", label)
		}
	}
	for _, path := range []string{failedToken, healthyToken} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != issued {
			t.Errorf("token %s after repair = %q, %v", filepath.Base(path), data, err)
		}
	}
}

func testEnterpriseHookWatchRepairBeforeOtherRetry(t *testing.T, shared bool, retryHold time.Duration, failedFileEvent bool) {
	restoreEnterpriseHooksLifecycleTestState(t)
	previousReconcile := enterpriseHookWatchReconcileOnce
	previousPlatformWatch := enterpriseHookWatchPlatformWatch
	previousTargetScoped := enterpriseHookWatchTargetScoped
	previousManifest := enterpriseHookManifest
	previousInterval, previousDebounce, previousSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	previousRetryMin, previousRetryMax := enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax
	t.Cleanup(func() {
		enterpriseHookWatchReconcileOnce = previousReconcile
		enterpriseHookWatchPlatformWatch = previousPlatformWatch
		enterpriseHookWatchTargetScoped = previousTargetScoped
		enterpriseHookManifest = previousManifest
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = previousInterval, previousDebounce, previousSettle
		enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax = previousRetryMin, previousRetryMax
	})
	dir := t.TempDir()
	token := filepath.Join(dir, ".hook-hermes.token")
	if shared {
		token = filepath.Join(dir, ".defenseclaw", "hooks", "inspect-tool.sh")
		if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const issued = "issued\n"
	if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
		t.Fatal(err)
	}
	failedToken := filepath.Join(dir, ".hook-failed.token")
	if failedFileEvent {
		if err := os.WriteFile(failedToken, []byte(issued), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg = &config.Config{DataDir: dir}
	enterpriseHookManifest = filepath.Join(dir, "targets.yaml")
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 50 * time.Millisecond
	enterpriseHookWatchSettle = 2 * time.Second
	enterpriseHookWatchRepairRetryMin = 2 * time.Second
	enterpriseHookWatchRepairRetryMax = 15 * time.Second
	if failedFileEvent {
		enterpriseHookWatchRepairRetryMin = time.Minute
		enterpriseHookWatchRepairRetryMax = time.Minute
	}
	ready := make(chan struct{})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { close(ready) }
	enterpriseHookWatchTargetScoped = func() bool { return true }
	healthy := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", OK: true}
	failing := enterpriseHookReconcileRow{User: "bob", Connector: "hermes", Error: "home unavailable"}
	owners := []string{enterpriseHookProtectedTargetKey(healthy)}
	if shared {
		healthy = enterpriseHookReconcileRow{User: "alice", UserHome: dir, Connector: "codex", OK: true}
		failing = enterpriseHookReconcileRow{User: "alice", UserHome: dir, Connector: "claudecode", Error: "repair pending"}
		owners = []string{enterpriseHookProtectedTargetKey(healthy), enterpriseHookProtectedTargetKey(failing)}
	}
	retryStarted := make(chan struct{})
	releaseRetry := make(chan struct{})
	repaired := make(chan time.Time, 1)
	watchFiles := []string{token}
	pathOwners := map[string][]string{token: owners}
	if failedFileEvent {
		watchFiles = append(watchFiles, failedToken)
		pathOwners[failedToken] = []string{enterpriseHookProtectedTargetKey(failing)}
	}
	calls := 0
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		calls++
		run := enterpriseHookReconcileRun{
			Rows: []enterpriseHookReconcileRow{failing, healthy}, Failures: 1,
			WatchDirs: []string{filepath.Dir(token)}, WatchExclusiveFiles: watchFiles,
			WatchPathOwners: pathOwners,
		}
		if calls == 2 {
			close(retryStarted)
			select {
			case <-releaseRetry:
			case <-ctx.Done():
				return run, ctx.Err()
			}
		}
		if calls >= 3 {
			data, err := os.ReadFile(token)
			if err != nil {
				return run, err
			}
			if string(data) != issued {
				if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
					return run, err
				}
				run.Repairs = 1
				select {
				case repaired <- time.Now():
				default:
				}
			}
		}
		return run, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	var log bytes.Buffer
	cmd.SetErr(&log)
	done := make(chan error, 1)
	go func() { done <- runEnterpriseHooksWatch(cmd, nil) }()
	if failedFileEvent {
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("guardian exited before file event: %v; log: %s", err, log.String())
		case <-time.After(4 * time.Second):
			t.Fatal("guardian did not start watcher")
		}
		if err := os.WriteFile(failedToken, []byte("changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-retryStarted:
	case err := <-done:
		t.Fatalf("guardian exited before retry: %v; log: %s", err, log.String())
	case <-time.After(4 * time.Second):
		t.Fatal("guardian did not start the failed target's retry")
	}
	// The retry already checked Alice. Overwrite while Bob's retry is
	// finishing, so the pass snapshots the damaged token after the event.
	writtenAt := time.Now()
	if err := os.WriteFile(token, []byte("overwritten\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if retryHold > 0 {
		release := time.AfterFunc(retryHold, func() { close(releaseRetry) })
		defer release.Stop()
	} else {
		close(releaseRetry)
	}
	var repairedAt time.Time
	repairLimit := 3 * time.Second
	if failedFileEvent {
		repairLimit = 5 * time.Second
	}
	select {
	case repairedAt = <-repaired:
	case <-time.After(repairLimit):
		cancel()
		<-done
		t.Fatalf("healthy token waited for the failing target's pass; log: %s", log.String())
	}
	data, err := os.ReadFile(token)
	if err != nil || string(data) != issued {
		t.Fatalf("token after event repair = %q, %v", data, err)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("guardian exit: %v", err)
	}
	if retryHold > 0 && repairedAt.Sub(writtenAt) >= 5*time.Second {
		t.Fatalf("healthy token repair took %s; limit five seconds; log: %s", repairedAt.Sub(writtenAt), log.String())
	}
	// The guardian logs the trigger path quoted (%q): on Windows its
	// backslashes are escaped, so match the quoted form on every platform.
	if !strings.Contains(log.String(), "reconcile reason=fsnotify") || !strings.Contains(log.String(), "trigger_path="+strconv.Quote(token)) {
		t.Fatalf("repair was not attributed to the token fsnotify event; log: %s", log.String())
	}
}
