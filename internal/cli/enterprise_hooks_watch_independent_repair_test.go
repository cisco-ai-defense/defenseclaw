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
			testEnterpriseHookWatchRepairBeforeOtherRetry(t, shared)
		})
	}
}

func testEnterpriseHookWatchRepairBeforeOtherRetry(t *testing.T, shared bool) {
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
	cfg = &config.Config{DataDir: dir}
	enterpriseHookManifest = filepath.Join(dir, "targets.yaml")
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 50 * time.Millisecond
	enterpriseHookWatchSettle = 2 * time.Second
	enterpriseHookWatchRepairRetryMin = 2 * time.Second
	enterpriseHookWatchRepairRetryMax = 15 * time.Second
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) {}
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
	repaired := make(chan struct{}, 1)
	calls := 0
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		calls++
		run := enterpriseHookReconcileRun{
			Rows: []enterpriseHookReconcileRow{failing, healthy}, Failures: 1,
			WatchDirs: []string{filepath.Dir(token)}, WatchExclusiveFiles: []string{token},
			WatchPathOwners: map[string][]string{token: owners},
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
				case repaired <- struct{}{}:
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
	select {
	case <-retryStarted:
	case err := <-done:
		t.Fatalf("guardian exited before retry: %v; log: %s", err, log.String())
	case <-time.After(4 * time.Second):
		t.Fatal("guardian did not start the failed target's retry")
	}
	// The retry already checked Alice. Overwrite while Bob's retry is
	// finishing, so the pass snapshots the damaged token after the event.
	if err := os.WriteFile(token, []byte("overwritten\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	close(releaseRetry)
	select {
	case <-repaired:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatalf("healthy token waited for the failing target's retry; log: %s", log.String())
	}
	data, err := os.ReadFile(token)
	if err != nil || string(data) != issued {
		t.Fatalf("token after event repair = %q, %v", data, err)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("guardian exit: %v", err)
	}
	// The guardian logs the trigger path quoted (%q): on Windows its
	// backslashes are escaped, so match the quoted form on every platform.
	if !strings.Contains(log.String(), "reconcile reason=fsnotify") || !strings.Contains(log.String(), "trigger_path="+strconv.Quote(token)) {
		t.Fatalf("repair was not attributed to the token fsnotify event; log: %s", log.String())
	}
}
