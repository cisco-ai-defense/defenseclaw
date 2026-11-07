//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/spf13/cobra"
)

// A changed owned file observed during an interval worker needs a prompt fsnotify pass.
func TestGAP0689IntervalConcurrentWriteReplaysFsnotify(t *testing.T) {
	for _, name := range []string{".hook-hermes.token", "hermes-hook.sh"} {
		t.Run(name, func(t *testing.T) { testGAP0689IntervalConcurrentWriteReplaysFsnotify(t, name, false) })
	}
}

func TestGAP0689RepeatedIntervalKeepsQueuedFsnotify(t *testing.T) {
	testGAP0689IntervalConcurrentWriteReplaysFsnotify(t, ".hook-hermes.token", true)
}

func testGAP0689IntervalConcurrentWriteReplaysFsnotify(t *testing.T, name string, repeatedInterval bool) {
	restoreEnterpriseHooksLifecycleTestState(t)
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: home, Shell: "/bin/sh"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", home, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: os.Getuid(), Home: home}})
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(hooks, name)
	const issued = "issued\n"
	if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPlatform, oldScoped := enterpriseHookWatchPlatformWatch, enterpriseHookWatchTargetScoped
	oldReconcile, oldAfter := enterpriseHookWatchReconcileOnce, enterpriseHookAfterWatchReconcile
	oldInterval, oldDebounce, oldSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	oldObserved := enterpriseHookWatchObservedDrift
	oldTicker := enterpriseHookWatchIntervalTicker
	t.Cleanup(func() {
		enterpriseHookWatchPlatformWatch, enterpriseHookWatchTargetScoped = oldPlatform, oldScoped
		enterpriseHookWatchReconcileOnce, enterpriseHookAfterWatchReconcile = oldReconcile, oldAfter
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = oldInterval, oldDebounce, oldSettle
		enterpriseHookWatchObservedDrift = oldObserved
		enterpriseHookWatchIntervalTicker = oldTicker
	})
	var intervalTick chan time.Time
	if repeatedInterval {
		enterpriseHookWatchInterval = 250 * time.Millisecond
	} else {
		enterpriseHookWatchInterval = time.Minute
		intervalTick = make(chan time.Time, 1)
		enterpriseHookWatchIntervalTicker = func(time.Duration) (<-chan time.Time, func()) {
			return intervalTick, func() {}
		}
	}
	enterpriseHookWatchDebounce = 80 * time.Millisecond
	enterpriseHookWatchSettle = 50 * time.Millisecond
	ready := make(chan struct{})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { close(ready) }
	enterpriseHookWatchTargetScoped = func() bool { return true }
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		run, err := runEnterpriseHookReconcileOnce(ctx)
		// The fixture cannot create root-owned service state. Keep the
		// production reconciliation and worker path under test.
		run.StateErr = nil
		return run, err
	}
	enterpriseHookAfterWatchReconcile = func(context.Context, io.Writer, enterpriseHookReconcileRun) {}
	observed := make(chan struct{}, 1)
	enterpriseHookWatchObservedDrift = func(path string) {
		if path == token {
			select {
			case observed <- struct{}{}:
			default:
			}
		}
	}
	tamperReady := make(chan struct{})
	tamperErr := make(chan error, 1)
	go func() {
		<-tamperReady
		tamperErr <- os.WriteFile(token, []byte("partial\n"), 0o600)
	}()
	var applies atomic.Int32
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		if request.Operation != enterpriseHookWorkerOpApply {
			return response, nil
		}
		call := applies.Add(1)
		switch call {
		case 2:
			close(tamperReady)
			if err := <-tamperErr; err != nil {
				return response, err
			}
			select {
			case <-observed:
			case <-time.After(3 * time.Second):
				return response, errors.New("watch did not observe the worker's write")
			}
			time.Sleep(150 * time.Millisecond)
		case 3:
			if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
				return response, err
			}
		}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true, Repaired: call == 3, RestoredElements: restoredElementsIf(call == 3),
				Result: &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome},
			})
		}
		_ = ctx
		return response, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	var log gap0523LogBuffer
	cmd.SetErr(&log)
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
		t.Fatalf("guardian exited during startup: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("guardian did not reach the watcher")
	}
	if intervalTick != nil {
		intervalTick <- time.Now()
	}
	want := "reconcile reason=fsnotify status=ok targets=1 pending=0 failures=0 repairs=1"
	pathTag := "repair_path=" + strconv.Quote(token)
	deadline := time.After(5 * time.Second)
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		lines := strings.Split(log.String(), "\n")
		for _, line := range lines {
			if strings.Contains(line, want) {
				if !strings.Contains(line, pathTag) || strings.Contains(line, "no_change=true") {
					t.Fatalf("restoring pass omitted its repair: %s", line)
				}
				return
			}
		}
		select {
		case <-poll.C:
		case <-deadline:
			t.Fatalf("no named repair; passes=%d log=%s", applies.Load(), log.String())
		}
	}
}
