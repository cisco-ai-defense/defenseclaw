//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/spf13/cobra"
)

type gap0523LogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *gap0523LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *gap0523LogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func gap0523RetryFixture(t *testing.T) (*standaloneFixture, map[string]bool, *sync.Mutex, map[string]int, enterpriseHookReconcileRun) {
	t.Helper()
	accounts := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, accounts)
	targets := make([]enterprisehooks.ManifestTarget, 0, 13)
	failing := map[string]bool{}
	for i := 0; i < 13; i++ {
		name := fmt.Sprintf("account%02d", i)
		home := f.home(t, name, 0o700)
		uid, gid := 5000+i, 5000+i
		if i == 12 && os.Getuid() != 0 {
			// The watch-loop test needs one home whose ownership checks
			// permit an actual fsnotify watch on its token.
			uid, gid = os.Getuid(), os.Getgid()
		}
		accounts.accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/sh"}
		targets = append(targets, enterprisehooks.ManifestTarget{User: name, Connector: "hermes"})
		failing[name] = i < 10
	}
	f.writeManifest(t, targets...)
	checkHome := enterpriseHookCheckHome
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	t.Cleanup(func() { enterpriseHookCheckHome = checkHome })
	var mu sync.Mutex
	attempts := map[string]int{}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		attempts[account.User]++
		fail := failing[account.User]
		mu.Unlock()
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			result := enterpriseHookWorkerTargetResult{Index: target.Index}
			if fail {
				result.Error = "repair pending"
			} else {
				result.OK = true
				result.Repaired = true
				result.Result = &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome}
			}
			response.Targets = append(response.Targets, result)
		}
		return response, nil
	}
	prior, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prior.Failures != 10 {
		t.Fatalf("initial failures = %d, want 10", prior.Failures)
	}
	mu.Lock()
	clear(attempts)
	mu.Unlock()
	return f, failing, &mu, attempts, prior
}

func gap0523FilesystemPass(t *testing.T, prior enterpriseHookReconcileRun, event string) enterpriseHookReconcileRun {
	t.Helper()
	previousWindow, previousPaths, previousAll := enterpriseHookReconcileRecheckWindow, enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll
	t.Cleanup(func() {
		enterpriseHookReconcileRecheckWindow, enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = previousWindow, previousPaths, previousAll
	})
	enterpriseHookReconcileRecheckWindow = 100 * time.Millisecond
	enterpriseHookReconcileRecheckPaths = []string{event}
	enterpriseHookReconcileRecheckAll = false
	ctx := context.WithValue(context.Background(), enterpriseHookWatchPriorRunKey{}, prior)
	run, err := runEnterpriseHookReconcileOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestGAP0523HealthyRepairDoesNotWaitForTenFailedAccounts(t *testing.T) {
	f, _, mu, attempts, prior := gap0523RetryFixture(t)
	event := filepath.Join(f.homes, "account12", ".defenseclaw", "hooks", ".hook-hermes.token")
	run := gap0523FilesystemPass(t, prior, event)
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 3 || attempts["account12"] != 1 || run.Failures != 10 || run.Repairs != 3 {
		t.Fatalf("filesystem pass: worker attempts=%v failures=%d repairs=%d", attempts, run.Failures, run.Repairs)
	}
}

func TestGAP0523FailedAccountEventAndRetryStillRun(t *testing.T) {
	f, failing, mu, attempts, prior := gap0523RetryFixture(t)
	mu.Lock()
	failing["account00"] = false
	mu.Unlock()
	event := filepath.Join(f.homes, "account00", ".defenseclaw", "hooks", ".hook-hermes.token")
	run := gap0523FilesystemPass(t, prior, event)
	mu.Lock()
	if attempts["account00"] != 1 || run.Failures != 9 {
		mu.Unlock()
		t.Fatalf("own event: worker attempts=%v failures=%d", attempts, run.Failures)
	}
	clear(attempts)
	mu.Unlock()
	enterpriseHookReconcileRecheckWindow = 0
	enterpriseHookReconcileRecheckPaths = nil
	if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 13 {
		t.Fatalf("retry checked %d accounts, want 13", len(attempts))
	}
}

func TestGAP0523ThirteenAccountWatchRepairsDuringSlowRetry(t *testing.T) {
	testGAP0523ThirteenAccountWatchRepairsDuringSlowPass(t, false)
}

func TestGAP0523ThirteenAccountWatchRepairsDuringSlowInterval(t *testing.T) {
	testGAP0523ThirteenAccountWatchRepairsDuringSlowPass(t, true)
}

func testGAP0523ThirteenAccountWatchRepairsDuringSlowPass(t *testing.T, interval bool) {
	if os.Getuid() == 0 {
		t.Skip("the watched fixture home needs a non-root owner")
	}
	f, failing, _, _, _ := gap0523RetryFixture(t)
	token := filepath.Join(f.homes, "account12", ".defenseclaw", "hooks", ".hook-hermes.token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	const issued = "issued\n"
	if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
		t.Fatal(err)
	}
	previousReconcile, previousPlatformWatch := enterpriseHookWatchReconcileOnce, enterpriseHookWatchPlatformWatch
	previousBefore, previousAfter := enterpriseHookBeforeWatchReconcile, enterpriseHookAfterWatchReconcile
	previousInterval, previousDebounce := enterpriseHookWatchInterval, enterpriseHookWatchDebounce
	previousRetryMin, previousRetryMax := enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax
	t.Cleanup(func() {
		enterpriseHookWatchReconcileOnce, enterpriseHookWatchPlatformWatch = previousReconcile, previousPlatformWatch
		enterpriseHookBeforeWatchReconcile, enterpriseHookAfterWatchReconcile = previousBefore, previousAfter
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce = previousInterval, previousDebounce
		enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax = previousRetryMin, previousRetryMax
	})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) {}
	enterpriseHookBeforeWatchReconcile = func(io.Writer) {}
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 50 * time.Millisecond
	enterpriseHookWatchRepairRetryMin = 100 * time.Millisecond
	enterpriseHookWatchRepairRetryMax = time.Second
	if interval {
		enterpriseHookWatchInterval = 100 * time.Millisecond
		enterpriseHookWatchRepairRetryMin = time.Minute
		enterpriseHookWatchRepairRetryMax = time.Minute
	}
	var phase atomic.Int32
	var canceledRetryPublished atomic.Bool
	blocking := make(chan struct{}, 1)
	checked := make(chan struct{}, 1)
	repaired := make(chan time.Time, 1)
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		phase.Add(1)
		return runEnterpriseHookReconcileOnce(ctx)
	}
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, w io.Writer, run enterpriseHookReconcileRun) {
		previousAfter(ctx, w, run)
		if phase.Load() == 2 {
			canceledRetryPublished.Store(true)
		}
		if phase.Load() >= 3 && run.Repairs > 0 {
			select {
			case repaired <- time.Now():
			default:
			}
		}
	}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if phase.Load() == 2 && account.User == "account00" {
			select {
			case blocking <- struct{}{}:
			default:
			}
			select {
			case <-ctx.Done():
				return enterpriseHookWorkerResponse{}, ctx.Err()
			case <-time.After(5200 * time.Millisecond):
			}
		}
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			result := enterpriseHookWorkerTargetResult{Index: target.Index}
			if failing[account.User] {
				result.Error = "repair pending"
			} else {
				result.OK, result.Repaired = true, true
				result.Result = &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome}
				if account.User == "account12" {
					if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
						return response, err
					}
				}
			}
			response.Targets = append(response.Targets, result)
		}
		if phase.Load() == 2 && account.User == "account12" {
			select {
			case checked <- struct{}{}:
			default:
			}
		}
		return response, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	var log gap0523LogBuffer
	cmd.SetErr(&log)
	done := make(chan struct{})
	var watchErr error
	go func() { watchErr = runEnterpriseHooksWatch(cmd, nil); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if watchErr != nil && !errors.Is(watchErr, context.Canceled) {
				t.Errorf("guardian exit: %v", watchErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("guardian did not stop")
		}
	})
	for _, ch := range []<-chan struct{}{blocking, checked} {
		select {
		case <-ch:
		case <-done:
			t.Fatalf("guardian stopped before retry: %v", watchErr)
		case <-time.After(4 * time.Second):
			t.Fatal("retry did not inspect the expected accounts")
		}
	}
	writtenAt := time.Now()
	if err := os.WriteFile(token, []byte("overwritten\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var repairedAt time.Time
	select {
	case repairedAt = <-repaired:
	case <-time.After(6 * time.Second):
		t.Fatalf("healthy token was not repaired during retry; log: %s", log.String())
	}
	if elapsed := repairedAt.Sub(writtenAt); elapsed >= 5*time.Second {
		t.Fatalf("healthy token repair took %s; limit five seconds; log: %s", elapsed, log.String())
	}
	if data, err := os.ReadFile(token); err != nil || string(data) != issued {
		t.Fatalf("token after repair = %q, %v", data, err)
	}
	cancel()
	<-done
	if canceledRetryPublished.Load() {
		t.Fatal("a canceled retry published its partial result")
	}
	if !strings.Contains(log.String(), "reconcile reason=fsnotify") || !strings.Contains(log.String(), "trigger_path="+strconv.Quote(token)) {
		t.Fatalf("repair was not attributed to the filesystem event; log: %s", log.String())
	}
}
