// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

// GAP-0754: the guardian put a tampered managed hook file back but reported
// no repair. These run the production standalone reconcile and worker pool
// under the watch loop, with a worker that restores the file the way the real
// one does (rewrite, or recreate after a delete), for each kind of tamper and
// for a shared agent config whose repair keeps the user own settings.
func TestGAP0754GuardianReportsWhatItRestored(t *testing.T) {
	const script = "#!/bin/sh\nexec defenseclaw-hook\n"
	const config = "hooks:\n  command: managed\nmodel: old\n"
	for _, tc := range []struct {
		name    string
		rel     string
		initial string
		tamper  func(path string) error
		repair  string // what the worker leaves; "" = the initial bytes
		named   bool   // the pass also names the file: it went back to the verified bytes
	}{
		{"hook script, byte appended", filepath.Join(".defenseclaw", "hooks", "hermes-hook.sh"), script,
			func(p string) error { return os.WriteFile(p, []byte(script+"#\n"), 0o700) }, "", true},
		{"hook script, deleted", filepath.Join(".defenseclaw", "hooks", "hermes-hook.sh"), script, os.Remove, "", true},
		{"shared config, hook entry edited and a user setting changed", filepath.Join(".hermes", "config.yaml"), config,
			func(p string) error {
				return os.WriteFile(p, []byte("hooks:\n  command: bypass\nmodel: new\n"), 0o600)
			}, "hooks:\n  command: managed\nmodel: new\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, log, applies := startGAP0754RealGuardian(t, tc.rel, tc.initial, tc.repair)
			if err := tc.tamper(path); err != nil {
				t.Fatal(err)
			}
			want := "reconcile reason=fsnotify status=ok targets=1 pending=0 failures=0 repairs=1"
			pathTag := "repair_path=" + strconv.Quote(path)
			deadline := time.After(6 * time.Second)
			poll := time.NewTicker(10 * time.Millisecond)
			defer poll.Stop()
			for {
				for _, line := range strings.Split(log.String(), "\n") {
					if strings.Contains(line, want) {
						if (tc.named && !strings.Contains(line, pathTag)) || strings.Contains(line, "no_change=true") {
							t.Fatalf("restoring pass omitted its repair: %s", line)
						}
						return
					}
				}
				select {
				case <-poll.C:
				case <-deadline:
					t.Fatalf("the restore was never reported (GAP-0754); worker passes=%d log=%s", applies.Load(), log.String())
				}
			}
		})
	}
}

// Nothing changed, nothing is reported: a rewrite of the verified bytes is
// not a repair, so a quiet file adds no repairs=1 row.
func TestGAP0754RewriteWithTheVerifiedBytesReportsNoRepair(t *testing.T) {
	const script = "#!/bin/sh\nexec defenseclaw-hook\n"
	path, log, _ := startGAP0754RealGuardian(t, filepath.Join(".defenseclaw", "hooks", "hermes-hook.sh"), script, "")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if strings.Contains(log.String(), "repairs=1") {
		t.Fatalf("a rewrite with the verified bytes was reported as a repair: %s", log.String())
	}
}

// startGAP0754RealGuardian starts the watch loop over a fixture account whose
// only worker restores the file at rel once (on its second apply, the pass the
// tamper arms). It returns the file, the guardian log and the apply counter.
func startGAP0754RealGuardian(t *testing.T, rel, initial, repair string) (string, *gap0523LogBuffer, *atomic.Int32) {
	t.Helper()
	restoreEnterpriseHooksLifecycleTestState(t)
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: home, Shell: "/bin/sh"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", home, "hermes"))
	key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{key: {UID: os.Getuid(), Home: home}})
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if repair == "" {
		repair = initial
	}

	oldPlatform, oldScoped := enterpriseHookWatchPlatformWatch, enterpriseHookWatchTargetScoped
	oldReconcile, oldAfter := enterpriseHookWatchReconcileOnce, enterpriseHookAfterWatchReconcile
	oldInterval, oldDebounce, oldSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	oldRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() {
		enterpriseHookWatchPlatformWatch, enterpriseHookWatchTargetScoped = oldPlatform, oldScoped
		enterpriseHookWatchReconcileOnce, enterpriseHookAfterWatchReconcile = oldReconcile, oldAfter
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = oldInterval, oldDebounce, oldSettle
		enterpriseHookWorkerRunner = oldRunner
	})
	enterpriseHookWatchInterval = time.Minute
	enterpriseHookWatchDebounce = 80 * time.Millisecond
	enterpriseHookWatchSettle = 50 * time.Millisecond
	ready := make(chan struct{})
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { close(ready) }
	enterpriseHookWatchTargetScoped = func() bool { return true }
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		run, err := runEnterpriseHookReconcileOnce(ctx)
		// The fixture cannot create root-owned service state.
		run.StateErr = nil
		return run, err
	}
	enterpriseHookAfterWatchReconcile = func(context.Context, io.Writer, enterpriseHookReconcileRun) {}
	applies := &atomic.Int32{}
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		if request.Operation != enterpriseHookWorkerOpApply {
			return response, nil
		}
		repaired := false
		if applies.Add(1) == 2 {
			if body, err := os.ReadFile(path); err != nil || string(body) != repair {
				if err := os.WriteFile(path, []byte(repair), 0o600); err != nil {
					return response, err
				}
				repaired = true
				// The worker is still finishing when its own write is seen.
				time.Sleep(300 * time.Millisecond)
			}
		}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true, Repaired: repaired,
				Result: &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome},
			})
		}
		return response, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	log := &gap0523LogBuffer{}
	cmd.SetErr(log)
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
	// Past the settle window of the startup pass: the tamper is not its tail.
	time.Sleep(600 * time.Millisecond)
	return path, log, applies
}
