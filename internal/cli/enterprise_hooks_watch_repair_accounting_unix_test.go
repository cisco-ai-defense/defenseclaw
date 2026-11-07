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

// A worker's write to an owned file is delivered through the same watcher
// as an account's write. The worker must finish its pass and publish the
// repair, while a later account write still gets its own pass.
func TestGAP0689ActiveWorkerWriteKeepsItsRepairPass(t *testing.T) {
	for _, name := range []string{".hook-hermes.token", "hermes-hook.sh"} {
		t.Run(name, func(t *testing.T) { testGAP0689ActiveWorkerWriteKeepsItsRepairPass(t, name, false) })
	}
}

func TestGAP0689ActiveWorkerReplaysRemainingDrift(t *testing.T) {
	testGAP0689ActiveWorkerWriteKeepsItsRepairPass(t, ".hook-hermes.token", true)
}

func testGAP0689ActiveWorkerWriteKeepsItsRepairPass(t *testing.T, name string, replay bool) {
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
	t.Cleanup(func() {
		enterpriseHookWatchPlatformWatch, enterpriseHookWatchTargetScoped = oldPlatform, oldScoped
		enterpriseHookWatchReconcileOnce, enterpriseHookAfterWatchReconcile = oldReconcile, oldAfter
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = oldInterval, oldDebounce, oldSettle
		enterpriseHookWatchObservedDrift = oldObserved
	})
	enterpriseHookWatchInterval = time.Minute
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
	var applies atomic.Int32
	enterpriseHookWorkerRunner = func(ctx context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		if request.Operation != enterpriseHookWorkerOpApply {
			return response, nil
		}
		call := applies.Add(1)
		if call == 2 {
			if err := os.WriteFile(token, []byte("partial\n"), 0o600); err != nil {
				return response, err
			}
			select {
			case <-observed:
			case <-time.After(3 * time.Second):
				return response, errors.New("watch did not observe the worker's write")
			}
			if !replay {
				if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
					return response, err
				}
			}
		} else if call == 3 && replay {
			if err := os.WriteFile(token, []byte(issued), 0o600); err != nil {
				return response, err
			}
		}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true, Repaired: (!replay && call == 2) || (replay && call == 3),
				RestoredElements: restoredElementsIf((!replay && call == 2) || (replay && call == 3)),
				Result:           &enterprisehooks.InstallResult{Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome},
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
	if err := os.WriteFile(token, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
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

func TestGAP0689ActiveWorkerScope(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "alice", ".defenseclaw", "hooks", "hermes-hook.sh")
	nestedOther := filepath.Join(root, "alice", "bob", "hook.sh")
	custom := filepath.Join(root, "custom", "hook.sh")
	ownKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"})
	otherKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "bob", Connector: "hermes"})
	active := newEnterpriseHookWatchActiveWorkers(enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{
			{User: "alice", UserHome: filepath.Join(root, "alice"), Connector: "hermes"},
			{User: "bob", UserHome: filepath.Join(root, "alice", "bob"), Connector: "hermes"},
		},
		WatchPathOwners: map[string][]string{
			own: {ownKey}, nestedOther: {otherKey}, custom: {ownKey},
		},
	})
	if got := active.targetKey(filepath.Join(root, "alice"), "alias", "hermes"); got != ownKey {
		t.Fatalf("worker target key = %q, want prior owner %q", got, ownKey)
	}
	active.start([]string{ownKey})
	activeOwn, _ := active.state(own)
	activeCustom, _ := active.state(custom)
	if !activeOwn || !activeCustom {
		t.Fatal("active account file was not recognized")
	}
	if otherActive, _ := active.state(nestedOther); otherActive {
		t.Fatal("nested other account was assigned to active worker")
	}
	active.finish([]string{ownKey}, nil)
	if stillActive, _ := active.state(own); stillActive {
		t.Fatal("finished account remained active")
	}
	active.start([]string{ownKey})
	active.finish([]string{ownKey}, []string{ownKey})
	_, repairedOwn := active.state(own)
	_, repairedOther := active.state(nestedOther)
	if !repairedOwn || repairedOther {
		t.Fatal("completed repair did not retain its account scope")
	}
}

// An unchanged owned file and a worker that reports no repair stay at zero.
func TestGAP0689UnchangedOwnedFileStaysNoChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hook-hermes.token")
	if err := os.WriteFile(path, []byte("issued\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := enterprisehooks.OwnedFileFingerprint(path)
	row := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", OK: true}
	key := enterpriseHookProtectedTargetKey(row)
	prior := enterpriseHookReconcileRun{Rows: []enterpriseHookReconcileRow{row}, WatchPathOwners: map[string][]string{path: {key}}}
	restored := enterpriseHookWatchRestoredOwnedFiles(prior,
		map[string]string{path: fingerprint}, map[string]string{path: fingerprint}, map[string]string{path: fingerprint},
		nil, nil, []string{path})
	if len(restored) != 0 || enterpriseHookReconcileChanged("same", "same", len(restored)) {
		t.Fatalf("unchanged file was reported repaired: %v", restored)
	}
}
