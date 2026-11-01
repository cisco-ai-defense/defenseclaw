// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-3 GAP-0276: a lifecycle run killed with its transaction pending
// left the hook guardian, the enumerator and the apply trigger stopped, and
// nothing started them again until an administrator ran verify, repair or
// the change again. A run now starts a watcher before it stops anything.
func TestTransactionStartsItsWatcherBeforeItStopsAService(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	var watched []string
	h.env.StartTransactionWatch = func(_ context.Context, pid int, snapshotDir string) error {
		pending, err := h.env.loadPending()
		if err != nil || pending == nil || pending.SnapshotDir != snapshotDir {
			t.Errorf("watcher started for %q without that intent written: %+v, %v", snapshotDir, pending, err)
		}
		if !h.services.isActive(unitGuardian) {
			t.Error("watcher started after the guardian was stopped")
		}
		if pid != os.Getpid() {
			t.Errorf("watcher pid = %d, want this run %d", pid, os.Getpid())
		}
		watched = append(watched, snapshotDir)
		return nil
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(watched) != 1 {
		t.Fatalf("watchers started = %v, want one for the repair transaction", watched)
	}
	if pending, _ := h.env.loadPending(); pending != nil {
		t.Fatalf("the finished run left its intent: %+v", pending)
	}
}

func TestTransactionWatcherStartsTheApplyTriggerWhenTheRunIsKilled(t *testing.T) {
	previous := transactionWatchPoll
	transactionWatchPoll = 10 * time.Millisecond
	t.Cleanup(func() { transactionWatchPoll = previous })
	for goos, want := range map[string]string{
		"linux":  "systemctl start --no-block " + unitApplyService,
		"darwin": "launchctl kickstart system/" + labelApply,
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			mkPendingDir(t, h)
			if err := h.env.savePending(&Pending{Action: ActionEnsure, SnapshotDir: "/snap/killed", Phase: "apply"}); err != nil {
				t.Fatal(err)
			}
			run := exec.Command("sleep", "60")
			if err := run.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- WatchTransaction(context.Background(), h.env, run.Process.Pid, "/snap/killed") }()
			time.Sleep(50 * time.Millisecond)
			if calls := h.calls(); strings.Contains(calls, want) {
				t.Fatalf("apply trigger started while the run is alive: %s", calls)
			}
			_ = run.Process.Kill()
			_ = run.Wait()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the watcher did not notice the killed run")
			}
			if calls := h.calls(); !strings.Contains(calls, want) {
				t.Fatalf("runner calls = %s, want %s", calls, want)
			}
		})
	}
}

func TestTransactionWatcherLeavesAFinishedTransactionAlone(t *testing.T) {
	previous := transactionWatchPoll
	transactionWatchPoll = 10 * time.Millisecond
	t.Cleanup(func() { transactionWatchPoll = previous })
	h := newTestHost(t, "linux")
	mkPendingDir(t, h)
	if err := h.env.savePending(&Pending{Action: ActionEnsure, SnapshotDir: "/snap/done", Phase: "activate"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- WatchTransaction(context.Background(), h.env, os.Getpid(), "/snap/done") }()
	time.Sleep(50 * time.Millisecond)
	if err := h.env.clearPending(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watcher kept waiting after the transaction finished")
	}
	if calls := h.calls(); strings.Contains(calls, unitApplyService) {
		t.Fatalf("a finished transaction started the apply trigger: %s", calls)
	}
	// Another transaction's intent is not this watcher's.
	if err := h.env.savePending(&Pending{Action: ActionEnsure, SnapshotDir: "/snap/next"}); err != nil {
		t.Fatal(err)
	}
	if err := WatchTransaction(context.Background(), h.env, 1<<30, "/snap/done"); err != nil {
		t.Fatal(err)
	}
	if calls := h.calls(); strings.Contains(calls, unitApplyService) {
		t.Fatalf("a watcher acted on another transaction: %s", calls)
	}
}

func mkPendingDir(t *testing.T, h *testHost) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.env.pendingPath()), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (h *testHost) calls() string {
	h.runner.mu.Lock()
	defer h.runner.mu.Unlock()
	return strings.Join(h.runner.calls, "\n")
}
