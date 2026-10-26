//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// A worker blocked in an uninterruptible file system call (a stalled FUSE
// mount in the home) survives SIGKILL and cannot be reaped. The caller must
// stop waiting for it, report the account not inspected, and not start a
// second worker for it while the first is stuck (GAP-1468, GAP-1470).
func TestEnterpriseHookWorkerThatCannotBeReapedIsAbandoned(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "sleep")
	release := make(chan struct{})
	origWait, origGrace := enterpriseHookWorkerWait, enterpriseHookWorkerAbandonGrace
	enterpriseHookWorkerAbandonGrace = 200 * time.Millisecond
	enterpriseHookWorkerWait = func(cmd *exec.Cmd) error {
		<-release
		return cmd.Wait()
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		enterpriseHookWorkerWait, enterpriseHookWorkerAbandonGrace = origWait, origGrace
	})
	account := selfWorkerAccount(t)
	request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpDiscover, Standalone: true, Connectors: []string{"codex"}, TimeoutSeconds: 1}

	run := func() (time.Duration, error) {
		type answer struct{ err error }
		done := make(chan answer, 1)
		start := time.Now()
		go func() {
			_, err := runEnterpriseHookWorker(context.Background(), account, request)
			done <- answer{err}
		}()
		select {
		case got := <-done:
			return time.Since(start), got.err
		case <-time.After(15 * time.Second):
			t.Fatal("runEnterpriseHookWorker still waits for a killed worker that cannot be reaped 15 s after its 1 s timeout")
			return 0, nil
		}
	}
	elapsed, err := run()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed > 8*time.Second {
		t.Fatalf("answered after %s", elapsed)
	}
	if !enterpriseHookWorkersStuck.has(account.UID) {
		t.Fatal("the account is not marked as having a stuck worker")
	}
	// No second worker while the first is stuck: the next cycle answers at once.
	elapsed, err = run()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || elapsed > time.Second {
		t.Fatalf("second run: err = %v after %s, want an immediate not-inspected answer", err, elapsed)
	}
	// Once the stuck worker is reaped, the account is inspected again.
	released = true
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for enterpriseHookWorkersStuck.has(account.UID) {
		if time.Now().After(deadline) {
			t.Fatal("the account stays stuck after its worker exited")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
