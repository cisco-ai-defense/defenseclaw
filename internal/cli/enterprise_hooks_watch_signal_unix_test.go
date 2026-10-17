//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
)

const guardianWatchSignalChildRootEnv = "DEFENSECLAW_TEST_GUARDIAN_WATCH_SIGNAL_ROOT"

// TestGuardianWatchWithdrawsReadyOnSIGTERM is the #896 review regression for
// macOS and Linux: launchd and systemd stop the guardian with SIGTERM, and an
// unhandled SIGTERM ends a Go process without running deferred calls, so the
// last ready stayed on disk until guardianstate.ReadyMaxAge. The real watch
// loop runs in a child process (with only its per-cycle reconcile faked);
// after SIGTERM it must exit cleanly and leave waiting_for_targets.
func TestGuardianWatchWithdrawsReadyOnSIGTERM(t *testing.T) {
	if root := os.Getenv(guardianWatchSignalChildRootEnv); root != "" {
		runGuardianWatchSignalChild(t, root)
		return
	}
	root := t.TempDir()
	statePath := filepath.Join(root, "hook-guardian-state", guardianstate.FileName)
	child := exec.Command(os.Args[0], "-test.run=^TestGuardianWatchWithdrawsReadyOnSIGTERM$", "-test.count=1")
	child.Env = append(os.Environ(), guardianWatchSignalChildRootEnv+"="+root)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	stopChild := func() {
		_ = child.Process.Kill()
		<-done
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		body, err := os.ReadFile(statePath)
		if err == nil && strings.TrimSpace(string(body)) == guardianstate.StateReady {
			break
		}
		if time.Now().After(deadline) {
			stopChild()
			t.Fatalf("child guardian never published ready:\n%s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		stopChild()
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guardian watch after SIGTERM exited with %v, want a clean exit:\n%s", err, output.String())
		}
	case <-time.After(30 * time.Second):
		stopChild()
		t.Fatalf("guardian watch did not stop after SIGTERM:\n%s", output.String())
	}
	body, err := os.ReadFile(statePath)
	if err != nil || strings.TrimSpace(string(body)) != guardianstate.StateWaitingForTargets {
		t.Fatalf("readiness after SIGTERM = %q (%v), want waiting_for_targets:\n%s", body, err, output.String())
	}
}

func runGuardianWatchSignalChild(t *testing.T, root string) {
	newGuardianWatchReadinessFixtureAt(t, root)
	enterpriseHookWatchReconcileOnce = func(context.Context) (enterpriseHookReconcileRun, error) {
		return enterpriseHookReconcileRun{}, nil
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetErr(io.Discard)
	if err := runEnterpriseHooksWatch(cmd, nil); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("watch returned %v", err)
	}
}
