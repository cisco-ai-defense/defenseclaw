// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-1850: a Codex probe that runs out of time returns at once and takes its
// child with it, even when that child holds stderr open (the npm launcher's
// native codex binary).
func TestInspectCodexPolicyWithAppServerKillsTheProbeTreeOnTimeout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	original := codexAppServerCommand
	t.Cleanup(func() { codexAppServerCommand = original })
	codexAppServerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", `sleep 30 & echo $! > "$1"; wait`, "sh", pidFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, err := inspectCodexPolicyWithAppServer(ctx, "codex", t.TempDir()); err == nil {
		t.Fatal("a probe that never answers must fail")
	}
	if elapsed := time.Since(began); elapsed > 10*time.Second {
		t.Fatalf("probe returned after %s: its child kept it waiting", elapsed)
	}
	body, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || pid <= 0 {
		t.Fatalf("child pid %q: %v", body, err)
	}
	for i := 0; i < 50; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("probe child %d still runs after the probe timed out", pid)
}
