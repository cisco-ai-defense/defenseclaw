// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A Copilot registration that outlives its deployment (an uninstall that
// could not act as a signed-out user, a package removed under a running
// Copilot) is inert: with the hook binary and the gateway binary beside it
// both gone, the command exits 0 and Copilot runs the call. Copilot denies
// every call whose hook fails, so the dangling command made the account
// unusable (GAP-1043, GAP-0999). With the deployment still installed and
// only the hook binary missing (a quarantine), the command still fails, so
// Copilot denies (GAP-0935).
func TestCopilotRegistrationIsInertOnlyOnceTheDeploymentIsRemoved(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "defenseclaw-hook")
	marker := filepath.Join(dir, "defenseclaw-gateway")
	if runtime.GOOS == "windows" {
		hook, marker = hook+".exe", marker+".exe"
	}
	command := CopilotVSCodeLocalManagedHookCommand(runtime.GOOS, hook, "PreToolUse")
	runCommand := func() int {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			fields := strings.Fields(command)
			cmd = exec.Command(fields[0], fields[1:]...)
		} else {
			cmd = exec.Command("/bin/sh", "-c", command)
		}
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
		err := cmd.Run()
		if cmd.ProcessState == nil {
			t.Fatalf("run %q: %v", command, err)
		}
		return cmd.ProcessState.ExitCode()
	}
	if code := runCommand(); code != 0 {
		t.Fatalf("removed deployment: exit %d, want 0 (inert)", code)
	}
	if err := os.WriteFile(marker, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := runCommand(); code == 0 {
		t.Fatal("installed deployment with its hook binary missing: exit 0, want a failure Copilot denies")
	}
}
