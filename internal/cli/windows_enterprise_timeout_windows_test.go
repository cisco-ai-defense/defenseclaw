//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

func TestWindowsEnterprisePowerShellChildBoundsInheritedPipe(t *testing.T) {
	switch os.Getenv("DC_ENTERPRISE_PIPE_HELPER") {
	case "parent":
		grandchild := exec.Command(os.Args[0], "-test.run=^TestWindowsEnterprisePowerShellChildBoundsInheritedPipe$")
		grandchild.Env = append(os.Environ(), "DC_ENTERPRISE_PIPE_HELPER=grandchild")
		grandchild.Stdout, grandchild.Stderr = os.Stdout, os.Stderr
		if err := grandchild.Start(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "grandchild":
		_, _ = os.Stdout.WriteString("pipe held\n")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsEnterprisePowerShellChildBoundsInheritedPipe$")
	child.Env = append(os.Environ(), "DC_ENTERPRISE_PIPE_HELPER=parent")
	child.WaitDelay = 200 * time.Millisecond
	var output bytes.Buffer
	child.Stdout = &output
	start := time.Now()
	err := runWindowsEnterprisePowerShellChild(child)
	if !errors.Is(err, exec.ErrWaitDelay) || time.Since(start) > 4*time.Second || !strings.Contains(output.String(), "pipe held") {
		t.Fatalf("child wait = %v after %s, output %q", err, time.Since(start), output.String())
	}
}

func TestWindowsEnterprisePowerShellEngineMapsDeadline(t *testing.T) {
	original := windowsEnterprisePowerShellChildRunner
	t.Cleanup(func() { windowsEnterprisePowerShellChildRunner = original })
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	windowsEnterprisePowerShellChildRunner = func(child *exec.Cmd) error {
		if child.WaitDelay == 0 {
			t.Fatal("engine did not bound inherited output pipes")
		}
		return ctx.Err()
	}
	command := &cobra.Command{}
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	_, err := runWindowsEnterprisePowerShellEngine(ctx, command, "unused-powershell.exe",
		func(string) ([]string, error) { return os.Environ(), nil }, "unused-installer.ps1", nil,
		&bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "lifecycle_timeout") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("engine deadline mapping = %v", err)
	}
}

func TestWindowsEnterpriseRestoreStartModeOnlyUndoesQuiesce(t *testing.T) {
	for _, input := range []struct {
		recorded string
		current  uint32
		want     uint32
		change   bool
	}{
		{"auto", windows.SERVICE_DISABLED, windows.SERVICE_AUTO_START, true},
		{"manual", windows.SERVICE_DISABLED, windows.SERVICE_DEMAND_START, true},
		{"disabled", windows.SERVICE_AUTO_START, 0, false},
		{"auto", windows.SERVICE_DEMAND_START, 0, false},
		{"unknown", windows.SERVICE_DISABLED, 0, false},
	} {
		got, change := windowsEnterpriseStartModeToRestore(input.recorded, input.current)
		if got != input.want || change != input.change {
			t.Fatalf("restore %q from %d = %d, %v", input.recorded, input.current, got, change)
		}
	}
}

func TestWindowsEnterpriseTimeoutPhasesRetainLastBoundedStages(t *testing.T) {
	stderr := []byte("ignored error with a path\nDC_LIFECYCLE_PHASE: 2026-10-14T21:19:00Z stop DefenseClawGateway wait\n")
	got := windowsEnterpriseTimeoutPhases(stderr)
	if got != "2026-10-14T21:19:00Z stop DefenseClawGateway wait" {
		t.Fatalf("timeout phase transcript = %q", got)
	}
}
