//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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
	var output bytes.Buffer
	child.Stdout = &output
	start := time.Now()
	err := runWindowsEnterprisePowerShellChild(child)
	if !errors.Is(err, exec.ErrWaitDelay) || time.Since(start) > 4*time.Second || !strings.Contains(output.String(), "pipe held") {
		t.Fatalf("child wait = %v after %s, output %q", err, time.Since(start), output.String())
	}
}

// The child runs through the same engine and runner as the standalone
// installer (runWindowsEnterprisePowerShell7): the engine builds it with
// exec.CommandContext, so the runner may set Cancel, and only the clean
// Wait releases the kill-on-close job that would end the grandchild. The
// runner only swaps PowerShell's arguments for this test's helper role.
func TestWindowsEnterprisePowerShellChildPreservesDetachedGrandchildAfterCleanWait(t *testing.T) {
	const run = "-test.run=^TestWindowsEnterprisePowerShellChildPreservesDetachedGrandchildAfterCleanWait$"
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv("DC_ENTERPRISE_DETACHED_HELPER") {
	case "parent":
		grandchild := exec.Command(self, run)
		grandchild.Env = append(os.Environ(), "DC_ENTERPRISE_DETACHED_HELPER=grandchild")
		grandchild.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags:    windows.DETACHED_PROCESS,
			NoInheritHandles: true,
		}
		if err := grandchild.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintf(os.Stdout, "grandchild_pid=%d\n", grandchild.Process.Pid)
		os.Exit(0)
	case "grandchild":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := &cobra.Command{}
	var stdout, stderr bytes.Buffer
	capture, err := runWindowsEnterprisePowerShellEngineWithRunner(ctx, command, self,
		func(string) ([]string, error) { return os.Environ(), nil }, "unused-installer.ps1", nil,
		&stdout, &stderr, true, func(child *exec.Cmd) error {
			// exec.CommandContext installs a default Cancel; exec.Command
			// leaves it nil, and the runner's Cancel would then fail Start.
			if child.Cancel == nil {
				t.Error("the engine did not build the child with exec.CommandContext")
			}
			child.Args = []string{self, run}
			child.Env = append(child.Env, "DC_ENTERPRISE_DETACHED_HELPER=parent")
			return runWindowsEnterprisePowerShellChild(child)
		})
	match := regexp.MustCompile(`grandchild_pid=(\d+)`).FindStringSubmatch(stdout.String())
	if len(match) != 2 {
		t.Fatalf("grandchild PID missing after child wait %v from %q (stderr %q)", err, stdout.String(), stderr.String())
	}
	pid, _ := strconv.ParseUint(match[1], 10, 32)
	handle, openErr := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if openErr != nil {
		t.Fatalf("open detached grandchild %d after child wait %v: %v", pid, err, openErr)
	}
	t.Cleanup(func() {
		_ = windows.TerminateProcess(handle, 1)
		_, _ = windows.WaitForSingleObject(handle, 2000)
		_ = windows.CloseHandle(handle)
	})
	if err != nil {
		t.Fatalf("clean child wait: %v", err)
	}
	if capture == nil || capture.pipeWaitDelayed {
		t.Fatal("the clean child wait was reported as a delayed pipe")
	}
	state, waitErr := windows.WaitForSingleObject(handle, 0)
	if waitErr != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("detached grandchild %d did not survive clean wait: state %d, error %v", pid, state, waitErr)
	}
}

func TestWindowsEnterprisePowerShellEngineMapsDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	runner := func(child *exec.Cmd) error {
		if child.WaitDelay != 0 {
			t.Fatal("standalone WaitDelay was applied in the shared engine")
		}
		return ctx.Err()
	}
	command := &cobra.Command{}
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	_, err := runWindowsEnterprisePowerShellEngineWithRunner(ctx, command, "unused-powershell.exe",
		func(string) ([]string, error) { return os.Environ(), nil }, "unused-installer.ps1", nil,
		&bytes.Buffer{}, &bytes.Buffer{}, true, runner)
	if err == nil || !strings.Contains(err.Error(), "lifecycle_timeout") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("engine deadline mapping = %v", err)
	}
}

func TestWindowsEnterpriseSuccessfulPowerShellWaitDelayIsWarning(t *testing.T) {
	switch os.Getenv("DC_ENTERPRISE_SUCCESS_HELPER") {
	case "parent":
		grandchild := exec.Command(os.Args[0], "-test.run=^TestWindowsEnterpriseSuccessfulPowerShellWaitDelayIsWarning$")
		grandchild.Env = append(os.Environ(), "DC_ENTERPRISE_SUCCESS_HELPER=grandchild")
		grandchild.Stdout = os.Stdout
		if err := grandchild.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("{\"schema_version\":1,\"ok\":true}\n")
		os.Exit(0)
	case "grandchild":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture, err := runWindowsEnterprisePowerShellEngineWithRunner(ctx, cmd, os.Args[0],
		func(string) ([]string, error) { return os.Environ(), nil }, "unused-installer.ps1", nil,
		&output, io.Discard, true, func(child *exec.Cmd) error {
			child.Args = []string{os.Args[0], "-test.run=^TestWindowsEnterpriseSuccessfulPowerShellWaitDelayIsWarning$"}
			child.Env = append(child.Env, "DC_ENTERPRISE_SUCCESS_HELPER=parent")
			return runWindowsEnterprisePowerShellChild(child)
		})
	if err != nil || capture == nil || !capture.pipeWaitDelayed || !strings.Contains(output.String(), `"ok":true`) {
		t.Fatalf("successful PowerShell pipe wait = %v, capture = %+v, output = %q", err, capture, output.String())
	}
}

func TestWindowsEnterpriseDeadlineKillsGrandchildHoldingPipe(t *testing.T) {
	switch os.Getenv("DC_ENTERPRISE_DEADLINE_HELPER") {
	case "parent":
		grandchild := exec.Command(os.Args[0], "-test.run=^TestWindowsEnterpriseDeadlineKillsGrandchildHoldingPipe$")
		grandchild.Env = append(os.Environ(), "DC_ENTERPRISE_DEADLINE_HELPER=grandchild")
		grandchild.Stdout = os.Stdout
		if err := grandchild.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintf(os.Stdout, "grandchild_pid=%d\n", grandchild.Process.Pid)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "grandchild":
		_, _ = os.Stdout.WriteString("pipe held\n")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	const deadline = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsEnterpriseDeadlineKillsGrandchildHoldingPipe$")
	child.Env = append(os.Environ(), "DC_ENTERPRISE_DEADLINE_HELPER=parent")
	var output bytes.Buffer
	child.Stdout = &output
	start := time.Now()
	err := runWindowsEnterprisePowerShellChild(child)
	if err == nil || time.Since(start) > deadline+2*time.Second+time.Second {
		t.Fatalf("deadline run = %v after %s, output %q", err, time.Since(start), output.String())
	}
	match := regexp.MustCompile(`grandchild_pid=(\d+)`).FindStringSubmatch(output.String())
	if len(match) != 2 {
		t.Fatalf("grandchild PID missing from %q", output.String())
	}
	pid, _ := strconv.ParseUint(match[1], 10, 32)
	handle, openErr := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(openErr, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if openErr != nil {
		t.Fatalf("inspect grandchild %d: %v", pid, openErr)
	}
	defer windows.CloseHandle(handle)
	state, waitErr := windows.WaitForSingleObject(handle, 2000)
	if waitErr != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("grandchild %d survived closed job: wait state %d, error %v", pid, state, waitErr)
	}
}

func TestWindowsEnterprisePhaseFilterKeepsErrorsAndHidesPhases(t *testing.T) {
	var console bytes.Buffer
	var raw windowsEnterpriseOutputCapture
	filter := &windowsEnterprisePhaseFilter{writer: &console}
	for _, part := range []string{"DC_LIFE", "CYCLE_PHASE: stop service\r\nreal error: access denied\r\nDC_LIFECYCLE_PHASE: cleanup", "\nlast error\n"} {
		if _, err := io.MultiWriter(&raw, filter).Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if err := filter.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(console.String(), "DC_LIFECYCLE_PHASE") || !strings.Contains(console.String(), "real error: access denied") || !strings.Contains(console.String(), "last error") {
		t.Fatalf("console stderr = %q", console.String())
	}
	if phases := windowsEnterpriseTimeoutPhases(raw.buffer.Bytes()); phases != "stop service | cleanup" {
		t.Fatalf("diagnostic phases = %q", phases)
	}
}

func TestWindowsEnterprisePipeWaitWarningReachesResult(t *testing.T) {
	original := windowsEnterpriseStandaloneRunner
	t.Cleanup(func() { windowsEnterpriseStandaloneRunner = original })
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		return windowsEnterpriseStandaloneRun{
			Output:          []byte(`{"schema_version":1,"ok":true,"action":"install","installed":true}`),
			PipeWaitDelayed: true, PhaseLines: []string{"DC_LIFECYCLE_PHASE: stop gateway"},
		}, nil
	}
	opts := &windowsEnterpriseLifecycleOptions{}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(context.Background(), &cobra.Command{}, opts, "unused.ps1", nil)
	if err != nil || report == nil || !report.OK || run.ExitCode != 0 || !opts.powerShellPipeWaitDelayed ||
		len(opts.diagnostics) != 1 || opts.diagnostics[0] != "DC_LIFECYCLE_PHASE: stop gateway" {
		t.Fatalf("successful standalone run = %+v, %+v, %v, opts = %+v", report, run, err, opts)
	}
	result := &enterprisestatus.Result{}
	addWindowsEnterprisePipeWaitWarning(result, opts)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "installer_pipe_wait_delayed" {
		t.Fatalf("result warnings = %+v", result.Warnings)
	}
	bounded := &windowsEnterpriseLifecycleOptions{diagnostics: make([]string, windowsEnterpriseEnsureDiagnosticsLimit)}
	if _, _, err := runWindowsEnterpriseStandaloneInstaller(context.Background(), &cobra.Command{}, bounded, "unused.ps1", nil); err != nil {
		t.Fatal(err)
	}
	if len(bounded.diagnostics) != windowsEnterpriseEnsureDiagnosticsLimit {
		t.Fatalf("diagnostics exceeded limit: %d", len(bounded.diagnostics))
	}
}

func TestWindowsEnterpriseEnsureCommittedPipeWaitDoesNotRestoreStartModes(t *testing.T) {
	failedVerify := installedStatus("verify")
	failedVerify["ok"] = false
	failedVerify["errors"] = []string{"managed path is missing: hook binary"}
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), failedVerify, installedStatus("repair")}}
	stub.install(t)
	baseRunner := windowsEnterpriseStandaloneRunner
	windowsEnterpriseStandaloneRunner = func(ctx context.Context, cmd *cobra.Command, script string, args []string) (windowsEnterpriseStandaloneRun, error) {
		run, err := baseRunner(ctx, cmd, script, args)
		if windowsEnterpriseInstallerAction(args) == "Repair" {
			run.PipeWaitDelayed = true
		}
		return run, err
	}
	originalRestore := windowsEnterpriseRestoreStartModes
	t.Cleanup(func() { windowsEnterpriseRestoreStartModes = originalRestore })
	windowsEnterpriseRestoreStartModes = func(*windowsEnterpriseInstallerReport) error {
		t.Fatal("committed repair with a successful pipe wait restored start modes")
		return nil
	}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(io.Discard)
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, ensureTestOptions(), "unused.ps1"); err != nil {
		t.Fatalf("ensure: %v, output %q", err, output.String())
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) == 0 || !slices.ContainsFunc(result.Warnings, func(message enterprisestatus.Message) bool {
		return message.Code == "installer_pipe_wait_delayed"
	}) {
		t.Fatalf("result missing pipe wait warning: %+v", result.Warnings)
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
