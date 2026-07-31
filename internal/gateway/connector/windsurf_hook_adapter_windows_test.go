// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func renderWindsurfAdapterForTest(t *testing.T, hookPath, failMode string) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/windsurf-hook.ps1")
	if err != nil {
		t.Fatalf("read Windsurf adapter template: %v", err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		HookBinaryPS:  strings.ReplaceAll(hookPath, "'", "''"),
		HookTimeoutMS: 2_000,
		FailMode:      failMode,
	})
	if err != nil {
		t.Fatalf("render Windsurf adapter: %v", err)
	}
	root := filepath.Join(t.TempDir(), "Windsurf Adapter's Root")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create adapter root: %v", err)
	}
	path := filepath.Join(root, "windsurf-hook.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write Windsurf adapter: %v", err)
	}
	return path
}

func copyWindsurfHookHelper(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	root := filepath.Join(t.TempDir(), "Packaged Hook's Root")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create helper root: %v", err)
	}
	target := filepath.Join(root, "defenseclaw-hook.exe")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatalf("open test executable: %v", err)
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatalf("create hook helper: %v", err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatalf("copy hook helper: %v", err)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("close hook helper: %v", err)
	}
	return target
}

func runWindsurfAdapterTest(
	t *testing.T,
	adapterPath, failMode string,
	exitCode int,
) (stdout, stderr string, gotExit int, elapsed time.Duration) {
	t.Helper()
	hookPath := copyWindsurfHookHelper(t)
	adapter := renderWindsurfAdapterForTest(t, hookPath, failMode)
	if adapterPath != "" {
		adapter = adapterPath
	}
	command := hookInvocationCommandFor(
		"windows",
		"windsurf",
		strings.TrimSuffix(adapter, ".ps1")+".sh",
	)
	// Keep this outer process watchdog comfortably above the adapter's rendered
	// two-second enforcement timeout. Hosted Windows can spend more than thirty
	// seconds starting PowerShell and scanning the copied test executable under
	// full-suite load; that startup time is outside the product timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		command,
	)
	cmd.Env = minimalWindowsHookTestEnvironment(
		windsurfAdapterHelperMode+"=result",
		windsurfAdapterExitCodeEnv+"="+strconv.Itoa(exitCode),
		"PSModuleAnalysisCachePath="+filepath.Join(t.TempDir(), "module-analysis-cache"),
	)
	cmd.Stdin = strings.NewReader(`{"source":"windsurf-adapter-probe"}`)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	started := time.Now()
	err := cmd.Run()
	elapsed = time.Since(started)
	if ctx.Err() != nil {
		t.Fatalf("Windsurf adapter exceeded deadline: %v", ctx.Err())
	}
	if err == nil {
		return out.String(), errOut.String(), 0, elapsed
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Windsurf adapter: %v", err)
	}
	return out.String(), errOut.String(), exitErr.ExitCode(), elapsed
}

func TestWindsurfPowerShellAdapterWaitsAndPropagatesExactProcessResult(t *testing.T) {
	const wantStdout = `{"continue":true,"source":"windsurf"}`
	const wantStderr = "windsurf helper stderr"
	for _, exitCode := range []int{0, 1, 2} {
		t.Run("exit-"+strconv.Itoa(exitCode), func(t *testing.T) {
			stdout, stderr, gotExit, elapsed := runWindsurfAdapterTest(t, "", "open", exitCode)
			if gotExit != exitCode {
				t.Fatalf("adapter exit = %d, want %d; stderr=%q", gotExit, exitCode, stderr)
			}
			if stdout != wantStdout {
				t.Fatalf("adapter stdout = %q, want exact %q", stdout, wantStdout)
			}
			if !strings.Contains(stderr, wantStderr) {
				t.Fatalf("adapter stderr = %q, want marker %q", stderr, wantStderr)
			}
			if elapsed < 300*time.Millisecond {
				t.Fatalf("adapter returned after %s before the packaged process exited", elapsed)
			}
		})
	}
}

func TestWindsurfPowerShellAdapterAvailabilityFailureUsesConfiguredPosture(t *testing.T) {
	for _, testCase := range []struct {
		failMode string
		wantExit int
	}{
		{failMode: "open", wantExit: 0},
		{failMode: "closed", wantExit: 2},
	} {
		t.Run(testCase.failMode, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing-defenseclaw-hook.exe")
			adapter := renderWindsurfAdapterForTest(t, missing, testCase.failMode)
			command := hookInvocationCommandFor(
				"windows",
				"windsurf",
				strings.TrimSuffix(adapter, ".ps1")+".sh",
			)
			cmd := exec.Command(
				"powershell.exe",
				"-NoLogo",
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				command,
			)
			cmd.Env = minimalWindowsHookTestEnvironment()
			cmd.Stdin = strings.NewReader(`{"source":"windsurf-adapter-probe"}`)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if got := windowsProcessExitCodeForTest(t, err); got != testCase.wantExit {
				t.Fatalf("adapter exit = %d, want %d; stderr=%q", got, testCase.wantExit, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("adapter failure stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "DefenseClaw Windsurf hook adapter:") {
				t.Fatalf("adapter failure stderr = %q, want bounded diagnostic", stderr.String())
			}
		})
	}
}
