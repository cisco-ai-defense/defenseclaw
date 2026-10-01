// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const cursorAdapterHelperMode = "TEST_CURSOR_ADAPTER_MODE"
const cursorAdapterPIDFileEnv = "TEST_CURSOR_ADAPTER_PID_FILE"
const copilotAdapterHelperMode = "TEST_COPILOT_ADAPTER_MODE"
const copilotAdapterPIDFileEnv = "TEST_COPILOT_ADAPTER_PID_FILE"

func TestMain(m *testing.M) {
	switch os.Getenv(copilotAdapterHelperMode) {
	case "result":
		payload, err := io.ReadAll(os.Stdin)
		if err != nil || string(payload) != `{"source":"copilot-adapter-probe"}` {
			fmt.Fprintf(os.Stderr, "Copilot adapter helper received wrong stdin: %q\n", string(payload))
			os.Exit(6)
		}
		if strings.Join(os.Args[1:], "|") != "hook|--connector|copilot|--event|preToolUse" {
			fmt.Fprintln(os.Stderr, "Copilot adapter helper received unexpected arguments")
			os.Exit(5)
		}
		fmt.Print(`{"permissionDecision":"deny","permissionDecisionReason":"matched: test"}`)
		os.Exit(0)
	case "timeout":
		writeAdapterLauncherRecord(os.Getenv(copilotAdapterPIDFileEnv))
		// Outlive the contract so a launcher the adapter failed to kill cannot
		// end inside the deadline on its own.
		time.Sleep(2 * time.Duration(copilotWindowsHookContractTimeoutMS) * time.Millisecond)
		os.Exit(0)
	}
	switch os.Getenv(cursorAdapterHelperMode) {
	case "success":
		payload, err := io.ReadAll(os.Stdin)
		if err != nil || !bytes.Contains(payload, []byte("cursor-adapter-probe")) {
			fmt.Fprintln(os.Stderr, "adapter helper did not receive the expected stdin payload")
			os.Exit(3)
		}
		if strings.Join(os.Args[1:], "|") != "hook|--connector|cursor|--enterprise-managed" {
			fmt.Fprintln(os.Stderr, "adapter helper received unexpected arguments")
			os.Exit(4)
		}
		fmt.Print(`{"continue":true}`)
		os.Exit(0)
	case "block":
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Print(`{"continue":false,"permission":"deny"}`)
		os.Exit(2)
	case "timeout":
		writeAdapterLauncherRecord(os.Getenv(cursorAdapterPIDFileEnv))
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		// Pre-existing connector fixtures exercise config, trust, CAS, and
		// teardown behavior without provisioning a real Codex installation.
		// Dedicated production-path tests explicitly restore the native policy
		// inspector; external CLI/gateway/installer tests use protected evidence.
		codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
			return codexEffectivePolicy{Source: "connector unit-test policy fixture"}, nil
		}
		os.Exit(m.Run())
	}
}

// writeAdapterLauncherRecord records the helper launcher's PID and kernel
// creation time. Adapter budgets are measured from the moment the launcher
// exists: PowerShell's own startup is host-dependent and outside them.
func writeAdapterLauncherRecord(pidFile string) {
	if pidFile == "" {
		return
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		fmt.Fprintf(os.Stderr, "adapter helper could not read its creation time: %v\n", err)
		os.Exit(7)
	}
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d %d", os.Getpid(), creation.Nanoseconds())), 0o600)
}

func readAdapterLauncherRecord(t *testing.T, pidFile, stderr string) (uint32, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read helper PID: %v; stderr=%q", err, stderr)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Fatalf("helper record = %q, want PID and creation time", raw)
	}
	pid, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		t.Fatalf("parse helper PID: %v", err)
	}
	launchedNS, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		t.Fatalf("parse helper creation time: %v", err)
	}
	return uint32(pid), time.Unix(0, launchedNS)
}

func renderCopilotAdapterForTest(t *testing.T, hookPath string, timeoutMS int) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
	if err != nil {
		t.Fatalf("read Copilot adapter: %v", err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		HookBinaryPS:         strings.ReplaceAll(hookPath, "'", "''"),
		CopilotHookTimeoutMS: timeoutMS,
	})
	if err != nil {
		t.Fatalf("render Copilot adapter: %v", err)
	}
	path := filepath.Join(t.TempDir(), "copilot-hook.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write Copilot adapter: %v", err)
	}
	return path
}

func runCopilotAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	quoted := strings.ReplaceAll(adapterPath, "'", "''")
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"& '"+quoted+"' -Event 'preToolUse'",
	)
	cmd.Stdin = strings.NewReader(payload)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Copilot adapter: %v", err)
	}
	return out.String(), errOut.String(), exitErr.ExitCode()
}

func TestCopilotAdapterPreservesJSONInputAndDenyResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(copilotAdapterHelperMode, "result")
	adapter := renderCopilotAdapterForTest(t, executable, 10_000)
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stdout) != `{"permissionDecision":"deny","permissionDecisionReason":"matched: test"}` {
		t.Fatalf("stdout = %q, want exact Copilot deny JSON; stderr=%q", stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestCopilotAdapterFailureUsesDocumentedFailOpenContract(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCopilotAdapterForTest(t, missingHook, 10_000)
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty fail-open response", stdout)
	}
	if !strings.Contains(stderr, "Copilot hook adapter failed open") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCopilotAdapterProductionDeadlineKillsChildAndFailsOpen(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(copilotAdapterHelperMode, "timeout")
	t.Setenv(copilotAdapterPIDFileEnv, pidFile)
	adapter := renderCopilotAdapterForTest(t, executable, copilotWindowsHookAdapterTimeoutMS)
	startedAt := time.Now()
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// PowerShell 5.1 startup is host-dependent and deliberately outside the
	// adapter's budget (it restarts the deadline once the launcher exists), so
	// the timeout plus the kill/drain reserve must fit the contract from there.
	if elapsed := finishedAt.Sub(launchedAt); elapsed > time.Duration(copilotWindowsHookContractTimeoutMS)*time.Millisecond {
		t.Fatalf("adapter exceeded the Copilot command-hook deadline: %s after the launcher started (%s including PowerShell startup)", elapsed, finishedAt.Sub(startedAt))
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty fail-open response", stdout)
	}
	if !strings.Contains(stderr, fmt.Sprintf("timed out after %dms", copilotWindowsHookAdapterTimeoutMS)) {
		t.Fatalf("stderr = %q, want production timeout diagnostic", stderr)
	}
	if windowsProcessRunning(pid) {
		t.Fatalf("timed-out Copilot launcher process %d is still running", pid)
	}
}

func renderCursorAdapterForTest(t *testing.T, hookPath, failMode string, managed bool, timeoutMS int) string {
	t.Helper()
	rendered, err := renderWindowsCursorAdapter(hookPath, failMode, managed, timeoutMS)
	if err != nil {
		t.Fatalf("render Cursor adapter: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cursor-hook.ps1")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatalf("write Cursor adapter: %v", err)
	}
	return path
}

func runCursorAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	quoted := strings.ReplaceAll(adapterPath, "'", "''")
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$input | & '"+quoted+"'",
	)
	cmd.Stdin = strings.NewReader(payload)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Cursor adapter: %v", err)
	}
	return out.String(), errOut.String(), exitErr.ExitCode()
}

func assertCursorAllowJSON(t *testing.T, stdout string) {
	t.Helper()
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("Cursor adapter stdout is empty")
	}
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("Cursor adapter stdout is not valid JSON: %v", err)
	}
	if response["continue"] != true {
		t.Fatalf("Cursor adapter response = %#v, want continue=true", response)
	}
}

func windowsProcessRunning(pid uint32) bool {
	const stillActive = 259
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	return windows.GetExitCodeProcess(handle, &code) == nil && code == stillActive
}

func TestCursorAdapterPreservesSuccessfulLauncherResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestCursorAdapterTimeoutKillsChildThatDoesNotReadStdinAndFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(cursorAdapterHelperMode, "timeout")
	t.Setenv(cursorAdapterPIDFileEnv, pidFile)
	const timeoutMS = 1_000
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, timeoutMS)
	// Exceed the typical anonymous-pipe buffer so a synchronous stdin write
	// would remain stuck until the helper's 30-second sleep completed.
	payload := `{"source":"cursor-adapter-probe","padding":"` + strings.Repeat("x", 2<<20) + `"}`
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, payload,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// As in production, the timeout plus the cleanup reserve must fit from the
	// moment the launcher exists; PowerShell startup is outside the budget.
	if elapsed := finishedAt.Sub(launchedAt); elapsed > time.Duration(timeoutMS+cursorWindowsHookCleanupBudgetMS)*time.Millisecond {
		t.Fatalf("adapter exceeded bounded timeout: %s after the launcher started", elapsed)
	}
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("stdout = %q, want explicit deny", stdout)
	}
	if !strings.Contains(stderr, "timed out after 1000ms") {
		t.Fatalf("stderr = %q, want timeout diagnostic", stderr)
	}
	if windowsProcessRunning(pid) {
		t.Fatalf("timed-out Cursor launcher process %d is still running", pid)
	}
}

func TestCursorAdapterExceptionEmitsFailClosedJSON(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, "closed", true, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("stdout = %q, want explicit deny", stdout)
	}
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCursorAdapterExceptionFailsOpenOnlyWhenConfigured(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, "open", false, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCursorAdapterPreservesLauncherBlockResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "block")
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, 1_000)
	stdout, stderr, code := runCursorAdapterTest(t, adapter, `{"source":"cursor-adapter-probe"}`)
	if code != 2 || !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("block response=(code=%d stdout=%q stderr=%q), want exit 2 with deny", code, stdout, stderr)
	}
}
