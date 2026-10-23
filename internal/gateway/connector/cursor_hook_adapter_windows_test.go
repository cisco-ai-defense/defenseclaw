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
	case "crash":
		// A launcher that dies without an answer (a panic exits 2).
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Fprintln(os.Stderr, "panic: copilot adapter probe")
		os.Exit(2)
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
		// Outlive the contract, as the Copilot helper does.
		time.Sleep(2 * time.Duration(cursorWindowsHookContractTimeoutMS) * time.Millisecond)
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

func renderCopilotAdapterForTest(t *testing.T, hookPath string, timeoutMS int, failMode string) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
	if err != nil {
		t.Fatalf("read Copilot adapter: %v", err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		FailMode:             failMode,
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
	adapter := renderCopilotAdapterForTest(t, executable, 10_000, "closed")
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

const copilotAdapterClosedDenial = `{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}`

// A closed fail mode (the per-user default) denies a tool call the adapter
// could not get checked: Copilot ignores a failed hook process, so an empty
// answer let the tool run.
func TestCopilotAdapterFailureDeniesAToolCallWhenClosed(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCopilotAdapterForTest(t, missingHook, 10_000, "closed")
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, `{"source":"copilot-adapter-probe"}`)
	if code != 0 || strings.TrimSpace(stdout) != copilotAdapterClosedDenial {
		t.Fatalf("exit %d stdout %q, want Copilot's denial; stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "Copilot hook adapter failed closed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

// A launcher that exits non-zero without an answer crashed; a closed mode
// denies the call.
func TestCopilotAdapterDeniesWhenTheLauncherCrashes(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(copilotAdapterHelperMode, "crash")
	adapter := renderCopilotAdapterForTest(t, executable, 10_000, "closed")
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, `{"source":"copilot-adapter-probe"}`)
	if code != 0 || strings.TrimSpace(stdout) != copilotAdapterClosedDenial {
		t.Fatalf("exit %d stdout %q, want Copilot's denial; stderr=%q", code, stdout, stderr)
	}
}

func TestCopilotAdapterFailureClosesLegacyPerUserOpen(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCopilotAdapterForTest(t, missingHook, 10_000, "open")
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want Copilot's stdout denial; stderr=%q", code, stderr)
	}
	if stdout != copilotAdapterClosedDenial {
		t.Fatalf("stdout = %q, want Copilot's denial", stdout)
	}
	if !strings.Contains(stderr, "Copilot hook adapter failed closed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCopilotAdapterProductionDeadlineKillsChildAndFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(copilotAdapterHelperMode, "timeout")
	t.Setenv(copilotAdapterPIDFileEnv, pidFile)
	adapter := renderCopilotAdapterForTest(t, executable, copilotWindowsHookAdapterTimeoutMS, "closed")
	startedAt := time.Now()
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// PowerShell 5.1 startup is host-dependent and deliberately outside the
	// adapter's budget (it restarts the deadline once the launcher exists), so
	// the timeout plus the kill/drain reserve must fit the contract from there.
	elapsed := finishedAt.Sub(launchedAt)
	// Hosted Windows runners can pause this test process after the adapter
	// has already exited. The timeout diagnostic and child liveness below
	// check the adapter behavior; this wall-clock guard allows that pause.
	if elapsed > time.Duration(copilotWindowsHookContractTimeoutMS+5_000)*time.Millisecond {
		t.Fatalf("adapter exceeded the Copilot command-hook deadline: %s after the launcher started (%s including PowerShell startup)", elapsed, finishedAt.Sub(startedAt))
	}
	t.Logf("adapter finished %s after the launcher started (%s including PowerShell startup)", elapsed, finishedAt.Sub(startedAt))
	if code != 0 || strings.TrimSpace(stdout) != copilotAdapterClosedDenial {
		t.Fatalf("exit %d stdout %q, want Copilot's denial; stderr=%q", code, stdout, stderr)
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

// windowsProcessRunning reports whether pid is still running after a short
// grace period. Kill only starts termination and the adapter waits for it
// with a bound, so the grace absorbs kernel teardown. Liveness comes from the
// process handle's signalled state, not GetExitCodeProcess, because a process
// may exit with STILL_ACTIVE (259). A PID that no longer exists counts as
// exited; any other open or wait failure counts as running so the caller's
// assertion fails safe.
func windowsProcessRunning(pid uint32) bool {
	const grace = 5 * time.Second
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, uint32(grace.Milliseconds()))
	return err != nil || result != windows.WAIT_OBJECT_0
}

func TestCursorAdapterPreservesSuccessfulLauncherResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	for _, mode := range []string{"closed", "open"} {
		t.Run(mode, func(t *testing.T) {
			// A cold Go test helper may take over a second to start on a
			// loaded Windows runner. This checks the successful response.
			adapter := renderCursorAdapterForTest(t, executable, mode, true, 5_000)
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
		})
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
	// Use the production deadline. A shorter one can expire before a starved
	// helper has recorded its PID, which leaves nothing to check.
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, cursorWindowsHookAdapterTimeoutMS)
	// Exceed the typical anonymous-pipe buffer so a synchronous stdin write
	// would remain stuck until the helper's sleep completed.
	payload := `{"source":"cursor-adapter-probe","padding":"` + strings.Repeat("x", 2<<20) + `"}`
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, payload,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// As for Copilot, the timeout plus the cleanup reserve must fit Cursor's
	// contract from the moment the launcher exists; PowerShell startup is
	// host-dependent and outside the adapter's budget.
	elapsed := finishedAt.Sub(launchedAt)
	if elapsed > time.Duration(cursorWindowsHookContractTimeoutMS)*time.Millisecond {
		t.Fatalf("adapter exceeded the Cursor command-hook deadline: %s after the launcher started", elapsed)
	}
	t.Logf("adapter finished %s after the launcher started", elapsed)
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("stdout = %q, want explicit deny", stdout)
	}
	if !strings.Contains(stderr, fmt.Sprintf("timed out after %dms", cursorWindowsHookAdapterTimeoutMS)) {
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

func TestCursorAdapterExceptionClosesWithOpenOutageMode(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, "open", false, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 2 || !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("local failure allowed with open outage mode: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
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

func TestCursorMappedAdapterUsesCurrentSIDNotPeerPolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	peer := "S-1-5-21-9999-9999-9999-9999"
	if peer == sid {
		t.Fatal("test peer is current SID")
	}
	for _, failure := range []string{"missing", "timeout", "block"} {
		for _, mode := range []string{"open", "closed", "unenrolled"} {
			t.Run(failure+"/"+mode, func(t *testing.T) {
				modes := map[string]string{peer: "open"}
				if mode != "unenrolled" {
					modes[sid] = mode
				}
				if mode == "open" {
					modes[peer] = "closed"
				}
				hook := filepath.Join(t.TempDir(), "missing-hook.exe")
				if failure != "missing" {
					hook, err = os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					t.Setenv(cursorAdapterHelperMode, failure)
				}
				body, err := RenderWindowsCursorEnterpriseAdapterForTargets(hook, modes)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.ReplaceAll(body, []byte("$timeoutMs = 10000"), []byte("$timeoutMs = 1000"))
				adapter := filepath.Join(t.TempDir(), "cursor-hook.ps1")
				if err := os.WriteFile(adapter, body, 0o600); err != nil {
					t.Fatal(err)
				}
				stdout, stderr, code := runCursorAdapterTest(t, adapter, `{"source":"cursor-adapter-probe"}`)
				if code != 2 || !strings.Contains(stdout, `"permission":"deny"`) {
					t.Fatalf("local adapter failure or valid denial allowed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
				if failure != "block" {
					loggedOpen := strings.Contains(stderr, "open gateway-outage mode does not apply")
					if loggedOpen != (mode == "open") {
						t.Fatalf("adapter used another SID's outage mode: mode=%s stderr=%q", mode, stderr)
					}
				}
			})
		}
	}
}

// The released per-user adapters (testdata/released-hooks) let the call run
// when the hook launcher is missing, as it is for a moment while an upgrade
// swaps it. After the installer's refresh to closed they deny it.
func TestRefreshedReleasedAdaptersDenyWhenTheLauncherIsMissing(t *testing.T) {
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, adapter := range []string{"cursor-hook.ps1", "copilot-hook.ps1"} {
			body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, adapter))
			if os.IsNotExist(err) {
				continue // 0.8.10 had no Copilot adapter.
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Run(release+"/"+adapter, func(t *testing.T) {
				hookDir := t.TempDir()
				missing := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
				body := strings.ReplaceAll(string(body), `C:\Users\dc-user\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe`, missing)
				path := filepath.Join(hookDir, adapter)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				run := func() (string, string, int) {
					if adapter == "copilot-hook.ps1" {
						return runCopilotAdapterTest(t, path, `{"source":"copilot-adapter-probe"}`)
					}
					return runCursorAdapterTest(t, path, `{"source":"cursor-adapter-probe"}`)
				}
				denied := func(stdout string, code int) bool {
					if adapter == "copilot-hook.ps1" {
						return code == 0 && strings.TrimSpace(stdout) == copilotAdapterClosedDenial
					}
					// powershell -Command reports an older adapter's exit 2 as 1.
					return code != 0 && strings.Contains(stdout, `"permission":"deny"`)
				}
				if stdout, stderr, code := run(); denied(stdout, code) {
					t.Fatalf("precondition: the %s adapter denies before the refresh: %q %q", release, stdout, stderr)
				}
				if _, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" }); err != nil {
					t.Fatal(err)
				}
				if stdout, stderr, code := run(); !denied(stdout, code) {
					t.Fatalf("the refreshed %s adapter: exit %d stdout %q stderr %q, want a denial", release, code, stdout, stderr)
				}
			})
		}
	}
}
