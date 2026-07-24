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

func TestMain(m *testing.M) {
	switch os.Getenv(cursorAdapterHelperMode) {
	case "success":
		inputPath := argumentValue(os.Args[1:], "--input-file")
		payload, err := os.ReadFile(inputPath)
		if err != nil || !bytes.Contains(payload, []byte("cursor-adapter-probe")) {
			fmt.Fprintln(os.Stderr, "adapter helper did not receive the expected input file")
			os.Exit(3)
		}
		fmt.Print(`{"continue":true}`)
		os.Exit(0)
	case "timeout":
		if pidFile := os.Getenv(cursorAdapterPIDFileEnv); pidFile != "" {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
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

func argumentValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func renderCursorAdapterForTest(t *testing.T, hookPath string, timeoutMS int) string {
	t.Helper()
	tTemplate, err := hookFS.ReadFile("hooks/cursor-hook.ps1")
	if err != nil {
		t.Fatalf("read Cursor adapter template: %v", err)
	}
	rendered, err := renderTemplate(string(tTemplate), templateData{
		HookBinaryPS:  strings.ReplaceAll(hookPath, "'", "''"),
		HookTimeoutMS: timeoutMS,
	})
	if err != nil {
		t.Fatalf("render Cursor adapter: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cursor-hook.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write Cursor adapter: %v", err)
	}
	return path
}

func runCursorAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
	overrideCleanup bool,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	var cmd *exec.Cmd
	quoted := strings.ReplaceAll(adapterPath, "'", "''")
	if overrideCleanup {
		command := "function global:Remove-Item { " +
			"param([string]$LiteralPath, [switch]$Force, [object]$ErrorAction) " +
			"throw 'simulated cleanup failure' }; $input | & '" + quoted + "'"
		cmd = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	} else {
		cmd = exec.Command(
			"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$input | & '"+quoted+"'",
		)
	}
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

func assertNoCursorPayload(t *testing.T, adapterPath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(adapterPath), ".cursor-input-*.json"))
	if err != nil {
		t.Fatalf("glob Cursor payloads: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary Cursor payloads remain after adapter exit: %d", len(matches))
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
	adapter := renderCursorAdapterForTest(t, executable, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`, false,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterTimeoutKillsChildAndFailsOpen(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(cursorAdapterHelperMode, "timeout")
	t.Setenv(cursorAdapterPIDFileEnv, pidFile)
	adapter := renderCursorAdapterForTest(t, executable, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`, false,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if !strings.Contains(stderr, "timed out after 1000ms") {
		t.Fatalf("stderr = %q, want timeout diagnostic", stderr)
	}
	rawPID, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read helper PID: %v", err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(rawPID)), 10, 32)
	if err != nil {
		t.Fatalf("parse helper PID: %v", err)
	}
	if windowsProcessRunning(uint32(pid)) {
		t.Fatalf("timed-out Cursor launcher process %d is still running", pid)
	}
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterExceptionEmitsFailOpenJSON(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`, false,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterReportsCleanupFailureWithoutPayloadContents(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	adapter := renderCursorAdapterForTest(t, executable, 1_000)
	const sensitiveMarker = "cursor-adapter-probe-sensitive-cleanup"
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"`+sensitiveMarker+`"}`, true,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if !strings.Contains(stderr, "could not remove temporary Cursor payload") {
		t.Fatalf("stderr = %q, want cleanup failure diagnostic", stderr)
	}
	if strings.Contains(stderr, sensitiveMarker) {
		t.Fatal("cleanup diagnostic leaked Cursor payload contents")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(adapter), ".cursor-input-*.json"))
	if err != nil {
		t.Fatalf("glob retained Cursor payload: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("retained Cursor payloads = %d, want 1 after simulated cleanup failure", len(matches))
	}
}
