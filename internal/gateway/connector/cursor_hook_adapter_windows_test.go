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
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const cursorAdapterHelperMode = "TEST_CURSOR_ADAPTER_MODE"
const cursorAdapterPIDFileEnv = "TEST_CURSOR_ADAPTER_PID_FILE"
const cursorAdapterDescendantPIDFileEnv = "TEST_CURSOR_ADAPTER_DESCENDANT_PID_FILE"
const cursorAdapterReleaseFileEnv = "TEST_CURSOR_ADAPTER_RELEASE_FILE"
const windsurfAdapterHelperMode = "TEST_WINDSURF_ADAPTER_MODE"
const windsurfAdapterExitCodeEnv = "TEST_WINDSURF_ADAPTER_EXIT_CODE"
const omnigentProbeHelperMode = "TEST_OMNIGENT_PROBE_MODE"

func TestMain(m *testing.M) {
	switch os.Getenv(cursorAdapterHelperMode) {
	case "success":
		inputPath := argumentValue(os.Args[1:], "--input-file")
		payload, err := os.ReadFile(inputPath)
		if err != nil || !bytes.Contains(payload, []byte("cursor-adapter-probe")) {
			fmt.Fprintln(os.Stderr, "adapter helper did not receive the expected input file")
			os.Exit(3)
		}
		fmt.Print(`{"permission":"allow"}`)
		os.Exit(0)
	case "timeout":
		if pidFile := os.Getenv(cursorAdapterPIDFileEnv); pidFile != "" {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "tree-timeout", "tree-complete":
		mode := os.Getenv(cursorAdapterHelperMode)
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), cursorAdapterHelperMode+"=tree-descendant")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "Cursor adapter tree helper could not start descendant")
			os.Exit(31)
		}
		if pidFile := os.Getenv(cursorAdapterPIDFileEnv); pidFile != "" {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(os.Getenv(cursorAdapterDescendantPIDFileEnv)); err == nil {
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "Cursor adapter tree descendant did not become ready")
				os.Exit(32)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if releaseFile := os.Getenv(cursorAdapterReleaseFileEnv); releaseFile != "" {
			for {
				if _, err := os.Stat(releaseFile); err == nil {
					break
				}
				if time.Now().After(deadline) {
					fmt.Fprintln(os.Stderr, "Cursor adapter tree helper was not released")
					os.Exit(33)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if mode == "tree-complete" {
			fmt.Print(`{"permission":"allow"}`)
			os.Exit(0)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "tree-descendant":
		if pidFile := os.Getenv(cursorAdapterDescendantPIDFileEnv); pidFile != "" {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		// Retain the stdout/stderr handles inherited from the helper parent.
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		switch os.Getenv(omnigentProbeHelperMode) {
		case "parent":
			child := exec.Command(os.Args[0])
			child.Env = append(os.Environ(), omnigentProbeHelperMode+"=descendant")
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			if err := child.Start(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(12)
			}
			time.Sleep(30 * time.Second)
			os.Exit(0)
		case "descendant":
			time.Sleep(30 * time.Second)
			os.Exit(0)
		}
		if os.Getenv(windsurfAdapterHelperMode) == "result" {
			payload, err := io.ReadAll(os.Stdin)
			if err != nil || string(payload) != `{"source":"windsurf-adapter-probe"}` {
				fmt.Fprintln(os.Stderr, "Windsurf adapter helper received wrong stdin")
				os.Exit(9)
			}
			if len(os.Args) != 4 || os.Args[1] != "hook" ||
				os.Args[2] != "--connector" || os.Args[3] != "windsurf" {
				fmt.Fprintln(os.Stderr, "Windsurf adapter helper received wrong arguments")
				os.Exit(8)
			}
			exitCode, err := strconv.Atoi(os.Getenv(windsurfAdapterExitCodeEnv))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Windsurf adapter helper received invalid exit code")
				os.Exit(7)
			}
			_, _ = os.Stdout.Write([]byte(`{"continue":true,"source":"windsurf"}`))
			_, _ = os.Stderr.Write([]byte("windsurf helper stderr"))
			time.Sleep(350 * time.Millisecond)
			os.Exit(exitCode)
		}
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

func renderCursorAdapterForTest(t *testing.T, hookPath string, timeoutMS int, failMode string) string {
	return renderCursorAdapterForTestOptions(t, hookPath, timeoutMS, failMode, false)
}

func renderCursorAdapterForTestOptions(
	t *testing.T,
	hookPath string,
	timeoutMS int,
	failMode string,
	forceTreeTerminationFailure bool,
) string {
	t.Helper()
	tTemplate, err := hookFS.ReadFile("hooks/cursor-hook.ps1")
	if err != nil {
		t.Fatalf("read Cursor adapter template: %v", err)
	}
	rendered, err := renderTemplate(string(tTemplate), templateData{
		HookBinaryPS:        strings.ReplaceAll(hookPath, "'", "''"),
		CursorHookTimeoutMS: timeoutMS,
		FailMode:            failMode,
	})
	if err != nil {
		t.Fatalf("render Cursor adapter: %v", err)
	}
	if forceTreeTerminationFailure {
		const terminationCondition = "if (!TerminateJobObject(job, 1))"
		if strings.Count(rendered, terminationCondition) != 1 {
			t.Fatalf("Cursor adapter termination condition count changed")
		}
		rendered = strings.Replace(
			rendered,
			terminationCondition,
			`if (String.Equals("forced", "forced", StringComparison.Ordinal))`,
			1,
		)
	}
	path := filepath.Join(t.TempDir(), "cursor-hook.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write Cursor adapter: %v", err)
	}
	return path
}

type cursorAdapterTestRun struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func startCursorAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
	overrideCleanup bool,
) *cursorAdapterTestRun {
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
	run := &cursorAdapterTestRun{cmd: cmd}
	cmd.Stdout = &run.stdout
	cmd.Stderr = &run.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Cursor adapter: %v", err)
	}
	return run
}

func (run *cursorAdapterTestRun) wait(t *testing.T) (stdout, stderr string, exitCode int) {
	t.Helper()
	err := run.cmd.Wait()
	if err == nil {
		return run.stdout.String(), run.stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Cursor adapter: %v", err)
	}
	return run.stdout.String(), run.stderr.String(), exitErr.ExitCode()
}

func runCursorAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
	overrideCleanup bool,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	return startCursorAdapterTest(t, adapterPath, payload, overrideCleanup).wait(t)
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
	if response["permission"] != "allow" {
		t.Fatalf("Cursor adapter response = %#v, want permission=allow", response)
	}
	if _, ok := response["continue"]; ok {
		t.Fatalf("Cursor adapter response = %#v, permission event must not carry continue", response)
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

func openRunningCursorProcessHandle(t *testing.T, path, label string) windows.Handle {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var pid uint64
	for pid == 0 {
		rawPID, err := os.ReadFile(path)
		if err == nil {
			pid, err = strconv.ParseUint(strings.TrimSpace(string(rawPID)), 10, 32)
			if err != nil {
				pid = 0
			}
		} else if !os.IsNotExist(err) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			t.Fatalf("read %s PID: %v", label, err)
		}
		if pid == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s PID did not become ready", label)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("open live %s process %d: %v", label, pid, err)
	}
	result, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatalf("check live %s process %d: %v", label, pid, err)
	}
	if result != uint32(windows.WAIT_TIMEOUT) {
		windows.CloseHandle(handle)
		t.Fatalf("%s process %d exited before its identity handle was retained", label, pid)
	}
	return handle
}

func assertCursorProcessHandleStopped(t *testing.T, handle windows.Handle, label string) {
	t.Helper()
	result, err := windows.WaitForSingleObject(handle, 5_000)
	if err != nil {
		t.Fatalf("wait for exact %s process handle: %v", label, err)
	}
	if result != windows.WAIT_OBJECT_0 {
		t.Fatalf("exact %s process handle wait result = %#x, want terminated", label, result)
	}
}

func TestCursorAdapterPreservesSuccessfulLauncherResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	adapter := renderCursorAdapterForTest(t, executable, 5_000, "open")
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"hook_event_name":"beforeShellExecution","source":"cursor-adapter-probe"}`, false,
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

func TestCursorAdapterTimeoutReapsTreeAndUsesExactFallback(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		event    string
		failMode string
		wantCode int
		wantJSON string
	}{
		{
			name:     "observe-fail-open",
			event:    "beforeShellExecution",
			failMode: "open",
			wantCode: 0,
			wantJSON: `{"permission":"allow"}`,
		},
		{
			name:     "action-fail-closed",
			event:    "beforeSubmitPrompt",
			failMode: "closed",
			wantCode: 2,
			wantJSON: `{"continue":false,"user_message":"DefenseClaw hook unavailable"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			parentPIDFile := filepath.Join(tempDir, "parent.pid")
			descendantPIDFile := filepath.Join(tempDir, "descendant.pid")
			releaseFile := filepath.Join(tempDir, "release")
			t.Setenv(cursorAdapterHelperMode, "tree-timeout")
			t.Setenv(cursorAdapterPIDFileEnv, parentPIDFile)
			t.Setenv(cursorAdapterDescendantPIDFileEnv, descendantPIDFile)
			t.Setenv(cursorAdapterReleaseFileEnv, releaseFile)
			adapter := renderCursorAdapterForTest(t, executable, 5_000, test.failMode)
			started := time.Now()
			run := startCursorAdapterTest(
				t,
				adapter,
				`{"hook_event_name":"`+test.event+`","source":"cursor-adapter-probe"}`,
				false,
			)
			parentHandle := openRunningCursorProcessHandle(t, parentPIDFile, "timed-out Cursor launcher")
			defer windows.CloseHandle(parentHandle)
			descendantHandle := openRunningCursorProcessHandle(t, descendantPIDFile, "timed-out Cursor descendant")
			defer windows.CloseHandle(descendantHandle)
			if err := os.WriteFile(releaseFile, []byte("ready"), 0o600); err != nil {
				t.Fatalf("release Cursor adapter tree helper: %v", err)
			}
			stdout, stderr, code := run.wait(t)
			if elapsed := time.Since(started); elapsed >= 12*time.Second {
				t.Fatalf("adapter elapsed time = %v, exceeds timeout plus cleanup budget", elapsed)
			}
			if code != test.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr=%q", code, test.wantCode, stderr)
			}
			if got := strings.TrimSpace(stdout); got != test.wantJSON {
				t.Fatalf("stdout = %q, want exact fallback %q", got, test.wantJSON)
			}
			if !strings.Contains(stderr, "timed out after 5000ms") {
				t.Fatalf("stderr = %q, want timeout diagnostic", stderr)
			}
			assertCursorProcessHandleStopped(t, parentHandle, "timed-out Cursor launcher")
			assertCursorProcessHandleStopped(t, descendantHandle, "timed-out Cursor descendant")
			assertNoCursorPayload(t, adapter)
		})
	}
}

func TestCursorAdapterCompletedRootReapsOwnedDescendant(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tempDir := t.TempDir()
	parentPIDFile := filepath.Join(tempDir, "parent.pid")
	descendantPIDFile := filepath.Join(tempDir, "descendant.pid")
	releaseFile := filepath.Join(tempDir, "release")
	t.Setenv(cursorAdapterHelperMode, "tree-complete")
	t.Setenv(cursorAdapterPIDFileEnv, parentPIDFile)
	t.Setenv(cursorAdapterDescendantPIDFileEnv, descendantPIDFile)
	t.Setenv(cursorAdapterReleaseFileEnv, releaseFile)
	adapter := renderCursorAdapterForTest(t, executable, 5_000, "open")
	started := time.Now()
	run := startCursorAdapterTest(
		t, adapter, `{"hook_event_name":"beforeShellExecution","source":"cursor-adapter-probe"}`, false,
	)
	parentHandle := openRunningCursorProcessHandle(t, parentPIDFile, "completed Cursor launcher")
	defer windows.CloseHandle(parentHandle)
	descendantHandle := openRunningCursorProcessHandle(t, descendantPIDFile, "owned residual Cursor descendant")
	defer windows.CloseHandle(descendantHandle)
	if err := os.WriteFile(releaseFile, []byte("ready"), 0o600); err != nil {
		t.Fatalf("release Cursor adapter tree helper: %v", err)
	}
	stdout, stderr, code := run.wait(t)
	if elapsed := time.Since(started); elapsed >= 10*time.Second {
		t.Fatalf("adapter elapsed time = %v, completed-root cleanup exceeded budget", elapsed)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if got := strings.TrimSpace(stdout); got != `{"permission":"allow"}` {
		t.Fatalf("stdout = %q, want exact launcher response", got)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertCursorProcessHandleStopped(t, parentHandle, "completed Cursor launcher")
	assertCursorProcessHandleStopped(t, descendantHandle, "owned residual Cursor descendant")
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterTreeTerminationFailureIsContentFreeAndFailClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tempDir := t.TempDir()
	parentPIDFile := filepath.Join(tempDir, "parent.pid")
	descendantPIDFile := filepath.Join(tempDir, "descendant.pid")
	releaseFile := filepath.Join(tempDir, "release")
	t.Setenv(cursorAdapterHelperMode, "tree-timeout")
	t.Setenv(cursorAdapterPIDFileEnv, parentPIDFile)
	t.Setenv(cursorAdapterDescendantPIDFileEnv, descendantPIDFile)
	t.Setenv(cursorAdapterReleaseFileEnv, releaseFile)
	adapter := renderCursorAdapterForTestOptions(t, executable, 5_000, "closed", true)
	const sensitiveMarker = "cursor-adapter-probe-sensitive-tree-termination"
	started := time.Now()
	run := startCursorAdapterTest(
		t,
		adapter,
		`{"hook_event_name":"beforeShellExecution","source":"`+sensitiveMarker+`"}`,
		false,
	)
	parentHandle := openRunningCursorProcessHandle(t, parentPIDFile, "Cursor launcher after termination failure")
	defer windows.CloseHandle(parentHandle)
	descendantHandle := openRunningCursorProcessHandle(t, descendantPIDFile, "Cursor descendant after termination failure")
	defer windows.CloseHandle(descendantHandle)
	if err := os.WriteFile(releaseFile, []byte("ready"), 0o600); err != nil {
		t.Fatalf("release Cursor adapter tree helper: %v", err)
	}
	stdout, stderr, code := run.wait(t)
	if elapsed := time.Since(started); elapsed >= 12*time.Second {
		t.Fatalf("adapter elapsed time = %v, exceeds timeout plus cleanup budget", elapsed)
	}
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	const wantJSON = `{"permission":"deny","user_message":"DefenseClaw hook unavailable","agent_message":"DefenseClaw hook unavailable"}`
	if got := strings.TrimSpace(stdout); got != wantJSON {
		t.Fatalf("stdout = %q, want exact fallback %q", got, wantJSON)
	}
	if !strings.Contains(stderr, "could not stop timed-out Cursor hook launcher process tree") ||
		!strings.Contains(stderr, "timed out after 5000ms") {
		t.Fatalf("stderr = %q, want content-free tree-cleanup and timeout diagnostics", stderr)
	}
	if strings.Contains(stdout, sensitiveMarker) || strings.Contains(stderr, sensitiveMarker) {
		t.Fatal("tree-termination failure leaked Cursor payload contents")
	}
	assertCursorProcessHandleStopped(t, parentHandle, "Cursor launcher after termination failure")
	assertCursorProcessHandleStopped(t, descendantHandle, "Cursor descendant after termination failure")
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterExceptionEmitsFailOpenJSON(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, 1_000, "open")
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"hook_event_name":"beforeShellExecution","source":"cursor-adapter-probe"}`, false,
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

func TestCursorAdapterExceptionHonorsFailClosed(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, 1_000, "closed")
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"hook_event_name":"beforeShellExecution","source":"cursor-adapter-probe"}`, false,
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("Cursor adapter stdout is not valid JSON: %v", err)
	}
	if response["permission"] != "deny" {
		t.Fatalf("Cursor adapter response = %#v, want concrete deny", response)
	}
	if _, ok := response["continue"]; ok {
		t.Fatalf("Cursor adapter response = %#v, permission event must not carry continue", response)
	}
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
	assertNoCursorPayload(t, adapter)
}

func TestCursorAdapterFailureUsesExactEventSchema(t *testing.T) {
	tests := []struct {
		event    string
		failMode string
		wantCode int
		want     map[string]interface{}
	}{
		{
			event:    "beforeSubmitPrompt",
			failMode: "closed",
			wantCode: 2,
			want: map[string]interface{}{
				"continue":     false,
				"user_message": "DefenseClaw hook unavailable",
			},
		},
		{
			event:    "subagentStart",
			failMode: "closed",
			wantCode: 2,
			want: map[string]interface{}{
				"permission":   "deny",
				"user_message": "DefenseClaw hook unavailable",
			},
		},
		{
			event:    "sessionEnd",
			failMode: "open",
			wantCode: 0,
			want:     map[string]interface{}{},
		},
	}
	for _, test := range tests {
		t.Run(test.event+"/"+test.failMode, func(t *testing.T) {
			missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
			adapter := renderCursorAdapterForTest(t, missingHook, 1_000, test.failMode)
			payload := `{"hook_event_name":"` + test.event + `","source":"cursor-adapter-probe"}`
			stdout, stderr, code := runCursorAdapterTest(t, adapter, payload, false)
			if code != test.wantCode {
				t.Fatalf("exit code=%d, want %d; stderr=%q", code, test.wantCode, stderr)
			}
			var got map[string]interface{}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("stdout is not valid JSON: %v; stdout=%q", err, stdout)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("response=%#v, want %#v", got, test.want)
			}
			assertNoCursorPayload(t, adapter)
		})
	}
}

func TestCursorAdapterReportsCleanupFailureWithoutPayloadContents(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	adapter := renderCursorAdapterForTest(t, executable, 5_000, "open")
	const sensitiveMarker = "cursor-adapter-probe-sensitive-cleanup"
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"hook_event_name":"beforeShellExecution","source":"`+sensitiveMarker+`"}`, true,
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
