// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	codexPolicyTreeHelperEnv       = "DEFENSECLAW_CODEX_POLICY_TREE_HELPER"
	codexPolicyGrandchildHelperEnv = "DEFENSECLAW_CODEX_POLICY_GRANDCHILD_HELPER"
	codexPolicyEntryPathEnv        = "DEFENSECLAW_CODEX_POLICY_ENTRY_PATH"
	codexPolicyReadyPathEnv        = "DEFENSECLAW_CODEX_POLICY_READY_PATH"
	codexPolicyMarkerPathEnv       = "DEFENSECLAW_CODEX_POLICY_MARKER_PATH"
	codexPolicyReleaseEnv          = "DEFENSECLAW_CODEX_POLICY_RELEASE"
)

func TestInspectCodexPolicyRequiresFreshSetupSelectionBeforeMutation(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	_, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{DataDir: dir})
	if err == nil || !strings.Contains(err.Error(), "setup-selected native executable") {
		t.Fatalf("fresh Windows policy inspection error = %v, want setup-selection refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, hookContractLockFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed inspection mutated hook lock: %v", statErr)
	}
}

func TestCodexSetupWithoutSelectionLeavesRegistrationAndArtifactsUntouched(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	configPath := filepath.Join(t.TempDir(), ".codex", "config.toml")
	originalInspector := codexPolicyInspector
	codexPolicyInspector = inspectCodexEffectivePolicy
	t.Cleanup(func() { codexPolicyInspector = originalInspector })
	originalConfigPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = originalConfigPath })

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:      dir,
		HookFailMode: "closed",
	})
	if err == nil || !strings.Contains(err.Error(), "setup-selected native executable") {
		t.Fatalf("fresh Windows Codex setup error = %v, want setup-selection refusal", err)
	}
	for _, path := range []string{
		configPath,
		filepath.Join(dir, "hooks"),
		filepath.Join(dir, "backups"),
		filepath.Join(dir, hookContractLockFile),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed Codex setup mutated %s: %v", path, statErr)
		}
	}
}

func TestStartCodexAppServerTreeAssignsBeforeImmediateGrandchild(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "wrapper-entered")
	ready := filepath.Join(root, "grandchild-ready")
	marker := filepath.Join(root, "grandchild-survived")
	release := testenv.NewRelease(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexPolicyAppServerTreeHelper$", "--")
	cmd.Env = append(
		os.Environ(),
		codexPolicyTreeHelperEnv+"=1",
		codexPolicyEntryPathEnv+"="+entry,
		codexPolicyReadyPathEnv+"="+ready,
		codexPolicyMarkerPathEnv+"="+marker,
		codexPolicyReleaseEnv+"="+release.Token(),
	)

	var wrapperExit <-chan error
	cleanup, err := startCodexAppServerTreeObserved(cmd, func() error {
		// Before assignment the wrapper's only thread must still be held by
		// CREATE_SUSPENDED: then it cannot have run, whatever the timing.
		if err := assertCodexPolicyProcessSuspended(cmd.Process.Pid); err != nil {
			return err
		}
		if _, err := os.Stat(entry); err == nil {
			return errors.New("wrapper executed before job assignment")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect wrapper entry marker: %w", err)
		}
		wrapperExit = codexPolicyExitErrors(testenv.ProcessExit(t, cmd.Process.Pid))
		return nil
	})
	if err != nil {
		t.Fatalf("start contained app-server tree: %v", err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanup()
		}
	}()

	data, err := testenv.WaitForFile(ready, wrapperExit)
	if err != nil {
		t.Fatalf("app-server wrapper did not start its grandchild: %v", err)
	}
	grandchildPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	// The grandchild blocks until released, so it is alive here.
	grandchild := testenv.ProcessExit(t, grandchildPID)
	cancel()
	cleanup()
	cleanup() // cleanup ownership is deliberately idempotent.
	cleaned = true
	// A contained grandchild was killed with the job's exit code before the
	// release; one that escaped the job would now write its marker and exit 0.
	release.Signal(t)
	if code := <-grandchild; code != 1 {
		t.Fatalf("immediate app-server grandchild exit code = %d, want 1 from job termination (escaped the assigned job?)", code)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("immediate app-server grandchild escaped the assigned job (stat: %v)", err)
	}
}

// TestCodexPolicyAppServerTreeHelper is the wrapper and grandchild entry
// point for TestStartCodexAppServerTreeAssignsBeforeImmediateGrandchild.
func TestCodexPolicyAppServerTreeHelper(t *testing.T) {
	if os.Getenv(codexPolicyGrandchildHelperEnv) == "1" {
		// Released only after the test tore the job down, so reaching the
		// marker means this process escaped the job.
		if released, err := testenv.AwaitRelease(os.Getenv(codexPolicyReleaseEnv)); err != nil || !released {
			os.Exit(33)
		}
		_ = os.WriteFile(os.Getenv(codexPolicyMarkerPathEnv), []byte("survived"), 0o600)
		os.Exit(0)
	}
	if os.Getenv(codexPolicyTreeHelperEnv) != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv(codexPolicyEntryPathEnv), []byte("entered"), 0o600); err != nil {
		os.Exit(30)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestCodexPolicyAppServerTreeHelper$", "--")
	child.Env = append(os.Environ(), codexPolicyGrandchildHelperEnv+"=1")
	if err := child.Start(); err != nil {
		os.Exit(31)
	}
	if err := os.WriteFile(os.Getenv(codexPolicyReadyPathEnv), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		os.Exit(32)
	}
	// Ended by the job; the release wait only covers an abandoned test.
	_, _ = testenv.AwaitRelease(os.Getenv(codexPolicyReleaseEnv))
	os.Exit(0)
}

func TestValidateCodexPolicyExecutableRejectsCommandProcessorWrapper(t *testing.T) {
	root := t.TempDir()
	wrapper := filepath.Join(root, "codex.cmd")
	if err := os.WriteFile(wrapper, []byte("@echo off\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := validateCodexPolicyExecutable(SetupOpts{AgentExecutable: wrapper})
	if err == nil || !strings.Contains(err.Error(), "native Windows .exe") {
		t.Fatalf("batch-wrapper validation error = %v, want native-image refusal", err)
	}
}

// assertCodexPolicyProcessSuspended proves that the sole thread of pid has
// a suspend count of at least one, i.e. it has not executed. Suspending and
// resuming again leaves the count unchanged.
func assertCodexPolicyProcessSuspended(pid int) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("snapshot threads: %w", err)
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != uint32(pid) {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return fmt.Errorf("open wrapper thread: %w", err)
		}
		defer windows.CloseHandle(thread)
		previous, _, callErr := codexPolicySuspendThread.Call(uintptr(thread))
		if uint32(previous) == ^uint32(0) {
			return fmt.Errorf("suspend wrapper thread: %w", callErr)
		}
		if _, err := windows.ResumeThread(thread); err != nil {
			return fmt.Errorf("resume wrapper thread: %w", err)
		}
		if previous == 0 {
			return errors.New("wrapper thread was running before job assignment")
		}
		return nil
	}
	return fmt.Errorf("wrapper process %d has no thread", pid)
}

var codexPolicySuspendThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("SuspendThread")

func codexPolicyExitErrors(codes <-chan uint32) <-chan error {
	exited := make(chan error, 1)
	go func() { exited <- fmt.Errorf("exit code %d", <-codes) }()
	return exited
}
