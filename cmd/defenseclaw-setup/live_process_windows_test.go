// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
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

func TestLiveProcessWithinInstallRoot(t *testing.T) {
	installRoot := t.TempDir()
	binDir := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(binDir, "defenseclaw-test-helper.exe")
	copyExecutable(t, source, target)

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(target, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_SETUP_PROCESS_HELPER=1",
		"GO_SETUP_PROCESS_READY="+ready,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start installed process helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect helper readiness: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("installed process helper did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}

	pid, imagePath, err := liveProcessWithinInstallRoot(installRoot)
	if err != nil {
		t.Fatalf("liveProcessWithinInstallRoot: %v", err)
	}
	if pid != uint32(cmd.Process.Pid) {
		t.Fatalf("PID = %d, want %d (image %q)", pid, cmd.Process.Pid, imagePath)
	}
	if !strings.EqualFold(filepath.Clean(imagePath), filepath.Clean(target)) {
		t.Fatalf("image path = %q, want %q", imagePath, target)
	}
	pid, imagePath, err = liveProcessWithinInstallRoot(installRoot, target)
	if err != nil {
		t.Fatalf("liveProcessWithinInstallRoot with ignored image: %v", err)
	}
	if pid != 0 || imagePath != "" {
		t.Fatalf("ignored installed process = (%d, %q), want no match", pid, imagePath)
	}
}

func TestProcessIdentityReportsExitedProcess(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start process: %v", err)
	}
	pid := uint32(cmd.Process.Pid)
	processHandle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatalf("open process synchronization handle: %v", err)
	}
	defer func() { _ = windows.CloseHandle(processHandle) }()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for process: %v", err)
	}
	if _, _, err := processIdentity(pid); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("processIdentity(%d) error = %v, want os.ErrProcessDone", pid, err)
	}
}

func TestPreflightInstalledClientsRejectsForegroundAndIgnoresGateway(t *testing.T) {
	installRoot := t.TempDir()
	binDir := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startHelper := func(target string) *exec.Cmd {
		t.Helper()
		copyExecutable(t, source, target)
		ready := filepath.Join(t.TempDir(), "ready")
		cmd := exec.Command(target, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
		cmd.Env = append(os.Environ(),
			"GO_WANT_SETUP_PROCESS_HELPER=1",
			"GO_SETUP_PROCESS_READY="+ready,
		)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start installed process helper: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				return cmd
			} else if !os.IsNotExist(err) {
				t.Fatalf("inspect helper readiness: %v", err)
			}
			if time.Now().After(deadline) {
				t.Fatal("installed process helper did not become ready")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}

	startHelper(filepath.Join(binDir, "defenseclaw-gateway.exe"))
	if err := preflightInstalledClients(installRoot); err != nil {
		t.Fatalf("gateway-only preflight: %v", err)
	}
	clientPath := filepath.Join(binDir, "defenseclaw.exe")
	startHelper(clientPath)
	if err := preflightInstalledClients(installRoot); !errors.Is(err, errInstalledProcessRunning) {
		t.Fatalf("foreground client preflight error = %v, want %v", err, errInstalledProcessRunning)
	} else if !strings.Contains(err.Error(), clientPath) {
		t.Fatalf("foreground client preflight error %q does not name %q", err, clientPath)
	}
}

func TestLiveProcessWithinInstallRootHelper(t *testing.T) {
	if os.Getenv("GO_WANT_SETUP_PROCESS_HELPER") != "1" {
		return
	}
	ready := os.Getenv("GO_SETUP_PROCESS_READY")
	if ready == "" {
		os.Exit(2)
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		os.Exit(3)
	}
	if stop := os.Getenv("GO_SETUP_PROCESS_STOP"); stop != "" {
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err := os.Stat(stop); err == nil {
				time.Sleep(250 * time.Millisecond)
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				os.Exit(4)
			}
			if !time.Now().Before(deadline) {
				os.Exit(5)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	time.Sleep(2 * time.Minute)
}

func TestDrainStableHookChildrenPreservesForeignExactAndNearMatchProcesses(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "HookRuntime")
	installBin := filepath.Join(root, "DefenseClaw", "bin")
	if err := os.MkdirAll(runtimeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installBin, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcherPath := filepath.Join(runtimeRoot, "defenseclaw-hook.exe")
	hookPath := filepath.Join(installBin, "defenseclaw-hook.exe")
	nearMatchPath := filepath.Join(installBin, "defenseclaw-hook-helper.exe")
	for _, target := range []string{launcherPath, hookPath, nearMatchPath} {
		copyExecutable(t, source, target)
	}

	startHelper := func(target string) *exec.Cmd {
		t.Helper()
		ready := filepath.Join(t.TempDir(), "ready")
		cmd := exec.Command(target, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
		cmd.Env = append(os.Environ(),
			"GO_WANT_SETUP_PROCESS_HELPER=1",
			"GO_SETUP_PROCESS_READY="+ready,
		)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start process helper %s: %v", target, err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		waitForSetupProcessReady(t, ready)
		return cmd
	}
	startParent := func(childPath string) (*exec.Cmd, uint32) {
		t.Helper()
		ready := filepath.Join(t.TempDir(), "child-pid")
		cmd := exec.Command(launcherPath, "-test.run=^TestStableHookParentHelper$")
		cmd.Env = append(os.Environ(),
			"GO_WANT_SETUP_HOOK_PARENT=1",
			"GO_SETUP_HOOK_CHILD="+childPath,
			"GO_SETUP_HOOK_CHILD_PID="+ready,
		)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start stable hook parent: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		waitForSetupProcessReady(t, ready)
		body, err := os.ReadFile(ready)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 32)
		if err != nil {
			t.Fatalf("parse stable hook child PID: %v", err)
		}
		child, err := os.FindProcess(int(pid))
		if err != nil {
			t.Fatalf("bind stable hook child process: %v", err)
		}
		t.Cleanup(func() {
			_ = child.Kill()
			_, _ = child.Wait()
		})
		return cmd, uint32(pid)
	}

	foreignExact := startHelper(hookPath)
	_, ownedChildPID := startParent(hookPath)
	_, nearMatchPID := startParent(nearMatchPath)
	if err := drainStableHookChildrenAt(launcherPath, hookPath, 25*time.Millisecond, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitForProcessExit(ownedChildPID, 5*time.Second); err != nil {
		t.Fatalf("authenticated stable hook child remained running: %v", err)
	}
	if _, _, err := processIdentity(uint32(foreignExact.Process.Pid)); err != nil {
		t.Fatalf("foreign exact-path process was terminated: %v", err)
	}
	if _, _, err := processIdentity(nearMatchPID); err != nil {
		t.Fatalf("near-match stable child was terminated: %v", err)
	}
}

func TestStableHookParentGenerationMustPredateChild(t *testing.T) {
	child := managedProcessProof{StartIdentity: "200"}
	for _, test := range []struct {
		name   string
		parent string
		want   bool
	}{
		{name: "older exact parent", parent: "100", want: true},
		{name: "same creation tick", parent: "200", want: true},
		{name: "reused parent PID", parent: "300", want: false},
		{name: "malformed identity", parent: "not-a-filetime", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := managedProcessProof{StartIdentity: test.parent}
			if got := stableHookParentPrecedesChild(parent, child); got != test.want {
				t.Fatalf("stableHookParentPrecedesChild = %t, want %t", got, test.want)
			}
		})
	}
}

func TestStableHookParentHelper(t *testing.T) {
	if os.Getenv("GO_WANT_SETUP_HOOK_PARENT") != "1" {
		return
	}
	childPath := os.Getenv("GO_SETUP_HOOK_CHILD")
	pidPath := os.Getenv("GO_SETUP_HOOK_CHILD_PID")
	if childPath == "" || pidPath == "" {
		os.Exit(2)
	}
	childReady := pidPath + ".ready"
	cmd := exec.Command(childPath, "-test.run=^TestLiveProcessWithinInstallRootHelper$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_SETUP_PROCESS_HELPER=1",
		"GO_SETUP_PROCESS_READY="+childReady,
	)
	if err := cmd.Start(); err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		os.Exit(4)
	}
	_ = cmd.Wait()
}

func waitForSetupProcessReady(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("process readiness timed out: %s", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestPathWithinRoot(t *testing.T) {
	root := filepath.Join(`C:\`, "Users", "example", "DefenseClaw")
	for _, test := range []struct {
		name string
		path string
		want bool
	}{
		{name: "child", path: filepath.Join(root, "bin", "defenseclaw.exe"), want: true},
		{name: "case-insensitive child", path: filepath.Join(`c:\`, "USERS", "EXAMPLE", "DEFENSECLAW", "bin", "python.exe"), want: true},
		{name: "root itself", path: root, want: false},
		{name: "sibling prefix", path: root + "-old\\bin\\defenseclaw.exe", want: false},
		{name: "parent", path: filepath.Dir(root), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pathWithinRoot(test.path, root); got != test.want {
				t.Fatalf("pathWithinRoot(%q, %q) = %t, want %t", test.path, root, got, test.want)
			}
		})
	}
}

func copyExecutable(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
