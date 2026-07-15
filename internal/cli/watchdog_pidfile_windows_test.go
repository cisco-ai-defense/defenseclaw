// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWatchdogUnlockedLiveProcessRequiresStrongIdentity(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	write := func(info watchdogPIDInfo) {
		t.Helper()
		f, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeWatchdogPIDInfo(f, info); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	write(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity})
	if live, got := watchdogUnlockedLiveProcess(pidPath); !live || got.PID != os.Getpid() {
		t.Fatalf("strong live record = (live=%v, info=%+v)", live, got)
	}

	write(watchdogPIDInfo{PID: os.Getpid()})
	if live, got := watchdogUnlockedLiveProcess(pidPath); live {
		t.Fatalf("legacy liveness-only record treated as strongly owned: %+v", got)
	}
}

func TestVerifyWatchdogProcess_StartIdentity(t *testing.T) {
	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	if !verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity}) {
		t.Fatal("verifyWatchdogProcess rejected the matching Windows start identity")
	}
	if verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity + "-stale"}) {
		t.Fatal("verifyWatchdogProcess accepted a stale Windows start identity")
	}
}

func TestWindowsWatchdogLockStateIsAuthoritative(t *testing.T) {
	pidPath := t.TempDir() + `\watchdog.pid`
	if locked, _, err := watchdogIsLocked(pidPath); err != nil || locked {
		t.Fatalf("missing lock state = (locked=%v, err=%v)", locked, err)
	}
	info := watchdogPIDInfo{PID: os.Getpid(), StartIdentity: watchdogProcessStartIdentity(os.Getpid()), ControlName: "control"}
	holder, err := acquireWatchdogPIDFile(pidPath, info)
	if err != nil {
		t.Fatal(err)
	}
	locked, got, err := watchdogIsLocked(pidPath)
	if err != nil || !locked {
		_ = holder.Close()
		t.Fatalf("held lock state = (locked=%v, err=%v)", locked, err)
	}
	if got.PID != info.PID || got.StartIdentity != info.StartIdentity || got.ControlName != info.ControlName {
		_ = holder.Close()
		t.Fatalf("locked fingerprint = %+v, want %+v", got, info)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	if locked, _, err := watchdogIsLocked(pidPath); err != nil || locked {
		t.Fatalf("released lock state = (locked=%v, err=%v)", locked, err)
	}
}

func TestWindowsWatchdogControlEventRequestsGracefulStop(t *testing.T) {
	name, triggered, cleanup, err := watchdogCreateControl()
	if err != nil {
		t.Fatal(err)
	}
	if !validWatchdogControlName(name) {
		cleanup()
		t.Fatalf("control name is not a valid private capability: %q", name)
	}

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	defer proc.Release() //nolint:errcheck -- test process handle.
	if err := watchdogTerminate(watchdogPIDInfo{PID: os.Getpid(), ControlName: name}, proc); err != nil {
		cleanup()
		t.Fatal(err)
	}
	select {
	case <-triggered:
	case <-time.After(2 * time.Second):
		cleanup()
		t.Fatal("named watchdog event was not signaled")
	}
	cleanup()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	if handle, openErr := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, namePtr); openErr == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("watchdog control event remained open after cleanup")
	}
}

func TestWindowsWatchdogControlRejectsForgedName(t *testing.T) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Release() //nolint:errcheck -- test process handle.
	err = watchdogTerminate(watchdogPIDInfo{PID: os.Getpid(), ControlName: `Local\DefenseClaw-Watchdog-not-hex`}, proc)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("forged control name error = %v", err)
	}
	if !watchdogProcessAlive(os.Getpid(), proc) {
		t.Fatal("invalid capability path terminated the calling process")
	}
}

func TestWindowsWatchdogWaitConfirmsOriginalProcessExit(t *testing.T) {
	const helperEnv = "DEFENSECLAW_TEST_WATCHDOG_WAIT_EXIT"
	if os.Getenv(helperEnv) == "1" {
		if err := os.WriteFile(os.Getenv("DEFENSECLAW_TEST_WATCHDOG_WAIT_READY"), []byte("ready"), 0o600); err != nil {
			os.Exit(2)
		}
		time.Sleep(150 * time.Millisecond)
		os.Exit(0)
	}

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsWatchdogWaitConfirmsOriginalProcessExit")
	cmd.Env = append(os.Environ(), helperEnv+"=1", "DEFENSECLAW_TEST_WATCHDOG_WAIT_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	identity := watchdogProcessStartIdentity(cmd.Process.Pid)
	if identity == "" {
		t.Fatal("helper process has no start identity")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not signal readiness")
		}
		time.Sleep(5 * time.Millisecond)
	}
	info := watchdogPIDInfo{PID: cmd.Process.Pid, StartIdentity: identity}
	started := time.Now()
	if !watchdogWaitForExit(cmd.Process, info, 5*time.Second) {
		t.Fatal("original process handle did not become signaled")
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("wait returned before helper exited: %s", elapsed)
	}
	if watchdogProcessAlive(info.PID, cmd.Process) {
		t.Fatal("terminated process with a retained handle was reported alive")
	}
}
