// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lowerIdentityImpersonationToken is this process's own token at low
// integrity: a thread that impersonates it may not open the threads of a
// process started with the process token, as the managed guardian may not
// while it impersonates an enrolled standard user.
func lowerIdentityImpersonationToken(t *testing.T) windows.Token {
	t.Helper()
	var primary windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &primary); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer primary.Close()
	var token windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		t.Fatalf("duplicate token: %v", err)
	}
	low, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		token.Close()
		t.Fatalf("low integrity SID: %v", err)
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		token.Close()
		t.Fatalf("lower the token's integrity: %v", err)
	}
	return token
}

// threadImpersonates reports whether the calling OS thread impersonates.
func threadImpersonates() bool {
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return false
	}
	token.Close()
	return true
}

// impersonate runs fn on one OS thread that impersonates token.
func impersonate(t *testing.T, token windows.Token, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		// The thread ends with the goroutine: its impersonation goes with it.
		if err := windows.SetThreadToken(nil, token); err != nil {
			t.Errorf("impersonate: %v", err)
			return
		}
		defer func() { _ = windows.RevertToSelf() }()
		fn()
	}()
	<-done
}

// GAP-0887: the managed Windows guardian runs connector Setup and its
// owned-hook check while it impersonates the enrolled user. The Hermes
// execution probe it starts runs with the guardian's own token, and the
// impersonating thread could not open the suspended child's thread to resume
// it: RunContained failed after its wait ("primary thread was not visible"),
// the probe failed, and every managed Hermes install, reinstall after purge
// and fail-mode change ended "owned hook command not present". A verify that
// does not impersonate (status, an upgrade with nothing to set up) passed.
func TestRunContainedWhileTheCallerImpersonatesALowerIdentity(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable: %v", err)
	}
	token := lowerIdentityImpersonationToken(t)
	defer token.Close()

	// The condition: such a thread may not open the child's thread.
	impersonate(t, token, func() {
		child := exec.Command(self, "-test.run=^$")
		child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
		if err := child.Start(); err != nil {
			t.Errorf("start a suspended child while impersonating: %v", err)
			return
		}
		defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
		opened := errors.New("no thread of the child was listed")
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
		if err != nil {
			t.Errorf("snapshot threads: %v", err)
			return
		}
		defer windows.CloseHandle(snapshot)
		var entry windows.ThreadEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		for walk := windows.Thread32First(snapshot, &entry); walk == nil; walk = windows.Thread32Next(snapshot, &entry) {
			if entry.OwnerProcessID == uint32(child.Process.Pid) {
				thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
				if openErr == nil {
					windows.CloseHandle(thread)
				}
				opened = openErr
				break
			}
		}
		// Not listed, or listed and not opened: either way this thread cannot
		// resume the child through its thread.
		if opened == nil {
			t.Error("the impersonating thread opened the child's thread; the test does not reproduce the guardian's condition")
		}
		t.Logf("resume through the child's thread while impersonating: %v", opened)
		if !threadImpersonates() {
			t.Error("callerThreadImpersonates = false on an impersonating thread")
		}
	})

	for _, run := range []struct {
		name string
		fn   func(*exec.Cmd) error
	}{{"RunContained", RunContained}, {"RunTree", RunTree}} {
		if threadImpersonates() {
			t.Fatal("the test goroutine's thread impersonates")
		}
		impersonate(t, token, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := CommandContext(ctx, self, "-test.run=^$")
			if err := run.fn(cmd); err != nil {
				t.Errorf("%s while impersonating = %v, want the child run to the end", run.name, err)
			}
		})
	}
}
