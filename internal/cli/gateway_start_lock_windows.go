// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hookColdStartSupported: a per-user Windows gateway ends with its sign-in
// session and no service starts it again, so the hook of a PowerShell
// (install.ps1) install starts it with `start --hook-cold-start`, which
// keeps the Linux and macOS rules: not after `defenseclaw-gateway stop`,
// not during an install, one try a minute after a failed start (GAP-0377).
// Secure Client and managed computers keep their own lifecycle: none of the
// stop marker, the PATH record or that start applies there.
func hookColdStartSupported() bool {
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) || secureClientHost() {
		return false
	}
	_, managedHost := managedHostWindowsStandalone()
	return !managedHost
}

// acquireGatewayStartLock takes the per-data-directory start lock, as on Linux
// and macOS, so concurrent start and restart commands (a script, the TUI and
// a person at once) run one after the other instead of racing to spawn and
// report FAILED for a gateway another one started (GAP-0528). A data
// directory that does not exist yet, or a lock file this account cannot open,
// runs unlocked as before.
func acquireGatewayStartLock(dataDir string, wait time.Duration) (func(), error) {
	path := filepath.Join(dataDir, gatewayStartLockName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil
	}
	handle := windows.Handle(f.Fd())
	deadline := time.Now().Add(wait)
	for {
		overlapped := new(windows.Overlapped)
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, new(windows.Overlapped))
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			_ = f.Close()
			return func() {}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("another gateway start or restart is still in progress after %s (%s)", wait, path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func liftHookResourceLimits() {}
