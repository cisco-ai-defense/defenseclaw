//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func withACPUserSetupLock(clientPath string, fn func() error) error {
	file, err := openACPUserSetupLock(clientPath, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	handle := windows.Handle(file.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return fmt.Errorf("acquire ACP editor lock: %w", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, overlapped) //nolint:errcheck // close releases lock
	if err := validateACPUserSetupLock(clientPath+".defenseclaw.lock", file); err != nil {
		return err
	}
	return fn()
}
