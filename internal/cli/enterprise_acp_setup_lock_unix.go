//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"syscall"
)

func withACPUserSetupLock(clientPath string, fn func() error) error {
	file, err := openACPUserSetupLock(clientPath, syscall.O_NOFOLLOW)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire ACP editor lock: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN) //nolint:errcheck // close releases lock
	if err := validateACPUserSetupLock(clientPath+".defenseclaw.lock", file); err != nil {
		return err
	}
	return fn()
}
