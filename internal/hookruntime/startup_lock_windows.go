// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

const gatewayStartMutexPollInterval = 50 * time.Millisecond

// WithGatewayStartLock serializes gateway cold-start authorization across all
// hook processes and native setup generations for the current Windows user.
// Setup uses the same lock while publishing or disabling state, closing the
// race where an invocation could re-enable a gateway after uninstall began.
func WithGatewayStartLock(ctx context.Context, fn func() error) (resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	name, err := gatewayStartMutexName()
	if err != nil {
		return err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	handle, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return fmt.Errorf("create gateway cold-start mutex: %w", err)
	}
	defer windows.CloseHandle(handle)
	// Windows mutex ownership belongs to the waiting OS thread, not to a Go
	// goroutine. Pin it until ReleaseMutex so scheduler migration cannot turn a
	// successful critical section into ERROR_NOT_OWNER.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		waitMillis := uint32(gatewayStartMutexPollInterval / time.Millisecond)
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ctx.Err()
			}
			if remaining < gatewayStartMutexPollInterval {
				waitMillis = uint32((remaining + time.Millisecond - 1) / time.Millisecond)
				if waitMillis == 0 {
					waitMillis = 1
				}
			}
		}
		result, waitErr := windows.WaitForSingleObject(handle, waitMillis)
		if waitErr != nil {
			return fmt.Errorf("wait for gateway cold-start mutex: %w", waitErr)
		}
		switch result {
		case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
			defer func() {
				resultErr = errors.Join(resultErr, windows.ReleaseMutex(handle))
			}()
			return fn()
		case uint32(windows.WAIT_TIMEOUT):
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		default:
			return fmt.Errorf("unexpected gateway cold-start mutex wait result %#x", result)
		}
	}
}

func gatewayStartMutexName() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", fmt.Errorf("resolve gateway cold-start identity: %w", err)
	}
	return `Global\Cisco.DefenseClaw.HookGatewayStart.` + user.User.Sid.String(), nil
}
