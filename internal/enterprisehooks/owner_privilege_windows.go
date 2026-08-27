//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// RunWithWindowsOwnerRestorePrivilege runs fn on a locked OS thread holding
// SeBackupPrivilege and SeRestorePrivilege from the process token. Assigning an
// owner other than the caller's SID requires SeRestorePrivilege, which a
// target-impersonated thread does not hold. Outside the LocalSystem guardian
// fn runs unchanged.
func RunWithWindowsOwnerRestorePrivilege(fn func() error) error {
	if fn == nil {
		return fmt.Errorf("enterprise hooks: owner privilege callback is required")
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		// Only fall through to a non-privileged fn() when the identity was
		// confirmed to be non-LocalSystem. Any other error (token lookup
		// failure, opaque GetTokenUser error) means we could not resolve
		// the identity at all, and hiding it would run mutations without
		// the required privileges. Propagate those.
		if errors.Is(err, errWindowsEnterpriseNotLocalSystem) {
			return fn()
		}
		return err
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create dedicated owner privilege token: %w", err)
			return
		}

		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
			false,
			&token,
		); err != nil {
			revertErr := windows.RevertToSelf()
			if revertErr == nil {
				runtime.UnlockOSThread()
				result <- fmt.Errorf("enterprise hooks: open owner privilege token: %w", err)
				return
			}
			result <- fmt.Errorf(
				"enterprise hooks: open owner privilege token: %v (revert failed: %v)",
				err,
				revertErr,
			)
			return
		}

		privilegeErr := enableWindowsThreadPrivilege(token, "SeBackupPrivilege")
		if privilegeErr == nil {
			privilegeErr = enableWindowsThreadPrivilege(token, "SeRestorePrivilege")
		}
		callErr := privilegeErr
		if callErr == nil {
			callErr = fn()
		}
		token.Close()

		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Do not return a still-privileged thread to the runtime pool.
			if callErr == nil {
				result <- fmt.Errorf("enterprise hooks: revert owner privilege token: %w", revertErr)
			} else {
				result <- fmt.Errorf("%v (revert owner privilege token failed: %v)", callErr, revertErr)
			}
			return
		}
		runtime.UnlockOSThread()
		result <- callErr
	}()
	return <-result
}
