// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "errors"

// WindowsUserRuntimeRepairRequiredError identifies an expected per-user
// repair after the machine-policy and target-identity checks succeeded.
// Unknown verification failures remain hard errors, even without a session.
type WindowsUserRuntimeRepairRequiredError struct{ Cause error }

func (e *WindowsUserRuntimeRepairRequiredError) Error() string { return e.Cause.Error() }
func (e *WindowsUserRuntimeRepairRequiredError) Unwrap() error { return e.Cause }

func IsWindowsUserRuntimeRepairRequired(err error) bool {
	var repair *WindowsUserRuntimeRepairRequiredError
	return errors.As(err, &repair)
}

func windowsUserRuntimeRepairRequired(err error) error {
	if err == nil || IsWindowsUserRuntimeRepairRequired(err) {
		return err
	}
	return &WindowsUserRuntimeRepairRequiredError{Cause: err}
}
