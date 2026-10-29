//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func validateManagedSharedHookOpenedFile(file *os.File, expectedOwnerSID string) error {
	expectedOwnerSID = strings.TrimSpace(expectedOwnerSID)
	if expectedOwnerSID == "" {
		return nil
	}
	target, err := windows.StringToSid(expectedOwnerSID)
	if err != nil || target == nil {
		return fmt.Errorf("parse managed shared hook target SID: %w", err)
	}
	// The script bytes are bound by the contract digest, so only the
	// descriptor can drift here. The installer or the guardian re-stamps it
	// on the held inode; a standard-user caller accepts and logs it.
	validate := func(handle windows.Handle) error {
		if err := validateWindowsManagedTargetRuntimeProtection(handle, target); err != nil {
			return managedDriftError{err: err}
		}
		return nil
	}
	if err := ensureWindowsManagedLockProtection(windowsManagedLockRepair{
		Label:    "managed shared hook script",
		Path:     file.Name(),
		Handle:   windows.Handle(file.Fd()),
		Validate: validate,
		Canonical: func() (*windows.SECURITY_DESCRIPTOR, error) {
			return windowsManagedTargetRuntimeSecurityDescriptor(target)
		},
		Policy:       windowsManagedTargetRuntimeDriftPolicy(target),
		PolicyOrCode: true,
	}); err != nil {
		return fmt.Errorf("managed shared hook protection is noncanonical: %w", err)
	}
	return nil
}
