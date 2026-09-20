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
	if err := validateWindowsManagedTargetRuntimeProtection(
		windows.Handle(file.Fd()),
		target,
	); err != nil {
		return fmt.Errorf("managed shared hook protection is noncanonical: %w", err)
	}
	return nil
}
