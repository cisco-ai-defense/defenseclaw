// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"

	"golang.org/x/sys/windows"
)

// TransformWindowsClaudeSettingsForUninstall uses the connector's durable,
// identity-bound settings transaction. It verifies the enrolled owner, gives
// that user, SYSTEM, and Administrators access when a privileged caller must
// converge an unsafe DACL, and preserves the resulting owner and DACL through
// replacement while retrying concurrent Claude writes. The caller supplies
// an exact-command-only transform.
func TransformWindowsClaudeSettingsForUninstall(path, stateDir, ownerSID string, transform func([]byte) ([]byte, int, error)) (int, error) {
	owner, err := windows.StringToSid(ownerSID)
	if err != nil {
		return 0, err
	}
	removed := 0
	err = atomicTransformFileV2(path, stateDir, 0o600, atomicTransformV2Options{
		preserveExistingProtection: true, expectedOwner: owner,
	}, func(current []byte, exists bool) (atomicTransformResult, error) {
		if !exists {
			return atomicTransformResult{Remove: true}, nil
		}
		out, count, err := transform(current)
		if err != nil {
			return atomicTransformResult{}, err
		}
		removed = count
		return atomicTransformResult{Data: out, Perm: os.FileMode(0o600)}, nil
	})
	return removed, err
}
