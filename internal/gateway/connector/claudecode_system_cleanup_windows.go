// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "os"

// TransformWindowsClaudeSettingsForUninstall uses the connector's durable,
// identity-bound settings transaction. It preserves the existing NTFS DACL
// while SYSTEM edits a signed-out user's settings and retries concurrent
// Claude writes. The caller supplies an exact-command-only transform.
func TransformWindowsClaudeSettingsForUninstall(path, stateDir string, transform func([]byte) ([]byte, int, error)) (int, error) {
	removed := 0
	err := atomicTransformFileWithStateDir(path, stateDir, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
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
