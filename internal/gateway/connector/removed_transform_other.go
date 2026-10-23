// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

func removedStubTransform(
	path, stateDir string, perm os.FileMode,
	transform func([]byte, bool) (atomicTransformResult, error),
) error {
	return atomicTransformFileWithStateDir(path, stateDir, perm, transform)
}

func removedStubRecoveryDir(path, stateDir string) string {
	return atomicTransformRenameableStateDir(path, stateDir)
}
