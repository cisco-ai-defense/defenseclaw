// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

func atomicTransformFileWithStateDir(
	path string,
	transactionDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	return atomicTransformFileLegacyWithStateDir(path, transactionDir, perm, transform)
}
