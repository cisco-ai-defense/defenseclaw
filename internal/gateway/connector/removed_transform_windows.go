// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "os"

// A retired module can carry the ownership and inherited DACL from an older
// setup. The Windows V1 CAS protocol holds the verified file against writes
// and replacement, detaches that exact handle, and publishes the private stub
// only if the path is still vacant. It keeps a recovery intent throughout.
// ReplaceFileW in V2 merges an inherited legacy DACL with the stage DACL, so
// its exact-metadata proof refuses this legitimate teardown.
func removedStubTransform(
	path, stateDir string, perm os.FileMode,
	transform func([]byte, bool) (atomicTransformResult, error),
) error {
	if err := atomicTransformFileLegacyWithStateDir(path, stateDir, perm, transform); err != nil {
		return err
	}
	// V1 leaves a completed receipt for compatibility with old callers.
	// Retire it now so teardown leaves only the saved copies it reports.
	return recoverAtomicTransformWithStateDir(path, stateDir)
}

func removedStubRecoveryDir(_ string, stateDir string) string {
	return stateDir
}
