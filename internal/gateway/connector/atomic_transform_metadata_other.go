// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

type atomicTransformBoundRenameProtection struct{}

func captureAtomicTransformBoundRenameProtectionPlatform(
	*os.File,
) (atomicTransformBoundRenameProtection, error) {
	return atomicTransformBoundRenameProtection{}, nil
}

func restoreAtomicTransformBoundRenameProtectionPlatform(
	*os.File, atomicTransformBoundRenameProtection,
) error {
	return nil
}

func atomicTransformMetadataPlatform(*os.File) (atomicTransformPlatformMetadata, error) {
	return atomicTransformPlatformMetadata{}, nil
}

func atomicTransformArtifactStatesEqualAfterBoundRename(
	a, b atomicTransformArtifactState,
) bool {
	return atomicTransformArtifactStatesEqualExact(a, b)
}
