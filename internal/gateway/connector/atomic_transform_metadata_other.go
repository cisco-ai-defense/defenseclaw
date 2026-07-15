// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

func atomicTransformMetadataPlatform(*os.File) (atomicTransformPlatformMetadata, error) {
	return atomicTransformPlatformMetadata{}, nil
}

func atomicTransformArtifactStatesEqualAfterBoundRename(
	a, b atomicTransformArtifactState,
) bool {
	return atomicTransformArtifactStatesEqualExact(a, b)
}
