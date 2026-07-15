// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "os"

func atomicTransformMetadataPlatform(file *os.File) (atomicTransformPlatformMetadata, error) {
	witness, err := atomicTransformV2WindowsMetadataFromOpen(file)
	if err != nil {
		return atomicTransformPlatformMetadata{}, err
	}
	return atomicTransformPlatformMetadata{
		digest:           witness.Digest,
		preservedDigest:  witness.PreservedDigest,
		stageOwnedDigest: witness.StageOwnedDigest,
		ownerGroupDigest: witness.OwnerGroupSHA256,
		creationTime:     witness.CreationTime,
		lastWriteTime:    witness.LastWriteTime,
	}, nil
}

// A no-replace rename on NTFS can normalize CreationTime and the
// ARCHIVE/NORMAL attribute pair even while the rename handle denies content or
// metadata writers. Require every stable component witnessed around that held
// handle, and tolerate only those two native rename effects.
func atomicTransformArtifactStatesEqualAfterBoundRename(
	a, b atomicTransformArtifactState,
) bool {
	return a.exists && b.exists && os.SameFile(a.info, b.info) &&
		a.identity == b.identity && a.digest == b.digest && a.size == b.size &&
		a.info.Mode() == b.info.Mode() && a.protectionDigest == b.protectionDigest &&
		a.preservedMetadataDigest == b.preservedMetadataDigest &&
		a.stageOwnedMetadataDigest == b.stageOwnedMetadataDigest &&
		a.ownerGroupDigest == b.ownerGroupDigest &&
		a.lastWriteTime == b.lastWriteTime && a.linkCount == b.linkCount
}
