// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

type atomicTransformBoundRenameProtection struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	canonical  string
}

func captureAtomicTransformBoundRenameProtectionPlatform(
	file *os.File,
) (atomicTransformBoundRenameProtection, error) {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return atomicTransformBoundRenameProtection{}, err
	}
	canonical, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(descriptor.String())
	if err != nil {
		return atomicTransformBoundRenameProtection{}, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return atomicTransformBoundRenameProtection{}, fmt.Errorf("read bound rename DACL: %w", err)
	}
	if dacl == nil {
		return atomicTransformBoundRenameProtection{}, fmt.Errorf("read bound rename DACL: DACL is absent")
	}
	return atomicTransformBoundRenameProtection{descriptor: descriptor, canonical: canonical}, nil
}

func restoreAtomicTransformBoundRenameProtectionPlatform(
	file *os.File, before atomicTransformBoundRenameProtection,
) error {
	current, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		return err
	}
	if current == before.canonical {
		return nil
	}
	normalized, err := atomicTransformV2WindowsDACLIsReplaceNormalization(current, before.canonical)
	if err != nil {
		return err
	}
	if !normalized {
		return fmt.Errorf("bound rename made an unrecognized DACL change: %s -> %s", before.canonical, current)
	}
	dacl, _, err := before.descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read authenticated pre-rename DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("read authenticated pre-rename DACL: DACL is absent")
	}
	control, _, err := before.descriptor.Control()
	if err != nil {
		return fmt.Errorf("read authenticated pre-rename DACL control: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, securityInformation,
		nil, nil, dacl, nil,
	); err != nil {
		return err
	}
	runtime.KeepAlive(before.descriptor)
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("flush restored bound rename DACL: %w", err)
	}
	restored, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		return err
	}
	if restored != before.canonical {
		return fmt.Errorf("restored bound rename DACL does not match authenticated source")
	}
	return nil
}

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
