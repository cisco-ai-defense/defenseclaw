// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// Reparse tags Windows attaches to ordinary files and folders without
// redirecting them anywhere: Compact OS / WOF compression, Data
// Deduplication, and OneDrive / cloud-files placeholders. None of them is a
// name surrogate, so the object still is what its path says.
const (
	windowsReparseTagWOF        uint32 = 0x80000017
	windowsReparseTagDedup      uint32 = 0x80000013
	windowsReparseTagCloud      uint32 = 0x9000001A
	windowsReparseTagCloudMask  uint32 = 0xFFFF0FFF
	windowsReparseTagSurrogate  uint32 = 0x20000000
	windowsReparseTagMicrosoft  uint32 = 0x80000000
	windowsReparseTagAppExecute uint32 = 0x8000001B
)

// harmlessWindowsReparseTag reports whether a reparse tag only changes how a
// file's data is stored. Junctions, symlinks, mount points, app-execution
// aliases and every unknown tag stay rejected.
func harmlessWindowsReparseTag(tag uint32) bool {
	if tag&windowsReparseTagSurrogate != 0 || tag&windowsReparseTagMicrosoft == 0 ||
		tag == windowsReparseTagAppExecute {
		return false
	}
	switch {
	case tag == windowsReparseTagWOF, tag == windowsReparseTagDedup:
		return true
	case tag&windowsReparseTagCloudMask == windowsReparseTagCloud:
		return true
	default:
		return false
	}
}
