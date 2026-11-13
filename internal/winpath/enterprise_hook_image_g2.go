// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"io/fs"
	"strings"
)

// Writer-side helpers for the versioned managed hook images (GAP-0751); see
// enterprise_hook_image.go for the layout.

// enterpriseHookStagingPrefix starts the name of the folder Setup writes a
// new launch set into before it renames it to <d16>: .staging-<32 hex>.
const enterpriseHookStagingPrefix = ".staging-"

// EnterpriseHookStagingDirName is the staging folder name for a 32-hex
// random suffix.
func EnterpriseHookStagingDirName(suffix string) string {
	return enterpriseHookStagingPrefix + strings.ToLower(suffix)
}

// IsEnterpriseHookStagingDirName reports a staging folder left by an
// interrupted stage: .staging-<32 hex>.
func IsEnterpriseHookStagingDirName(name string) bool {
	suffix, ok := strings.CutPrefix(strings.ToLower(name), enterpriseHookStagingPrefix)
	return ok && isLowerHex(suffix, 32)
}

// IsEnterpriseHookImageBackupName reports the copy the guardian's image swap
// keeps of a replaced launch image while a program still runs it:
// <image name>.backup.<32 hex>.
func IsEnterpriseHookImageBackupName(name string) bool {
	lower := strings.ToLower(name)
	for _, image := range []string{EnterpriseHookImageName, EnterpriseHookGuardImageName} {
		if suffix, ok := strings.CutPrefix(lower, image+".backup."); ok && isLowerHex(suffix, 32) {
			return true
		}
	}
	return false
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// ResolveEnterpriseHookLaunchSet is ResolveEnterpriseHookImage for writers:
// when bin has no hooks folder (a 1.0.9 layout, Secure Client, a development
// tree) it returns the transition set after one Lstat, without reading the
// transition image, so those layouts cost what they cost before. A process
// started from a launch folder resolves its own folder this way too (it has
// no hooks folder below it).
func ResolveEnterpriseHookLaunchSet(bin string) EnterpriseHookImage {
	return ResolveEnterpriseHookLaunchSetWith(osHookImageFS{}, bin)
}

// ResolveEnterpriseHookLaunchSetWith is ResolveEnterpriseHookLaunchSet on fsys.
func ResolveEnterpriseHookLaunchSetWith(fsys EnterpriseHookImageFS, bin string) EnterpriseHookImage {
	bin = cleanWindowsPath(bin)
	if _, err := fsys.Lstat(EnterpriseHookImagesRoot(bin)); errors.Is(err, fs.ErrNotExist) {
		out := EnterpriseHookImage{
			Bin:   bin,
			Hook:  joinWindowsPath(bin, EnterpriseHookImageName),
			State: EnterpriseHookImageLegacyLayout,
		}
		guard := joinWindowsPath(bin, EnterpriseHookGuardImageName)
		if info, err := fsys.Lstat(guard); err == nil && info.Mode().IsRegular() {
			out.Guard = guard
		}
		return out
	}
	return ResolveEnterpriseHookImageWith(fsys, bin)
}

// EnterpriseHookLaunchPath is the hook path a writer puts in an agent
// config for bin (ResolveEnterpriseHookLaunchSet(bin).Hook).
func EnterpriseHookLaunchPath(bin string) string {
	return ResolveEnterpriseHookLaunchSet(bin).Hook
}
