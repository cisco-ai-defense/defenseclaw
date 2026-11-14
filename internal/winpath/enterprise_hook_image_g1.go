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

import "strings"

// EnterpriseInstallBinOf returns the <InstallRoot>\bin folder that holds
// executable: its own folder when that folder is named bin (the gateway,
// the CLI, the transition hook image), or the bin of a hook or hook guard
// launch image under bin\hooks\<16 hex> (GAP-0751). It returns "" for any
// other path. The caller still validates the install root, Dir(bin).
func EnterpriseInstallBinOf(executable string) string {
	executable = cleanWindowsPath(executable)
	if !windowsAbsoluteDrivePath(executable) {
		return ""
	}
	if location, ok := ParseEnterpriseHookImagePath(executable); ok {
		return location.Bin
	}
	dir, name := splitWindowsParent(executable)
	if name == "" || isDriveRoot(dir) || !strings.EqualFold(lastWindowsName(dir), "bin") {
		return ""
	}
	return dir
}

// SameEnterpriseHookImageFamilyExact is SameEnterpriseHookImageFamily for
// the checks that also require a recorded path's exact spelling: the bin
// folder and the image name are spelled the same in both paths; only the
// launch folder (or its absence, for the transition image) may differ.
func SameEnterpriseHookImageFamilyExact(a, b string) bool {
	left, ok := ParseEnterpriseHookImagePath(a)
	if !ok || cleanWindowsPath(a) != a {
		return false
	}
	right, ok := ParseEnterpriseHookImagePath(b)
	if !ok || cleanWindowsPath(b) != b {
		return false
	}
	return left.Name == right.Name && left.Bin == right.Bin
}

// SameEnterpriseHookImageDirFamily reports two folders that each hold a
// managed hook launch set of the same bin: bin itself (the transition
// images) or bin\hooks\<16 hex>. Codex names that folder in
// hooks.windows_managed_dir, so an earlier release's value is this
// install's own folder too.
func SameEnterpriseHookImageDirFamily(a, b string) bool {
	return SameEnterpriseHookImageFamily(
		joinWindowsPath(a, EnterpriseHookImageName),
		joinWindowsPath(b, EnterpriseHookImageName),
	)
}

// EnterpriseHookImagePathsIn returns every drive path in text that ends with
// the hook image name, from the nearest drive prefix ("X:\") before the name
// to the end of the name, when that span holds no quote or line break: the
// hook paths a rendered hook command names (GAP-0751). Callers keep only
// paths of the family they own and still compare the whole command with the
// one rendered for that path, so this only proposes candidates.
func EnterpriseHookImagePathsIn(text string) []string {
	var paths []string
	lower := strings.ToLower(text)
	name := strings.ToLower(EnterpriseHookImageName)
	for offset := 0; ; {
		index := strings.Index(lower[offset:], name)
		if index < 0 {
			return paths
		}
		start := offset + index
		end := start + len(name)
		offset = end
		drive := strings.LastIndex(text[:start], `:\`)
		if drive < 1 {
			continue
		}
		candidate := text[drive-1 : end]
		if strings.ContainsAny(candidate, "\"'\r\n`") {
			continue
		}
		if _, ok := ParseEnterpriseHookImagePath(candidate); ok {
			paths = append(paths, candidate)
		}
	}
}
