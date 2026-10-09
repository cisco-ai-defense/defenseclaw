// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"path/filepath"
	"strings"
)

// addressablePath is path in the extended form when its last element ends
// with a dot or a space. Win32 path normalization drops those from the last
// element, so os.Stat of such a skill folder looked for another name and the
// watcher skipped the folder without a word, while an agent reading the
// files below it (the dot is kept on inner elements) still loads it
// (GAP-0573).
func addressablePath(path string) string {
	base := filepath.Base(path)
	if base == "." || base == ".." || (!strings.HasSuffix(base, ".") && !strings.HasSuffix(base, " ")) {
		return path
	}
	if strings.HasPrefix(path, `\\?\`) || !filepath.IsAbs(path) {
		return path
	}
	if volume := filepath.VolumeName(path); len(volume) == 2 && strings.HasSuffix(volume, ":") {
		return `\\?\` + path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return path
}

// addressableStandalonePath also preserves final spaces for standalone
// watcher assets; Secure Client retains its original path handling.
func addressableStandalonePath(path string) string {
	if strings.HasSuffix(path, ".") || strings.HasSuffix(path, " ") {
		return extendedWindowsPath(path)
	}
	return path
}

// extendedWindowsPath bypasses Win32's trailing-dot and trailing-space
// normalization while preserving the same absolute path.
func extendedWindowsPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) || !filepath.IsAbs(path) {
		return path
	}
	if volume := filepath.VolumeName(path); len(volume) == 2 && strings.HasSuffix(volume, ":") {
		return `\\?\` + path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return path
}

// addressableQuarantinePaths keeps the checked source and destination names
// exact while giving the planner roots in the same extended spelling.
func addressableQuarantinePaths(path string, roots []string, quarantineRoot string) (string, []string, string) {
	if !strings.HasSuffix(path, ".") && !strings.HasSuffix(path, " ") {
		return path, roots, quarantineRoot
	}
	extendedRoots := make([]string, len(roots))
	for i, root := range roots {
		extendedRoots[i] = extendedWindowsPath(root)
	}
	return extendedWindowsPath(path), extendedRoots, extendedWindowsPath(quarantineRoot)
}

// physicalAssetName preserves a final space that filepath.Base normalizes.
func physicalAssetName(path string) string {
	if strings.HasSuffix(path, " ") {
		return path[strings.LastIndexAny(path, `/\`)+1:]
	}
	return filepath.Base(path)
}
