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
