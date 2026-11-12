// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import "syscall"

// projectSkillFileLinkCount is how many names the file at path has.
func projectSkillFileLinkCount(path string) (uint64, error) {
	info, err := pathStat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 1, nil
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink), nil //nolint:unconvert // Nlink is 16 bits wide on darwin
	}
	return 1, nil
}
