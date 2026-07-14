// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package nativeinstallstate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// LoadForExecutable recognizes only the current user's Known-Folder-derived
// native install. recognized remains true for a damaged canonical install so
// callers fail closed instead of falling back to ambient profile variables.
func LoadForExecutable(executable string) (state State, recognized bool, err error) {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_UserProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return state, false, fmt.Errorf("resolve UserProgramFiles Known Folder: %w", err)
	}
	if strings.TrimSpace(programs) == "" {
		return state, false, fmt.Errorf("UserProgramFiles Known Folder is empty")
	}
	installRoot := filepath.Join(programs, "DefenseClaw")
	absExecutable, err := filepath.Abs(executable)
	if err != nil {
		return state, false, err
	}
	if !samePath(filepath.Dir(absExecutable), filepath.Join(installRoot, "bin")) {
		return state, false, nil
	}
	state, err = loadAt(absExecutable, installRoot)
	return state, true, err
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}

func safePath(path string) bool {
	current, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		pointer, err := winpath.UTF16Ptr(current)
		if err != nil {
			return false
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
		current = parent
	}
}
