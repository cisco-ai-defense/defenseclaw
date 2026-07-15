// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package nativeinstallstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var nativeInstallStateCompareStringOrdinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")

// LoadForExecutable recognizes only the current user's Known-Folder-derived
// native install. recognized remains true for a damaged canonical install so
// callers fail closed instead of falling back to ambient profile variables.
func LoadForExecutable(executable string) (state State, recognized bool, err error) {
	programs, err := winfolders.UserProgramFiles()
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
	return pathidentity.Same(left, right)
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

func openStateFile(path string) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap native install state handle")
	}
	if err := validateOpenedStateFile(file, path); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenedStateFile(file *os.File, expectedPath string) error {
	var info windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("native install state handle is redirected or not a regular file")
	}
	resolved, err := nativeInstallStateFinalPath(handle)
	if err != nil {
		return err
	}
	expected, err := filepath.Abs(expectedPath)
	if err != nil {
		return err
	}
	if !nativeInstallStatePathsEqual(resolved, filepath.Clean(expected)) {
		return fmt.Errorf("native install state final path changed: got %s", resolved)
	}
	return nil
}

func nativeInstallStateFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err == nil && length < uint32(len(buffer)) {
			resolved := windows.UTF16ToString(buffer[:length])
			switch {
			case strings.HasPrefix(resolved, `\\?\UNC\`):
				resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
			case strings.HasPrefix(resolved, `\\?\`):
				resolved = strings.TrimPrefix(resolved, `\\?\`)
			}
			return filepath.Clean(resolved), nil
		}
		if length >= uint32(len(buffer)) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			next := int(length) + 1
			if next <= len(buffer) {
				next = len(buffer) * 2
			}
			buffer = make([]uint16, next)
			continue
		}
		if err != nil {
			return "", err
		}
		buffer = make([]uint16, len(buffer)*2)
	}
}

func nativeInstallStatePathsEqual(left, right string) bool {
	leftUTF16, leftErr := windows.UTF16FromString(left)
	rightUTF16, rightErr := windows.UTF16FromString(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	result, _, _ := nativeInstallStateCompareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&leftUTF16[0])), uintptr(len(leftUTF16)-1),
		uintptr(unsafe.Pointer(&rightUTF16[0])), uintptr(len(rightUTF16)-1),
		1,
	)
	return result == 2
}
