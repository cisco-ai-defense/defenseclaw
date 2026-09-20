// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package winpath prepares filesystem paths for raw Win32 APIs. Go's os
// package adds extended-length prefixes internally, but x/sys/windows calls do
// not. Keeping the conversion in one place prevents a redirected user profile
// or deeply nested repository from falling back to the legacy MAX_PATH limit.
package winpath

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Extended returns an absolute, cleaned extended-length Win32 path. UNC paths
// use the required \\?\UNC\server\share form. Win32 device namespaces are
// rejected: this helper is for filesystem paths, never devices or GLOBALROOT.
func Extended(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("Windows filesystem path is empty")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", fmt.Errorf("Windows filesystem path contains NUL")
	}
	path = filepath.FromSlash(path)
	if strings.HasPrefix(path, `\\.\`) {
		return "", fmt.Errorf("Windows device path is not a filesystem path")
	}
	if strings.HasPrefix(path, `\\?\UNC\`) {
		parts := strings.Split(strings.TrimPrefix(path, `\\?\UNC\`), `\`)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("Windows extended UNC path has no server/share")
		}
		return path, nil
	}
	if strings.HasPrefix(path, `\\?\`) {
		candidate := strings.TrimPrefix(path, `\\?\`)
		if len(candidate) < 3 || candidate[1] != ':' || (candidate[2] != '\\' && candidate[2] != '/') {
			return "", fmt.Errorf("unsupported Windows extended filesystem path")
		}
		return path, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	if strings.HasPrefix(absolute, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(absolute, `\\`), nil
	}
	return `\\?\` + absolute, nil
}

// UTF16Ptr returns a NUL-terminated pointer for an extended-length filesystem
// path suitable for raw Win32 file APIs.
func UTF16Ptr(path string) (*uint16, error) {
	extended, err := Extended(path)
	if err != nil {
		return nil, err
	}
	return windows.UTF16PtrFromString(extended)
}

// RejectReparseChain rejects any existing reparse point between path and its
// volume root. Missing path elements are allowed so callers can validate a
// destination before creating it.
func RejectReparseChain(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		ptr, err := UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point in path: %s", current)
		}
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}
