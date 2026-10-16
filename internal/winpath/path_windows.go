// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package winpath prepares filesystem paths for raw Win32 APIs. Go's os
// package adds extended-length prefixes internally, but x/sys/windows calls do
// not. Keeping the conversion in one place prevents a redirected user profile
// or deeply nested repository from falling back to the legacy MAX_PATH limit.
package winpath

import (
	"errors"
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

// windowsPathAttributes reads the attributes of one element. Tests replace it
// to check that no element below a refused or missing one is read.
var windowsPathAttributes = func(path string) (uint32, error) {
	ptr, err := UTF16Ptr(path)
	if err != nil {
		return 0, err
	}
	return windows.GetFileAttributes(ptr)
}

// RejectReparseChain checks from the volume root down and rejects any existing
// reparse point before reading an element below it. A missing element ends the
// walk without reading below it, so callers can validate a destination before
// creating it.
func RejectReparseChain(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// Keep conversion errors observable even when an ancestor is missing.
	if _, err := UTF16Ptr(abs); err != nil {
		return err
	}
	var chain []string
	for current := abs; ; {
		chain = append(chain, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	for i := len(chain) - 1; i >= 0; i-- {
		attributes, err := windowsPathAttributes(chain[i])
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point in path: %s", chain[i])
		}
	}
	return nil
}
