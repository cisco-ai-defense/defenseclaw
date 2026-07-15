// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func trustedWindowsSystemDirectory() string {
	dir, err := windows.GetSystemDirectory()
	if err == nil && filepath.IsAbs(dir) && strings.TrimSpace(dir) != "" {
		return filepath.Clean(dir)
	}
	// GetWindowsDirectoryW is a second immutable OS boundary for older or
	// unusual hosts where GetSystemDirectoryW cannot populate its buffer.
	root, fallbackErr := windows.GetWindowsDirectory()
	if fallbackErr == nil && filepath.IsAbs(root) && strings.TrimSpace(root) != "" {
		return filepath.Join(filepath.Clean(root), "System32")
	}
	// Both kernel32 calls failing indicates a broken Windows runtime. Keep the
	// command independent of attacker-controlled environment variables while
	// retaining the conventional fail-safe location for diagnostics.
	return `C:\Windows\System32`
}
