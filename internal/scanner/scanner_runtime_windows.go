// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// scannerRuntimePath is the installed scanner runtime, or "" when this host
// has none; tests replace it.
var scannerRuntimePath = func() string {
	root, err := managed.StandaloneWindowsScannerRuntimeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	// Only an administrator-owned runtime that no standard user can
	// replace is run.
	if managed.ValidateTrustedFilePath(path, "scanner runtime") != nil {
		return ""
	}
	return path
}

// resolveScannerRuntime binds a bare default scanner command to the scanner
// runtime the standalone Windows enterprise lifecycle installs. An explicit
// scanner path in config stays authoritative, and every other install
// (per-user, Secure Client) has no scanner runtime and keeps binary.
func resolveScannerRuntime(binary string, defaults ...string) string {
	for _, name := range defaults {
		if strings.EqualFold(strings.TrimSpace(binary), name) {
			if path := scannerRuntimePath(); path != "" {
				return path
			}
			return binary
		}
	}
	return binary
}
