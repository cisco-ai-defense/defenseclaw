//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

var pluginScannerExecutable = os.Executable

// resolveDefaultPluginScanner binds the packaged gateway's default scanner
// command to the launcher installed beside it. Explicit scanner configuration
// remains authoritative; only the two bare defaults are eligible for packaged
// resolution.
func resolveDefaultPluginScanner(binaryPath string) string {
	if binaryPath != "defenseclaw" && binaryPath != "defenseclaw.exe" {
		return binaryPath
	}

	gatewayPath, err := pluginScannerExecutable()
	if err != nil || !filepath.IsAbs(gatewayPath) ||
		!strings.EqualFold(filepath.Base(gatewayPath), "defenseclaw-gateway.exe") {
		return binaryPath
	}

	launcherPath := filepath.Join(filepath.Dir(gatewayPath), "defenseclaw.exe")
	info, err := os.Lstat(launcherPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return binaryPath
	}
	return launcherPath
}
