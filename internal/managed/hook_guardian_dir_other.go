// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import (
	"path/filepath"
	"runtime"
	"strings"
)

// standaloneLayoutGuardianAuthDir is the Linux or macOS standalone layout's
// authorization folder when dataDir is that layout's data folder. On Linux it
// is <dataDir>-hook-guardian; on macOS it is the hook-guardian-state folder
// next to the runtime folder.
func standaloneLayoutGuardianAuthDir(dataDir string) (string, bool) {
	layout, err := StandaloneLayoutFor(runtime.GOOS)
	if err != nil || strings.TrimSpace(layout.GuardianAuthDir) == "" || strings.TrimSpace(layout.DataDir) == "" ||
		filepath.Clean(layout.DataDir) != dataDir {
		return "", false
	}
	return filepath.Clean(layout.GuardianAuthDir), true
}
