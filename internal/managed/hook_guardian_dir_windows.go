// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"path/filepath"
	"strings"
)

// standaloneLayoutGuardianAuthDir is the Windows standalone layout's
// authorization folder (ProgramData\Cisco\DefenseClaw\hook-guardian-state)
// when dataDir is that layout's data folder (its runtime folder), compared
// without case.
func standaloneLayoutGuardianAuthDir(dataDir string) (string, bool) {
	layout, err := StandaloneWindowsLayout()
	if err != nil || strings.TrimSpace(layout.GuardianAuthDir) == "" || strings.TrimSpace(layout.DataDir) == "" ||
		!strings.EqualFold(filepath.Clean(layout.DataDir), dataDir) {
		return "", false
	}
	return filepath.Clean(layout.GuardianAuthDir), true
}
