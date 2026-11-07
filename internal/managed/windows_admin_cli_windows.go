//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsAdminProgramFiles is Program Files from the protected HKLM
// registration (winpath.TrustedProgramFiles, as StandaloneWindowsLayout
// reads it), or windowsDefaultProgramFiles when it cannot be read.
func windowsAdminProgramFiles() string {
	root, err := winpath.TrustedProgramFiles()
	root = strings.TrimRight(strings.TrimSpace(root), `\`)
	if err != nil || root == "" {
		return windowsDefaultProgramFiles
	}
	return root
}
