//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// windowsAdminProgramFiles is windowsDefaultProgramFiles: this computer has
// no Windows machine registration, and only renders the hint.
func windowsAdminProgramFiles() string {
	return windowsDefaultProgramFiles
}
