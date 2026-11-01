// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"strings"
)

// WindowsStandaloneAdminCLI is the managed CLI an administrator runs on a
// Windows standalone computer, as the docs name it. Setup puts no
// DefenseClaw command on PATH, so a hint must name this path (GAP-1183).
func WindowsStandaloneAdminCLI() string {
	root := strings.TrimRight(strings.TrimSpace(os.Getenv("ProgramFiles")), `\`)
	if root == "" {
		root = `C:\Program Files`
	}
	return root + `\Cisco\DefenseClaw\bin\defenseclaw.exe`
}
