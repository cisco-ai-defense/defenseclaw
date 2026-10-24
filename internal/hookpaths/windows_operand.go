// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// WindowsOperandPath resolves one static path operand of a command a Windows
// hook ran, in a spelling Git Bash, cmd or PowerShell accepts there (C:\x,
// C:/x, /c/x, /cygdrive/c/x, UNC and extended paths, %USERPROFILE%,
// $env:USERPROFILE, $HOME, ~), relative operands against the Windows working
// directory. It is the resolver the Windows action decision uses, so a
// gateway proof and the action decision name the same target. The result is
// the lower-case, forward-slash form. It reports false when the operand has
// no static Windows target: an expansion or glob, a drive-relative, ".." or
// short-name spelling, a relative operand without a Windows working
// directory, or a home spelling without a Windows home.
func WindowsOperandPath(value, cwd, home string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if strings.ContainsAny(value[:1], "~$%") && !actionWindowsHome(home) {
		return "", false
	}
	resolved, ok := actionWindowsPath(value, cwd, home)
	if !ok || !actionWindowsHome(resolved) {
		return "", false
	}
	return resolved, true
}
