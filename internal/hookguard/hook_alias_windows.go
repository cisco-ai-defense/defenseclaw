// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// hookExecutableAlias reports an absolute 8.3 alias (C:\PROGRA~1\...\
// DEFENS~1.EXE) of an existing regular file whose own long name is
// defenseclaw-hook.exe. An administrator's HKLM Claude matrix can name the
// launcher of the guarded wrapper so (GAP-2244). The long spelling is the
// one Windows reports for path itself and must open the same file, so an
// alias admits exactly what its long spelling admits: another file, or a
// name that does not answer, is refused. Standard library and x/sys only,
// as the rest of the guard.
func hookExecutableAlias(path string) bool {
	if !strings.Contains(path, "~") || !IsWindowsAbsolutePath(path) {
		return false
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return false
	}
	long := windows.UTF16ToString(buffer[:n])
	if strings.Contains(long[strings.LastIndexAny(long, `\/`)+1:], "~") || !AbsoluteHookExecutable(long) {
		return false
	}
	aliasInfo, aliasErr := os.Stat(path)
	longInfo, longErr := os.Stat(long)
	return aliasErr == nil && longErr == nil && aliasInfo.Mode().IsRegular() && os.SameFile(aliasInfo, longInfo)
}
