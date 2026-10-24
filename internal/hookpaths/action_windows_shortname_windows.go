// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Expand existing 8.3 components through Windows. A new final name has no
// short alias yet, so use the nearest existing parent and keep its suffix.
func actionWindowsExpandShortPath(value string) (string, bool) {
	full := strings.ReplaceAll(value, "/", `\`)
	for prefix := full; ; {
		name, err := windows.UTF16PtrFromString(prefix)
		if err != nil {
			return "", false
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetLongPathName(name, &buf[0], uint32(len(buf)))
		if err == nil && n > 0 && n < uint32(len(buf)) {
			suffix := strings.TrimPrefix(full[len(prefix):], `\`)
			return filepath.ToSlash(filepath.Join(windows.UTF16ToString(buf[:n]), suffix)), true
		}
		parent := filepath.Dir(prefix)
		if parent == prefix || parent == "." {
			return "", false
		}
		prefix = parent
	}
}
