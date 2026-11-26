// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"golang.org/x/sys/windows"
)

// Expand existing 8.3 components through Windows. A new final name has no
// short alias yet, so use the nearest existing parent and keep its suffix.
//
// Each prefix is expanded as readGated reads it (rel-1-0-10:GAP-1264): below
// a share that has answered, under the hold of its last component, and only
// when the share walk read the prefix as spelled (readNameAsGated):
// GetLongPathName looks the name up again, so a prefix the walk read through
// a link (which may lead to a share since the walk) is not expanded and the
// caller audits it, as an unresolved 8.3 component.
func actionWindowsExpandShortPath(value string) (string, bool) {
	full := strings.ReplaceAll(value, "/", `\`)
	for prefix := full; ; {
		long, err := readGatedValue("getlongpathname", prefix, func(read string) (string, error) {
			if err := readNameAsGated("getlongpathname", prefix, read); err != nil {
				return "", err
			}
			name, err := windows.UTF16PtrFromString(read)
			if err != nil {
				return "", err
			}
			buf := make([]uint16, windows.MAX_LONG_PATH)
			n, err := windows.GetLongPathName(name, &buf[0], uint32(len(buf)))
			if err != nil {
				return "", err
			}
			if n == 0 || n >= uint32(len(buf)) {
				return "", windows.ERROR_INSUFFICIENT_BUFFER
			}
			return windows.UTF16ToString(buf[:n]), nil
		})
		switch {
		case err == nil:
			suffix := strings.TrimPrefix(full[len(prefix):], `\`)
			// An unresolved 8.3 component has no known file identity. Let the
			// caller audit it and apply the protected-directory fallback.
			if strings.Contains(suffix, "~") {
				return "", false
			}
			return filepath.ToSlash(filepath.Join(long, suffix)), true
		case errors.Is(err, errNetworkShareUnanswered), errors.Is(err, errNameReadThroughLink),
			errors.Is(err, pathidentity.ErrLinked):
			return "", false
		}
		parent := filepath.Dir(prefix)
		if parent == prefix || parent == "." {
			return "", false
		}
		prefix = parent
	}
}
