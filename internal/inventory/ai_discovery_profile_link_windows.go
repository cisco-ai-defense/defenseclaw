// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// discoveryPathThroughLink reports whether path, at or below root, is reached
// through a link, junction, mount point or other reparse point, so that the
// gateway service reading it would read another folder than the one root
// names. It opens path without following a final reparse point and compares
// the opened object with root: the object must not be a reparse point and
// its final path must be root's followed by the same relative path. That
// needs read-attributes access on path alone, all a managed gateway has
// below a profile, and catches a junction at any element above path. A path
// that does not exist, or that the caller may not open, passes: the scan
// cannot read it either. Asked about root itself, it reports whether root is
// a reparse point.
func discoveryPathThroughLink(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return true
	}
	finalRoot := root
	if attributes, final, ok := discoveryNoFollowFacts(root); ok {
		if rel == "." {
			return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
		}
		if final != "" {
			finalRoot = final
		}
	}
	if rel == "." {
		return false
	}
	attributes, final, ok := discoveryNoFollowFacts(path)
	if !ok {
		return false
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || final == "" {
		return true
	}
	return !strings.EqualFold(final, strings.TrimRight(finalRoot, `\`)+`\`+rel)
}

// discoveryNoFollowFacts opens path for its attributes alone, without
// following a final reparse point, and returns its attributes and final path
// (empty when Windows cannot name it). ok is false when path cannot be opened.
func discoveryNoFollowFacts(path string) (attributes uint32, final string, ok bool) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, "", false
	}
	handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, "", false
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, "", false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED, VOLUME_NAME_DOS
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return info.FileAttributes, "", true
	}
	final = windows.UTF16ToString(buf[:n])
	if strings.HasPrefix(final, `\\?\UNC\`) {
		final = `\\` + final[len(`\\?\UNC\`):]
	} else {
		final = strings.TrimPrefix(final, `\\?\`)
	}
	return info.FileAttributes, filepath.Clean(final), true
}
