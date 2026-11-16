// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"path/filepath"
	"runtime"
)

// actionMissingSimpleTargets proves that a large group of numeric names in
// one directory has no existing entry or protected pathname. In this case
// a directory listing gives the same absence answer as walking each name.
// Existing entries, complex paths and unreadable directories use the usual
// per-target resolver, which also checks links and file identity.
func actionMissingSimpleTargets(names []string, cwd string, protected protectedFiles, ssh string, memo *TargetMemo) bool {
	if runtime.GOOS != "linux" || len(names) < 128 || !filepath.IsAbs(cwd) {
		return false
	}
	for _, name := range names {
		if name == "" {
			return false
		}
		for _, ch := range name {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	parent, ok := memo.resolveWriteTarget(cwd)
	if !ok {
		return false
	}
	dir, err := pathOpen(parent)
	if err != nil {
		return false
	}
	// A very large directory is cheaper to check with the normal path
	// resolver than to enumerate. Read one past the bound to detect it.
	entries, readErr := dir.ReadDir(4097)
	closeErr := dir.Close()
	if len(entries) > 4096 || readErr != nil && readErr != io.EOF || closeErr != nil {
		return false
	}
	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		present[entry.Name()] = true
	}
	for _, name := range names {
		if present[name] {
			return false
		}
		target := filepath.Join(parent, name)
		if protected.has(target) || samePathName(target, ssh) {
			return false
		}
	}
	return true
}
