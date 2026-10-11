// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"strings"
)

// discoveryPathThroughLink reports whether path, at or below root, resolves
// outside root through a symbolic link, the rule a per-user scan applies to
// its own home: a link that stays inside root is the owner's own content. A
// path that does not exist or cannot be resolved passes: the scan cannot read
// it either. Asked about root itself, it reports whether root is a link.
func discoveryPathThroughLink(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	if rel == "." {
		info, err := os.Lstat(root)
		return err == nil && info.Mode()&os.ModeSymlink != 0
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err = filepath.Rel(resolvedRoot, resolved)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
