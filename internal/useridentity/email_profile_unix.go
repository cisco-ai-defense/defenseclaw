// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// profileFileInside requires path, with every link resolved, to stay inside
// home. A ~/.codex that links into another account's home would otherwise
// report that account's address as this profile owner's.
func profileFileInside(home, path string) error {
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return ErrNoEmail
	}
	resolved, err := filepath.EvalSymlinks(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ErrNoEmail
	case errors.Is(err, os.ErrPermission):
		return profileFileProblem(home, path, "access is denied (a link to another account's folder, or a folder only its owner may open)")
	case err != nil:
		return profileFileProblem(home, path, "its path cannot be resolved")
	}
	rel, err := filepath.Rel(resolvedHome, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return profileFileProblem(home, path, "it links outside the profile")
	}
	return nil
}
