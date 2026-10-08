// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// profileFileInside requires every element of path below home to be an
// ordinary folder or file, not a link or junction. The SYSTEM enumerator
// reads every enrolled profile, so a profile whose .codex is a junction to
// another account's .codex would otherwise report that account's address as
// this profile owner's.
func profileFileInside(home, path string) error {
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return profileFileProblem(home, path, "it is not inside the profile")
	}
	current := filepath.Clean(home)
	for _, part := range strings.Split(rel, `\`) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return ErrNoEmail
		case errors.Is(err, os.ErrPermission):
			return profileFileProblem(home, path, "access is denied")
		case err != nil:
			return profileFileProblem(home, path, "it cannot be inspected")
		case info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
			return profileFileProblem(home, path, "its path goes through a link or junction")
		}
	}
	return nil
}
