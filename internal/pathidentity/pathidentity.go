// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package pathidentity compares filesystem paths by object identity whenever
// the objects exist. This prevents aliases such as junctions, hard links,
// mapped drives, and Windows short names from bypassing ownership checks.
package pathidentity

import (
	"errors"
	"os"
	"path/filepath"
)

// Same reports whether left and right identify the same filesystem object.
// Existing objects are compared with os.SameFile. A lexical comparison is
// used only when both paths do not exist, which keeps transaction planning
// useful without weakening checks around an existing object.
func Same(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftAbs = filepath.Clean(leftAbs)
	rightAbs = filepath.Clean(rightAbs)

	leftInfo, leftStatErr := os.Stat(leftAbs)
	rightInfo, rightStatErr := os.Stat(rightAbs)
	if leftStatErr == nil && rightStatErr == nil {
		return os.SameFile(leftInfo, rightInfo)
	}
	if errors.Is(leftStatErr, os.ErrNotExist) && errors.Is(rightStatErr, os.ErrNotExist) {
		return sameMissingPath(leftAbs, rightAbs)
	}
	return false
}
