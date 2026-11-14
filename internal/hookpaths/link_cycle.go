// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"strings"
)

// linkPointsIntoItself reports a link whose target is the link or lies below
// it (ln -s /a/b/c /a/b, or ln -s /a/b/c /a, which names /a/b/c itself where
// /a is a directory). Every path through such a link returns to the link, so
// it ends in ELOOP and reaches no file. Left in the alias list it made the
// walk of every later write loop to its step bound and fail closed, so a
// benign ln -s of a folder into its own parent was an authorized-keys block
// (rel-1-0-10:GAP-0018). Windows names compare without case and take either
// separator, so it keeps the old reading there.
func linkPointsIntoItself(name, target string) bool {
	if runtime.GOOS == "windows" || name == "" || target == "" {
		return false
	}
	name, target = filepath.Clean(name), filepath.Clean(target)
	if name == string(filepath.Separator) {
		return false
	}
	return target == name || strings.HasPrefix(target, name+string(filepath.Separator))
}
