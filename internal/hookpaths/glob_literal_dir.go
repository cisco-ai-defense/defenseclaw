// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"strings"
)

// A pathname pattern selects only names under its literal leading
// directory: the components before the first one that holds a glob
// metacharacter. When that directory is away from every protected target
// (NearProtected), by its name and by its resolved form, no match can be
// one of them, and the pattern is decided from its text. Listing such a
// directory made the verdict depend on the box: a glob over a busy /tmp
// passed the listing bound and failed closed as an authorized-keys write,
// the same glob over a small /tmp was allowed (rel-1-0-10:GAP-0270).
//
// A link that a listing would find there is not followed. Making such a
// link names its protected target, and that call is judged by the write
// and link readings; a literal operand through a link is still resolved.

// actionGlobLiteralDir is the literal leading directory of an absolute
// pattern. A component that a shell may still rewrite (a brace list, an
// extglob group, an escape) ends it as a metacharacter does, so the
// directory is never deeper than the one bash expands under.
func actionGlobLiteralDir(pattern string) string {
	separator := string(filepath.Separator)
	volume := filepath.VolumeName(pattern)
	dir := volume + separator
	for _, component := range strings.Split(strings.TrimPrefix(pattern[len(volume):], separator), separator) {
		if component == "" {
			continue
		}
		if actionGlobComponentMayExpand(component) {
			break
		}
		dir = filepath.Join(dir, component)
	}
	return dir
}

// actionGlobComponentMayExpand reports a path component a shell may expand
// or rewrite: a glob metacharacter, a brace list, an extglob group (+(, @(,
// !( with extglob on; ?( and *( hold a metacharacter already) or a
// backslash escape.
func actionGlobComponentMayExpand(component string) bool {
	return strings.ContainsAny(component, "*?[{\\") ||
		strings.Contains(component, "+(") || strings.Contains(component, "@(") || strings.Contains(component, "!(")
}

// actionGlobDirAway reports that dir, as named and as resolved, is away
// from the protected targets of home (NearProtected), so a pattern under it
// cannot select one by name. A directory or home this process cannot
// resolve is not away: the pattern keeps its expansion.
func actionGlobDirAway(dir, home string, memo *TargetMemo) bool {
	if home == "" || !filepath.IsAbs(dir) || !filepath.IsAbs(home) {
		return false
	}
	physical, ok := memo.resolveWriteTarget(dir)
	if !ok {
		return false
	}
	physicalHome, ok := memo.resolveWriteTarget(home)
	if !ok {
		return false
	}
	keys := memo.ProtectedAuthorizedKeysPaths(home)
	for _, candidate := range []string{dir, physical} {
		for _, root := range []string{home, physicalHome} {
			if pathNear(candidate, root) {
				return false
			}
		}
		for _, key := range keys {
			if pathNear(candidate, filepath.Dir(key)) {
				return false
			}
		}
	}
	return true
}

// NearProtected reports a path that is the active home, or one of the
// directories of its protected key files, or inside or above one of them:
// the places where a write can reach the key files, the DefenseClaw state
// and the agent hook configs. Names compare without case on Windows and
// macOS.
func NearProtected(path, home string) bool {
	if pathNear(path, home) {
		return true
	}
	for _, key := range ProtectedAuthorizedKeysPaths(home) {
		if pathNear(path, filepath.Dir(key)) {
			return true
		}
	}
	return false
}

// pathNear reports that a and b are the same path or one is inside the
// other.
func pathNear(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	within := func(path, root string) bool {
		return path == root || strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}
