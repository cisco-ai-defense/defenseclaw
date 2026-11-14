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
// metacharacter. Listing a directory made the verdict depend on the box: a
// glob over a busy /tmp passed the listing bound and failed closed as an
// authorized-keys write, the same glob over a small /tmp was allowed
// (rel-1-0-10:GAP-0270).
//
// A pattern is decided from its text (actionGlobTextDecides) only when both
// hold:
//   - its literal directory is away from every protected target, by its
//     name and by its resolved form, a ".." resolved after the links before
//     it (rel-1-0-10:GAP-0400);
//   - no component from the first one the shell expands can match a
//     protected name: the .ssh folder, the folder and file names of the
//     protected key files (authorized_keys, the ssh control files, sshd's
//     Windows administrator key file) or a private key name (the name gate,
//     rel-1-0-10:GAP-0398). A link of any name in an away folder that leads
//     to ~/.ssh is then followed by the walk, as before the fix.
//
// Otherwise the pattern is expanded, and an expansion that cannot finish is
// an unknown target, never a silent allow.

// actionGlobLiteralDir is the literal leading directory of an absolute
// pattern, "" for a relative one. A component that a shell may still rewrite
// (a brace list, an extglob group, an escape) ends it as a metacharacter
// does, so the directory is never deeper than the one bash expands under.
// "." and ".." are kept as written: the kernel resolves ".." after the links
// before it, and so does the resolver (walkWritePath); cleaning it by name
// would undo OperandPath, which keeps it raw (rel-1-0-10:GAP-0400).
func actionGlobLiteralDir(pattern string) string {
	if !filepath.IsAbs(pattern) {
		return ""
	}
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
		if !strings.HasSuffix(dir, separator) {
			dir += separator
		}
		dir += component
	}
	return dir
}

// actionGlobComponentMayExpand reports a path component a shell may expand
// or rewrite: a glob metacharacter, a brace list, an extglob group (+(, @(,
// !( with extglob on; ?( and *( hold a metacharacter already) or a
// backslash escape.
func actionGlobComponentMayExpand(component string) bool {
	return strings.ContainsAny(component, "*?[{\\") || actionGlobComponentExtglob(component)
}

func actionGlobComponentExtglob(component string) bool {
	return strings.Contains(component, "+(") || strings.Contains(component, "@(") || strings.Contains(component, "!(")
}

// actionGlobTextDecides reports an absolute pattern that is decided from its
// text: its literal directory is away (actionGlobDirAway) and the name gate
// finds no component that can select a protected name
// (actionGlobMayNameProtected).
func actionGlobTextDecides(pattern, home string, memo *TargetMemo) bool {
	return actionGlobDirAway(actionGlobLiteralDir(pattern), home, memo) && !actionGlobMayNameProtected(pattern, home, memo)
}

// actionGlobMayNameProtected is the name gate: a component of pattern, from
// the first one the shell expands, that can match a protected name
// (actionGlobProtectedNames), without the leading-dot rule and without case
// on Windows and macOS. A component the shell may rewrite (a brace list, an
// extglob group, an escape) can match any name. A pattern with no expanding
// component names only its literal path, which the resolver judges.
func actionGlobMayNameProtected(pattern, home string, memo *TargetMemo) bool {
	separator := string(filepath.Separator)
	volume := filepath.VolumeName(pattern)
	fold := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	names := actionGlobProtectedNames(home, memo)
	expanding := false
	for _, component := range strings.Split(strings.TrimPrefix(pattern[len(volume):], separator), separator) {
		if !expanding && !actionGlobComponentMayExpand(component) {
			continue
		}
		expanding = true
		if component == "" || component == "." || component == ".." {
			continue
		}
		if strings.ContainsAny(component, "{\\") || actionGlobComponentExtglob(component) {
			return true
		}
		if fold {
			component = strings.ToLower(component)
		}
		for _, name := range names {
			if fold {
				name = strings.ToLower(name)
			}
			if matched, err := filepath.Match(component, name); err != nil || matched {
				return true
			}
		}
	}
	return false
}

// actionGlobProtectedNames are the names a pattern component is gated on:
// the file and folder names of the protected key files of home
// (ProtectedAuthorizedKeysPaths: .ssh, authorized_keys, the ssh control
// files, sshd's Windows administrator key file and its folder) and the
// private key names of the key-read rule (actionPrivateKeyNames).
func actionGlobProtectedNames(home string, memo *TargetMemo) []string {
	names := append([]string{".ssh"}, actionPrivateKeyNames...)
	for _, path := range memo.ProtectedAuthorizedKeysPaths(home) {
		names = append(names, filepath.Base(path), filepath.Base(filepath.Dir(path)))
	}
	return names
}

// actionGlobDirAway reports that dir, as named and as resolved, is away
// from the protected targets of home: neither the home, nor a folder of its
// protected key files, nor inside or above one of them (pathNear). A
// directory or home this process cannot resolve is not away: the pattern
// keeps its expansion.
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

// pathNear reports that a and b are the same path or one is inside the
// other. Names compare without case on Windows and macOS.
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

// NearProtected reports a path that is the active home, or one of the
// directories of its protected key files, or inside or above one of them.
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
