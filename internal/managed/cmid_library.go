// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cmidLibraryName is the Cloud Management identity library the managed
// cloud auth provider loads to mint bearer tokens.
const cmidLibraryName = "cmidapi.dll"

// cmidNestedDirectory sits between the two version directories Secure
// Client nests the library under:
//
//	CM\<cm version>\CMID\<cmid version>\<arch>\cmidapi.dll
const cmidNestedDirectory = "CMID"

// This half of the search is plain path work, so it stays off the
// windows build tag and its tests run on every platform.

// discoverCMIDLibraryIn walks CM\<version>\CMID\<version>\<arch> newest
// first and returns the first library that exists, so a leftover older
// tree cannot pin the gateway to a stale library.
//
// Every discovered directory element is passed through
// rejectCMIDLibraryReparse before use so a malicious junction, symlink,
// or reparse point posing as a version directory (or the leaf library
// file itself) cannot redirect the walk off the Secure Client tree.
// On non-Windows platforms the reparse-point check is a no-op — this
// function is only reachable from Windows in practice (see
// DiscoverCMIDLibrary in cmid_library_windows.go).
func discoverCMIDLibraryIn(cmRoot, arch string) string {
	for _, cmVersion := range versionDirectoriesNewestFirst(cmRoot) {
		cmidRoot := filepath.Join(cmRoot, cmVersion, cmidNestedDirectory)
		if err := rejectCMIDLibraryReparse(cmidRoot); err != nil {
			continue
		}
		for _, cmidVersion := range versionDirectoriesNewestFirst(cmidRoot) {
			archDir := filepath.Join(cmidRoot, cmidVersion, arch)
			if err := rejectCMIDLibraryReparse(archDir); err != nil {
				continue
			}
			candidate := filepath.Join(archDir, cmidLibraryName)
			info, err := os.Lstat(candidate)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if err := rejectCMIDLibraryReparse(candidate); err != nil {
				continue
			}
			return candidate
		}
	}
	return ""
}

// versionDirectoriesNewestFirst lists the immediate subdirectories of
// root ordered by descending version. Names that do not parse as dotted
// numbers sort last so a stray directory cannot outrank a real version.
func versionDirectoriesNewestFirst(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		// Lstat rather than the DirEntry type so a reparse point posing
		// as a version directory cannot redirect the search off the
		// Secure Client tree. The Lstat-based `!IsDir()` check already
		// rejects unix symlinks (their mode bit is distinct from a
		// directory), but on Windows a junction posing as a directory
		// still reports Lstat.Mode().IsDir() == true — the reparse-point
		// filter below is the load-bearing rejection there.
		candidate := filepath.Join(root, entry.Name())
		info, err := os.Lstat(candidate)
		if err != nil || !info.IsDir() {
			continue
		}
		if err := rejectCMIDLibraryReparse(candidate); err != nil {
			continue
		}
		names = append(names, entry.Name())
	}
	sortVersionsDescending(names)
	return names
}

// sortVersionsDescending orders names newest first. Names that compare
// equal keep the order ReadDir gave them, which is already sorted, so
// the walk stays deterministic without a name tiebreaker.
func sortVersionsDescending(names []string) {
	// Insertion sort: these directories number in the single digits.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && compareVersions(names[j-1], names[j]) < 0; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
}

// compareVersions orders two dotted version strings, returning a
// positive number when a is newer and zero when every component
// matches. Unparsable components compare as older than any number.
func compareVersions(a, b string) int {
	left := strings.Split(a, ".")
	right := strings.Split(b, ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		if diff := versionComponent(left, i) - versionComponent(right, i); diff != 0 {
			return diff
		}
	}
	return 0
}

// versionComponent reads one dotted component. A component past the end
// is zero, so 1.2 and 1.2.0 are the same version.
func versionComponent(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	value, err := strconv.Atoi(parts[index])
	if err != nil {
		return -1
	}
	return value
}
