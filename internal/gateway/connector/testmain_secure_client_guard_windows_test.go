// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// secureClientTrees are the shared Cisco Secure Client folders of the real
// machine (ProgramData and Program Files). The Secure Client installer
// re-ACLs and rewrites that tree on its own schedule, but a test never has
// a reason to add to it. The connector tests run against temp layouts
// (t.TempDir) and the package's layout seams; a run that leaves a new entry
// here (GAP-0780, the DefenseClaw-Cert folder) wrote to the real machine.
// A root that cannot be resolved is left out: nothing there can be judged.
func secureClientTrees() []string {
	var trees []string
	for _, resolve := range []func() (string, error){winpath.TrustedProgramData, winpath.TrustedProgramFiles} {
		if base, err := resolve(); err == nil && base != "" {
			trees = append(trees, filepath.Join(base, "Cisco", "Cisco Secure Client"))
		}
	}
	return trees
}

// guardSecureClientTree records the real Secure Client folders now and
// returns the check that names every entry the run added, by name only.
func guardSecureClientTree() func() []string {
	return guardTreesAdditions(secureClientTrees())
}

func guardTreesAdditions(trees []string) func() []string {
	before := treeEntries(trees)
	return func() []string {
		var added []string
		for path := range treeEntries(trees) {
			if !before[path] {
				added = append(added, path)
			}
		}
		sort.Strings(added)
		return added
	}
}

func treeEntries(trees []string) map[string]bool {
	entries := map[string]bool{}
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				// An absent or unreadable folder has no entries to compare.
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			entries[path] = true
			return nil
		})
	}
	return entries
}
