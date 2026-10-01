// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
)

// Quarantined repositories. The nested-repository guard renames a .git the
// session creates in a mounted project to .git.defenseclaw-quarantine-<time>
// (nestguard), so no git on this machine reads it. What git init wrote
// there is the repository's, not the project's: the review shows each
// quarantined repository once, as a critical entry, and leaves its files
// out of the counts, the diff and the scanners (git's stock sample hooks
// buried the real risks). Undo removes the empty directory tree the
// quarantine leaves once the restore took its files.

// quarantineRoot returns the quarantined .git a project-relative path lies
// in (the path up to and including its quarantine component), or "".
func quarantineRoot(rel string) string {
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, nestguard.QuarantinePrefix) {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return ""
}

// splitQuarantined separates the changes inside quarantined repositories
// and returns the rest with one critical flag per folder whose .git was
// quarantined (a repository recreated under the guard's rename has more
// than one quarantined name).
func splitQuarantined(changes []TreeChange) ([]TreeChange, []Flag) {
	type repo struct {
		names []string
		files int
	}
	repos := map[string]*repo{}
	kept := changes[:0:0]
	for _, c := range changes {
		root := quarantineRoot(c.Path)
		if root == "" {
			kept = append(kept, c)
			continue
		}
		dir := path.Dir(root)
		r := repos[dir]
		if r == nil {
			r = &repo{}
			repos[dir] = r
		}
		if !containsStr(r.names, root) {
			r.names = append(r.names, root)
		}
		if c.NewMode != "040000" && !(c.OldMode == "040000" && c.NewMode == "") {
			r.files++
		}
	}
	dirs := make([]string, 0, len(repos))
	for dir := range repos {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	flags := make([]Flag, 0, len(dirs))
	for _, dir := range dirs {
		r := repos[dir]
		sort.Strings(r.names)
		label := path.Join(dir, ".git") + " (quarantined)"
		if dir == "." {
			label = ".git (quarantined)"
		}
		as := r.names[0]
		if len(r.names) > 1 {
			as += fmt.Sprintf(" and %d more", len(r.names)-1)
		}
		flags = append(flags, Flag{Path: r.names[0], Label: label, Kind: RiskNestedRepo, Severity: SeverityCritical,
			Detail: fmt.Sprintf("the session created a git repository here, which DefenseClaw renamed to %s so git on this machine never "+
				"reads it; its %d file(s) are left out of the file counts, the diff and the scans; undo removes it", as, r.files)})
	}
	return kept, flags
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// withoutQuarantinedDiffs drops the file sections of a unified diff that
// lie in quarantined repositories and ends it with a line naming what was
// left out.
func withoutQuarantinedDiffs(diff []byte) []byte {
	if !bytes.Contains(diff, []byte(nestguard.QuarantinePrefix)) {
		return diff
	}
	var out bytes.Buffer
	skipped := map[string]int{}
	skip := false
	for _, line := range bytes.SplitAfter(diff, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("diff --git ")) {
			root := quarantineRoot(diffPath(string(line)))
			skip = root != ""
			if skip {
				skipped[root]++
			}
		}
		if !skip {
			out.Write(line)
		}
	}
	if len(skipped) > 0 {
		roots := make([]string, 0, len(skipped))
		n := 0
		for root, files := range skipped {
			roots = append(roots, root)
			n += files
		}
		sort.Strings(roots)
		fmt.Fprintf(&out, "… %d file(s) of quarantined git repositories are left out: %s\n", n, strings.Join(firstN(roots, 3), ", "))
	}
	return out.Bytes()
}

// diffPath is the a/ path of a "diff --git a/<path> b/<path>" line.
func diffPath(line string) string {
	line = strings.TrimSuffix(strings.TrimPrefix(line, "diff --git "), "\n")
	line = strings.Trim(line, `"`)
	if rest, ok := strings.CutPrefix(line, "a/"); ok {
		if i := strings.Index(rest, " b/"); i >= 0 {
			return rest[:i]
		}
		return rest
	}
	return line
}

// removeQuarantined deletes the quarantined .git entries of the session
// (project-relative, as the guard recorded them) that the restore left as
// empty directory trees. One that still holds a file (the restore did not
// take it: git ignored it, say) is kept and named in a warning, and a path
// that is no quarantine is left alone. Removal goes through os.Root, so a
// symlink planted on the way cannot lead it out of the project.
func removeQuarantined(project string, quarantined []string) (removed, warnings []string) {
	if len(quarantined) == 0 {
		return nil, nil
	}
	r, err := openRootFS(project)
	if err != nil {
		return nil, []string{"the quarantined git repositories were not removed: " + err.Error()}
	}
	defer r.Close()
	seen := map[string]bool{}
	for _, raw := range quarantined {
		rel := path.Clean(filepath.ToSlash(strings.TrimSpace(raw)))
		if seen[rel] || rel == "." || path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") ||
			!strings.HasPrefix(path.Base(rel), nestguard.QuarantinePrefix) {
			continue
		}
		seen[rel] = true
		info, err := r.root.Lstat(rel)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			warnings = append(warnings, "the quarantined "+rel+" was not removed: "+err.Error())
			continue
		case !info.IsDir():
			// A quarantined .git file is a file of the session's; the
			// restore removed it unless it predates the snapshot.
			continue
		}
		if file, err := firstFile(r, rel); err != nil || file != "" {
			why := "it holds " + file
			if err != nil {
				why = err.Error()
			}
			warnings = append(warnings, "kept the quarantined "+rel+": "+why)
			continue
		}
		if err := r.root.RemoveAll(rel); err != nil {
			warnings = append(warnings, "the quarantined "+rel+" was not removed: "+err.Error())
			continue
		}
		removed = append(removed, rel)
	}
	sort.Strings(removed)
	return removed, warnings
}

// firstFile returns the first entry under rel that is not a directory
// (symlinks are not followed), or "".
func firstFile(r *rootFS, rel string) (string, error) {
	var found string
	err := fs.WalkDir(r.root.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	return found, err
}
