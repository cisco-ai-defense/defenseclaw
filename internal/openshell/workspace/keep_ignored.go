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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A snapshot can keep a copy of some of the directories it otherwise only
// records by their metadata (ignored.go): the dependency directories git
// ignores, or a folder without git skips, whose files run on this machine
// (node_modules/.bin, .venv/bin/activate). SnapshotOptions.KeepIgnored names
// them; the copies go below the snapshot, as file clones where the
// filesystem supports them and byte copies otherwise, up to
// SnapshotOptions.KeepIgnoredBytes of file content. A directory whose copy
// would pass that cap keeps none (the manifest's OverCap), so Review and Undo
// report it as before. Undo puts a kept directory back as the snapshot found
// it; what the session left there is not kept.

// keptIgnoredDirName is the snapshot directory entry that holds the copies.
const keptIgnoredDirName = "ignored-copy"

func (l layout) keptIgnored(name string) string {
	return filepath.Join(l.snapshotDir(name), keptIgnoredDirName)
}

// keepIgnored copies, below the snapshot, each directory among the
// manifest's roots recorded in full whose name is in names, in path order,
// while the copies stay within limit bytes; a directory that would pass it
// is recorded in m.OverCap and the next ones are still tried. It records the
// copied directories in m.Kept and returns what it could not copy.
func keepIgnored(lay layout, name, project string, m *ignoredManifest, names []string, limit int64) []string {
	if len(names) == 0 || limit <= 0 {
		return nil
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.TrimSpace(n)] = true
	}
	var cands []string
	candSet := map[string]bool{}
	for _, r := range m.Roots {
		if !r.Complete || !strings.HasSuffix(r.Path, "/") {
			continue
		}
		if want[path.Base(strings.TrimSuffix(r.Path, "/"))] {
			cands = append(cands, r.Path)
			candSet[strings.TrimSuffix(r.Path, "/")] = true
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Strings(cands)
	// What each copy holds, from the manifest the snapshot just took.
	size := map[string]int64{}
	for rel, f := range m.Files {
		for p := path.Dir(rel); p != "." && p != "/" && p != ""; p = path.Dir(p) {
			if candSet[p] {
				size[p+"/"] += f.Size
				break
			}
		}
	}
	dst := lay.keptIgnored(name)
	skip := toSet(m.Skip)
	var warnings []string
	budget := limit
	for _, root := range cands {
		if size[root] > budget {
			m.OverCap = append(m.OverCap, root)
			continue
		}
		if err := copyIgnoredDir(project, dst, strings.TrimSuffix(root, "/"), skip); err != nil {
			_ = removeTree(filepath.Join(dst, filepath.FromSlash(strings.TrimSuffix(root, "/"))))
			warnings = append(warnings, "undo keeps no copy of "+root+" ("+err.Error()+"); undo reports what the session changes there")
			continue
		}
		budget -= size[root]
		m.Kept = append(m.Kept, root)
	}
	if len(m.Kept) == 0 {
		_ = removeTree(dst)
	}
	return warnings
}

// copyIgnoredDir copies the project directory rel, through os.Root on the
// project (no symlink is followed out of it), to the same path below dst:
// directories, symbolic links and regular files, without .git directories
// and the skip set (masked paths, which the sandbox cannot change). Other
// file types are left out, as the restore leaves them alone. Any entry it
// cannot read fails the copy: a partial copy would make undo delete what it
// left out.
func copyIgnoredDir(project, dst, rel string, skip map[string]struct{}) error {
	r, err := openRootFS(project)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.realParents(rel); err != nil {
		return err
	}
	info, err := r.root.Lstat(rel)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", rel)
	}
	type dirMode struct {
		path  string
		mode  fs.FileMode
		mtime time.Time
	}
	var dirs []dirMode
	err = fs.WalkDir(r.root.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipped(skip, p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() && p != rel && d.Name() == ".git" {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, filepath.FromSlash(p))
		switch {
		case info.IsDir():
			if err := os.MkdirAll(to, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirMode{to, info.Mode().Perm(), info.ModTime()})
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := r.root.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, to)
		case info.Mode().IsRegular():
			return copyRegular(filepath.Join(project, filepath.FromSlash(p)), to, info.Mode(), info.ModTime())
		}
		return nil
	})
	// Directory modes last, so a read-only directory does not block the
	// copy below it (and stays removable with the snapshot).
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Chmod(dirs[i].path, dirs[i].mode|0o700)
		_ = os.Chtimes(dirs[i].path, dirs[i].mtime, dirs[i].mtime)
	}
	return err
}

// keptRootOf returns the kept directory ("node_modules/") rel is in, or "".
func (m *ignoredManifest) keptRootOf(rel string) string {
	return rootOf(m.Kept, rel)
}

// overCapRootOf returns the directory left without a copy for the cap that
// rel is in, or "".
func (m *ignoredManifest) overCapRootOf(rel string) string {
	return rootOf(m.OverCap, rel)
}

func rootOf(roots []string, rel string) string {
	for _, root := range roots {
		if strings.HasPrefix(rel, root) || rel == strings.TrimSuffix(root, "/") {
			return root
		}
	}
	return ""
}

// markKept marks the changes undo restores from a kept copy (every path
// they name is inside one) and those a copy was left out of for the cap.
func (m *ignoredManifest) markKept(changes []IgnoredChange) {
	if m == nil || (len(m.Kept) == 0 && len(m.OverCap) == 0) {
		return
	}
	for i := range changes {
		c := &changes[i]
		paths := append(append([]string{c.Path}, c.files...), c.gone...)
		kept, over := true, false
		for _, p := range paths {
			if m.keptRootOf(p) == "" {
				kept = false
			}
			if m.overCapRootOf(p) != "" {
				over = true
			}
		}
		c.Restored = kept && len(m.Kept) > 0 && !c.Removed
		c.OverCap = over && !c.Restored
	}
}

// unmarkKept marks unrestored every change markKept marked restored that
// has a path in the kept directory root, which could not be restored: a
// grouped change's own path may lie outside root while its files do not.
func (m *ignoredManifest) unmarkKept(changes []IgnoredChange, root string) {
	for i := range changes {
		c := &changes[i]
		if !c.Restored {
			continue
		}
		for _, p := range append(append([]string{c.Path}, c.files...), c.gone...) {
			if m.keptRootOf(p) == root {
				c.Restored = false
				break
			}
		}
	}
}

// restoreKept puts back, from the snapshot's copies, each kept directory a
// change undo restores (Restored) is in: what the session added there is
// removed, and what it changed or deleted is copied back. A directory it
// cannot restore is warned about, and its changes are marked unrestored.
// The manifest then records the restored directories as they are now, so a
// review after the undo does not report them again.
func restoreKept(lay layout, name, project string, m *ignoredManifest, changes []IgnoredChange) []string {
	if m == nil || len(m.Kept) == 0 {
		return nil
	}
	var roots []string
	seen := map[string]bool{}
	for _, c := range changes {
		if !c.Restored {
			continue
		}
		for _, p := range append(append([]string{c.Path}, c.files...), c.gone...) {
			if root := m.keptRootOf(p); root != "" && !seen[root] {
				seen[root] = true
				roots = append(roots, root)
			}
		}
	}
	if len(roots) == 0 {
		return nil
	}
	sort.Strings(roots)
	skip := toSet(m.Skip)
	var warnings, restored []string
	for _, root := range roots {
		if err := restoreKeptDir(project, lay.keptIgnored(name), strings.TrimSuffix(root, "/"), skip, m); err != nil {
			warnings = append(warnings, "could not restore "+root+" from the copy the undo point keeps: "+err.Error())
			m.unmarkKept(changes, root)
			continue
		}
		restored = append(restored, root)
	}
	if len(restored) > 0 {
		for rel := range m.Files {
			if rootOf(restored, rel) != "" {
				delete(m.Files, rel)
			}
		}
		if _, _, err := walkIgnored(project, restored, skip, maxIgnoredFiles, func(rel string, f ignoredFile) { m.Files[rel] = f }); err == nil {
			if err := writeIgnored(lay, name, m); err != nil {
				warnings = append(warnings, err.Error())
			}
		}
	}
	return warnings
}

// restoreKeptDir makes the project directory rel what its copy below
// keptDir holds (restoreTree), comparing the two: a regular file whose
// metadata still matches the manifest is unchanged, any other is compared
// byte for byte.
func restoreKeptDir(project, keptDir, rel string, skip map[string]struct{}, m *ignoredManifest) error {
	before, err := listKeptCopy(keptDir, rel)
	if err != nil {
		return err
	}
	r, err := openRootFS(project)
	if err != nil {
		return err
	}
	defer r.Close()
	after, err := listProjectDir(r, project, rel, skip)
	if err != nil {
		return err
	}
	var changes []TreeChange
	for p, b := range before {
		a, ok := after[p]
		if !ok {
			changes = append(changes, TreeChange{Path: p, Status: "D", OldMode: gitMode(b.info)})
			continue
		}
		bm, am := gitMode(b.info), gitMode(a.info)
		if (bm == "040000") != (am == "040000") || (bm == modeSymlink) != (am == modeSymlink) {
			changes = append(changes, TreeChange{Path: p, Status: "T", OldMode: bm, NewMode: am})
			continue
		}
		switch {
		case bm == "040000":
			continue
		case bm == modeSymlink:
			bt, _ := os.Readlink(b.abs)
			at, _ := r.root.Readlink(p)
			if bt != at {
				changes = append(changes, TreeChange{Path: p, Status: "M", OldMode: bm, NewMode: am})
			}
			continue
		}
		if f, ok := m.Files[p]; ok && f == ignoredFileOf(a.info) {
			continue
		}
		if b.info.Mode().Perm() == a.info.Mode().Perm() && r.sameFile(p, b.abs) {
			continue
		}
		changes = append(changes, TreeChange{Path: p, Status: "M", OldMode: bm, NewMode: am})
	}
	for p, a := range after {
		if _, ok := before[p]; !ok {
			changes = append(changes, TreeChange{Path: p, Status: "A", NewMode: gitMode(a.info)})
		}
	}
	if len(changes) == 0 {
		return nil
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return restoreTree(project, changes, before)
}

// listKeptCopy lists the copy of rel below keptDir, keyed by project path.
func listKeptCopy(keptDir, rel string) (map[string]treeEntry, error) {
	root := filepath.Join(keptDir, filepath.FromSlash(rel))
	out := map[string]treeEntry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&fs.ModeSymlink == 0 {
			return nil
		}
		sub, err := filepath.Rel(keptDir, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(sub)] = treeEntry{abs: p, info: info}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the copy of %s: %w", rel, err)
	}
	return out, nil
}

// listProjectDir lists the project directory rel through os.Root: its
// directories, symbolic links and regular files, without .git directories
// and the skip set, as copyIgnoredDir copies them. A rel that is missing, or
// under a parent that is no longer a real directory, lists nothing: the
// restore then recreates it (restoreTree replaces such a parent).
func listProjectDir(r *rootFS, project, rel string, skip map[string]struct{}) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	if r.realParents(rel) != nil {
		return out, nil
	}
	info, err := r.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		out[rel] = treeEntry{abs: filepath.Join(project, filepath.FromSlash(rel)), info: info}
		return out, nil
	}
	err = fs.WalkDir(r.root.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipped(skip, p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() && p != rel && d.Name() == ".git" {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&fs.ModeSymlink == 0 {
			return nil
		}
		out[p] = treeEntry{abs: filepath.Join(project, filepath.FromSlash(p)), info: info}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	return out, nil
}
