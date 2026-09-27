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
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// treeEntry is one path in a non-git snapshot comparison.
type treeEntry struct {
	abs  string
	info fs.FileInfo
}

func gitMode(info fs.FileInfo) string {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return modeSymlink
	case info.IsDir():
		return "040000"
	case info.Mode().Perm()&0o111 != 0:
		return modeExec
	default:
		return "100644"
	}
}

// listTree collects every entry under root. When project is set it skips
// what the snapshot skipped (.git, heavy caches, the skip set) and refuses
// a folder with more than maxEntries entries (walkLimit): a partial listing
// would report the rest as deleted and miss what was created there.
func listTree(root string, project bool, skip map[string]struct{}, maxEntries int) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	visit := func(rel string, d fs.DirEntry) error {
		if skipped(skip, rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if project && (isOpaqueDir(d) || d.Name() == ".git") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		out[rel] = treeEntry{abs: filepath.Join(root, filepath.FromSlash(rel)), info: info}
		return nil
	}
	if project {
		truncated, err := walkProject(root, maxEntries, visit)
		if err != nil {
			return nil, err
		}
		if truncated {
			return nil, tooManyEntries("the folder (compared with its undo snapshot)", maxEntries)
		}
		return out, nil
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		return visit(filepath.ToSlash(rel), d)
	})
	return out, err
}

// compareTrees reports the changes that turn the snapshot at snap into the
// folder at project (A: created during the session, D: deleted, M: content
// or mode changed, T: type changed). Every file and symlink is listed;
// directories appear only where a whole directory was created or deleted
// (mode 040000). Line counts for text files are a multiset estimate; exact
// diffs come from git for repositories. The folder is read under the walk
// limit the snapshot was taken with.
func compareTrees(snap *CopyTree, project string) ([]TreeChange, map[string]treeEntry, map[string]treeEntry, error) {
	skipSet := toSet(snap.Skipped)
	before, err := listTree(snap.Dir, false, skipSet, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("workspace: read snapshot: %w", err)
	}
	after, err := listTree(project, true, skipSet, snap.MaxEntries)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, nil, nil, err
		}
		return nil, nil, nil, fmt.Errorf("workspace: read %s: %w", project, err)
	}
	var changes []TreeChange
	for rel, b := range before {
		a, ok := after[rel]
		if !ok {
			if !b.info.IsDir() {
				changes = append(changes, TreeChange{Path: rel, Status: "D", OldMode: gitMode(b.info)})
			} else if !parentMissing(rel, after) {
				changes = append(changes, TreeChange{Path: rel, Status: "D", OldMode: "040000"})
			}
			continue
		}
		bm, am := gitMode(b.info), gitMode(a.info)
		if (bm == "040000") != (am == "040000") || (bm == modeSymlink) != (am == modeSymlink) {
			changes = append(changes, TreeChange{Path: rel, Status: "T", OldMode: bm, NewMode: am})
			continue
		}
		switch bm {
		case "040000":
			continue
		case modeSymlink:
			bt, _ := os.Readlink(b.abs)
			at, _ := os.Readlink(a.abs)
			if bt != at {
				changes = append(changes, TreeChange{Path: rel, Status: "M", OldMode: bm, NewMode: am})
			}
			continue
		}
		same, err := sameContent(b, a)
		if err != nil {
			return nil, nil, nil, err
		}
		if same && bm == am {
			continue
		}
		c := TreeChange{Path: rel, Status: "M", OldMode: bm, NewMode: am}
		if !same {
			c.Added, c.Deleted, c.Binary = lineDelta(b.abs, a.abs)
		}
		changes = append(changes, c)
	}
	for rel, a := range after {
		if _, ok := before[rel]; ok {
			continue
		}
		if a.info.IsDir() {
			if !parentMissing(rel, before) {
				changes = append(changes, TreeChange{Path: rel, Status: "A", NewMode: "040000"})
			}
			continue
		}
		c := TreeChange{Path: rel, Status: "A", NewMode: gitMode(a.info)}
		if a.info.Mode().IsRegular() {
			c.Added, _, c.Binary = lineDelta("", a.abs)
		}
		changes = append(changes, c)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, before, after, nil
}

// parentMissing reports whether a parent directory of rel is absent from
// set, meaning the change is already covered by the parent's A/D entry.
func parentMissing(rel string, set map[string]treeEntry) bool {
	for p := path.Dir(rel); p != "." && p != ""; p = path.Dir(p) {
		if _, ok := set[p]; !ok {
			return true
		}
	}
	return false
}

func sameContent(a, b treeEntry) (bool, error) {
	if a.info.Size() != b.info.Size() {
		return false, nil
	}
	fa, err := os.Open(a.abs)
	if err != nil {
		return false, err
	}
	defer fa.Close()
	fb, err := os.Open(b.abs)
	if err != nil {
		return false, err
	}
	defer fb.Close()
	bufA, bufB := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		na, errA := io.ReadFull(fa, bufA)
		nb, errB := io.ReadFull(fb, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false, nil
		}
		if errA == io.EOF || errA == io.ErrUnexpectedEOF {
			return errB == io.EOF || errB == io.ErrUnexpectedEOF, nil
		}
		if errA != nil {
			return false, errA
		}
		if errB != nil {
			return false, errB
		}
	}
}

const maxLineDeltaBytes = 1 << 20

// lineDelta estimates added/deleted lines between two text files by line
// multiset difference. before "" means an empty file.
func lineDelta(before, after string) (added, deleted int, binary bool) {
	read := func(p string) ([]byte, bool) {
		if p == "" {
			return nil, true
		}
		b, err := readSmallRegular(p, maxLineDeltaBytes+1)
		if err != nil || len(b) > maxLineDeltaBytes || looksBinary(b) {
			return nil, false
		}
		return b, true
	}
	a, okA := read(before)
	b, okB := read(after)
	if !okA || !okB {
		return 0, 0, true
	}
	counts := map[string]int{}
	for _, l := range splitLines(a) {
		counts[l]++
	}
	for _, l := range splitLines(b) {
		if counts[l] > 0 {
			counts[l]--
		} else {
			added++
		}
	}
	for _, n := range counts {
		deleted += n
	}
	return added, deleted, false
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(s, "\n")
}

// restoreTree applies the reverse of changes: created entries are removed
// and deleted or modified ones are copied back from the snapshot. Every
// write goes through os.Root on the project.
func restoreTree(project string, changes []TreeChange, before map[string]treeEntry) error {
	r, err := openRootFS(project)
	if err != nil {
		return err
	}
	defer r.Close()
	// Remove what the session created, deepest first.
	var created []string
	for _, c := range changes {
		if c.Status == "A" {
			created = append(created, c.Path)
		}
	}
	sort.Slice(created, func(i, j int) bool { return strings.Count(created[i], "/") > strings.Count(created[j], "/") })
	for _, rel := range created {
		if err := r.clear(rel); err != nil {
			return fmt.Errorf("workspace: remove %s: %w", rel, err)
		}
	}
	// Recreate, parents first. A deleted directory brings back its whole
	// snapshot subtree.
	var restore []string
	for _, c := range changes {
		if c.Status == "A" {
			continue
		}
		restore = append(restore, c.Path)
		if b, ok := before[c.Path]; ok && b.info.IsDir() {
			prefix := c.Path + "/"
			for rel := range before {
				if strings.HasPrefix(rel, prefix) {
					restore = append(restore, rel)
				}
			}
		}
	}
	restore = dedupe(restore)
	sort.Slice(restore, func(i, j int) bool {
		di, dj := strings.Count(restore[i], "/"), strings.Count(restore[j], "/")
		if di != dj {
			return di < dj
		}
		return restore[i] < restore[j]
	})
	for _, rel := range restore {
		b, ok := before[rel]
		if !ok {
			continue
		}
		switch {
		case b.info.IsDir():
			if info, err := r.root.Lstat(rel); err == nil && !info.IsDir() {
				if err := r.clear(rel); err != nil {
					return err
				}
			}
			if err := r.ensureDir(rel); err != nil {
				return fmt.Errorf("workspace: restore %s: %w", rel, err)
			}
			_ = r.root.Chmod(rel, b.info.Mode().Perm())
		case b.info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(b.abs)
			if err != nil {
				return err
			}
			if err := r.symlink(rel, target); err != nil {
				return fmt.Errorf("workspace: restore %s: %w", rel, err)
			}
		default:
			f, err := os.Open(b.abs)
			if err != nil {
				return err
			}
			err = r.writeFile(rel, f, b.info.Mode(), b.info.ModTime())
			_ = f.Close()
			if err != nil {
				return fmt.Errorf("workspace: restore %s: %w", rel, err)
			}
		}
	}
	return nil
}
