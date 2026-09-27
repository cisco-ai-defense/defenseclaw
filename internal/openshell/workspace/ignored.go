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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// A snapshot holds no copy of the files git ignores (build output, virtual
// environments, node_modules, Python bytecode caches) nor, in a folder that
// is not a git repository, of the dependency directories it skips. Many of
// them run on this machine: your shell sources .venv/bin/activate, npm runs
// node_modules/.bin, and Python loads __pycache__ bytecode in place of the
// source. The ignored manifest records each of those files by its metadata
// (type and mode, size, inode, modification and change time), so Review can
// say what a session changed there and Undo what it cannot put back. No
// unprivileged process can set a file's change time, so an edit whose
// modification time was put back still shows.

const ignoredManifestName = "ignored.json"

// maxIgnoredFiles caps the files a manifest records (a variable for tests).
// Past it, a file the manifest does not hold counts as added or changed when
// its change time is later than the snapshot.
var maxIgnoredFiles = 200_000

// ignoredClockSlack is taken off the snapshot time a file's change time is
// compared with, so a coarse filesystem clock (whole seconds on some
// filesystems, a scheduler tick on Linux) errs toward reporting. A variable
// for tests.
var ignoredClockSlack = 2 * time.Second

// maxIgnoredFlags caps the per-file review flags for executables outside
// the diff; the rest are counted in their directory's flag.
const maxIgnoredFlags = 20

// ignoredManifest is the metadata of every file below Roots when the
// snapshot was taken.
type ignoredManifest struct {
	Version int `json:"version"`
	// Since is when recording started, less ignoredClockSlack.
	Since time.Time              `json:"since"`
	Roots []ignoredRoot          `json:"roots"`
	Files map[string]ignoredFile `json:"files"`
	// Skip are the masked paths left out (the sandbox cannot change them).
	Skip []string `json:"skip,omitempty"`
	// Truncated reports that the file cap stopped the recording.
	Truncated bool `json:"truncated,omitempty"`

	complete map[string]bool // Complete roots, without the trailing "/"
}

// ignoredRoot is one ignored path (a directory ends in "/"). Complete
// means every file below it is in the manifest.
type ignoredRoot struct {
	Path     string `json:"path"`
	Complete bool   `json:"complete,omitempty"`
}

type ignoredFile struct {
	Mode  uint32 `json:"m"`
	Size  int64  `json:"s,omitempty"`
	Ino   uint64 `json:"i,omitempty"`
	MTime int64  `json:"t,omitempty"`
	CTime int64  `json:"c,omitempty"`
	Link  string `json:"l,omitempty"`
}

func (l layout) ignoredManifest(name string) string {
	return filepath.Join(l.snapshotDir(name), ignoredManifestName)
}

// IgnoredChange sums up what a session changed in one place a snapshot
// holds no copy of: a directory or file git ignores or, in a folder that is
// not a git repository, a dependency directory the snapshot skips.
type IgnoredChange struct {
	// Path is the directory ("node_modules/", "calc/__pycache__/") or file.
	Path     string `json:"path"`
	Added    int    `json:"added,omitempty"`
	Modified int    `json:"modified,omitempty"`
	Deleted  int    `json:"deleted,omitempty"`
	// Executables are added or changed files that run on this machine
	// (executable files, package bin entries, Python .pth files): the first
	// few of ExecutableCount.
	Executables     []string `json:"executables,omitempty"`
	ExecutableCount int      `json:"executable_count,omitempty"`
	// Dependencies marks an installed-package directory (node_modules,
	// .venv, ...), which can only be reinstalled.
	Dependencies bool `json:"dependencies,omitempty"`
	// Removed reports that undo deletes what the session added or changed
	// here: a Python bytecode cache, which Python rebuilds. Otherwise undo
	// leaves the path as the session left it and Remedy says what to do.
	Removed bool   `json:"removed,omitempty"`
	Remedy  string `json:"remedy,omitempty"`

	kind  ignoredKind
	files []string // added and changed paths
	execs []string
}

type ignoredKind int

const (
	ignoredOther ignoredKind = iota
	ignoredDependencies
	ignoredBytecode
)

// Summary is "3 files added or changed, 1 deleted".
func (c IgnoredChange) Summary() string {
	var parts []string
	if n := c.Added + c.Modified; n > 0 {
		parts = append(parts, fmt.Sprintf("%s added or changed", plural(n, "file", "files")))
	}
	if c.Deleted > 0 {
		parts = append(parts, fmt.Sprintf("%s deleted", plural(c.Deleted, "file", "files")))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Dependency directories: their packages can only be reinstalled. The
// remedy names the usual command when there is one.
var dependencyAreas = map[string]string{
	"node_modules":     "delete it and reinstall the packages (for example `npm ci`)",
	"bower_components": "delete it and reinstall the packages",
	".venv":            "delete it and create the virtual environment again",
	"venv":             "delete it and create the virtual environment again",
	".tox":             "delete it; tox creates it again",
	".nox":             "delete it; nox creates it again",
	".pnpm-store":      "delete it and reinstall the packages",
	".yarn":            "delete it and reinstall the packages",
	"vendor":           "delete it and reinstall the dependencies",
	".gradle":          "delete it; Gradle downloads it again",
	".terraform":       "delete it and run `terraform init` again",
}

// ignoredAreaOf names the area a changed path is reported under: the first
// dependency directory or bytecode cache on its path, else the ignored
// directory that holds it, else the file itself.
func ignoredAreaOf(rel string, roots map[string]bool) (string, ignoredKind) {
	segs := strings.Split(rel, "/")
	for i := 0; i < len(segs)-1; i++ {
		if _, ok := dependencyAreas[segs[i]]; ok {
			return strings.Join(segs[:i+1], "/") + "/", ignoredDependencies
		}
		if segs[i] == "__pycache__" {
			return strings.Join(segs[:i+1], "/") + "/", ignoredBytecode
		}
	}
	for p := path.Dir(rel); p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if roots[p+"/"] {
			return p + "/", ignoredOther
		}
	}
	return rel, ignoredOther
}

func ignoredRemedy(area string, kind ignoredKind) string {
	switch kind {
	case ignoredDependencies:
		return dependencyAreas[path.Base(strings.TrimSuffix(area, "/"))]
	case ignoredBytecode:
		return "delete it; Python rebuilds it"
	}
	if strings.HasSuffix(area, "/") {
		return "check these files and delete what you did not create"
	}
	return "check it, and delete it if you did not create it"
}

// runsOnHost reports whether an added or changed file runs on this machine
// without the operator reading it: an executable or symlinked command, an
// entry in a package bin directory, or a file Python runs at start-up.
func runsOnHost(rel string, mode uint32, area string) bool {
	m := fs.FileMode(mode)
	if m.IsRegular() && m.Perm()&0o111 != 0 {
		return true
	}
	switch strings.ToLower(path.Base(rel)) {
	case "sitecustomize.py", "usercustomize.py":
		return true
	}
	if strings.HasSuffix(strings.ToLower(rel), ".pth") {
		return true
	}
	inner := strings.TrimPrefix(rel, area)
	for _, seg := range strings.Split(path.Dir(inner), "/") {
		switch seg {
		case "bin", ".bin", "Scripts":
			return m.IsRegular() || m&fs.ModeSymlink != 0
		}
	}
	return false
}

// normalizeRoots cleans ignored paths ("dir/" for a directory), drops any
// that leave the folder, and drops those inside another directory root.
func normalizeRoots(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		dir := strings.HasSuffix(s, "/")
		p := path.Clean(strings.TrimSuffix(filepath.ToSlash(s), "/"))
		if p == "." || p == "" || p == ".." || strings.HasPrefix(p, "../") || path.IsAbs(p) {
			continue
		}
		if dir {
			p += "/"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	kept := out[:0]
	last := ""
	for _, p := range out {
		if last != "" && strings.HasPrefix(p, last) {
			continue
		}
		kept = append(kept, p)
		if strings.HasSuffix(p, "/") {
			last = p
		}
	}
	return kept
}

func ignoredFileOf(info fs.FileInfo) ignoredFile {
	f := ignoredFile{Mode: uint32(info.Mode()), MTime: info.ModTime().UnixNano(), CTime: changeTime(info)}
	if info.Mode().IsRegular() {
		f.Size = info.Size()
	}
	if id, ok := identityOf(info); ok {
		f.Ino = id.Ino
	}
	return f
}

// walkIgnored visits every entry but directories below roots, through
// os.Root on the project: no symlink is followed out of it, a root whose
// parent is a symlink is skipped, .git directories are not entered, and
// skip is left out. It stops after limit files; complete names the roots
// it visited in full.
func walkIgnored(project string, roots []string, skip map[string]struct{}, limit int, fn func(rel string, f ignoredFile)) (map[string]bool, bool, error) {
	r, err := openRootFS(project)
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	complete := map[string]bool{}
	count := 0
	visit := func(rel string, info fs.FileInfo) bool {
		if count++; count > limit {
			return false
		}
		f := ignoredFileOf(info)
		if info.Mode()&fs.ModeSymlink != 0 {
			f.Link, _ = r.root.Readlink(rel)
		}
		fn(rel, f)
		return true
	}
	for _, root := range roots {
		rel := strings.TrimSuffix(root, "/")
		if skipped(skip, rel) {
			complete[root] = true
			continue
		}
		if err := r.realParents(rel); err != nil {
			complete[root] = errors.Is(err, fs.ErrNotExist)
			continue
		}
		info, err := r.root.Lstat(rel)
		if errors.Is(err, fs.ErrNotExist) {
			complete[root] = true
			continue
		}
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !visit(rel, info) {
				return complete, true, nil
			}
			complete[root] = true
			continue
		}
		whole, stopped := true, false
		err = fs.WalkDir(r.root.FS(), rel, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				whole = false
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != rel && (d.Name() == ".git" || skipped(skip, p)) {
					return fs.SkipDir
				}
				return nil
			}
			if skipped(skip, p) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if !visit(p, info) {
				stopped = true
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			return nil, false, fmt.Errorf("workspace: read %s: %w", rel, err)
		}
		if stopped {
			return complete, true, nil
		}
		complete[root] = whole
	}
	return complete, false, nil
}

// recordIgnored takes the manifest of the files below roots.
func recordIgnored(project string, roots []string, skip map[string]struct{}) (*ignoredManifest, error) {
	m := &ignoredManifest{Version: 1, Since: time.Now().Add(-ignoredClockSlack).UTC(), Files: map[string]ignoredFile{}}
	roots = normalizeRoots(roots)
	complete, truncated, err := walkIgnored(project, roots, skip, maxIgnoredFiles, func(rel string, f ignoredFile) { m.Files[rel] = f })
	if err != nil {
		return nil, err
	}
	m.Truncated = truncated
	for _, root := range roots {
		m.Roots = append(m.Roots, ignoredRoot{Path: root, Complete: complete[root]})
	}
	for s := range skip {
		m.Skip = append(m.Skip, s)
	}
	sort.Strings(m.Skip)
	return m, nil
}

func writeIgnored(lay layout, name string, m *ignoredManifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("workspace: encode %s: %w", ignoredManifestName, err)
	}
	if err := safefile.Write(lay.ignoredManifest(name), data); err != nil {
		return fmt.Errorf("workspace: write %s: %w", lay.ignoredManifest(name), err)
	}
	return nil
}

// loadIgnored reads a snapshot's manifest; nil when the snapshot has none
// (taken by an older build).
func loadIgnored(dataDir, name string) (*ignoredManifest, error) {
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	var m ignoredManifest
	if err := readJSON(lay.ignoredManifest(name), &m); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if m.Files == nil {
		m.Files = map[string]ignoredFile{}
	}
	return &m, nil
}

func (m *ignoredManifest) rootPaths() []string {
	out := make([]string, 0, len(m.Roots))
	for _, r := range m.Roots {
		out = append(out, r.Path)
	}
	return out
}

// covers reports whether rel is, or is inside, a root recorded in full. It
// looks rel and its parents up, so a comparison stays linear in the files.
func (m *ignoredManifest) covers(rel string) bool {
	if m == nil {
		return false
	}
	if m.complete == nil {
		m.complete = map[string]bool{}
		for _, r := range m.Roots {
			if r.Complete {
				m.complete[strings.TrimSuffix(r.Path, "/")] = true
			}
		}
	}
	for p := strings.TrimSuffix(rel, "/"); p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if m.complete[p] {
			return true
		}
	}
	return false
}

type ignoredDelta struct {
	Path   string
	Status string // A, M or D
	Mode   uint32 // after (A, M) or before (D)
}

// ignoredReport is what changed below the ignored roots of a snapshot and
// of the folder now.
type ignoredReport struct {
	Changes []IgnoredChange
	// Truncated reports that the manifest or the walk now hit the cap.
	Truncated bool
}

// diffIgnored compares the folder with the manifest below the manifest's
// roots and nowRoots (what is ignored now). Paths in inDiff are part of the
// snapshot's own comparison and left out.
func diffIgnored(project string, m *ignoredManifest, nowRoots []string, skip, inDiff map[string]struct{}) (*ignoredReport, error) {
	roots := normalizeRoots(append(m.rootPaths(), nowRoots...))
	allSkip := toSet(m.Skip)
	for s := range skip {
		allSkip[s] = struct{}{}
	}
	now := map[string]ignoredFile{}
	_, truncated, err := walkIgnored(project, roots, allSkip, 2*maxIgnoredFiles, func(rel string, f ignoredFile) { now[rel] = f })
	if err != nil {
		return nil, err
	}
	since := m.Since.UnixNano()
	var deltas []ignoredDelta
	for rel, f := range now {
		if _, ok := inDiff[rel]; ok {
			continue
		}
		if before, ok := m.Files[rel]; ok {
			if before != f {
				deltas = append(deltas, ignoredDelta{Path: rel, Status: "M", Mode: f.Mode})
			}
			continue
		}
		if m.covers(rel) || f.CTime == 0 || f.CTime >= since {
			deltas = append(deltas, ignoredDelta{Path: rel, Status: "A", Mode: f.Mode})
		}
	}
	if !truncated {
		for rel, before := range m.Files {
			if _, ok := now[rel]; ok {
				continue
			}
			if _, ok := inDiff[rel]; ok {
				continue
			}
			deltas = append(deltas, ignoredDelta{Path: rel, Status: "D", Mode: before.Mode})
		}
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Path < deltas[j].Path })
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[r] = true
	}
	return &ignoredReport{Changes: groupIgnored(deltas, rootSet), Truncated: truncated || m.Truncated}, nil
}

// groupIgnored sums deltas up per area. A bytecode cache the session only
// deleted from is left out: Python rebuilds it.
func groupIgnored(deltas []ignoredDelta, roots map[string]bool) []IgnoredChange {
	byArea := map[string]*IgnoredChange{}
	var order []string
	for _, d := range deltas {
		area, kind := ignoredAreaOf(d.Path, roots)
		c := byArea[area]
		if c == nil {
			c = &IgnoredChange{Path: area, kind: kind, Dependencies: kind == ignoredDependencies, Remedy: ignoredRemedy(area, kind)}
			byArea[area] = c
			order = append(order, area)
		}
		switch d.Status {
		case "A":
			c.Added++
		case "M":
			c.Modified++
		case "D":
			c.Deleted++
			continue
		}
		c.files = append(c.files, d.Path)
		if runsOnHost(d.Path, d.Mode, area) {
			c.execs = append(c.execs, d.Path)
		}
	}
	sort.Strings(order)
	var out []IgnoredChange
	for _, area := range order {
		c := byArea[area]
		if c.kind == ignoredBytecode {
			if len(c.files) == 0 {
				continue
			}
			c.Removed = true
		}
		c.ExecutableCount = len(c.execs)
		c.Executables = append([]string(nil), c.execs[:min(len(c.execs), 5)]...)
		out = append(out, *c)
	}
	return out
}

// ignoredFlags turns the changes into review flags: one per dependency
// directory and bytecode cache, and one per executable elsewhere (up to
// maxIgnoredFlags). It also returns the areas whose other changes no flag
// names. gitProject picks the wording for why the diff misses them.
func ignoredFlags(changes []IgnoredChange, gitProject bool) ([]Flag, []string) {
	dirWhy, fileWhy := "git ignores these files, so they are not in the diff", "git ignores it, so it is not in the diff"
	if !gitProject {
		dirWhy = "the undo snapshot does not copy this directory, so they are not in the diff"
		fileWhy = "the undo snapshot does not copy its directory, so it is not in the diff"
	}
	var flags []Flag
	var quiet []string
	perFile := 0
	for _, c := range changes {
		switch c.kind {
		case ignoredDependencies:
			sev := SeverityMedium
			detail := c.Summary() + " during the session; " + dirWhy + ". Packages run on this machine when you use them"
			if c.ExecutableCount > 0 {
				sev = SeverityHigh
				detail += ", and " + plural(c.ExecutableCount, "command or start-up file", "commands or start-up files") +
					" changed (" + strings.Join(trimArea(c.Executables, c.Path), ", ") + moreSuffix(c.ExecutableCount, len(c.Executables)) + ")"
			}
			detail += ". Undo cannot restore " + c.Path + ": " + c.Remedy
			flags = append(flags, Flag{Path: strings.TrimSuffix(c.Path, "/"), Label: c.Path, Kind: RiskDependencies, Severity: sev, Detail: detail})
			continue
		case ignoredBytecode:
			flags = append(flags, Flag{Path: strings.TrimSuffix(c.Path, "/"), Label: c.Path, Kind: RiskAutoExec, Severity: SeverityMedium,
				Detail: plural(len(c.files), "file was", "files were") + " written to this Python bytecode cache during the session; " +
					"Python runs cached bytecode in place of the source, and " + dirWhy + " (undo deletes them; Python rebuilds the cache)"})
		}
		undo := "undo cannot restore it"
		if c.Removed {
			undo = "undo deletes it"
		}
		folded := 0
		for _, p := range c.execs {
			if perFile >= maxIgnoredFlags {
				folded++
				continue
			}
			perFile++
			flags = append(flags, Flag{Path: p, Label: p, Kind: RiskExecutable, Severity: SeverityHigh,
				Detail: "new or changed executable file; " + fileWhy + ", and " + undo})
		}
		if c.kind == ignoredOther && (folded > 0 || len(c.execs) < len(c.files) || c.Deleted > 0) {
			quiet = append(quiet, c.Path)
		}
	}
	return flags, quiet
}

func trimArea(paths []string, area string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = strings.TrimPrefix(p, area)
	}
	return out
}

func moreSuffix(total, shown int) string {
	if total > shown {
		return fmt.Sprintf(", +%d more", total-shown)
	}
	return ""
}

// removeIgnored deletes what the session added or changed in the areas
// undo removes, through os.Root on the project, and then each area's
// directory when that left it empty. It returns what it could not delete.
func removeIgnored(project string, changes []IgnoredChange) []string {
	var warnings []string
	r, err := openRootFS(project)
	if err != nil {
		return []string{err.Error()}
	}
	defer r.Close()
	for _, c := range changes {
		if !c.Removed {
			continue
		}
		for _, p := range c.files {
			if err := r.realParents(p); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					warnings = append(warnings, fmt.Sprintf("could not delete %s: %v", p, err))
				}
				continue
			}
			if info, err := r.root.Lstat(p); err != nil || info.IsDir() {
				continue
			}
			if err := r.root.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				warnings = append(warnings, fmt.Sprintf("could not delete %s: %v", p, err))
			}
		}
		dir := strings.TrimSuffix(c.Path, "/")
		if r.realParents(dir) == nil {
			if info, err := r.root.Lstat(dir); err == nil && info.IsDir() {
				_ = r.root.Remove(dir) // only while empty
			}
		}
	}
	return warnings
}

// ignoredWarning is the warning for a comparison the file cap cut short.
func ignoredWarning(rep *ignoredReport, gitProject bool) string {
	if !rep.Truncated {
		return ""
	}
	what := "files git ignores"
	if !gitProject {
		what = "files in dependency directories"
	}
	return fmt.Sprintf("the folder holds more %s than DefenseClaw checks (%d); some changes there may not be reported", what, maxIgnoredFiles)
}
