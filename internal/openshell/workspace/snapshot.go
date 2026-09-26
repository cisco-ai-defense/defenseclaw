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
	"context"
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

// SnapshotKind says how a snapshot was taken.
type SnapshotKind string

const (
	// SnapshotGit is a commit of the whole working tree in the shadow git
	// directory, plus the project's HEAD, branch and refs.
	SnapshotGit SnapshotKind = "git"
	// SnapshotCopy is a reflink/byte copy of a non-git folder.
	SnapshotCopy SnapshotKind = "copy"
)

// DefaultMaxCopySnapshotBytes caps non-git snapshots.
const DefaultMaxCopySnapshotBytes int64 = 1 << 30

// SnapshotOptions configures Snapshot.
type SnapshotOptions struct {
	Project   string
	Name      string
	DataDir   string
	Home      string
	Protected []string
	// Replace overwrites an existing snapshot of the same name (a kept
	// sandbox being started again).
	Replace bool
	// MaxCopyBytes caps non-git snapshots (DefaultMaxCopySnapshotBytes).
	MaxCopyBytes int64
	// Skip lists project-relative paths a non-git snapshot neither copies
	// nor restores (masked secrets: the sandbox cannot change them).
	Skip []string
	// NoProjectRef skips writing refs/defenseclaw/pre/<name> into the
	// project repository (the shadow copy is always written).
	NoProjectRef bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// SnapshotRecord is the persisted pre-session state.
type SnapshotRecord struct {
	Version   int          `json:"version"`
	Name      string       `json:"name"`
	Project   string       `json:"project"`
	Kind      SnapshotKind `json:"kind"`
	CreatedAt time.Time    `json:"created_at"`
	Git       *GitSnapshot `json:"git,omitempty"`
	Copy      *CopyTree    `json:"copy,omitempty"`
	// Sentinels are files that can run code on the host, recorded by a
	// filesystem walk so Review sees changes git ignores (.envrc in
	// .gitignore, IDE folders) and nested repositories.
	Sentinels       map[string]FileState      `json:"sentinels,omitempty"`
	NestedRepos     []string                  `json:"nested_repos,omitempty"`
	DependencyDirs  map[string]DirFingerprint `json:"dependency_dirs,omitempty"`
	SentinelsCapped bool                      `json:"sentinels_capped,omitempty"`
	Warnings        []string                  `json:"warnings,omitempty"`
	UndoneAt        *time.Time                `json:"undone_at,omitempty"`
	// PostCommit is the shadow commit of the folder as it was when Undo
	// ran, so an undo can itself be reverted.
	PostCommit string `json:"post_commit,omitempty"`
}

// GitSnapshot is the git half of a snapshot.
type GitSnapshot struct {
	GitDir   string `json:"git_dir"`
	GitDirID FileID `json:"git_dir_id"`
	// Shadow is the DefenseClaw-owned git dir holding the snapshot.
	Shadow string `json:"shadow"`
	// Ref names the snapshot commit in the shadow and, when ProjectRef is
	// set, in the project repository too.
	Ref        string `json:"ref"`
	ProjectRef bool   `json:"project_ref,omitempty"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
	// IndexCommit wraps the tree of the project's staging area.
	IndexCommit string `json:"index_commit,omitempty"`
	// Head is the HEAD commit ("" for an unborn branch); Branch the ref HEAD
	// points at ("" when detached).
	Head   string            `json:"head,omitempty"`
	Branch string            `json:"branch,omitempty"`
	Refs   map[string]string `json:"refs,omitempty"`
	// Control holds agent-writable git control files (relative to GitDir)
	// that Undo restores.
	Control map[string]FileState `json:"control,omitempty"`
	// Pinned holds the files a live mount binds read-only (relative to the
	// project); changes there were made on the host and are only reported.
	Pinned           map[string]FileState `json:"pinned,omitempty"`
	Ignored          []string             `json:"ignored,omitempty"`
	IgnoredTruncated bool                 `json:"ignored_truncated,omitempty"`
	ObjectsLinked    bool                 `json:"objects_linked"`
}

// CopyTree is a non-git snapshot on disk.
type CopyTree struct {
	Dir     string   `json:"dir"`
	Files   int      `json:"files"`
	Bytes   int64    `json:"bytes"`
	Skipped []string `json:"skipped,omitempty"`
	// Opaque lists heavy directories (node_modules, .venv) that were not
	// copied; Undo leaves them alone.
	Opaque []string `json:"opaque,omitempty"`
}

// DirFingerprint is a cheap change signal for a dependency directory.
type DirFingerprint struct {
	Exists  bool      `json:"exists"`
	Entries int       `json:"entries"`
	ModTime time.Time `json:"mod_time"`
	Marker  string    `json:"marker,omitempty"`
}

// agentWritableControl are git control files inside the git dir that the
// agent can write through the mount and that change how host git behaves.
var agentWritableControl = []string{
	"config.worktree", "info/attributes", "info/grafts", "info/sparse-checkout",
	"objects/info/alternates", "shallow",
}

const (
	maxIgnoredEntries = 20_000
	maxSentinels      = 5_000
	keepControlBytes  = 256 << 10
)

// Snapshot records the project before a session so Undo can restore it.
func Snapshot(ctx context.Context, opts SnapshotOptions) (*SnapshotRecord, error) {
	if !platformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	if err := ValidateName(opts.Name); err != nil {
		return nil, err
	}
	lay, err := newLayout(opts.DataDir)
	if err != nil {
		return nil, err
	}
	if !opts.Replace && pathExists(lay.snapshotRecord(opts.Name)) {
		return nil, fmt.Errorf("%w: %s", ErrSnapshotExists, opts.Name)
	}
	src, err := ValidateSource(ctx, opts.Project, SourceOptions{Home: opts.Home, DataDir: lay.dataDir, Protected: opts.Protected})
	if err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	rec := &SnapshotRecord{Version: 1, Name: opts.Name, Project: src.Path, CreatedAt: now().UTC()}
	if opts.Replace {
		if err := removeSnapshotData(ctx, lay, opts.Name, true); err != nil {
			return nil, err
		}
	}
	if err := ensurePrivateDir(lay.snapshotDir(opts.Name)); err != nil {
		return nil, err
	}
	if src.Git != nil {
		rec.Kind = SnapshotGit
		if err := snapshotGit(ctx, lay, src, opts, rec); err != nil {
			_ = os.RemoveAll(lay.snapshotDir(opts.Name))
			return nil, err
		}
	} else {
		rec.Kind = SnapshotCopy
		if err := snapshotCopy(lay, src, opts, rec); err != nil {
			_ = os.RemoveAll(lay.snapshotDir(opts.Name))
			return nil, err
		}
	}
	sentinels, err := scanSentinels(src.Path, opts.Skip)
	if err != nil {
		_ = os.RemoveAll(lay.snapshotDir(opts.Name))
		return nil, err
	}
	rec.Sentinels, rec.NestedRepos, rec.DependencyDirs, rec.SentinelsCapped = sentinels.files, sentinels.nested, sentinels.deps, sentinels.capped
	if err := writeJSON(lay.snapshotRecord(opts.Name), rec); err != nil {
		_ = os.RemoveAll(lay.snapshotDir(opts.Name))
		return nil, err
	}
	return rec, nil
}

func snapshotGit(ctx context.Context, lay layout, src *Source, opts SnapshotOptions, rec *SnapshotRecord) error {
	gitDir := src.Git.GitDir
	info, err := os.Lstat(gitDir)
	if err != nil {
		return err
	}
	id, _ := identityOf(info)
	sh, unlock, err := openShadow(ctx, lay, src.Path, gitDir, opts.Home)
	if err != nil {
		return err
	}
	defer unlock()

	gs := &GitSnapshot{GitDir: gitDir, GitDirID: id, Shadow: sh.dir, Ref: "refs/defenseclaw/pre/" + opts.Name}
	rec.Git = gs
	linked, why := sh.linkObjects()
	gs.ObjectsLinked = linked
	if !linked {
		rec.Warnings = append(rec.Warnings, why)
	}
	proj := gitCmd{dir: src.Path, gitDir: gitDir, workTree: src.Path}
	gs.Head, gs.Branch, err = resolveHead(ctx, proj)
	if err != nil {
		return err
	}
	if gs.Refs, err = listRefs(ctx, proj); err != nil {
		return err
	}
	commit, tree, warnings, err := sh.capture(ctx, "defenseclaw: working tree before sandbox session "+opts.Name, gs.Head)
	if err != nil {
		return err
	}
	rec.Warnings = append(rec.Warnings, warnings...)
	gs.Commit, gs.Tree = commit, tree
	if err := sh.updateRef(ctx, gs.Ref, commit); err != nil {
		return err
	}
	if ic, err := indexCommit(ctx, sh, opts.Name); err == nil {
		gs.IndexCommit = ic
	} else {
		rec.Warnings = append(rec.Warnings, "the staging area was not recorded ("+err.Error()+"); undo will leave it as the session left it")
	}
	ignored, err := sh.ignoredEntries(ctx, maxIgnoredEntries+1)
	if err == nil {
		gs.IgnoredTruncated = len(ignored) > maxIgnoredEntries
		if gs.IgnoredTruncated {
			ignored = ignored[:maxIgnoredEntries]
		}
		gs.Ignored = ignored
	}
	gs.Control, err = captureControl(gitDir)
	if err != nil {
		return err
	}
	gs.Pinned, err = capturePinned(src)
	if err != nil {
		return err
	}
	if hasGitlinks(ctx, sh.bare(), tree) {
		rec.Warnings = append(rec.Warnings, "submodule working trees are not part of the snapshot; undo restores which submodule commit is checked out, not files inside submodules")
	}
	if !opts.NoProjectRef {
		if err := exportToProject(ctx, sh, proj, gs.Ref); err != nil {
			rec.Warnings = append(rec.Warnings, "could not add "+gs.Ref+" to the project repository ("+err.Error()+"); the snapshot is kept by DefenseClaw only")
		} else {
			gs.ProjectRef = true
		}
	}
	return nil
}

// resolveHead returns the HEAD commit ("" when unborn) and the symbolic
// ref HEAD points at ("" when detached).
func resolveHead(ctx context.Context, g gitCmd) (head, branch string, err error) {
	out, code, err := g.outputCode(ctx, "symbolic-ref", "-q", "HEAD")
	if err != nil {
		return "", "", err
	}
	if code == 0 {
		branch = strings.TrimSpace(string(out))
	}
	out, code, err = g.outputCode(ctx, "rev-parse", "-q", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", "", err
	}
	if code == 0 {
		head = strings.TrimSpace(string(out))
	}
	return head, branch, nil
}

func listRefs(ctx context.Context, g gitCmd) (map[string]string, error) {
	out, err := g.output(ctx, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		oid, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && isOID(oid) {
			refs[name] = oid
		}
	}
	return refs, nil
}

// indexCommit records the project's staging area as a commit in the
// shadow by reading a copy of the project's index there.
func indexCommit(ctx context.Context, sh *shadow, name string) (string, error) {
	src := filepath.Join(sh.gitDir, "index")
	if !pathExists(src) {
		return "", nil
	}
	tmp := filepath.Join(sh.dir, "dc-index-"+randomSuffix())
	defer os.Remove(tmp)
	if err := copyRegular(src, tmp, 0o600, time.Time{}); err != nil {
		return "", err
	}
	g := sh.bare()
	g.index = tmp
	tree, err := g.line(ctx, "write-tree")
	if err != nil {
		return "", err
	}
	commit, err := g.line(ctx, "commit-tree", tree, "-m", "defenseclaw: staging area before sandbox session "+name)
	if err != nil {
		return "", err
	}
	if err := sh.updateRef(ctx, "refs/defenseclaw/pre-index/"+name, commit); err != nil {
		return "", err
	}
	return commit, nil
}

func captureControl(gitDir string) (map[string]FileState, error) {
	out := map[string]FileState{}
	for _, rel := range agentWritableControl {
		st, err := captureState(filepath.Join(gitDir, filepath.FromSlash(rel)), keepControlBytes)
		if err != nil {
			return nil, err
		}
		out[rel] = st
	}
	return out, nil
}

func capturePinned(src *Source) (map[string]FileState, error) {
	// The commondir pin is DefenseClaw's own and comes and goes with the
	// mount, so it is not tracked here.
	g := src.Git
	paths := []string{
		filepath.Join(g.GitDir, "config"),
		filepath.Join(g.GitDir, "hooks"),
	}
	if g.HooksPath != "" {
		paths = append(paths, g.HooksPath)
	}
	paths = append(paths, g.IncludeFiles...)
	for _, sub := range g.Submodules {
		paths = append(paths, filepath.Join(sub, "config"), filepath.Join(sub, "hooks"))
	}
	out := map[string]FileState{}
	for _, p := range paths {
		rel, err := relSlash(src.Path, p)
		if err != nil {
			continue
		}
		st, err := captureState(p, 0)
		if err != nil {
			return nil, err
		}
		out[rel] = st
	}
	return out, nil
}

func hasGitlinks(ctx context.Context, g gitCmd, tree string) bool {
	out, err := g.output(ctx, "ls-tree", "-r", "-z", tree)
	if err != nil {
		return false
	}
	for _, e := range splitNUL(out) {
		if strings.HasPrefix(e, modeGitlink+" ") {
			return true
		}
	}
	return false
}

// exportToProject fetches a shadow ref into the project repository under
// the same name. The fetch runs in the project with every gitsafe
// mitigation and never updates the working tree; upload-pack runs in the
// DefenseClaw-owned shadow.
func exportToProject(ctx context.Context, sh *shadow, proj gitCmd, ref string) error {
	proj.workTree = ""
	proj.config = append(proj.config, "fetch.writeCommitGraph=false", "fetch.fsckObjects=false")
	return proj.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc",
		"--no-auto-maintenance", "--no-recurse-submodules", sh.dir, "+"+ref+":"+ref)
}

func snapshotCopy(lay layout, src *Source, opts SnapshotOptions, rec *SnapshotRecord) error {
	limit := opts.MaxCopyBytes
	if limit <= 0 {
		limit = DefaultMaxCopySnapshotBytes
	}
	skip := toSet(opts.Skip)
	var total int64
	var files int
	var opaque []string
	type entry struct {
		rel  string
		info fs.FileInfo
	}
	var entries []entry
	_, err := walkProject(src.Path, 0, func(rel string, d fs.DirEntry) error {
		if skipped(skip, rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if isOpaqueDir(d) {
			opaque = append(opaque, rel)
			return nil
		}
		if d.Name() == ".git" {
			opaque = append(opaque, rel)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode().IsRegular():
			total += info.Size()
			files++
			if total > limit {
				return &TooLargeError{What: "the folder (for its undo snapshot)", Size: total, Limit: limit}
			}
		case info.IsDir(), info.Mode()&os.ModeSymlink != 0:
		default:
			rec.Warnings = append(rec.Warnings, rel+" is a special file and is not part of the snapshot")
			return nil
		}
		entries = append(entries, entry{rel: rel, info: info})
		return nil
	})
	if err != nil {
		var tl *TooLargeError
		if errors.As(err, &tl) {
			return err
		}
		return fmt.Errorf("workspace: snapshot %s: %w", src.Path, err)
	}
	dst := lay.plainTree(opts.Name)
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	var dirs []entry
	for _, e := range entries {
		to := filepath.Join(dst, filepath.FromSlash(e.rel))
		from := filepath.Join(src.Path, filepath.FromSlash(e.rel))
		switch {
		case e.info.IsDir():
			if err := os.Mkdir(to, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, e)
		case e.info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(from)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, to); err != nil {
				return err
			}
		default:
			if err := copyRegular(from, to, e.info.Mode(), e.info.ModTime()); err != nil {
				return fmt.Errorf("workspace: snapshot %s: %w", e.rel, err)
			}
		}
	}
	// Directory modes last, so read-only directories do not block the copy.
	for i := len(dirs) - 1; i >= 0; i-- {
		to := filepath.Join(dst, filepath.FromSlash(dirs[i].rel))
		_ = os.Chmod(to, dirs[i].info.Mode().Perm()|0o700)
		_ = os.Chtimes(to, dirs[i].info.ModTime(), dirs[i].info.ModTime())
	}
	sort.Strings(opaque)
	rec.Copy = &CopyTree{Dir: dst, Files: files, Bytes: total, Skipped: sortedCopy(opts.Skip), Opaque: opaque}
	if len(opaque) > 0 {
		rec.Warnings = append(rec.Warnings, "not part of the undo snapshot: "+strings.Join(firstN(opaque, 5), ", "))
	}
	return nil
}

type sentinelScan struct {
	files  map[string]FileState
	nested []string
	deps   map[string]DirFingerprint
	capped bool
}

// scanSentinels walks the folder for host-executable files, nested git
// repositories and dependency directories, whether or not git tracks or
// ignores them.
func scanSentinels(root string, skip []string) (*sentinelScan, error) {
	res := &sentinelScan{files: map[string]FileState{}, deps: map[string]DirFingerprint{}}
	skipSet := toSet(skip)
	truncated, err := walkProject(root, 0, func(rel string, d fs.DirEntry) error {
		if skipped(skipSet, rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" {
			if rel != ".git" {
				res.nested = append(res.nested, path.Dir(rel))
			}
			return nil
		}
		if d.IsDir() {
			if isDependencyDir(d.Name()) && strings.Count(rel, "/") < 3 {
				res.deps[rel] = fingerprintDir(filepath.Join(root, filepath.FromSlash(rel)))
			}
			return nil
		}
		if !isSentinelPath(rel) {
			return nil
		}
		if len(res.files) >= maxSentinels {
			res.capped = true
			return nil
		}
		st, err := captureState(filepath.Join(root, filepath.FromSlash(rel)), sentinelKeep(rel))
		if err != nil {
			return nil
		}
		res.files[rel] = st
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: scan %s: %w", root, err)
	}
	res.capped = res.capped || truncated
	sort.Strings(res.nested)
	return res, nil
}

// sentinelKeep keeps the content of files Review parses (package.json
// scripts, .gitattributes drivers, .gitmodules URLs).
func sentinelKeep(rel string) int64 {
	switch strings.ToLower(path.Base(rel)) {
	case "package.json", ".gitattributes", ".gitmodules":
		return 256 << 10
	}
	return 0
}

func isDependencyDir(name string) bool {
	for _, d := range dependencyDirNames {
		if name == d {
			return true
		}
	}
	return false
}

// fingerprintDir summarizes a dependency directory from its first two
// levels (entry count, newest modification time) plus the package
// manager's own state file. Installs and removals always show; an in-place
// edit deep inside one installed package may not.
func fingerprintDir(dir string) DirFingerprint {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return DirFingerprint{}
	}
	fp := DirFingerprint{Exists: true, ModTime: info.ModTime().UTC()}
	newest := func(t time.Time) {
		if t.UTC().After(fp.ModTime) {
			fp.ModTime = t.UTC()
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		fp.Entries = len(entries)
		for _, e := range entries {
			ei, err := e.Info()
			if err != nil {
				continue
			}
			newest(ei.ModTime())
			if !e.IsDir() {
				continue
			}
			sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			fp.Entries += len(sub)
			for _, s := range sub {
				if si, err := s.Info(); err == nil {
					newest(si.ModTime())
				}
			}
		}
	}
	for _, marker := range []string{".package-lock.json", ".modules.yaml", ".yarn-state.yml", "pyvenv.cfg"} {
		if _, sum, err := hashFile(filepath.Join(dir, marker), 0); err == nil {
			fp.Marker = marker + ":" + sum
			break
		}
	}
	return fp
}

func toSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.Trim(filepath.ToSlash(s), "/")] = struct{}{}
	}
	return out
}

// skipped reports whether rel or one of its parents is in set.
func skipped(set map[string]struct{}, rel string) bool {
	if len(set) == 0 {
		return false
	}
	for p := rel; p != "." && p != ""; p = path.Dir(p) {
		if _, ok := set[p]; ok {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// LoadSnapshot reads the record for name.
func LoadSnapshot(dataDir, name string) (*SnapshotRecord, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	var rec SnapshotRecord
	if err := readJSON(lay.snapshotRecord(name), &rec); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrSnapshotNotFound, name)
		}
		return nil, err
	}
	if rec.Name != name {
		return nil, fmt.Errorf("workspace: snapshot record %s names %q", name, rec.Name)
	}
	return &rec, nil
}

// ListSnapshots returns every recorded snapshot, oldest first.
func ListSnapshots(dataDir string) ([]*SnapshotRecord, error) {
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(lay.snapshotsRoot())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*SnapshotRecord
	for _, e := range entries {
		if !e.IsDir() || ValidateName(e.Name()) != nil {
			continue
		}
		rec, err := LoadSnapshot(dataDir, e.Name())
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// DeleteSnapshot forgets a snapshot: its record, copy, shadow refs and the
// project ref. The shadow git dir goes when no other snapshot uses it.
func DeleteSnapshot(ctx context.Context, dataDir, name string) error {
	lay, err := newLayout(dataDir)
	if err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	return removeSnapshotData(ctx, lay, name, false)
}

// removeSnapshotData deletes a snapshot. keepShadow retains the shadow git
// dir even when no other snapshot uses it (a snapshot being replaced).
func removeSnapshotData(ctx context.Context, lay layout, name string, keepShadow bool) error {
	rec, err := LoadSnapshot(lay.dataDir, name)
	if err != nil && !errors.Is(err, ErrSnapshotNotFound) {
		return err
	}
	if rec != nil && rec.Git != nil {
		gs := rec.Git
		if sh, unlock, err := reopenShadow(ctx, gs.Shadow, rec.Project, gs.GitDir); err == nil {
			for _, ref := range []string{gs.Ref, "refs/defenseclaw/pre-index/" + name, "refs/defenseclaw/post/" + name} {
				_ = sh.bare().run(ctx, "update-ref", "-d", ref)
			}
			unlock()
		}
		if gs.ProjectRef && gitDirUnchanged(gs) {
			proj := gitCmd{dir: rec.Project, gitDir: gs.GitDir}
			for _, ref := range []string{gs.Ref, "refs/defenseclaw/post/" + name} {
				_ = proj.run(ctx, "update-ref", "-d", ref)
			}
		}
	}
	if err := os.RemoveAll(lay.snapshotDir(name)); err != nil {
		_ = chmodTree(lay.snapshotDir(name))
		if err := os.RemoveAll(lay.snapshotDir(name)); err != nil {
			return fmt.Errorf("workspace: remove snapshot %s: %w", name, err)
		}
	}
	if rec != nil && rec.Git != nil && !keepShadow && !shadowInUse(lay, rec.Git.Shadow) {
		_ = os.RemoveAll(rec.Git.Shadow)
		_ = os.Remove(rec.Git.Shadow + ".lock")
	}
	return nil
}

func shadowInUse(lay layout, dir string) bool {
	recs, err := ListSnapshots(lay.dataDir)
	if err != nil {
		return true
	}
	for _, r := range recs {
		if r.Git != nil && r.Git.Shadow == dir {
			return true
		}
	}
	return false
}

// gitDirUnchanged reports whether the project's git dir is still the one
// the snapshot recorded (same path, same inode).
func gitDirUnchanged(gs *GitSnapshot) bool {
	info, err := os.Lstat(gs.GitDir)
	if err != nil || !info.IsDir() {
		return false
	}
	id, ok := identityOf(info)
	return ok && id == gs.GitDirID
}
