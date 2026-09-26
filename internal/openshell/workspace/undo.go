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
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// UndoOptions configures Undo. The sandbox must be stopped (or deleted)
// first: a running agent could keep writing while the folder is restored.
type UndoOptions struct {
	DataDir string
	Name    string
	// Preview computes the result without changing anything.
	Preview bool
	// KeepRefs leaves branches and tags as the session left them; by default
	// they are reset to their pre-session values along with HEAD.
	KeepRefs bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// RefChange is a branch or tag the session created, moved or deleted.
type RefChange struct {
	Ref    string `json:"ref"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// UndoResult describes what Undo changed (or, with Preview, would change).
// Changes are listed from the pre-session state to the current folder; an
// undo reverses each one.
type UndoResult struct {
	Name    string       `json:"name"`
	Project string       `json:"project"`
	Kind    SnapshotKind `json:"kind"`
	Preview bool         `json:"preview"`
	Changes []TreeChange `json:"changes,omitempty"`
	// HEAD and branch before the session and now.
	HeadBefore   string      `json:"head_before,omitempty"`
	HeadAfter    string      `json:"head_after,omitempty"`
	BranchBefore string      `json:"branch_before,omitempty"`
	BranchAfter  string      `json:"branch_after,omitempty"`
	RefChanges   []RefChange `json:"ref_changes,omitempty"`
	// ControlChanges are agent-writable git control files that are reset.
	ControlChanges []string `json:"control_changes,omitempty"`
	// PinnedChanges are read-only-mounted git files that changed anyway,
	// so the change came from the host; they are reported, not reverted.
	PinnedChanges []string `json:"pinned_changes,omitempty"`
	// NestedRepos are git repositories created inside the folder during
	// the session; undo removes them.
	NestedRepos []string `json:"nested_repos,omitempty"`
	// LostObjects are pre-session commits missing from the project's
	// object store (deleted during the session); undo copies them back.
	LostObjects   []string `json:"lost_objects,omitempty"`
	IndexRestored bool     `json:"index_restored,omitempty"`
	// PostCommit keeps the folder as the session left it (shadow commit,
	// and refs/defenseclaw/post/<name> in the project when possible).
	PostCommit string   `json:"post_commit,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Empty reports whether the folder already matches the snapshot.
func (r *UndoResult) Empty() bool {
	return len(r.Changes) == 0 && len(r.RefChanges) == 0 && len(r.ControlChanges) == 0 &&
		len(r.NestedRepos) == 0 && len(r.LostObjects) == 0 &&
		r.HeadBefore == r.HeadAfter && r.BranchBefore == r.BranchAfter
}

// Undo restores the project folder to its pre-session snapshot: the
// working tree (tracked and untracked files; ignored files are left alone),
// HEAD and the branch, branches and tags, the staging area, and the git
// control files the agent could write. Run it with Preview first to show
// the operator what will change.
func Undo(ctx context.Context, opts UndoOptions) (*UndoResult, error) {
	if !platformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	rec, err := LoadSnapshot(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return nil, err
	}
	res := &UndoResult{Name: rec.Name, Project: rec.Project, Kind: rec.Kind, Preview: opts.Preview}
	switch rec.Kind {
	case SnapshotGit:
		err = undoGit(ctx, rec, opts, res)
	case SnapshotCopy:
		err = undoCopy(rec, opts, res)
	default:
		err = fmt.Errorf("workspace: snapshot %s has unknown kind %q", rec.Name, rec.Kind)
	}
	if err != nil {
		return nil, err
	}
	if !opts.Preview {
		now := time.Now
		if opts.Now != nil {
			now = opts.Now
		}
		t := now().UTC()
		rec.UndoneAt = &t
		if res.PostCommit != "" {
			rec.PostCommit = res.PostCommit
		}
		lay, _ := newLayout(opts.DataDir)
		if err := writeJSON(lay.snapshotRecord(rec.Name), rec); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		}
	}
	return res, nil
}

// checkProjectPath refuses to restore into a folder whose path now goes
// through a symlink or is gone.
func checkProjectPath(project string) error {
	real, err := filepath.EvalSymlinks(project)
	if err != nil {
		return fmt.Errorf("workspace: project folder %s: %w", project, err)
	}
	if real != project {
		return &SourceError{Path: project, Reason: "the path now goes through a symbolic link"}
	}
	info, err := os.Stat(project)
	if err != nil || !info.IsDir() {
		return &SourceError{Path: project, Reason: "it is no longer a directory"}
	}
	return nil
}

// sessionState is the project's git state after a session, read through
// the shadow and the project's own refs.
type sessionState struct {
	sh       *shadow
	unlock   func()
	post     string
	postTree string
	proj     gitCmd
	head     string
	branch   string
	refs     map[string]string
	gitDirOK bool
	warnings []string
}

// openSession captures the folder as it is now into the shadow and reads
// HEAD and refs. The capture needs only the shadow, so it works even when
// the project's git dir was replaced; reading refs does not, and is skipped
// (gitDirOK false) unless requireGitDir turns that into ErrGitDirReplaced.
func openSession(ctx context.Context, rec *SnapshotRecord, label string, requireGitDir bool) (*sessionState, error) {
	gs := rec.Git
	gitDirOK := gitDirUnchanged(gs)
	if !gitDirOK && requireGitDir {
		return nil, fmt.Errorf("%w: %s is not the directory recorded before the session; the pre-session state is kept in %s (commit %s)",
			ErrGitDirReplaced, gs.GitDir, gs.Shadow, gs.Commit)
	}
	sh, unlock, err := reopenShadow(ctx, gs.Shadow, rec.Project, gs.GitDir)
	if err != nil {
		return nil, err
	}
	st := &sessionState{sh: sh, unlock: unlock, gitDirOK: gitDirOK}
	st.post, st.postTree, st.warnings, err = sh.capture(ctx, label, gs.Commit)
	if err != nil {
		unlock()
		return nil, err
	}
	st.proj = gitCmd{dir: rec.Project, gitDir: gs.GitDir}
	if !gitDirOK {
		return st, nil
	}
	st.head, st.branch, err = resolveHead(ctx, st.proj)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("workspace: read the project's HEAD: %w", err)
	}
	st.refs, err = listRefs(ctx, st.proj)
	if err != nil {
		unlock()
		return nil, err
	}
	return st, nil
}

func refChanges(before, after map[string]string) []RefChange {
	var out []RefChange
	for ref, b := range before {
		if a := after[ref]; a != b {
			out = append(out, RefChange{Ref: ref, Before: b, After: a})
		}
	}
	for ref, a := range after {
		if _, ok := before[ref]; !ok {
			out = append(out, RefChange{Ref: ref, After: a})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func controlChanges(gs *GitSnapshot) ([]string, error) {
	now, err := captureControl(gs.GitDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for rel, before := range gs.Control {
		if !before.equal(now[rel]) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out, nil
}

func pinnedChanges(rec *SnapshotRecord) []string {
	var out []string
	for rel, before := range rec.Git.Pinned {
		now, err := captureState(filepath.Join(rec.Project, filepath.FromSlash(rel)), 0)
		unchanged := err == nil && (before.equal(now) || (emptyPin(before) && emptyPin(now)))
		if !unchanged {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// emptyPin reports whether a state is absent, an empty file or an empty
// directory: the shapes PlanMount creates and ReleaseMount removes, which
// must not read as operator changes.
func emptyPin(s FileState) bool {
	switch {
	case !s.Exists:
		return true
	case s.Dir:
		return s.Empty
	case s.Symlink == "":
		return s.Size == 0
	}
	return false
}

// newNestedRepos lists git repositories that appeared inside the folder
// since the snapshot.
func newNestedRepos(rec *SnapshotRecord) ([]string, bool, error) {
	now, err := scanSentinels(rec.Project, skipList(rec))
	if err != nil {
		return nil, false, err
	}
	before := toSet(rec.NestedRepos)
	var out []string
	for _, n := range now.nested {
		if _, ok := before[n]; !ok {
			out = append(out, n)
		}
	}
	return out, rec.SentinelsCapped || now.capped, nil
}

func skipList(rec *SnapshotRecord) []string {
	if rec.Copy != nil {
		return rec.Copy.Skipped
	}
	return nil
}

func undoGit(ctx context.Context, rec *SnapshotRecord, opts UndoOptions, res *UndoResult) error {
	gs := rec.Git
	st, err := openSession(ctx, rec, "defenseclaw: working tree when sandbox session "+rec.Name+" was undone", true)
	if err != nil {
		return err
	}
	defer st.unlock()
	res.Warnings = append(res.Warnings, st.warnings...)
	res.PostCommit = st.post
	res.HeadBefore, res.BranchBefore = gs.Head, gs.Branch
	res.HeadAfter, res.BranchAfter = st.head, st.branch

	if res.Changes, err = diffTrees(ctx, st.sh.bare(), gs.Tree, st.postTree); err != nil {
		return err
	}
	res.RefChanges = refChanges(gs.Refs, st.refs)
	if res.ControlChanges, err = controlChanges(gs); err != nil {
		return err
	}
	res.PinnedChanges = pinnedChanges(rec)
	nested, capped, err := newNestedRepos(rec)
	if err != nil {
		return err
	}
	res.NestedRepos = nested
	if capped {
		res.Warnings = append(res.Warnings, "the folder is too large to check completely for new nested git repositories")
	}
	needed := map[string]struct{}{}
	for _, oid := range gs.Refs {
		needed[oid] = struct{}{}
	}
	if gs.Head != "" {
		needed[gs.Head] = struct{}{}
	}
	res.LostObjects = missingObjects(ctx, st.proj, needed)
	if opts.Preview {
		return nil
	}
	if res.Empty() {
		// Nothing to restore; keep the session state an earlier undo saved.
		res.PostCommit = rec.PostCommit
		return nil
	}

	postRef := "refs/defenseclaw/post/" + rec.Name
	if err := st.sh.updateRef(ctx, postRef, st.post); err != nil {
		return err
	}
	// Git control files first, so no later git command in the project
	// reads a planted attributes, grafts or alternates file.
	if err := restoreControl(gs, res.ControlChanges); err != nil {
		return err
	}
	if len(res.LostObjects) > 0 {
		if still := recoverObjects(ctx, st, gs); len(still) > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%d pre-session commit(s) could not be recovered into the project: %s", len(still), strings.Join(firstN(still, 3), ", ")))
		}
	}
	if !opts.KeepRefs {
		warnings, err := restoreRefs(ctx, st, gs, res.RefChanges)
		if err != nil {
			return err
		}
		res.Warnings = append(res.Warnings, warnings...)
	}
	// The shadow index holds the capture just taken, so a one-way reset
	// removes what the session created and rewrites what it changed.
	if err := st.sh.git().run(ctx, "read-tree", "--reset", "-u", gs.Commit); err != nil {
		return fmt.Errorf("workspace: restore the working tree: %w", err)
	}
	if err := removeNestedRepos(ctx, st.sh, rec.Project, gs.Tree, res.NestedRepos); err != nil {
		return err
	}
	restored, warning := restoreIndex(ctx, st, gs, rec.Name)
	res.IndexRestored = restored
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}
	if err := exportToProject(ctx, st.sh, st.proj, postRef); err != nil {
		res.Warnings = append(res.Warnings, "the session's version of the folder is kept by DefenseClaw only ("+err.Error()+")")
	}
	return nil
}

// restoreControl puts agent-writable git control files back. Writes go
// through os.Root on the git dir, so a directory the agent replaced with a
// symlink cannot redirect them.
func restoreControl(gs *GitSnapshot, changed []string) error {
	if len(changed) == 0 {
		return nil
	}
	r, err := openRootFS(gs.GitDir)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, rel := range changed {
		before := gs.Control[rel]
		switch {
		case !before.Exists:
			if err := r.clear(rel); err != nil {
				return fmt.Errorf("workspace: remove %s: %w", rel, err)
			}
		case before.Dir || before.Symlink != "" || (before.Content == nil && before.Size > 0):
			return fmt.Errorf("workspace: cannot restore git control file %s (not recorded byte for byte)", rel)
		default:
			if err := r.writeFile(rel, bytes.NewReader(before.Content), os.FileMode(before.Mode), time.Time{}); err != nil {
				return fmt.Errorf("workspace: restore %s: %w", rel, err)
			}
		}
	}
	return nil
}

// recoverObjects fetches back, from the shadow, every pre-session ref
// target the project's object store lost during the session (the agent can
// delete .git/objects). It returns the oids that could not be recovered.
func recoverObjects(ctx context.Context, st *sessionState, gs *GitSnapshot) []string {
	needed := map[string]struct{}{}
	for _, oid := range gs.Refs {
		needed[oid] = struct{}{}
	}
	if gs.Head != "" {
		needed[gs.Head] = struct{}{}
	}
	missing := missingObjects(ctx, st.proj, needed)
	if len(missing) == 0 {
		return nil
	}
	// A fetch cannot repair this: the project still has refs naming the
	// lost commits, so negotiation claims them and nothing is sent. The
	// shadow holds the same immutable pack and loose-object files (hard
	// links taken at snapshot time), so put those back instead.
	_ = restoreObjectFiles(st.sh)
	return missingObjects(ctx, st.proj, needed)
}

// restoreObjectFiles links (or copies) every pack and loose object file
// the shadow has and the project lacks back into the project's store. The
// target directories are made real directories first, through os.Root, so
// a planted symlink cannot redirect the writes.
func restoreObjectFiles(sh *shadow) error {
	r, err := openRootFS(sh.gitDir)
	if err != nil {
		return err
	}
	defer r.Close()
	put := func(rel string) error {
		if _, err := r.root.Lstat(rel); err == nil {
			return nil
		}
		if err := r.ensureDir(path.Dir(rel)); err != nil {
			return err
		}
		src := filepath.Join(sh.dir, filepath.FromSlash(rel))
		if err := os.Link(src, filepath.Join(sh.gitDir, filepath.FromSlash(rel))); err == nil {
			return nil
		}
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		return r.writeFile(rel, f, 0o444, time.Time{})
	}
	packs, _ := os.ReadDir(filepath.Join(sh.dir, "objects", "pack"))
	var names []string
	for _, e := range packs {
		if e.Type().IsRegular() && packFileRE.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		ii, ji := strings.HasSuffix(names[i], ".idx"), strings.HasSuffix(names[j], ".idx")
		if ii != ji {
			return !ii
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		if err := put("objects/pack/" + n); err != nil {
			return err
		}
	}
	prefixes, _ := os.ReadDir(filepath.Join(sh.dir, "objects"))
	for _, p := range prefixes {
		if !p.IsDir() || !loosePrefixRE.MatchString(p.Name()) {
			continue
		}
		objs, _ := os.ReadDir(filepath.Join(sh.dir, "objects", p.Name()))
		for _, o := range objs {
			if o.Type().IsRegular() && looseObjectRE.MatchString(o.Name()) {
				if err := put("objects/" + p.Name() + "/" + o.Name()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// restoreRefs resets branches, tags and HEAD in one update-ref transaction.
func restoreRefs(ctx context.Context, st *sessionState, gs *GitSnapshot, changes []RefChange) ([]string, error) {
	var warnings []string
	var stdin bytes.Buffer
	for _, c := range changes {
		switch {
		case c.Before == "":
			fmt.Fprintf(&stdin, "delete %s %s\n", c.Ref, c.After)
		case c.After == "":
			fmt.Fprintf(&stdin, "create %s %s\n", c.Ref, c.Before)
		default:
			fmt.Fprintf(&stdin, "update %s %s %s\n", c.Ref, c.Before, c.After)
		}
	}
	if stdin.Len() > 0 {
		g := st.proj
		g.stdin = &stdin
		if err := g.run(ctx, "update-ref", "-m", "defenseclaw: undo sandbox session", "--stdin"); err != nil {
			return warnings, fmt.Errorf("workspace: restore branches and tags: %w", err)
		}
	}
	switch {
	case gs.Branch != "" && st.branch != gs.Branch:
		if err := st.proj.run(ctx, "symbolic-ref", "-m", "defenseclaw: undo sandbox session", "HEAD", gs.Branch); err != nil {
			return warnings, fmt.Errorf("workspace: restore HEAD: %w", err)
		}
	case gs.Branch == "" && gs.Head != "" && (st.branch != "" || st.head != gs.Head):
		if err := st.proj.run(ctx, "update-ref", "--no-deref", "-m", "defenseclaw: undo sandbox session", "HEAD", gs.Head); err != nil {
			return warnings, fmt.Errorf("workspace: restore HEAD: %w", err)
		}
	}
	return warnings, nil
}

// missingObjects returns the oids g's object store cannot find, with one
// cat-file --batch-check for the whole set.
func missingObjects(ctx context.Context, g gitCmd, oids map[string]struct{}) []string {
	if len(oids) == 0 {
		return nil
	}
	sorted := make([]string, 0, len(oids))
	for oid := range oids {
		sorted = append(sorted, oid)
	}
	sort.Strings(sorted)
	var in bytes.Buffer
	for _, oid := range sorted {
		in.WriteString(oid)
		in.WriteByte('\n')
	}
	g.stdin = &in
	g.workTree = ""
	out, err := g.output(ctx, "cat-file", "--batch-check=%(objectname)")
	if err != nil {
		return sorted
	}
	var missing []string
	for _, line := range strings.Split(string(out), "\n") {
		if oid, ok := strings.CutSuffix(strings.TrimSpace(line), " missing"); ok {
			missing = append(missing, oid)
		}
	}
	return missing
}

// removeNestedRepos deletes git repositories the session created. A whole
// directory goes when it did not exist before the session; otherwise only
// its .git entry is removed.
func removeNestedRepos(ctx context.Context, sh *shadow, project, preTree string, nested []string) error {
	if len(nested) == 0 {
		return nil
	}
	r, err := openRootFS(project)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, dir := range nested {
		existed := false
		if out, err := sh.bare().output(ctx, "ls-tree", "-z", "--name-only", preTree, "--", dir); err == nil && len(out) > 0 {
			existed = true
		}
		target := path.Join(dir, ".git")
		if !existed {
			target = dir
		}
		if err := r.clear(target); err != nil {
			return fmt.Errorf("workspace: remove nested repository %s: %w", dir, err)
		}
	}
	return nil
}

// restoreIndex puts the project's staging area back when the session
// changed it.
func restoreIndex(ctx context.Context, st *sessionState, gs *GitSnapshot, name string) (bool, string) {
	if gs.IndexCommit == "" {
		return false, ""
	}
	wantTree, err := st.sh.bare().line(ctx, "rev-parse", gs.IndexCommit+"^{tree}")
	if err != nil {
		return false, "the pre-session staging area could not be read: " + err.Error()
	}
	if cur, err := currentIndexTree(ctx, st.sh); err == nil && cur == wantTree {
		return false, ""
	}
	ref := "refs/defenseclaw/pre-index/" + name
	if missing := missingObjects(ctx, st.proj, map[string]struct{}{gs.IndexCommit: {}}); len(missing) > 0 {
		if err := st.proj.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc",
			"--no-auto-maintenance", "--no-recurse-submodules", st.sh.dir, "+"+ref+":"+ref); err != nil {
			return false, "the pre-session staging area could not be restored: " + err.Error()
		}
		defer func() { _ = st.proj.run(ctx, "update-ref", "-d", ref) }()
	}
	proj := st.proj
	proj.workTree = st.sh.project
	if err := proj.run(ctx, "read-tree", gs.IndexCommit); err != nil {
		return false, "the pre-session staging area could not be restored: " + err.Error()
	}
	_, _, _ = proj.outputCode(ctx, "update-index", "-q", "--refresh")
	return true, ""
}

func currentIndexTree(ctx context.Context, sh *shadow) (string, error) {
	src := filepath.Join(sh.gitDir, "index")
	tmp := filepath.Join(sh.dir, "dc-index-"+randomSuffix())
	defer os.Remove(tmp)
	if err := copyRegular(src, tmp, 0o600, time.Time{}); err != nil {
		return "", err
	}
	g := sh.bare()
	g.index = tmp
	return g.line(ctx, "write-tree")
}

func undoCopy(rec *SnapshotRecord, opts UndoOptions, res *UndoResult) error {
	if rec.Copy == nil {
		return fmt.Errorf("workspace: snapshot %s has no copy", rec.Name)
	}
	changes, before, _, err := compareTrees(rec.Copy.Dir, rec.Project, rec.Copy.Skipped)
	if err != nil {
		return err
	}
	res.Changes = changes
	nested, capped, err := newNestedRepos(rec)
	if err != nil {
		return err
	}
	res.NestedRepos = nested
	if capped {
		res.Warnings = append(res.Warnings, "the folder is too large to check completely for new nested git repositories")
	}
	if len(rec.Copy.Opaque) > 0 {
		res.Warnings = append(res.Warnings, "left as the session left them: "+strings.Join(firstN(rec.Copy.Opaque, 5), ", "))
	}
	if opts.Preview {
		return nil
	}
	if err := restoreTree(rec.Project, changes, before); err != nil {
		return err
	}
	if len(nested) == 0 {
		return nil
	}
	r, err := openRootFS(rec.Project)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, dir := range nested {
		if err := r.clear(path.Join(dir, ".git")); err != nil {
			return err
		}
	}
	return nil
}
