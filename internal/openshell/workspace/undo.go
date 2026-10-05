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
	// Quarantined are the project-relative quarantined .git entries of the
	// session (the nested-repository guard's detections): undo removes the
	// empty directory trees the restore leaves of them.
	Quarantined []string
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
	LostObjects []string `json:"lost_objects,omitempty"`
	// HiddenRemoved are files the session hid from git with changed
	// ignore rules; undo removes them too (they stay recoverable from
	// refs/defenseclaw/post-hidden/<name> in the snapshot storage).
	HiddenRemoved []string `json:"hidden_removed,omitempty"`
	IndexRestored bool     `json:"index_restored,omitempty"`
	// PostCommit keeps the folder as the session left it (shadow commit,
	// and refs/defenseclaw/post/<name> in the project when possible).
	PostCommit string `json:"post_commit,omitempty"`
	// SavedRefs are the post-session ref tips saved under refs/defenseclaw/post-refs/<name>/
	// before restoring the pre-session state, so the session's branch work is recoverable.
	SavedRefs []string `json:"saved_refs,omitempty"`
	// Ignored are changes where the snapshot holds no copy of the files:
	// what git ignores or, in a folder that is not a git repository, the
	// dependency directories it skips. Undo deletes what the session wrote
	// to Python bytecode caches (Removed), restores the directories the
	// undo point keeps a copy of (Restored, SnapshotOptions.KeepIgnored) and
	// leaves the rest, each with a Remedy.
	Ignored []IgnoredChange `json:"ignored,omitempty"`
	// QuarantineRemoved are the quarantined .git entries of the session
	// (UndoOptions.Quarantined) undo removed.
	QuarantineRemoved []string `json:"quarantine_removed,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

// Empty reports whether undo has nothing to put back: the folder matches
// the snapshot, apart from any Unrestored changes.
func (r *UndoResult) Empty() bool {
	return len(r.Changes) == 0 && len(r.RefChanges) == 0 && len(r.ControlChanges) == 0 &&
		len(r.NestedRepos) == 0 && len(r.LostObjects) == 0 &&
		r.HeadBefore == r.HeadAfter && r.BranchBefore == r.BranchAfter && !r.removesIgnored()
}

// Unrestored are the changes undo cannot put back (see Ignored).
func (r *UndoResult) Unrestored() []IgnoredChange {
	var out []IgnoredChange
	for _, c := range r.Ignored {
		if !c.Removed && !c.Restored {
			out = append(out, c)
		}
	}
	return out
}

// RestoredIgnored are the places undo puts back from the copies its undo
// point keeps (IgnoredChange.Restored).
func (r *UndoResult) RestoredIgnored() []IgnoredChange {
	var out []IgnoredChange
	for _, c := range r.Ignored {
		if c.Restored {
			out = append(out, c)
		}
	}
	return out
}

// removesIgnored reports an ignored place undo changes: a bytecode cache it
// empties or a kept directory it restores.
func (r *UndoResult) removesIgnored() bool {
	for _, c := range r.Ignored {
		if c.Removed || c.Restored {
			return true
		}
	}
	return false
}

// Undo restores the project folder to its pre-session snapshot: the
// working tree (tracked and untracked files), HEAD and the branch, branches
// and tags, the staging area, and the git control files the agent could
// write. Files git ignores have no copy in the snapshot: undo deletes what
// the session wrote to Python bytecode caches and reports the rest
// (UndoResult.Ignored). Run it with Preview first to show the operator what
// will change.
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
		removed, warnings := removeQuarantined(rec.Project, opts.Quarantined)
		res.QuarantineRemoved = removed
		res.Warnings = append(res.Warnings, warnings...)
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
		after := now[rel]
		// Empty pins (absent or empty files) created by PlanMount are not
		// reported as control changes when they stay empty.
		if before.equal(after) || (emptyPin(before) && emptyPin(after)) {
			continue
		}
		out = append(out, rel)
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
// since the snapshot, from a fresh scan of it (also returned). A folder
// the session made unreadable fails it with an *UnreadableError: undo
// cannot tell what it holds.
func newNestedRepos(rec *SnapshotRecord) ([]string, bool, *sentinelScan, error) {
	now, err := scanSentinels(rec.Project, skipList(rec))
	if err != nil {
		return nil, false, nil, err
	}
	if dirs := newUnreadable(rec, now); len(dirs) > 0 {
		return nil, false, nil, &UnreadableError{Project: rec.Project, Dirs: dirs}
	}
	before := toSet(rec.NestedRepos)
	var out []string
	for _, n := range now.nested {
		if _, ok := before[n]; !ok {
			out = append(out, n)
		}
	}
	return out, rec.SentinelsCapped || now.capped, now, nil
}

// newUnreadable lists the operator's folders that cannot be listed now but
// could be before the session.
func newUnreadable(rec *SnapshotRecord, now *sentinelScan) []string {
	before := toSet(rec.Unreadable)
	var out []string
	for _, dir := range now.unreadable {
		if _, ok := before[dir]; !ok {
			out = append(out, dir)
		}
	}
	return out
}

// undoIgnored fills res.Ignored from the snapshot's ignored manifest, if it
// has one, and returns the manifest; nowRoots are the ignored places now and
// changes the snapshot's own comparison.
func undoIgnored(rec *SnapshotRecord, dataDir string, nowRoots []string, changes []TreeChange, res *UndoResult) *ignoredManifest {
	man, err := loadIgnored(dataDir, rec.Name)
	if err != nil {
		res.Warnings = append(res.Warnings, "the record of the files the undo point does not copy is unreadable ("+err.Error()+"); undo cannot say what changed there")
		return nil
	}
	if man == nil {
		return nil
	}
	irep, err := diffIgnored(rec.Project, man, nowRoots, nil, changedPaths(changes))
	if err != nil {
		res.Warnings = append(res.Warnings, "could not check the files the undo point does not copy: "+err.Error())
		return nil
	}
	res.Ignored = irep.Changes
	if w := ignoredWarning(irep, rec.Kind == SnapshotGit); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	return man
}

// restoreIgnored puts back the kept directories (restoreKept) and deletes
// what the session wrote to bytecode caches (removeIgnored).
func restoreIgnored(rec *SnapshotRecord, dataDir string, man *ignoredManifest, res *UndoResult) {
	if lay, err := newLayout(dataDir); err == nil {
		res.Warnings = append(res.Warnings, restoreKept(lay, rec.Name, rec.Project, man, res.Ignored)...)
	}
	res.Warnings = append(res.Warnings, removeIgnored(rec.Project, res.Ignored)...)
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

	allChanges, err := diffTrees(ctx, st.sh.bare(), gs.Tree, st.postTree)
	if err != nil {
		return err
	}
	// Filter out pre-existing ignored files that are now visible only because
	// the session removed their ignore rule. These files existed before and
	// should not be reported as "A" (added) or removed by undo.
	for _, c := range allChanges {
		if c.Status == "A" && wasIgnored(c.Path, gs.Ignored) {
			// This file existed as an ignored file before the session.
			continue
		}
		res.Changes = append(res.Changes, c)
	}
	res.RefChanges = refChanges(gs.Refs, st.refs)
	if res.ControlChanges, err = controlChanges(gs); err != nil {
		return err
	}
	res.PinnedChanges = pinnedChanges(rec)
	nested, capped, _, err := newNestedRepos(rec)
	if err != nil {
		return err
	}
	res.NestedRepos = nested
	if capped {
		res.Warnings = append(res.Warnings, "the folder is too large to check completely for new nested git repositories")
	}
	nowIgnored, _ := st.sh.ignoredEntries(ctx, maxIgnoredFiles+1)
	// Only what the reset restores is left out of the ignored comparison.
	// A file that was ignored before the session and shows up now because
	// the agent removed its ignore rule is kept as it is on disk, so any
	// change the session made to it is one undo cannot put back.
	man := undoIgnored(rec, opts.DataDir, nowIgnored, res.Changes, res)
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
		warnings, savedRefs, err := restoreRefs(ctx, st, gs, rec.Name, res.RefChanges)
		if err != nil {
			return err
		}
		res.Warnings = append(res.Warnings, warnings...)
		res.SavedRefs = savedRefs
	}
	// Before resetting the tree, drop pre-existing ignored files from the
	// shadow index so read-tree --reset -u never touches them. These files
	// existed before the session and should stay exactly as they are on disk.
	var toPreserve []string
	for _, c := range allChanges {
		if c.Status == "A" && wasIgnored(c.Path, gs.Ignored) {
			toPreserve = append(toPreserve, c.Path)
		}
	}
	if len(toPreserve) > 0 {
		// Read through the project's os.Root to verify no parent is symlinked
		// before removing from the index.
		r, err := openRootFS(rec.Project)
		if err != nil {
			return err
		}
		var verified []string
		for _, p := range toPreserve {
			rel := path.Clean(p)
			if err := r.realParents(rel); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("cannot preserve %s: %v", rel, err))
				continue
			}
			verified = append(verified, p)
		}
		r.Close()
		if len(verified) > 0 {
			// Remove these paths from the shadow index in batches.
			const batchSize = 100
			for i := 0; i < len(verified); i += batchSize {
				end := i + batchSize
				if end > len(verified) {
					end = len(verified)
				}
				batch := verified[i:end]
				var stdin bytes.Buffer
				for _, p := range batch {
					stdin.WriteString(p)
					stdin.WriteByte(0)
				}
				g := st.sh.git()
				g.stdin = &stdin
				// The reset below would delete any file still in the shadow
				// index, so a failure here must stop the undo rather than
				// lose files that existed before the session.
				if err := g.run(ctx, "update-index", "-z", "--force-remove", "--stdin"); err != nil {
					return fmt.Errorf("workspace: keep pre-existing ignored files out of the undo: %w", err)
				}
			}
		}
	}

	// The shadow index holds the capture just taken, so a one-way reset
	// removes what the session created and rewrites what it changed.
	if err := st.sh.git().run(ctx, "read-tree", "--reset", "-u", gs.Commit); err != nil {
		return fmt.Errorf("workspace: restore the working tree: %w", err)
	}
	if err := removeNestedRepos(ctx, st.sh, rec.Project, gs.Tree, res.NestedRepos); err != nil {
		return err
	}
	// The reset put the pre-session .gitignore files back. Anything that
	// is visible now but was not before was either:
	// (a) hidden by ignore rules the session changed, or
	// (b) existed before as an ignored file but is now visible because the
	//     session removed its ignore rule.
	// Only (a) should be removed; (b) must be kept (they match gs.Ignored).
	hidden, hiddenTree, _, err := st.sh.capture(ctx, "defenseclaw: files hidden by ignore rules during sandbox session "+rec.Name, st.post)
	if err != nil {
		return err
	}
	if hiddenTree != gs.Tree {
		extra, err := diffTrees(ctx, st.sh.bare(), gs.Tree, hiddenTree)
		if err != nil {
			return err
		}
		// Filter out files that existed before and matched the pre-session ignore rules.
		var toRemove []TreeChange
		for _, c := range extra {
			if c.Status == "A" && wasIgnored(c.Path, gs.Ignored) {
				// This file existed before the session as an ignored file.
				// The agent removed its ignore rule, making it visible.
				// Keep it.
				continue
			}
			toRemove = append(toRemove, c)
		}
		if len(toRemove) > 0 {
			if err := st.sh.updateRef(ctx, "refs/defenseclaw/post-hidden/"+rec.Name, hidden); err != nil {
				return err
			}
			if err := st.sh.git().run(ctx, "read-tree", "--reset", "-u", gs.Commit); err != nil {
				return fmt.Errorf("workspace: remove files hidden during the session: %w", err)
			}
			for _, c := range toRemove {
				res.HiddenRemoved = append(res.HiddenRemoved, c.Path)
			}
		}
	}
	restored, warning := restoreIndex(ctx, st, gs, rec.Name)
	res.IndexRestored = restored
	if warning != "" {
		res.Warnings = append(res.Warnings, warning)
	}
	restoreIgnored(rec, opts.DataDir, man, res)
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
	// shadow holds its own copy of the object files taken at snapshot
	// time, so put those back instead.
	_ = restoreObjectFiles(st.sh)
	return missingObjects(ctx, st.proj, needed)
}

// restoreObjectFiles copies back into the project's store every pack and
// loose object file the shadow holds that the project lacks or holds with
// different bytes. Object files are named after their content, so a
// same-named file with other bytes was damaged, and the shadow's copy is an
// equivalent replacement. A replaced pack takes its whole group along (and
// loses derived files the shadow does not hold), so index and pack always
// match. Writes are byte copies through os.Root on the git dir: a planted
// symlink cannot redirect them, and the project never shares an inode with
// the shadow.
func restoreObjectFiles(sh *shadow) error {
	r, err := openRootFS(sh.gitDir)
	if err != nil {
		return err
	}
	defer r.Close()
	src := filepath.Join(sh.dir, "objects")
	put := func(rel string) error {
		f, err := os.OpenFile(filepath.Join(src, filepath.FromSlash(rel)), os.O_RDONLY|oNoFollow, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		return r.writeFile("objects/"+rel, f, 0o444, time.Time{})
	}
	packs, loose := objectFiles(src)
	for _, group := range packs {
		base := strings.TrimSuffix(group[0], path.Ext(group[0]))
		held := map[string]bool{}
		replace := false
		for _, rel := range group {
			held[rel] = true
			if ext := path.Ext(rel); (ext == ".pack" || ext == ".idx") && !r.sameFile("objects/"+rel, filepath.Join(src, filepath.FromSlash(rel))) {
				replace = true
			}
		}
		if !replace {
			// Intact pack and index; only fill in missing derived files.
			for _, rel := range group {
				if _, err := r.root.Lstat("objects/" + rel); err != nil {
					if err := put(rel); err != nil {
						return err
					}
				}
			}
			continue
		}
		for _, ext := range []string{".rev", ".bitmap", ".mtimes"} {
			if !held[base+ext] {
				_ = r.clear("objects/" + base + ext)
			}
		}
		for _, rel := range group {
			if err := put(rel); err != nil {
				return err
			}
		}
	}
	for _, rel := range loose {
		if !r.sameFile("objects/"+rel, filepath.Join(src, filepath.FromSlash(rel))) {
			if err := put(rel); err != nil {
				return err
			}
		}
	}
	return nil
}

// restoreRefs resets branches, tags and HEAD in one update-ref transaction.
// Before any ref is deleted or rewound, its post-session tip is saved under
// refs/defenseclaw/post-refs/<name>/<undo-id>/ so the session's work is recoverable
// even across multiple undos.
func restoreRefs(ctx context.Context, st *sessionState, gs *GitSnapshot, name string, changes []RefChange) ([]string, []string, error) {
	var warnings []string
	var savedRefs []string
	if len(changes) == 0 {
		return warnings, savedRefs, nil
	}
	// Generate a unique undo ID: UTC timestamp + random suffix.
	undoID := time.Now().UTC().Format("20060102T150405Z") + "-" + randomSuffix()[:8]
	// First, save all post-session ref tips under refs/defenseclaw/post-refs/<name>/<undo-id>/.
	var saveStdin bytes.Buffer
	refsSaved := make(map[string]bool)
	for _, c := range changes {
		if c.After != "" {
			// Save the post-session tip, whether it's being moved or deleted.
			savedRef := "refs/defenseclaw/post-refs/" + name + "/" + undoID + "/" + c.Ref
			fmt.Fprintf(&saveStdin, "create %s %s\n", savedRef, c.After)
			refsSaved[c.Ref] = false // Mark as pending
		}
	}
	if saveStdin.Len() > 0 {
		g := st.proj
		g.stdin = &saveStdin
		if err := g.run(ctx, "update-ref", "-m", "defenseclaw: save post-session refs before undo "+undoID, "--stdin"); err != nil {
			warnings = append(warnings, "could not save post-session ref tips: "+err.Error())
			// Mark all refs as failed to save
			for ref := range refsSaved {
				refsSaved[ref] = false
			}
		} else {
			// Mark all refs as successfully saved
			for ref := range refsSaved {
				refsSaved[ref] = true
				savedRefs = append(savedRefs, ref)
			}
		}
	}

	// Now restore the pre-session refs, but only for refs that were successfully saved.
	var stdin bytes.Buffer
	var skippedRefs []string
	for _, c := range changes {
		// If this ref had a post-session tip and we failed to save it, skip restoring it.
		if c.After != "" && !refsSaved[c.Ref] {
			skippedRefs = append(skippedRefs, c.Ref)
			continue
		}
		switch {
		case c.Before == "":
			fmt.Fprintf(&stdin, "delete %s %s\n", c.Ref, c.After)
		case c.After == "":
			fmt.Fprintf(&stdin, "create %s %s\n", c.Ref, c.Before)
		default:
			fmt.Fprintf(&stdin, "update %s %s %s\n", c.Ref, c.Before, c.After)
		}
	}
	if len(skippedRefs) > 0 {
		warnings = append(warnings, fmt.Sprintf("refs not reset because their post-session tips could not be saved: %s", strings.Join(skippedRefs, ", ")))
	}
	if stdin.Len() > 0 {
		g := st.proj
		g.stdin = &stdin
		if err := g.run(ctx, "update-ref", "-m", "defenseclaw: undo sandbox session", "--stdin"); err != nil {
			return warnings, savedRefs, fmt.Errorf("workspace: restore branches and tags: %w", err)
		}
	}
	switch {
	case gs.Branch != "" && st.branch != gs.Branch:
		if err := st.proj.run(ctx, "symbolic-ref", "-m", "defenseclaw: undo sandbox session", "HEAD", gs.Branch); err != nil {
			return warnings, savedRefs, fmt.Errorf("workspace: restore HEAD: %w", err)
		}
	case gs.Branch == "" && gs.Head != "" && (st.branch != "" || st.head != gs.Head):
		if err := st.proj.run(ctx, "update-ref", "--no-deref", "-m", "defenseclaw: undo sandbox session", "HEAD", gs.Head); err != nil {
			return warnings, savedRefs, fmt.Errorf("workspace: restore HEAD: %w", err)
		}
	}
	// Update the hint to show the actual save location with the undo ID.
	if len(savedRefs) > 0 {
		sort.Strings(savedRefs)
		refList := strings.Join(savedRefs, ", ")
		example := savedRefs[0]
		msg := fmt.Sprintf("Your session's branch and tag changes have been saved under refs/defenseclaw/post-refs/%s/%s/. To recover a branch, run: git branch <new-name> refs/defenseclaw/post-refs/%s/%s/%s. Changed/deleted: %s",
			name, undoID, name, undoID, example, refList)
		warnings = append(warnings, msg)
	}
	return warnings, savedRefs, nil
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

// removeNestedRepos deletes git repositories the session created. When the
// enclosing directory existed in the pre-session tree (tracked by git), the
// whole directory is removed only if it is now empty after removing .git.
// Otherwise, only the .git entry goes: an ignored directory may have existed
// with operator files, invisible to ls-tree, which must be kept.
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
		// Check if the directory itself was tracked in the pre-session tree.
		dirTracked := false
		if out, err := sh.bare().output(ctx, "ls-tree", "-z", "--name-only", preTree, "--", dir); err == nil && len(out) > 0 {
			dirTracked = true
		}

		// Remove the .git entry first. When dir is "." (top-level .git),
		// always target just ".git", never the entire project directory.
		gitPath := path.Join(dir, ".git")
		if dir == "." {
			gitPath = ".git"
		}
		if err := r.clear(gitPath); err != nil {
			return fmt.Errorf("workspace: remove nested repository %s: %w", dir, err)
		}

		// Only remove the whole directory if it was tracked and is now empty,
		// or if it was not tracked and contains only the .git we just removed.
		if dirTracked {
			// If tracked, the tree reset already restored any pre-session files.
			// If the directory is now empty, remove it too.
			fullPath := filepath.Join(project, filepath.FromSlash(dir))
			if entries, err := os.ReadDir(fullPath); err == nil && len(entries) == 0 {
				if err := r.clear(dir); err != nil {
					return fmt.Errorf("workspace: remove empty nested repo directory %s: %w", dir, err)
				}
			}
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

// wasIgnored reports whether path p was ignored in the pre-session snapshot.
// The snapshot's Ignored field contains the actual file paths git reported as
// ignored (via git ls-files --others --ignored --exclude-standard), so this
// is a simple membership check. Git's own matching handles nested .gitignore
// files, negation, directory patterns, anchored patterns, etc.
// Directory patterns end with "/" and match any file under that directory.
func wasIgnored(p string, ignoredPaths []string) bool {
	for _, ignored := range ignoredPaths {
		if ignored == p {
			return true
		}
		// Check if p is under an ignored directory (ends with /).
		if strings.HasSuffix(ignored, "/") && strings.HasPrefix(p, ignored) {
			return true
		}
	}
	return false
}

func undoCopy(rec *SnapshotRecord, opts UndoOptions, res *UndoResult) error {
	if rec.Copy == nil {
		return fmt.Errorf("workspace: snapshot %s has no copy", rec.Name)
	}
	changes, before, _, err := compareTrees(rec.Copy, rec.Project)
	if err != nil {
		return err
	}
	res.Changes = changes
	nested, capped, now, err := newNestedRepos(rec)
	if err != nil {
		return err
	}
	res.NestedRepos = nested
	if capped {
		res.Warnings = append(res.Warnings, "the folder is too large to check completely for new nested git repositories")
	}
	if man, _ := loadIgnored(opts.DataDir, rec.Name); man == nil && len(rec.Copy.Opaque) > 0 {
		// A snapshot from before the ignored manifest: say what undo skips.
		res.Warnings = append(res.Warnings, "left as the session left them: "+strings.Join(firstN(rec.Copy.Opaque, 5), ", "))
	}
	man := undoIgnored(rec, opts.DataDir, now.heavy, changes, res)
	if opts.Preview {
		return nil
	}
	if err := restoreTree(rec.Project, changes, before); err != nil {
		return err
	}
	restoreIgnored(rec, opts.DataDir, man, res)
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
