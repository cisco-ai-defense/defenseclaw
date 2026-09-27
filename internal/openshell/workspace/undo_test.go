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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func changePaths(cs []TreeChange) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Status+":"+c.Path)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func mustSnapshot(t *testing.T, e *env, name string) *SnapshotRecord {
	t.Helper()
	rec, err := Snapshot(bg, e.snapOpts(name))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustUndo(t *testing.T, e *env, name string, preview bool) *UndoResult {
	t.Helper()
	res, err := Undo(bg, UndoOptions{DataDir: e.data, Name: name, Preview: preview})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSnapshotUndoRestoresTrackedAndUntrackedFiles(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "notes.txt", "untracked before the session\n")
	writeFile(t, e.project, "src/app.go", "package main // uncommitted edit\n")
	writeFile(t, e.project, "build/cache.bin", "ignored before\n")
	rec := mustSnapshot(t, e, "s1")
	if rec.Kind != SnapshotGit || rec.Git.Head == "" || rec.Git.Branch != "refs/heads/main" {
		t.Fatalf("record: %+v", rec.Git)
	}
	if !rec.Git.ProjectRef || e.git(e.project, "rev-parse", "refs/defenseclaw/pre/s1") != rec.Git.Commit {
		t.Fatal("snapshot ref missing from the project repository")
	}

	// The session.
	writeFile(t, e.project, "README.md", "rewritten by the agent\n")
	if err := os.Remove(filepath.Join(e.project, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "src/new.go", "package main\n")
	writeFileMode(t, e.project, "run.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "build/out.log", "ignored output\n")
	if err := os.Chmod(filepath.Join(e.project, "src", "app.go"), 0o755); err != nil {
		t.Fatal(err)
	}

	preview := mustUndo(t, e, "s1", true)
	if got := changePaths(preview.Changes); got != "A:run.sh A:src/new.go D:notes.txt M:README.md M:src/app.go" {
		t.Fatalf("preview changes = %s", got)
	}
	if readFile(t, e.project, "README.md") != "rewritten by the agent\n" {
		t.Fatal("preview changed the folder")
	}

	res := mustUndo(t, e, "s1", false)
	if res.PostCommit == "" {
		t.Fatal("the session's state was not kept")
	}
	if readFile(t, e.project, "README.md") != "hello\n" || readFile(t, e.project, "notes.txt") != "untracked before the session\n" ||
		readFile(t, e.project, "src/app.go") != "package main // uncommitted edit\n" {
		t.Fatal("files not restored")
	}
	if info, _ := os.Stat(filepath.Join(e.project, "src", "app.go")); info.Mode().Perm()&0o111 != 0 {
		t.Fatal("mode change not reverted")
	}
	for _, gone := range []string{"src/new.go", "run.sh"} {
		if pathExists(filepath.Join(e.project, gone)) {
			t.Fatalf("%s created during the session survived undo", gone)
		}
	}
	if readFile(t, e.project, "build/out.log") != "ignored output\n" || readFile(t, e.project, "build/cache.bin") != "ignored before\n" {
		t.Fatal("ignored files must be left alone")
	}
	// The session's version is recoverable from the project repository.
	if got := e.git(e.project, "show", "refs/defenseclaw/post/s1:README.md"); got != "rewritten by the agent" {
		t.Fatalf("post-session state = %q", got)
	}
	// A second undo is a no-op and keeps the saved session state.
	again := mustUndo(t, e, "s1", false)
	if !again.Empty() || again.PostCommit != res.PostCommit {
		t.Fatalf("second undo: %+v", again)
	}
}

func TestUndoRestoresBranchHeadRefsAndStagingArea(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "tag", "v1")
	writeFile(t, e.project, "staged.txt", "staged\n")
	e.git(e.project, "add", "staged.txt")
	before := e.git(e.project, "rev-parse", "HEAD")
	mustSnapshot(t, e, "s1")

	e.git(e.project, "commit", "-q", "-m", "agent commit on main")
	e.git(e.project, "checkout", "-q", "-b", "feature")
	writeFile(t, e.project, "feature.txt", "x\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "feature")
	e.git(e.project, "tag", "-d", "v1")
	e.git(e.project, "tag", "agent-tag")

	preview := mustUndo(t, e, "s1", true)
	if preview.BranchBefore != "refs/heads/main" || preview.BranchAfter != "refs/heads/feature" || preview.HeadBefore != before {
		t.Fatalf("head/branch preview: %+v", preview)
	}
	var refs []string
	for _, c := range preview.RefChanges {
		refs = append(refs, c.Ref)
	}
	if strings.Join(refs, ",") != "refs/heads/feature,refs/heads/main,refs/tags/agent-tag,refs/tags/v1" {
		t.Fatalf("ref changes = %v", refs)
	}

	res := mustUndo(t, e, "s1", false)
	if got := e.git(e.project, "symbolic-ref", "HEAD"); got != "refs/heads/main" {
		t.Fatalf("HEAD = %s", got)
	}
	if got := e.git(e.project, "rev-parse", "HEAD"); got != before {
		t.Fatalf("main = %s, want %s", got, before)
	}
	if out := e.git(e.project, "branch", "--list", "feature"); out != "" {
		t.Fatalf("feature branch survived: %q", out)
	}
	if e.git(e.project, "tag", "--list") != "v1" {
		t.Fatalf("tags = %q", e.git(e.project, "tag", "--list"))
	}
	if !res.IndexRestored || e.git(e.project, "diff", "--cached", "--name-only") != "staged.txt" {
		t.Fatalf("staging area not restored (restored=%v, cached=%q)", res.IndexRestored, e.git(e.project, "diff", "--cached", "--name-only"))
	}
	if pathExists(filepath.Join(e.project, "feature.txt")) {
		t.Fatal("feature.txt survived")
	}
	if st := e.git(e.project, "status", "--porcelain"); st != "A  staged.txt" {
		t.Fatalf("status after undo = %q", st)
	}
}

func TestUndoKeepRefsLeavesBranches(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	writeFile(t, e.project, "x.txt", "x\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "agent")
	head := e.git(e.project, "rev-parse", "HEAD")
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1", KeepRefs: true}); err != nil {
		t.Fatal(err)
	}
	if e.git(e.project, "rev-parse", "HEAD") != head {
		t.Fatal("KeepRefs moved the branch")
	}
	if pathExists(filepath.Join(e.project, "x.txt")) {
		t.Fatal("working tree not restored")
	}
}

func TestUndoDetachedAndUnbornHead(t *testing.T) {
	t.Run("detached", func(t *testing.T) {
		e := newEnv(t)
		e.initRepo()
		head := e.git(e.project, "rev-parse", "HEAD")
		e.git(e.project, "checkout", "-q", "--detach")
		mustSnapshot(t, e, "s1")
		e.git(e.project, "checkout", "-q", "main")
		writeFile(t, e.project, "y", "y")
		e.git(e.project, "add", "-A")
		e.git(e.project, "commit", "-q", "-m", "y")
		mustUndo(t, e, "s1", false)
		if out, err := runGitMaybe(e, "symbolic-ref", "-q", "HEAD"); err == nil {
			t.Fatalf("HEAD should be detached, is %s", out)
		}
		if e.git(e.project, "rev-parse", "HEAD") != head || e.git(e.project, "rev-parse", "main") != head {
			t.Fatal("detached HEAD or main not restored")
		}
	})
	t.Run("unborn", func(t *testing.T) {
		e := newEnv(t)
		e.git(e.project, "init", "-q", "-b", "main")
		writeFile(t, e.project, "draft.txt", "draft\n")
		rec := mustSnapshot(t, e, "s1")
		if rec.Git.Head != "" || rec.Git.Branch != "refs/heads/main" {
			t.Fatalf("unborn record: %+v", rec.Git)
		}
		writeFile(t, e.project, "draft.txt", "agent\n")
		e.git(e.project, "add", "-A")
		e.git(e.project, "commit", "-q", "-m", "first")
		mustUndo(t, e, "s1", false)
		if _, err := runGitMaybe(e, "rev-parse", "-q", "--verify", "HEAD"); err == nil {
			t.Fatal("branch should be unborn again")
		}
		if readFile(t, e.project, "draft.txt") != "draft\n" {
			t.Fatal("draft not restored")
		}
	})
}

func runGitMaybe(e *env, args ...string) (string, error) {
	e.t.Helper()
	cmd := gitCmd{dir: e.project}
	out, err := cmd.strict(bg, args...)
	return strings.TrimSpace(string(out)), err
}

func TestUndoRestoresControlFilesAndRemovesNestedRepos(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustMkdir(t, filepath.Join(e.project, "vendor", "lib"))
	writeFile(t, e.project, "vendor/lib/keep.txt", "keep\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "vendor")
	mustSnapshot(t, e, "s1")

	// Planted git state.
	writeFile(t, e.project, ".git/info/attributes", "* filter=evil\n")
	evil := filepath.Join(e.project, "evil")
	e.git(e.project, "init", "-q", evil)
	writeFile(t, evil, "e.txt", "e")
	e.git(evil, "add", "-A")
	e.git(evil, "commit", "-q", "-m", "e")
	e.git(evil, "config", "core.fsmonitor", "touch "+filepath.Join(e.root, "PWNED"))
	e.git(e.project, "add", "evil")
	e.git(filepath.Join(e.project, "vendor", "lib"), "init", "-q")

	preview := mustUndo(t, e, "s1", true)
	if strings.Join(preview.ControlChanges, ",") != "info/attributes" {
		t.Fatalf("control changes = %v", preview.ControlChanges)
	}
	if strings.Join(preview.NestedRepos, ",") != "evil,vendor/lib" {
		t.Fatalf("nested repos = %v", preview.NestedRepos)
	}
	mustUndo(t, e, "s1", false)
	if pathExists(filepath.Join(e.project, ".git", "info", "attributes")) {
		t.Fatal("planted info/attributes survived")
	}
	if pathExists(evil) {
		t.Fatal("nested repository created during the session survived")
	}
	if pathExists(filepath.Join(e.project, "vendor", "lib", ".git")) || !pathExists(filepath.Join(e.project, "vendor", "lib", "keep.txt")) {
		t.Fatal("a pre-existing directory must keep its files and lose only the planted .git")
	}
	if pathExists(filepath.Join(e.root, "PWNED")) {
		t.Fatal("DefenseClaw's own git commands ran the planted fsmonitor")
	}
}

func TestUndoRemovesFilesHiddenByChangedIgnoreRules(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "build/keep.o", "ignored before the session\n")
	mustSnapshot(t, e, "s1")
	// The agent drops a payload and hides it from git.
	writeFileMode(t, e.project, "tools/evil.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\ntools/\n")
	writeFile(t, e.project, "out.log", "ignored output\n")

	res := mustUndo(t, e, "s1", false)
	if strings.Join(res.HiddenRemoved, ",") != "tools/evil.sh" {
		t.Fatalf("HiddenRemoved = %v", res.HiddenRemoved)
	}
	if pathExists(filepath.Join(e.project, "tools")) {
		t.Fatal("hidden payload survived undo")
	}
	if readFile(t, e.project, ".gitignore") != "*.log\nbuild/\n.env\n" {
		t.Fatal(".gitignore not restored")
	}
	if !pathExists(filepath.Join(e.project, "out.log")) || !pathExists(filepath.Join(e.project, "build", "keep.o")) {
		t.Fatal("files ignored under the pre-session rules must stay")
	}
}

func TestUndoRecoversDeletedObjects(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "gc", "-q")
	head := e.git(e.project, "rev-parse", "HEAD")
	rec := mustSnapshot(t, e, "s1")
	if !rec.Git.ObjectsCopied {
		t.Fatalf("the snapshot did not copy the project's objects: %v", rec.Warnings)
	}
	// The agent wipes the object store.
	for _, dir := range []string{"pack"} {
		entries, _ := os.ReadDir(filepath.Join(e.project, ".git", "objects", dir))
		for _, en := range entries {
			_ = os.Remove(filepath.Join(e.project, ".git", "objects", dir, en.Name()))
		}
	}
	writeFile(t, e.project, "README.md", "changed\n")
	preview := mustUndo(t, e, "s1", true)
	if len(preview.LostObjects) == 0 {
		t.Fatal("lost objects not detected")
	}
	mustUndo(t, e, "s1", false)
	if e.git(e.project, "rev-parse", "HEAD^{commit}") != head || e.git(e.project, "cat-file", "-p", "HEAD:README.md") != "hello" {
		t.Fatal("history not recovered")
	}
	if readFile(t, e.project, "README.md") != "hello\n" {
		t.Fatal("working tree not restored")
	}
}

func TestUndoRefusesReplacedGitDir(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	if err := os.Rename(filepath.Join(e.project, ".git"), filepath.Join(e.project, ".git-old")); err != nil {
		t.Fatal(err)
	}
	e.git(e.project, "init", "-q")
	_, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1"})
	if !errors.Is(err, ErrGitDirReplaced) {
		t.Fatalf("err = %v, want ErrGitDirReplaced", err)
	}
	rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "s1", Scanners: []ContentScanner{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Flags) == 0 || rep.Flags[0].Kind != RiskGitControl || rep.Flags[0].Severity != SeverityCritical {
		t.Fatalf("review flags = %+v", rep.Flags)
	}
}

func TestUndoDoesNotFollowPlantedSymlinks(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	outside := filepath.Join(e.root, "outside")
	mustMkdir(t, outside)
	mustSnapshot(t, e, "s1")
	if err := os.RemoveAll(filepath.Join(e.project, "src")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.project, "src")); err != nil {
		t.Fatal(err)
	}
	// Also plant a symlinked .git/info so control-file restores cannot be
	// redirected either.
	writeFile(t, e.project, ".git/info/grafts", "")
	mustUndo(t, e, "s1", false)
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("undo wrote outside the project: %v", entries)
	}
	info, err := os.Lstat(filepath.Join(e.project, "src"))
	if err != nil || !info.IsDir() || readFile(t, e.project, "src/app.go") != "package main\n" {
		t.Fatal("src not restored as a directory")
	}
}

func TestSnapshotExistsAndReplace(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	if _, err := Snapshot(bg, e.snapOpts("s1")); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("err = %v", err)
	}
	writeFile(t, e.project, "README.md", "kept\n")
	opts := e.snapOpts("s1")
	opts.Replace = true
	if _, err := Snapshot(bg, opts); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "README.md", "agent\n")
	mustUndo(t, e, "s1", false)
	if readFile(t, e.project, "README.md") != "kept\n" {
		t.Fatal("replaced snapshot not used")
	}
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "nope"}); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteSnapshotRemovesRefsAndShadow(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	a := mustSnapshot(t, e, "a")
	mustSnapshot(t, e, "b")
	if err := DeleteSnapshot(bg, e.data, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := runGitMaybe(e, "rev-parse", "-q", "--verify", "refs/defenseclaw/pre/a"); err == nil {
		t.Fatal("project ref for a survived")
	}
	if !pathExists(a.Git.Shadow) {
		t.Fatal("shadow removed while b still uses it")
	}
	if err := DeleteSnapshot(bg, e.data, "b"); err != nil {
		t.Fatal(err)
	}
	if pathExists(a.Git.Shadow) {
		t.Fatal("shadow survived its last snapshot")
	}
	recs, err := ListSnapshots(e.data)
	if err != nil || len(recs) != 0 {
		t.Fatalf("ListSnapshots = %v, %v", recs, err)
	}
}

func TestPlainSnapshotUndo(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "doc.md", "one\ntwo\n")
	writeFileMode(t, e.project, "bin/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "docs/guide.md", "guide\n")
	writeFile(t, e.project, ".env", "SECRET=1\n")
	writeFile(t, e.project, "node_modules/x/index.js", "x\n")
	if err := os.Symlink("doc.md", filepath.Join(e.project, "link")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(e.root, "outside")
	mustMkdir(t, outside)
	opts := e.snapOpts("p1")
	opts.Skip = []string{".env"}
	rec, err := Snapshot(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != SnapshotCopy || rec.Copy.Files != 3 || strings.Join(rec.Copy.Opaque, ",") != "node_modules" {
		t.Fatalf("record: %+v", rec.Copy)
	}
	if pathExists(filepath.Join(rec.Copy.Dir, ".env")) {
		t.Fatal("masked secret copied into the snapshot")
	}

	writeFile(t, e.project, "doc.md", "one\nthree\nfour\n")
	if err := os.Chmod(filepath.Join(e.project, "bin", "tool"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "new/deep/file.txt", "n\n")
	if err := os.Remove(filepath.Join(e.project, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(e.project, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(e.project, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.project, "docs")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "node_modules/x/index.js", "changed\n")

	preview := mustUndo(t, e, "p1", true)
	if got := changePaths(preview.Changes); got != "A:new A:new/deep/file.txt D:docs/guide.md M:bin/tool M:doc.md M:link T:docs" {
		t.Fatalf("preview = %s", got)
	}
	for _, c := range preview.Changes {
		if c.Path == "doc.md" && (c.Added != 2 || c.Deleted != 1) {
			t.Fatalf("doc.md delta = +%d -%d", c.Added, c.Deleted)
		}
	}
	mustUndo(t, e, "p1", false)
	if readFile(t, e.project, "doc.md") != "one\ntwo\n" || readFile(t, e.project, "docs/guide.md") != "guide\n" {
		t.Fatal("files not restored")
	}
	if info, _ := os.Stat(filepath.Join(e.project, "bin", "tool")); info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if target, _ := os.Readlink(filepath.Join(e.project, "link")); target != "doc.md" {
		t.Fatalf("link -> %s", target)
	}
	if pathExists(filepath.Join(e.project, "new")) {
		t.Fatal("created tree survived")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("restore followed the planted docs symlink")
	}
	if readFile(t, e.project, ".env") != "SECRET=1\n" || readFile(t, e.project, "node_modules/x/index.js") != "changed\n" {
		t.Fatal("skipped and opaque paths must be left alone")
	}
}

func TestPlainSnapshotEntryLimit(t *testing.T) {
	e := newEnv(t)
	for _, rel := range []string{"a.txt", "b.txt", "c.txt", "d/e.txt", "d/f.txt"} {
		writeFile(t, e.project, rel, rel+"\n")
	}
	// Six entries (five files, one directory): a walk that stops at five
	// must not become a snapshot of part of the folder.
	opts := e.snapOpts("p1")
	opts.MaxWalkEntries = 5
	_, err := Snapshot(bg, opts)
	var tl *TooLargeError
	if !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || !tl.Entries || tl.Limit != 5 {
		t.Fatalf("err = %v", err)
	}
	if pathExists(filepath.Join(e.data, "snapshots", "p1")) {
		t.Fatal("refused snapshot left data behind")
	}

	opts.MaxWalkEntries = 8
	rec, err := Snapshot(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Copy.Files != 5 || rec.Copy.MaxEntries != 8 {
		t.Fatalf("record: %+v", rec.Copy)
	}
	// Review and Undo read the folder under the snapshot's limit. Once the
	// session grows it past that, they refuse instead of comparing a
	// partial listing (which would call the unread files deleted and keep
	// what was created among them).
	for _, rel := range []string{"g.txt", "h.txt", "i.txt"} {
		writeFile(t, e.project, rel, "created in the session\n")
	}
	if _, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "p1", Scanners: []ContentScanner{}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("review: %v", err)
	}
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "p1"}); !errors.As(err, &tl) || !tl.Entries {
		t.Fatalf("undo: %v", err)
	}
	for _, rel := range []string{"a.txt", "d/f.txt", "g.txt", "i.txt"} {
		if !pathExists(filepath.Join(e.project, filepath.FromSlash(rel))) {
			t.Fatalf("refused undo changed the folder: %s is gone", rel)
		}
	}
	// Back under the limit, undo works again.
	if err := os.Remove(filepath.Join(e.project, "i.txt")); err != nil {
		t.Fatal(err)
	}
	if got := changePaths(mustUndo(t, e, "p1", false).Changes); got != "A:g.txt A:h.txt" {
		t.Fatalf("undo changes = %s", got)
	}
	if pathExists(filepath.Join(e.project, "g.txt")) || readFile(t, e.project, "d/f.txt") != "d/f.txt\n" {
		t.Fatal("undo did not restore the folder")
	}
}

func TestPlainSnapshotSizeCap(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "big.bin", strings.Repeat("x", 4096))
	opts := e.snapOpts("p1")
	opts.MaxCopyBytes = 1024
	_, err := Snapshot(bg, opts)
	var tl *TooLargeError
	if !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || tl.Size <= 1024 {
		t.Fatalf("err = %v", err)
	}
	if pathExists(filepath.Join(e.data, "snapshots", "p1")) {
		t.Fatal("failed snapshot left data behind")
	}
}

// TestUndoPreservesIgnoredDirectoryWithNestedRepo tests p1a-19: when the
// agent plants a .git marker inside an ignored directory that existed before
// the session, undo must only remove the .git entry, not the whole directory.
func TestUndoPreservesIgnoredDirectoryWithNestedRepo(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	// Pre-session: an ignored directory with operator files.
	writeFile(t, e.project, "build/data.json", "operator marker data\n")
	writeFile(t, e.project, "build/cache.bin", "operator marker cache\n")
	mustSnapshot(t, e, "s1")

	// Session: agent creates .git inside the ignored directory.
	writeFile(t, e.project, "build/.git/config", "[core]\n")
	writeFile(t, e.project, "build/.git/HEAD", "ref: refs/heads/main\n")

	preview := mustUndo(t, e, "s1", true)
	if len(preview.NestedRepos) != 1 || preview.NestedRepos[0] != "build" {
		t.Fatalf("nested repos = %v", preview.NestedRepos)
	}

	mustUndo(t, e, "s1", false)
	// The .git entry should be removed, but operator files kept.
	if pathExists(filepath.Join(e.project, "build/.git")) {
		t.Fatal("nested .git survived undo")
	}
	if readFile(t, e.project, "build/data.json") != "operator marker data\n" {
		t.Fatal("pre-existing ignored file was lost")
	}
	if readFile(t, e.project, "build/cache.bin") != "operator marker cache\n" {
		t.Fatal("pre-existing ignored file was lost")
	}
}

// TestUndoPreservesIgnoredFilesWhenIgnoreRuleRemoved tests p1a-21: when a
// file was ignored before the session and the agent removes its ignore rule,
// undo must keep the pre-existing file.
func TestUndoPreservesIgnoredFilesWhenIgnoreRuleRemoved(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	// Pre-session: ignored files exist.
	writeFile(t, e.project, ".env", "SECRET=operator marker value\n")
	writeFile(t, e.project, "debug.log", "operator marker log\n")
	writeFile(t, e.project, "build/output.bin", "operator marker output\n")
	mustSnapshot(t, e, "s1")

	// Session: agent removes .env and *.log from .gitignore.
	writeFile(t, e.project, ".gitignore", "build/\n")

	preview := mustUndo(t, e, "s1", true)
	// The ignored files should not appear as "A" (added).
	for _, c := range preview.Changes {
		if c.Path == ".env" || c.Path == "debug.log" {
			t.Fatalf("pre-session ignored file %s reported as %s", c.Path, c.Status)
		}
	}

	mustUndo(t, e, "s1", false)
	// The pre-session ignored files must survive.
	if readFile(t, e.project, ".env") != "SECRET=operator marker value\n" {
		t.Fatal("pre-existing .env was removed")
	}
	if readFile(t, e.project, "debug.log") != "operator marker log\n" {
		t.Fatal("pre-existing debug.log was removed")
	}
	if readFile(t, e.project, "build/output.bin") != "operator marker output\n" {
		t.Fatal("pre-existing build/output.bin was removed")
	}
}

// TestUndoSavesPostSessionRefTips tests p1a-22: before resetting branches
// and tags, undo must save the post-session tips so they are recoverable.
func TestUndoSavesPostSessionRefTips(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "tag", "v1")
	hostBranch := e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "branch", "feature")
	mustSnapshot(t, e, "s1")

	// Session: agent creates commits, moves branches and tags.
	writeFile(t, e.project, "agent.txt", "agent marker commit\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "agent commit on main")
	agentMainTip := e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "checkout", "-q", "feature")
	writeFile(t, e.project, "feature.txt", "agent marker feature\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "agent feature commit")
	agentFeatureTip := e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "tag", "-d", "v1")
	e.git(e.project, "tag", "agent-tag")
	agentTagTip := e.git(e.project, "rev-parse", "agent-tag")

	mustUndo(t, e, "s1", false)
	// The pre-session state should be restored.
	if e.git(e.project, "rev-parse", "HEAD") != hostBranch {
		t.Fatal("HEAD not restored")
	}
	if e.git(e.project, "rev-parse", "refs/tags/v1") != hostBranch {
		t.Fatal("v1 tag not restored")
	}
	// But the agent's work must be saved under refs/defenseclaw/post-refs/.
	if got := e.git(e.project, "rev-parse", "refs/defenseclaw/post-refs/s1/refs/heads/main"); got != agentMainTip {
		t.Fatalf("agent's main tip not saved: got %s, want %s", got, agentMainTip)
	}
	if got := e.git(e.project, "rev-parse", "refs/defenseclaw/post-refs/s1/refs/heads/feature"); got != agentFeatureTip {
		t.Fatalf("agent's feature tip not saved: got %s, want %s", got, agentFeatureTip)
	}
	if got := e.git(e.project, "rev-parse", "refs/defenseclaw/post-refs/s1/refs/tags/agent-tag"); got != agentTagTip {
		t.Fatalf("agent's tag not saved: got %s, want %s", got, agentTagTip)
	}
	// The pre-session feature branch must also be saved (it existed but was not changed).
	if got := e.git(e.project, "rev-parse", "refs/defenseclaw/post-refs/s1/refs/heads/feature"); got != agentFeatureTip {
		t.Fatalf("pre-session feature tip not saved")
	}
}
