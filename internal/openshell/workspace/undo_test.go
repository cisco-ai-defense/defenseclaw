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
	"time"
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
	e.lastSnapshot = rec
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

// savedRefsID returns the undo id of the refs/defenseclaw/post-refs/<name>/
// namespace the undo's recovery hint names.
func savedRefsID(t *testing.T, res *UndoResult, name string) string {
	t.Helper()
	prefix := "refs/defenseclaw/post-refs/" + name + "/"
	for _, w := range res.Warnings {
		if _, rest, ok := strings.Cut(w, prefix); ok && strings.Contains(w, "git branch <new-name>") {
			return strings.Split(rest, "/")[0]
		}
	}
	t.Fatalf("no recovery hint for %s in %v", prefix, res.Warnings)
	return ""
}

func TestSnapshotUndoRestoresTrackedAndUntrackedFiles(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "notes.txt", "untracked before the session\n")
	writeFile(t, e.project, "src/app.go", "package main // uncommitted edit\n")
	writeFile(t, e.project, "build/cache.bin", "ignored before\n")
	rec := mustSnapshot(t, e, "s1")
	if rec.Kind != SnapshotGit || rec.Git.Head == "" || rec.Git.Branch != "refs/heads/main" ||
		!rec.Git.ProjectRef || e.git(e.project, "rev-parse", "refs/defenseclaw/pre/s1") != rec.Git.Commit {
		t.Fatalf("record: %+v", rec.Git)
	}

	// The session.
	writeFile(t, e.project, "README.md", "rewritten by the agent\n")
	mustRemove(t, e.project, "notes.txt")
	writeFile(t, e.project, "src/new.go", "package main\n")
	writeFileMode(t, e.project, "run.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "build/out.log", "ignored output\n")
	mustChmod(t, filepath.Join(e.project, "src", "app.go"), 0o755)

	preview := mustUndo(t, e, "s1", true)
	if got := changePaths(preview.Changes); got != "A:run.sh A:src/new.go D:notes.txt M:README.md M:src/app.go" {
		t.Fatalf("preview changes = %s", got)
	}
	wantFiles(t, e.project, "README.md", "rewritten by the agent\n")
	res := mustUndo(t, e, "s1", false)
	wantFiles(t, e.project, "README.md", "hello\n", "notes.txt", "untracked before the session\n",
		"src/app.go", "package main // uncommitted edit\n", "src/new.go", absent, "run.sh", absent,
		// Ignored files are left alone.
		"build/out.log", "ignored output\n", "build/cache.bin", "ignored before\n")
	wantMode(t, e.project, "src/app.go", 0o644)
	// The session's version is recoverable from the project repository.
	if res.PostCommit == "" || e.git(e.project, "show", "refs/defenseclaw/post/s1:README.md") != "rewritten by the agent" {
		t.Fatalf("post-session state not kept: %+v", res)
	}
	// A second undo is a no-op and keeps the saved session state.
	if again := mustUndo(t, e, "s1", false); !again.Empty() || again.PostCommit != res.PostCommit {
		t.Fatalf("second undo: %+v", again)
	}
}

// TestUndoRestoresBranchesTagsAndStagingArea: undo puts HEAD, branches,
// tags and the staging area back, and first saves the tips the session
// left under refs/defenseclaw/post-refs/<name>/<undo-id>/, so its branch
// work stays recoverable.
func TestUndoRestoresBranchesTagsAndStagingArea(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "tag", "v1")
	e.git(e.project, "branch", "topic")
	writeFile(t, e.project, "staged.txt", "staged\n")
	e.git(e.project, "add", "staged.txt")
	before := e.git(e.project, "rev-parse", "HEAD")
	mustSnapshot(t, e, "s1")

	e.git(e.project, "commit", "-q", "-m", "agent commit on main")
	tips := map[string]string{"refs/heads/main": e.git(e.project, "rev-parse", "HEAD")}
	e.git(e.project, "checkout", "-q", "topic")
	writeFile(t, e.project, "topic.txt", "agent marker topic\n")
	e.commit("agent topic commit")
	tips["refs/heads/topic"] = e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "checkout", "-q", "-b", "feature")
	writeFile(t, e.project, "feature.txt", "x\n")
	e.commit("feature")
	tips["refs/heads/feature"] = e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "tag", "-d", "v1")
	e.git(e.project, "tag", "agent-tag")
	tips["refs/tags/agent-tag"] = tips["refs/heads/feature"]

	preview := mustUndo(t, e, "s1", true)
	if preview.BranchBefore != "refs/heads/main" || preview.BranchAfter != "refs/heads/feature" || preview.HeadBefore != before {
		t.Fatalf("head/branch preview: %+v", preview)
	}
	var refs []string
	for _, c := range preview.RefChanges {
		refs = append(refs, c.Ref)
	}
	if strings.Join(refs, ",") != "refs/heads/feature,refs/heads/main,refs/heads/topic,refs/tags/agent-tag,refs/tags/v1" {
		t.Fatalf("ref changes = %v", refs)
	}

	res := mustUndo(t, e, "s1", false)
	if e.git(e.project, "symbolic-ref", "HEAD") != "refs/heads/main" || e.git(e.project, "rev-parse", "HEAD") != before ||
		e.git(e.project, "rev-parse", "topic") != before {
		t.Fatal("HEAD, main or topic not restored")
	}
	if out := e.git(e.project, "branch", "--list", "feature"); out != "" || e.git(e.project, "tag", "--list") != "v1" {
		t.Fatalf("feature branch %q or tags %q survived", out, e.git(e.project, "tag", "--list"))
	}
	if st := e.git(e.project, "status", "--porcelain"); !res.IndexRestored || st != "A  staged.txt" {
		t.Fatalf("staging area not restored (restored=%v, status %q)", res.IndexRestored, st)
	}
	wantFiles(t, e.project, "feature.txt", absent, "topic.txt", absent)
	prefix := "refs/defenseclaw/post-refs/s1/" + savedRefsID(t, res, "s1") + "/"
	for ref, tip := range tips {
		if got := e.git(e.project, "rev-parse", prefix+ref); got != tip {
			t.Errorf("the session's %s tip is not saved: got %s, want %s", ref, got, tip)
		}
	}
}

// TestSnapshotLifecycle: two undos of one name save the session tips under
// different namespaces, and KeepRefs restores the files alone. A second
// snapshot of a name is refused unless it replaces the first, which keeps
// the saved tips (the only copy of an earlier session's branch work) and
// is what undo then restores. Deleting a snapshot removes its project ref
// and saved tips, but neither those of a sandbox whose name starts the
// same nor the shadow another snapshot still uses.
func TestSnapshotLifecycle(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	initial := e.git(e.project, "rev-parse", "HEAD")
	mustSnapshot(t, e, "s1")
	other := mustSnapshot(t, e, "b")
	var ids []string
	for _, f := range []string{"v1.txt", "v2.txt"} {
		writeFile(t, e.project, f, f+"\n")
		e.commit(f)
		tip := e.git(e.project, "rev-parse", "HEAD")
		res := mustUndo(t, e, "s1", false)
		id := savedRefsID(t, res, "s1")
		if e.git(e.project, "rev-parse", "HEAD") != initial || e.git(e.project, "rev-parse", "refs/defenseclaw/post-refs/s1/"+id+"/refs/heads/main") != tip {
			t.Fatalf("undo %s: HEAD not restored or session tip not saved", f)
		}
		ids = append(ids, id)
	}
	if ids[0] == ids[1] {
		t.Fatalf("both undos used the same id %s", ids[0])
	}
	writeFile(t, e.project, "x.txt", "x\n")
	e.commit("agent")
	head := e.git(e.project, "rev-parse", "HEAD")
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1", KeepRefs: true}); err != nil || e.git(e.project, "rev-parse", "HEAD") != head {
		t.Fatalf("KeepRefs undo = %v, or it moved the branch", err)
	}
	wantFiles(t, e.project, "x.txt", absent)

	if _, err := Snapshot(bg, e.snapOpts("s1")); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("err = %v", err)
	}
	saved := func(name string) string {
		return e.git(e.project, "for-each-ref", "--format=%(refname)", "refs/defenseclaw/post-refs/"+name+"/")
	}
	writeFile(t, e.project, "README.md", "kept\n")
	opts := e.snapOpts("s1")
	opts.Replace = true
	if _, err := Snapshot(bg, opts); err != nil || saved("s1") == "" {
		t.Fatalf("replacing the snapshot (%v) dropped the saved branch tips", err)
	}
	writeFile(t, e.project, "README.md", "agent\n")
	mustUndo(t, e, "s1", false)
	wantFiles(t, e.project, "README.md", "kept\n")
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "nope"}); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("err = %v", err)
	}

	e.git(e.project, "update-ref", "refs/defenseclaw/post-refs/s10/x/refs/heads/main", "HEAD")
	must(t, DeleteSnapshot(bg, e.data, "s1"))
	if _, err := runGitMaybe(e, "rev-parse", "-q", "--verify", "refs/defenseclaw/pre/s1"); err == nil || saved("s1") != "" || saved("s10") == "" {
		t.Fatalf("after deleting s1: pre ref kept (%v), s1 refs %q, s10 refs %q", err, saved("s1"), saved("s10"))
	}
	if !pathExists(other.Git.Shadow) {
		t.Fatal("the shadow went while b still uses it")
	}
	if err := DeleteSnapshot(bg, e.data, "b"); err != nil || pathExists(other.Git.Shadow) {
		t.Fatalf("delete b = %v; the shadow must go with its last snapshot", err)
	}
	if recs, err := ListSnapshots(e.data); err != nil || len(recs) != 0 {
		t.Fatalf("ListSnapshots = %v, %v", recs, err)
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
		e.commit("y")
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
		if rec := mustSnapshot(t, e, "s1"); rec.Git.Head != "" || rec.Git.Branch != "refs/heads/main" {
			t.Fatalf("unborn record: %+v", rec.Git)
		}
		writeFile(t, e.project, "draft.txt", "agent\n")
		e.commit("first")
		mustUndo(t, e, "s1", false)
		if _, err := runGitMaybe(e, "rev-parse", "-q", "--verify", "HEAD"); err == nil {
			t.Fatal("branch should be unborn again")
		}
		wantFiles(t, e.project, "draft.txt", "draft\n")
	})
}

func runGitMaybe(e *env, args ...string) (string, error) {
	e.t.Helper()
	out, err := gitCmd{dir: e.project}.strict(bg, args...)
	return strings.TrimSpace(string(out)), err
}

// chmodT sets a test folder's mode and puts it back to 0755 at cleanup, so
// the temporary directory can be removed.
func chmodT(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	mustChmod(t, dir, mode)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// TestReviewAndUndoSeeFoldersMadeUnreadable: the sandbox runs as the
// operator's uid, so the agent can take read permission off a folder. No
// walk can list it, yet host git reads a .git inside it by path while
// search permission is left. Review flags the folder and that repository,
// and undo refuses until the folder is readable again; a folder that was
// already unreadable before the session is not the session's doing.
func TestReviewAndUndoSeeFoldersMadeUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can list every folder")
	}
	for _, git := range []bool{true, false} {
		t.Run(map[bool]string{true: "git", false: "plain"}[git], func(t *testing.T) {
			e := newEnv(t)
			if git {
				e.initRepo()
			} else {
				writeFile(t, e.project, "README.md", "hello\n")
			}
			mustMkdir(t, filepath.Join(e.project, "locked-before"))
			chmodT(t, filepath.Join(e.project, "locked-before"), 0o311)
			if rec := mustSnapshot(t, e, "s1"); strings.Join(rec.Unreadable, " ") != "locked-before" {
				t.Fatalf("snapshot unreadable = %v", rec.Unreadable)
			}

			// Session: a repository in a folder left with search and write
			// permission but no read permission.
			writeFile(t, e.project, "tools/.git/HEAD", "ref: refs/heads/main\n")
			writeFile(t, e.project, "tools/.git/config", "[core]\n")
			writeFile(t, e.project, "tools/notes.txt", "agent marker\n")
			chmodT(t, filepath.Join(e.project, "tools"), 0o311)

			rep := review(t, e, "s1", nil)
			if f, ok := flagByLabel(rep, "tools/"); !ok || f.Kind != RiskUnreadable || f.Severity != SeverityHigh {
				t.Fatalf("unreadable folder not flagged: %+v", rep.Flags)
			}
			if f, ok := flagByLabel(rep, "tools/.git"); !ok || f.Kind != RiskNestedRepo {
				t.Fatalf("repository in the unreadable folder not flagged: %+v", rep.Flags)
			}
			if _, ok := flagByLabel(rep, "locked-before/"); ok || !rep.Sensitive() {
				t.Fatalf("flags = %+v, sensitive %v", rep.Flags, rep.Sensitive())
			}
			for _, preview := range []bool{true, false} {
				_, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1", Preview: preview})
				var ue *UnreadableError
				if !errors.Is(err, ErrUnreadableFolders) || !errors.As(err, &ue) || strings.Join(ue.Dirs, " ") != "tools" {
					t.Fatalf("preview=%v: undo = %v, want it refused for tools", preview, err)
				}
			}
			// Readable again, undo takes out what the session put there.
			mustChmod(t, filepath.Join(e.project, "tools"), 0o755)
			mustUndo(t, e, "s1", false)
			wantFiles(t, e.project, "tools/.git", absent, "tools/notes.txt", absent)
		})
	}
}

func TestUndoRefusesReplacedGitDir(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	must(t, os.Rename(filepath.Join(e.project, ".git"), filepath.Join(e.project, ".git-old")))
	e.git(e.project, "init", "-q")
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1"}); !errors.Is(err, ErrGitDirReplaced) {
		t.Fatalf("err = %v, want ErrGitDirReplaced", err)
	}
	if rep := review(t, e, "s1", []ContentScanner{}); len(rep.Flags) == 0 || rep.Flags[0].Kind != RiskGitControl || rep.Flags[0].Severity != SeverityCritical {
		t.Fatalf("review flags = %+v", rep.Flags)
	}
}

func TestPlainSnapshotUndo(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "doc.md", "one\ntwo\n")
	writeFileMode(t, e.project, "bin/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "docs/guide.md", "guide\n")
	writeFile(t, e.project, ".env", "SECRET=1\n")
	writeFile(t, e.project, "node_modules/x/index.js", "x\n")
	mustSymlink(t, "doc.md", filepath.Join(e.project, "link"))
	outside := filepath.Join(e.root, "outside")
	mustMkdir(t, outside)
	opts := e.snapOpts("p1")
	opts.Skip = []string{".env"}
	rec, err := Snapshot(bg, opts)
	if err != nil || rec.Kind != SnapshotCopy || rec.Copy.Files != 3 || strings.Join(rec.Copy.Opaque, ",") != "node_modules" {
		t.Fatalf("record: %+v, %v", rec, err)
	}
	wantFiles(t, rec.Copy.Dir, ".env", absent) // a masked secret is not copied

	writeFile(t, e.project, "doc.md", "one\nthree\nfour\n")
	mustChmod(t, filepath.Join(e.project, "bin", "tool"), 0o644)
	writeFile(t, e.project, "new/deep/file.txt", "n\n")
	mustRemove(t, e.project, "link", "docs")
	mustSymlink(t, "/etc/passwd", filepath.Join(e.project, "link"))
	mustSymlink(t, outside, filepath.Join(e.project, "docs"))
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
	// Skipped and opaque paths are left alone.
	wantFiles(t, e.project, "doc.md", "one\ntwo\n", "docs/guide.md", "guide\n", "new", absent,
		".env", "SECRET=1\n", "node_modules/x/index.js", "changed\n")
	wantMode(t, e.project, "bin/tool", 0o755)
	if target, _ := os.Readlink(filepath.Join(e.project, "link")); target != "doc.md" {
		t.Fatalf("link -> %s", target)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("restore followed the planted docs symlink")
	}
}

// TestPlainSnapshotLimits: a plain folder past the size or entry limit is
// refused (nothing is left behind), not snapshotted in part; review and
// undo refuse a folder the session grew past the snapshot's entry limit
// instead of comparing a partial listing, which would call the unread
// files deleted and keep what was created among them.
func TestPlainSnapshotLimits(t *testing.T) {
	e := newEnv(t)
	for _, rel := range []string{"a.txt", "b.txt", "c.txt", "d/e.txt", "d/f.txt"} {
		writeFile(t, e.project, rel, rel+"\n")
	}
	var tl *TooLargeError
	opts := e.snapOpts("p1")
	opts.MaxCopyBytes = 10
	if _, err := Snapshot(bg, opts); !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || tl.Size <= 10 {
		t.Fatalf("size limit: %v", err)
	}
	// Six entries (five files, one directory).
	opts.MaxCopyBytes, opts.MaxWalkEntries = 0, 5
	if _, err := Snapshot(bg, opts); !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || !tl.Entries || tl.Limit != 5 {
		t.Fatalf("entry limit: %v", err)
	}
	wantFiles(t, e.data, "snapshots/p1", absent)
	opts.MaxWalkEntries = 8
	if rec, err := Snapshot(bg, opts); err != nil || rec.Copy.Files != 5 || rec.Copy.MaxEntries != 8 {
		t.Fatalf("record: %+v, %v", rec, err)
	}
	for _, rel := range []string{"g.txt", "h.txt", "i.txt"} {
		writeFile(t, e.project, rel, "created in the session\n")
	}
	if _, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "p1", Scanners: []ContentScanner{}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("review: %v", err)
	}
	if _, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "p1"}); !errors.As(err, &tl) || !tl.Entries {
		t.Fatalf("undo: %v", err)
	}
	wantFiles(t, e.project, "a.txt", present, "d/f.txt", present, "g.txt", present, "i.txt", present)
	// Back under the limit, undo works again.
	mustRemove(t, e.project, "i.txt")
	if got := changePaths(mustUndo(t, e, "p1", false).Changes); got != "A:g.txt A:h.txt" {
		t.Fatalf("undo changes = %s", got)
	}
	wantFiles(t, e.project, "g.txt", absent, "d/f.txt", "d/f.txt\n")
}

// TestUndoKeepsFilesIgnoredBeforeTheSession: files git ignored before the
// session stay exactly as they are (content, mode, size, modification
// time; a large one is never read into memory) when the agent removes
// their ignore rules. Git's own matching decides what was ignored (nested
// .gitignore files, negation, directory and anchored patterns). One the
// agent rewrote after dropping its rule is listed as a change undo cannot
// put back, and a .git planted in an ignored folder goes alone.
func TestUndoKeepsFilesIgnoredBeforeTheSession(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "*.log\n!important.log\n/secret.txt\ntmp/\nbuild/\n.env\nexecutable.sh\nlarge.dat\n")
	writeFile(t, e.project, "src/.gitignore", "*.bak\n!keep.bak\n/local-config.json\n")
	ignored := map[string]string{
		"debug.log": "operator marker log\n", "quiet.log": "operator marker untouched\n",
		"secret.txt": "operator marker secret\n", "tmp/cache.dat": "operator marker cache\n",
		"src/old.bak": "operator marker old\n", "src/local-config.json": "operator marker config\n",
		".env": "SECRET=operator marker value\n", "build/data.json": "operator marker data\n",
	}
	for rel, content := range ignored {
		writeFile(t, e.project, rel, content)
	}
	writeFileMode(t, e.project, "executable.sh", "#!/bin/sh\necho marker\n", 0o755)
	notIgnored := []string{"important.log", "data/secret.txt", "src/keep.bak", "src/sub/local-config.json"}
	for _, rel := range notIgnored {
		writeFile(t, e.project, rel, "tracked marker\n")
	}
	e.commit("tracked")
	// A sparse file above the old 128 MiB cap, marked at both ends.
	const size = 200 << 20
	large := filepath.Join(e.project, "large.dat")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	_, err1 := f.WriteAt([]byte("START"), 0)
	_, err2 := f.WriteAt([]byte("END"), size-3)
	must(t, errors.Join(err1, err2, f.Close()))
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)
	must(t, os.Chtimes(large, mtime, mtime))
	mustSnapshot(t, e, "s1")
	for _, rel := range notIgnored {
		if wasIgnored(rel, e.lastSnapshot.Git.Ignored) {
			t.Errorf("%s was not ignored before the session but is in the snapshot's ignored list", rel)
		}
	}

	// Session: the agent drops every rule but build/, rewrites one log and
	// plants a repository in the ignored build folder.
	writeFile(t, e.project, ".gitignore", "build/\n")
	writeFile(t, e.project, "src/.gitignore", "")
	writeFile(t, e.project, "debug.log", "agent marker rewritten content\n")
	writeFile(t, e.project, "build/.git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, e.project, "build/.git/config", "[core]\n")

	check := func(res *UndoResult, when string) {
		t.Helper()
		for _, c := range res.Changes {
			if _, ok := ignored[c.Path]; ok || c.Path == "executable.sh" || c.Path == "large.dat" {
				t.Fatalf("%s: pre-session ignored file %s reported as %s", when, c.Path, c.Status)
			}
		}
		if un := res.Unrestored(); len(un) != 1 || un[0].Path != "debug.log" || un[0].Modified != 1 {
			t.Fatalf("%s: unrestored = %+v, want debug.log modified", when, un)
		}
		if strings.Join(res.NestedRepos, ",") != "build" {
			t.Fatalf("%s: nested repos = %v", when, res.NestedRepos)
		}
		for _, w := range res.Warnings {
			if strings.Contains(w, "large.dat") || strings.Contains(w, "MB") {
				t.Fatalf("%s: unexpected warning: %s", when, w)
			}
		}
	}
	check(mustUndo(t, e, "s1", true), "preview")
	check(mustUndo(t, e, "s1", false), "undo")
	ignored["debug.log"] = "agent marker rewritten content\n"
	for rel, content := range ignored {
		wantFiles(t, e.project, rel, content)
	}
	wantFiles(t, e.project, ".gitignore", "*.log\n!important.log\n/secret.txt\ntmp/\nbuild/\n.env\nexecutable.sh\nlarge.dat\n",
		"src/.gitignore", "*.bak\n!keep.bak\n/local-config.json\n", "build/.git", absent)
	wantMode(t, e.project, "executable.sh", 0o755)
	wantMode(t, e.project, "secret.txt", 0o644)
	info, err := os.Stat(large)
	if err != nil || info.Size() != size || info.ModTime().Sub(mtime).Abs() > time.Second {
		t.Fatalf("large.dat = %v, %v; want %d bytes from %v", info, err, size, mtime)
	}
	f, err = os.Open(large)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start, end := make([]byte, 5), make([]byte, 3)
	_, err1 = f.ReadAt(start, 0)
	_, err2 = f.ReadAt(end, size-3)
	if err1 != nil || err2 != nil || string(start) != "START" || string(end) != "END" {
		t.Fatalf("large.dat content = %q...%q (%v, %v)", start, end, err1, err2)
	}
}

// TestRootFSRefusesSymlinkedParents checks the helpers undo uses to read
// preserved files: a parent directory that is a symlink is refused even when
// it points inside the root, and a path escaping the root never resolves.
func TestRootFSRefusesSymlinkedParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "secret.txt", "operator marker\n")
	writeFile(t, root, "real/keep.txt", "marker\n")
	mustSymlink(t, outside, filepath.Join(root, "out"))
	mustSymlink(t, filepath.Join(root, "real"), filepath.Join(root, "in"))
	r, err := openRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, rel := range []string{"out/secret.txt", "in/keep.txt"} {
		if err := r.realParents(rel); err == nil {
			t.Errorf("realParents(%q) = nil, want a symlink refusal", rel)
		}
	}
	if _, err := r.readRegular("out/secret.txt", 1<<20); err == nil {
		t.Error("readRegular read a file outside the root")
	}
	if err := r.realParents("real/keep.txt"); err != nil {
		t.Errorf("realParents(real/keep.txt) = %v", err)
	}
	if data, err := r.readRegular("real/keep.txt", 1<<20); err != nil || string(data) != "marker\n" {
		t.Errorf("readRegular(real/keep.txt) = %q, %v", data, err)
	}
	if _, err := r.readRegular("real/keep.txt", 3); err == nil {
		t.Error("readRegular ignored its size limit")
	}
}

// TestUndoRemovesPlantedGitStateAndHiddenFiles: undo restores the git
// control files and removes the repositories the session created (a
// folder that existed keeps its files and loses only the planted .git)
// without running the fsmonitor they carry, and removes files the agent
// hid behind new ignore rules while keeping those ignored under the
// pre-session rules.
func TestUndoRemovesPlantedGitStateAndHiddenFiles(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "vendor/lib/keep.txt", "keep\n")
	e.commit("vendor")
	writeFile(t, e.project, "build/keep.o", "ignored before the session\n")
	mustSnapshot(t, e, "s1")

	writeFile(t, e.project, ".git/info/attributes", "* filter=evil\n")
	evil := filepath.Join(e.project, "evil")
	e.git(e.project, "init", "-q", evil)
	writeFile(t, evil, "e.txt", "e")
	e.git(evil, "add", "-A")
	e.git(evil, "commit", "-q", "-m", "e")
	e.git(evil, "config", "core.fsmonitor", "touch "+filepath.Join(e.root, "PWNED"))
	e.git(e.project, "add", "evil")
	e.git(filepath.Join(e.project, "vendor", "lib"), "init", "-q")
	writeFileMode(t, e.project, "tools/evil.sh", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\ntools/\n")
	writeFile(t, e.project, "out.log", "ignored output\n")

	preview := mustUndo(t, e, "s1", true)
	if strings.Join(preview.ControlChanges, ",") != "info/attributes" || strings.Join(preview.NestedRepos, ",") != "evil,vendor/lib" {
		t.Fatalf("control changes = %v, nested repos = %v", preview.ControlChanges, preview.NestedRepos)
	}
	// The nested repository's files are hidden from the project's git too.
	if res := mustUndo(t, e, "s1", false); strings.Join(res.HiddenRemoved, ",") != "evil/e.txt,tools/evil.sh" {
		t.Fatalf("HiddenRemoved = %v", res.HiddenRemoved)
	}
	wantFiles(t, e.project, ".git/info/attributes", absent, "evil", absent, "vendor/lib/.git", absent, "vendor/lib/keep.txt", "keep\n",
		"tools", absent, ".gitignore", "*.log\nbuild/\n.env\n", "out.log", present, "build/keep.o", present)
	wantFiles(t, e.root, "PWNED", absent)
}

// TestUndoDoesNotFollowPlantedSymlinks: a folder the agent swapped for a
// symlink to a folder outside is put back as a folder without writing
// through the link. Git records a symlink that replaced the folder of an
// ignored file as a single entry and never lists paths below it, so undo
// removes that one without reading through it either: nothing outside the
// project changes, and nothing from there is copied in.
func TestUndoDoesNotFollowPlantedSymlinks(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "data/secret.txt\n")
	writeFile(t, e.project, "data/secret.txt", "operator marker\n")
	mustSnapshot(t, e, "s1")
	empty, full := filepath.Join(e.root, "outside"), filepath.Join(e.root, "outside-data")
	mustMkdir(t, empty)
	writeFile(t, full, "secret.txt", "operator marker\n")
	mustRemove(t, e.project, "src", "data")
	mustSymlink(t, empty, filepath.Join(e.project, "src"))
	mustSymlink(t, full, filepath.Join(e.project, "data"))
	writeFile(t, e.project, ".git/info/grafts", "")
	writeFile(t, e.project, ".gitignore", "")
	mustUndo(t, e, "s1", false)

	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatalf("undo wrote outside the project: %v", entries)
	}
	if entries, err := os.ReadDir(full); err != nil || len(entries) != 1 || entries[0].Name() != "secret.txt" {
		t.Errorf("outside directory entries = %v, %v; want only secret.txt", entries, err)
	}
	wantFiles(t, full, "secret.txt", "operator marker\n")
	if info, err := os.Lstat(filepath.Join(e.project, "src")); err != nil || !info.IsDir() {
		t.Fatal("src not restored as a directory")
	}
	if info, err := os.Lstat(filepath.Join(e.project, "data")); err == nil && info.Mode()&os.ModeSymlink != 0 {
		t.Error("undo left the session-created symlink in place")
	}
	wantFiles(t, e.project, "src/app.go", "package main\n", "data/secret.txt", absent)
}
