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
	"errors"
	"fmt"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cloneHereServer serves e.project's history over smart HTTP (git
// http-backend, partial clone allowed) and makes it the checkout's origin,
// with main tracking origin/main.
func cloneHereServer(t *testing.T, e *env) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	srv := filepath.Join(e.root, "srv")
	mustMkdir(t, srv)
	bare := filepath.Join(srv, "app.git")
	e.git(e.root, "clone", "-q", "--bare", e.project, bare)
	e.git(bare, "config", "uploadpack.allowFilter", "true")
	h := &cgi.Handler{Path: gitBin, Args: []string{"http-backend"}, InheritEnv: []string{"PATH"},
		Env: []string{"GIT_PROJECT_ROOT=" + srv, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + e.home}}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	url := ts.URL + "/app.git"
	e.git(e.project, "remote", "add", "origin", url)
	e.git(e.project, "fetch", "-q", "origin")
	e.git(e.project, "branch", "-q", "--set-upstream-to=origin/main", "main")
	return url
}

// B2 2.3: run --clone . ships only base..HEAD (secret blobs withheld) and
// the working tree; the sandbox fetches the rest of the branch's history
// from the remote, as a partial clone.
func TestCloneHereBundleWithholdsSecretBlobs(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	for i := 1; i <= 3; i++ {
		writeFile(t, e.project, "src/app.go", fmt.Sprintf("package main // %d\n", i))
		e.commit(fmt.Sprintf("pushed %d", i))
	}
	url := cloneHereServer(t, e)
	writeFile(t, e.project, ".env", "TOKEN=not-a-real-value\n")
	e.git(e.project, "add", "-f", ".env")
	writeFile(t, e.project, "src/app.go", "package main // local 1\n")
	e.commit("local 1")
	secretBlob := e.git(e.project, "rev-parse", "HEAD:.env")
	writeFile(t, e.project, "src/app.go", "package main // local 2\n")
	e.commit("local 2")
	writeFile(t, e.project, "README.md", "dirty\n")

	rec, fs := launchCopy(t, e, "here", func(o *StageOptions) { o.Upstream = true })
	up := rec.Upstream
	if up == nil || up.Remote != "origin" || up.URL != url || up.Branch != "main" || up.Commits != 2 || up.Changes != 1 {
		t.Fatalf("upstream = %+v", up)
	}
	dir := rec.RemoteDir
	if n := fs.agent(dir, "rev-list", "--count", "HEAD"); n != "3" {
		t.Fatalf("shipped %s commits, want the 2 unpushed ones and the base", n)
	}
	if _, err := FetchUpstream(bg, e.data, "here", fs); err != nil {
		t.Fatal(err)
	}
	if n := fs.agent(dir, "rev-list", "--count", "HEAD"); n != "6" {
		t.Fatalf("after the fetch the sandbox has %s commits, want the full 6", n)
	}
	if s := fs.agent(dir, "rev-parse", "--is-shallow-repository"); s != "false" {
		t.Fatalf("shallow after the fetch: %s", s)
	}
	if p := fs.agent(dir, "config", "remote.origin.promisor"); p != "true" {
		t.Fatalf("origin is not a promisor (partial clone): %q", p)
	}
	if got := fs.agent(dir, "rev-parse", "HEAD"); got != e.git(e.project, "rev-parse", "HEAD") {
		t.Fatalf("sandbox HEAD %s is not the checkout's", got)
	}
	if got := readFile(t, fs.local(dir), "README.md"); got != "dirty\n" {
		t.Fatalf("uncommitted change not in the copy: %q", got)
	}
	if _, err := os.Stat(filepath.Join(fs.local(dir), ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".env is in the copy's working tree: %v", err)
	}
	cmd := exec.Command("git", "--git-dir", fs.local(rec.RemoteGitDir), "cat-file", "-e", secretBlob)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "HOME="+e.home)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("the secret blob %s reached the sandbox: %s", secretBlob, out)
	}
	// The copy is a normal git copy: the agent commits on the full history
	// and pull brings the work back.
	fs.write(dir+"/src/app.go", "package main // agent\n")
	fs.agent(dir, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-qam", "agent")
	pull(t, e, fs, "here")
	if diff, err := PullDiff(bg, e.data, "here"); err != nil || !strings.Contains(diff, "+package main // agent") {
		t.Fatalf("diff = %q, %v", diff, err)
	}
}

func TestCloneHereNoCommonBaseRefused(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	other := filepath.Join(e.root, "other")
	mustMkdir(t, other)
	e.git(other, "init", "-q", "-b", "main")
	writeFile(t, other, "x.txt", "unrelated\n")
	e.git(other, "add", "-A")
	e.git(other, "commit", "-q", "-m", "unrelated")
	e.git(e.project, "remote", "add", "origin", "https://git.example.test/team/app.git")
	e.git(e.project, "fetch", "-q", other, "+main:refs/remotes/origin/main")
	const want = "this branch shares no commit with origin; use run without --clone ."
	if _, err := ResolveUpstream(bg, e.project, nil); err == nil || err.Error() != want {
		t.Fatalf("ResolveUpstream err = %v, want %q", err, want)
	}
	opts := e.stageOpts("nobase")
	opts.Upstream = true
	_, err := Stage(bg, opts)
	var refused *UpstreamError
	if !errors.As(err, &refused) || refused.Msg != want {
		t.Fatalf("Stage err = %v, want %q", err, want)
	}
}

func TestCloneHereRemoteRefused(t *testing.T) {
	for _, tc := range []struct{ name, url, sub, want string }{
		{"local path", "/srv/git/app.git", "", "remote origin is a local path; use run without --clone ."},
		{"file url", "file:///srv/git/app.git", "", "remote origin is a local path; use run without --clone ."},
		{"scp form", "git@git.example.test:team/app.git", "", "remote origin is an ssh address no https rewrite covers; ask your administrator to add it to substrate.git.https_rewrite"},
		{"http url", "http://git.example.test/team/app.git", "", "remote origin uses http://, which sends your git credentials unencrypted"},
		{"no remote", "", "", "this checkout has no remote origin; use run without --clone ."},
		{"subfolder", "https://git.example.test/team/app.git", "src", "not the top folder of a git checkout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.initRepo()
			if tc.url != "" {
				e.git(e.project, "remote", "add", "origin", tc.url)
			}
			_, err := ResolveUpstream(bg, filepath.Join(e.project, tc.sub), nil)
			var refused *UpstreamError
			if !errors.As(err, &refused) || !strings.Contains(refused.Msg, tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// B2 2.5: an scp-form or ssh remote a rewrite covers is cloned at its
// https address; one no rewrite covers is refused with the key to set.
func TestB2CloneHereSSHRemoteRewritten(t *testing.T) {
	toHTTPS := func(raw string) (string, bool) {
		if rest, ok := strings.CutPrefix(raw, "git@git.example.test:"); ok {
			return "https://git.example.test/" + rest, true
		}
		return "", false
	}
	for _, tc := range []struct{ url, want string }{
		{"git@git.example.test:team/app.git", "https://git.example.test/team/app.git"},
		{"git@other.example.test:team/app.git", ""},
	} {
		t.Run(tc.url, func(t *testing.T) {
			e := newEnv(t)
			e.initRepo()
			e.git(e.project, "remote", "add", "origin", tc.url)
			e.git(e.project, "update-ref", "refs/remotes/origin/HEAD", "HEAD")
			up, err := ResolveUpstream(bg, e.project, toHTTPS)
			switch {
			case tc.want != "" && (err != nil || up.URL != tc.want):
				t.Errorf("up %+v err %v, want %s", up, err, tc.want)
			case tc.want == "" && (err == nil || !strings.Contains(err.Error(), "substrate.git.https_rewrite")):
				t.Errorf("err %v, want the rewrite refusal", err)
			}
		})
	}
}
