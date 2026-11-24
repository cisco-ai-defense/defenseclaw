//go:build !windows

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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// localExec runs the actor scripts in a local shell (the relay exec runs
// them the same way in the actor).
func localExec(ctx context.Context, argv []string, dir string, env map[string]string, _ time.Duration) (string, string, int, error) {
	// The HTTPS fixture uses an explicit git command setting, and a file
	// repository: the scripts disable system and global config and allow
	// only https, so the fixture's git allows file too.
	if origin := os.Getenv("DC_TEST_PUSH_ORIGIN"); origin != "" && len(argv) >= 3 && argv[0] == "sh" && argv[1] == "-c" && strings.HasPrefix(argv[2], pushGit) {
		argv = append([]string(nil), argv...)
		fork := ""
		if os.Getenv("DC_TEST_PUSH_FORK") != "" {
			fork = ` -c "url.file://$DC_TEST_PUSH_FORK.insteadOf=https://git.example.test/team/fork.git"`
		}
		argv[2] = `git() { GIT_ALLOW_PROTOCOL=https:file command git -c "url.file://$DC_TEST_PUSH_ORIGIN.insteadOf=https://git.example.test/team/app.git"` + fork + ` "$@"; }` + "\n" + argv[2]
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), ee.ExitCode(), nil
	}
	return out.String(), errb.String(), 0, err
}

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// B2 2.4 (B2-07): pull --push-branch commits the agent's uncommitted work
// without moving its HEAD, flags a credential placeholder and CI files,
// pushes a new branch, refuses a branch someone else made, fast-forwards
// one it pushed, and never forces.
func TestB2PushBranchFromTheActor(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := t.TempDir()
	origin := filepath.Join(tmp, "origin.git")
	// The test executor maps HTTPS with an explicit -c setting.
	t.Setenv("DC_TEST_PUSH_ORIGIN", origin)
	gitT(t, tmp, "init", "-q", "--bare", origin)
	root := filepath.Join(tmp, "work")
	gitT(t, tmp, "clone", "-q", origin, root+"/app")
	repo := filepath.Join(root, "app")
	// The actor's origin is an https address; this checkout reads it as
	// the local bare repository.
	gitT(t, repo, "remote", "set-url", "origin", "https://git.example.test/team/app.git")
	gitT(t, repo, "config", "url.file://"+origin+".insteadOf", "https://git.example.test/team/app.git")
	os.WriteFile(filepath.Join(repo, "README"), []byte("one\n"), 0o644)
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-qm", "base")
	gitT(t, repo, "push", "-q", "origin", "HEAD:refs/heads/main")
	gitT(t, repo, "fetch", "-q", "origin")

	ctx := context.Background()
	if p, err := PrepareBranchPush(ctx, localExec, root, "a1", "https://git.example.test/team/app.git", nil); err != nil || p.Commits != 0 {
		t.Fatalf("nothing new: %+v %v", p, err)
	}
	head := gitT(t, repo, "rev-parse", "HEAD")
	os.MkdirAll(filepath.Join(repo, ".github/workflows"), 0o755)
	os.WriteFile(filepath.Join(repo, ".github/workflows/ci.yml"), []byte("on: push\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "npmrc"), []byte("//r/:_authToken="+kit.PlaceholderSecret+"\n"), 0o644)
	p, err := PrepareBranchPush(ctx, localExec, root, "a1", "https://git.example.test/team/app.git", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Made || p.Commits != 1 || len(p.Files) != 2 || p.Host != "git.example.test" || p.Repo != "team/app" || p.PushURL != "https://git.example.test/team/app.git" ||
		len(p.Placeholder) != 1 || p.Placeholder[0] != "npmrc" || len(p.RunsCode) != 1 || !p.Flagged() {
		t.Fatalf("plan: %+v", p)
	}
	if gitT(t, repo, "rev-parse", "HEAD") != head || gitT(t, repo, "status", "--porcelain") == "" {
		t.Fatal("the agent's HEAD or index moved")
	}
	if err := p.Push(ctx, localExec, "agent/fix", "a1", ""); err != nil {
		t.Fatal(err)
	}
	if got := gitT(t, tmp, "--git-dir", origin, "rev-parse", "refs/heads/agent/fix"); got != p.Commit {
		t.Fatalf("origin agent/fix %s, want %s", got, p.Commit)
	}
	// More work: the same branch fast-forwards.
	os.WriteFile(filepath.Join(repo, "README"), []byte("two\n"), 0o644)
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-qm", "more")
	p2, err := PrepareBranchPush(ctx, localExec, root, "a1", "https://git.example.test/team/app.git", nil)
	if err != nil || p2.Made {
		t.Fatalf("committed work: %+v %v", p2, err)
	}
	if err := p2.Push(ctx, localExec, "agent/fix", "a1", p.Commit); err != nil {
		t.Fatalf("fast-forward of its own branch: %v", err)
	}
	if gitT(t, tmp, "--git-dir", origin, "merge-base", "--is-ancestor", p.Commit, p2.Commit) != "" ||
		gitT(t, tmp, "--git-dir", origin, "rev-parse", "refs/heads/agent/fix") != p2.Commit {
		t.Fatal("the branch did not move forward from the first push")
	}
	// Someone else's branch is never overwritten.
	gitT(t, tmp, "--git-dir", origin, "update-ref", "refs/heads/theirs", head)
	var pe *BranchPushError
	if err := p2.Push(ctx, localExec, "theirs", "a1", p2.Commit); !errors.As(err, &pe) || pe.Kind != "exists" {
		t.Fatalf("someone else's branch: %v", err)
	}
	if gitT(t, tmp, "--git-dir", origin, "rev-parse", "refs/heads/theirs") != head {
		t.Fatal("someone else's branch moved")
	}
	// Its own branch moved on origin by someone else: no force.
	gitT(t, tmp, "--git-dir", origin, "update-ref", "refs/heads/agent/fix", head)
	if err := p2.Push(ctx, localExec, "agent/fix", "a1", p2.Commit); !errors.As(err, &pe) || pe.Kind != "exists" {
		t.Fatalf("moved branch: %v", err)
	}
}

func TestB2PushBranchTargetsAndLinks(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/team/app.git":          "github.com team/app https://github.com/team/app.git",
		"git@gitlab.com:group/sub/app.git":         "gitlab.com group/sub/app https://gitlab.com/group/sub/app.git",
		"ssh://git@git.corp.example/team/app":      "git.corp.example team/app https://git.corp.example/team/app",
		"https://x-access-token:p@h.example/r?x#y": "h.example r https://h.example/r",
		"/srv/app.git":                  "  ",
		"git@git.corp.example:team/app": "  ",
	} {
		h, r, u := GitRemoteTarget(in, nil)
		if h+" "+r+" "+u != want {
			t.Errorf("%s: %q %q, want %q", in, h, r, want)
		}
	}
	if l := CompareLink("github.com", "team/app", "agent/fix-login"); l != "https://github.com/team/app/compare/agent/fix-login?expand=1" {
		t.Fatal(l)
	}
	if CompareLink("git.corp.example", "team/app", "b") != "" {
		t.Fatal("link for an unknown host form")
	}
}
