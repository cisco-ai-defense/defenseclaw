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

// RV-SYNC4 (GAP-0768..0772): the agent writes its checkout's git config
// and refs. None of it changes where pull --push-branch pushes, what it
// pushes, what the review shows, or which branch it may move.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

type rv4 struct {
	t                       *testing.T
	tmp, origin, root, repo string
}

// rv4Setup is an actor checkout whose origin is
// https://git.example.test/team/app.git. The test executor maps that
// address with an explicit -c setting; the checkout's own config maps it
// the same way for the agent's own git.
func rv4Setup(t *testing.T) *rv4 {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s := &rv4{t: t, tmp: t.TempDir()}
	s.origin = filepath.Join(s.tmp, "origin.git")
	t.Setenv("DC_TEST_PUSH_ORIGIN", s.origin)
	gitT(t, s.tmp, "init", "-q", "--bare", s.origin)
	s.root = filepath.Join(s.tmp, "work")
	gitT(t, s.tmp, "clone", "-q", s.origin, s.root+"/app")
	s.repo = filepath.Join(s.root, "app")
	gitT(t, s.repo, "remote", "set-url", "origin", "https://git.example.test/team/app.git")
	gitT(t, s.repo, "config", "url.file://"+s.origin+".insteadOf", "https://git.example.test/team/app.git")
	s.write("README", "one\n")
	gitT(t, s.repo, "add", ".")
	gitT(t, s.repo, "commit", "-qm", "base")
	gitT(t, s.repo, "push", "-q", "origin", "HEAD:refs/heads/main")
	gitT(t, s.repo, "fetch", "-q", "origin")
	return s
}

func (s *rv4) bare(name string) string {
	p := filepath.Join(s.tmp, name)
	gitT(s.t, s.tmp, "init", "-q", "--bare", p)
	return p
}

func (s *rv4) write(name, body string) {
	s.t.Helper()
	p := filepath.Join(s.repo, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *rv4) commit(msg string) {
	gitT(s.t, s.repo, "add", "-A")
	gitT(s.t, s.repo, "commit", "-qm", msg)
}

func (s *rv4) prepare() *BranchPush {
	s.t.Helper()
	p, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", "https://git.example.test/team/app.git", nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return p
}

func rv4Ref(dir, ref string) string {
	out, _ := exec.Command("git", "--git-dir", dir, "rev-parse", "-q", "--verify", ref).Output()
	return string(out)
}

// GAP-0768: remote.origin.pushurl, a second remote.origin.url and
// url.*.pushInsteadOf in the checkout do not move the push, and the
// review names the address it goes to.
func TestRV4PushGoesOnlyToTheReviewedURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(s *rv4, other string)
	}{
		{"pushurl", func(s *rv4, other string) { gitT(s.t, s.repo, "config", "remote.origin.pushurl", "file://"+other) }},
		{"second url", func(s *rv4, other string) {
			gitT(s.t, s.repo, "config", "--replace-all", "remote.origin.url", "file://"+other)
			gitT(s.t, s.repo, "config", "--add", "remote.origin.url", "https://git.example.test/team/app.git")
		}},
		{"pushInsteadOf", func(s *rv4, other string) {
			gitT(s.t, s.repo, "config", "url.file://"+other+".pushInsteadOf", "https://git.example.test/")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rv4Setup(t)
			other := s.bare("other.git")
			tc.set(s, other)
			s.write("a.txt", "x\n")
			p := s.prepare()
			if p.Host != "git.example.test" || p.Repo != "team/app" || rv4URL(p) != "https://git.example.test/team/app.git" {
				t.Fatalf("review target %s %s %s", p.Host, p.Repo, rv4URL(p))
			}
			if err := rv4Push(p, "agent/a", ""); err != nil {
				t.Fatal(err)
			}
			if rv4Ref(other, "refs/heads/agent/a") != "" {
				t.Fatal("the push went to a repository the review did not name")
			}
			if rv4Ref(s.origin, "refs/heads/agent/a") == "" {
				t.Fatal("the reviewed origin did not get the branch")
			}
		})
	}
}

// GAP-0768: push.followTags in the checkout pushes no tag.
func TestRV4PushCarriesNoTags(t *testing.T) {
	s := rv4Setup(t)
	gitT(t, s.repo, "config", "push.followTags", "true")
	s.write("f.txt", "x\n")
	s.commit("f")
	gitT(t, s.repo, "tag", "-a", "-m", "rel", "v9.9.9")
	if err := rv4Push(s.prepare(), "agent/f", ""); err != nil {
		t.Fatal(err)
	}
	if rv4Ref(s.origin, "refs/tags/v9.9.9") != "" {
		t.Fatal("a tag the review did not show reached origin")
	}
}

// GAP-0769: a "pushed before" record planted in the checkout's config lets
// no push move a branch origin already has.
func TestRV4PlantedRecordMovesNoBranch(t *testing.T) {
	t.Run("main", func(t *testing.T) {
		s := rv4Setup(t)
		before := rv4Ref(s.origin, "refs/heads/main")
		gitT(t, s.repo, "config", "defenseclaw-push.main.commit", before[:len(before)-1])
		s.write("c.txt", "x\n")
		var pe *BranchPushError
		if err := rv4Push(s.prepare(), "main", ""); !errors.As(err, &pe) || pe.Kind != "exists" {
			t.Fatalf("push to main: %v", err)
		}
		if rv4Ref(s.origin, "refs/heads/main") != before {
			t.Fatal("main moved")
		}
	})
	t.Run("teammate", func(t *testing.T) {
		s := rv4Setup(t)
		gitT(t, s.repo, "checkout", "-qb", "teammate")
		s.write("team.txt", "t\n")
		s.commit("team")
		gitT(t, s.repo, "push", "-q", "origin", "HEAD:refs/heads/feature")
		gitT(t, s.repo, "checkout", "-q", "main")
		gitT(t, s.repo, "branch", "-qD", "teammate")
		gitT(t, s.repo, "fetch", "-q", "origin")
		cur := rv4Ref(s.origin, "refs/heads/feature")
		gitT(t, s.repo, "config", "defenseclaw-push.feature.commit", cur[:len(cur)-1])
		s.write("c2.txt", "x\n")
		var pe *BranchPushError
		if err := rv4Push(s.prepare(), "feature", ""); !errors.As(err, &pe) || pe.Kind != "exists" {
			t.Fatalf("push to a teammate's branch: %v", err)
		}
		if rv4Ref(s.origin, "refs/heads/feature") != cur {
			t.Fatal("the teammate's branch moved")
		}
	})
}

// GAP-0770: a commit hidden behind an agent-moved refs/remotes/origin/*
// is in the review.
func TestRV4ReviewSeesCommitsBehindMovedRemoteRefs(t *testing.T) {
	s := rv4Setup(t)
	s.write(".github/workflows/x.yml", "on: push\n")
	s.commit("hidden")
	gitT(t, s.repo, "update-ref", "refs/remotes/origin/zz", "HEAD")
	s.write("benign.txt", "x\n")
	s.commit("benign")
	p := s.prepare()
	if p.Commits != 2 || !slices.Contains(p.Files, ".github/workflows/x.yml") || !slices.Contains(p.RunsCode, ".github/workflows/x.yml") || !p.Flagged() {
		t.Fatalf("review: commits=%d files=%q runsCode=%q", p.Commits, p.Files, p.RunsCode)
	}
}

// GAP-0771: names git would quote reach RunsCode and the review as they
// are.
func TestRV4ReviewReadsRealNames(t *testing.T) {
	s := rv4Setup(t)
	wf := ".github/workflows/ci\u00e9.yml"
	s.write(wf, "on: push\n")
	s.write("Makefile\t", "x:\n")
	p := s.prepare()
	if !slices.Contains(p.Files, wf) || !slices.Contains(p.Files, "Makefile\t") || !slices.Contains(p.RunsCode, wf) {
		t.Fatalf("files=%q runsCode=%q", p.Files, p.RunsCode)
	}
	if DisplayName("Makefile\t") != `"Makefile\t"` || DisplayName(wf) != wf {
		t.Fatalf("display %s %s", DisplayName("Makefile\t"), DisplayName(wf))
	}
}

// GAP-0772 / RV6-4: commits that write the placeholders of an upload with
// replaced credentials are refused before anything is pushed, committed or
// not, with no copy record.
func TestRV4ReplacedCredentialPlaceholdersAreRefused(t *testing.T) {
	for _, committed := range []bool{true, false} {
		s := rv4Setup(t)
		s.write("config/app.env", "API_TOKEN=DC_SECRET_1\n")
		if committed {
			s.commit("the upload's replaced lines")
		}
		_, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", "https://git.example.test/team/app.git", nil)
		var pe *BranchPushError
		if !errors.As(err, &pe) || pe.Kind != "replaced_copy" {
			t.Fatalf("committed=%v: %v", committed, err)
		}
	}
}

// GAP-0767 (a) / evil merge: a merge commit's own tree can add content
// that no parent has, and `git log -p/--name-only` prints no diff for a
// merge. Each merge in the range is diffed against its first parent, so
// that content reaches the file list, the flags, the placeholder check and
// the secret scan.
func TestRV4MergeOnlyContentIsReviewed(t *testing.T) {
	merge := func(s *rv4, add func()) {
		gitT(t, s.repo, "checkout", "-q", "-b", "side")
		s.write("side.txt", "side\n")
		s.commit("side")
		gitT(t, s.repo, "checkout", "-q", "-")
		s.write("main.txt", "main\n")
		s.commit("main")
		gitT(t, s.repo, "merge", "-q", "--no-ff", "--no-commit", "side")
		add()
		gitT(t, s.repo, "add", "-A")
		gitT(t, s.repo, "commit", "-qm", "merge side")
	}
	s := rv4Setup(t)
	merge(s, func() {
		s.write(".github/workflows/evil.yml", "on: push\n")
		s.write("conf/app.cfg", "token: "+kit.PlaceholderSecret+"\n")
		s.write("conf/aws.ini", "aws_access_key_id = AKIA"+"7Q2M9X4B6C8D3F5H\n")
	})
	p := s.prepare()
	if !slices.Contains(p.Files, ".github/workflows/evil.yml") || !slices.Contains(p.RunsCode, ".github/workflows/evil.yml") ||
		!slices.Contains(p.Placeholder, "conf/app.cfg") || !p.Flagged() {
		t.Errorf("merge-only files: files=%q runsCode=%q placeholder=%q", p.Files, p.RunsCode, p.Placeholder)
	}
	found := false
	for _, f := range p.Secrets {
		found = found || f.Path == "conf/aws.ini"
	}
	if !found {
		t.Errorf("merge-only secret not scanned: %+v", p.Secrets)
	}

	s = rv4Setup(t)
	merge(s, func() { s.write("config/app.env", "API_TOKEN=DC_SECRET_1\n") })
	_, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", "https://git.example.test/team/app.git", nil)
	var pe *BranchPushError
	if !errors.As(err, &pe) || pe.Kind != "replaced_copy" {
		t.Errorf("merge-only placeholder of a replaced upload: %v", err)
	}
}
