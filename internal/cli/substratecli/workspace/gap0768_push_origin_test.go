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

// GAP-0768 / GAP-0810 (TST-5887): the agent writes its checkout's git
// config and its own user config in the actor. pull --push-branch reviews
// and pushes to the origin this computer recorded when it made the copy,
// never to an address the actor's config names.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// gap0768Prepare reviews the push with the origin this computer recorded.
func gap0768Prepare(s *rv4) (*BranchPush, error) {
	return PrepareBranchPush(context.Background(), localExec, s.root, "a1", gap0768Origin, nil)
}

func TestGAP0768PushUsesTheRecordedOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(s *rv4, fork string)
	}{
		{"second url appended (TST-5887)", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "--add", "remote.origin.url", gap0768Fork)
		}},
		{"second url, pushurl and followTags (TST-5887)", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "remote.origin.pushurl", gap0768Fork)
			gitT(s.t, s.repo, "config", "--add", "remote.origin.url", gap0768Fork)
			gitT(s.t, s.repo, "config", "push.followTags", "true")
		}},
		{"origin url replaced", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "remote", "set-url", "origin", gap0768Fork)
		}},
		{"origin removed, named in the actor's user config", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "remote", "remove", "origin")
			gap0768File(s.t, filepath.Join(os.Getenv("HOME"), ".gitconfig"), "[remote \"origin\"]\n\turl = "+gap0768Fork+"\n")
		}},
		{"pushurl", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "remote.origin.pushurl", gap0768Fork)
		}},
		{"insteadOf", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "url."+gap0768Fork+".insteadOf", gap0768Origin)
		}},
		{"pushInsteadOf", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "url."+gap0768Fork+".pushInsteadOf", gap0768Origin)
		}},
		{"url.<base> on the host", func(s *rv4, fork string) {
			// file://<tmp>/host/team/app.git is the fork, by its base.
			host := filepath.Join(s.tmp, "host")
			gap0768Mkdir(s.t, filepath.Join(host, "team"))
			if err := os.Symlink(fork, filepath.Join(host, "team", "app.git")); err != nil {
				s.t.Fatal(err)
			}
			gitT(s.t, s.repo, "config", "url.file://"+host+"/.insteadOf", "https://git.example.test/")
			gitT(s.t, s.repo, "config", "url.file://"+host+"/.pushInsteadOf", "https://git.example.test/")
		}},
		{"include.path", func(s *rv4, _ string) {
			inc := filepath.Join(s.tmp, "inc.cfg")
			gap0768File(s.t, inc, "[remote \"origin\"]\n\turl = "+gap0768Fork+"\n\tpushurl = "+gap0768Fork+"\n")
			gitT(s.t, s.repo, "config", "include.path", inc)
		}},
		{"includeIf gitdir", func(s *rv4, _ string) {
			inc := filepath.Join(s.tmp, "incif.cfg")
			gap0768File(s.t, inc, "[remote \"origin\"]\n\turl = "+gap0768Fork+"\n")
			gitT(s.t, s.repo, "config", "includeIf.gitdir:"+s.repo+"/.git.path", inc)
		}},
		{"the actor's XDG git config (RV-T6A)", func(s *rv4, _ string) {
			gap0768File(s.t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git", "config"),
				"[url \""+gap0768Fork+"\"]\n\tpushInsteadOf = "+gap0768Origin+"\n\tinsteadOf = "+gap0768Origin+"\n[remote \"origin\"]\n\tpushurl = "+gap0768Fork+"\n")
		}},
		{"core.sshCommand with an ssh origin", func(s *rv4, _ string) {
			gitT(s.t, s.repo, "config", "core.sshCommand", "false")
			gitT(s.t, s.repo, "remote", "set-url", "origin", "git@git.example.test:team/fork.git")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rv4Setup(t)
			t.Setenv("HOME", filepath.Join(s.tmp, "home"))
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(s.tmp, "home", ".config"))
			fork := s.bare("fork.git")
			t.Setenv("DC_TEST_PUSH_FORK", fork)
			tc.set(s, fork)
			s.write("a.txt", "x\n")
			p, err := gap0768Prepare(s)
			if err != nil {
				t.Fatalf("review: %v", err)
			}
			if p.Host != "git.example.test" || p.Repo != "team/app" || p.PushURL != gap0768Origin || p.URL != gap0768Origin {
				t.Fatalf("review names %s %s %s (url %s), want the recorded origin", p.Host, p.Repo, p.PushURL, p.URL)
			}
			if err := p.Push(context.Background(), localExec, "agent/a", "a1", ""); err != nil {
				t.Fatalf("push: %v", err)
			}
			if rv4Ref(fork, "refs/heads/agent/a") != "" {
				t.Fatal("the push went to a repository the review did not name")
			}
			if rv4Ref(s.origin, "refs/heads/agent/a") == "" {
				t.Fatal("the recorded origin did not get the branch")
			}
		})
	}
}

// Without a recorded origin there is nothing trusted to push to: refused
// before any network read, whatever the checkout's config says.
func TestGAP0768NoRecordedOriginIsRefused(t *testing.T) {
	s := rv4Setup(t)
	s.write("a.txt", "x\n")
	_, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", "", nil)
	var pe *BranchPushError
	if !errors.As(err, &pe) || pe.Kind != "no_origin" {
		t.Fatalf("got %v, want a no_origin refusal", err)
	}
}
