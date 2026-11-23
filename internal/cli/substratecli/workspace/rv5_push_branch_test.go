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

// RV-SYNC5: the push carries the objects the review read, from the
// checkout's own store at review time (GAP-0797), and moves origin's branch
// only from the state the review saw (GAP-0798).

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rv5Git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return strings.TrimSpace(gitT(t, dir, args...))
}

// GAP-0797: a checkout that borrows objects from another store is refused;
// the push sends only what the checkout holds itself.
func TestRV5ReviewRefusesBorrowedObjects(t *testing.T) {
	for _, name := range []string{"alternates", "http-alternates"} {
		t.Run(name, func(t *testing.T) {
			s := rv4Setup(t)
			s.write("a.txt", "one\n")
			s.commit("a")
			other := s.bare("other.git")
			info := filepath.Join(s.repo, ".git", "objects", "info")
			if err := os.MkdirAll(info, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(info, name), []byte(filepath.Join(other, "objects")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", nil)
			var pe *BranchPushError
			if !errors.As(err, &pe) || pe.Kind != "alternates" {
				t.Fatalf("a checkout with objects/info/%s: %v, want an alternates refusal", name, err)
			}
		})
	}
}

// GAP-0797: after the review the agent drops the reviewed blob from its
// store and names another store (objects/info/alternates) holding a
// different body under the same name. The push still carries the reviewed
// body, from the copy the review made.
func TestRV5AlternatesWrittenAfterTheReviewAreNotRead(t *testing.T) {
	s := rv4Setup(t)
	s.write("a.txt", "reviewed\n")
	s.commit("a")
	p := s.prepare()
	blob := rv5Git(t, s.repo, "rev-parse", "HEAD:a.txt")
	objs := filepath.Join(s.repo, ".git", "objects")
	if err := os.Remove(filepath.Join(objs, blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(s.tmp, "other", "objects")
	body := "other body\n"
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	fmt.Fprintf(zw, "blob %d\x00%s", len(body), body)
	_ = zw.Close()
	if err := os.MkdirAll(filepath.Join(other, blob[:2]), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, blob[:2], blob[2:]), z.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(objs, "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(objs, "info", "alternates"), []byte(other+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.Push(context.Background(), localExec, "agent/a", "a1", ""); err != nil {
		t.Fatalf("push after the store changed: %v", err)
	}
	if got := rv5Git(t, s.tmp, "--git-dir", s.origin, "cat-file", "-p", "refs/heads/agent/a:a.txt"); got != "reviewed" {
		t.Fatalf("origin's a.txt = %q, want the reviewed body", got)
	}
}

// GAP-0810: config written into the review snapshot after approval cannot
// rewrite the pinned destination or redirect the push.
func TestRV5SnapshotConfigCannotRedirectApprovedPush(t *testing.T) {
	s := rv4Setup(t)
	s.write("b14.txt", "approved\n")
	p := s.prepare()
	other := s.bare("redirected.git")
	if err := os.WriteFile(filepath.Join(p.snapshot, "g", "config"), []byte("[url \"file://"+other+"\"]\n\t\tinsteadOf = https://git.example.test/team/app.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Push(context.Background(), localExec, "agent/b14", "a1", ""); err != nil {
		t.Fatal(err)
	}
	if rv4Ref(other, "refs/heads/agent/b14") != "" {
		t.Fatal("the push followed a snapshot config rewrite")
	}
	if rv4Ref(s.origin, "refs/heads/agent/b14") == "" {
		t.Fatal("the reviewed destination did not receive the branch")
	}
}

// rv5MoveOnPush puts a git first on PATH that, on its first push, moves
// origin's refs/heads/BRANCH to to (a writer racing the push), then runs git.
func rv5MoveOnPush(t *testing.T, s *rv4, branch, to string) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	dir := filepath.Join(s.tmp, "shim")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(dir, "fired")
	sh := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = push ] && [ ! -e %q ]; then\n    : > %q\n    %q --git-dir=%q update-ref refs/heads/%s %s || exit 99\n    break\n  fi\ndone\nexec %q \"$@\"\n",
		mark, mark, real, s.origin, branch, to, real)
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(sh), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// GAP-0798: a branch the review saw as new, or at the commit this computer
// pushed before, is updated only from that state; a writer that moves it
// between the check and the push makes the push fail, and nothing moves.
func TestRV5PushIsBoundToTheReviewedBranchState(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		s := rv4Setup(t)
		base := rv5Git(t, s.repo, "rev-parse", "HEAD")
		s.write("a.txt", "one\n")
		s.commit("a")
		p := s.prepare()
		rv5MoveOnPush(t, s, "agent/a", base)
		err := p.Push(context.Background(), localExec, "agent/a", "a1", "")
		var pe *BranchPushError
		if !errors.As(err, &pe) || pe.Kind != "moved" {
			t.Fatalf("branch made during the push: %v, want a moved refusal", err)
		}
		if got := strings.TrimSpace(rv4Ref(s.origin, "refs/heads/agent/a")); got != base {
			t.Fatalf("origin's agent/a = %q, want the other writer's %s", got, base)
		}
	})
	t.Run("recorded", func(t *testing.T) {
		s := rv4Setup(t)
		base := rv5Git(t, s.repo, "rev-parse", "HEAD")
		s.write("a.txt", "one\n")
		s.commit("a")
		p := s.prepare()
		if err := p.Push(context.Background(), localExec, "agent/a", "a1", ""); err != nil {
			t.Fatal(err)
		}
		prev := p.Commit
		s.write("a.txt", "two\n")
		s.commit("b")
		p = s.prepare()
		rv5MoveOnPush(t, s, "agent/a", base)
		err := p.Push(context.Background(), localExec, "agent/a", "a1", prev)
		var pe *BranchPushError
		if !errors.As(err, &pe) || pe.Kind != "moved" {
			t.Fatalf("branch moved during the push: %v, want a moved refusal", err)
		}
		if got := strings.TrimSpace(rv4Ref(s.origin, "refs/heads/agent/a")); got != base {
			t.Fatalf("origin's agent/a = %q, want the other writer's %s", got, base)
		}
	})
	t.Run("moved_after_review", func(t *testing.T) {
		s := rv4Setup(t)
		s.write("a.txt", "one\n")
		s.commit("a")
		p := s.prepare()
		if err := p.Push(context.Background(), localExec, "agent/a", "a1", ""); err != nil {
			t.Fatal(err)
		}
		prev := p.Commit
		s.write("a.txt", "two\n")
		s.commit("b")
		p = s.prepare()
		// Deleted on origin after the review: the push does not make it
		// again from a state the review did not see.
		gitT(t, s.tmp, "--git-dir", s.origin, "update-ref", "-d", "refs/heads/agent/a")
		err := p.Push(context.Background(), localExec, "agent/a", "a1", prev)
		var pe *BranchPushError
		if !errors.As(err, &pe) || pe.Kind != "moved" {
			t.Fatalf("branch deleted after the review: %v, want a moved refusal", err)
		}
	})
}
