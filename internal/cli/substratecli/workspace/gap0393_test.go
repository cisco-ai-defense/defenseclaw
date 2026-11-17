// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Uses the host copy fixtures (POSIX paths).
//go:build unix

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0393: pull --branch in a git folder with no commit yet makes the
// branch, with no parent (there is nothing to branch from); the folder and
// its unborn branch stay as they were. The folder's own unborn branch is
// refused, and an edit of a file that is in no commit gets a clear message.
func TestGAP0393BranchInARepositoryWithNoCommit(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	proj := o.project
	o.git(proj, "init", "-q", "-b", "main")
	hcWrite(t, proj, "README.md", "not committed yet\n")

	_, c := hcActor(t)
	ctx := context.Background()
	res, err := Start(ctx, StartOptions{Transport: c, Project: proj, Name: "u1", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	remote := filepath.FromSlash(res.RemoteDir)
	hcWrite(t, remote, "agent.txt", "made by the agent\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "u1"}); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	_, err = Apply(ctx, ApplyOptions{DataDir: o.data, Name: "u1", Mode: ModeBranch, Branch: "main"})
	if err == nil || !strings.Contains(err.Error(), "no commit yet") {
		t.Fatalf("branch named as the folder's unborn branch: err = %v", err)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "u1", Mode: ModeBranch, Branch: "agent/u1"}); err != nil {
		t.Fatalf("branch: %v", err)
	}
	if out := o.git(proj, "show", "agent/u1:agent.txt"); out != "made by the agent\n" {
		t.Errorf("branch content %q", out)
	}
	if n := strings.TrimSpace(o.git(proj, "rev-list", "--count", "agent/u1")); n != "1" {
		t.Errorf("branch has %s commits, want 1", n)
	}
	if exec.Command("git", "-C", proj, "rev-parse", "--verify", "-q", "HEAD").Run() == nil {
		t.Error("the folder's branch got a commit")
	}
	if _, err := os.Stat(filepath.Join(proj, "agent.txt")); !os.IsNotExist(err) {
		t.Errorf("the folder changed: %v", err)
	}
	if out := o.git(proj, "status", "--porcelain"); out != "?? README.md\n" {
		t.Errorf("status after the branch %q", out)
	}

	// An edit of a file that is in no commit has nothing to apply to.
	hcWrite(t, remote, "README.md", "edited by the agent\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "u1"}); err != nil {
		t.Fatalf("second Pull: %v", err)
	}
	_, err = Apply(ctx, ApplyOptions{DataDir: o.data, Name: "u1", Mode: ModeBranch, Branch: "agent/u1-2"})
	if err == nil || !strings.Contains(err.Error(), "make a first commit") {
		t.Fatalf("edit of an uncommitted file: err = %v", err)
	}
	if exec.Command("git", "-C", proj, "rev-parse", "--verify", "-q", "refs/heads/agent/u1-2").Run() == nil {
		t.Error("a branch was made for changes that do not apply")
	}
}
