// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0393: pull --branch in a git folder with no commit said only
// "git worktree: fatal: invalid reference: HEAD"; it now says the folder
// needs a first commit and what else works.
func TestHostCopyBranchNeedsAFirstCommitGAP0393(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q")
	hcWrite(t, o.project, "a.txt", "one\n")
	_, c := hcActor(t)
	ctx := context.Background()
	res, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w3", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatal(err)
	}
	hcWrite(t, filepath.FromSlash(res.RemoteDir), "a.txt", "agent\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "w3"}); err != nil {
		t.Fatal(err)
	}
	_, err = Apply(ctx, ApplyOptions{DataDir: o.data, Name: "w3", Mode: ModeBranch, Branch: "agent/w3"})
	if err == nil || !strings.Contains(err.Error(), "needs a first commit") || strings.Contains(err.Error(), "invalid reference") {
		t.Fatalf("err = %v, want the first-commit message", err)
	}
}
