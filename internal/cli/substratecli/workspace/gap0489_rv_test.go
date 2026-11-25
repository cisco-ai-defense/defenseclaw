// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// gap0489Second clones o.project into a second computer's folder of the same
// name and returns it and that computer's data directory.
func gap0489Second(t *testing.T, o *hcEnv) (clone, data string) {
	t.Helper()
	second := filepath.Join(t.TempDir(), "laptop2")
	clone = filepath.Join(second, "myapp")
	o.git(filepath.Dir(o.project), "clone", "-q", o.project, clone)
	return clone, filepath.Join(second, "data")
}

func gap0489Commit(o *hcEnv) {
	o.git(o.project, "add", ".")
	o.git(o.project, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "init")
}

// substrate-1 GAP-0489 (RV-T6A): the second computer's baseline is HEAD's
// files, export-ignore paths and export-subst files as committed. Before, it
// was git archive's output, which leaves out export-ignore paths and rewrites
// export-subst files, so an unchanged tests/ folder showed as added (and
// --apply always fell back to a patch file), and unchanged files showed as
// modified. Line endings and filters: TestGAP0489BaselineIsTheCheckoutHere.
func TestGAP0489BaselineIsTheCommittedBytes(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	hcWrite(t, o.project, ".gitattributes", "/tests export-ignore\nversion.txt export-subst\n")
	hcWrite(t, o.project, "tests/a_test.txt", "a test\n")
	hcWrite(t, o.project, "version.txt", "$Format:%H$\n")
	hcWrite(t, o.project, "README.md", "line one\n")
	gap0489Commit(o)

	workdir, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	hcWrite(t, filepath.Join(workdir, "myapp"), "README.md", "line one\nline two by the agent\n")
	hostCopy = old
	clone, data2 := gap0489Second(t, o)
	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone})
	if err != nil {
		t.Fatalf("pull on the second computer: %v", err)
	}
	if len(rv.Changed) != 1 || rv.Changed[0].Path != "README.md" || rv.Changed[0].Status != "modified" {
		t.Fatalf("changed %+v, want only README.md modified (review %q)", rv.Changed, rv.Text)
	}
}

// substrate-1 GAP-0489 (RV-T6A): a file run left out with --exclude is not
// written over on the second computer until the person says what run left
// out. Before, the agent's file at that path was diffed against the
// committed one and --apply wrote the agent's content over it.
func TestGAP0489SecondComputerHonoursRunExclude(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	hcWrite(t, o.project, "README.md", "line one\n")
	hcWrite(t, o.project, "config/local.yaml", "mine: true\n")
	gap0489Commit(o)

	workdir, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home, Masks: []string{"config/local.yaml"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	remote := filepath.Join(workdir, "myapp")
	if _, err := os.Stat(filepath.Join(remote, "config", "local.yaml")); err == nil {
		t.Fatal("run sent a file it was told to leave out")
	}
	hcWrite(t, remote, "config/local.yaml", "agent: wrote this\n")
	hostCopy = old
	clone, data2 := gap0489Second(t, o)
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone}); err != nil {
		t.Fatalf("pull on the second computer: %v", err)
	}
	_, applyErr := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModeApply, AcceptSensitive: true})
	_, branchErr := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModeBranch, Branch: "agent/w1"})
	if b, err := os.ReadFile(filepath.Join(clone, "config", "local.yaml")); err != nil || string(b) != "mine: true\n" {
		t.Errorf("the excluded file was written over on the second computer: %q %v", b, err)
	}
	if applyErr == nil || branchErr == nil {
		t.Errorf("--apply (%v) and --branch (%v) on the second computer, before it knew run's --exclude: want both refused", applyErr, branchErr)
	}
}
