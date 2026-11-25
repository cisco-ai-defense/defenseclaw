// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// substrate-1 GAP-0489 (RV-T6A): once the person repeats run's --exclude on
// the second computer, the path is held back on both sides as run held it:
// not measured, not shown, not written, not deleted; --apply and --branch
// work. --no-exclude says run left nothing out. A patch works at any time.
func TestGAP0489ExcludeStatedOnTheSecondComputer(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	hcWrite(t, o.project, "README.md", "line one\n")
	hcWrite(t, o.project, "config/local.yaml", "mine: true\n")
	hcWrite(t, o.project, "config/other.yaml", "kept: true\n")
	gap0489Commit(o)
	workdir, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home, Masks: []string{"config/local.yaml"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	remote := filepath.Join(workdir, "myapp")
	hcWrite(t, remote, "config/local.yaml", "agent: wrote this\n")
	hcWrite(t, remote, "README.md", "line one\nline two by the agent\n")
	hostCopy = old
	clone, data2 := gap0489Second(t, o)

	// Unknown: a patch is fine, apply and branch refuse and say why.
	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rv.Text, "--no-exclude") {
		t.Errorf("the review does not say how to give run's --exclude: %q", rv.Text)
	}
	var unknown *ExcludesUnknownError
	if _, err := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModeApply, AcceptSensitive: true}); !errors.As(err, &unknown) {
		t.Errorf("apply before the excludes are known: %v", err)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModePatch, PatchPath: filepath.Join(t.TempDir(), "p.diff")}); err != nil {
		t.Errorf("a patch before the excludes are known: %v", err)
	}

	// Stated: held back on both sides.
	rv, err = Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone, Exclude: []string{"config/local.yaml"}, ExcludesStated: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rv.Changed) != 1 || rv.Changed[0].Path != "README.md" {
		t.Fatalf("changed %+v, want only README.md (review %q)", rv.Changed, rv.Text)
	}
	if strings.Contains(string(rv.Diff), "agent: wrote this") || strings.Contains(string(rv.Diff), "mine: true") {
		t.Errorf("the excluded file reached the diff:\n%s", rv.Diff)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: data2, Name: "w1", Mode: ModeApply}); err != nil {
		t.Fatalf("apply with the excludes stated: %v", err)
	}
	for p, want := range map[string]string{"config/local.yaml": "mine: true\n", "config/other.yaml": "kept: true\n", "README.md": "line one\nline two by the agent\n"} {
		if b, err := os.ReadFile(filepath.Join(clone, filepath.FromSlash(p))); err != nil || string(b) != want {
			t.Errorf("%s after apply: %q %v, want %q", p, b, err, want)
		}
	}

	// --no-exclude on a fresh second computer: run's left-out file shows as
	// deleted, as the person said nothing was left out.
	clone3, data3 := gap0489Second(t, o)
	rv, err = Pull(ctx, PullOptions{Exec: c, DataDir: data3, Name: "w1", Project: clone3, ExcludesStated: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: data3, Name: "w1", Mode: ModeBranch, Branch: "agent/w1"}); err != nil {
		t.Fatalf("branch with --no-exclude: %v (review %q)", err, rv.Text)
	}
}
