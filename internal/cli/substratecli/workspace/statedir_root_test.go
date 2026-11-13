//go:build unix

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0163: through a real relay the copy is <workdir>/<folder>, the copy
// state is under the relay user home (outside the working directory, mode
// 0700, not in what the agent lists), and a file the agent writes in the
// copy comes back with pull.
func TestCopyStateOutsideTheWorkdirAndPullBringsTheFileBack(t *testing.T) {
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	o := newOperator(t)
	o.initRepo()
	a := newActor(t)
	c := a.client()
	ctx := context.Background()
	res, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "c-gap163", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	home := os.Getenv("HOME")
	if !strings.HasPrefix(res.StateDir, filepath.Join(home, ".local", "state", "defenseclaw", "copies")+"/") {
		t.Fatalf("state dir %q, want under the relay home", res.StateDir)
	}
	if strings.HasPrefix(res.StateDir, a.workdir+"/") || !strings.HasPrefix(res.RemoteDir, a.workdir+"/") {
		t.Fatalf("copy %q state %q (workdir %q)", res.RemoteDir, res.StateDir, a.workdir)
	}
	fi, err := os.Stat(filepath.Dir(res.StateDir))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state root %v %v", fi, err)
	}
	entries, _ := os.ReadDir(a.workdir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), StateDirPrefix) {
			t.Errorf("state is still in the working directory: %s", e.Name())
		}
	}
	// The agent writes a file where it starts (the copy, relay dir).
	if err := os.WriteFile(filepath.Join(res.RemoteDir, "stk-smoke.txt"), []byte("done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "c-gap163", Label: "agent-1"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	found := false
	for _, f := range rv.Changed {
		if f.Path == "stk-smoke.txt" {
			found = true
		}
	}
	if rv.Empty || !found {
		t.Fatalf("pull does not bring the file back: %q", rv.Text)
	}
}
