// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The host copy runs on Linux and macOS (OpenShell sandboxes are not supported on Windows hosts); its tests use POSIX paths.
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

// GAP-0173: the host copy (the launcher on Windows) through a real relay.
// It runs on every OS, Windows included: nothing of it needs a unix host.
func TestHostCopyRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })

	o := newHCEnv(t)
	proj := filepath.Join(t.TempDir(), "lc proj", "my app") // spaces, as on dc-win2
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	o.project = proj
	o.git(proj, "init", "-q", "-b", "main")
	hcWrite(t, proj, "README.md", "line one\r\nline two\r\n") // CRLF kept byte for byte
	hcWrite(t, proj, "naïve café.txt", "unicode name\n")
	hcWrite(t, proj, "src/main.go", "package main\n")
	hcWrite(t, proj, "gone.txt", "to be deleted\n")
	hcWrite(t, proj, ".gitignore", "build/\n")
	hcWrite(t, proj, "build/out.bin", "ignored\n")
	hcWrite(t, proj, ".env", "API_KEY=do-not-copy-this-value\n")
	o.git(proj, "add", "README.md", "naïve café.txt", "src/main.go", "gone.txt", ".gitignore")
	o.git(proj, "-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-qm", "init")
	hcWrite(t, proj, "untracked.txt", "not committed yet\n")

	workdir, c := hcActor(t)
	ctx := context.Background()
	res, err := Start(ctx, StartOptions{Transport: c, Project: proj, Name: "w1", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	remote := filepath.Join(workdir, "my app")
	if filepath.FromSlash(res.RemoteDir) != filepath.Join(workdir, "my app") {
		t.Fatalf("remote dir %q", res.RemoteDir)
	}
	b, err := os.ReadFile(filepath.Join(remote, "README.md"))
	if err != nil || string(b) != "line one\r\nline two\r\n" {
		t.Fatalf("README in the actor %q %v", b, err)
	}
	for _, want := range []string{"naïve café.txt", "src/main.go", "untracked.txt", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(remote, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s not copied: %v", want, err)
		}
	}
	for _, not := range []string{".env", "build/out.bin", ".git"} {
		if _, err := os.Stat(filepath.Join(remote, filepath.FromSlash(not))); err == nil {
			t.Errorf("%s was copied", not)
		}
	}
	if len(res.KeptBack) != 1 || res.KeptBack[0] != ".env" {
		t.Errorf("kept back %v", res.KeptBack)
	}

	// The agent works in the copy.
	hcWrite(t, remote, "README.md", "line one\r\nline 2 by the agent\r\n")
	hcWrite(t, remote, "docs/über guide.md", "new file\n")
	if err := os.Remove(filepath.Join(remote, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	hcWrite(t, remote, "node_modules/x/index.js", "cache\n")
	hcWrite(t, remote, "build/new.bin", "ignored output\n")
	hcWrite(t, remote, ".env", "API_KEY=agent-made\n")
	_ = os.Symlink("/etc/passwd", filepath.Join(remote, "link"))

	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "w1", Label: "agent-1"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got := map[string]string{}
	for _, f := range rv.Changed {
		got[f.Path] = f.Status
	}
	want := map[string]string{"README.md": "modified", "docs/über guide.md": "added", "gone.txt": "deleted"}
	for p, st := range want {
		if got[p] != st {
			t.Errorf("%s: %q, want %q (review %q)", p, got[p], st, rv.Text)
		}
	}
	for _, p := range []string{"node_modules/x/index.js", "build/new.bin", ".env", "link"} {
		if _, ok := got[p]; ok {
			t.Errorf("%s is in the review", p)
		}
	}
	if len(rv.Dropped) != 1 || rv.Dropped[0] != ".env" || !strings.HasPrefix(rv.Text, "agent-1: 3 files changed") {
		t.Errorf("dropped %v, text %q", rv.Dropped, rv.Text)
	}

	// Apply into the folder: exact bytes, deletion done.
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "w1", Mode: ModeApply}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	b, _ = os.ReadFile(filepath.Join(proj, "README.md"))
	if string(b) != "line one\r\nline 2 by the agent\r\n" {
		t.Errorf("README after apply %q", b)
	}
	if b, err := os.ReadFile(filepath.Join(proj, "docs", "über guide.md")); err != nil || string(b) != "new file\n" {
		t.Errorf("new file %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(proj, "gone.txt")); !os.IsNotExist(err) {
		t.Errorf("gone.txt still there: %v", err)
	}
	// A second pull starts from what was applied: nothing new.
	rv, err = Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "w1"})
	if err != nil || !rv.Empty {
		t.Fatalf("second pull %v %q", err, rv.Text)
	}

	// Branch and patch modes.
	hcWrite(t, remote, "src/main.go", "package main\n\nfunc main() {}\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "w1"}); err != nil {
		t.Fatal(err)
	}
	patch := filepath.Join(t.TempDir(), "agent.patch")
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "w1", Mode: ModePatch, PatchPath: patch}); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if b, _ := os.ReadFile(patch); !strings.Contains(string(b), "func main() {}") {
		t.Errorf("patch %q", b)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "w1", Mode: ModeBranch, Branch: "agent/w1"}); err != nil {
		t.Fatalf("branch: %v", err)
	}
	if out := o.git(proj, "show", "agent/w1:src/main.go"); !strings.Contains(out, "func main() {}") {
		t.Errorf("branch content %q", out)
	}
	if b, _ := os.ReadFile(filepath.Join(proj, "src", "main.go")); string(b) != "package main\n" {
		t.Errorf("the checkout changed: %q", b)
	}
}

// A file changed locally since the copy is not overwritten: apply changes
// nothing and keeps the patch.
func TestHostCopyApplyRefusesAConflict(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	hcWrite(t, o.project, "a.txt", "one\n")
	_, c := hcActor(t)
	ctx := context.Background()
	res, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w2", DataDir: o.data, Home: o.home})
	if err != nil {
		t.Fatal(err)
	}
	hcWrite(t, filepath.FromSlash(res.RemoteDir), "a.txt", "agent\n")
	if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "w2"}); err != nil {
		t.Fatal(err)
	}
	hcWrite(t, o.project, "a.txt", "mine\n")
	out, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "w2", Mode: ModeApply})
	if err != nil || !out.FellBack || out.PatchPath == "" {
		t.Fatalf("apply %+v %v", out, err)
	}
	if b, _ := os.ReadFile(filepath.Join(o.project, "a.txt")); string(b) != "mine\n" {
		t.Errorf("my change was overwritten: %q", b)
	}
}

func TestWindowsNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"a/b.txt": true, "naïve café.txt": true, "dir/con.txt": false, "nul": false, "a:b": false,
		"trailing.": false, "trailing ": false, "q?.md": false, "x\x01": false, "COM1.log": false,
	} {
		if windowsName(name) != ok {
			t.Errorf("windowsName(%q) = %v", name, !ok)
		}
	}
}
