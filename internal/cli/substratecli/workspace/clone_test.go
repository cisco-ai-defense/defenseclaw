// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"errors"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0175: --clone clones inside the actor through the relay exec, and the
// agent then starts in the clone. A real git HTTP server (git http-backend)
// stands in for the repository host.
func TestCloneInTheActor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the relay exec runs in a Linux actor")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	out, _ := exec.Command(git, "--exec-path").Output()
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not installed")
	}
	o := newHCEnv(t)
	served := t.TempDir()
	src := filepath.Join(t.TempDir(), "src")
	_ = os.MkdirAll(src, 0o755)
	o.git(src, "init", "-q", "-b", "main")
	hcWrite(t, src, "hello.txt", "hello from the repo\n")
	o.git(src, "add", ".")
	o.git(src, "commit", "-qm", "one")
	o.git(src, "branch", "feature")
	o.git(src, "checkout", "-q", "feature")
	hcWrite(t, src, "feature.txt", "on the branch\n")
	o.git(src, "add", ".")
	o.git(src, "commit", "-qm", "two")
	o.git(served, "clone", "-q", "--bare", src, filepath.Join(served, "app.git"))
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + served, "GIT_HTTP_EXPORT_ALL=1"}})
	defer srv.Close()

	workdir, c := hcActor(t)
	ctx := context.Background()
	dir, err := Clone(ctx, c, o.data, "cl1", srv.URL+"/app.git", "feature")
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if dir != workdir+"/app" {
		t.Fatalf("clone dir %q", dir)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "feature.txt")); err != nil || string(b) != "on the branch\n" {
		t.Fatalf("the ref was not checked out: %q %v", b, err)
	}
	if RemoteDirOf(o.data, "cl1") != dir {
		t.Errorf("RemoteDirOf = %q", RemoteDirOf(o.data, "cl1"))
	}

	// A repository that is not there: git says why, in plain words.
	_, err = Clone(ctx, c, o.data, "cl2", srv.URL+"/missing.git", "")
	var ce *CloneError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "git could not clone") || ce.Message == "" {
		t.Fatalf("missing repo: %v", err)
	}
}

func TestCloneRefusesWhatIsNotARepositoryAddress(t *testing.T) {
	for _, bad := range []string{"", "-uhelp", "/srv/repo.git", "file:///srv/repo.git", "ext::sh -c id", "https://user:token@git.example.test/a.git", "https://tok@git.example.test/a.git"} {
		if CheckCloneURL(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"https://github.com/octocat/Hello-World.git", "git@github.com:me/app.git", "ssh://git@git.example.test/team/app.git"} {
		if err := CheckCloneURL(good); err != nil {
			t.Errorf("refused %q: %v", good, err)
		}
	}
	for _, bad := range []string{"-x", "a b", "--upload-pack=x"} {
		if CheckCloneRef(bad) == nil {
			t.Errorf("ref %q accepted", bad)
		}
	}
	if cloneFolder("git@github.com:me/My-App.git") != "My-App" || cloneFolder("https://h/x/") != "x" {
		t.Error("folder names")
	}
}
