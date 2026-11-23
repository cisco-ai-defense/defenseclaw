// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Uses the host copy fixtures (POSIX paths).
//go:build unix

package workspace

import (
	"context"
	"errors"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0175: --clone clones inside the actor through the relay exec, and the
// agent then starts in the clone. A real git HTTP server (git http-backend)
// stands in for the repository host.
func TestCloneInTheActor(t *testing.T) {
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
	hcWrite(t, src, ".gitignore", "build/\n")
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
	res, err := Clone(ctx, c, o.data, "cl1", srv.URL+"/app.git", "feature", CloneOptions{})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	dir := res.Dir
	if res.Note != "" {
		t.Errorf("clone note %q, want none", res.Note)
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

	// The agent works in the clone; pull, run in a checkout of the same
	// repository on this computer, reviews and brings back only that.
	hcWrite(t, dir, "feature.txt", "on the branch\nedited by the agent\n")
	hcWrite(t, dir, "new.txt", "made by the agent\n")
	hcWrite(t, dir, "build/out.o", "ignored build output\n")
	hcWrite(t, dir, ".env", "API_KEY=never-brought-back\n")
	local := filepath.Join(t.TempDir(), "app")
	o.git(filepath.Dir(local), "clone", "-q", "-b", "feature", srv.URL+"/app.git", local)
	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: o.data, Name: "cl1", Label: "cl1", Project: local})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	got := map[string]string{}
	for _, f := range rv.Changed {
		got[f.Path] = f.Status
	}
	if len(got) != 2 || got["feature.txt"] != "modified" || got["new.txt"] != "added" {
		t.Fatalf("review %v, want feature.txt modified and new.txt added only\n%s", got, rv.Text)
	}
	if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "cl1", Mode: ModeApply}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(local, "feature.txt")); string(b) != "on the branch\nedited by the agent\n" {
		t.Errorf("feature.txt after apply %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(local, "new.txt")); string(b) != "made by the agent\n" {
		t.Errorf("new.txt after apply %q", b)
	}
	for _, never := range []string{"build/out.o", ".env"} {
		if _, err := os.Stat(filepath.Join(local, never)); err == nil {
			t.Errorf("%s was brought back", never)
		}
	}

	// A repository that is not there: git says why, in plain words.
	_, err = Clone(ctx, c, o.data, "cl2", srv.URL+"/missing.git", "", CloneOptions{})
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
	if cloneFolder("git@github.com:me/My-App.git") != "My-App" || cloneFolder("https://h/x/") != "x" || cloneFolder("https://h/team/projekt-über.git") != "projekt-über" {
		t.Error("folder names")
	}
	// Seen on stk: the egress guard answers 503; the person learns who refused.
	e := &CloneError{URL: "https://github.com/a/b.git", Message: "unable to access 'https://github.com/a/b.git/': The requested URL returned error: 503"}
	if !strings.Contains(e.Error(), "network guard refused the request") {
		t.Errorf("503 hint missing: %q", e.Error())
	}
}

func TestB1CloneHostAndHint(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Git.Corp.Example:8443/team/app.git": "git.corp.example",
		"http://git.corp.example/a.git":              "git.corp.example",
		"ssh://git@git.corp.example/team/app.git":    "git.corp.example",
		"git@github.com:me/app.git":                  "github.com",
		"git@git.corp.example:me/app.git":            "", // stays SSH in the actor: no token
		"ssh://deploy@git.corp.example/a.git":        "",
		"git://git.corp.example/a.git":               "",
	} {
		if got := CloneHost(raw, nil); got != want {
			t.Errorf("CloneHost(%q) = %q, want %q", raw, got, want)
		}
	}
	e := &CloneError{URL: "https://git.corp.example/a.git", Message: "fatal: Authentication failed for 'https://git.corp.example/a.git/'"}
	if !e.NeedsCredential() || !strings.Contains(e.Error(), "ask your administrator to allow it") {
		t.Fatalf("no hint: %q", e.Error())
	}
	e.Hint = "git.corp.example needs a token"
	if got := e.Error(); !strings.HasSuffix(got, ". git.corp.example needs a token") || strings.Contains(got, "ask your administrator") {
		t.Fatalf("hint: %q", got)
	}
	e = &CloneError{URL: "https://git.corp.example/a.git", Message: "fatal: unable to access: Could not resolve host: git.corp.example", Hint: "x"}
	if e.NeedsCredential() || strings.Contains(e.Error(), ". x") || !strings.Contains(e.Error(), "network rules may not allow") {
		t.Fatalf("resolve: %q", e.Error())
	}
}

// B2 2.5: a cluster rewrite makes an scp-form address on a company host
// ask for that host's token.
func TestB2CloneHostRewriteMap(t *testing.T) {
	rules := []config.SubstrateGitRewrite{{From: "git@git.corp.example:", To: "https://git.corp.example/"}}
	if got := CloneHost("git@git.corp.example:me/app.git", rules); got != "git.corp.example" {
		t.Errorf("CloneHost with the map = %q", got)
	}
	// RV-SYNC3 F1 (GAP-0733): the image bakes the SaaS rules, which a map
	// cannot drop, so git in the agent still asks GitHub for a token.
	if got := CloneHost("git@github.com:me/app.git", rules); got != "github.com" {
		t.Errorf("a map without GitHub = %q, want github.com", got)
	}
}
