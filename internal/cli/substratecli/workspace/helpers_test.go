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

//go:build unix

package workspace

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const testToken = "test-session-token"

// bearer accepts one fixed token, standing in for the signed session tokens
// (the relay's own tests cover those).
type bearer string

func (b bearer) Verify(_ context.Context, r *http.Request) (relay.Session, error) {
	if relay.TokenFrom(r) != string(b) {
		return relay.Session{}, relay.ErrNoToken
	}
	return relay.Session{Person: "alice@example.test", Actor: "t-ns/actor-1"}, nil
}

// actor is a real relay handler on a test server whose working directory is
// a temporary directory.
type actor struct {
	srv     *httptest.Server
	workdir string
}

func newActor(t *testing.T) *actor {
	t.Helper()
	cfg := kit.DefaultConfig()
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Relay.Workdir = wd
	s := relay.NewServer(relay.Options{
		Config: cfg, Verifier: bearer(testToken),
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warm: func(context.Context, string) error { return nil },
	})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &actor{srv: srv, workdir: wd}
}

func (a *actor) client() *Client {
	return NewClient(a.srv.Client(), relay.RouteBase(a.srv.URL), func(context.Context) (string, error) { return testToken, nil })
}

// sandboxFS maps the paths the copy-mode pipeline uses inside a sandbox
// (/sandbox/work and the state directory beside the project) to a
// temporary directory, so the real relay and the real git can run the
// pipeline's scripts as an actor would.
type sandboxFS struct {
	*Client
	dir string
}

func (s sandboxFS) rw(p string) string { return strings.ReplaceAll(p, "/sandbox/", s.dir+"/sandbox/") }

func (s sandboxFS) Root(context.Context) (string, error) { return osw.DefaultRemoteRoot, nil }

func (s sandboxFS) Exec(ctx context.Context, sb string, req osw.ExecRequest) (*osw.ExecResult, error) {
	argv := make([]string, len(req.Argv))
	for i, a := range req.Argv {
		argv[i] = s.rw(a)
	}
	req.Argv, req.Workdir = argv, s.rw(req.Workdir)
	return s.Client.Exec(ctx, sb, req)
}

func (s sandboxFS) Upload(ctx context.Context, sb, local, remoteDir string) error {
	return s.Client.Upload(ctx, sb, local, s.rw(remoteDir))
}

func (s sandboxFS) Download(ctx context.Context, sb, remote, localDir string) error {
	return s.Client.Download(ctx, sb, s.rw(remote), localDir)
}

// local is the host path of a sandbox path.
func (s sandboxFS) local(p string) string { return s.rw(p) }

// operator is a throwaway person: a home with a project and a state directory.
type operator struct {
	t       *testing.T
	root    string
	home    string
	data    string
	project string
}

func newOperator(t *testing.T) *operator {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o := &operator{t: t, root: root, home: filepath.Join(root, "home")}
	o.data = filepath.Join(o.home, ".defenseclaw")
	o.project = filepath.Join(o.home, "code", "myapp")
	for _, d := range []string{o.project, o.data} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func (o *operator) git(dir string, args ...string) string {
	o.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+o.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		o.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// initRepo makes the project a git repository with one commit.
func (o *operator) initRepo() {
	o.t.Helper()
	o.git(o.project, "init", "-q", "-b", "main")
	write(o.t, o.project, "README.md", "hello\n", 0o644)
	write(o.t, o.project, ".gitignore", "*.log\nbuild/\n", 0o644)
	write(o.t, o.project, "src/app.go", "package main\n", 0o644)
	o.git(o.project, "add", "-A")
	o.git(o.project, "commit", "-q", "-m", "init")
}

var _ osw.Transport = sandboxFS{}
