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

// The fixtures (hcActor) are unix-only, like the host copy tests.
//go:build unix

package workspace

import (
	"context"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func b2NeedGit(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	return git
}

// B2 2.5: the rewrite map lands in the actor user's git config, once, and
// git there turns the company ssh addresses into https; a bad pair is
// left out.
func TestB2WriteGitRewrite(t *testing.T) {
	git := b2NeedGit(t)
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	_, c := hcActor(t)
	rules := []config.SubstrateGitRewrite{
		{From: "git@ghe.corp.example:", To: "https://ghe.corp.example/"},
		{From: "bad from:", To: "https://bad.example/"},
		{From: "ssh://git@bb.corp.example:7999/", To: "https://bb.corp.example/scm/"},
	}
	for i := 0; i < 2; i++ {
		if err := WriteGitRewrite(context.Background(), c, rules); err != nil {
			t.Fatalf("WriteGitRewrite %d: %v", i, err)
		}
	}
	cfg, _ := os.ReadFile(filepath.Join(xdg, "git", "config"))
	if n := strings.Count(string(cfg), "defenseclaw-rewrite"); n != 1 {
		t.Fatalf("include written %d times:\n%s", n, cfg)
	}
	if b, _ := os.ReadFile(filepath.Join(xdg, "git", "defenseclaw-rewrite")); strings.Contains(string(b), "bad.example") {
		t.Fatalf("bad pair written:\n%s", b)
	}
	for in, want := range map[string]string{
		"git@ghe.corp.example:team/app.git":           "https://ghe.corp.example/team/app.git",
		"ssh://git@bb.corp.example:7999/team/app.git": "https://bb.corp.example/scm/team/app.git",
	} {
		out, err := exec.Command(git, "ls-remote", "--get-url", in).Output()
		if got := strings.TrimSpace(string(out)); err != nil || got != want {
			t.Errorf("git resolves %s to %q (%v), want %s", in, got, err, want)
		}
	}
}

// B2 2.5: run --clone brings submodules (relative URL, over the same https
// server) when substrate.git.submodules is on, and says how many LFS files
// stayed pointers when LFS is off.
func TestB2CloneSubmodulesAndLFS(t *testing.T) {
	git := b2NeedGit(t)
	out, _ := exec.Command(git, "--exec-path").Output()
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not installed")
	}
	o := newHCEnv(t)
	served := t.TempDir()
	lib := filepath.Join(t.TempDir(), "lib")
	_ = os.MkdirAll(lib, 0o755)
	o.git(lib, "init", "-q", "-b", "main")
	hcWrite(t, lib, "lib.txt", "from the submodule\n")
	o.git(lib, "add", ".")
	o.git(lib, "commit", "-qm", "lib")
	o.git(served, "clone", "-q", "--bare", lib, filepath.Join(served, "lib.git"))
	src := filepath.Join(t.TempDir(), "app")
	_ = os.MkdirAll(src, 0o755)
	o.git(src, "init", "-q", "-b", "main")
	o.git(src, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	o.git(src, "config", "--file", ".gitmodules", "submodule.lib.url", "../lib.git")
	hcWrite(t, src, ".gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
	hcWrite(t, src, "model.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\nsize 12345\n")
	o.git(src, "add", ".")
	o.git(src, "commit", "-qm", "app")
	o.git(served, "clone", "-q", "--bare", src, filepath.Join(served, "app.git"))
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + served, "GIT_HTTP_EXPORT_ALL=1"}})
	defer srv.Close()

	for _, tc := range []struct {
		name string
		opts CloneOptions
		sub  bool
	}{
		{"submodules on, LFS off", CloneOptions{Submodules: true}, true},
		{"submodules off", CloneOptions{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := hcActor(t)
			res, err := Clone(context.Background(), c, o.data, "sm", srv.URL+"/app.git", "", tc.opts)
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			_, serr := os.Stat(filepath.Join(res.Dir, "lib", "lib.txt"))
			if (serr == nil) != tc.sub {
				t.Errorf("submodule file present = %v, want %v", serr == nil, tc.sub)
			}
			if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "1 LFS file is a pointer") {
				t.Errorf("warnings %q, want the LFS pointer count", res.Warnings)
			}
		})
	}
}
