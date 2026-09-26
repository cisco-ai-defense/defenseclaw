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

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// env is a throwaway operator: a home directory with a project and a
// DefenseClaw data dir inside it, all symlink-free.
type env struct {
	t       *testing.T
	root    string
	home    string
	data    string
	project string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if !platformSupported() {
		t.Skip("workspaces are Linux/macOS only")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root, home: filepath.Join(root, "home")}
	e.data = filepath.Join(e.home, ".defenseclaw")
	e.project = filepath.Join(e.home, "code", "myapp")
	mustMkdir(t, e.project)
	mustMkdir(t, e.data)
	return e
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	writeFileMode(t, root, rel, content, 0o644)
}

func writeFileMode(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	mustMkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// git runs a fixture git command with an isolated identity and config.
func (e *env) git(dir string, args ...string) string {
	e.t.Helper()
	return runGit(e.t, e.home, dir, args...)
}

func runGit(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// initRepo makes e.project a git repo with one commit.
func (e *env) initRepo() {
	e.t.Helper()
	e.git(e.project, "init", "-q", "-b", "main")
	writeFile(e.t, e.project, "README.md", "hello\n")
	writeFile(e.t, e.project, ".gitignore", "*.log\nbuild/\n.env\n")
	writeFile(e.t, e.project, "src/app.go", "package main\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "init")
}

func (e *env) mountOpts(name string) MountOptions {
	return MountOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home}
}

func (e *env) snapOpts(name string) SnapshotOptions {
	return SnapshotOptions{Project: e.project, Name: name, DataDir: e.data, Home: e.home}
}

func mountByTarget(p *MountPlan, target string) (Mount, bool) {
	for _, m := range p.Mounts {
		if m.Target == target {
			return m, true
		}
	}
	return Mount{}, false
}

var bg = context.Background()
