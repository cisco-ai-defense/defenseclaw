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

package sandboxcli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostGitConfigReadsTheRepositoryFirst runs the host's git: the
// repository's own identity wins over the user's, and an unset key or a
// folder outside any repository reads as the user's value or "".
func TestHostGitConfigReadsTheRepositoryFirst(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	global := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(global, []byte("[user]\n\tname = Global Name\n\temail = global@example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"GIT_CONFIG_GLOBAL=" + global, "GIT_CONFIG_NOSYSTEM=1", "HOME=" + root, "PATH=" + os.Getenv("PATH")}
	repo := filepath.Join(root, "repo")
	plain := filepath.Join(root, "plain")
	for _, d := range []string{repo, plain} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "repo@example.org"}} {
		cmd := exec.Command(git, append([]string{"-C", repo}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	a := &App{LookPath: exec.LookPath, Environ: func() []string { return env }}
	ctx := context.Background()
	for _, tc := range []struct{ dir, key, want string }{
		{repo, "user.email", "repo@example.org"},
		{repo, "user.name", "Global Name"},
		{plain, "user.email", "global@example.org"},
		{repo, "user.signingkey", ""},
	} {
		if got := a.hostGitConfig(ctx, tc.dir, tc.key); got != tc.want {
			t.Errorf("hostGitConfig(%s, %s) = %q, want %q", filepath.Base(tc.dir), tc.key, got, tc.want)
		}
	}
	missing := &App{LookPath: func(string) (string, error) { return "", exec.ErrNotFound }, Environ: func() []string { return env }}
	if got := missing.hostGitConfig(ctx, repo, "user.email"); got != "" {
		t.Fatalf("without git = %q", got)
	}
}
