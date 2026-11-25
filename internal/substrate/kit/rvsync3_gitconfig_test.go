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

// The actor kit runs in Linux actor images only.
//go:build linux

package kit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// RV-SYNC3 F1 (GAP-0733): config.RewriteGitURL gives the address real git
// uses with the image's /etc/gitconfig (gitConfig) as the system config and
// an admin map written to the actor user's config as WriteGitRewrite does.
func TestRVSync3GitRewriteParityWithGit(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	sys := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(sys, []byte(gitConfig()), 0o644); err != nil {
		t.Fatal(err)
	}
	xdg := filepath.Join(dir, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "XDG_CONFIG_HOME=" + xdg, "GIT_CONFIG_SYSTEM=" + sys}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	admin := []config.SubstrateGitRewrite{
		{From: "git@github.com:", To: "https://ghproxy.example/"}, // a tie with a baked rule
		{From: "ssh://git@", To: "https://sshproxy.example/"},     // a tie with a generic rule
		{From: "git@github.com:corp/", To: "https://ghproxy.example/corp/"},
		{From: "git@ghe.example:", To: "https://ghe.example/"},
		{From: "ssh://git@ghe.example/", To: "https://ghe.example/scm/"},
	}
	inc := filepath.Join(xdg, "git", "defenseclaw-rewrite")
	for _, r := range admin {
		if config.CheckSubstrateGitRewrite(r) == nil {
			git("config", "--file", inc, "--add", "url."+r.To+".insteadOf", r.From)
		}
	}
	git("config", "--file", filepath.Join(xdg, "git", "config"), "--add", "include.path", "defenseclaw-rewrite")
	for _, raw := range []string{
		"git@github.com:o/r.git", "git@github.com:corp/app.git", "git@gitlab.com:o/r.git",
		"git@bitbucket.org:o/r.git", "ssh://git@other.example/o/r.git", "git+ssh://git@h.example/o/r",
		"ssh://git@ghe.example/t/a.git", "git@ghe.example:t/a.git", "git@nomatch.example:o/r",
		"https://github.com/o/r",
	} {
		want := git("ls-remote", "--get-url", raw)
		got, ok := config.RewriteGitURL(raw, admin)
		if !ok {
			got = raw
		}
		if got != want {
			t.Errorf("%s: launcher reads %q, git uses %q", raw, got, want)
		}
	}
}

// RV-SYNC3 F4: the image's generic ssh rules come from
// config.SubstrateGitGenericRewrites, and the image text is unchanged.
func TestRVSync3GitConfigRendersGenericRules(t *testing.T) {
	const want = "# DefenseClaw actor image (root-owned): SSH remotes use HTTPS, credentials are placeholders.\n" +
		"[url \"https://\"]\n\tinsteadOf = ssh://git@\n\tinsteadOf = git+ssh://git@\n" +
		"[url \"https://github.com/\"]\n\tinsteadOf = git@github.com:\n" +
		"[url \"https://gitlab.com/\"]\n\tinsteadOf = git@gitlab.com:\n" +
		"[url \"https://bitbucket.org/\"]\n\tinsteadOf = git@bitbucket.org:\n" +
		"[credential]\n\thelper = " + CredHelper + "\n\tuseHttpPath = false\n" +
		"[http]\n\tsslCAInfo = " + TrustBundle + "\n"
	if got := gitConfig(); got != want {
		t.Fatalf("image git config changed:\n%s", got)
	}
	old := config.SubstrateGitGenericRewrites
	t.Cleanup(func() { config.SubstrateGitGenericRewrites = old })
	config.SubstrateGitGenericRewrites = append(append([]config.SubstrateGitRewrite{}, old...), config.SubstrateGitRewrite{From: "ssh+git://git@", To: "https://"})
	if !strings.Contains(gitConfig(), "\tinsteadOf = ssh+git://git@\n") {
		t.Fatal("gitConfig does not render config.SubstrateGitGenericRewrites")
	}
}
