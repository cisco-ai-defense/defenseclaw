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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestValidateSourceRefusalMatrix(t *testing.T) {
	e := newEnv(t)
	protected := filepath.Join(e.root, "vault")
	mustMkdir(t, filepath.Join(protected, "inner"))
	for _, h := range []string{".ssh/keys", ".aws", ".config/nvim", ".defenseclaw/sandboxes",
		".claude/skills", ".codex", ".cursor", ".copilot", ".gemini/antigravity", ".agents", ".local/share/opencode"} {
		mustMkdir(t, filepath.Join(e.home, filepath.FromSlash(h)))
	}
	link := filepath.Join(e.home, "code", "link")
	mustSymlink(t, e.project, link)
	writeFile(t, e.home, "code/file.txt", "x")

	for _, tc := range []struct {
		name   string
		path   string
		reason string
	}{
		{"root", "/", "top-level"},
		{"top level", "/tmp", ""},
		{"etc", "/etc", ""},
		{"usr tree", "/usr/local", ""},
		{"home itself", e.home, "home directory"},
		{"contains home", filepath.Dir(e.home), "contains your home"},
		{"ssh", filepath.Join(e.home, ".ssh"), ".ssh"},
		{"inside ssh", filepath.Join(e.home, ".ssh", "keys"), ".ssh"},
		{"aws", filepath.Join(e.home, ".aws"), ".aws"},
		{"inside config", filepath.Join(e.home, ".config", "nvim"), ".config"},
		{"data dir", e.data, ".defenseclaw"},
		{"inside data dir", filepath.Join(e.data, "sandboxes"), ".defenseclaw"},
		// A harness loads its settings and hooks from these on the host.
		{"claude home", filepath.Join(e.home, ".claude"), "~/.claude, which holds an agent's settings"},
		{"inside claude home", filepath.Join(e.home, ".claude", "skills"), "~/.claude"},
		{"codex home", filepath.Join(e.home, ".codex"), "~/.codex"},
		{"cursor home", filepath.Join(e.home, ".cursor"), "~/.cursor"},
		{"copilot home", filepath.Join(e.home, ".copilot"), "~/.copilot"},
		{"antigravity home", filepath.Join(e.home, ".gemini", "antigravity"), "~/.gemini"},
		{"shared agent skills", filepath.Join(e.home, ".agents"), "~/.agents"},
		{"opencode data", filepath.Join(e.home, ".local", "share", "opencode"), "~/.local/share/opencode"},
		{"contains protected", e.root, "contains"},
		{"inside protected", filepath.Join(protected, "inner"), "inside"},
		{"symlinked component", link, "symbolic link"},
		{"missing", filepath.Join(e.home, "code", "nope"), "does not exist"},
		{"file", filepath.Join(e.home, "code", "file.txt"), "not a directory"},
		{"empty", "  ", "no folder"},
		{"control chars", e.project + "\n", "control"},
	} {
		_, err := ValidateSource(bg, tc.path, SourceOptions{Home: e.home, DataDir: e.data, Protected: []string{protected}})
		if !errors.Is(err, ErrUnsafeSource) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: ValidateSource(%q) = %v, want ErrUnsafeSource mentioning %q", tc.name, tc.path, err, tc.reason)
		}
	}
	// The hint for a symlinked folder names the real path.
	_, err := ValidateSource(bg, link, SourceOptions{Home: e.home})
	var se *SourceError
	if !errors.As(err, &se) || !strings.Contains(se.Hint, e.project) {
		t.Fatalf("err = %v, want hint naming %s", err, e.project)
	}
}

// TestValidateSourceAccepts: a plain folder, a git project with the host
// executable git state it has to protect (hooks path, config includes,
// submodule git dirs) and a leftover commondir pin, and a subfolder of a
// repository, which is taken as a plain folder with a warning naming the
// repository.
func TestValidateSourceAccepts(t *testing.T) {
	e := newEnv(t)
	opts := SourceOptions{Home: e.home, DataDir: e.data}
	if src, err := ValidateSource(bg, e.project, opts); err != nil || src.Path != e.project || src.Git != nil {
		t.Fatalf("plain folder: %+v, %v", src, err)
	}
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".husky/_")
	e.git(e.project, "config", "include.path", "../.gitconfig.project")
	writeFile(t, e.project, ".gitconfig.project", "[include]\n\tpath = .git/extra.inc\n")
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "objects"))
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "refs"))
	writeFile(t, e.project, ".git/modules/lib/HEAD", "ref: refs/heads/main\n")
	writeFile(t, e.project, ".git/modules/lib/config", "[core]\n")
	writeFile(t, e.project, ".git/commondir", commondirPin)
	src, err := ValidateSource(bg, e.project, opts)
	if err != nil {
		t.Fatal(err)
	}
	if g := src.Git; g == nil || g.GitDir != filepath.Join(e.project, ".git") || g.DotGitFile || !g.StaleCommondirPin ||
		g.HooksPath != filepath.Join(e.project, ".husky", "_") ||
		len(g.IncludeFiles) < 1 || g.IncludeFiles[0] != filepath.Join(e.project, ".gitconfig.project") ||
		len(g.Submodules) != 1 || g.Submodules[0] != filepath.Join(e.project, ".git", "modules", "lib") {
		t.Fatalf("git layout: %+v", src.Git)
	}
	src, err = ValidateSource(bg, filepath.Join(e.project, "src"), opts)
	if err != nil || src.Git != nil || len(src.Warnings) == 0 || !strings.Contains(src.Warnings[0], e.project) {
		t.Fatalf("subfolder: %+v, %v; want a plain folder with the enclosing repository named", src, err)
	}
}

func TestValidateSourceGitLayoutsThatNeedCopyMode(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(e *env) string
		reason string
	}{
		{"worktree", func(e *env) string {
			e.initRepo()
			wt := filepath.Join(e.home, "code", "wt")
			e.git(e.project, "worktree", "add", "-q", wt)
			return wt
		}, "outside the folder"},
		{"dot git symlink", func(e *env) string {
			e.initRepo()
			if err := os.Rename(filepath.Join(e.project, ".git"), filepath.Join(e.home, "code", "gitdir")); err != nil {
				e.t.Fatal(err)
			}
			mustSymlink(e.t, filepath.Join(e.home, "code", "gitdir"), filepath.Join(e.project, ".git"))
			return e.project
		}, "symbolic link"},
		{"foreign commondir", func(e *env) string {
			e.initRepo()
			writeFile(e.t, e.project, ".git/commondir", "../../elsewhere\n")
			return e.project
		}, "linked worktree"},
		{"core.worktree", func(e *env) string {
			e.initRepo()
			e.git(e.project, "config", "core.worktree", "/tmp")
			return e.project
		}, "core.worktree"},
		{"incomplete git dir", func(e *env) string {
			mustMkdir(e.t, filepath.Join(e.project, ".git"))
			return e.project
		}, "incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			_, err := ValidateSource(bg, tc.setup(e), SourceOptions{Home: e.home})
			if !errors.Is(err, ErrNeedsCopy) || !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "--copy") {
				t.Fatalf("err = %v, want ErrNeedsCopy mentioning %q and --copy", err, tc.reason)
			}
		})
	}
}

func TestMatchGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, rel string
		want         bool
	}{
		{".env", ".env", true},
		{".env", "config/.env", true},
		{".env.*", ".env.local", true},
		{"*.pem", "certs/dev.pem", true},
		{"*.PEM", "certs/dev.pem", true},
		{"certs/*.pem", "certs/dev.pem", true},
		{"certs/*.pem", "other/certs/dev.pem", false},
		{"**/certs/*.pem", "other/certs/dev.pem", true},
		{"config/**/prod.yaml", "config/a/b/prod.yaml", true},
		{"config/**/prod.yaml", "config/prod.yaml", true},
		{".github/workflows/*", ".github/workflows/ci.yml", true},
		{".github/workflows/*", ".github/workflows/sub/ci.yml", false},
		{".idea/**", ".idea/workspace.xml", true},
		{"/secrets.yaml", "secrets.yaml", true},
		{"", "x", false},
	} {
		if got := matchGlob(tc.pattern, tc.rel); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.rel, got, tc.want)
		}
	}
}

func TestSecretNames(t *testing.T) {
	for rel, want := range map[string]bool{
		".env": true, "api/.env.production": true, ".env.example": false, "prod.env": true,
		"certs/dev.pem": true, "id_ed25519": true, "id_ed25519.pub": false, ".npmrc": true,
		"credentials.json": true, "main.go": false, "README.md": false, "terraform.tfstate": true,
	} {
		if _, got := isSecretName(rel); got != want {
			t.Errorf("isSecretName(%q) = %v, want %v", rel, got, want)
		}
	}
}

// TestNamesAndLabels keeps the workspace name rule and the one OpenShell
// calls use identical, apart from the reserved layout names ("git" is the
// shared shadow directory under <data>/snapshots): a name one accepts and
// the other refuses would write host state for a sandbox that can never
// be created or addressed. Refusals are openshell.ErrInvalidName, and no
// refused name reaches a host path.
func TestNamesAndLabels(t *testing.T) {
	bad := []string{"", ".hidden", "-x", "x-", "a/b", "a..b", "x.lock", "x.", strings.Repeat("a", 64), "sp ace",
		"A.b_c-1", "Upper", "under_score", "dot.ted", "git"}
	good := []string{"dc-claude-myapp-7f3a", "fix-tests", "a", "0", "gitx", "my-git", strings.Repeat("a", 63)}
	for _, n := range bad {
		if err := ValidateName(n); !errors.Is(err, openshell.ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want openshell.ErrInvalidName", n, err)
		}
	}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q): %v", n, err)
		}
	}
	for _, n := range append(append(bad, good...), "z9", "a--b", "ab.c", "AB", "gits", "é", strings.Repeat("x", 62), "0-0", "dc-copy-1") {
		_, reserved := reservedNames[n]
		if got, want := ValidateName(n) == nil, openshell.ValidSandboxName(n) && !reserved; got != want {
			t.Errorf("ValidateName(%q) accepted=%v, openshell.ValidSandboxName=%v reserved=%v", n, got, openshell.ValidSandboxName(n), reserved)
		}
	}
	if k, v := ProjectLabel("/home/u/code/myapp"); k != ProjectLabelKey || len(v) != 32 || v != ProjectKey("/home/u/code/myapp/") {
		t.Fatalf("ProjectLabel = %s=%s", k, v)
	}
	if RepoName("/x/My App!") != "My-App" || RepoName("/x/...") != "project" {
		t.Fatalf("RepoName sanitization: %q %q", RepoName("/x/My App!"), RepoName("/x/..."))
	}
}

// TestValidateSourceRefusesXDGAndLinkedConfigDirs: the credential and
// OpenShell state directories are refused wherever they really live (a
// symlinked ~/.config, the XDG base directories, the OpenShell config dir)
// and in both directions: a share may neither be inside one nor contain
// one. Not parallel: it sets XDG variables.
func TestValidateSourceRefusesXDGAndLinkedConfigDirs(t *testing.T) {
	if !platformSupported() {
		t.Skip("workspaces are Linux/macOS only")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	dotfiles := filepath.Join(home, "dotfiles")
	mustMkdir(t, filepath.Join(dotfiles, "config", "nvim"))
	mustMkdir(t, filepath.Join(dotfiles, "notes"))
	mustSymlink(t, filepath.Join(dotfiles, "config"), filepath.Join(home, ".config"))
	xdgConfig, xdgData, xdgState := filepath.Join(root, "xdg", "config"), filepath.Join(root, "xdg-data"), filepath.Join(root, "xdg-state")
	for _, d := range []string{
		filepath.Join(xdgConfig, "openshell"), filepath.Join(xdgConfig, "app"),
		filepath.Join(xdgData, "openshell", "gateways"), filepath.Join(xdgData, "keyrings"), filepath.Join(xdgData, "fonts"),
		filepath.Join(xdgState, "openshell"), filepath.Join(xdgState, "app"),
		filepath.Join(home, ".local", "share", "keyrings"), filepath.Join(home, "code", "app"),
	} {
		mustMkdir(t, d)
	}
	t.Setenv("XDG_CONFIG_HOME", xdgConfig)
	t.Setenv("XDG_DATA_HOME", xdgData)
	t.Setenv("XDG_STATE_HOME", xdgState)

	for _, tc := range []struct {
		path, reason string
	}{
		{filepath.Join(dotfiles, "config", "nvim"), "inside ~/.config"},
		{dotfiles, "contains ~/.config"},
		{filepath.Join(xdgConfig, "app"), "inside " + xdgConfig},
		{filepath.Join(root, "xdg"), "contains " + xdgConfig},
		{filepath.Join(xdgData, "openshell", "gateways"), "inside " + filepath.Join(xdgData, "openshell")},
		{xdgData, "contains " + filepath.Join(xdgData, "keyrings")},
		{filepath.Join(xdgState, "openshell"), "inside " + filepath.Join(xdgState, "openshell")},
		{xdgState, "contains " + filepath.Join(xdgState, "openshell")},
		{filepath.Join(home, ".local"), "contains ~/.local/share/keyrings"},
	} {
		_, _, err := validateShareable(tc.path, SourceOptions{Home: home})
		if !errors.Is(err, ErrUnsafeSource) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: err = %v, want a refusal saying %q", tc.path, err, tc.reason)
		}
	}
	for _, ok := range []string{filepath.Join(home, "code", "app"), filepath.Join(dotfiles, "notes"), filepath.Join(xdgData, "fonts"), filepath.Join(xdgState, "app")} {
		if _, _, err := validateShareable(ok, SourceOptions{Home: home}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	// Relative XDG values are ignored, as the XDG spec says.
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if _, _, err := validateShareable(filepath.Join(home, "code", "app"), SourceOptions{Home: home}); err != nil {
		t.Errorf("relative XDG_CONFIG_HOME: %v", err)
	}
}

// TestOverlaps pins the relation ValidateSource refuses for protected
// paths, as the sandbox manager re-checks it: a path inside the share, the
// share itself, or a folder that holds it, also through a symbolic link.
func TestOverlaps(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	packs := filepath.Join(root, "packs")
	mustMkdir(t, filepath.Join(project, ".defenseclaw"))
	mustMkdir(t, packs)
	link := filepath.Join(root, "link")
	mustSymlink(t, filepath.Join(project, ".defenseclaw"), link)
	for protected, want := range map[string]bool{
		filepath.Join(project, ".defenseclaw", "pack.yaml"): true, // a pack file inside the project
		filepath.Join(project, "later", "pack.yaml"):        true, // one not created yet
		project:                          true, // the project itself
		root:                             true, // a folder holding the project
		filepath.Join(link, "pack.yaml"): true, // a pack reached through a symbolic link into the project
		filepath.Join(packs, "team", "pack.yaml"): false, // a sibling folder
		project + "-other":                        false, // a name that only shares a prefix
		"":                                        false,
	} {
		if got := Overlaps(project, protected); got != want {
			t.Errorf("Overlaps(%s, %s) = %v, want %v", project, protected, got, want)
		}
	}
}
