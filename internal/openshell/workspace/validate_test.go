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
	mustMkdir(t, filepath.Join(e.home, ".ssh", "keys"))
	mustMkdir(t, filepath.Join(e.home, ".aws"))
	mustMkdir(t, filepath.Join(e.home, ".config", "nvim"))
	mustMkdir(t, filepath.Join(e.data, "sandboxes"))
	link := filepath.Join(e.home, "code", "link")
	if err := os.Symlink(e.project, link); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.home, "code/file.txt", "x")

	cases := []struct {
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
		{"contains protected", e.root, "contains"},
		{"inside protected", filepath.Join(protected, "inner"), "inside"},
		{"symlinked component", link, "symbolic link"},
		{"missing", filepath.Join(e.home, "code", "nope"), "does not exist"},
		{"file", filepath.Join(e.home, "code", "file.txt"), "not a directory"},
		{"empty", "  ", "no folder"},
		{"control chars", e.project + "\n", "control"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateSource(bg, tc.path, SourceOptions{Home: e.home, DataDir: e.data, Protected: []string{protected}})
			if !errors.Is(err, ErrUnsafeSource) {
				t.Fatalf("ValidateSource(%q) = %v, want ErrUnsafeSource", tc.path, err)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error %q does not mention %q", err, tc.reason)
			}
		})
	}
}

func TestValidateSourceSymlinkHintNamesRealPath(t *testing.T) {
	e := newEnv(t)
	link := filepath.Join(e.home, "proj-link")
	if err := os.Symlink(e.project, link); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateSource(bg, link, SourceOptions{Home: e.home})
	var se *SourceError
	if !errors.As(err, &se) || !strings.Contains(se.Hint, e.project) {
		t.Fatalf("err = %v, want hint naming %s", err, e.project)
	}
}

func TestValidateSourceAcceptsPlainAndGitProjects(t *testing.T) {
	e := newEnv(t)
	src, err := ValidateSource(bg, e.project, SourceOptions{Home: e.home, DataDir: e.data})
	if err != nil {
		t.Fatal(err)
	}
	if src.Path != e.project || src.Git != nil {
		t.Fatalf("plain folder: %+v", src)
	}
	e.initRepo()
	src, err = ValidateSource(bg, e.project, SourceOptions{Home: e.home, DataDir: e.data})
	if err != nil {
		t.Fatal(err)
	}
	if src.Git == nil || src.Git.GitDir != filepath.Join(e.project, ".git") || src.Git.DotGitFile {
		t.Fatalf("git layout: %+v", src.Git)
	}
}

func TestValidateSourceSubfolderOfRepoIsPlainWithWarning(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	sub := filepath.Join(e.project, "src")
	src, err := ValidateSource(bg, sub, SourceOptions{Home: e.home})
	if err != nil {
		t.Fatal(err)
	}
	if src.Git != nil {
		t.Fatal("a subfolder must be treated as a plain folder")
	}
	if len(src.Warnings) == 0 || !strings.Contains(src.Warnings[0], e.project) {
		t.Fatalf("warnings = %v, want the enclosing repository named", src.Warnings)
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
			other := filepath.Join(e.home, "code", "other")
			if err := os.Rename(filepath.Join(e.project, ".git"), filepath.Join(e.home, "code", "gitdir")); err != nil {
				e.t.Fatal(err)
			}
			mustMkdir(e.t, other)
			if err := os.Symlink(filepath.Join(e.home, "code", "gitdir"), filepath.Join(e.project, ".git")); err != nil {
				e.t.Fatal(err)
			}
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
			p := tc.setup(e)
			_, err := ValidateSource(bg, p, SourceOptions{Home: e.home})
			if !errors.Is(err, ErrNeedsCopy) {
				t.Fatalf("err = %v, want ErrNeedsCopy", err)
			}
			if !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "--copy") {
				t.Fatalf("error %q should mention %q and --copy", err, tc.reason)
			}
		})
	}
}

func TestValidateSourceDetectsHostExecutableGitState(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "config", "core.hooksPath", ".husky/_")
	e.git(e.project, "config", "include.path", "../.gitconfig.project")
	writeFile(t, e.project, ".gitconfig.project", "[include]\n\tpath = .git/extra.inc\n")
	// A submodule git dir the agent could otherwise rewrite.
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "objects"))
	mustMkdir(t, filepath.Join(e.project, ".git", "modules", "lib", "refs"))
	writeFile(t, e.project, ".git/modules/lib/HEAD", "ref: refs/heads/main\n")
	writeFile(t, e.project, ".git/modules/lib/config", "[core]\n")

	src, err := ValidateSource(bg, e.project, SourceOptions{Home: e.home})
	if err != nil {
		t.Fatal(err)
	}
	g := src.Git
	if g.HooksPath != filepath.Join(e.project, ".husky", "_") {
		t.Fatalf("HooksPath = %q", g.HooksPath)
	}
	wantIncludes := []string{filepath.Join(e.project, ".gitconfig.project")}
	if len(g.IncludeFiles) < 1 || g.IncludeFiles[0] != wantIncludes[0] {
		t.Fatalf("IncludeFiles = %v, want %v first", g.IncludeFiles, wantIncludes)
	}
	if len(g.Submodules) != 1 || g.Submodules[0] != filepath.Join(e.project, ".git", "modules", "lib") {
		t.Fatalf("Submodules = %v", g.Submodules)
	}
}

func TestValidateSourceAcceptsStaleCommondirPin(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".git/commondir", commondirPin)
	src, err := ValidateSource(bg, e.project, SourceOptions{Home: e.home})
	if err != nil {
		t.Fatal(err)
	}
	if !src.Git.StaleCommondirPin {
		t.Fatal("a leftover commondir pin should be recognized")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
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
	}
	for _, tc := range cases {
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

func TestNamesAndLabels(t *testing.T) {
	for _, bad := range []string{
		"", ".hidden", "-x", "x-", "a/b", "a..b", "x.lock", "x.", strings.Repeat("a", 64), "sp ace",
		// OpenShell refuses these, so no host state may be written for them.
		"A.b_c-1", "Upper", "under_score", "dot.ted",
		// "git" is the shared shadow directory under <data>/snapshots.
		"git",
	} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) accepted", bad)
		} else if !errors.Is(err, openshell.ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want openshell.ErrInvalidName", bad, err)
		}
	}
	for _, good := range []string{"dc-claude-myapp-7f3a", "fix-tests", "a", "0", "gitx", "my-git", strings.Repeat("a", 63)} {
		if err := ValidateName(good); err != nil {
			t.Errorf("ValidateName(%q): %v", good, err)
		}
	}
	k, v := ProjectLabel("/home/u/code/myapp")
	if k != ProjectLabelKey || len(v) != 32 || v != ProjectKey("/home/u/code/myapp/") {
		t.Fatalf("ProjectLabel = %s=%s", k, v)
	}
	if RepoName("/x/My App!") != "My-App" || RepoName("/x/...") != "project" {
		t.Fatalf("RepoName sanitization: %q %q", RepoName("/x/My App!"), RepoName("/x/..."))
	}
}

// TestValidateNameMatchesOpenShell keeps the workspace rule and the one
// OpenShell calls use identical, apart from the reserved layout names:
// a name one accepts and the other refuses would write host state for a
// sandbox that can never be created or addressed.
func TestValidateNameMatchesOpenShell(t *testing.T) {
	names := []string{"", "a", "z9", "-a", "a-", "a--b", "ab.c", "a_b", "AB", "git", "gits", "a b", "a/b", "é",
		strings.Repeat("x", 62), strings.Repeat("x", 63), strings.Repeat("x", 64), "0-0", "dc-copy-1"}
	for _, n := range names {
		_, reserved := reservedNames[n]
		want := openshell.ValidSandboxName(n) && !reserved
		if got := ValidateName(n) == nil; got != want {
			t.Errorf("ValidateName(%q) accepted=%v, openshell.ValidSandboxName=%v reserved=%v", n, got, openshell.ValidSandboxName(n), reserved)
		}
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
	if err := os.Symlink(filepath.Join(dotfiles, "config"), filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
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
