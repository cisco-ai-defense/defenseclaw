// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A parent step after a link is read by the file system: project/lnk/.. is
// the folder lnk points out of. A directory without a parent step keeps the
// spelling the caller reached it by, and one that cannot be resolved is
// cleaned as text.
func TestPlaceDirectoryReadsAParentStepAfterALinkByTheFileSystem(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "lnk")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project, filepath.Join(root, "proj-alias")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, base, dir, want string }{
		{"absolute through a link", "", project + "/lnk/..", home},
		{"absolute with a dot", "", project + "/lnk/../.", home},
		{"relative through a link", project, "lnk/..", home},
		{"relative through a link, deeper", project, "lnk/../proj/sub/..", filepath.Join(home, "proj")},
		{"absolute workdir over a base", project, project + "/lnk/..", home},
		{"parent step without a link", project, "sub/..", project},
		{"plain relative", project, "sub", filepath.Join(project, "sub")},
		{"a link without a parent step keeps its spelling", "", filepath.Join(root, "proj-alias"), filepath.Join(root, "proj-alias")},
		{"missing folder is cleaned as text", project, "missing/..", project},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := PlaceDirectory(c.base, c.dir); got != c.want {
				t.Fatalf("PlaceDirectory(%q, %q) = %q, want %q", c.base, c.dir, got, c.want)
			}
		})
	}
}

// Codex cleans an exec_command workdir as text before it starts the process,
// so lnk/.. is the folder that holds lnk, whatever lnk is; another agent
// hands the spelling to the file system (PlaceDirectory).
func TestCleanedDirectoryIsTheTextCleanUpCodexAppliesToAWorkdir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "lnk")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, base, dir, want string }{
		{"relative through a link", project, "lnk/..", project},
		{"absolute through a link", project, project + "/lnk/..", project},
		{"plain relative", home, "proj", project},
		{"leading parent step", project, "../proj", project},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := CleanedDirectory(c.base, c.dir); got != c.want {
				t.Fatalf("CleanedDirectory(%q, %q) = %q, want %q", c.base, c.dir, got, c.want)
			}
		})
	}
	if !WorkdirCleanedByAgent("codex") || !WorkdirCleanedByAgent(" Codex ") {
		t.Fatal("Codex cleans its workdir as text")
	}
	for _, other := range []string{"claudecode", "cursor", "amp", ""} {
		if WorkdirCleanedByAgent(other) {
			t.Fatalf("%q hands its directory to the file system", other)
		}
	}
}
