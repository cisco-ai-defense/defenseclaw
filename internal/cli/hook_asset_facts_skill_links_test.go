// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// The standalone hook runs as the user and follows a link the gateway may not
// be able to, and reports the skill folder it leads to; a call with no link
// into a skill folder reports nothing.
func TestHookAssetFactsReportsTheSkillFolderALinkLeadsTo(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	held := filepath.Join(home, ".claude", "skills", "held")
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{held, proj} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(held, filepath.Join(proj, "lnk-held")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	event := func(path string) []byte {
		raw, err := json.Marshal(map[string]any{
			"tool_name": "Read", "cwd": proj, "tool_input": map[string]any{"file_path": path},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", event("lnk-held/SKILL.md")))
	if len(facts.SkillLinks) != 1 || facts.SkillLinks[0] != held {
		t.Fatalf("SkillLinks = %v, want [%s]", facts.SkillLinks, held)
	}
	// A link into a skills folder that is not a skill root of the connector, a
	// folder reached twice and a parent segment after a link.
	away := filepath.Join(home, "elsewhere", "skills", "thing")
	if err := os.MkdirAll(filepath.Join(held, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(away, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(away, filepath.Join(proj, "lnk-away")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	if err := os.Symlink(filepath.Join(held, "sub"), filepath.Join(proj, "lnk-sub")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	if facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", event("lnk-away/SKILL.md"))); len(facts.SkillLinks) != 0 {
		t.Fatalf("a link outside every skill root: SkillLinks = %v, want none", facts.SkillLinks)
	}
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": proj, "tool_input": map[string]any{"command": "cat lnk-held/SKILL.md lnk-held/other.md lnk-sub/../SKILL.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw)); len(facts.SkillLinks) != 1 || facts.SkillLinks[0] != held {
		t.Fatalf("SkillLinks = %v, want [%s] once", facts.SkillLinks, held)
	}
	for _, path := range []string{filepath.Join(held, "SKILL.md"), filepath.Join(proj, "notes.txt")} {
		if facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", event(path))); len(facts.SkillLinks) != 0 {
			t.Fatalf("%s: SkillLinks = %v, want none", path, facts.SkillLinks)
		}
	}
}

// A linked held folder whose path is long (a deep project or home) is still
// reported: the claim is not cut at the length of an ordinary field.
func TestHookAssetFactsReportsALongLinkedSkillFolderPath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := base
	for len(home)-len(base) < 1200 {
		home = filepath.Join(home, strings.Repeat("d", 200))
	}
	held := filepath.Join(home, ".claude", "skills", "held")
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{held, proj} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("cannot make a path this long here: %v", err)
		}
	}
	if err := os.Symlink(held, filepath.Join(proj, "lnk-held")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Read", "cwd": proj, "tool_input": map[string]any{"file_path": "lnk-held/SKILL.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
	if len(held) <= 1024 || len(facts.SkillLinks) != 1 || facts.SkillLinks[0] != held || facts.SkillLinksTruncated {
		t.Fatalf("held path of %d bytes: SkillLinks = %v truncated=%t, want it reported", len(held), facts.SkillLinks, facts.SkillLinksTruncated)
	}
}

// A linked skill folder whose name is space is reported by its own path and
// with the name its SKILL.md declares: cleaning must not turn the path into
// its skill root or drop the claim.
func TestHookAssetFactsReportsASpaceNamedLinkedSkillFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows drops trailing spaces from a name, so no folder is named space.
		t.Skip("a folder named space cannot exist on Windows")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, declared := range map[string]string{" ": "listed-name", "ordinary": "ordinary-skill"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("cannot make this folder name here: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+declared+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, filepath.Join(proj, "lnk-"+strings.TrimSpace(name)+"x")); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": proj, "tool_input": map[string]any{"command": "cat lnk-x/SKILL.md lnk-ordinaryx/SKILL.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
	spaced, ordinary := filepath.Join(root, " "), filepath.Join(root, "ordinary")
	if len(facts.SkillLinks) != 2 || !slices.Contains(facts.SkillLinks, spaced) || !slices.Contains(facts.SkillLinks, ordinary) || facts.SkillLinksTruncated {
		t.Fatalf("SkillLinks = %q truncated=%t, want %q and %q", facts.SkillLinks, facts.SkillLinksTruncated, spaced, ordinary)
	}
	if got := facts.DeclaredFor(" "); len(got) != 1 || got[0] != "listed-name" {
		t.Fatalf("DeclaredFor(space) = %q, want the declared name", got)
	}
	if got := facts.DeclaredFor("ordinary"); len(got) != 1 || got[0] != "ordinary-skill" {
		t.Fatalf("DeclaredFor(ordinary) = %q, want its declared name", got)
	}
}

// A linked skill folder whose name holds a tab is a valid folder: the hook
// reports its own path and the name its SKILL.md declares, with no loss signal,
// so the gateway can judge the folder the link leads to.
func TestHookAssetFactsReportsATabNamedLinkedSkillFolder(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".claude", "skills", "ordinary\tcopy")
	proj := filepath.Join(home, "proj")
	for _, d := range []string{dir, proj} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Skipf("cannot make this folder name here: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: ordinary-skill\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(proj, "ordinary-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": proj, "tool_input": map[string]any{"command": "cat " + link + "/SKILL.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := assetfacts.Decode(hookAssetFacts("claudecode", raw))
	if !ok || len(facts.SkillLinks) != 1 || facts.SkillLinks[0] != dir || facts.SkillLinksTruncated || facts.SkillsTruncated {
		t.Fatalf("SkillLinks = %q links_truncated=%t skills_truncated=%t, want %q carried with no signal",
			facts.SkillLinks, facts.SkillLinksTruncated, facts.SkillsTruncated, dir)
	}
	if got := facts.DeclaredFor("ordinary\tcopy"); len(got) != 1 || got[0] != "ordinary-skill" {
		t.Fatalf("DeclaredFor(tab name) = %q, want its declared name", got)
	}
}
