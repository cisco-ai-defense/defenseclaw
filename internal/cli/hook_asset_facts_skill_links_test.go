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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// A linked skill folder whose name is only whitespace is reported by its own
// path and with the name its SKILL.md declares: cleaning must not turn the path
// into its skill root or drop the claim. The names are the ones the file system
// holds: a space, which Windows cannot hold (Win32 drops a trailing space from a
// name), and the no-break and ideographic spaces, which every system holds.
func TestHookAssetFactsReportsASpaceNamedLinkedSkillFolder(t *testing.T) {
	names := []string{"\u00a0", "\u3000"}
	if runtime.GOOS != "windows" {
		names = append(names, " ")
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
	declaredOf := map[string]string{"ordinary": "ordinary-skill"}
	for i, name := range names {
		declaredOf[name] = fmt.Sprintf("listed-name-%d", i)
	}
	var command []string
	for name, declared := range declaredOf {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("cannot make the folder %q: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+declared+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := "lnk-" + declared
		if err := os.Symlink(dir, filepath.Join(proj, link)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
		command = append(command, link+"/SKILL.md")
	}
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": proj, "tool_input": map[string]any{"command": "cat " + strings.Join(command, " ")},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
	if len(facts.SkillLinks) != len(declaredOf) || facts.SkillLinksTruncated || facts.SkillsTruncated {
		t.Fatalf("SkillLinks = %q links_truncated=%t skills_truncated=%t, want one per folder and no signal", facts.SkillLinks, facts.SkillLinksTruncated, facts.SkillsTruncated)
	}
	for name, declared := range declaredOf {
		if !slices.Contains(facts.SkillLinks, filepath.Join(root, name)) {
			t.Errorf("SkillLinks = %q, want %q", facts.SkillLinks, filepath.Join(root, name))
		}
		if got := facts.DeclaredFor(name); len(got) != 1 || got[0] != declared {
			t.Errorf("DeclaredFor(%q) = %q, want %q", name, got, declared)
		}
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

// A link on a network share that answers is followed and the folder it leads to
// is reported; when shares that do not answer have spent the wait the hook call
// has for shares before a share that would have answered is asked, the link
// there is not followed and the claim says so, so the gateway judges the call by
// its policy tier instead of taking the folder for an ordinary one.
func TestHookAssetFactsReportsALinkWalkThatAShareCutShort(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	held := filepath.Join(home, ".claude", "skills", "held")
	live := filepath.Join(home, "live-share")
	dead := []string{filepath.Join(home, "dead-share-1"), filepath.Join(home, "dead-share-2")}
	for _, dir := range append([]string{held, live}, dead...) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(held, filepath.Join(live, "lnk-held")); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	release := make(chan struct{})
	restore := hookpaths.OverrideNetworkSharesForTest(func(path string) string {
		for _, root := range append([]string{live}, dead...) {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				return root
			}
		}
		return ""
	}, func(root string) {
		if strings.TrimRight(root, string(filepath.Separator)) == live {
			time.Sleep(600 * time.Millisecond)
			return
		}
		<-release
	})
	t.Cleanup(func() {
		close(release)
		restore()
	})
	facts := func(command string) assetfacts.Facts {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home, "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
		return decoded
	}
	link := filepath.Join(live, "lnk-held", "SKILL.md")
	// The share was asked by no call yet: this one is cut short, the next finds
	// the answer the share gave.
	got := facts("cat " + filepath.Join(dead[0], "a") + " " + filepath.Join(dead[1], "a") + " " + link)
	if len(got.SkillLinks) != 0 || !got.SkillLinksUnproven {
		t.Errorf("a link on a share the wait was spent before: SkillLinks = %q unproven=%t, want none and the signal", got.SkillLinks, got.SkillLinksUnproven)
	}
	if got = facts("cat " + link); !slices.Equal(got.SkillLinks, []string{held}) || got.SkillLinksUnproven {
		t.Errorf("a link on an answering share: SkillLinks = %q unproven=%t, want [%s] and no signal", got.SkillLinks, got.SkillLinksUnproven, held)
	}
}
