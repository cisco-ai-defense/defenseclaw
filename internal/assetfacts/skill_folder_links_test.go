// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func linkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
}

func skillTree(t *testing.T) (home, root, held string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(home, ".claude", "skills")
	held = filepath.Join(root, "held")
	if err := os.MkdirAll(held, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "SKILL.md"), []byte("---\nname: held\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, root, held
}

func linkedRef(refs []FolderRef, dir string) (FolderRef, bool) {
	for _, ref := range refs {
		if ref.Dir == dir && ref.Linked {
			return ref, true
		}
	}
	return FolderRef{}, false
}

// A link outside a skills root that leads into a skill folder names that
// folder as the direct path does, whatever the link or the path looks like.
func TestSkillFolderRefsFollowLinksIntoSkillFolders(t *testing.T) {
	home, root, held := skillTree(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, held, filepath.Join(proj, "lnk-held"))
	linkOrSkip(t, filepath.Join(proj, "lnk-held"), filepath.Join(proj, "chain-two"))
	linkOrSkip(t, filepath.Join(proj, "chain-two"), filepath.Join(proj, "chain-three"))
	linkOrSkip(t, root, filepath.Join(proj, "lnk-root"))
	linkOrSkip(t, filepath.Join("..", ".claude", "skills", "held"), filepath.Join(proj, "lnk-relative"))
	linkOrSkip(t, filepath.Join(root, "not-yet"), filepath.Join(proj, "lnk-dangling"))
	linkOrSkip(t, filepath.Join(proj, "dangling-hop"), filepath.Join(proj, "lnk-dangling-chain"))
	linkOrSkip(t, filepath.Join(root, "later"), filepath.Join(proj, "dangling-hop"))
	for name, tc := range map[string]struct {
		input string
		want  string
	}{
		"link":              {filepath.Join(proj, "lnk-held", "SKILL.md"), held},
		"link as folder":    {filepath.Join(proj, "lnk-held"), held},
		"two links":         {filepath.Join(proj, "chain-two", "SKILL.md"), held},
		"three links":       {filepath.Join(proj, "chain-three", "SKILL.md"), held},
		"link to the root":  {filepath.Join(proj, "lnk-root", "held", "SKILL.md"), held},
		"relative link":     {filepath.Join(proj, "lnk-relative", "SKILL.md"), held},
		"relative path":     {"lnk-held/SKILL.md", held},
		"parent segment":    {filepath.Join(proj, "chain-two", "..", "lnk-held", "SKILL.md"), held},
		"missing file":      {filepath.Join(proj, "lnk-held", "nested", "missing.txt"), held},
		"dangling link":     {filepath.Join(proj, "lnk-dangling", "SKILL.md"), filepath.Join(root, "not-yet")},
		"dangling chain":    {filepath.Join(proj, "lnk-dangling-chain", "SKILL.md"), filepath.Join(root, "later")},
		"in a command line": {"cat " + filepath.Join(proj, "lnk-held", "SKILL.md"), held},
	} {
		t.Run(name, func(t *testing.T) {
			refs := SkillFolderRefs(map[string]any{"command": tc.input}, home, proj)
			ref, ok := linkedRef(refs, tc.want)
			if !ok {
				t.Fatalf("refs = %#v, want a linked ref to %s", refs, tc.want)
			}
			if ref.Name != filepath.Base(tc.want) {
				t.Fatalf("name = %q", ref.Name)
			}
		})
	}
}

// A link that leads nowhere near a skill folder, a path with no link and a
// path that cannot be examined add no reference: the spelling is judged as it
// was before.
func TestSkillFolderRefsAddNothingForOrdinaryLinks(t *testing.T) {
	home, _, _ := skillTree(t)
	proj := filepath.Join(home, "proj")
	other := filepath.Join(home, "elsewhere")
	for _, dir := range []string{proj, other} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	linkOrSkip(t, other, filepath.Join(proj, "lnk-other"))
	linkOrSkip(t, filepath.Join(proj, "loop-b"), filepath.Join(proj, "loop-a"))
	linkOrSkip(t, filepath.Join(proj, "loop-a"), filepath.Join(proj, "loop-b"))
	for _, input := range []string{
		filepath.Join(proj, "lnk-other", "notes.txt"),
		filepath.Join(proj, "plain.txt"),
		filepath.Join(proj, "loop-a", "SKILL.md"),
		filepath.Join(home, "no", "such", "tree", "file"),
		"cat lnk-other/notes.txt | wc -l",
	} {
		if refs := SkillFolderRefs(map[string]any{"command": input}, home, proj); len(refs) != 0 {
			t.Fatalf("%q: refs = %#v, want none", input, refs)
		}
	}
}

// A link to a skill folder of another name keeps the name it leads to, so a
// call that reaches an allowed skill through a link is judged as that skill.
func TestSkillFolderRefsLinkToAnotherSkillKeepsItsName(t *testing.T) {
	home, root, _ := skillTree(t)
	ok := filepath.Join(root, "ordinary")
	if err := os.MkdirAll(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	linkOrSkip(t, ok, filepath.Join(proj, "lnk-ordinary"))
	refs := SkillFolderRefs(filepath.Join(proj, "lnk-ordinary", "SKILL.md"), home, proj)
	if len(refs) != 1 || refs[0].Name != "ordinary" || refs[0].Dir != ok || !refs[0].Linked {
		t.Fatalf("refs = %#v, want only the ordinary skill", refs)
	}
}

// A parent segment after a link leaves the folder the link leads to, so the
// raw spelling reaches a different folder than its cleaned form. The cleaned
// spelling is not what the filesystem opens.
func TestSkillFolderRefsFollowLinkThenParentSegment(t *testing.T) {
	home, root, held := skillTree(t)
	sub := filepath.Join(held, "sub")
	other := filepath.Join(root, "ordinary")
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{sub, other, proj, filepath.Join(proj, "plain")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	linkOrSkip(t, sub, filepath.Join(proj, "via-sub"))
	linkOrSkip(t, filepath.Join(proj, "via-sub"), filepath.Join(proj, "via-chain"))
	linkOrSkip(t, other, filepath.Join(proj, "via-other"))
	sep := string(filepath.Separator)
	for name, tc := range map[string]string{
		"absolute":      proj + sep + "via-sub" + sep + ".." + sep + "SKILL.md",
		"relative":      "via-sub" + sep + ".." + sep + "SKILL.md",
		"through chain": proj + sep + "via-chain" + sep + ".." + sep + "SKILL.md",
		"in a command":  "cat " + proj + sep + "via-sub" + sep + ".." + sep + "SKILL.md",
		"dot first":     proj + sep + "." + sep + "via-sub" + sep + ".." + sep + "SKILL.md",
	} {
		t.Run(name, func(t *testing.T) {
			refs := SkillFolderRefs(map[string]any{"command": tc}, home, proj)
			if _, ok := linkedRef(refs, held); !ok {
				t.Fatalf("refs = %#v, want a linked ref to %s", refs, held)
			}
		})
	}
	// A benign twin: the same shape through a link to another skill reaches the
	// folder that skill sits in, and a parent segment inside the project reaches
	// no skill folder at all.
	if refs := SkillFolderRefs(proj+sep+"via-other"+sep+".."+sep+"ordinary"+sep+"SKILL.md", home, proj); len(refs) != 1 || refs[0].Name != "ordinary" {
		t.Fatalf("refs = %#v, want only the ordinary skill", refs)
	}
	if refs := SkillFolderRefs(proj+sep+"plain"+sep+".."+sep+"notes.txt", home, proj); len(refs) != 0 {
		t.Fatalf("refs = %#v, want none", refs)
	}
}

// The linked folders a claim carries are bounded far past an ordinary call, a
// folder past a bound or one the claim cannot carry is never dropped without
// the signal, and a long valid path is carried.
func TestSkillLinksPastTheBoundAreSignalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture paths are not absolute here")
	}
	sep := string(filepath.Separator)
	skills := filepath.Join(sep, "home", "u", ".claude", "skills")
	var dirs []string
	for i := 0; i < maxSkillLinks+6; i++ {
		dirs = append(dirs, filepath.Join(skills, fmt.Sprintf("s%05d", i)))
	}
	facts, ok := Decode(Encode(Facts{SkillLinks: dirs}))
	if !ok || len(facts.SkillLinks) != maxSkillLinks || !facts.SkillLinksTruncated {
		t.Fatalf("ok=%t links=%d truncated=%t, want %d links and the signal", ok, len(facts.SkillLinks), facts.SkillLinksTruncated, maxSkillLinks)
	}
	facts, ok = Decode(Encode(Facts{SkillLinks: dirs[:65]}))
	if !ok || len(facts.SkillLinks) != 65 || facts.SkillLinksTruncated {
		t.Fatalf("ok=%t links=%d truncated=%t, want 65 links and no signal", ok, len(facts.SkillLinks), facts.SkillLinksTruncated)
	}
	long := filepath.Join(sep, "home", "u", strings.Repeat("d", 1200), ".claude", "skills", "held")
	facts, ok = Decode(Encode(Facts{SkillLinks: []string{long}}))
	if !ok || len(facts.SkillLinks) != 1 || facts.SkillLinks[0] != long || facts.SkillLinksTruncated {
		t.Fatalf("a %d byte path: ok=%t links=%d truncated=%t, want it carried", len(long), ok, len(facts.SkillLinks), facts.SkillLinksTruncated)
	}
	// A path the claim cannot carry (past the bound of one path, or text that
	// is not a path) is signalled, with the ones it can carry kept.
	for name, bad := range map[string]string{
		"past the path bound": filepath.Join(sep, "home", strings.Repeat("d", maxSkillLinkPathBytes), "held"),
		"control character":   filepath.Join(sep, "home", "u", "sk\x01ll"),
		"not absolute":        "skills/held",
	} {
		facts, ok = Decode(Encode(Facts{SkillLinks: []string{dirs[0], bad}}))
		if !ok || len(facts.SkillLinks) != 1 || !facts.SkillLinksTruncated {
			t.Fatalf("%s: ok=%t links=%d truncated=%t, want one link and the signal", name, ok, len(facts.SkillLinks), facts.SkillLinksTruncated)
		}
	}
}

func TestResolveLinksKeepsMissingTail(t *testing.T) {
	home, _, held := skillTree(t)
	linkOrSkip(t, held, filepath.Join(home, "lnk"))
	want := filepath.Join(held, "a", "b")
	if got := ResolveLinks(filepath.Join(home, "lnk", "a", "b")); got != want {
		t.Fatalf("ResolveLinks = %q, want %q", got, want)
	}
	missing := filepath.Join(home, "none", "x")
	if got := ResolveLinks(missing); got != missing {
		t.Fatalf("ResolveLinks(%q) = %q, want it unchanged", missing, got)
	}
}
