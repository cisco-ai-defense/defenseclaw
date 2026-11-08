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
	"os"
	"path/filepath"
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
