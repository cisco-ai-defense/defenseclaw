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
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodePreservesPinnedMCPWithLargeArguments(t *testing.T) {
	args := make([]string, 7)
	for i := range args {
		args[i] = strings.Repeat("x", 900)
	}
	want := MCPServer{
		Name: "notes", URL: "https://example.test/mcp",
		Command: "server", Args: args, Transport: "http",
	}
	header := Encode(Facts{MCP: &want})
	got, ok := Decode(header)
	if !ok || got.MCP == nil {
		t.Fatalf("MCP facts missing from encoded header")
	}
	if got.MCP.URL != want.URL || got.MCP.Command != want.Command ||
		got.MCP.Transport != want.Transport || len(got.MCP.Args) != len(want.Args) {
		t.Fatalf("pinned MCP facts changed: %#v", got.MCP)
	}
	for i := range args {
		if got.MCP.Args[i] != args[i] {
			t.Fatalf("MCP argument %d changed", i)
		}
	}
}

func TestSkillFolderRefsKeepsDistinctPathsWithSameName(t *testing.T) {
	home := t.TempDir()
	first := filepath.Join(home, ".agents", "skills", "shared")
	second := filepath.Join(home, "project", ".agents", "skills", "shared")
	refs := SkillFolderRefs([]string{
		filepath.Join(first, "SKILL.md"),
		filepath.Join(second, "SKILL.md"),
		filepath.Join(first, "other.md"),
	}, home, home)
	if len(refs) != 2 || refs[0].Dir != first || refs[1].Dir != second {
		t.Fatalf("distinct skill paths were not preserved: %#v", refs)
	}
}

func TestSkillFolderRefsPreservesQuotedPathWithSpaces(t *testing.T) {
	home := filepath.Join(t.TempDir(), "Alice Smith")
	dir := filepath.Join(home, ".codex", "skills", "blocked")
	refs := SkillFolderRefs("cat '"+filepath.Join(dir, "SKILL.md")+"'", home, home)
	if len(refs) != 1 || refs[0].Dir != dir || refs[0].Name != "blocked" {
		t.Fatalf("quoted skill path was not preserved: %#v", refs)
	}
}

func TestSkillFolderRefsResolvesParentBeforeSelectingSkill(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "denied")
	input := filepath.Join(home, ".claude", "skills") + "/benign/../denied/SKILL.md"
	refs := SkillFolderRefs(input, home, home)
	if len(refs) != 1 || refs[0].Dir != dir || refs[0].Name != "denied" {
		t.Fatalf("skill path selected before normalization: %#v", refs)
	}
}

// A read inside a nested skill reaches both skill folders, including the
// inner folder whose own runtime policy may deny access.
func TestSkillFolderRefsIncludesNestedSkill(t *testing.T) {
	home := t.TempDir()
	outer := filepath.Join(home, "skills", "parent")
	inner := filepath.Join(outer, ".agents", "skills", "denied")
	refs := SkillFolderRefs(filepath.Join(inner, "SKILL.md"), home, home)
	if len(refs) != 2 || refs[0].Dir != outer || refs[0].Name != "parent" ||
		refs[1].Dir != inner || refs[1].Name != "denied" {
		t.Fatalf("nested skill folders = %#v", refs)
	}
}

func TestSkillFolderRefsKeepsPathOfLargeMultiEdit(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "blocked")
	edits := make([]any, 40)
	for i := range edits {
		edits[i] = map[string]any{"old_string": "a", "new_string": "b"}
	}
	input := map[string]any{"edits": edits, "file_path": filepath.Join(dir, "SKILL.md")}
	for i := 0; i < 200; i++ {
		refs := SkillFolderRefs(input, home, home)
		if len(refs) != 1 || refs[0].Dir != dir {
			t.Fatalf("run %d: denied skill path dropped: %#v", i, refs)
		}
	}
}
