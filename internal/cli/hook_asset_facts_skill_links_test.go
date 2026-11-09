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
