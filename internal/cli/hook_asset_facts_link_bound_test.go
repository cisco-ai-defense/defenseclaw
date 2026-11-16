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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// A call that names more links into skill folders than the hook reads is
// reported as cut at once, with the links read so far; the same call below
// the bound reports every link and no cut.
func TestHookAssetFactsReportsACallThatNamesMoreSkillLinksThanItReads(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, "w4"), 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := 0; i < 1100; i++ {
		dir := filepath.Join(root, fmt.Sprintf("ordinary%04d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("w4/l%04d", i)
		if err := os.Symlink(dir, filepath.Join(proj, name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
		names = append(names, name)
	}
	claim := func(count int) assetfacts.Facts {
		raw, err := json.Marshal(map[string]any{
			"tool_name": "Bash", "cwd": proj, "tool_input": map[string]any{"command": "ls -d " + strings.Join(names[:count], " ")},
		})
		if err != nil {
			t.Fatal(err)
		}
		facts, _ := assetfacts.Decode(hookAssetFacts("claudecode", raw))
		return facts
	}
	if facts := claim(len(names)); !facts.SkillLinksTruncated || len(facts.SkillLinks) < 1000 || len(facts.SkillLinks) > 1100 {
		t.Errorf("1100 links: truncated = %t with %d links, want the cut signal and the links read", facts.SkillLinksTruncated, len(facts.SkillLinks))
	}
	if facts := claim(20); facts.SkillLinksTruncated || len(facts.SkillLinks) != 20 {
		t.Errorf("20 links: truncated = %t with %d links, want 20 and no cut", facts.SkillLinksTruncated, len(facts.SkillLinks))
	}
}
