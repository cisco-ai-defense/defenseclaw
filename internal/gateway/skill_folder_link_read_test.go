// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// A skill admission blocked and disabled whose quarantine failed stays in its
// folder. A tool call that reaches the folder through a link anywhere on disk
// is refused as the direct path is; a link to a skill that is not held, and
// a call that names no skill folder, stay allowed.
func TestHeldSkillFolderReadThroughALinkIsRefused(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	for _, name := range []string{"held", "ordinary"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	link := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(proj, name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	link(filepath.Join(root, "held"), "lnk-held")
	link(filepath.Join(proj, "lnk-held"), "lnk-chain")
	link(root, "lnk-root")
	link(filepath.Join(root, "ordinary"), "lnk-ordinary")
	link(filepath.Join(root, "held-later"), "lnk-dangling")
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held-later", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store, logger: logger, scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	decide := func(tool, key, value string) bool {
		t.Helper()
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: tool, CWD: proj,
			ToolInput: map[string]interface{}{key: value},
		})
		return matched && decision.Action == "block"
	}
	for name, tc := range map[string]struct{ tool, key, value string }{
		"direct read":     {"Read", "file_path", filepath.Join(root, "held", "SKILL.md")},
		"link read":       {"Read", "file_path", filepath.Join(proj, "lnk-held", "SKILL.md")},
		"link as folder":  {"Glob", "path", filepath.Join(proj, "lnk-held")},
		"chain read":      {"Read", "file_path", filepath.Join(proj, "lnk-chain", "SKILL.md")},
		"root link read":  {"Read", "file_path", filepath.Join(proj, "lnk-root", "held", "SKILL.md")},
		"relative read":   {"Read", "file_path", "lnk-held/SKILL.md"},
		"shell reader":    {"Bash", "command", "cat lnk-held/SKILL.md"},
		"shell after cd":  {"Bash", "command", "cd " + proj + " && head -n 3 lnk-chain/SKILL.md"},
		"dangling link":   {"Read", "file_path", filepath.Join(proj, "lnk-dangling", "SKILL.md")},
		"grep in the dir": {"Grep", "path", filepath.Join(proj, "lnk-held")},
	} {
		t.Run(name, func(t *testing.T) {
			if !decide(tc.tool, tc.key, tc.value) {
				t.Fatalf("%s %s=%q was allowed, want the held skill refused", tc.tool, tc.key, tc.value)
			}
		})
	}
	for name, tc := range map[string]struct{ tool, key, value string }{
		"link to another skill": {"Read", "file_path", filepath.Join(proj, "lnk-ordinary", "SKILL.md")},
		"direct other skill":    {"Read", "file_path", filepath.Join(root, "ordinary", "SKILL.md")},
		"project file":          {"Read", "file_path", filepath.Join(proj, "notes.txt")},
		"shell in the project":  {"Bash", "command", "ls -la " + proj},
	} {
		t.Run(name, func(t *testing.T) {
			if decide(tc.tool, tc.key, tc.value) {
				t.Fatalf("%s %s=%q was refused, want it allowed", tc.tool, tc.key, tc.value)
			}
		})
	}
}

// A link whose folder a gateway cannot enter is followed by the standalone
// hook, which reports where it ends; the gateway takes the report only for a
// folder directly in a skill root of the connector.
func TestReportedSkillLinksAreTakenOnlyInASkillRoot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "home", "fixture", ".claude", "skills")
	inRoot := filepath.Join(root, "held")
	refs := []assetfacts.FolderRef{{Dir: inRoot, Name: "held"}}
	got := appendReportedSkillLinks(refs, []string{
		inRoot,
		filepath.Join(root, "other"),
		filepath.Join(root, "other", "nested"),
		filepath.Join(string(filepath.Separator), "tmp", "skills", "held"),
	}, []string{root})
	if len(got) != 2 || got[0].Dir != inRoot || got[1].Dir != filepath.Join(root, "other") || got[1].Name != "other" || !got[1].Linked {
		t.Fatalf("refs = %#v, want the folder in the root added once", got)
	}
}
