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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	if err := os.MkdirAll(filepath.Join(root, "held", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link(filepath.Join(root, "held", "sub"), "lnk-sub")
	link(filepath.Join(root, "ordinary"), "lnk-ordinary-up")
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
		// A parent segment after a link leaves the folder the link leads to.
		"link then parent":          {"Read", "file_path", filepath.Join(proj, "lnk-sub") + "/../SKILL.md"},
		"relative link then parent": {"Read", "file_path", "lnk-sub/../SKILL.md"},
		"shell link then parent":    {"Bash", "command", "cat " + filepath.Join(proj, "lnk-sub") + "/../SKILL.md"},
		"two parents from the sub":  {"Read", "file_path", filepath.Join(proj, "lnk-sub") + "/../../held/SKILL.md"},
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
		// The same spelling through a link to a skill that is not held, and
		// a parent segment that returns to the project.
		"other skill then parent": {"Read", "file_path", filepath.Join(proj, "lnk-ordinary-up") + "/../ordinary/SKILL.md"},
		"parent in the project":   {"Read", "file_path", filepath.Join(proj, "nested", "..", "notes.txt")},
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

// A gateway that cannot enter the project (a service account against a private
// home) judges the folders the hook reports. A held folder is refused whatever
// number of ordinary links come before it in the call, and a call that reaches
// more linked folders than the report can carry is refused as unproven.
func TestReportedSkillLinksAreAllJudged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the project folder cannot be made unreadable here")
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	var paths, targets []string
	for i := 0; i < 70; i++ {
		name := fmt.Sprintf("ordinary-%02d", i)
		if i == 69 {
			name = "held"
		}
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(proj, fmt.Sprintf("link-%02d", i))
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
		paths = append(paths, link+"/SKILL.md")
		targets = append(targets, dir)
	}
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(proj, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(proj, 0o700) })
	api := &APIServer{store: store, logger: logger, scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}}
	decide := func(facts assetfacts.Facts, paths []string) (bool, string) {
		t.Helper()
		claims, _ := assetfacts.Decode(assetfacts.Encode(facts))
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
		ctx = context.WithValue(ctx, claimedAssetFactsContextKey{}, claims)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: proj,
			ToolInput: map[string]interface{}{"command": "cat " + strings.Join(paths, " ")},
		})
		return matched && decision.Action == "block", decision.Reason
	}
	// 20 ordinary links then the held one, all reported: refused for the held one.
	if blocked, _ := decide(assetfacts.Facts{SkillLinks: append(append([]string{}, targets[:20]...), targets[69])}, append(append([]string{}, paths[:20]...), paths[69])); !blocked {
		t.Fatal("a held folder after 20 ordinary linked folders was allowed")
	}
	// All 70 linked folders reported, the held one last: refused, and no cut.
	if blocked, _ := decide(assetfacts.Facts{SkillLinks: targets}, paths); !blocked {
		t.Fatal("a held folder after 69 ordinary linked folders was allowed")
	}
	// Only ordinary folders reported, however many: allowed.
	for _, n := range []int{20, 65, 69} {
		if blocked, reason := decide(assetfacts.Facts{SkillLinks: targets[:n]}, paths[:n]); blocked {
			t.Fatalf("%d ordinary linked folders were refused: %s", n, reason)
		}
	}
	// A report that could not carry every link names a folder that cannot be
	// ruled out while a skill is held: refused as unproven.
	if blocked, _ := decide(assetfacts.Facts{SkillLinks: targets[:20], SkillLinksTruncated: true}, paths[:20]); !blocked {
		t.Fatal("a cut report was allowed while a skill is held")
	}
	// With nothing held or denied no folder can be one, and the same cut
	// report runs the ordinary call.
	if err := enforce.NewPolicyEngine(store).Enable("skill", "held"); err != nil {
		t.Fatal(err)
	}
	if blocked, reason := decide(assetfacts.Facts{SkillLinks: targets[:20], SkillLinksTruncated: true}, paths[:20]); blocked {
		t.Fatalf("a cut report with nothing held or denied was refused: %s", reason)
	}
}

// A gateway that cannot enter the project judges the folder a link leads to by
// the claims the hook sends. A folder named with space that declares a denied
// name is refused through a link as it is directly; a folder named with space
// that declares an ordinary name stays allowed.
func TestReportedSpaceNamedSkillFolderKeepsItsDeclaredName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the project folder cannot be made unreadable here")
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{}
	for _, name := range []string{" ", "  "} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("cannot make this folder name here: %v", err)
		}
		link := filepath.Join(proj, fmt.Sprintf("link-%d", len(name)))
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
		links[name] = link
	}
	if err := os.Chmod(proj, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(proj, 0o700) })
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}
	decide := func(name, declared string) bool {
		t.Helper()
		claims, _ := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{
			SkillLinks: []string{filepath.Join(root, name)}, Skills: []assetfacts.Skill{{Folder: name, Declared: declared}},
		}))
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
		ctx = context.WithValue(ctx, claimedAssetFactsContextKey{}, claims)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: proj,
			ToolInput: map[string]interface{}{"command": "cat " + links[name] + "/SKILL.md"},
		})
		return matched && decision.Action == "block"
	}
	if !decide(" ", "listed-name") {
		t.Fatal("a space-named linked folder declaring a denied name was allowed")
	}
	if decide("  ", "ordinary-skill") {
		t.Fatal("a space-named linked folder declaring an ordinary name was refused")
	}
}

// A gateway that cannot enter the project judges a linked skill folder by the
// claims the hook sends, and a folder whose name holds a tab is carried exactly
// like any other: the ordinary one runs in the balanced default while an
// unrelated skill is denied, and one that declares a denied name or is held is
// refused through the link.
func TestReportedTabNamedSkillFolderIsJudgedByItsClaims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the project folder cannot be made unreadable here")
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	names := []string{"ordinary\tcopy", "listed\tcopy", "held\tcopy"}
	links := map[string]string{}
	for i, name := range names {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("cannot make this folder name here: %v", err)
		}
		link := filepath.Join(proj, fmt.Sprintf("link-%d", i))
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
		links[name] = link
	}
	if err := os.Chmod(proj, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(proj, 0o700) })
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held\tcopy", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}, {Name: "unrelated-denied-skill"}}
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}
	decide := func(name, declared string) bool {
		t.Helper()
		claims, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{
			SkillLinks: []string{filepath.Join(root, name)}, Skills: []assetfacts.Skill{{Folder: name, Declared: declared}},
		}))
		if !ok || claims.SkillLinksTruncated || claims.SkillsTruncated {
			t.Fatalf("%q: claims %+v lost a claim", name, claims)
		}
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
		ctx = context.WithValue(ctx, claimedAssetFactsContextKey{}, claims)
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: proj,
			ToolInput: map[string]interface{}{"command": "cat " + links[name] + "/SKILL.md"},
		})
		return matched && decision.Action == "block"
	}
	if decide("ordinary\tcopy", "ordinary-skill") {
		t.Fatal("a tab-named linked folder declaring an ordinary name was refused")
	}
	if !decide("listed\tcopy", "listed-name") {
		t.Fatal("a tab-named linked folder declaring a denied name was allowed")
	}
	if !decide("held\tcopy", "held-skill") {
		t.Fatal("a held tab-named linked folder was allowed")
	}
}
