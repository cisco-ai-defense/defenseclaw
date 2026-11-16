// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// A word with no slash that names an existing link in the working folder is a
// path: every spelling of the link reaches the held skill folder as ./name
// does, for Read, Grep, Glob, shell readers, a link chain and a leading cd, and
// SKILL.md read from inside the held folder is its manifest. Ordinary words
// and the link to a skill that is not held stay allowed.
func TestHeldSkillFolderNamedByABareOperandIsRefused(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"lnk-held":     filepath.Join(root, "held"),
		"lnk-chain":    filepath.Join(proj, "lnk-held"),
		"lnk-ordinary": filepath.Join(root, "ordinary"),
	} {
		if err := os.Symlink(target, filepath.Join(proj, link)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store, logger: logger, scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	decide := func(cwd, tool, key, value string) bool {
		t.Helper()
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: tool, CWD: cwd,
			ToolInput: map[string]interface{}{key: value},
		})
		return matched && decision.Action == "block"
	}
	for name, tc := range map[string]struct{ cwd, tool, key, value string }{
		"bare read":         {proj, "Read", "file_path", "lnk-held"},
		"bare grep":         {proj, "Grep", "path", "lnk-held"},
		"bare glob":         {proj, "Glob", "path", "lnk-held"},
		"bare ls":           {proj, "Bash", "command", "ls lnk-held"},
		"bare recursive":    {proj, "Bash", "command", "grep -r token lnk-held"},
		"bare link chain":   {proj, "Bash", "command", "cat lnk-chain"},
		"leading cd":        {proj, "Bash", "command", "cd lnk-held && ls"},
		"cd then manifest":  {proj, "Bash", "command", "cd lnk-held; cat SKILL.md"},
		"manifest in place": {filepath.Join(root, "held"), "Bash", "command", "cat SKILL.md"},
		"read in place":     {filepath.Join(root, "held"), "Read", "file_path", "SKILL.md"},
	} {
		t.Run(name, func(t *testing.T) {
			if !decide(tc.cwd, tc.tool, tc.key, tc.value) {
				t.Fatalf("%s %s=%q in %s was allowed, want the held skill refused", tc.tool, tc.key, tc.value, tc.cwd)
			}
		})
	}
	for name, tc := range map[string]struct{ cwd, tool, key, value string }{
		"link to another skill": {proj, "Bash", "command", "ls lnk-ordinary"},
		"bare ordinary link":    {proj, "Read", "file_path", "lnk-ordinary"},
		"ordinary file":         {proj, "Bash", "command", "cat notes.txt"},
		"ordinary words":        {proj, "Bash", "command", "echo hello held"},
		"missing word":          {proj, "Bash", "command", "ls nothing-here"},
		"in the other skill":    {filepath.Join(root, "ordinary"), "Bash", "command", "cat SKILL.md"},
	} {
		t.Run("twin "+name, func(t *testing.T) {
			if decide(tc.cwd, tc.tool, tc.key, tc.value) {
				t.Fatalf("%s %s=%q in %s was refused, want it allowed", tc.tool, tc.key, tc.value, tc.cwd)
			}
		})
	}
}

// A managed deployment refuses a call whose links could not all be followed
// while a skill is held, in the default policy tier too; the OSS default
// allows it with a warning, and with nothing held both run the call.
func TestManagedDeploymentRefusesAnUnprovenLinkWhileASkillIsHeld(t *testing.T) {
	for _, row := range []struct {
		name      string
		managed   bool
		held      bool
		wantBlock bool
	}{
		{"managed-held", true, true, true},
		{"managed-nothing-held", true, false, false},
		{"oss-held", false, true, false},
		{"oss-nothing-held", false, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newShareSkillFixture(t, false, row.held, 50*time.Millisecond)
			if row.managed {
				f.api.scannerCfg.DeploymentMode = "managed_enterprise"
				f.api.scannerCfg.Enterprise.Profile = "standalone"
			}
			decision, matched := f.decide("Read", "file_path", filepath.Join(f.projectD, "notes.txt"), assetfacts.Facts{SkillLinksUnproven: true})
			if blocked := matched && decision.Action == "block"; blocked != row.wantBlock {
				t.Fatalf("an unproven claim: blocked=%t, want %t (%+v)", blocked, row.wantBlock, decision)
			}
			if row.wantBlock && decision.Source != "skill-links-unproven" {
				t.Errorf("source = %q, want skill-links-unproven", decision.Source)
			}
		})
	}
}

// A gateway that cannot enter the user's project takes the link claim of the
// standalone hook. The folder a link ends in is judged whichever connector's
// call followed the link: Codex into the Claude Code skill root, and OpenCode,
// which has no skill root list of its own. A claim for a skill that is not
// held, and a call with no claim, stay allowed.
func TestReportedSkillLinkIsJudgedForEveryConnector(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a project folder this process cannot enter")
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".claude", "skills")
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(root, "held"), filepath.Join(root, "ordinary"), proj} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"held", "ordinary"} {
		if err := os.WriteFile(filepath.Join(root, name, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, name), filepath.Join(proj, "lnk-"+name)); err != nil {
			t.Skipf("cannot create a link here: %v", err)
		}
	}
	if err := os.Chmod(proj, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(proj, 0o755) })
	if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store, logger: logger, scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}}
	base := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	for _, connector := range []string{"claudecode", "codex", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			blocked := func(path string, claims assetfacts.Facts) bool {
				t.Helper()
				ctx := context.WithValue(base, claimedAssetFactsContextKey{}, claims)
				var decision config.AssetPolicyDecision
				var matched bool
				switch connector {
				case "claudecode":
					decision, matched = api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", ToolName: "Read", CWD: proj, ToolInput: map[string]interface{}{"file_path": path}})
				case "codex":
					decision, matched = api.codexSkillAssetDecision(ctx, codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "Bash", CWD: proj, ToolInput: map[string]interface{}{"command": "cat " + path}})
				default:
					args, err := json.Marshal(map[string]any{"filePath": path})
					if err != nil {
						t.Fatal(err)
					}
					decision, matched = api.agentHookSkillAssetDecision(ctx, agentHookRequest{
						ConnectorName: connector, HookEventName: "tool.execute.before", ToolName: "read", CWD: proj, ToolArgs: args})
				}
				return matched && decision.Action == "block"
			}
			held := filepath.Join(proj, "lnk-held", "SKILL.md")
			if !blocked(filepath.Join(root, "held", "SKILL.md"), assetfacts.Facts{}) {
				t.Error("the held folder named directly was allowed")
			}
			if !blocked(held, assetfacts.Facts{SkillLinks: []string{filepath.Join(root, "held")}}) {
				t.Error("the held folder reached through a link the hook reported was allowed")
			}
			if blocked(filepath.Join(proj, "lnk-ordinary", "SKILL.md"), assetfacts.Facts{SkillLinks: []string{filepath.Join(root, "ordinary")}}) {
				t.Error("a link to a skill that is not held was refused")
			}
			if blocked(filepath.Join(proj, "notes.txt"), assetfacts.Facts{}) {
				t.Error("a file of the project was refused")
			}
		})
	}
}
