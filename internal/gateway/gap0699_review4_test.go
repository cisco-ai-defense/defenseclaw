// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func gap0699Config(connector string) *config.Config {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = connector
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	cfg.AssetPolicy.Skill.RuntimeDetection.Enabled = true
	cfg.AssetPolicy.Plugin.RuntimeDetection.Enabled = true
	return cfg
}

func gap0699Context(t *testing.T, facts assetfacts.Facts) context.Context {
	t.Helper()
	header := http.Header{}
	header.Set(assetfacts.Header, assetfacts.Encode(facts))
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: t.TempDir()})
	return withClaimedAssetFacts(ctx, header)
}

func gap0699Claude(t *testing.T, cfg *config.Config, req claudeCodeHookRequest, facts assetfacts.Facts) (string, string) {
	t.Helper()
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	resp := api.evaluateClaudeCodeHook(gap0699Context(t, facts), req)
	return resp.Action, resp.Reason
}

func gap0699ReadSkill(t *testing.T, dir string) assetfacts.Facts {
	t.Helper()
	content, ok := assetfacts.ReadContent(assetfacts.ContentSkill, filepath.Base(dir), dir)
	if !ok {
		t.Fatalf("skill folder %s was not read", dir)
	}
	return assetfacts.Facts{SkillDirs: []string{dir}, Contents: []assetfacts.Content{content}}
}

func gap0699Write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// GAP-0699, GAP-0701 review 4: a verdict on part of a skill is not a verdict
// on the skill. A harmful instruction past the bound the hook can send, and a
// harmful instruction in a linked SKILL.md, are both refused under action-mode
// runtime detection; the ordinary twins (a large reference file, a linked
// skill folder) stay allowed, and the default configuration is unchanged.
func TestGAP0699SkillTextPastTheBoundOrBehindALinkStillGetsAVerdict(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	skillCall := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Skill", ToolInput: map[string]interface{}{"skill": "np10-crit"}}
	base := t.TempDir()
	newSkill := func(name string) string { return filepath.Join(base, name, "skills", "np10-crit") }

	past := newSkill("past")
	gap0699Write(t, filepath.Join(past, "SKILL.md"), "# Notes\n")
	gap0699Write(t, filepath.Join(past, "reference.md"), strings.Repeat("A ordinary line of text\n", 4000)+gap0699Harmful)
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), skillCall, gap0699ReadSkill(t, past)); action != "block" {
		t.Fatalf("harmful text past the bound ran: action=%q reason=%q", action, reason)
	}
	if action, reason := gap0699Claude(t, config.DefaultConfig(), skillCall, gap0699ReadSkill(t, past)); action == "block" {
		t.Fatalf("default configuration refused the same skill: %s", reason)
	}

	large := newSkill("large")
	gap0699Write(t, filepath.Join(large, "SKILL.md"), gap0699Plain)
	gap0699Write(t, filepath.Join(large, "reference.md"), strings.Repeat("A ordinary line of text\n", 1500))
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), skillCall, gap0699ReadSkill(t, large)); action != "allow" {
		t.Fatalf("large ordinary skill: action=%q reason=%q, want it allowed", action, reason)
	}

	target := filepath.Join(base, "instructions.md")
	gap0699Write(t, target, gap0699Harmful)
	linked := newSkill("linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(linked, "SKILL.md")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), skillCall, gap0699ReadSkill(t, linked)); action != "block" {
		t.Fatalf("harmful linked SKILL.md ran: action=%q reason=%q", action, reason)
	}
	gap0699Write(t, target, gap0699Plain)
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), skillCall, gap0699ReadSkill(t, linked)); action != "allow" {
		t.Fatalf("ordinary linked SKILL.md: action=%q reason=%q, want it allowed", action, reason)
	}

	// Content the hook marks as not read in full has no verdict: refused under
	// action-mode runtime detection, open under the default configuration.
	facts := gap0699ReadSkill(t, large)
	facts.Contents[0].Truncated = true
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), skillCall, facts); action != "block" {
		t.Fatalf("truncated content ran: action=%q reason=%q", action, reason)
	}
	if action, reason := gap0699Claude(t, config.DefaultConfig(), skillCall, facts); action == "block" {
		t.Fatalf("default configuration refused truncated content: %s", reason)
	}
}

// A plugin the request names but the hook sent nothing for, as a slash
// command or as plugin:skill, has no verdict and is refused under the same
// config; a plugin with its text sent is judged on it.
func TestGAP0699NamedPluginWithoutContentHasNoVerdict(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	pluginDir := filepath.Join(t.TempDir(), "r109kit")
	plugin := assetfacts.Facts{Contents: []assetfacts.Content{{Kind: assetfacts.ContentPlugin, Name: "r109kit", Dir: pluginDir,
		Files: []assetfacts.ContentFile{{Rel: "skills/notes/SKILL.md", Text: gap0699Plain}}}}}
	calls := map[string]claudeCodeHookRequest{
		"plugin command": {HookEventName: "UserPromptExpansion", ExpansionType: "slash_command", CommandName: "r109kit:notes", CommandSource: "plugin", Prompt: "/r109kit:notes"},
		"plugin skill":   {HookEventName: "PreToolUse", ToolName: "Skill", ToolInput: map[string]interface{}{"skill": "r109kit:notes"}},
	}
	for name, req := range calls {
		t.Run(name, func(t *testing.T) {
			if action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, assetfacts.Facts{}); action != "block" {
				t.Fatalf("named plugin with no content ran: action=%q reason=%q", action, reason)
			}
			if action, reason := gap0699Claude(t, config.DefaultConfig(), req, assetfacts.Facts{}); action == "block" {
				t.Fatalf("default configuration refused a plugin with no content: %s", reason)
			}
			if action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, plugin); action != "allow" {
				t.Fatalf("ordinary plugin with its text sent: action=%q reason=%q, want it allowed", action, reason)
			}
			harmful := assetfacts.Facts{Contents: []assetfacts.Content{plugin.Contents[0]}}
			harmful.Contents[0].Files = []assetfacts.ContentFile{{Rel: "skills/notes/SKILL.md", Text: gap0699Harmful}}
			if action, _ := gap0699Claude(t, gap0699Config("claudecode"), req, harmful); action != "block" {
				t.Fatal("harmful plugin text ran")
			}
		})
	}
}

// GAP-0701: Copilot CLI reports a skill use as a skill tool call. A skill
// created while the service was stopped is judged on its first use after the
// restart, from the text the hook reads; an ordinary Copilot skill stays
// allowed and so does the default configuration.
func TestGAP0701CopilotSkillIsJudgedFromTheHookText(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	dir := filepath.Join(t.TempDir(), ".copilot", "skills", "np10-crit-cp")
	run := func(cfg *config.Config, facts assetfacts.Facts) (config.AssetPolicyDecision, bool) {
		t.Helper()
		store, logger := newNativeSkillRuntimeTestStore(t)
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
		return api.agentHookSkillAssetDecision(gap0699Context(t, facts), agentHookRequest{
			ConnectorName: "copilot", HookEventName: "preToolUse", ToolName: "skill", ToolArgs: json.RawMessage(`{"skill":"np10-crit-cp"}`),
		})
	}
	facts := func(text string) assetfacts.Facts {
		return assetfacts.Facts{SkillDirs: []string{dir}, Contents: []assetfacts.Content{{Kind: assetfacts.ContentSkill, Name: "np10-crit-cp", Dir: dir,
			Files: []assetfacts.ContentFile{{Rel: "SKILL.md", Text: text}}}}}
	}
	if decision, matched := run(gap0699Config("copilot"), facts(gap0699Harmful)); !matched || decision.Action != "block" {
		t.Fatalf("harmful Copilot skill: matched=%v decision=%+v, want a block", matched, decision)
	}
	if decision, matched := run(gap0699Config("copilot"), assetfacts.Facts{SkillDirs: []string{dir}}); !matched || decision.Action != "block" {
		t.Fatalf("Copilot skill the hook sent no text for: matched=%v decision=%+v, want a block", matched, decision)
	}
	if decision, matched := run(gap0699Config("copilot"), facts(gap0699Plain)); matched && decision.Action == "block" {
		t.Fatalf("ordinary Copilot skill refused: %+v", decision)
	}
	if decision, matched := run(config.DefaultConfig(), facts(gap0699Harmful)); matched && decision.Action == "block" {
		t.Fatalf("default configuration refused a Copilot skill: %+v", decision)
	}
}
