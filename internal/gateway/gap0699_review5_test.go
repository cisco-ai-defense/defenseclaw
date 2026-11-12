// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0699 review 5: a tool of a server a Claude Code plugin bundles
// (mcp__plugin_<plugin>_<server>__<tool>) names an owner the gateway cannot
// tell from the name alone. Where it judges the plugin text the hook sends,
// no content for any owner is an unscanned plugin, and the call is refused
// whatever the reason the hook sent none (an unreadable or oversized
// registry); a plugin whose text was sent is judged on it, and the other
// plugins the name could belong to do not refuse it.
func TestGAP0699BundledServerToolWithoutAnOwnerContentIsRefused(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_r109_kit_kit_time__run", MCPServerName: "plugin_r109_kit_kit_time"}
	dir := filepath.Join(t.TempDir(), "r109_kit")
	content := func(text string) assetfacts.Facts {
		return assetfacts.Facts{Contents: []assetfacts.Content{{Kind: assetfacts.ContentPlugin, Name: "r109_kit", Dir: dir,
			Files: []assetfacts.ContentFile{{Rel: "skills/notes/SKILL.md", Text: text}}}}}
	}
	for name, tc := range map[string]struct {
		facts assetfacts.Facts
		block bool
	}{
		"no claim at all (registry unreadable)": {assetfacts.Facts{}, true},
		"the hook's failure state": {assetfacts.Facts{Contents: []assetfacts.Content{
			assetfacts.UnreadContent(assetfacts.ContentPlugin, "plugin_r109_kit_kit_time", "")}}, true},
		"a truncated owner content": {assetfacts.Facts{Contents: []assetfacts.Content{
			assetfacts.UnreadContent(assetfacts.ContentPlugin, "r109_kit", dir)}}, true},
		"harmful owner content":  {content(gap0699Harmful), true},
		"ordinary owner content": {content(gap0699Plain), false},
	} {
		t.Run(name, func(t *testing.T) {
			action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, tc.facts)
			if (action == "block") != tc.block {
				t.Fatalf("action=%q reason=%q, want block=%v", action, reason, tc.block)
			}
			// Twin: the default configuration and observe mode never refuse.
			if action, reason := gap0699Claude(t, config.DefaultConfig(), req, tc.facts); action == "block" {
				t.Fatalf("default configuration refused: %s", reason)
			}
			observe := gap0699Config("claudecode")
			observe.AssetPolicy.Mode = config.AssetPolicyModeObserve
			if action, reason := gap0699Claude(t, observe, req, tc.facts); action == "block" {
				t.Fatalf("observe mode refused: %s", reason)
			}
		})
	}
	// The decision is the same when taken on the plugin path alone.
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{scannerCfg: gap0699Config("claudecode"), store: store, logger: logger}
	if decision, matched := api.claudeCodePluginAssetDecision(gap0699Context(t, assetfacts.Facts{}), req); !matched || decision.Action != "block" {
		t.Fatalf("plugin decision with no owner content: matched=%v decision=%+v", matched, decision)
	}
}
