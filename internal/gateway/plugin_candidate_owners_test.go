// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A plugin tool name that two installed plugins can own is judged on the text
// of every candidate the hook sends: a harmful candidate refuses the call, and
// two ordinary ones allow it.
func TestAmbiguousPluginServerIsJudgedOnEveryCandidateOwnerText(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_r109_kit_time__run", MCPServerName: "plugin_r109_kit_time"}
	content := func(name, text string) assetfacts.Content {
		return assetfacts.Content{Kind: assetfacts.ContentPlugin, Name: name, Dir: filepath.Join(t.TempDir(), name),
			Files: []assetfacts.ContentFile{{Rel: "skills/notes/SKILL.md", Text: text}}}
	}
	for name, tc := range map[string]struct {
		facts assetfacts.Facts
		block bool
	}{
		"harmful short-name owner": {assetfacts.Facts{Contents: []assetfacts.Content{content("r109", gap0699Harmful), content("r109_kit", gap0699Plain)}}, true},
		"harmful long-name owner":  {assetfacts.Facts{Contents: []assetfacts.Content{content("r109", gap0699Plain), content("r109_kit", gap0699Harmful)}}, true},
		"both ordinary":            {assetfacts.Facts{Contents: []assetfacts.Content{content("r109", gap0699Plain), content("r109_kit", gap0699Plain)}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, tc.facts)
			if (action == "block") != tc.block {
				t.Fatalf("action=%q reason=%q, want block=%v", action, reason, tc.block)
			}
			if action, reason := gap0699Claude(t, config.DefaultConfig(), req, tc.facts); action == "block" {
				t.Fatalf("default configuration refused: %s", reason)
			}
		})
	}
}
