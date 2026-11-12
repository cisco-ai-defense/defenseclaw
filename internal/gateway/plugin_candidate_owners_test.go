// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
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

// Four installed plugins can own one plugin tool name: all four with ordinary
// text allow the call, in the managed and the default configuration, whether
// the text is a line or tens of KiB; a harmful fourth one still blocks.
func TestFourOrdinaryPluginCandidateOwnersAllow(t *testing.T) {
	for name, text := range map[string]string{
		"short": gap0699Plain,
		"large": strings.Repeat(gap0699Plain, 480),
	} {
		t.Run(name, func(t *testing.T) { fourOrdinaryPluginCandidateOwners(t, text) })
	}
}

func fourOrdinaryPluginCandidateOwners(t *testing.T, text string) {
	t.Helper()
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	names := []string{"p", "p_a", "p_a_b", "p_a_b_c"}
	var contents []assetfacts.Content
	for _, name := range names {
		contents = append(contents, assetfacts.Content{Kind: assetfacts.ContentPlugin, Name: name,
			Dir: filepath.Join(t.TempDir(), name), Files: []assetfacts.ContentFile{{Rel: "SKILL.md", Text: text}}})
	}
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_p_a_b_c_d__run", MCPServerName: "plugin_p_a_b_c_d"}
	facts := assetfacts.Facts{Contents: contents}
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, facts); action != "allow" {
		t.Errorf("four ordinary candidate owners blocked: action=%q reason=%q", action, reason)
	}
	if action, reason := gap0699Claude(t, config.DefaultConfig(), req, facts); action != "allow" {
		t.Errorf("default configuration blocked: action=%q reason=%q", action, reason)
	}
	contents[3].Files[0].Text = gap0699Harmful + text
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, assetfacts.Facts{Contents: contents}); action != "block" {
		t.Errorf("harmful fourth candidate allowed: action=%q reason=%q", action, reason)
	}
}

// Every plugin a 64-character tool name can have as owner (23) with an
// ordinary document of tens of KiB each is judged on its text, not refused
// for the size of the claim; the harmful last one still blocks.
func TestMostPluginCandidateOwnersOfOneToolNameAllow(t *testing.T) {
	saved := profileAssetScanApplies
	t.Cleanup(func() { profileAssetScanApplies = saved })
	profileAssetScanApplies = func(*config.Config) bool { return true }
	name, owners := "p", 23
	var contents []assetfacts.Content
	for i := 0; i < owners; i++ {
		if i > 0 {
			name += "_a"
		}
		contents = append(contents, assetfacts.Content{Kind: assetfacts.ContentPlugin, Name: name,
			Dir: filepath.Join(t.TempDir(), name), Files: []assetfacts.ContentFile{{Rel: "SKILL.md", Text: referenceTable(i, 56640)}}})
	}
	tool := "mcp__plugin_" + name + "_z__run"
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: tool, MCPServerName: "plugin_" + name + "_z"}
	facts := assetfacts.Facts{Contents: contents}
	for label, cfg := range map[string]*config.Config{"managed": gap0699Config("claudecode"), "default": config.DefaultConfig()} {
		if action, reason := gap0699Claude(t, cfg, req, facts); action != "allow" {
			t.Errorf("%s: %d ordinary candidate owners blocked: action=%q reason=%q", label, owners, action, reason)
		}
	}
	contents[owners-1].Files[0].Text = gap0699Harmful + contents[owners-1].Files[0].Text
	if action, reason := gap0699Claude(t, gap0699Config("claudecode"), req, assetfacts.Facts{Contents: contents}); action != "block" {
		t.Errorf("harmful last candidate allowed: action=%q reason=%q", action, reason)
	}
}

// referenceTable is an ordinary reference document of about size bytes whose
// rows are random letters, so it hardly shrinks when deflated: the claim of
// the most candidate owners one tool name can have must carry it whole.
func referenceTable(owner, size int) string {
	random := rand.New(rand.NewSource(int64(owner) + 1))
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var doc strings.Builder
	for row := 0; doc.Len() < size-64; row++ {
		line := make([]byte, 40)
		for i := range line {
			line[i] = letters[random.Intn(len(letters))]
		}
		fmt.Fprintf(&doc, "Row %d.%d: %s\n", owner, row, line)
	}
	return doc.String()
}
