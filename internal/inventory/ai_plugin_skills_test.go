// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pluginSkillFacts(t *testing.T, home string) (map[string]AISkillFacts, map[string]string) {
	t.Helper()
	catalog := []AISignature{
		{ID: "claudecode", Vendor: "Anthropic", Category: SignalSupportedConnector, SupportedConnector: "claudecode"},
		{ID: "codex", Vendor: "OpenAI", Category: SignalSupportedConnector, SupportedConnector: "codex"},
		{ID: "copilot", Vendor: "GitHub", Category: SignalSupportedConnector, SupportedConnector: "copilot"},
		{ID: "cursor", Vendor: "Anysphere", Category: SignalSupportedConnector, SupportedConnector: "cursor"},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	facts, keys := map[string]AISkillFacts{}, map[string]string{}
	for _, signal := range svc.detectSkills() {
		for _, ev := range signal.Evidence {
			if ev.Skill != nil {
				facts[signal.SignatureID+"/"+ev.Basename] = *ev.Skill
				key := signal.SignatureID + "/" + ev.Basename
				keys[key+"#fingerprint"] = signal.Fingerprint
				keys[key+"#evidence"] = signal.EvidenceHash
				keys[key+"#paths"] = strings.Join(signal.PathHashes, "|")
				keys[key+"#entry"] = ev.PathHash
				for _, row := range signal.Evidence {
					if row.Type == "skill" {
						keys[signal.SignatureID+"/"+ev.Basename] = row.PathHash
					}
				}
			}
		}
	}
	return facts, keys
}

func writeClaudeRegistry(t *testing.T, home string, installs map[string]string) {
	t.Helper()
	plugins := map[string]any{}
	for id, dir := range installs {
		plugins[id] = []map[string]string{{"scope": "user", "installPath": dir, "version": filepath.Base(dir)}}
	}
	data, _ := json.Marshal(map[string]any{"version": 2, "plugins": plugins})
	writeSkillFiles(t, home, map[string]string{".claude/plugins/installed_plugins.json": string(data)})
}

func TestDetectPluginSkillsFromTheAgentsRegistries(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, ".claude", "plugins", "cache", "official", "pr-review")
	writeSkillFiles(t, home, map[string]string{
		".claude/plugins/cache/official/pr-review/1.0.1/.claude-plugin/plugin.json": `{"version":"1.0.1","author":{"name":"Anthropic","email":"a@example.com"}}`,
		".claude/plugins/cache/official/pr-review/1.0.1/skills/review/SKILL.md":     "---\nname: review\nauthor: Someone\n---\n",
		".claude/plugins/cache/official/pr-review/0.9.0/skills/old/SKILL.md":        "stale version",
		".claude/settings.json": `{"enabledPlugins":{"pr-review@official":false}}`,
		".codex/config.toml":    "model = \"x\"\n[plugins.\"teams@openai-curated\"]\nenabled = true\n",
		".codex/plugins/cache/openai-curated/teams/11c74d6b/.codex-plugin/plugin.json":      `{"author":{"name":"OpenAI"}}`,
		".codex/plugins/cache/openai-curated/teams/11c74d6b/skills/teams-messages/SKILL.md": "x",
		".codex/plugins/cache/openai-curated/unlisted/1.0/skills/ghost/SKILL.md":            "not installed",
		".copilot/installed-plugins/market/tools/plugin.json":                               `{"version":"2.0.0","author":"Jane Doe"}`,
		".copilot/installed-plugins/market/tools/skills/lint/SKILL.md":                      "---\nname: lint\n---\n",
		"outside/skills/escape/SKILL.md":                                                    "must not be read",
	})
	writeClaudeRegistry(t, home, map[string]string{
		"pr-review@official": filepath.Join(cache, "1.0.1"),
		"escape@official":    filepath.Join(home, "outside"),
	})
	facts, keys := pluginSkillFacts(t, home)
	disabled, enabled := false, true
	for key, want := range map[string]AISkillPlugin{
		"claudecode/review":    {ID: "pr-review@official", Version: "1.0.1", Author: "Anthropic", Enabled: &disabled},
		"codex/teams-messages": {ID: "teams@openai-curated", Version: "11c74d6b", Author: "OpenAI", Enabled: &enabled},
		"copilot/lint":         {ID: "tools@market", Version: "2.0.0", Author: "Jane Doe"},
	} {
		got, ok := facts[key]
		if !ok || got.Scope != SkillScopePlugin || got.Plugin == nil || got.ContentStatus != SkillContentOK {
			t.Fatalf("%s = %+v", key, got)
		}
		plugin := *got.Plugin
		if plugin.ID != want.ID || plugin.Version != want.Version || plugin.Author != want.Author ||
			(plugin.Enabled == nil) != (want.Enabled == nil) || (plugin.Enabled != nil && *plugin.Enabled != *want.Enabled) {
			t.Errorf("%s plugin = %+v, want %+v", key, plugin, want)
		}
	}
	if facts["claudecode/review"].Author != "Someone" {
		t.Errorf("SKILL.md author = %q", facts["claudecode/review"].Author)
	}
	if !realDirsBelow(home, ".claude/plugins/cache/official/pr-review/1.0.1/.claude-plugin/plugin.json") || realDirsBelow(home, "missing/plugin.json") {
		t.Error("realDirsBelow must accept real folders and refuse missing ones")
	}
	for _, key := range []string{"claudecode/old", "codex/ghost", "claudecode/escape"} {
		if _, ok := facts[key]; ok {
			t.Errorf("%s must not be reported", key)
		}
	}

	// An upgrade keeps the key the skill's id is built from.
	writeSkillFiles(t, home, map[string]string{".claude/plugins/cache/official/pr-review/1.0.2/skills/review/SKILL.md": "new"})
	writeClaudeRegistry(t, home, map[string]string{"pr-review@official": filepath.Join(cache, "1.0.2")})
	upgraded, upgradedKeys := pluginSkillFacts(t, home)
	if upgradedKeys["claudecode/review"] != keys["claudecode/review"] || upgraded["claudecode/review"].ContentHash == facts["claudecode/review"].ContentHash {
		t.Fatalf("upgrade: key %q -> %q, hash unchanged %v", keys["claudecode/review"], upgradedKeys["claudecode/review"],
			upgraded["claudecode/review"].ContentHash == facts["claudecode/review"].ContentHash)
	}
	for _, field := range []string{"#fingerprint", "#paths", "#entry"} {
		key := "claudecode/review" + field
		if upgradedKeys[key] == "" || upgradedKeys[key] != keys[key] {
			t.Errorf("plugin upgrade changed %s: %q -> %q", field, keys[key], upgradedKeys[key])
		}
	}
	if upgradedKeys["claudecode/review#evidence"] == keys["claudecode/review#evidence"] {
		t.Error("plugin content change did not update the evidence hash")
	}
	writeSkillFiles(t, home, map[string]string{".claude/settings.json": `{"enabledPlugins":{"pr-review@official":true}}`})
	metadataChanged, metadataKeys := pluginSkillFacts(t, home)
	if metadataChanged["claudecode/review"].ContentHash != upgraded["claudecode/review"].ContentHash ||
		metadataKeys["claudecode/review#fingerprint"] != upgradedKeys["claudecode/review#fingerprint"] ||
		metadataKeys["claudecode/review#evidence"] == upgradedKeys["claudecode/review#evidence"] {
		t.Fatal("changing the plugin's enabled state must update the evidence without replacing the skill identity")
	}
}

func TestDetectCursorPluginSkillsAndManifestFolders(t *testing.T) {
	home := t.TempDir()
	extra := filepath.Join(home, ".claude", "plugins", "cache", "official", "extra", "1.0")
	writeSkillFiles(t, home, map[string]string{
		".cursor/plugins/cache/market/notes/aaa111/.cache-complete":            "",
		".cursor/plugins/cache/market/notes/aaa111/.cursor-plugin/plugin.json": `{"version":"1.2.0","author":{"name":"Acme"},"skills":"./custom"}`,
		".cursor/plugins/cache/market/notes/aaa111/custom/summarize/SKILL.md":  "x",
		".cursor/plugins/cache/market/notes/aaa111/skills/unused/SKILL.md":     "the manifest folder replaces skills/",
		".cursor/plugins/cache/market/notes/bbb222/skills/partial/SKILL.md":    "an unfinished download",
		".cursor/plugins/local/mine/skills/draft/SKILL.md":                     "x",
		".claude/plugins/cache/official/extra/1.0/.claude-plugin/plugin.json":  `{"skills":["./more","../escape"]}`,
		".claude/plugins/cache/official/extra/1.0/skills/base/SKILL.md":        "x",
		".claude/plugins/cache/official/extra/1.0/more/added/SKILL.md":         "x",
		".claude/plugins/cache/official/extra/escape/outside/SKILL.md":         "must not be read",
	})
	writeClaudeRegistry(t, home, map[string]string{"extra@official": extra})
	facts, _ := pluginSkillFacts(t, home)
	for key, id := range map[string]string{
		"cursor/summarize": "notes@market", "cursor/draft": "mine@local", "claudecode/base": "extra@official", "claudecode/added": "extra@official",
	} {
		if got := facts[key]; got.Scope != SkillScopePlugin || got.Plugin == nil || got.Plugin.ID != id || got.Plugin.Enabled != nil {
			t.Errorf("%s = %+v", key, got)
		}
	}
	if p := facts["cursor/summarize"].Plugin; p == nil || p.Version != "1.2.0" || p.Author != "Acme" {
		t.Errorf("cursor manifest = %+v", p)
	}
	for _, key := range []string{"cursor/unused", "cursor/partial", "claudecode/outside"} {
		if _, ok := facts[key]; ok {
			t.Errorf("%s must not be reported", key)
		}
	}
}

// A managed scan reads every account's home, so it refuses a plugin folder
// reached through a link above the plugin; a per-user scan follows it.
func TestManagedScanRefusesALinkAbovePluginFolders(t *testing.T) {
	home := t.TempDir()
	writeSkillFiles(t, home, map[string]string{
		"other/cache/official/tool/1.0/skills/linked/SKILL.md": "---\nname: linked\n---\n",
		".claude/settings.json":                                "{}",
	})
	if err := os.MkdirAll(filepath.Join(home, ".claude", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "other", "cache"), filepath.Join(home, ".claude", "plugins", "cache")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	writeClaudeRegistry(t, home, map[string]string{
		"tool@official": filepath.Join(home, ".claude", "plugins", "cache", "official", "tool", "1.0"),
	})
	catalog := []AISignature{{ID: "claudecode", Vendor: "Anthropic", Category: SignalSupportedConnector, SupportedConnector: "claudecode"}}
	for _, test := range []struct {
		name    string
		managed bool
		want    int
	}{{name: "per-user", want: 1}, {name: "secure client", managed: true}} {
		t.Run(test.name, func(t *testing.T) {
			svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
				Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data-"+test.name), HomeDir: home,
				ManagedEnterprise: test.managed, SecureClient: test.managed,
			}, catalog)
			cleanupPreparedDiscoveryService(t, svc)
			got := 0
			for _, signal := range svc.detectPluginSkills() {
				for _, ev := range signal.Evidence {
					if ev.Skill != nil && ev.Basename == "linked" {
						got++
					}
				}
			}
			if got != test.want {
				t.Fatalf("skills read through the link = %d, want %d", got, test.want)
			}
		})
	}
}
