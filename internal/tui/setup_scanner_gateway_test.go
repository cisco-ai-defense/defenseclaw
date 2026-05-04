// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#9 — Scanner, Gateway Watcher, Gateway Watchdog round-trips
// ------------------------------------------------------------------

// TestApplyConfigField_ScannersFullSurface walks the entire Scanner
// key surface and asserts each key lands in the right struct field.
// A regression here is exactly the "silent drop of a new knob" bug
// we're trying to prevent as the Python scanners gain options.
func TestApplyConfigField_ScannersFullSurface(t *testing.T) {
	cases := []struct {
		key    string
		val    string
		verify func(c *config.Config) bool
	}{
		{"scanners.skill_scanner.binary", "/usr/bin/ss", func(c *config.Config) bool { return c.Scanners.SkillScanner.Binary == "/usr/bin/ss" }},
		{"scanners.skill_scanner.policy", "strict", func(c *config.Config) bool { return c.Scanners.SkillScanner.Policy == "strict" }},
		{"scanners.skill_scanner.lenient", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.Lenient }},
		{"scanners.skill_scanner.use_llm", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.UseLLM }},
		{"scanners.skill_scanner.llm_consensus_runs", "3", func(c *config.Config) bool { return c.Scanners.SkillScanner.LLMConsensus == 3 }},
		{"scanners.skill_scanner.use_behavioral", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.UseBehavioral }},
		{"scanners.skill_scanner.enable_meta", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.EnableMeta }},
		{"scanners.skill_scanner.use_trigger", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.UseTrigger }},
		{"scanners.skill_scanner.use_virustotal", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.UseVirusTotal }},
		{"scanners.skill_scanner.virustotal_api_key_env", "VT_KEY", func(c *config.Config) bool { return c.Scanners.SkillScanner.VirusTotalKeyEnv == "VT_KEY" }},
		{"scanners.skill_scanner.use_aidefense", "true", func(c *config.Config) bool { return c.Scanners.SkillScanner.UseAIDefense }},
		{"scanners.mcp_scanner.binary", "mcp-scanner", func(c *config.Config) bool { return c.Scanners.MCPScanner.Binary == "mcp-scanner" }},
		{"scanners.mcp_scanner.analyzers", "yara,regex", func(c *config.Config) bool { return c.Scanners.MCPScanner.Analyzers == "yara,regex" }},
		{"scanners.mcp_scanner.scan_prompts", "true", func(c *config.Config) bool { return c.Scanners.MCPScanner.ScanPrompts }},
		{"scanners.mcp_scanner.scan_resources", "true", func(c *config.Config) bool { return c.Scanners.MCPScanner.ScanResources }},
		{"scanners.mcp_scanner.scan_instructions", "true", func(c *config.Config) bool { return c.Scanners.MCPScanner.ScanInstructions }},
		{"scanners.plugin_scanner", "py-plugin-scan", func(c *config.Config) bool { return c.Scanners.PluginScanner == "py-plugin-scan" }},
		{"scanners.codeguard", "/usr/bin/cg", func(c *config.Config) bool { return c.Scanners.CodeGuard == "/usr/bin/cg" }},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			c := &config.Config{}
			applyConfigField(c, tc.key, tc.val)
			if !tc.verify(c) {
				t.Errorf("applyConfigField(%s=%s) didn't land in the struct", tc.key, tc.val)
			}
		})
	}
}

// TestApplyConfigField_GatewayWatcher exhaustively verifies the
// watcher key set. Dirs are CSV on the wire so we round-trip a
// multi-entry list too.
func TestApplyConfigField_GatewayWatcher(t *testing.T) {
	c := &config.Config{}

	applyConfigField(c, "gateway.watcher.enabled", "true")
	if !c.Gateway.Watcher.Enabled {
		t.Error("gateway.watcher.enabled didn't stick")
	}

	applyConfigField(c, "gateway.watcher.skill.enabled", "true")
	applyConfigField(c, "gateway.watcher.skill.take_action", "true")
	applyConfigField(c, "gateway.watcher.skill.dirs", "~/a, ~/b ,~/c")
	if !c.Gateway.Watcher.Skill.Enabled || !c.Gateway.Watcher.Skill.TakeAction {
		t.Error("watcher.skill flags didn't stick")
	}
	if want := []string{"~/a", "~/b", "~/c"}; !reflect.DeepEqual(c.Gateway.Watcher.Skill.Dirs, want) {
		t.Errorf("watcher.skill.dirs = %v, want %v", c.Gateway.Watcher.Skill.Dirs, want)
	}

	applyConfigField(c, "gateway.watcher.plugin.enabled", "true")
	applyConfigField(c, "gateway.watcher.plugin.take_action", "true")
	applyConfigField(c, "gateway.watcher.plugin.dirs", "/p1,/p2")
	if !c.Gateway.Watcher.Plugin.Enabled || !c.Gateway.Watcher.Plugin.TakeAction {
		t.Error("watcher.plugin flags didn't stick")
	}
	if want := []string{"/p1", "/p2"}; !reflect.DeepEqual(c.Gateway.Watcher.Plugin.Dirs, want) {
		t.Errorf("watcher.plugin.dirs = %v, want %v", c.Gateway.Watcher.Plugin.Dirs, want)
	}

	applyConfigField(c, "gateway.watcher.mcp.take_action", "true")
	if !c.Gateway.Watcher.MCP.TakeAction {
		t.Error("watcher.mcp.take_action didn't stick")
	}
}

// TestApplyConfigField_GatewayWatcher_DirsClearToNil is the subtle
// one: clearing a Dirs field should produce nil, not [""], so the
// YAML omits the empty entry on next write.
func TestApplyConfigField_GatewayWatcher_DirsClearToNil(t *testing.T) {
	c := &config.Config{}
	c.Gateway.Watcher.Skill.Dirs = []string{"/old"}
	applyConfigField(c, "gateway.watcher.skill.dirs", "   ")
	if c.Gateway.Watcher.Skill.Dirs != nil {
		t.Errorf("empty input must clear to nil, got %v", c.Gateway.Watcher.Skill.Dirs)
	}
}

func TestApplyConfigField_GatewayWatchdog(t *testing.T) {
	c := &config.Config{}
	applyConfigField(c, "gateway.watchdog.enabled", "true")
	applyConfigField(c, "gateway.watchdog.interval", "30")
	applyConfigField(c, "gateway.watchdog.debounce", "2")
	if !c.Gateway.Watchdog.Enabled || c.Gateway.Watchdog.Interval != 30 || c.Gateway.Watchdog.Debounce != 2 {
		t.Errorf("watchdog fields didn't stick: %+v", c.Gateway.Watchdog)
	}
}

// TestSetupSections_ScannerShape locks the shape of the Scanners
// section so future refactors can't quietly drop a row.
func TestSetupSections_ScannerShape(t *testing.T) {
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.loadSections()
	var scanner *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Scanners" {
			scanner = &p.sections[i]
			break
		}
	}
	if scanner == nil {
		t.Fatal("Scanners section missing")
		return
	}
	// Expect at least one field per scanner category.
	want := []string{
		"scanners.skill_scanner.binary",
		"scanners.skill_scanner.policy",
		"scanners.skill_scanner.use_llm",
		"scanners.skill_scanner.llm_consensus_runs",
		"scanners.skill_scanner.use_virustotal",
		"scanners.skill_scanner.use_aidefense",
		"scanners.mcp_scanner.binary",
		"scanners.mcp_scanner.scan_prompts",
		"scanners.mcp_scanner.scan_resources",
		"scanners.plugin_scanner",
		"scanners.codeguard",
	}
	seen := map[string]bool{}
	for _, f := range scanner.Fields {
		seen[f.Key] = true
	}
	for _, k := range want {
		if !seen[k] {
			t.Errorf("Scanners section missing field %q", k)
		}
	}
}

// TestSetupSections_WatcherAndWatchdogPresent asserts the new
// P2-#9 sections are registered.
func TestSetupSections_WatcherAndWatchdogPresent(t *testing.T) {
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.loadSections()
	seen := map[string]int{}
	for i := range p.sections {
		seen[p.sections[i].Name] = len(p.sections[i].Fields)
	}
	if seen["Gateway Watcher"] == 0 {
		t.Error("Gateway Watcher section is missing or empty")
	}
	if seen["Gateway Watchdog"] == 0 {
		t.Error("Gateway Watchdog section is missing or empty")
	}
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"":          nil,
		"   ":       nil,
		",":         nil,
		"a":         {"a"},
		"a,b":       {"a", "b"},
		" a , b ":   {"a", "b"},
		"a,,b":      {"a", "b"},
		"~/x,~/y/z": {"~/x", "~/y/z"},
	}
	for in, want := range cases {
		got := splitCSV(in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
		}
	}
}
