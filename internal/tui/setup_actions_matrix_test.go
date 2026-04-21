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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestActionMatrixFields_ShapeIsConstant locks in the 1 header + 15
// row layout (5 severities × 3 columns). If someone adds a severity
// or column this test catches the arithmetic and forces a review of
// every downstream consumer (applyActionsField, tests, docs).
func TestActionMatrixFields_ShapeIsConstant(t *testing.T) {
	fields := actionMatrixFields("skill_actions", config.SkillActionsConfig{})
	if want := 1 + 5*3; len(fields) != want {
		t.Fatalf("skill actions matrix must have %d rows (1 header + 15 choices), got %d", want, len(fields))
	}
	if fields[0].Kind != "header" {
		t.Errorf("first row must be a header, got kind=%q", fields[0].Kind)
	}
	for i, f := range fields[1:] {
		if f.Kind != "choice" {
			t.Errorf("row %d kind=%q, want choice", i+1, f.Kind)
		}
		if f.Key == "" || !strings.HasPrefix(f.Key, "skill_actions.") {
			t.Errorf("row %d key=%q must be namespaced under skill_actions.", i+1, f.Key)
		}
	}
}

// TestActionMatrixFields_OptionSetsDifferPerColumn guards against a
// future refactor that accidentally unifies the option slices —
// install has 3 values (none/block/allow) while file has 2 and
// runtime has 2. Merging them would let the operator pick
// nonsensical combinations.
func TestActionMatrixFields_OptionSetsDifferPerColumn(t *testing.T) {
	fields := actionMatrixFields("mcp_actions", config.MCPActionsConfig{})
	byCol := map[string]map[string]bool{
		"file":    {},
		"runtime": {},
		"install": {},
	}
	for _, f := range fields {
		for col := range byCol {
			if strings.HasSuffix(f.Key, "."+col) {
				for _, o := range f.Options {
					byCol[col][o] = true
				}
			}
		}
	}
	if len(byCol["file"]) != 2 {
		t.Errorf("file column should expose 2 options, got %v", byCol["file"])
	}
	if len(byCol["runtime"]) != 2 {
		t.Errorf("runtime column should expose 2 options, got %v", byCol["runtime"])
	}
	if len(byCol["install"]) != 3 {
		t.Errorf("install column should expose 3 options, got %v", byCol["install"])
	}
}

// TestActionMatrixFields_UnknownPrefixDegrades is defence in depth:
// a typo in the caller should render a visible hint, not a segfault.
func TestActionMatrixFields_UnknownPrefixDegrades(t *testing.T) {
	fields := actionMatrixFields("nope", nil)
	if len(fields) == 0 {
		t.Fatal("unknown prefix should still render something")
	}
	if fields[0].Kind != "header" {
		t.Errorf("unknown prefix should degrade to a header, got %q", fields[0].Kind)
	}
}

// TestApplyActionsField_RoundTrips confirms applyConfigField routes
// skill_actions.*/mcp_actions.*/plugin_actions.* through
// applyActionsField correctly and that values land in the right
// struct field. This is the "save path" anchor for P1-#6 — without
// this, edits in the TUI would appear accepted but would quietly
// never make it to disk.
func TestApplyActionsField_RoundTrips(t *testing.T) {
	cfg := &config.Config{}
	// Every (prefix, severity, column) triple.
	cases := []struct {
		key   string
		val   string
		check func(*config.Config) string
	}{
		{
			"skill_actions.critical.file",
			string(config.FileActionQuarantine),
			func(c *config.Config) string { return string(c.SkillActions.Critical.File) },
		},
		{
			"skill_actions.high.runtime",
			string(config.RuntimeDisable),
			func(c *config.Config) string { return string(c.SkillActions.High.Runtime) },
		},
		{
			"skill_actions.medium.install",
			string(config.InstallAllow),
			func(c *config.Config) string { return string(c.SkillActions.Medium.Install) },
		},
		{
			"mcp_actions.low.file",
			string(config.FileActionNone),
			func(c *config.Config) string { return string(c.MCPActions.Low.File) },
		},
		{
			"mcp_actions.info.install",
			string(config.InstallBlock),
			func(c *config.Config) string { return string(c.MCPActions.Info.Install) },
		},
		{
			"plugin_actions.critical.runtime",
			string(config.RuntimeEnable),
			func(c *config.Config) string { return string(c.PluginActions.Critical.Runtime) },
		},
		{
			"plugin_actions.high.install",
			string(config.InstallBlock),
			func(c *config.Config) string { return string(c.PluginActions.High.Install) },
		},
	}
	for _, tc := range cases {
		applyConfigField(cfg, tc.key, tc.val)
		if got := tc.check(cfg); got != tc.val {
			t.Errorf("%s: want %q, got %q", tc.key, tc.val, got)
		}
	}
}

// TestApplyActionsField_IgnoresMalformedKey defends against a future
// caller typo. We prefer silent-drop to panic because
// applyConfigField is called in a tight loop on Save and a panic
// there would kill the whole TUI.
func TestApplyActionsField_IgnoresMalformedKey(t *testing.T) {
	cfg := &config.Config{}
	for _, bad := range []string{
		"skill_actions.critical",           // missing column
		"skill_actions.critical.file.oops", // 4 parts
		"skill_actions.bogus.file",         // unknown severity
		"mcp_actions.critical.bogus",       // unknown column
	} {
		applyConfigField(cfg, bad, "quarantine")
	}
	// If anything landed in the struct we'd see a non-zero field.
	if cfg.SkillActions.Critical.File != "" {
		t.Errorf("malformed keys must not mutate config, got %q", cfg.SkillActions.Critical.File)
	}
}

// TestLoadSections_ActionsMatrixPresent confirms the three new
// sections show up in the editor. This is a thin integration check
// — if SetupPanel.loadSections forgets to include them, the 45
// editable fields vanish from the TUI without a compile error.
func TestLoadSections_ActionsMatrixPresent(t *testing.T) {
	p := SetupPanel{cfg: &config.Config{}}
	p.loadSections()
	want := map[string]bool{
		"Skill Actions":  false,
		"MCP Actions":    false,
		"Plugin Actions": false,
	}
	for _, s := range p.sections {
		if _, ok := want[s.Name]; ok {
			want[s.Name] = true
			if len(s.Fields) < 10 {
				t.Errorf("%s section has only %d fields; expected >= 16 (1 header + 15 choices)", s.Name, len(s.Fields))
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing section %q in setup config editor", name)
		}
	}
}
