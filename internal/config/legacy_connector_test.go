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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

func loadLegacyConnectorFixture(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	path := filepath.Join(dir, DefaultConfigName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	return cfg
}

func TestLoadCanonicalizesRetiredConnectorID(t *testing.T) {
	retired := legacyconnector.RetiredDesktopID
	replacement := legacyconnector.Replacement

	t.Run("primary", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nclaw:\n  mode: "+retired+"\nguardrail:\n  connector: "+retired+"\n")
		if cfg.Guardrail.Connector != replacement || string(cfg.Claw.Mode) != replacement {
			t.Fatalf("connector=%q claw.mode=%q, want %q", cfg.Guardrail.Connector, cfg.Claw.Mode, replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], cfg.ConfigFilePath) {
			t.Fatalf("notices = %v, want one naming %s", cfg.LegacyConnectorNotices, cfg.ConfigFilePath)
		}
	})

	t.Run("map", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: codex\n  connectors:\n    codex:\n      mode: observe\n    "+
			retired+":\n      mode: action\n      hook_fail_mode: open\n")
		if _, ok := cfg.Guardrail.Connectors[retired]; ok {
			t.Fatalf("retired key survived: %v", cfg.Guardrail.Connectors)
		}
		block, ok := cfg.Guardrail.Connectors[replacement]
		if !ok || block.Mode != "action" || block.HookFailMode != "open" {
			t.Fatalf("%s block = %+v, %v; want the retired block's settings", replacement, block, ok)
		}
		if got := cfg.ActiveConnectors(); strings.Join(got, ",") != "codex,"+replacement {
			t.Fatalf("active connectors = %v", got)
		}
	})

	t.Run("both keys present", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+replacement+"\n  connectors:\n    "+
			replacement+":\n      mode: observe\n    "+retired+":\n      mode: action\n")
		if len(cfg.Guardrail.Connectors) != 1 {
			t.Fatalf("connectors = %v, want only %s", cfg.Guardrail.Connectors, replacement)
		}
		if cfg.Guardrail.Connectors[replacement].Mode != "observe" {
			t.Fatalf("explicit %s block must win: %+v", replacement, cfg.Guardrail.Connectors)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], retired) {
			t.Fatalf("notices = %v, want one listing the dropped key", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("other per-connector maps", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+replacement+"\n"+
			"asset_policy:\n  connectors:\n    "+retired+":\n      mode: action\n"+
			"application_protection:\n  connectors:\n    "+retired+":\n      min_confidence: 0.7\n"+
			"observability:\n  connectors:\n    "+replacement+":\n      webhooks: []\n    "+retired+":\n      webhooks: []\n")
		if _, ok := cfg.AssetPolicy.Connectors[retired]; ok {
			t.Fatalf("asset_policy kept the retired key: %v", cfg.AssetPolicy.Connectors)
		}
		if got := cfg.AssetPolicy.Connectors[replacement].Mode; got != "action" {
			t.Fatalf("asset_policy.%s.mode = %q, want the retired block's action", replacement, got)
		}
		block, ok := cfg.ApplicationProtection.Connectors[replacement]
		if !ok || block.MinConfidence == nil || *block.MinConfidence != 0.7 {
			t.Fatalf("application_protection.%s = %+v, %v; want the retired block's settings", replacement, block, ok)
		}
		if _, ok := cfg.ApplicationProtection.Connectors[retired]; ok {
			t.Fatalf("application_protection kept the retired key")
		}
		if len(cfg.Observability.Connectors) != 1 {
			t.Fatalf("observability.connectors = %v, want only the explicit %s block", cfg.Observability.Connectors, replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "observability.connectors."+retired) {
			t.Fatalf("notices = %v, want one naming the dropped observability key", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("connector_hooks", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+retired+"\n  mode: observe\n"+
			"connector_hooks:\n  "+retired+":\n    enabled: true\n    mode: action\n")
		if _, ok := cfg.ConnectorHooks[retired]; ok {
			t.Fatalf("connector_hooks kept the retired key: %v", cfg.ConnectorHooks)
		}
		if hook := cfg.ConnectorHookConfig(replacement); !hook.Enabled || hook.Mode != "action" {
			t.Fatalf("connector_hooks.%s = %+v, want the retired block's settings", replacement, hook)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "connector_hooks") {
			t.Fatalf("notices = %v, want one naming connector_hooks", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("connector_hooks keeps an explicit replacement", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+replacement+"\n"+
			"connector_hooks:\n  "+replacement+":\n    mode: observe\n  "+retired+":\n    mode: action\n")
		if len(cfg.ConnectorHooks) != 1 || cfg.ConnectorHookConfig(replacement).Mode != "observe" {
			t.Fatalf("connector_hooks = %+v, want only the explicit %s entry", cfg.ConnectorHooks, replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "connector_hooks."+retired) {
			t.Fatalf("notices = %v, want one naming the dropped connector_hooks key", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("guardrail.judge.hook_connectors", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+replacement+"\n"+
			"  judge:\n    enabled: true\n    hook_connectors: [codex, "+retired+", "+replacement+"]\n")
		if got := strings.Join(cfg.Guardrail.Judge.HookConnectors, ","); got != "codex,"+replacement {
			t.Fatalf("hook_connectors = %v, want codex and %s once", cfg.Guardrail.Judge.HookConnectors, replacement)
		}
		if !cfg.Guardrail.Judge.HookConnectorEnabled(replacement) {
			t.Fatalf("the hook-lane judge is off for %s", replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "guardrail.judge.hook_connectors") {
			t.Fatalf("notices = %v, want one naming guardrail.judge.hook_connectors", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("application_protection.include_connectors", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: codex\n"+
			"application_protection:\n  include_connectors: ["+retired+"]\n")
		if got := strings.Join(cfg.ApplicationProtection.IncludeConnectors, ","); got != replacement {
			t.Fatalf("include_connectors = %v, want [%s]", cfg.ApplicationProtection.IncludeConnectors, replacement)
		}
		if !cfg.ApplicationProtection.AllowsConnector(replacement) || cfg.ApplicationProtection.AllowsConnector("codex") {
			t.Fatalf("include_connectors must now include only %s", replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "application_protection.include_connectors") {
			t.Fatalf("notices = %v, want one naming application_protection.include_connectors", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("application_protection.exclude_connectors", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: codex\n"+
			"application_protection:\n  exclude_connectors: ["+retired+", "+retired+"]\n")
		if got := strings.Join(cfg.ApplicationProtection.ExcludeConnectors, ","); got != replacement {
			t.Fatalf("exclude_connectors = %v, want [%s]", cfg.ApplicationProtection.ExcludeConnectors, replacement)
		}
		if cfg.ApplicationProtection.AllowsConnector(replacement) {
			t.Fatalf("exclude_connectors no longer excludes %s", replacement)
		}
		if len(cfg.LegacyConnectorNotices) != 1 || !strings.Contains(cfg.LegacyConnectorNotices[0], "application_protection.exclude_connectors") {
			t.Fatalf("notices = %v, want one naming application_protection.exclude_connectors", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("asset_policy rule connectors", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: "+retired+"\n"+
			"asset_policy:\n  enabled: true\n  mode: action\n  mcp:\n    default: allow\n"+
			"    denied:\n      - name: marker-server\n        connector: "+retired+"\n"+
			"    registry:\n      - name: approved-server\n        connector: "+retired+"\n"+
			"  skill:\n    allowed:\n      - name: marker-skill\n        connector: codex\n")
		if got := cfg.AssetPolicy.MCP.Denied[0].Connector; got != replacement {
			t.Fatalf("denied rule connector = %q, want %q", got, replacement)
		}
		if got := cfg.AssetPolicy.MCP.Registry[0].Connector; got != replacement {
			t.Fatalf("registry entry connector = %q, want %q", got, replacement)
		}
		if got := cfg.AssetPolicy.Skill.Allowed[0].Connector; got != "codex" {
			t.Fatalf("another connector's rule changed to %q", got)
		}
		decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{TargetType: "mcp", Name: "marker-server", Connector: replacement})
		if decision.Action != "block" {
			t.Fatalf("a denied rule written for the retired ID no longer blocks %s: %+v", replacement, decision)
		}
		if len(cfg.LegacyConnectorNotices) != 1 ||
			!strings.Contains(cfg.LegacyConnectorNotices[0], "asset_policy.mcp.registry, asset_policy.mcp.denied") ||
			strings.Contains(cfg.LegacyConnectorNotices[0], "asset_policy.skill") {
			t.Fatalf("notices = %v, want one naming the moved rule lists", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("observability route selector connectors", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: codex\n"+
			"observability:\n  destinations:\n    - name: console\n      kind: console\n      routes:\n"+
			"        - name: codex-only\n          signals: [logs]\n          selector:\n            connectors: [codex]\n"+
			"        - name: desktop\n          signals: [logs]\n          selector:\n            connectors: ["+retired+"]\n")
		if len(cfg.LegacyConnectorNotices) != 1 ||
			!strings.Contains(cfg.LegacyConnectorNotices[0], "observability.destinations[0].routes[1].selector.connectors") ||
			strings.Contains(cfg.LegacyConnectorNotices[0], "routes[0]") {
			t.Fatalf("notices = %v, want one naming the second route's selector", cfg.LegacyConnectorNotices)
		}
	})

	t.Run("unaffected config has no notice", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: cursor\n")
		if cfg.Guardrail.Connector != "cursor" || len(cfg.LegacyConnectorNotices) != 0 {
			t.Fatalf("connector=%q notices=%v", cfg.Guardrail.Connector, cfg.LegacyConnectorNotices)
		}
	})
}

// The v8 observability compiler reads the file itself: a route selector or
// connector block written for the retired ID keeps applying to its
// replacement, the way the config loader renames the other settings.
func TestParseCompileObservabilityV8RenamesTheRetiredConnector(t *testing.T) {
	retired, replacement := legacyconnector.RetiredDesktopID, legacyconnector.Replacement
	source := "config_version: 8\nobservability:\n" +
		"  connectors:\n    " + retired + ":\n      webhooks: []\n" +
		"  destinations:\n    - name: console\n      kind: console\n      routes:\n" +
		"        - name: desktop\n          signals: [logs]\n          selector:\n" +
		"            buckets: [security.finding]\n            connectors: [codex, " + retired + ", " + replacement + "]\n" +
		"          action: send\n          redaction_profile: none\n"
	compiled, err := ParseCompileObservabilityV8("<test>", []byte(source), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	selector := compiled.Observability.Destinations[0].Routes[0].Selector
	if got := strings.Join(selector.Connectors, ","); got != "codex,"+replacement {
		t.Fatalf("route selector connectors = %q, want codex and %s once", got, replacement)
	}
	if _, ok := compiled.Observability.Connectors[retired]; ok {
		t.Fatalf("retired observability.connectors key survived: %v", compiled.Observability.Connectors)
	}
	if _, ok := compiled.Observability.Connectors[replacement]; !ok {
		t.Fatalf("observability.connectors lacks %s: %v", replacement, compiled.Observability.Connectors)
	}
}
