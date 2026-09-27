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

	t.Run("unaffected config has no notice", func(t *testing.T) {
		cfg := loadLegacyConnectorFixture(t, "config_version: 6\nguardrail:\n  connector: cursor\n")
		if cfg.Guardrail.Connector != "cursor" || len(cfg.LegacyConnectorNotices) != 0 {
			t.Fatalf("connector=%q notices=%v", cfg.Guardrail.Connector, cfg.LegacyConnectorNotices)
		}
	})
}
