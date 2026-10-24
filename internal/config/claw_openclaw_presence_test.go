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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// loadWithoutOpenClaw loads raw as config.yaml for a user whose home holds no
// OpenClaw and whose PATH has no openclaw binary.
func loadWithoutOpenClaw(t *testing.T, raw string, binaryInstalled bool) (*Config, string) {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	previous := OpenClawBinaryInstalled
	OpenClawBinaryInstalled = func() bool { return binaryInstalled }
	t.Cleanup(func() { OpenClawBinaryInstalled = previous })
	path := filepath.Join(t.TempDir(), DefaultConfigName)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	return cfg, home
}

// GAP-0568: a config.yaml with no claw block (or the claw.mode openclaw that
// init wrote before 1.0.4) on an account without OpenClaw selects no
// connector, so the watcher resolves no OpenClaw folders and status names no
// OpenClaw. An installed OpenClaw and an explicit connector keep it.
func TestLoadOpenClawImpliedButNotInstalledConfiguresNoConnector(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"no claw block", "config_version: 9\n"},
		{"claw.mode written by an older init", "config_version: 9\nclaw:\n  mode: openclaw\n"},
		{"disabled fleet with older init", "config_version: 9\nclaw:\n  mode: openclaw\ngateway:\n  fleet_mode: disabled\n"},
		{"off fleet with older init", "config_version: 9\nclaw:\n  mode: openclaw\ngateway:\n  fleet_mode: off\n"},
		{"false fleet with older init", "config_version: 9\nclaw:\n  mode: openclaw\ngateway:\n  fleet_mode: false\n"},
		{"remote disabled fleet with older init", "config_version: 9\nclaw:\n  mode: openclaw\ngateway:\n  host: 10.0.0.5\n  fleet_mode: disabled\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := loadWithoutOpenClaw(t, tc.raw, false)
			if cfg.HasConnectorConfigured() {
				t.Fatalf("HasConnectorConfigured() = true, want false without OpenClaw; fleet_mode=%q", cfg.Gateway.FleetMode)
			}
			if got := cfg.ActiveConnectors(); len(got) != 0 {
				t.Fatalf("ActiveConnectors() = %v, want none", got)
			}
			if got := cfg.activeConnector(); got != "" {
				t.Errorf("activeConnector() = %q, want no agent", got)
			}
			if got := cfg.SkillDirs(); len(got) != 0 {
				t.Errorf("SkillDirs() = %v, want no agent paths", got)
			}
			if got := cfg.PluginDirs(); len(got) != 0 {
				t.Errorf("PluginDirs() = %v, want no agent paths", got)
			}
			// The gateway publishes and diffs deep copies of the loaded config.
			copied, err := cfg.DeepCopy()
			if err != nil {
				t.Fatal(err)
			}
			if copied.HasConnectorConfigured() {
				t.Fatal("DeepCopy().HasConnectorConfigured() = true, want false without OpenClaw")
			}
			if got := copied.activeConnector(); got != "" {
				t.Errorf("DeepCopy().activeConnector() = %q, want no agent", got)
			}
		})
	}

	t.Run("openclaw.json present", func(t *testing.T) {
		home := t.TempDir()
		testenv.SetHome(t, home)
		if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := OpenClawBinaryInstalled
		OpenClawBinaryInstalled = func() bool { return false }
		t.Cleanup(func() { OpenClawBinaryInstalled = previous })
		path := filepath.Join(t.TempDir(), DefaultConfigName)
		if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Fatalf("LoadFromFile: %v", err)
		}
		if got := cfg.ActiveConnectors(); len(got) != 1 || got[0] != "openclaw" {
			t.Fatalf("ActiveConnectors() = %v, want [openclaw] with openclaw.json present", got)
		}
	})

	t.Run("openclaw binary installed", func(t *testing.T) {
		cfg, _ := loadWithoutOpenClaw(t, "config_version: 9\n", true)
		if !cfg.HasConnectorConfigured() {
			t.Fatal("HasConnectorConfigured() = false, want true with an openclaw binary")
		}
	})

	t.Run("explicit connector", func(t *testing.T) {
		cfg, _ := loadWithoutOpenClaw(t, "config_version: 9\nguardrail:\n  connector: openclaw\n", false)
		if got := cfg.ActiveConnectors(); len(got) != 1 || got[0] != "openclaw" {
			t.Fatalf("ActiveConnectors() = %v, want [openclaw] for an explicit connector", got)
		}
	})
}

func TestLoadRosterWithoutClawBlockDoesNotSelectOpenClaw(t *testing.T) {
	cfg, _ := loadWithoutOpenClaw(t, "config_version: 9\nguardrail:\n  connectors:\n    codex: {}\n", false)
	if got := cfg.activeConnector(); got != "codex" {
		t.Errorf("activeConnector() = %q, want configured codex", got)
	}
	if got := cfg.ActiveConnectors(); len(got) != 1 || got[0] != "codex" {
		t.Errorf("ActiveConnectors() = %v, want [codex]", got)
	}
}
