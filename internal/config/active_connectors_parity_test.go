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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestActiveConnectorsParityFixture loads every case of the fixture the Python
// CLI test (cli/tests/test_active_connectors_parity.py) also reads, so Go and
// Python resolve the same primary, roster, policy set and per-connector rule
// pack for the same config.yaml (GAP-0707).
func TestActiveConnectorsParityFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "active-connectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name     string            `json:"name"`
			Config   string            `json:"config"`
			Primary  string            `json:"primary"`
			Roster   []string          `json:"roster"`
			Policy   []string          `json:"policy"`
			RulePack map[string]string `json:"rule_pack"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			testenv.SetHome(t, t.TempDir())
			dir := t.TempDir()
			path := filepath.Join(dir, DefaultConfigName)
			body := "config_version: 9\ndata_dir: " + strconv.Quote(dir) + "\n" + tc.Config
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatalf("LoadFromFile: %v", err)
			}
			if got := cfg.activeConnector(); got != tc.Primary {
				t.Errorf("primary = %q, want %q", got, tc.Primary)
			}
			if got := nonNil(cfg.ActiveConnectors()); !reflect.DeepEqual(got, tc.Roster) {
				t.Errorf("ActiveConnectors() = %v, want %v", got, tc.Roster)
			}
			if got := nonNil(cfg.PolicyConnectors()); !reflect.DeepEqual(got, tc.Policy) {
				t.Errorf("PolicyConnectors() = %v, want %v", got, tc.Policy)
			}
			for connector, want := range tc.RulePack {
				if got := cfg.EffectiveRulePackRefForConnector(connector).Name; got != want {
					t.Errorf("rule pack for %s = %q, want %q", connector, got, want)
				}
			}
		})
	}
}

func nonNil(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

// A Secure Client config keeps the first sorted roster key as its primary even
// when claw.mode lists another; the same roster outside Secure Client boots
// the connector claw.mode names (GAP-0707).
func TestMigrateConnectorSelectionLeavesSecureClientPrimaryUnchanged(t *testing.T) {
	build := func() *Config {
		cfg := DefaultConfig()
		cfg.Claw.Mode = ClawMode("kiro")
		cfg.Guardrail.Connector = ""
		cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {}, "kiro": {}}
		return cfg
	}
	// The load passes resolvesToSecureClient(cfg, pin) as the second argument.
	sc := build()
	migrateConnectorSelection(sc, true)
	if got := sc.activeConnector(); got != "codex" {
		t.Errorf("Secure Client primary = %q, want codex (unchanged)", got)
	}
	oss := build()
	migrateConnectorSelection(oss, false)
	if got := oss.activeConnector(); got != "kiro" {
		t.Errorf("standalone primary = %q, want kiro (claw.mode is listed)", got)
	}
}
