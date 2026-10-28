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
)

// until 1.1: old 0.8.x and 1.0.x files must load after retired connector removal.
func TestRetiredConnectorUpgradeLoads(t *testing.T) {
	for _, version := range []string{"8", "9"} {
		t.Run(version, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := "config_version: " + version + "\nguardrail:\n  connector: openhands\n  connectors:\n    openhands: {}\n    codex: {}\nclaw:\n  mode: omnigent\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Guardrail.Connector != "codex" || len(cfg.Guardrail.Connectors) != 1 || string(cfg.Claw.Mode) != "" {
				t.Fatalf("retired connector still selected: guardrail=%q connectors=%v claw=%q", cfg.Guardrail.Connector, cfg.Guardrail.Connectors, cfg.Claw.Mode)
			}
			if len(cfg.LegacyConnectorNotices) == 0 || !strings.Contains(cfg.LegacyConnectorNotices[len(cfg.LegacyConnectorNotices)-1], "removed") {
				t.Fatalf("missing upgrade notice: %v", cfg.LegacyConnectorNotices)
			}
		})
	}
}

func TestRetiredConnectorUpgradeOnlyRetiredRosterLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 8\nguardrail:\n  connector: openhands\n  connectors:\n    openhands: {}\nclaw:\n  mode: omnigent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ActiveConnectors()) != 0 || cfg.HasConnectorConfigured() {
		t.Fatalf("retired-only roster remains configured: %+v", cfg.ActiveConnectors())
	}
}

func TestRetiredConnectorUpgradeDropsPolicyReferences(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"open-hands": {}, "codex": {}}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"workers": {
		Connectors: map[string]PerConnectorGuardrailConfig{"OmniGent": {}, "codex": {}},
		Sandbox:    &OpenShellAdminConfig{RequiredFor: []string{"omnigent", "codex"}},
	}}
	cfg.Guardrail.ProfileAssignments = []ProfileAssignment{{Profile: "workers", Match: ProfileMatch{Connectors: []string{"openhands"}}}}
	cfg.Guardrail.Judge.HookConnectors = []string{"openhands", "codex"}
	cfg.AssetPolicy.Connectors = map[string]PerConnectorAssetPolicy{"openhands": {}, "codex": {}}
	cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{"omnigent": {}, "codex": {}}
	cfg.ApplicationProtection.IncludeConnectors = []string{"open_hands", "codex"}
	cfg.Observability.Connectors = map[string]PerConnectorObservability{"omnigent": {}, "codex": {}}
	cfg.ConnectorHooks = map[string]AgentHookConfig{"openhands": {}, "codex": {}}
	cfg.Enterprise.MachinePolicy.Connectors = map[string]EnterpriseConnectorPolicy{"omnigent": {}, "codex": {}}
	cfg.OpenShell.Harnesses = []string{"omnigent", "codex"}
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"openhands", "codex"}
	dropRetiredConnectorSettings(cfg)
	if len(cfg.Guardrail.Connectors) != 1 || len(cfg.AssetPolicy.Connectors) != 1 ||
		len(cfg.ApplicationProtection.Connectors) != 1 || len(cfg.Observability.Connectors) != 1 ||
		len(cfg.ConnectorHooks) != 1 || len(cfg.Enterprise.MachinePolicy.Connectors) != 1 ||
		len(cfg.Guardrail.Profiles["workers"].Connectors) != 1 || len(cfg.Guardrail.ProfileAssignments) != 0 ||
		strings.Join(cfg.Guardrail.Judge.HookConnectors, ",") != "codex" ||
		strings.Join(cfg.ApplicationProtection.IncludeConnectors, ",") != "codex" ||
		strings.Join(cfg.OpenShell.Harnesses, ",") != "codex" ||
		strings.Join(cfg.OpenShell.Admin.AllowedHarnesses, ",") != "codex" {
		t.Fatalf("retired connector survived policy cleanup: %+v", cfg)
	}
}

func TestRetiredConnectorUpgradeDropsV8TelemetryRoutes(t *testing.T) {
	source := &ObservabilityV8Source{
		Connectors: map[string]ObservabilityV8ConnectorSource{"openhands": {}, "codex": {}},
		Destinations: []ObservabilityV8DestinationSource{{Routes: []ObservabilityV8RouteSource{
			{Name: "retired", Selector: &ObservabilityV8SelectorSource{Connectors: []string{"omnigent"}}},
			{Name: "mixed", Selector: &ObservabilityV8SelectorSource{Connectors: []string{"openhands", "codex"}}},
		}}},
	}
	migrateObservabilityV8LegacyConnectors(source)
	if len(source.Connectors) != 1 || len(source.Destinations[0].Routes) != 1 ||
		source.Destinations[0].Routes[0].Name != "mixed" ||
		strings.Join(source.Destinations[0].Routes[0].Selector.Connectors, ",") != "codex" {
		t.Fatalf("retired telemetry route survived: %+v", source)
	}
}

func TestRetiredConnectorUpgradeDoesNotBroadenAllowLists(t *testing.T) {
	cfg := &Config{}
	cfg.ApplicationProtection.Enabled = true
	cfg.ApplicationProtection.IncludeConnectors = []string{"openhands"}
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Harnesses = []string{"omnigent"}
	cfg.OpenShell.Admin.AllowedHarnesses = []string{"openhands"}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"workers": {
		Sandbox: &OpenShellAdminConfig{AllowedHarnesses: []string{"omnigent"}},
	}}
	dropRetiredConnectorSettings(cfg)
	profile := cfg.Guardrail.Profiles["workers"]
	if cfg.ApplicationProtection.Enabled || cfg.OpenShell.Enabled ||
		cfg.OpenShell.Admin.Allowed == nil || *cfg.OpenShell.Admin.Allowed ||
		profile.Sandbox.Allowed == nil || *profile.Sandbox.Allowed {
		t.Fatalf("retired-only allow-list became unrestricted: %+v", cfg)
	}
}

// An assignment for a removed connector and a group must not turn into one
// for every connector of that group.
func TestRetiredConnectorUpgradeDropsRetiredOnlyAssignmentWithOtherMatchers(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.ProfileAssignments = []ProfileAssignment{
		{Profile: "strict", Match: ProfileMatch{Groups: []string{"eng"}, Connectors: []string{"openhands"}}},
		{Profile: "mixed", Match: ProfileMatch{Groups: []string{"eng"}, Connectors: []string{"omnigent", "codex"}}},
		{Profile: "groups", Match: ProfileMatch{Groups: []string{"eng"}}},
	}
	dropRetiredConnectorSettings(cfg)
	got := cfg.Guardrail.ProfileAssignments
	if len(got) != 2 || got[0].Profile != "mixed" || strings.Join(got[0].Match.Connectors, ",") != "codex" ||
		got[1].Profile != "groups" {
		t.Fatalf("profile assignments after cleanup = %+v", got)
	}
}

// A destination whose every route selected only removed connectors goes:
// empty routes do not compile and no routes would send it every signal.
// Destinations with a surviving route, and ones without routes, stay.
func TestRetiredConnectorUpgradeDropsDestinationLeftWithoutRoutes(t *testing.T) {
	body := "config_version: 8\nobservability:\n  destinations:\n" +
		"    - name: omnigent-only\n      kind: console\n      routes:\n" +
		"        - {name: omnigent, signals: [logs], selector: {connectors: [omnigent]}}\n" +
		"        - {name: openhands, signals: [logs], selector: {connectors: [OpenHands]}, action: drop}\n" +
		"    - name: mixed\n      kind: console\n      routes:\n" +
		"        - {name: retired, signals: [logs], selector: {connectors: [openhands]}}\n" +
		"        - {name: codex, signals: [logs], selector: {connectors: [codex]}}\n" +
		"    - name: everything\n      kind: console\n"
	for _, version := range []string{"8", "9"} {
		t.Run(version, func(t *testing.T) {
			source := strings.Replace(body, "config_version: 8", "config_version: "+version, 1)
			compiled, err := ParseCompileObservabilityV8("<test>", []byte(source), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()})
			if err != nil {
				t.Fatalf("compile after removed-connector cleanup: %v", err)
			}
			var names []string
			for _, destination := range compiled.Observability.Destinations {
				names = append(names, destination.Name)
			}
			if got := strings.Join(names, ","); got != "mixed,everything" {
				t.Fatalf("destinations = %q, want mixed,everything", got)
			}
			if routes := compiled.Observability.Destinations[0].Routes; len(routes) != 1 || routes[0].Name != "codex" {
				t.Fatalf("mixed routes = %+v, want only codex", routes)
			}
			if compiled.Observability.Destinations[1].Routes != nil {
				t.Fatalf("a destination without routes gained some: %+v", compiled.Observability.Destinations[1].Routes)
			}
			if destination, ok := compiled.Plan.Destination("omnigent-only"); ok {
				t.Fatalf("the removed connectors destination still compiles: %+v", destination)
			}
			if _, ok := compiled.Plan.Destination("mixed"); !ok {
				t.Fatal("the mixed destination did not compile")
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFromFile(path); err != nil {
				t.Fatalf("load after removed-connector cleanup: %v", err)
			}
		})
	}
}

// The sandbox lists refuse an empty list, so a list of only removed
// connectors is left out (no constraint) and allowed: false keeps the
// emptied allow-list closed; the config still loads.
func TestRetiredConnectorUpgradeOmitsEmptiedSandboxLists(t *testing.T) {
	for name, section := range map[string]string{
		"admin": "openshell:\n  admin:\n    allowed_harnesses: [openhands]\n    required_for: [omnigent]\n",
		"profile": "  profiles:\n    workers:\n      sandbox:\n        allowed_harnesses: [omnigent]\n        required_for: [openhands]\n" +
			"    mixed:\n      sandbox:\n        allowed_harnesses: [omnigent, codex]\n        required_for: [openhands, codex]\n",
	} {
		t.Run(name, func(t *testing.T) {
			body := "config_version: 9\nguardrail:\n  connector: codex\n  connectors:\n    codex: {}\n"
			if name == "profile" {
				body += section
			} else {
				body = section + body
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatalf("load after removed-connector cleanup: %v", err)
			}
			closed := cfg.OpenShell.Admin
			if name == "profile" {
				closed = *cfg.Guardrail.Profiles["workers"].Sandbox
				mixed := cfg.Guardrail.Profiles["mixed"].Sandbox
				if strings.Join(mixed.AllowedHarnesses, ",") != "codex" || strings.Join(mixed.RequiredFor, ",") != "codex" || mixed.Allowed != nil {
					t.Fatalf("mixed sandbox = %+v", mixed)
				}
			}
			if closed.Allowed == nil || *closed.Allowed || closed.AllowedHarnesses != nil || closed.RequiredFor != nil {
				t.Fatalf("emptied sandbox lists = %+v; want them left out and allowed: false", closed)
			}
		})
	}
}
