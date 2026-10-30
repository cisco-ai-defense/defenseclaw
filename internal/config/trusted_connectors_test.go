// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func validTrustedConnector() TrustedConnectorConfig {
	return TrustedConnectorConfig{
		Name: "gas", Account: `CORP\svc-gas`,
		MayActFor: TrustedConnectorScope{Groups: []string{"agents-users@corp.example.com"}},
	}
}

func TestValidateTrustedConnectors(t *testing.T) {
	if err := ValidateTrustedConnectors(EnterpriseIdentityConfig{}); err != nil {
		t.Fatalf("empty list refused: %v", err)
	}
	if err := ValidateTrustedConnectors(EnterpriseIdentityConfig{TrustedConnectors: []TrustedConnectorConfig{validTrustedConnector()}}); err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	mutate := func(f func(*TrustedConnectorConfig)) []TrustedConnectorConfig {
		entry := validTrustedConnector()
		f(&entry)
		return []TrustedConnectorConfig{entry}
	}
	for name, entries := range map[string][]TrustedConnectorConfig{
		"bad name":          mutate(func(e *TrustedConnectorConfig) { e.Name = "GAS gateway" }),
		"no account":        mutate(func(e *TrustedConnectorConfig) { e.Account = " " }),
		"root":              mutate(func(e *TrustedConnectorConfig) { e.Account = "root" }),
		"uid 0":             mutate(func(e *TrustedConnectorConfig) { e.Account = "0" }),
		"system":            mutate(func(e *TrustedConnectorConfig) { e.Account = `NT AUTHORITY\SYSTEM` }),
		"system sid":        mutate(func(e *TrustedConnectorConfig) { e.Account = "S-1-5-18" }),
		"local service sid": mutate(func(e *TrustedConnectorConfig) { e.Account = "S-1-5-19" }),
		"network service":   mutate(func(e *TrustedConnectorConfig) { e.Account = "S-1-5-20" }),
		"domain admin name": mutate(func(e *TrustedConnectorConfig) { e.Account = `CORP\Administrator` }),
		"nt service":        mutate(func(e *TrustedConnectorConfig) { e.Account = `NT SERVICE\gas` }),
		"nt service sid":    mutate(func(e *TrustedConnectorConfig) { e.Account = "S-1-5-80-1-2-3-4-5" }),
		"other route":       mutate(func(e *TrustedConnectorConfig) { e.Route = "claudecode" }),
		"empty may_act_for": mutate(func(e *TrustedConnectorConfig) { e.MayActFor = TrustedConnectorScope{} }),
		"blank user":        mutate(func(e *TrustedConnectorConfig) { e.MayActFor.Users = []string{""} }),
		"root user":         mutate(func(e *TrustedConnectorConfig) { e.MayActFor.Users = []string{"root"} }),
		"duplicate group":   mutate(func(e *TrustedConnectorConfig) { e.MayActFor.Groups = []string{"a", "A"} }),
		"acts for itself":   mutate(func(e *TrustedConnectorConfig) { e.MayActFor.Users = []string{`corp\svc-gas`} }),
		"duplicate name":    {validTrustedConnector(), validTrustedConnector()},
		"duplicate account": {validTrustedConnector(), func() TrustedConnectorConfig { e := validTrustedConnector(); e.Name = "gas2"; return e }()},
		"acts for connector": {validTrustedConnector(), func() TrustedConnectorConfig {
			e := validTrustedConnector()
			e.Name = "gas2"
			e.Account = "svc-two"
			e.MayActFor.Users = []string{`CORP\svc-gas`}
			return e
		}()},
	} {
		if err := ValidateTrustedConnectors(EnterpriseIdentityConfig{TrustedConnectors: entries}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := make([]TrustedConnectorConfig, MaxTrustedConnectors+1)
	for i := range many {
		many[i] = validTrustedConnector()
	}
	if err := ValidateTrustedConnectors(EnterpriseIdentityConfig{TrustedConnectors: many}); err == nil {
		t.Error("an over-long list was accepted")
	}
}

// The three 1.0.6 settings are off by default, and a config that never sets
// them marshals without them, so 1.0.2 to 1.0.5 configs stay byte-identical
// and a rollback to 1.0.4 or 1.0.5 reads them.
func TestIdentityChainSettingsOffByDefaultAndOmitted(t *testing.T) {
	var cfg Config
	if cfg.Connectors.AgentGateway.Enabled || cfg.Guardrail.Chains.RootScope || len(cfg.Enterprise.Identity.TrustedConnectors) != 0 {
		t.Fatal("a zero config enables a 1.0.6 setting")
	}
	if keys := cfg.UsesMinProductVersion106Keys(); len(keys) != 0 {
		t.Fatalf("a zero config uses %v", keys)
	}
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"connectors:", "chains:", "identity:", "trusted_connectors", "agent_gateway", "root_scope"} {
		if strings.Contains(string(out), key) {
			t.Errorf("a zero config marshals %q:\n%s", key, out)
		}
	}
	cfg.Connectors.AgentGateway.Enabled = true
	cfg.Guardrail.Chains.RootScope = true
	cfg.Enterprise.Identity.TrustedConnectors = []TrustedConnectorConfig{validTrustedConnector()}
	if keys := cfg.UsesMinProductVersion106Keys(); len(keys) != 3 {
		t.Fatalf("keys = %v, want all three", keys)
	}
	out, err = yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Connectors.AgentGateway.Enabled || !back.Guardrail.Chains.RootScope || len(back.Enterprise.Identity.TrustedConnectors) != 1 {
		t.Fatalf("the settings did not round-trip:\n%s", out)
	}
}

// Every released config_version 9 home (the upgrade fixtures of 1.0.0 and
// 1.0.1, the shape 1.0.2 to 1.0.5 keep) passes the schema unchanged and
// decodes with the new settings off.
func TestReleasedConfigsKeepNewSettingsOff(t *testing.T) {
	for _, release := range []string{"1.0.0", "1.0.1"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "upgrade", release, "config.golden.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.ReplaceAll(string(raw), "@HOME@", "/home/alice/.defenseclaw"))
		if err := ValidateV8SchemaBytes("config.yaml", raw); err != nil {
			t.Fatalf("%s: schema refuses the released config: %v", release, err)
		}
		var cfg Config
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("%s: %v", release, err)
		}
		if keys := cfg.UsesMinProductVersion106Keys(); len(keys) != 0 {
			t.Fatalf("%s: a released config sets %v", release, keys)
		}
	}
}

func TestIdentityChainSettingsSchema(t *testing.T) {
	ok := "config_version: 9\nconnectors:\n  agent_gateway:\n    enabled: true\n    instance_name: gas\nguardrail:\n  chains:\n    root_scope: false\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(ok)); err != nil {
		t.Fatalf("schema refuses the settings: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown connectors key": "config_version: 9\nconnectors:\n  claude:\n    enabled: true\n",
		"unknown agent_gateway":  "config_version: 9\nconnectors:\n  agent_gateway:\n    route: x\n",
		"bad instance name":      "config_version: 9\nconnectors:\n  agent_gateway:\n    instance_name: Has Space\n",
		"unknown chains key":     "config_version: 9\nguardrail:\n  chains:\n    window: 3\n",
		"root_scope not bool":    "config_version: 9\nguardrail:\n  chains:\n    root_scope: yes please\n",
		"unknown identity key":   "config_version: 9\nenterprise:\n  identity:\n    acting_for: true\n",
		"trusted route":          "config_version: 9\nenterprise:\n  identity:\n    trusted_connectors:\n      - name: gas\n        account: svc\n        route: codex\n        may_act_for: {users: [a]}\n",
		"trusted unknown field":  "config_version: 9\nenterprise:\n  identity:\n    trusted_connectors:\n      - name: gas\n        account: svc\n        groups: [a]\n        may_act_for: {users: [a]}\n",
	} {
		if err := ValidateV8SchemaBytes("config.yaml", []byte(bad)); err == nil {
			t.Errorf("%s: schema accepted", name)
		}
	}
}

func TestIdentityChainSettingsRefusedUnderSecureClient(t *testing.T) {
	cfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client"}}
	if err := cfg.ValidateIdentityChainSettings(); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	cfg.Connectors.AgentGateway.Enabled = true
	if err := cfg.ValidateIdentityChainSettings(); err == nil {
		t.Error("agent_gateway accepted under Secure Client")
	}
	cfg.Connectors.AgentGateway.Enabled = false
	cfg.Guardrail.Chains.RootScope = true
	if err := cfg.ValidateIdentityChainSettings(); err == nil {
		t.Error("root_scope accepted under Secure Client")
	}
	rest := cfg.Enterprise
	rest.Profile = ""
	rest.Identity.TrustedConnectors = []TrustedConnectorConfig{validTrustedConnector()}
	if enterpriseBlockEmpty(rest) {
		t.Error("trusted_connectors does not count as an enterprise setting, so Secure Client would take it")
	}
	per := &Config{Connectors: ConnectorsConfig{AgentGateway: AgentGatewayConnectorConfig{Enabled: true, InstanceName: "Bad Name"}}}
	if err := per.ValidateIdentityChainSettings(); err == nil {
		t.Error("an invalid instance_name was accepted")
	}
}
