// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func webhookPtr(ws ...WebhookConfig) *[]WebhookConfig {
	out := append([]WebhookConfig(nil), ws...)
	return &out
}

func TestObservability_EffectiveWebhooks_TriState(t *testing.T) {
	global := []WebhookConfig{{Name: "global-hook", URL: "https://global.example"}}
	obs := ObservabilityConfig{
		Connectors: map[string]PerConnectorObservability{
			"codex":      {Webhooks: webhookPtr(WebhookConfig{Name: "codex-hook", URL: "https://codex.example"})},
			"claudecode": {Webhooks: webhookPtr()}, // suppress
			"hermes":     {},
		},
	}
	if got := obs.EffectiveWebhooks("codex", global); len(got) != 1 || got[0].Name != "codex-hook" {
		t.Fatalf("codex webhooks = %+v, want [codex-hook]", got)
	}
	if got := obs.EffectiveWebhooks("claudecode", global); len(got) != 0 {
		t.Fatalf("claudecode webhooks = %+v, want [] (suppressed)", got)
	}
	if got := obs.EffectiveWebhooks("hermes", global); len(got) != 1 || got[0].Name != "global-hook" {
		t.Fatalf("hermes webhooks = %+v, want [global-hook] (inherit)", got)
	}
	if got := obs.EffectiveWebhooks("unknown", global); len(got) != 1 || got[0].Name != "global-hook" {
		t.Fatalf("unknown webhooks = %+v, want [global-hook] (inherit)", got)
	}
}

func TestObservability_ConnectorLookup_AliasInsensitive(t *testing.T) {
	obs := ObservabilityConfig{
		Connectors: map[string]PerConnectorObservability{
			"open-hands": {Webhooks: webhookPtr(WebhookConfig{Name: "oh"})},
		},
	}
	// Registry-canonical "openhands" must resolve the "open-hands" alias key.
	got := obs.EffectiveWebhooks("openhands", nil)
	if len(got) != 1 || got[0].Name != "oh" {
		t.Fatalf("openhands effective = %+v, want [oh] via alias", got)
	}
}

func TestObservability_Validate_RejectsDuplicateAlias(t *testing.T) {
	obs := ObservabilityConfig{
		Connectors: map[string]PerConnectorObservability{
			"open-hands": {},
			"openhands":  {},
		},
	}
	if err := obs.Validate(); err == nil {
		t.Fatal("expected Validate to reject open-hands/openhands alias collision")
	}
	// A single canonical entry validates clean.
	ok := ObservabilityConfig{Connectors: map[string]PerConnectorObservability{"codex": {}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("unexpected Validate error: %v", err)
	}
}

// TestObservability_LoadRoundTrip pins the per-connector webhook overrides
// through the loader: an override and an explicit empty list (suppress), and
// that a load-save cycle keeps that shape.
func TestObservability_LoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", tmpDir)

	configFile := filepath.Join(tmpDir, DefaultConfigName)
	data := []byte(`config_version: 9
observability:
  connectors:
    codex:
      webhooks:
        - name: codex-hook
          url: https://codex.example/hook
          type: generic
          enabled: true
    claudecode:
      webhooks: []
`)
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadFromFile(ConfigPath())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	conns := cfg.Observability.Connectors
	if len(conns) != 2 {
		t.Fatalf("expected 2 connectors, got %d (%v)", len(conns), cfg.Observability.ConnectorNames())
	}
	if pc := conns["codex"]; pc.Webhooks == nil || len(*pc.Webhooks) != 1 {
		t.Fatalf("codex.webhooks = %v, want 1-entry override", pc.Webhooks)
	}
	// Explicit empty list = suppress (non-nil pointer, len 0).
	if pc := conns["claudecode"]; pc.Webhooks == nil || len(*pc.Webhooks) != 0 {
		t.Fatalf("claudecode.webhooks = %v, want a non-nil empty list (suppress)", pc.Webhooks)
	}

	// A load-save cycle must keep the suppress + override shape, so it never
	// silently re-introduces global routing for a suppressed connector.
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	var reparsed Config
	if err := yaml.Unmarshal(out, &reparsed); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if pc := reparsed.Observability.Connectors["claudecode"]; pc.Webhooks == nil || len(*pc.Webhooks) != 0 {
		t.Fatalf("claudecode suppress did not survive Save round-trip: %v", pc.Webhooks)
	}
	if pc := reparsed.Observability.Connectors["codex"]; pc.Webhooks == nil || len(*pc.Webhooks) != 1 {
		t.Fatalf("codex override did not survive Save round-trip: %v", pc.Webhooks)
	}
}
