// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestMaterializeSidecarGatewayTokenUsesResolvedPrecedence(t *testing.T) {
	t.Run("canonical environment replaces stale inline config", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "current-environment-token")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "legacy-environment-token")
		gatewayConfig := config.GatewayConfig{Token: "stale-inline-token"}

		materializeSidecarGatewayToken(&gatewayConfig, "")

		if got := gatewayConfig.Token; got != "current-environment-token" {
			t.Fatalf("materialized token = %q, want canonical environment token", got)
		}
	})

	t.Run("custom environment remains highest priority", func(t *testing.T) {
		t.Setenv("CUSTOM_GATEWAY_TOKEN", "custom-environment-token")
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "canonical-environment-token")
		gatewayConfig := config.GatewayConfig{
			TokenEnv: "CUSTOM_GATEWAY_TOKEN",
			Token:    "stale-inline-token",
		}

		materializeSidecarGatewayToken(&gatewayConfig, "")

		if got := gatewayConfig.Token; got != "custom-environment-token" {
			t.Fatalf("materialized token = %q, want custom environment token", got)
		}
	})

	t.Run("deprecated explicit flag still wins", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "canonical-environment-token")
		gatewayConfig := config.GatewayConfig{Token: "inline-token"}

		materializeSidecarGatewayToken(&gatewayConfig, "explicit-flag-token")

		if got := gatewayConfig.Token; got != "explicit-flag-token" {
			t.Fatalf("materialized token = %q, want explicit flag token", got)
		}
	})

	t.Run("inline config remains the final fallback", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
		gatewayConfig := config.GatewayConfig{Token: "inline-token"}

		materializeSidecarGatewayToken(&gatewayConfig, "")

		if got := gatewayConfig.Token; got != "inline-token" {
			t.Fatalf("materialized token = %q, want inline token", got)
		}
	})
}

// TestFormatDetailValue_Scalars locks in the rendering contract used
// by the gateway status panel. JSON unmarshalling reduces every numeric
// value to “float64“; whole numbers must round-trip back to ints so
// fields like “protocol: 3“ and “port: 4000“ don't render as
// “3.0“ / “4000.0“ to operators reading the terminal.
func TestFormatDetailValue_Scalars(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
		ok   bool
	}{
		{name: "string", in: "127.0.0.1:4317", want: "127.0.0.1:4317", ok: true},
		{name: "bool true", in: true, want: "true", ok: true},
		{name: "bool false", in: false, want: "false", ok: true},
		{name: "json int", in: float64(3), want: "3", ok: true},
		{name: "json large int", in: float64(18789), want: "18789", ok: true},
		{name: "json fractional", in: 1.5, want: "1.5", ok: true},
		{name: "go int", in: int(42), want: "42", ok: true},
		{name: "go int64", in: int64(42), want: "42", ok: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatDetailValue(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tt.ok, got)
			}
			if got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFormatDetailValue_NonScalarsAreSkipped confirms that structured
// fields kept on the /health JSON surface (e.g. the per-sink
// “sinks: [...]“ array, or the Guardrail "connectors" roster) are
// signalled as "not renderable" so the CLI printer skips them rather
// than dumping a “[map[...]]“ blob or duplicating the authoritative
// "Agents" connector enumeration. Equivalent JSON-decoded shapes
// (“[]interface{}“ / “map[string]interface{}“) and Go-native shapes are
// both covered.
func TestFormatDetailValue_NonScalarsAreSkipped(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
	}{
		{
			name: "json-decoded slice of maps",
			in: []interface{}{
				map[string]interface{}{
					"name": "local-otlp-logs",
					"kind": "otlp_logs",
				},
			},
		},
		{
			name: "json-decoded slice of strings",
			in:   []interface{}{"otlp_logs", "splunk_hec"},
		},
		{
			name: "json-decoded map",
			in:   map[string]interface{}{"name": "local-otlp-logs"},
		},
		{
			name: "go native slice of maps",
			in:   []map[string]interface{}{{"name": "local-otlp-logs"}},
		},
		{
			name: "go native string slice",
			in:   []string{"otlp_logs"},
		},
		{
			name: "nil",
			in:   nil,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatDetailValue(tt.in)
			if ok {
				t.Fatalf("ok = true (got=%q), want false — non-scalar must be skipped", got)
			}
		})
	}
}

func TestGuardrailBannerLinesShowJudgeNotBlankProxyRows(t *testing.T) {
	// GAP-2107: hook-only installs printed "Model:  → " and an empty "API key:".
	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Port = 4000
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Judge.Enabled = true
	cfg.Guardrail.Judge.LLM.Model = "bedrock/judge-model"
	got := strings.Join(guardrailBannerLines(cfg), "\n")
	if strings.Contains(got, "Model:") || strings.Contains(got, "API key:") {
		t.Fatalf("blank proxy rows in banner:\n%s", got)
	}
	if !strings.Contains(got, "Judge:      bedrock/judge-model") {
		t.Fatalf("judge model missing from banner:\n%s", got)
	}
	cfg.Guardrail.Model = "openai/gpt"
	if got := strings.Join(guardrailBannerLines(cfg), "\n"); !strings.Contains(got, "Model:      openai/gpt") {
		t.Fatalf("proxy model row missing:\n%s", got)
	}
}

// GAP-0077: a standalone managed service runs no watcher and dials no
// OpenClaw fleet, so its banner must not advertise either. Secure Client
// keeps the banner of main (GAP-0105, issue #1092).
func TestSidecarBannerManagedShowsNoWatcherOrFleet(t *testing.T) {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	cfg.Gateway.Host, cfg.Gateway.Port = "127.0.0.1", 18789
	cfg.Gateway.Watcher.Enabled, cfg.Gateway.Watcher.Skill.Enabled = true, true
	got := fleetBannerLine(cfg) + "\n" + strings.Join(watcherBannerLines(cfg), "\n")
	if strings.Contains(got, "18789") || strings.Contains(got, "Skill dirs") || !strings.Contains(got, "idle (no directories to watch)") {
		t.Fatalf("standalone banner:\n%s", got)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	got = fleetBannerLine(cfg) + "\n" + strings.Join(watcherBannerLines(cfg), "\n")
	want := "  Gateway:      127.0.0.1:18789\n  Watcher:      true\n    Skill:      enabled=true take_action=false\n    Skill dirs: autodiscover (from claw mode)"
	if got != want {
		t.Fatalf("Secure Client banner:\n%s\nwant:\n%s", got, want)
	}
}
