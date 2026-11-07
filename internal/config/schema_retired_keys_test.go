// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestRetiredConfigurationKeysNameTheirReplacement(t *testing.T) {
	for _, tc := range []struct {
		name, body, path, replacement, version string
	}{
		{"otel", "otel: {}\n", "$.otel", "observability", "9"},
		{"update check", "update_check: true\n", "$.update_check", "update.check", "9"},
		{"audit sinks", "audit_sinks: []\n", "$.audit_sinks", "observability.destinations", "8"},
		{"audit db", "audit_db: /tmp/audit.db\n", "$.audit_db", "observability.local.path", "8"},
		{"judge bodies db", "judge_bodies_db: /tmp/judge.db\n", "$.judge_bodies_db", "observability.local.judge_bodies_path", "8"},
		{"splunk", "splunk: {}\n", "$.splunk", "splunk_hec", "8"},
		{"privacy", "privacy:\n  disable_redaction: false\n", "$.privacy", "remove it", "9"},
		{"discovery", "ai_discovery:\n  emit_otel: false\n", "$.ai_discovery.emit_otel", "ai.discovery", "8"},
		{"connector sinks", "observability:\n  connectors:\n    codex:\n      audit_sinks: []\n", "$.observability.connectors.codex.audit_sinks", "connector selectors", "8"},
		{"named connector sinks", "observability:\n  connectors:\n    'team.name':\n      audit_sinks: []\n", "$.observability.connectors", "connector selectors", "8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateV8SchemaBytes("config.yaml", []byte("config_version: 9\n"+tc.body))
			if err == nil {
				t.Fatal("retired key accepted")
			}
			message := err.Error()
			for _, want := range []string{tc.path[2:], "retired", "config_version " + tc.version, tc.replacement} {
				if !strings.Contains(message, want) {
					t.Errorf("error %q does not name %q", message, want)
				}
			}
			if strings.Contains(message, "did you mean") {
				t.Errorf("retired key received a spelling suggestion: %q", message)
			}
			var schemaErr *V8SchemaError
			if errors.As(err, &schemaErr) && schemaErr.Suggestion != "" {
				t.Errorf("retired key received suggestion %q", schemaErr.Suggestion)
			}
		})
	}
}

func TestUnknownConfigurationKeyKeepsSpellingSuggestion(t *testing.T) {
	err := ValidateV8SchemaBytes("config.yaml", []byte("config_version: 9\nguardrail:\n  mdoe: observe\n"))
	var schemaErr *V8SchemaError
	if !errors.As(err, &schemaErr) || schemaErr.Path != "$.guardrail.mdoe" || schemaErr.Suggestion != "mode" ||
		!strings.Contains(err.Error(), "did you mean mode?") {
		t.Fatalf("unknown key = %v (%+v), want the ordinary spelling suggestion", err, schemaErr)
	}
}

func TestV9RetiredConfigurationKeysNameTheirReplacement(t *testing.T) {
	for _, tc := range []struct{ name, body, replacement string }{
		{"skill actions", "skill_actions: {}\n", "admission.skill.actions"},
		{"mcp actions", "mcp_actions: {}\n", "admission.mcp.actions"},
		{"plugin actions", "plugin_actions: {}\n", "admission.plugin.actions"},
		{"watch bypass scan", "watch: {allow_list_bypass_scan: true}\n", "admission.<type>.allow_list_bypass_scan"},
		{"guardrail pack", "guardrail: {rule_pack_dir: /tmp/pack}\n", "rule_pack or custom_packs"},
		{"connector pack", "guardrail:\n  connectors:\n    codex: {rule_pack_dir: /tmp/pack}\n", "rule_pack or custom_packs"},
		{"profile pack", "guardrail:\n  profiles:\n    p: {rule_pack_dir: /tmp/pack}\n", "rule_pack or custom_packs"},
		{"profile connector pack", "guardrail:\n  profiles:\n    p:\n      connectors:\n        codex: {rule_pack_dir: /tmp/pack}\n", "rule_pack or custom_packs"},
		{"trace aliases", "observability:\n  trace_policy: {compatibility_aliases: true}\n", "canonical attribute names"},
		{"resource attribute", "observability:\n  resource:\n    attributes: {deployment.environment: prod}\n", "deployment.environment.name"},
		{"skill binary", "scanners:\n  skill_scanner: {binary: /tmp/scanner}\n", "managed scanner install"},
		{"skill virustotal", "scanners:\n  skill_scanner: {use_virustotal: true}\n", "scanners.skill_scanner.analyzers.virustotal.enabled"},
		{"skill aidefense", "scanners:\n  skill_scanner: {use_aidefense: true}\n", "scanners.skill_scanner.analyzers.aidefense.enabled"},
		{"skill credential", "scanners:\n  skill_scanner: {virustotal_api_key: old}\n", "defenseclaw keys set"},
		{"skill credential env", "scanners:\n  skill_scanner: {virustotal_api_key_env: OLD}\n", "scanners.skill_scanner.analyzers.virustotal.api_key_env"},
		{"mcp binary", "scanners:\n  mcp_scanner: {binary: /tmp/scanner}\n", "managed scanner install"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateV8SchemaBytes("config.yaml", []byte("config_version: 9\n"+tc.body))
			var yamlErr *V8YAMLError
			if !errors.As(err, &yamlErr) || yamlErr.Code != V8YAMLErrorLegacyKeyForbidden {
				t.Fatalf("retired key = %v, want a targeted refusal", err)
			}
			for _, want := range []string{"retired", "config_version 9", tc.replacement} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "did you mean") {
				t.Errorf("retired key received a spelling suggestion: %q", err)
			}
		})
	}
}
