// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigV8SchemaAcceptsManagedHookPolicyKeys(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	raw := []byte(`config_version: 8
claude_code:
  enabled: true
  allow_unmanaged_hooks: true
connector_hooks:
  cursor:
    enabled: true
    approved_foreign_hooks:
      - ` + digest + `
      - sha256:` + strings.ToUpper(digest) + `
`)
	compile := func(source string, data []byte) error {
		_, err := ParseCompileObservabilityV8(source, data, ObservabilityV8CompileOptions{DefaultDataDir: "/tmp/defenseclaw"})
		return err
	}
	if err := compile("managed-hook-policy-v8.yaml", raw); err != nil {
		t.Fatalf("v8 compiler rejected the managed hook policy keys: %v", err)
	}
	var parsed Config
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("claude_code.allow_unmanaged_hooks was not honored")
	}
	approved, err := parsed.ApprovedForeignHooksForConnector("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || approved[0] != digest {
		t.Fatalf("approved foreign hooks = %v, want one normalized digest", approved)
	}

	bad := []byte(`config_version: 8
connector_hooks:
  cursor:
    approved_foreign_hooks:
      - not-a-digest
`)
	if err := compile("managed-hook-policy-bad-v8.yaml", bad); err == nil {
		t.Fatal("v8 compiler accepted a malformed approved_foreign_hooks digest")
	}
	unknown := []byte(`config_version: 8
claude_code:
  allow_unmanaged_hook: true
`)
	if err := compile("managed-hook-policy-typo-v8.yaml", unknown); err == nil {
		t.Fatal("v8 compiler accepted a misspelled managed hook policy key")
	}
}

func TestManagedHookPolicyDefaultsAreSecure(t *testing.T) {
	var cfg *Config
	if cfg.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("nil config opted out of the Claude managed-hooks-only lock")
	}
	empty := &Config{}
	if empty.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("default config opted out of the Claude managed-hooks-only lock")
	}
	approved, err := empty.ApprovedForeignHooksForConnector("cursor")
	if err != nil || approved == nil || len(approved) != 0 {
		t.Fatalf("default allowlist = (%v, %v), want non-nil empty", approved, err)
	}
	invalid := &Config{ConnectorHooks: map[string]AgentHookConfig{
		"cursor": {ApprovedForeignHooks: []string{"md5:abc"}},
	}}
	if _, err := invalid.ApprovedForeignHooksForConnector("cursor"); err == nil {
		t.Fatal("malformed allowlist entry accepted")
	}
	legacy := &Config{ClaudeCode: AgentHookConfig{AllowUnmanagedHooks: true}}
	if !legacy.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("legacy claude_code block opt-out was not honored")
	}
	legacy.ConnectorHooks = map[string]AgentHookConfig{"claudecode": {Enabled: true}}
	if !legacy.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("claude_code opt-out was hidden by connector_hooks.claudecode")
	}
	legacy.ClaudeCode.AllowUnmanagedHooks = false
	legacy.ConnectorHooks["claudecode"] = AgentHookConfig{AllowUnmanagedHooks: true}
	if !legacy.ClaudeCodeAllowUnmanagedHooks() {
		t.Fatal("connector_hooks.claudecode opt-out was not honored")
	}
}
