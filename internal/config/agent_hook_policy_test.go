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
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigV8SchemaAcceptsManagedHookPolicyKeys(t *testing.T) {
	raw := []byte(`config_version: 8
claude_code:
  enabled: true
  allow_unmanaged_hooks: true
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
