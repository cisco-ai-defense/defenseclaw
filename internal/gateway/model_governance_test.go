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

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// newTestOPA creates a temporary OPA engine with the given model_governance
// data and the production Rego policy.
func newTestOPA(t *testing.T, govData map[string]interface{}) *policy.Engine {
	t.Helper()

	dir := t.TempDir()

	data := map[string]interface{}{
		"model_governance": govData,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o644); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	regoSrc, err := os.ReadFile("../../policies/rego/model_governance.rego")
	if err != nil {
		t.Fatalf("read model_governance.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model_governance.rego"), regoSrc, 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}

	engine, err := policy.New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return engine
}

func govCfg(mode string) config.ModelGovernanceConfig {
	return config.ModelGovernanceConfig{
		Enabled: true,
		Mode:    mode,
	}
}

func TestNilGovernorAllowsAll(t *testing.T) {
	var g *ModelGovernor
	v := g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Fatalf("nil governor should allow all requests")
	}
}

func TestDisabledGovernorReturnsNil(t *testing.T) {
	g := NewModelGovernor(config.ModelGovernanceConfig{Enabled: false}, nil)
	if g != nil {
		t.Fatalf("disabled config should produce nil governor")
	}
}

func TestNoOPAEngineAllowsAll(t *testing.T) {
	g := NewModelGovernor(govCfg("enforce"), nil)
	v := g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Fatalf("nil OPA engine should allow all requests (fail-open)")
	}
}

func TestProviderAllowList(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{"openai", "anthropic"},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	tests := []struct {
		provider string
		model    string
		allowed  bool
		rule     string
	}{
		{"openai", "gpt-4o", true, ""},
		{"anthropic", "claude-3.5-sonnet", true, ""},
		{"openrouter", "gpt-4o", false, "provider-allow"},
		{"gemini", "gemini-pro", false, "provider-allow"},
		{"", "gpt-4o", true, ""},
	}

	for _, tt := range tests {
		v := g.Check(tt.provider, tt.model)
		if v.Allowed != tt.allowed {
			t.Errorf("Check(%q, %q): got allowed=%v, want %v (reason=%s)",
				tt.provider, tt.model, v.Allowed, tt.allowed, v.Reason)
		}
		if !v.Allowed && v.Rule != tt.rule {
			t.Errorf("Check(%q, %q): got rule=%q, want %q",
				tt.provider, tt.model, v.Rule, tt.rule)
		}
	}
}

func TestProviderDenyList(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{"openrouter", "bedrock"},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	tests := []struct {
		provider string
		allowed  bool
	}{
		{"openai", true},
		{"anthropic", true},
		{"openrouter", false},
		{"bedrock", false},
		{"gemini", true},
	}

	for _, tt := range tests {
		v := g.Check(tt.provider, "some-model")
		if v.Allowed != tt.allowed {
			t.Errorf("Check(%q, ...): got allowed=%v, want %v", tt.provider, v.Allowed, tt.allowed)
		}
		if !v.Allowed && v.Rule != "provider-deny" {
			t.Errorf("Check(%q, ...): got rule=%q, want provider-deny", tt.provider, v.Rule)
		}
	}
}

func TestModelAllowListWithGlobs(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{"gpt-4o", "gpt-4o-*", "claude-*"},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	tests := []struct {
		model   string
		allowed bool
	}{
		{"gpt-4o", true},
		{"gpt-4o-mini", true},
		{"gpt-4o-2024-08-06", true},
		{"claude-3.5-sonnet", true},
		{"claude-3-opus", true},
		{"gpt-3.5-turbo", false},
		{"llama-3-70b", false},
		{"gemini-pro", false},
	}

	for _, tt := range tests {
		v := g.Check("openai", tt.model)
		if v.Allowed != tt.allowed {
			t.Errorf("Check(openai, %q): got allowed=%v, want %v (reason=%s)",
				tt.model, v.Allowed, tt.allowed, v.Reason)
		}
	}
}

func TestModelDenyListWithGlobs(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{"gpt-3.5-*", "llama-*"},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	tests := []struct {
		model   string
		allowed bool
	}{
		{"gpt-4o", true},
		{"claude-3.5-sonnet", true},
		{"gpt-3.5-turbo", false},
		{"gpt-3.5-turbo-16k", false},
		{"llama-3-70b", false},
		{"llama-2-13b", false},
	}

	for _, tt := range tests {
		v := g.Check("openai", tt.model)
		if v.Allowed != tt.allowed {
			t.Errorf("Check(openai, %q): got allowed=%v, want %v", tt.model, v.Allowed, tt.allowed)
		}
	}
}

func TestCombinedProviderAllowedModelDenied(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{"openai"},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{"gpt-3.5-*"},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	v := g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Error("openai/gpt-4o should be allowed")
	}

	v = g.Check("openai", "gpt-3.5-turbo")
	if v.Allowed {
		t.Error("openai/gpt-3.5-turbo should be denied by model deny list")
	}
	if v.Rule != "model-deny" {
		t.Errorf("got rule=%q, want model-deny", v.Rule)
	}

	v = g.Check("anthropic", "claude-3.5-sonnet")
	if v.Allowed {
		t.Error("anthropic should be denied by provider allow list")
	}
	if v.Rule != "provider-allow" {
		t.Errorf("got rule=%q, want provider-allow", v.Rule)
	}
}

func TestEmptyListsAllowAll(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	v := g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Error("empty lists should allow all")
	}

	v = g.Check("bedrock", "llama-3-70b")
	if !v.Allowed {
		t.Error("empty lists should allow all")
	}
}

func TestCaseInsensitivity(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{"OpenAI", "Anthropic"},
			"deny":  []string{},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{"GPT-3.5-*"},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	v := g.Check("OPENAI", "gpt-4o")
	if !v.Allowed {
		t.Error("provider matching should be case-insensitive")
	}

	v = g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Error("provider matching should be case-insensitive")
	}

	v = g.Check("openai", "GPT-3.5-turbo")
	if v.Allowed {
		t.Error("model matching should be case-insensitive")
	}
}

func TestMonitorMode(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{"bedrock"},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("monitor"), opa)

	if !g.IsMonitorOnly() {
		t.Error("should report monitor mode")
	}

	v := g.Check("bedrock", "some-model")
	if v.Allowed {
		t.Error("Check should still return denied even in monitor mode (caller decides enforcement)")
	}
}

func TestGovernanceBlockMessage(t *testing.T) {
	g := NewModelGovernor(config.ModelGovernanceConfig{
		Enabled:      true,
		BlockMessage: "Custom block message",
	}, nil)
	if g.BlockMessage() != "Custom block message" {
		t.Error("should return custom block message")
	}

	g2 := NewModelGovernor(config.ModelGovernanceConfig{Enabled: true}, nil)
	if g2.BlockMessage() == "" {
		t.Error("should return default block message when empty")
	}

	var nilGov *ModelGovernor
	if nilGov.BlockMessage() == "" {
		t.Error("nil governor should return default block message")
	}
}

func TestLogAllowed(t *testing.T) {
	g := NewModelGovernor(config.ModelGovernanceConfig{
		Enabled:    true,
		LogAllowed: true,
	}, nil)
	if !g.LogAllowed() {
		t.Error("should report log_allowed=true")
	}

	g2 := NewModelGovernor(config.ModelGovernanceConfig{Enabled: true}, nil)
	if g2.LogAllowed() {
		t.Error("should default to log_allowed=false")
	}
}

func TestProviderAllowAndDenyCombined(t *testing.T) {
	opa := newTestOPA(t, map[string]interface{}{
		"providers": map[string]interface{}{
			"allow": []string{"openai", "bedrock"},
			"deny":  []string{"bedrock"},
		},
		"models": map[string]interface{}{
			"allow": []string{},
			"deny":  []string{},
		},
	})
	g := NewModelGovernor(govCfg("enforce"), opa)

	v := g.Check("openai", "gpt-4o")
	if !v.Allowed {
		t.Error("openai should be allowed")
	}

	v = g.Check("bedrock", "some-model")
	if v.Allowed {
		t.Error("bedrock should be denied by deny list even if in allow list")
	}
}
