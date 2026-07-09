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
	"strings"
	"testing"
)

func validAgentControlConfig() AgentControlConfig {
	return AgentControlConfig{
		Enabled:             true,
		AgentName:           "defenseclaw-policy-sync",
		TargetType:          "defenseclaw.installation",
		TargetID:            "installation-1",
		RefreshSeconds:      60,
		CachePollSeconds:    2,
		InitRetryMaxSeconds: 300,
		OPA: AgentControlOPAConfig{
			Enabled:    true,
			Precedence: "stricter",
			Activation: "reload",
		},
		RulePack: AgentControlRulePackConfig{
			Activation: "restart",
			MaxRules:   1000,
		},
		Observability: AgentControlObservabilityConfig{Enabled: true, IncludeContent: true},
	}
}

func TestAgentControlConfigValidate(t *testing.T) {
	cfg := validAgentControlConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*AgentControlConfig){
		"missing target":      func(c *AgentControlConfig) { c.TargetID = "" },
		"bad agent name":      func(c *AgentControlConfig) { c.AgentName = "shared-application-agent" },
		"bad target type":     func(c *AgentControlConfig) { c.TargetType = "application" },
		"bad precedence":      func(c *AgentControlConfig) { c.OPA.Precedence = "merge" },
		"bad OPA activation":  func(c *AgentControlConfig) { c.OPA.Activation = "restart" },
		"bad rule activation": func(c *AgentControlConfig) { c.RulePack.Activation = "reload" },
		"bad max rules":       func(c *AgentControlConfig) { c.RulePack.MaxRules = 1001 },
		"bad refresh":         func(c *AgentControlConfig) { c.RefreshSeconds = 0 },
		"bad cache poll":      func(c *AgentControlConfig) { c.CachePollSeconds = 0 },
		"bad init retry":      func(c *AgentControlConfig) { c.InitRetryMaxSeconds = 0 },
		"overlong target":     func(c *AgentControlConfig) { c.TargetID = strings.Repeat("x", 256) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validAgentControlConfig()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDefaultAgentControlConfig(t *testing.T) {
	cfg := DefaultConfig().AgentControl
	if cfg.Enabled {
		t.Fatal("Agent Control integration must remain opt-in")
	}
	if !cfg.Observability.Enabled || !cfg.Observability.IncludeContent {
		t.Fatalf("Agent Control observability defaults = %+v, want enabled exact content", cfg.Observability)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default Agent Control config is invalid: %v", err)
	}
}

func TestGuardrailConfigRejectsDuplicateOverlayDirs(t *testing.T) {
	cfg := GuardrailConfig{RulePackOverlayDirs: []string{"/tmp/rules", "/tmp/rules/"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate overlay error")
	}
}
