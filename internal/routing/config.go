// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import "fmt"

// RoutingConfig is the opt-in intelligent routing configuration.
type RoutingConfig struct {
	Enabled   bool           `yaml:"enabled" mapstructure:"enabled"`
	Models    []ModelBackend `yaml:"models" mapstructure:"models"`
	Signals   SignalConfig   `yaml:"signals" mapstructure:"signals"`
	Decisions []DecisionRule `yaml:"decisions" mapstructure:"decisions"`
}

// ModelBackend defines a named upstream LLM backend.
type ModelBackend struct {
	Name         string   `yaml:"name" mapstructure:"name"`
	Provider     string   `yaml:"provider" mapstructure:"provider"`
	Model        string   `yaml:"model" mapstructure:"model"`
	BaseURL      string   `yaml:"base_url,omitempty" mapstructure:"base_url"`
	APIKeyEnv    string   `yaml:"api_key_env,omitempty" mapstructure:"api_key_env"`
	Weight       int      `yaml:"weight,omitempty" mapstructure:"weight"`
	Capabilities []string `yaml:"capabilities,omitempty" mapstructure:"capabilities"`
}

// SignalConfig holds all signal definitions for classification.
type SignalConfig struct {
	Keywords []KeywordSignal `yaml:"keywords,omitempty" mapstructure:"keywords"`
}

// KeywordSignal defines a keyword-based signal.
type KeywordSignal struct {
	Name     string   `yaml:"name" mapstructure:"name"`
	Keywords []string `yaml:"keywords" mapstructure:"keywords"`
	Operator string   `yaml:"operator,omitempty" mapstructure:"operator"`
}

// DecisionRule defines a prioritized routing rule.
type DecisionRule struct {
	Name       string      `yaml:"name" mapstructure:"name"`
	Priority   int         `yaml:"priority" mapstructure:"priority"`
	Conditions []Condition `yaml:"conditions,omitempty" mapstructure:"conditions"`
	Operator   string      `yaml:"operator,omitempty" mapstructure:"operator"`
	ModelRefs  []string    `yaml:"model_refs" mapstructure:"model_refs"`
	Algorithm  string      `yaml:"algorithm,omitempty" mapstructure:"algorithm"`
}

// Condition is a single signal match requirement within a decision.
type Condition struct {
	Type string `yaml:"type" mapstructure:"type"`
	Name string `yaml:"name" mapstructure:"name"`
}

// Validate checks the routing config for internal consistency.
func (c *RoutingConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	modelNames := make(map[string]bool, len(c.Models))
	for _, m := range c.Models {
		if m.Name == "" {
			return fmt.Errorf("routing: model entry missing name")
		}
		if modelNames[m.Name] {
			return fmt.Errorf("routing: duplicate model name %q", m.Name)
		}
		modelNames[m.Name] = true
	}
	for _, d := range c.Decisions {
		for _, ref := range d.ModelRefs {
			if !modelNames[ref] {
				return fmt.Errorf("routing: decision %q references unknown backend %q", d.Name, ref)
			}
		}
	}
	return nil
}
