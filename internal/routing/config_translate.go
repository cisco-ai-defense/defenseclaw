// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SRConfig is the vLLM Semantic Router v0.3 canonical configuration format.
type SRConfig struct {
	Version   string                    `yaml:"version"`
	Listeners []SRListenerConfig        `yaml:"listeners"`
	Providers map[string]SRProviderCfg  `yaml:"providers"`
	Routing   SRRoutingConfig           `yaml:"routing"`
	Global    map[string]interface{}    `yaml:"global,omitempty"`
}

type SRListenerConfig struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Timeout string `yaml:"timeout,omitempty"`
}

type SRProviderCfg struct {
	Provider        string   `yaml:"provider"`
	Model           string   `yaml:"model"`
	BaseURL         string   `yaml:"base_url,omitempty"`
	APIKeyEnv       string   `yaml:"api_key_env,omitempty"`
	Capabilities    []string `yaml:"capabilities,omitempty"`
	CostPer1kTokens float64  `yaml:"cost_per_1k_tokens,omitempty"`
}

type SRRoutingConfig struct {
	Signals   SRSignalsConfig    `yaml:"signals,omitempty"`
	Decisions []SRDecisionConfig `yaml:"decisions,omitempty"`
}

type SRSignalsConfig struct {
	Keywords      []SRKeywordSignal `yaml:"keywords,omitempty"`
	Embedding     *SRSignalToggle   `yaml:"embedding,omitempty"`
	Domain        *SRSignalToggle   `yaml:"domain,omitempty"`
	Complexity    *SRSignalToggle   `yaml:"complexity,omitempty"`
	ContextLength *SRContextLength  `yaml:"context_length,omitempty"`
}

type SRKeywordSignal struct {
	Name     string   `yaml:"name"`
	Keywords []string `yaml:"keywords"`
	Operator string   `yaml:"operator,omitempty"`
}

type SRSignalToggle struct {
	Enabled   bool    `yaml:"enabled"`
	Threshold float64 `yaml:"threshold,omitempty"`
}

type SRContextLength struct {
	Thresholds []int `yaml:"thresholds,omitempty"`
}

type SRDecisionConfig struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Priority    int           `yaml:"priority"`
	Rules       SRRules       `yaml:"rules"`
	ModelRefs   []SRModelRef  `yaml:"modelRefs"`
	Algorithm   *SRAlgorithm  `yaml:"algorithm,omitempty"`
}

type SRRules struct {
	Operator   string        `yaml:"operator"`
	Conditions []SRCondition `yaml:"conditions,omitempty"`
}

type SRCondition struct {
	Type          string  `yaml:"type"`
	Name          string  `yaml:"name"`
	MinConfidence float64 `yaml:"min_confidence,omitempty"`
	Value         string  `yaml:"value,omitempty"`
}

type SRModelRef struct {
	Model string `yaml:"model"`
}

type SRAlgorithm struct {
	Name string `yaml:"name,omitempty"`
}

// TranslateInput mirrors the fields needed from config.RoutingConfig
// without importing the config package.
type TranslateInput struct {
	Port              int
	Algorithm         string
	Models            []TranslateModel
	Signals           TranslateSignals
	Decisions         []TranslateDecision
	EmbeddingProvider string
	EmbeddingBaseURL  string
	EmbeddingModel    string
	LLMBaseURL        string
	LLMModel          string
}

type TranslateModel struct {
	Name            string
	Provider        string
	Model           string
	BaseURL         string
	APIKeyEnv       string
	Capabilities    []string
	CostPer1kTokens float64
	Weight          int
}

type TranslateSignals struct {
	Keywords           []TranslateKeyword
	EmbeddingEnabled   bool
	EmbeddingThreshold float64
	DomainEnabled      bool
	ComplexityEnabled  bool
	ContextThresholds  []int
}

type TranslateKeyword struct {
	Name     string
	Keywords []string
	Operator string
}

type TranslateDecision struct {
	Name       string
	Priority   int
	Conditions []TranslateCondition
	Operator   string
	ModelRefs  []string
	Algorithm  string
}

type TranslateCondition struct {
	Signal        string
	MinConfidence float64
	Value         string
}

// TranslateAndWrite converts a TranslateInput to the v0.3 SR config and writes it.
func TranslateAndWrite(input TranslateInput, dir string) (string, error) {
	cfg := Translate(input)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("routing: create dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("routing: marshal config: %w", err)
	}

	path := filepath.Join(dir, "config.yaml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", fmt.Errorf("routing: write tmp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("routing: rename config: %w", err)
	}

	return path, nil
}

// Translate converts TranslateInput to the canonical v0.3 SR config.
func Translate(input TranslateInput) *SRConfig {
	port := input.Port
	if port == 0 {
		port = 8888
	}

	cfg := &SRConfig{
		Version: "v0.3",
		Listeners: []SRListenerConfig{
			{
				Name:    fmt.Sprintf("http-%d", port),
				Address: "0.0.0.0",
				Port:    port,
				Timeout: "300s",
			},
		},
		Providers: make(map[string]SRProviderCfg),
	}

	// Providers (models as named map entries)
	for _, m := range input.Models {
		cfg.Providers[m.Name] = SRProviderCfg{
			Provider:        m.Provider,
			Model:           m.Model,
			BaseURL:         m.BaseURL,
			APIKeyEnv:       m.APIKeyEnv,
			Capabilities:    m.Capabilities,
			CostPer1kTokens: m.CostPer1kTokens,
		}
	}

	// Routing signals
	for _, k := range input.Signals.Keywords {
		cfg.Routing.Signals.Keywords = append(cfg.Routing.Signals.Keywords, SRKeywordSignal{
			Name:     k.Name,
			Keywords: k.Keywords,
			Operator: k.Operator,
		})
	}
	if input.Signals.EmbeddingEnabled {
		cfg.Routing.Signals.Embedding = &SRSignalToggle{Enabled: true, Threshold: input.Signals.EmbeddingThreshold}
	}
	if input.Signals.DomainEnabled {
		cfg.Routing.Signals.Domain = &SRSignalToggle{Enabled: true}
	}
	if input.Signals.ComplexityEnabled {
		cfg.Routing.Signals.Complexity = &SRSignalToggle{Enabled: true}
	}
	if len(input.Signals.ContextThresholds) > 0 {
		cfg.Routing.Signals.ContextLength = &SRContextLength{Thresholds: input.Signals.ContextThresholds}
	}

	// Routing decisions
	for _, d := range input.Decisions {
		op := d.Operator
		if op == "" {
			op = "AND"
		}
		rules := SRRules{Operator: op}
		for _, c := range d.Conditions {
			rules.Conditions = append(rules.Conditions, SRCondition{
				Type:          "keyword",
				Name:          c.Signal,
				MinConfidence: c.MinConfidence,
				Value:         c.Value,
			})
		}

		var modelRefs []SRModelRef
		for _, ref := range d.ModelRefs {
			modelRefs = append(modelRefs, SRModelRef{Model: ref})
		}

		dec := SRDecisionConfig{
			Name:        d.Name,
			Description: fmt.Sprintf("Route to %s", d.Name),
			Priority:    d.Priority,
			Rules:       rules,
			ModelRefs:   modelRefs,
		}
		if d.Algorithm != "" {
			dec.Algorithm = &SRAlgorithm{Name: d.Algorithm}
		}
		cfg.Routing.Decisions = append(cfg.Routing.Decisions, dec)
	}

	return cfg
}
