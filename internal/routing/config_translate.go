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

package routing

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SRConfig is the semantic router's native configuration format.
// DefenseClaw generates this from its own RoutingConfig.
type SRConfig struct {
	Server     SRServerConfig      `yaml:"server"`
	Listeners  []SRListenerConfig  `yaml:"listeners"`
	Models     []SRModelConfig     `yaml:"models"`
	Signals    SRSignalsConfig     `yaml:"signals"`
	Decisions  []SRDecisionConfig  `yaml:"decisions"`
	Embedding  *SREmbeddingConfig  `yaml:"embedding,omitempty"`
	Classifier *SRClassifierConfig `yaml:"classifier,omitempty"`
}

type SRListenerConfig struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Timeout string `yaml:"timeout,omitempty"`
}

type SRServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type SRModelConfig struct {
	Name            string   `yaml:"name"`
	Provider        string   `yaml:"provider"`
	Model           string   `yaml:"model"`
	BaseURL         string   `yaml:"base_url,omitempty"`
	APIKeyEnv       string   `yaml:"api_key_env,omitempty"`
	Capabilities    []string `yaml:"capabilities,omitempty"`
	CostPer1kTokens float64  `yaml:"cost_per_1k_tokens,omitempty"`
	Weight          int      `yaml:"weight,omitempty"`
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
	Name       string        `yaml:"name"`
	Priority   int           `yaml:"priority"`
	Conditions []SRCondition `yaml:"conditions,omitempty"`
	Operator   string        `yaml:"operator,omitempty"`
	ModelRefs  []string      `yaml:"model_refs"`
	Algorithm  string        `yaml:"algorithm,omitempty"`
}

type SRCondition struct {
	Signal        string  `yaml:"signal"`
	MinConfidence float64 `yaml:"min_confidence,omitempty"`
	Value         string  `yaml:"value,omitempty"`
}

type SREmbeddingConfig struct {
	Provider string `yaml:"provider"`
	BaseURL  string `yaml:"base_url"`
	Model    string `yaml:"model"`
}

type SRClassifierConfig struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
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

// TranslateAndWrite converts a TranslateInput to SRConfig and writes it to dir/config.yaml.
// Returns the path written.
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

// Translate converts TranslateInput to the SR native config structure.
func Translate(input TranslateInput) *SRConfig {
	port := input.Port
	if port == 0 {
		port = 8888
	}

	cfg := &SRConfig{
		Server: SRServerConfig{Host: "127.0.0.1", Port: port},
		Listeners: []SRListenerConfig{
			{
				Name:    fmt.Sprintf("http-%d", port),
				Address: "0.0.0.0",
				Port:    port,
				Timeout: "300s",
			},
		},
	}

	// Models
	for _, m := range input.Models {
		cfg.Models = append(cfg.Models, SRModelConfig{
			Name:            m.Name,
			Provider:        m.Provider,
			Model:           m.Model,
			BaseURL:         m.BaseURL,
			APIKeyEnv:       m.APIKeyEnv,
			Capabilities:    m.Capabilities,
			CostPer1kTokens: m.CostPer1kTokens,
			Weight:          m.Weight,
		})
	}

	// Signals
	for _, k := range input.Signals.Keywords {
		cfg.Signals.Keywords = append(cfg.Signals.Keywords, SRKeywordSignal{
			Name:     k.Name,
			Keywords: k.Keywords,
			Operator: k.Operator,
		})
	}
	if input.Signals.EmbeddingEnabled {
		cfg.Signals.Embedding = &SRSignalToggle{Enabled: true, Threshold: input.Signals.EmbeddingThreshold}
	}
	if input.Signals.DomainEnabled {
		cfg.Signals.Domain = &SRSignalToggle{Enabled: true}
	}
	if input.Signals.ComplexityEnabled {
		cfg.Signals.Complexity = &SRSignalToggle{Enabled: true}
	}
	if len(input.Signals.ContextThresholds) > 0 {
		cfg.Signals.ContextLength = &SRContextLength{Thresholds: input.Signals.ContextThresholds}
	}

	// Decisions
	for _, d := range input.Decisions {
		dec := SRDecisionConfig{
			Name:      d.Name,
			Priority:  d.Priority,
			Operator:  d.Operator,
			ModelRefs: d.ModelRefs,
			Algorithm: d.Algorithm,
		}
		for _, c := range d.Conditions {
			dec.Conditions = append(dec.Conditions, SRCondition{
				Signal:        c.Signal,
				MinConfidence: c.MinConfidence,
				Value:         c.Value,
			})
		}
		cfg.Decisions = append(cfg.Decisions, dec)
	}

	// Embedding
	if input.EmbeddingBaseURL != "" && input.EmbeddingModel != "" {
		cfg.Embedding = &SREmbeddingConfig{
			Provider: input.EmbeddingProvider,
			BaseURL:  input.EmbeddingBaseURL,
			Model:    input.EmbeddingModel,
		}
	}

	// Classifier
	if input.LLMBaseURL != "" && input.LLMModel != "" {
		cfg.Classifier = &SRClassifierConfig{BaseURL: input.LLMBaseURL, Model: input.LLMModel}
	}

	return cfg
}
