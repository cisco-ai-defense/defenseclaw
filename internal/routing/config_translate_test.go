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
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTranslate_MinimalConfig(t *testing.T) {
	input := TranslateInput{
		Port:      8090,
		Algorithm: "round_robin",
		Models: []TranslateModel{
			{
				Name:     "gpt-4",
				Provider: "openai",
				Model:    "gpt-4",
				BaseURL:  "https://api.openai.com/v1",
			},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{
					Name:     "security",
					Keywords: []string{"password", "secret"},
					Operator: "any",
				},
			},
		},
		Decisions: []TranslateDecision{
			{
				Name:      "default",
				Priority:  1,
				ModelRefs: []string{"gpt-4"},
				Conditions: []TranslateCondition{
					{
						Signal:        "keywords.security",
						MinConfidence: 0.8,
					},
				},
			},
		},
	}

	cfg := Translate(input)

	if cfg == nil {
		t.Fatal("Translate returned nil")
	}

	// Server
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 8090 {
		t.Errorf("Server.Port = %d, want 8090", cfg.Server.Port)
	}

	// Models
	if len(cfg.Models) != 1 {
		t.Fatalf("len(Models) = %d, want 1", len(cfg.Models))
	}
	if cfg.Models[0].Name != "gpt-4" {
		t.Errorf("Models[0].Name = %q, want gpt-4", cfg.Models[0].Name)
	}
	if cfg.Models[0].Provider != "openai" {
		t.Errorf("Models[0].Provider = %q, want openai", cfg.Models[0].Provider)
	}

	// Signals
	if len(cfg.Signals.Keywords) != 1 {
		t.Fatalf("len(Signals.Keywords) = %d, want 1", len(cfg.Signals.Keywords))
	}
	if cfg.Signals.Keywords[0].Name != "security" {
		t.Errorf("Signals.Keywords[0].Name = %q, want security", cfg.Signals.Keywords[0].Name)
	}
	if len(cfg.Signals.Keywords[0].Keywords) != 2 {
		t.Fatalf("len(Signals.Keywords[0].Keywords) = %d, want 2", len(cfg.Signals.Keywords[0].Keywords))
	}

	// Decisions
	if len(cfg.Decisions) != 1 {
		t.Fatalf("len(Decisions) = %d, want 1", len(cfg.Decisions))
	}
	if cfg.Decisions[0].Name != "default" {
		t.Errorf("Decisions[0].Name = %q, want default", cfg.Decisions[0].Name)
	}
	if cfg.Decisions[0].Priority != 1 {
		t.Errorf("Decisions[0].Priority = %d, want 1", cfg.Decisions[0].Priority)
	}
	if len(cfg.Decisions[0].ModelRefs) != 1 {
		t.Fatalf("len(Decisions[0].ModelRefs) = %d, want 1", len(cfg.Decisions[0].ModelRefs))
	}
	if cfg.Decisions[0].ModelRefs[0] != "gpt-4" {
		t.Errorf("Decisions[0].ModelRefs[0] = %q, want gpt-4", cfg.Decisions[0].ModelRefs[0])
	}
	if len(cfg.Decisions[0].Conditions) != 1 {
		t.Fatalf("len(Decisions[0].Conditions) = %d, want 1", len(cfg.Decisions[0].Conditions))
	}
	if cfg.Decisions[0].Conditions[0].Signal != "keywords.security" {
		t.Errorf("Decisions[0].Conditions[0].Signal = %q, want keywords.security", cfg.Decisions[0].Conditions[0].Signal)
	}
}

func TestTranslate_DefaultPort(t *testing.T) {
	input := TranslateInput{
		Models: []TranslateModel{
			{Name: "test", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"test"}},
		},
	}

	cfg := Translate(input)

	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080 (default)", cfg.Server.Port)
	}
}

func TestTranslate_EmbeddingConfig(t *testing.T) {
	input := TranslateInput{
		Port: 8080,
		Models: []TranslateModel{
			{Name: "test", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
			EmbeddingEnabled:   true,
			EmbeddingThreshold: 0.85,
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"test"}},
		},
		EmbeddingProvider: "openai",
		EmbeddingBaseURL:  "https://api.openai.com/v1",
		EmbeddingModel:    "text-embedding-ada-002",
	}

	cfg := Translate(input)

	if cfg.Embedding == nil {
		t.Fatal("Embedding is nil, expected non-nil")
	}
	if cfg.Embedding.Provider != "openai" {
		t.Errorf("Embedding.Provider = %q, want openai", cfg.Embedding.Provider)
	}
	if cfg.Embedding.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("Embedding.BaseURL = %q, want https://api.openai.com/v1", cfg.Embedding.BaseURL)
	}
	if cfg.Embedding.Model != "text-embedding-ada-002" {
		t.Errorf("Embedding.Model = %q, want text-embedding-ada-002", cfg.Embedding.Model)
	}

	// Check signal is enabled
	if cfg.Signals.Embedding == nil {
		t.Fatal("Signals.Embedding is nil, expected non-nil")
	}
	if !cfg.Signals.Embedding.Enabled {
		t.Error("Signals.Embedding.Enabled = false, want true")
	}
	if cfg.Signals.Embedding.Threshold != 0.85 {
		t.Errorf("Signals.Embedding.Threshold = %f, want 0.85", cfg.Signals.Embedding.Threshold)
	}
}

func TestTranslate_ClassifierConfig(t *testing.T) {
	input := TranslateInput{
		Port: 8080,
		Models: []TranslateModel{
			{Name: "test", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"test"}},
		},
		LLMBaseURL: "http://localhost:8000/v1",
		LLMModel:   "llama-3.1",
	}

	cfg := Translate(input)

	if cfg.Classifier == nil {
		t.Fatal("Classifier is nil, expected non-nil")
	}
	if cfg.Classifier.BaseURL != "http://localhost:8000/v1" {
		t.Errorf("Classifier.BaseURL = %q, want http://localhost:8000/v1", cfg.Classifier.BaseURL)
	}
	if cfg.Classifier.Model != "llama-3.1" {
		t.Errorf("Classifier.Model = %q, want llama-3.1", cfg.Classifier.Model)
	}
}

func TestTranslateAndWrite_WritesFile(t *testing.T) {
	tmpDir := t.TempDir()

	input := TranslateInput{
		Port: 8090,
		Models: []TranslateModel{
			{Name: "gpt-4", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"gpt-4"}},
		},
	}

	path, err := TranslateAndWrite(input, tmpDir)
	if err != nil {
		t.Fatalf("TranslateAndWrite failed: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "config.yaml")
	if path != expectedPath {
		t.Errorf("path = %q, want %q", path, expectedPath)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not found: %v", err)
	}

	// Verify file is valid YAML
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var cfg SRConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify content
	if cfg.Server.Port != 8090 {
		t.Errorf("parsed config Server.Port = %d, want 8090", cfg.Server.Port)
	}
	if len(cfg.Models) != 1 {
		t.Errorf("parsed config has %d models, want 1", len(cfg.Models))
	}
}

func TestTranslateAndWrite_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()

	input := TranslateInput{
		Port: 8080,
		Models: []TranslateModel{
			{Name: "test", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"test"}},
		},
	}

	_, err := TranslateAndWrite(input, tmpDir)
	if err != nil {
		t.Fatalf("TranslateAndWrite failed: %v", err)
	}

	// Verify .tmp file doesn't linger
	tmpPath := filepath.Join(tmpDir, "config.yaml.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("tmp file still exists after write: %v", err)
	}
}

func TestTranslate_AllSignals(t *testing.T) {
	input := TranslateInput{
		Port: 8080,
		Models: []TranslateModel{
			{Name: "test", Provider: "openai", Model: "gpt-4"},
		},
		Signals: TranslateSignals{
			Keywords: []TranslateKeyword{
				{Name: "test", Keywords: []string{"test"}},
			},
			EmbeddingEnabled:   true,
			EmbeddingThreshold: 0.9,
			DomainEnabled:      true,
			ComplexityEnabled:  true,
			ContextThresholds:  []int{100, 500, 1000},
		},
		Decisions: []TranslateDecision{
			{Name: "test", Priority: 1, ModelRefs: []string{"test"}},
		},
	}

	cfg := Translate(input)

	// Embedding
	if cfg.Signals.Embedding == nil || !cfg.Signals.Embedding.Enabled {
		t.Error("Signals.Embedding not enabled")
	}
	if cfg.Signals.Embedding.Threshold != 0.9 {
		t.Errorf("Signals.Embedding.Threshold = %f, want 0.9", cfg.Signals.Embedding.Threshold)
	}

	// Domain
	if cfg.Signals.Domain == nil || !cfg.Signals.Domain.Enabled {
		t.Error("Signals.Domain not enabled")
	}

	// Complexity
	if cfg.Signals.Complexity == nil || !cfg.Signals.Complexity.Enabled {
		t.Error("Signals.Complexity not enabled")
	}

	// Context length
	if cfg.Signals.ContextLength == nil {
		t.Fatal("Signals.ContextLength is nil")
	}
	if len(cfg.Signals.ContextLength.Thresholds) != 3 {
		t.Errorf("len(ContextLength.Thresholds) = %d, want 3", len(cfg.Signals.ContextLength.Thresholds))
	}
}
