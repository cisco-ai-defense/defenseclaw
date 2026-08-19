// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTranslateFullConfig_MinimalInput(t *testing.T) {
	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "fast", ProviderModelID: "gpt-4o-mini", APIFormat: "openai"},
		},
	}

	cfg := TranslateFullConfig(input)

	if cfg.Version != "v0.3" {
		t.Errorf("expected version v0.3, got %q", cfg.Version)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Port != 8080 {
		t.Errorf("expected listener port 8080, got %d", cfg.Listeners[0].Port)
	}
	if len(cfg.Providers.Models) != 1 {
		t.Fatalf("expected 1 provider model, got %d", len(cfg.Providers.Models))
	}
	if cfg.Providers.Models[0].Name != "fast" {
		t.Errorf("expected model name 'fast', got %q", cfg.Providers.Models[0].Name)
	}
}

func TestTranslateFullConfig_DefaultPort(t *testing.T) {
	input := TranslateFullInput{
		Models: []TranslateFullModel{
			{Name: "m1", ProviderModelID: "claude-sonnet-4-6", APIFormat: "anthropic"},
		},
	}

	cfg := TranslateFullConfig(input)

	if cfg.Listeners[0].Port != 8888 {
		t.Errorf("expected default port 8888, got %d", cfg.Listeners[0].Port)
	}
}

func TestTranslateFullConfig_AllSignalTypes(t *testing.T) {
	input := TranslateFullInput{
		Port: 9000,
		Models: []TranslateFullModel{
			{Name: "m1", ProviderModelID: "gpt-4o", APIFormat: "openai"},
		},
		Signals: TranslateFullSignals{
			Keywords: []TranslateKeywordV2{
				{Name: "code_kw", Keywords: []string{"code", "debug"}, Operator: "OR", Method: "bm25"},
			},
			Embedding: []TranslateEmbeddingSignal{
				{Name: "tech_support", Threshold: 0.75, AggregationMethod: "max", Candidates: []TranslateEmbeddingCandidate{{Text: "troubleshooting"}, {Text: "config help"}}},
			},
			Domain: []TranslateDomainSignal{
				{Name: "cs", Description: "Computer science", MMLUCategories: []string{"computer science"}},
			},
			Complexity: []TranslateComplexitySignal{
				{Name: "needs_reasoning", Threshold: 0.8, Description: "Hard prompts"},
			},
			Context: []TranslateContextSignal{
				{Name: "long", MinTokens: 32000, MaxTokens: 256000},
			},
			Structure: []TranslateStructureSignal{
				{Name: "many_questions", Description: "Multiple questions"},
			},
			Jailbreak: []TranslateJailbreakSignal{
				{Name: "injection", Threshold: 0.8},
			},
			PII: []TranslatePIISignal{
				{Name: "restricted", Threshold: 0.85},
			},
			Language: []TranslateLanguageSignal{
				{Name: "zh", Description: "Chinese"},
			},
		},
	}

	cfg := TranslateFullConfig(input)

	if len(cfg.Routing.Signals.Keywords) != 1 {
		t.Errorf("expected 1 keyword signal, got %d", len(cfg.Routing.Signals.Keywords))
	}
	if cfg.Routing.Signals.Keywords[0].Method != "bm25" {
		t.Errorf("expected method bm25, got %q", cfg.Routing.Signals.Keywords[0].Method)
	}
	if len(cfg.Routing.Signals.Embedding) != 1 {
		t.Errorf("expected 1 embedding signal, got %d", len(cfg.Routing.Signals.Embedding))
	}
	if cfg.Routing.Signals.Embedding[0].Threshold != 0.75 {
		t.Errorf("expected threshold 0.75, got %f", cfg.Routing.Signals.Embedding[0].Threshold)
	}
	if len(cfg.Routing.Signals.Domain) != 1 {
		t.Errorf("expected 1 domain signal, got %d", len(cfg.Routing.Signals.Domain))
	}
	if len(cfg.Routing.Signals.Complexity) != 1 {
		t.Errorf("expected 1 complexity signal, got %d", len(cfg.Routing.Signals.Complexity))
	}
	if len(cfg.Routing.Signals.Context) != 1 {
		t.Errorf("expected 1 context signal, got %d", len(cfg.Routing.Signals.Context))
	}
	if len(cfg.Routing.Signals.Structure) != 1 {
		t.Errorf("expected 1 structure signal, got %d", len(cfg.Routing.Signals.Structure))
	}
	if len(cfg.Routing.Signals.Jailbreak) != 1 {
		t.Errorf("expected 1 jailbreak signal, got %d", len(cfg.Routing.Signals.Jailbreak))
	}
	if len(cfg.Routing.Signals.PII) != 1 {
		t.Errorf("expected 1 pii signal, got %d", len(cfg.Routing.Signals.PII))
	}
	if len(cfg.Routing.Signals.Language) != 1 {
		t.Errorf("expected 1 language signal, got %d", len(cfg.Routing.Signals.Language))
	}
}

func TestTranslateFullConfig_Decisions(t *testing.T) {
	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "reasoning", ProviderModelID: "claude-sonnet-4-6", APIFormat: "anthropic"},
			{Name: "fast", ProviderModelID: "gpt-4o-mini", APIFormat: "openai"},
		},
		Decisions: []TranslateFullDecision{
			{
				Name:        "code_route",
				Description: "Route code tasks",
				Priority:    100,
				Tier:        "1",
				Operator:    "AND",
				Conditions: []TranslateFullCondition{
					{Type: "keyword", Name: "code_kw"},
					{Type: "complexity", Name: "needs_reasoning"},
				},
				ModelRefs: []TranslateFullModelRef{
					{Model: "reasoning", UseReasoning: true, ReasoningEffort: "high", Weight: 1.0},
				},
				Algorithm: &TranslateAlgorithm{Type: "confidence"},
				Plugins: []TranslatePlugin{
					{Type: "system_prompt", Configuration: map[string]interface{}{"enabled": true, "system_prompt": "You are a code expert."}},
				},
			},
			{
				Name:     "default_route",
				Priority: 10,
				Operator: "AND",
				ModelRefs: []TranslateFullModelRef{
					{Model: "fast"},
				},
				Algorithm: &TranslateAlgorithm{Type: "static"},
			},
		},
	}

	cfg := TranslateFullConfig(input)

	if len(cfg.Routing.Decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(cfg.Routing.Decisions))
	}

	d := cfg.Routing.Decisions[0]
	if d.Name != "code_route" {
		t.Errorf("expected decision name 'code_route', got %q", d.Name)
	}
	if d.Priority != 100 {
		t.Errorf("expected priority 100, got %d", d.Priority)
	}
	if d.Rules.Operator != "AND" {
		t.Errorf("expected operator AND, got %q", d.Rules.Operator)
	}
	if len(d.Rules.Conditions) != 2 {
		t.Errorf("expected 2 conditions, got %d", len(d.Rules.Conditions))
	}
	if len(d.ModelRefs) != 1 {
		t.Fatalf("expected 1 model ref, got %d", len(d.ModelRefs))
	}
	if d.ModelRefs[0].UseReasoning != true {
		t.Error("expected use_reasoning true")
	}
	if d.ModelRefs[0].ReasoningEffort != "high" {
		t.Errorf("expected reasoning_effort 'high', got %q", d.ModelRefs[0].ReasoningEffort)
	}
	if d.Algorithm == nil || d.Algorithm.Type != "confidence" {
		t.Error("expected algorithm type 'confidence'")
	}
	if len(d.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(d.Plugins))
	}
	if d.Plugins[0].Type != "system_prompt" {
		t.Errorf("expected plugin type 'system_prompt', got %q", d.Plugins[0].Type)
	}
}

func TestTranslateFullConfig_NestedConditions(t *testing.T) {
	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "m1", ProviderModelID: "gpt-4o", APIFormat: "openai"},
		},
		Decisions: []TranslateFullDecision{
			{
				Name:     "nested_route",
				Priority: 50,
				Operator: "AND",
				Conditions: []TranslateFullCondition{
					{Type: "domain", Name: "business"},
					{
						Operator: "OR",
						Conditions: []TranslateFullCondition{
							{Type: "keyword", Name: "urgent"},
							{Type: "complexity", Name: "hard"},
						},
					},
					{
						Operator: "NOT",
						Conditions: []TranslateFullCondition{
							{Type: "jailbreak", Name: "injection"},
						},
					},
				},
				ModelRefs: []TranslateFullModelRef{{Model: "m1"}},
			},
		},
	}

	cfg := TranslateFullConfig(input)

	d := cfg.Routing.Decisions[0]
	if len(d.Rules.Conditions) != 3 {
		t.Fatalf("expected 3 top-level conditions, got %d", len(d.Rules.Conditions))
	}
	orCond := d.Rules.Conditions[1]
	if orCond.Operator != "OR" {
		t.Errorf("expected nested OR operator, got %q", orCond.Operator)
	}
	if len(orCond.Conditions) != 2 {
		t.Errorf("expected 2 children in OR, got %d", len(orCond.Conditions))
	}
	notCond := d.Rules.Conditions[2]
	if notCond.Operator != "NOT" {
		t.Errorf("expected nested NOT operator, got %q", notCond.Operator)
	}
}

func TestTranslateFullConfig_ModelCards(t *testing.T) {
	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "reasoning", ProviderModelID: "claude-sonnet-4-6", APIFormat: "anthropic"},
		},
		ModelCards: []TranslateModelCard{
			{
				Name:              "reasoning",
				QualityScore:      0.96,
				Capabilities:      []string{"reasoning", "analysis"},
				Modality:          "ar",
				Tags:              []string{"premium"},
				ParamSize:         "200B",
				ContextWindowSize: 200000,
			},
		},
	}

	cfg := TranslateFullConfig(input)

	if len(cfg.Routing.ModelCards) != 1 {
		t.Fatalf("expected 1 model card, got %d", len(cfg.Routing.ModelCards))
	}
	mc := cfg.Routing.ModelCards[0]
	if mc.QualityScore != 0.96 {
		t.Errorf("expected quality_score 0.96, got %f", mc.QualityScore)
	}
	if mc.ParamSize != "200B" {
		t.Errorf("expected param_size '200B', got %q", mc.ParamSize)
	}
	if mc.ContextWindowSize != 200000 {
		t.Errorf("expected context_window_size 200000, got %d", mc.ContextWindowSize)
	}
}

func TestTranslateFullConfig_ProducesValidYAML(t *testing.T) {
	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "m1", ProviderModelID: "gpt-4o", APIFormat: "openai"},
			{Name: "m2", ProviderModelID: "claude-sonnet-4-6", APIFormat: "anthropic"},
		},
		ModelCards: []TranslateModelCard{
			{Name: "m1", QualityScore: 0.9, Capabilities: []string{"chat"}},
		},
		Signals: TranslateFullSignals{
			Keywords: []TranslateKeywordV2{
				{Name: "kw1", Keywords: []string{"hello", "world"}, Operator: "OR"},
			},
			Embedding: []TranslateEmbeddingSignal{
				{Name: "emb1", Threshold: 0.7, Candidates: []TranslateEmbeddingCandidate{{Text: "candidate1"}}},
			},
		},
		Decisions: []TranslateFullDecision{
			{
				Name:       "route1",
				Priority:   100,
				Operator:   "AND",
				Conditions: []TranslateFullCondition{{Type: "keyword", Name: "kw1"}},
				ModelRefs:  []TranslateFullModelRef{{Model: "m1", UseReasoning: true}},
				Algorithm:  &TranslateAlgorithm{Type: "static"},
			},
		},
	}

	cfg := TranslateFullConfig(input)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}

	var reparsed SRFullConfig
	if err := yaml.Unmarshal(data, &reparsed); err != nil {
		t.Fatalf("yaml.Unmarshal of output failed: %v", err)
	}
	if reparsed.Version != "v0.3" {
		t.Errorf("round-trip: expected version v0.3, got %q", reparsed.Version)
	}
	if len(reparsed.Routing.Decisions) != 1 {
		t.Errorf("round-trip: expected 1 decision, got %d", len(reparsed.Routing.Decisions))
	}
}

func TestTranslateFullAndWrite_AtomicWrite(t *testing.T) {
	dir := t.TempDir()

	input := TranslateFullInput{
		Port: 8080,
		Models: []TranslateFullModel{
			{Name: "m1", ProviderModelID: "gpt-4o", APIFormat: "openai"},
		},
		Decisions: []TranslateFullDecision{
			{
				Name:      "default",
				Priority:  10,
				Operator:  "AND",
				ModelRefs: []TranslateFullModelRef{{Model: "m1"}},
			},
		},
	}

	path, err := TranslateFullAndWrite(input, dir)
	if err != nil {
		t.Fatalf("TranslateFullAndWrite failed: %v", err)
	}

	if filepath.Base(path) != "config.yaml" {
		t.Errorf("expected filename config.yaml, got %q", filepath.Base(path))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read written file: %v", err)
	}

	if !strings.Contains(string(data), "version: v0.3") {
		t.Error("written file does not contain 'version: v0.3'")
	}
	if !strings.Contains(string(data), "name: m1") {
		t.Error("written file does not contain model name")
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestTranslateFullConfig_EmptyInput(t *testing.T) {
	input := TranslateFullInput{}

	cfg := TranslateFullConfig(input)

	if cfg.Version != "v0.3" {
		t.Errorf("expected version v0.3, got %q", cfg.Version)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener even with empty input, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Port != 8888 {
		t.Errorf("expected default port 8888, got %d", cfg.Listeners[0].Port)
	}
}
