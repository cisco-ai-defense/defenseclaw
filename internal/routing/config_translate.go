// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"gopkg.in/yaml.v3"
)

// SRConfig is the vLLM Semantic Router v0.3 canonical configuration format.
type SRConfig struct {
	Version   string             `yaml:"version"`
	Listeners []SRListenerConfig `yaml:"listeners"`
	Providers SRProvidersConfig  `yaml:"providers"`
	Routing   SRRoutingConfig    `yaml:"routing"`
	Global    SRGlobalConfig     `yaml:"global"`
}

type SRListenerConfig struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Timeout string `yaml:"timeout,omitempty"`
}

type SRProvidersConfig struct {
	Defaults SRProviderDefaults `yaml:"defaults"`
	Models   []SRProviderModel  `yaml:"models"`
}

type SRProviderDefaults struct {
	DefaultModel string `yaml:"default_model"`
}

type SRProviderModel struct {
	Name            string         `yaml:"name"`
	ProviderModelID string         `yaml:"provider_model_id"`
	APIFormat       string         `yaml:"api_format"`
	BackendRefs     []SRBackendRef `yaml:"backend_refs"`
}

type SRBackendRef struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	Protocol string `yaml:"protocol"`
	Weight   int    `yaml:"weight"`
}

type SRRoutingConfig struct {
	ModelCards []SRModelCard      `yaml:"modelCards"`
	Signals    SRSignalsConfig    `yaml:"signals,omitempty"`
	Decisions  []SRDecisionConfig `yaml:"decisions,omitempty"`
}

type SRModelCard struct {
	Name         string   `yaml:"name"`
	Capabilities []string `yaml:"capabilities,omitempty"`
}

type SRSignalsConfig struct {
	Keywords []SRKeywordSignal `yaml:"keywords,omitempty"`
}

type SRKeywordSignal struct {
	Name     string   `yaml:"name"`
	Keywords []string `yaml:"keywords"`
	Operator string   `yaml:"operator,omitempty"`
}

type SRDecisionConfig struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Priority    int          `yaml:"priority"`
	Rules       SRRules      `yaml:"rules"`
	ModelRefs   []SRModelRef `yaml:"modelRefs"`
	Algorithm   *SRAlgorithm `yaml:"algorithm,omitempty"`
}

type SRRules struct {
	Operator   string        `yaml:"operator"`
	Conditions []SRCondition `yaml:"conditions"`
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
	Type string `yaml:"type"`
}

// SRGlobalConfig disables v0.3 services and learned-model initialization that
// DefenseClaw does not use. The managed container is a classifier only: it
// evaluates configured keyword decisions, while DefenseClaw retains provider
// credentials, forwarding, guardrails, caching, and observability ownership.
type SRGlobalConfig struct {
	Router       SRGlobalRouter       `yaml:"router"`
	Services     SRGlobalServices     `yaml:"services"`
	Stores       SRGlobalStores       `yaml:"stores"`
	ModelCatalog SRGlobalModelCatalog `yaml:"model_catalog"`
}

type SRGlobalRouter struct {
	ModelSelection SRFeatureToggle `yaml:"model_selection"`
}

type SRGlobalServices struct {
	ResponseAPI   SRFeatureToggle       `yaml:"response_api"`
	RouterReplay  SRFeatureToggle       `yaml:"router_replay"`
	Observability SRRouterObservability `yaml:"observability"`
	Authz         SREmptyProviders      `yaml:"authz"`
	RateLimit     SREmptyProviders      `yaml:"ratelimit"`
}

type SRRouterObservability struct {
	Tracing SRFeatureToggle `yaml:"tracing"`
	Metrics SRFeatureToggle `yaml:"metrics"`
}

type SRGlobalStores struct {
	SemanticCache SRFeatureToggle `yaml:"semantic_cache"`
}

type SRGlobalModelCatalog struct {
	Embeddings SRGlobalEmbeddings `yaml:"embeddings"`
	KBs        []interface{}      `yaml:"kbs"`
}

type SRGlobalEmbeddings struct {
	Semantic SRGlobalSemanticEmbedding `yaml:"semantic"`
}

type SRGlobalSemanticEmbedding struct {
	MMBertModelPath string                   `yaml:"mmbert_model_path"`
	EmbeddingConfig SREmbeddingRuntimeConfig `yaml:"embedding_config"`
}

type SREmbeddingRuntimeConfig struct {
	PreloadEmbeddings  bool `yaml:"preload_embeddings"`
	EnableSoftMatching bool `yaml:"enable_soft_matching"`
}

type SRFeatureToggle struct {
	Enabled bool `yaml:"enabled"`
}

type SREmptyProviders struct {
	Providers []interface{} `yaml:"providers"`
}

// TranslateInput mirrors the fields needed from config.RoutingConfig
// without importing the config package.
type TranslateInput struct {
	Port      int
	Algorithm string
	Models    []TranslateModel
	Signals   TranslateSignals
	Decisions []TranslateDecision
}

type TranslateModel struct {
	Name         string
	Provider     string
	Model        string
	BaseURL      string
	APIKeyEnv    string
	Capabilities []string
}

type TranslateSignals struct {
	Keywords []TranslateKeyword
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

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("routing: marshal config: %w", err)
	}

	path := filepath.Join(dir, "config.yaml")
	if err := safefile.Write(path, data); err != nil {
		return "", fmt.Errorf("routing: write config: %w", err)
	}

	return path, nil
}

// Translate converts TranslateInput to the canonical v0.3 SR config.
func Translate(input TranslateInput) *SRConfig {
	port := input.Port
	if port == 0 {
		port = DefaultAPIPort
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
		Global: SRGlobalConfig{
			Router: SRGlobalRouter{ModelSelection: SRFeatureToggle{Enabled: false}},
			Services: SRGlobalServices{
				ResponseAPI:  SRFeatureToggle{Enabled: false},
				RouterReplay: SRFeatureToggle{Enabled: false},
				Observability: SRRouterObservability{
					Tracing: SRFeatureToggle{Enabled: false},
					Metrics: SRFeatureToggle{Enabled: false},
				},
				Authz:     SREmptyProviders{Providers: []interface{}{}},
				RateLimit: SREmptyProviders{Providers: []interface{}{}},
			},
			Stores: SRGlobalStores{SemanticCache: SRFeatureToggle{Enabled: false}},
			ModelCatalog: SRGlobalModelCatalog{
				Embeddings: SRGlobalEmbeddings{Semantic: SRGlobalSemanticEmbedding{
					MMBertModelPath: "",
					EmbeddingConfig: SREmbeddingRuntimeConfig{
						PreloadEmbeddings:  false,
						EnableSoftMatching: false,
					},
				}},
				KBs: []interface{}{},
			},
		},
	}

	// The semantic-router sidecar is only a classifier. Provider credentials
	// and real upstream URLs stay in DefenseClaw, so the v0.3 provider catalog
	// uses an inert loopback backend solely to register each routing alias.
	for _, m := range input.Models {
		cfg.Providers.Models = append(cfg.Providers.Models, SRProviderModel{
			Name:            m.Name,
			ProviderModelID: m.Model,
			APIFormat:       "openai",
			BackendRefs: []SRBackendRef{{
				Name:     "defenseclaw-classifier-only",
				Endpoint: "127.0.0.1:1",
				Protocol: "http",
				Weight:   100,
			}},
		})
		cfg.Routing.ModelCards = append(cfg.Routing.ModelCards, SRModelCard{
			Name:         m.Name,
			Capabilities: append([]string(nil), m.Capabilities...),
		})
	}
	cfg.Providers.Defaults.DefaultModel = defaultRoutingModel(input)

	// Routing signals
	for _, k := range input.Signals.Keywords {
		cfg.Routing.Signals.Keywords = append(cfg.Routing.Signals.Keywords, SRKeywordSignal{
			Name:     k.Name,
			Keywords: k.Keywords,
			Operator: k.Operator,
		})
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
				Type:          c.Signal,
				Name:          c.Value,
				MinConfidence: c.MinConfidence,
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
		// Use decision-specific algorithm if provided, otherwise fall back to input.Algorithm.
		alg := d.Algorithm
		if alg == "" {
			alg = input.Algorithm
		}
		if alg != "" {
			dec.Algorithm = &SRAlgorithm{Type: alg}
		}
		cfg.Routing.Decisions = append(cfg.Routing.Decisions, dec)
	}

	return cfg
}

func defaultRoutingModel(input TranslateInput) string {
	// An unconditional decision is the operator's explicit fallback. Prefer it
	// over catalog order so setup wizards may list specialized models first.
	for _, decision := range input.Decisions {
		if len(decision.Conditions) == 0 && len(decision.ModelRefs) > 0 {
			return decision.ModelRefs[0]
		}
	}
	if len(input.Models) > 0 {
		return input.Models[0].Name
	}
	return ""
}
