// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// SR v0.3 Full Config Output Types
// ---------------------------------------------------------------------------

// SRFullConfig is the complete vLLM Semantic Router v0.3 config format.
type SRFullConfig struct {
	Version     string             `yaml:"version"`
	Listeners   []SRListenerConfig `yaml:"listeners"`
	Providers   SRProvidersBlock   `yaml:"providers"`
	Routing     SRRoutingBlock     `yaml:"routing"`
	Entrypoints []SREntrypoint     `yaml:"entrypoints,omitempty"`
	Recipes     []SRRecipe         `yaml:"recipes,omitempty"`
	Global      *SRGlobalBlock     `yaml:"global,omitempty"`
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

// SRProvidersBlock holds the model provider configuration including defaults.
type SRProvidersBlock struct {
	Defaults *SRProviderDefaults `yaml:"defaults,omitempty"`
	Models   []SRModelConfig     `yaml:"models"`
}

// SRProviderDefaults specifies global provider defaults.
type SRProviderDefaults struct {
	DefaultModel           string                       `yaml:"default_model,omitempty"`
	DefaultReasoningEffort string                       `yaml:"default_reasoning_effort,omitempty"`
	ReasoningFamilies      map[string]SRReasoningFamily `yaml:"reasoning_families,omitempty"`
}

// SRReasoningFamily describes a model reasoning family and how to activate it.
type SRReasoningFamily struct {
	Type      string `yaml:"type"`
	Parameter string `yaml:"parameter"`
}

// SRModelConfig defines a single model entry in the providers block.
type SRModelConfig struct {
	Name             string               `yaml:"name"`
	ReasoningFamily  string               `yaml:"reasoning_family,omitempty"`
	ProviderModelID  string               `yaml:"provider_model_id,omitempty"`
	APIFormat        string               `yaml:"api_format,omitempty"`
	Pricing          *SRModelPricing      `yaml:"pricing,omitempty"`
	ExternalModelIDs map[string]string    `yaml:"external_model_ids,omitempty"`
	BackendRefs      []SRBackendRef       `yaml:"backend_refs,omitempty"`
	Reliability      *SRReliabilityConfig `yaml:"reliability,omitempty"`
}

// SRModelPricing contains token pricing information for a model.
type SRModelPricing struct {
	Currency         string  `yaml:"currency,omitempty"`
	PromptPer1M      float64 `yaml:"prompt_per_1m,omitempty"`
	CachedInputPer1M float64 `yaml:"cached_input_per_1m,omitempty"`
	CacheWritePer1M  float64 `yaml:"cache_write_per_1m,omitempty"`
	CompletionPer1M  float64 `yaml:"completion_per_1m,omitempty"`
}

// SRBackendRef defines a backend endpoint for a model.
type SRBackendRef struct {
	Name         string            `yaml:"name"`
	Endpoint     string            `yaml:"endpoint,omitempty"`
	BaseURL      string            `yaml:"base_url,omitempty"`
	Protocol     string            `yaml:"protocol,omitempty"`
	Provider     string            `yaml:"provider,omitempty"`
	Weight       int               `yaml:"weight,omitempty"`
	Type         string            `yaml:"type,omitempty"`
	APIKeyEnv    string            `yaml:"api_key_env,omitempty"`
	APIKey       string            `yaml:"api_key,omitempty"`
	ExtraHeaders map[string]string `yaml:"extra_headers,omitempty"`
}

// SRReliabilityConfig specifies retry and failover behavior for a model.
type SRReliabilityConfig struct {
	RetryAttempts   int    `yaml:"retry_attempts,omitempty"`
	RetryBackoff    string `yaml:"retry_backoff,omitempty"`
	FailoverModel   string `yaml:"failover_model,omitempty"`
	CircuitBreaker  string `yaml:"circuit_breaker,omitempty"`
	TimeoutOverride string `yaml:"timeout_override,omitempty"`
}

// ---------------------------------------------------------------------------
// Routing Block
// ---------------------------------------------------------------------------

// SRRoutingBlock is the top-level routing configuration.
type SRRoutingBlock struct {
	Strategy    string              `yaml:"strategy,omitempty"`
	ModelCards  []SRModelCard       `yaml:"modelCards,omitempty"`
	Signals     SRSignalsBlock      `yaml:"signals"`
	Projections *SRProjectionsBlock `yaml:"projections,omitempty"`
	Decisions   []SRDecisionBlock   `yaml:"decisions"`
}

// SRModelCard provides metadata about a model for the routing engine.
type SRModelCard struct {
	Name              string   `yaml:"name"`
	ParamSize         string   `yaml:"param_size,omitempty"`
	ContextWindowSize int      `yaml:"context_window_size,omitempty"`
	Description       string   `yaml:"description,omitempty"`
	Capabilities      []string `yaml:"capabilities,omitempty"`
	QualityScore      float64  `yaml:"quality_score,omitempty"`
	Modality          string   `yaml:"modality,omitempty"`
	Tags              []string `yaml:"tags,omitempty"`
	LoRAs             []SRLoRA `yaml:"loras,omitempty"`
}

// SRLoRA describes a LoRA adapter attached to a model.
type SRLoRA struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

// SRSignalsBlock contains all signal type configurations.
type SRSignalsBlock struct {
	Keywords   []SRKeywordSignalV2    `yaml:"keywords,omitempty"`
	Embedding  []SREmbeddingSignal    `yaml:"embedding,omitempty"`
	Domain     []SRDomainSignal       `yaml:"domain,omitempty"`
	Complexity []SRComplexitySignal   `yaml:"complexity,omitempty"`
	Context    []SRContextSignal      `yaml:"context,omitempty"`
	Structure  []SRStructureSignal    `yaml:"structure,omitempty"`
	Jailbreak  []SRJailbreakSignal    `yaml:"jailbreak,omitempty"`
	PII        []SRPIISignal          `yaml:"pii,omitempty"`
	Language   []SRLanguageSignal     `yaml:"language,omitempty"`
	Custom     []SRCustomSignal       `yaml:"custom,omitempty"`
}

// SRKeywordSignalV2 defines a keyword matching signal (v2 expanded format).
type SRKeywordSignalV2 struct {
	Name           string   `yaml:"name"`
	Operator       string   `yaml:"operator,omitempty"`
	Method         string   `yaml:"method,omitempty"`
	Keywords       []string `yaml:"keywords,omitempty"`
	CaseSensitive  bool     `yaml:"case_sensitive,omitempty"`
	BM25Threshold  float64  `yaml:"bm25_threshold,omitempty"`
	MinMatches     int      `yaml:"min_matches,omitempty"`
	Description    string   `yaml:"description,omitempty"`
}

// SREmbeddingSignal defines a semantic embedding similarity signal.
type SREmbeddingSignal struct {
	Name              string               `yaml:"name"`
	Threshold         float64              `yaml:"threshold,omitempty"`
	AggregationMethod string               `yaml:"aggregation_method,omitempty"`
	Candidates        []SREmbeddingCandidate `yaml:"candidates,omitempty"`
	QueryModality     string               `yaml:"query_modality,omitempty"`
	Model             string               `yaml:"model,omitempty"`
	Description       string               `yaml:"description,omitempty"`
}

// SREmbeddingCandidate is a reference text for embedding similarity comparison.
type SREmbeddingCandidate struct {
	Text     string  `yaml:"text"`
	Label    string  `yaml:"label,omitempty"`
	Weight   float64 `yaml:"weight,omitempty"`
}

// SRDomainSignal classifies queries by academic/professional domain.
type SRDomainSignal struct {
	Name           string                    `yaml:"name"`
	Description    string                    `yaml:"description,omitempty"`
	MMLUCategories []string                  `yaml:"mmlu_categories,omitempty"`
	ModelScores    map[string]float64        `yaml:"model_scores,omitempty"`
}

// SRComplexitySignal evaluates query complexity.
type SRComplexitySignal struct {
	Name        string                   `yaml:"name"`
	Threshold   float64                  `yaml:"threshold,omitempty"`
	Description string                   `yaml:"description,omitempty"`
	Hard        *SRComplexityCandidates  `yaml:"hard,omitempty"`
	Easy        *SRComplexityCandidates  `yaml:"easy,omitempty"`
}

// SRComplexityCandidates holds example candidates for a complexity level.
type SRComplexityCandidates struct {
	Candidates []string `yaml:"candidates,omitempty"`
}

// SRContextSignal evaluates input context length characteristics.
type SRContextSignal struct {
	Name        string `yaml:"name"`
	MinTokens   int    `yaml:"min_tokens,omitempty"`
	MaxTokens   int    `yaml:"max_tokens,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// SRStructureSignal inspects structural features of the input.
type SRStructureSignal struct {
	Name        string             `yaml:"name"`
	Description string             `yaml:"description,omitempty"`
	Feature     *SRStructureFeature `yaml:"feature,omitempty"`
}

// SRStructureFeature specifies what structural feature to detect.
type SRStructureFeature struct {
	Type      string `yaml:"type"`
	Source    string `yaml:"source,omitempty"`
	Predicate string `yaml:"predicate,omitempty"`
}

// SRJailbreakSignal detects prompt injection or jailbreak attempts.
type SRJailbreakSignal struct {
	Name        string  `yaml:"name"`
	Threshold   float64 `yaml:"threshold,omitempty"`
	Model       string  `yaml:"model,omitempty"`
	Description string  `yaml:"description,omitempty"`
}

// SRPIISignal detects personally identifiable information.
type SRPIISignal struct {
	Name        string   `yaml:"name"`
	Categories  []string `yaml:"categories,omitempty"`
	Threshold   float64  `yaml:"threshold,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// SRLanguageSignal detects the language of the input.
type SRLanguageSignal struct {
	Name        string   `yaml:"name"`
	Languages   []string `yaml:"languages,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// SRCustomSignal is a user-defined signal with arbitrary configuration.
type SRCustomSignal struct {
	Name          string                 `yaml:"name"`
	Type          string                 `yaml:"type,omitempty"`
	Description   string                 `yaml:"description,omitempty"`
	Configuration map[string]interface{} `yaml:"configuration,omitempty"`
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

// SRProjectionsBlock defines computed projections over signals.
type SRProjectionsBlock struct {
	Projections []SRProjection `yaml:"projections,omitempty"`
}

// SRProjection is a computed signal derived from one or more base signals.
type SRProjection struct {
	Name        string                 `yaml:"name"`
	Type        string                 `yaml:"type,omitempty"`
	Inputs      []string               `yaml:"inputs,omitempty"`
	Weights     map[string]float64     `yaml:"weights,omitempty"`
	Function    string                 `yaml:"function,omitempty"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty"`
	Description string                 `yaml:"description,omitempty"`
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

// SRDecisionBlock defines a routing decision rule with model selection.
type SRDecisionBlock struct {
	Name        string              `yaml:"name"`
	Description string              `yaml:"description,omitempty"`
	Priority    int                 `yaml:"priority"`
	Tier        string              `yaml:"tier,omitempty"`
	Rules       SRRulesBlock        `yaml:"rules"`
	ModelRefs   []SRModelRefBlock   `yaml:"modelRefs"`
	Algorithm   *SRAlgorithmBlock   `yaml:"algorithm,omitempty"`
	Plugins     []SRPluginBlock     `yaml:"plugins,omitempty"`
	Adaptations []SRAdaptationBlock `yaml:"adaptations,omitempty"`
	Emits       []string            `yaml:"emits,omitempty"`
}

// SRRulesBlock defines the condition tree for a decision.
type SRRulesBlock struct {
	Operator   string             `yaml:"operator"`
	Conditions []SRConditionBlock `yaml:"conditions,omitempty"`
}

// SRConditionBlock represents a single condition or a nested group.
type SRConditionBlock struct {
	// Leaf condition fields
	Type          string  `yaml:"type,omitempty"`
	Name          string  `yaml:"name,omitempty"`
	Operator      string  `yaml:"operator,omitempty"`
	MinConfidence float64 `yaml:"min_confidence,omitempty"`
	Value         string  `yaml:"value,omitempty"`

	// Nested condition group (recursive)
	Conditions []SRConditionBlock `yaml:"conditions,omitempty"`
}

// SRModelRefBlock references a model for routing, with optional reasoning config.
type SRModelRefBlock struct {
	Model                string  `yaml:"model"`
	UseReasoning         bool    `yaml:"use_reasoning,omitempty"`
	ReasoningEffort      string  `yaml:"reasoning_effort,omitempty"`
	ReasoningDescription string  `yaml:"reasoning_description,omitempty"`
	LoRAName             string  `yaml:"lora_name,omitempty"`
	Weight               float64 `yaml:"weight,omitempty"`
}

// SRAlgorithmBlock specifies the load balancing or selection algorithm.
type SRAlgorithmBlock struct {
	Type          string                 `yaml:"type"`
	Configuration map[string]interface{} `yaml:"configuration,omitempty"`
}

// SRPluginBlock defines a plugin invoked during decision evaluation.
type SRPluginBlock struct {
	Type          string                 `yaml:"type"`
	Configuration map[string]interface{} `yaml:"configuration,omitempty"`
}

// SRAdaptationBlock defines dynamic adaptations to routing behavior.
type SRAdaptationBlock struct {
	Type          string                 `yaml:"type"`
	Trigger       string                 `yaml:"trigger,omitempty"`
	Configuration map[string]interface{} `yaml:"configuration,omitempty"`
}

// ---------------------------------------------------------------------------
// Entrypoints
// ---------------------------------------------------------------------------

// SREntrypoint defines an API entrypoint with its pipeline.
type SREntrypoint struct {
	Name        string                 `yaml:"name"`
	Path        string                 `yaml:"path,omitempty"`
	Methods     []string               `yaml:"methods,omitempty"`
	Pipeline    []string               `yaml:"pipeline,omitempty"`
	Middleware  []string               `yaml:"middleware,omitempty"`
	RateLimit   map[string]interface{} `yaml:"rate_limit,omitempty"`
	Description string                 `yaml:"description,omitempty"`
}

// ---------------------------------------------------------------------------
// Recipes
// ---------------------------------------------------------------------------

// SRRecipe defines a reusable routing recipe.
type SRRecipe struct {
	Name        string                 `yaml:"name"`
	Type        string                 `yaml:"type,omitempty"`
	Description string                 `yaml:"description,omitempty"`
	Steps       []SRRecipeStep         `yaml:"steps,omitempty"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty"`
}

// SRRecipeStep is a single step within a recipe.
type SRRecipeStep struct {
	Action        string                 `yaml:"action"`
	Configuration map[string]interface{} `yaml:"configuration,omitempty"`
}

// ---------------------------------------------------------------------------
// Global
// ---------------------------------------------------------------------------

// SRGlobalBlock contains global router configuration.
type SRGlobalBlock struct {
	Router       map[string]interface{} `yaml:"router,omitempty"`
	Services     map[string]interface{} `yaml:"services,omitempty"`
	Stores       map[string]interface{} `yaml:"stores,omitempty"`
	ModelCatalog map[string]interface{} `yaml:"model_catalog,omitempty"`
	Integrations map[string]interface{} `yaml:"integrations,omitempty"`
}

// ---------------------------------------------------------------------------
// TranslateFullInput - DC-side input mirroring the expanded config
// ---------------------------------------------------------------------------

// TranslateFullInput mirrors the expanded DefenseClaw routing config
// for the v0.3 full format translator. Package-local to avoid circular imports.
type TranslateFullInput struct {
	Port      int
	Strategy  string

	// Provider configuration
	ProviderDefaults *TranslateProviderDefaults
	Models           []TranslateFullModel

	// Model cards for the routing engine
	ModelCards []TranslateModelCard

	// Signals
	Signals TranslateFullSignals

	// Projections
	Projections []TranslateProjection

	// Decisions
	Decisions []TranslateFullDecision

	// Entrypoints
	Entrypoints []TranslateEntrypoint

	// Recipes
	Recipes []TranslateRecipe

	// Global settings (deeply nested, passed as maps)
	Global *TranslateGlobal
}

// TranslateProviderDefaults specifies global defaults for providers.
type TranslateProviderDefaults struct {
	DefaultModel           string
	DefaultReasoningEffort string
	ReasoningFamilies      map[string]TranslateReasoningFamily
}

// TranslateReasoningFamily describes a reasoning family for translation.
type TranslateReasoningFamily struct {
	Type      string
	Parameter string
}

// TranslateFullModel is the expanded model input for v2 translation.
type TranslateFullModel struct {
	Name             string
	ReasoningFamily  string
	ProviderModelID  string
	APIFormat        string
	Pricing          *TranslateModelPricing
	ExternalModelIDs map[string]string
	BackendRefs      []TranslateBackendRef
	Reliability      *TranslateReliability
}

// TranslateModelPricing holds pricing data for a model.
type TranslateModelPricing struct {
	Currency         string
	PromptPer1M      float64
	CachedInputPer1M float64
	CacheWritePer1M  float64
	CompletionPer1M  float64
}

// TranslateBackendRef describes a single backend for a model.
type TranslateBackendRef struct {
	Name         string
	Endpoint     string
	BaseURL      string
	Protocol     string
	Provider     string
	Weight       int
	Type         string
	APIKeyEnv    string
	APIKey       string
	ExtraHeaders map[string]string
}

// TranslateReliability specifies retry/failover for a model.
type TranslateReliability struct {
	RetryAttempts   int
	RetryBackoff    string
	FailoverModel   string
	CircuitBreaker  string
	TimeoutOverride string
}

// TranslateModelCard is the input for model card metadata.
type TranslateModelCard struct {
	Name              string
	ParamSize         string
	ContextWindowSize int
	Description       string
	Capabilities      []string
	QualityScore      float64
	Modality          string
	Tags              []string
	LoRAs             []TranslateLoRA
}

// TranslateLoRA represents a LoRA adapter for model card input.
type TranslateLoRA struct {
	Name        string
	Description string
}

// TranslateFullSignals contains all signal type inputs.
type TranslateFullSignals struct {
	Keywords   []TranslateKeywordV2
	Embedding  []TranslateEmbeddingSignal
	Domain     []TranslateDomainSignal
	Complexity []TranslateComplexitySignal
	Context    []TranslateContextSignal
	Structure  []TranslateStructureSignal
	Jailbreak  []TranslateJailbreakSignal
	PII        []TranslatePIISignal
	Language   []TranslateLanguageSignal
	Custom     []TranslateCustomSignal
}

// TranslateKeywordV2 is the expanded keyword signal input.
type TranslateKeywordV2 struct {
	Name          string
	Operator      string
	Method        string
	Keywords      []string
	CaseSensitive bool
	BM25Threshold float64
	MinMatches    int
	Description   string
}

// TranslateEmbeddingSignal is the input for an embedding signal.
type TranslateEmbeddingSignal struct {
	Name              string
	Threshold         float64
	AggregationMethod string
	Candidates        []TranslateEmbeddingCandidate
	QueryModality     string
	Model             string
	Description       string
}

// TranslateEmbeddingCandidate is a reference text for embedding comparison.
type TranslateEmbeddingCandidate struct {
	Text   string
	Label  string
	Weight float64
}

// TranslateDomainSignal is the input for a domain classification signal.
type TranslateDomainSignal struct {
	Name           string
	Description    string
	MMLUCategories []string
	ModelScores    map[string]float64
}

// TranslateComplexitySignal is the input for a complexity signal.
type TranslateComplexitySignal struct {
	Name        string
	Threshold   float64
	Description string
	Hard        []string
	Easy        []string
}

// TranslateContextSignal is the input for a context length signal.
type TranslateContextSignal struct {
	Name        string
	MinTokens   int
	MaxTokens   int
	Description string
}

// TranslateStructureSignal is the input for a structural feature signal.
type TranslateStructureSignal struct {
	Name        string
	Description string
	FeatureType string
	Source      string
	Predicate   string
}

// TranslateJailbreakSignal is the input for jailbreak detection.
type TranslateJailbreakSignal struct {
	Name        string
	Threshold   float64
	Model       string
	Description string
}

// TranslatePIISignal is the input for PII detection.
type TranslatePIISignal struct {
	Name        string
	Categories  []string
	Threshold   float64
	Description string
}

// TranslateLanguageSignal is the input for language detection.
type TranslateLanguageSignal struct {
	Name        string
	Languages   []string
	Description string
}

// TranslateCustomSignal is the input for user-defined custom signals.
type TranslateCustomSignal struct {
	Name          string
	Type          string
	Description   string
	Configuration map[string]interface{}
}

// TranslateProjection is the input for a computed projection.
type TranslateProjection struct {
	Name        string
	Type        string
	Inputs      []string
	Weights     map[string]float64
	Function    string
	Parameters  map[string]interface{}
	Description string
}

// TranslateFullDecision is the expanded decision input.
type TranslateFullDecision struct {
	Name        string
	Description string
	Priority    int
	Tier        string
	Operator    string
	Conditions  []TranslateFullCondition
	ModelRefs   []TranslateFullModelRef
	Algorithm   *TranslateAlgorithm
	Plugins     []TranslatePlugin
	Adaptations []TranslateAdaptation
	Emits       []string
}

// TranslateFullCondition is a condition that supports nesting.
type TranslateFullCondition struct {
	// Leaf condition
	Type          string
	Name          string
	Operator      string
	MinConfidence float64
	Value         string

	// Nested group
	Conditions []TranslateFullCondition
}

// TranslateFullModelRef is a model reference with reasoning support.
type TranslateFullModelRef struct {
	Model                string
	UseReasoning         bool
	ReasoningEffort      string
	ReasoningDescription string
	LoRAName             string
	Weight               float64
}

// TranslateAlgorithm specifies the selection algorithm for a decision.
type TranslateAlgorithm struct {
	Type          string
	Configuration map[string]interface{}
}

// TranslatePlugin specifies a plugin for a decision.
type TranslatePlugin struct {
	Type          string
	Configuration map[string]interface{}
}

// TranslateAdaptation specifies a dynamic adaptation for a decision.
type TranslateAdaptation struct {
	Type          string
	Trigger       string
	Configuration map[string]interface{}
}

// TranslateEntrypoint is the input for an API entrypoint.
type TranslateEntrypoint struct {
	Name        string
	Path        string
	Methods     []string
	Pipeline    []string
	Middleware  []string
	RateLimit   map[string]interface{}
	Description string
}

// TranslateRecipe is the input for a reusable recipe.
type TranslateRecipe struct {
	Name        string
	Type        string
	Description string
	Steps       []TranslateRecipeStep
	Parameters  map[string]interface{}
}

// TranslateRecipeStep is a single step in a recipe.
type TranslateRecipeStep struct {
	Action        string
	Configuration map[string]interface{}
}

// TranslateGlobal contains global settings (deeply nested optional config).
type TranslateGlobal struct {
	Router       map[string]interface{}
	Services     map[string]interface{}
	Stores       map[string]interface{}
	ModelCatalog map[string]interface{}
	Integrations map[string]interface{}
}

// ---------------------------------------------------------------------------
// TranslateFullConfig converts a TranslateFullInput to the full v0.3 SRFullConfig.
// ---------------------------------------------------------------------------

// TranslateFullConfig produces the complete vLLM Semantic Router v0.3 config.
func TranslateFullConfig(input TranslateFullInput) *SRFullConfig {
	port := input.Port
	if port == 0 {
		port = 8888
	}

	cfg := &SRFullConfig{
		Version: "v0.3",
		Listeners: []SRListenerConfig{
			{
				Name:    fmt.Sprintf("http-%d", port),
				Address: "0.0.0.0",
				Port:    port,
				Timeout: "300s",
			},
		},
	}

	// --- Providers ---
	cfg.Providers = translateProviders(input)

	// --- Routing ---
	cfg.Routing = translateRoutingBlock(input)

	// --- Entrypoints ---
	for _, ep := range input.Entrypoints {
		cfg.Entrypoints = append(cfg.Entrypoints, SREntrypoint{
			Name:        ep.Name,
			Path:        ep.Path,
			Methods:     ep.Methods,
			Pipeline:    ep.Pipeline,
			Middleware:  ep.Middleware,
			RateLimit:   ep.RateLimit,
			Description: ep.Description,
		})
	}

	// --- Recipes ---
	for _, r := range input.Recipes {
		recipe := SRRecipe{
			Name:        r.Name,
			Type:        r.Type,
			Description: r.Description,
			Parameters:  r.Parameters,
		}
		for _, s := range r.Steps {
			recipe.Steps = append(recipe.Steps, SRRecipeStep{
				Action:        s.Action,
				Configuration: s.Configuration,
			})
		}
		cfg.Recipes = append(cfg.Recipes, recipe)
	}

	// --- Global ---
	if input.Global != nil {
		cfg.Global = &SRGlobalBlock{
			Router:       input.Global.Router,
			Services:     input.Global.Services,
			Stores:       input.Global.Stores,
			ModelCatalog: input.Global.ModelCatalog,
			Integrations: input.Global.Integrations,
		}
	}

	return cfg
}

// translateProviders builds the providers block from input.
func translateProviders(input TranslateFullInput) SRProvidersBlock {
	pb := SRProvidersBlock{}

	// Defaults
	if input.ProviderDefaults != nil {
		pd := &SRProviderDefaults{
			DefaultModel:           input.ProviderDefaults.DefaultModel,
			DefaultReasoningEffort: input.ProviderDefaults.DefaultReasoningEffort,
		}
		if len(input.ProviderDefaults.ReasoningFamilies) > 0 {
			pd.ReasoningFamilies = make(map[string]SRReasoningFamily, len(input.ProviderDefaults.ReasoningFamilies))
			for k, v := range input.ProviderDefaults.ReasoningFamilies {
				pd.ReasoningFamilies[k] = SRReasoningFamily{
					Type:      v.Type,
					Parameter: v.Parameter,
				}
			}
		}
		pb.Defaults = pd
	}

	// Models
	for _, m := range input.Models {
		mc := SRModelConfig{
			Name:             m.Name,
			ReasoningFamily:  m.ReasoningFamily,
			ProviderModelID:  m.ProviderModelID,
			APIFormat:        m.APIFormat,
			ExternalModelIDs: m.ExternalModelIDs,
		}

		if m.Pricing != nil {
			mc.Pricing = &SRModelPricing{
				Currency:         m.Pricing.Currency,
				PromptPer1M:      m.Pricing.PromptPer1M,
				CachedInputPer1M: m.Pricing.CachedInputPer1M,
				CacheWritePer1M:  m.Pricing.CacheWritePer1M,
				CompletionPer1M:  m.Pricing.CompletionPer1M,
			}
		}

		for _, br := range m.BackendRefs {
			mc.BackendRefs = append(mc.BackendRefs, SRBackendRef{
				Name:         br.Name,
				Endpoint:     br.Endpoint,
				BaseURL:      br.BaseURL,
				Protocol:     br.Protocol,
				Provider:     br.Provider,
				Weight:       br.Weight,
				Type:         br.Type,
				APIKeyEnv:    br.APIKeyEnv,
				APIKey:       br.APIKey,
				ExtraHeaders: br.ExtraHeaders,
			})
		}

		if m.Reliability != nil {
			mc.Reliability = &SRReliabilityConfig{
				RetryAttempts:   m.Reliability.RetryAttempts,
				RetryBackoff:    m.Reliability.RetryBackoff,
				FailoverModel:   m.Reliability.FailoverModel,
				CircuitBreaker:  m.Reliability.CircuitBreaker,
				TimeoutOverride: m.Reliability.TimeoutOverride,
			}
		}

		pb.Models = append(pb.Models, mc)
	}

	return pb
}

// translateRoutingBlock builds the routing block from input.
func translateRoutingBlock(input TranslateFullInput) SRRoutingBlock {
	rb := SRRoutingBlock{
		Strategy: input.Strategy,
	}

	// Model cards
	for _, mc := range input.ModelCards {
		card := SRModelCard{
			Name:              mc.Name,
			ParamSize:         mc.ParamSize,
			ContextWindowSize: mc.ContextWindowSize,
			Description:       mc.Description,
			Capabilities:      mc.Capabilities,
			QualityScore:      mc.QualityScore,
			Modality:          mc.Modality,
			Tags:              mc.Tags,
		}
		for _, l := range mc.LoRAs {
			card.LoRAs = append(card.LoRAs, SRLoRA{
				Name:        l.Name,
				Description: l.Description,
			})
		}
		rb.ModelCards = append(rb.ModelCards, card)
	}

	// Signals
	rb.Signals = translateSignals(input.Signals)

	// Projections
	if len(input.Projections) > 0 {
		rb.Projections = &SRProjectionsBlock{}
		for _, p := range input.Projections {
			rb.Projections.Projections = append(rb.Projections.Projections, SRProjection{
				Name:        p.Name,
				Type:        p.Type,
				Inputs:      p.Inputs,
				Weights:     p.Weights,
				Function:    p.Function,
				Parameters:  p.Parameters,
				Description: p.Description,
			})
		}
	}

	// Decisions
	for _, d := range input.Decisions {
		rb.Decisions = append(rb.Decisions, translateDecision(d))
	}

	return rb
}

// translateSignals builds the signals block from input.
func translateSignals(input TranslateFullSignals) SRSignalsBlock {
	sb := SRSignalsBlock{}

	// Keywords
	for _, k := range input.Keywords {
		sb.Keywords = append(sb.Keywords, SRKeywordSignalV2{
			Name:          k.Name,
			Operator:      k.Operator,
			Method:        k.Method,
			Keywords:      k.Keywords,
			CaseSensitive: k.CaseSensitive,
			BM25Threshold: k.BM25Threshold,
			MinMatches:    k.MinMatches,
			Description:   k.Description,
		})
	}

	// Embedding
	for _, e := range input.Embedding {
		sig := SREmbeddingSignal{
			Name:              e.Name,
			Threshold:         e.Threshold,
			AggregationMethod: e.AggregationMethod,
			QueryModality:     e.QueryModality,
			Model:             e.Model,
			Description:       e.Description,
		}
		for _, c := range e.Candidates {
			sig.Candidates = append(sig.Candidates, SREmbeddingCandidate{
				Text:   c.Text,
				Label:  c.Label,
				Weight: c.Weight,
			})
		}
		sb.Embedding = append(sb.Embedding, sig)
	}

	// Domain
	for _, d := range input.Domain {
		sb.Domain = append(sb.Domain, SRDomainSignal{
			Name:           d.Name,
			Description:    d.Description,
			MMLUCategories: d.MMLUCategories,
			ModelScores:    d.ModelScores,
		})
	}

	// Complexity
	for _, c := range input.Complexity {
		sig := SRComplexitySignal{
			Name:        c.Name,
			Threshold:   c.Threshold,
			Description: c.Description,
		}
		if len(c.Hard) > 0 {
			sig.Hard = &SRComplexityCandidates{Candidates: c.Hard}
		}
		if len(c.Easy) > 0 {
			sig.Easy = &SRComplexityCandidates{Candidates: c.Easy}
		}
		sb.Complexity = append(sb.Complexity, sig)
	}

	// Context
	for _, c := range input.Context {
		sb.Context = append(sb.Context, SRContextSignal{
			Name:        c.Name,
			MinTokens:   c.MinTokens,
			MaxTokens:   c.MaxTokens,
			Description: c.Description,
		})
	}

	// Structure
	for _, s := range input.Structure {
		sig := SRStructureSignal{
			Name:        s.Name,
			Description: s.Description,
		}
		if s.FeatureType != "" {
			sig.Feature = &SRStructureFeature{
				Type:      s.FeatureType,
				Source:    s.Source,
				Predicate: s.Predicate,
			}
		}
		sb.Structure = append(sb.Structure, sig)
	}

	// Jailbreak
	for _, j := range input.Jailbreak {
		sb.Jailbreak = append(sb.Jailbreak, SRJailbreakSignal{
			Name:        j.Name,
			Threshold:   j.Threshold,
			Model:       j.Model,
			Description: j.Description,
		})
	}

	// PII
	for _, p := range input.PII {
		sb.PII = append(sb.PII, SRPIISignal{
			Name:        p.Name,
			Categories:  p.Categories,
			Threshold:   p.Threshold,
			Description: p.Description,
		})
	}

	// Language
	for _, l := range input.Language {
		sb.Language = append(sb.Language, SRLanguageSignal{
			Name:        l.Name,
			Languages:   l.Languages,
			Description: l.Description,
		})
	}

	// Custom
	for _, c := range input.Custom {
		sb.Custom = append(sb.Custom, SRCustomSignal{
			Name:          c.Name,
			Type:          c.Type,
			Description:   c.Description,
			Configuration: c.Configuration,
		})
	}

	return sb
}

// translateDecision converts a single decision input to the SR output format.
func translateDecision(d TranslateFullDecision) SRDecisionBlock {
	op := d.Operator
	if op == "" {
		op = "AND"
	}

	dec := SRDecisionBlock{
		Name:        d.Name,
		Description: d.Description,
		Priority:    d.Priority,
		Tier:        d.Tier,
		Rules: SRRulesBlock{
			Operator:   op,
			Conditions: translateConditions(d.Conditions),
		},
		Emits: d.Emits,
	}

	// Model refs
	for _, mr := range d.ModelRefs {
		dec.ModelRefs = append(dec.ModelRefs, SRModelRefBlock{
			Model:                mr.Model,
			UseReasoning:         mr.UseReasoning,
			ReasoningEffort:      mr.ReasoningEffort,
			ReasoningDescription: mr.ReasoningDescription,
			LoRAName:             mr.LoRAName,
			Weight:               mr.Weight,
		})
	}

	// Algorithm
	if d.Algorithm != nil {
		dec.Algorithm = &SRAlgorithmBlock{
			Type:          d.Algorithm.Type,
			Configuration: d.Algorithm.Configuration,
		}
	}

	// Plugins
	for _, p := range d.Plugins {
		dec.Plugins = append(dec.Plugins, SRPluginBlock{
			Type:          p.Type,
			Configuration: p.Configuration,
		})
	}

	// Adaptations
	for _, a := range d.Adaptations {
		dec.Adaptations = append(dec.Adaptations, SRAdaptationBlock{
			Type:          a.Type,
			Trigger:       a.Trigger,
			Configuration: a.Configuration,
		})
	}

	return dec
}

// translateConditions recursively converts condition inputs to SR output format.
func translateConditions(conditions []TranslateFullCondition) []SRConditionBlock {
	if len(conditions) == 0 {
		return nil
	}

	result := make([]SRConditionBlock, 0, len(conditions))
	for _, c := range conditions {
		block := SRConditionBlock{
			Type:          c.Type,
			Name:          c.Name,
			Operator:      c.Operator,
			MinConfidence: c.MinConfidence,
			Value:         c.Value,
		}
		if len(c.Conditions) > 0 {
			block.Conditions = translateConditions(c.Conditions)
		}
		result = append(result, block)
	}
	return result
}

// ---------------------------------------------------------------------------
// TranslateFullAndWrite writes the full v0.3 config atomically.
// ---------------------------------------------------------------------------

// TranslateFullAndWrite converts a TranslateFullInput to the full v0.3 SR config
// and writes it atomically to the specified directory. Returns the file path.
func TranslateFullAndWrite(input TranslateFullInput, dir string) (string, error) {
	cfg := TranslateFullConfig(input)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("routing: create dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("routing: marshal full config: %w", err)
	}

	path := filepath.Join(dir, "config.yaml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", fmt.Errorf("routing: write tmp full config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("routing: rename full config: %w", err)
	}

	return path, nil
}
