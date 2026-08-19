// Copyright 2024-2026 Cisco Systems, Inc. and its affiliates.
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

package config

// routing_types.go defines the expanded config types for vLLM Semantic Router
// v0.3 integration. These use a "V2" suffix to avoid breaking the existing
// types in config.go which remain for backward-compat parsing. A config
// translator converts V1 -> V2 at boot time.

// ---------------------------------------------------------------------------
// Top-level routing config
// ---------------------------------------------------------------------------

// RoutingConfigV2 is the expanded top-level routing configuration for
// vLLM Semantic Router v0.3.
type RoutingConfigV2 struct {
	Enabled     bool                     `mapstructure:"enabled"      yaml:"enabled"`
	Version     string                   `mapstructure:"version"      yaml:"version,omitempty"`
	Container   RoutingContainerConfig   `mapstructure:"container"    yaml:"container,omitempty"`
	Remote      RoutingRemoteConfig      `mapstructure:"remote"       yaml:"remote,omitempty"`
	Models      []RoutingModelV2         `mapstructure:"models"       yaml:"models,omitempty"`
	Signals     RoutingSignalConfigV2    `mapstructure:"signals"      yaml:"signals,omitempty"`
	Projections RoutingProjectionsConfig `mapstructure:"projections"  yaml:"projections,omitempty"`
	Decisions   []RoutingDecisionV2      `mapstructure:"decisions"    yaml:"decisions,omitempty"`
	Global      RoutingGlobalConfig      `mapstructure:"global"       yaml:"global,omitempty"`
	Recipes     []RoutingRecipe          `mapstructure:"recipes"      yaml:"recipes,omitempty"`
	Entrypoints []RoutingEntrypoint      `mapstructure:"entrypoints"  yaml:"entrypoints,omitempty"`
	Context     RoutingContextConfig     `mapstructure:"context"      yaml:"context,omitempty"`
}

// ---------------------------------------------------------------------------
// Container config
// ---------------------------------------------------------------------------

// RoutingContainerConfig describes the vLLM sidecar container settings.
type RoutingContainerConfig struct {
	Image      string `mapstructure:"image"       yaml:"image,omitempty"`
	ModelsDir  string `mapstructure:"models_dir"  yaml:"models_dir,omitempty"`
	GPU        string `mapstructure:"gpu"         yaml:"gpu,omitempty"`
	DeployMode string `mapstructure:"deploy_mode" yaml:"deploy_mode,omitempty"` // docker | k8s
}

// ---------------------------------------------------------------------------
// Model definitions
// ---------------------------------------------------------------------------

// RoutingModelV2 is the expanded model definition with quality scores,
// modality, LoRA adapters, pricing, and external model ID mappings.
type RoutingModelV2 struct {
	Name              string              `mapstructure:"name"                yaml:"name"`
	Provider          string              `mapstructure:"provider"            yaml:"provider"`
	Model             string              `mapstructure:"model"               yaml:"model"`
	BaseURL           string              `mapstructure:"base_url"            yaml:"base_url,omitempty"`
	APIKeyEnv         string              `mapstructure:"api_key_env"         yaml:"api_key_env,omitempty"`
	Weight            int                 `mapstructure:"weight"              yaml:"weight,omitempty"`
	Capabilities      []string            `mapstructure:"capabilities"        yaml:"capabilities,omitempty"`
	CostPer1kTokens   float64             `mapstructure:"cost_per_1k_tokens"  yaml:"cost_per_1k_tokens,omitempty"`
	ReasoningFamily   string              `mapstructure:"reasoning_family"    yaml:"reasoning_family,omitempty"`
	ParamSize         string              `mapstructure:"param_size"          yaml:"param_size,omitempty"`
	ContextWindowSize int                 `mapstructure:"context_window_size" yaml:"context_window_size,omitempty"`
	QualityScore      float64             `mapstructure:"quality_score"       yaml:"quality_score,omitempty"`
	Modality          []string            `mapstructure:"modality"            yaml:"modality,omitempty"`
	Tags              []string            `mapstructure:"tags"                yaml:"tags,omitempty"`
	LoRAs             []RoutingLoRAConfig `mapstructure:"loras"               yaml:"loras,omitempty"`
	Pricing           RoutingModelPricing `mapstructure:"pricing"             yaml:"pricing,omitempty"`
	BackendRefs       []RoutingBackendRef `mapstructure:"backend_refs"        yaml:"backend_refs,omitempty"`
	ExternalModelIDs  map[string]string   `mapstructure:"external_model_ids"  yaml:"external_model_ids,omitempty"`
}

// RoutingLoRAConfig describes a LoRA adapter attached to a model.
type RoutingLoRAConfig struct {
	Name   string `mapstructure:"name"   yaml:"name"`
	Path   string `mapstructure:"path"   yaml:"path,omitempty"`
	Ref    string `mapstructure:"ref"    yaml:"ref,omitempty"`
	Weight int    `mapstructure:"weight" yaml:"weight,omitempty"`
}

// RoutingModelPricing captures per-token pricing for a model.
type RoutingModelPricing struct {
	InputPer1MTokens  float64 `mapstructure:"input_per_1m_tokens"  yaml:"input_per_1m_tokens,omitempty"`
	OutputPer1MTokens float64 `mapstructure:"output_per_1m_tokens" yaml:"output_per_1m_tokens,omitempty"`
	CachedInputPer1M  float64 `mapstructure:"cached_input_per_1m"  yaml:"cached_input_per_1m,omitempty"`
}

// RoutingBackendRef points to an upstream endpoint for a model.
type RoutingBackendRef struct {
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	Region   string `mapstructure:"region"   yaml:"region,omitempty"`
	Priority int    `mapstructure:"priority" yaml:"priority,omitempty"`
}

// ---------------------------------------------------------------------------
// Signal types (17+ signal definitions)
// ---------------------------------------------------------------------------

// RoutingSignalConfigV2 contains all signal type slices for the expanded
// router configuration.
type RoutingSignalConfigV2 struct {
	Keywords     []RoutingKeywordSignalV2    `mapstructure:"keywords"      yaml:"keywords,omitempty"`
	Embedding    []RoutingEmbeddingSignal    `mapstructure:"embedding"     yaml:"embedding,omitempty"`
	Domain       []RoutingDomainSignal       `mapstructure:"domain"        yaml:"domain,omitempty"`
	Complexity   []RoutingComplexitySignal   `mapstructure:"complexity"    yaml:"complexity,omitempty"`
	Context      []RoutingContextSignal      `mapstructure:"context"       yaml:"context,omitempty"`
	Structure    []RoutingStructureSignal    `mapstructure:"structure"     yaml:"structure,omitempty"`
	Modality     []RoutingModalitySignal     `mapstructure:"modality"      yaml:"modality,omitempty"`
	Language     []RoutingLanguageSignal     `mapstructure:"language"      yaml:"language,omitempty"`
	PII          []RoutingPIISignal          `mapstructure:"pii"           yaml:"pii,omitempty"`
	Jailbreak    []RoutingJailbreakSignal    `mapstructure:"jailbreak"     yaml:"jailbreak,omitempty"`
	FactCheck    []RoutingFactCheckSignal    `mapstructure:"fact_check"    yaml:"fact_check,omitempty"`
	UserFeedback []RoutingUserFeedbackSignal `mapstructure:"user_feedback" yaml:"user_feedback,omitempty"`
	Reask        []RoutingReaskSignal        `mapstructure:"reask"         yaml:"reask,omitempty"`
	Preference   []RoutingPreferenceSignal   `mapstructure:"preference"    yaml:"preference,omitempty"`
	Conversation []RoutingConversationSignal `mapstructure:"conversation"  yaml:"conversation,omitempty"`
	Event        []RoutingEventSignal        `mapstructure:"event"         yaml:"event,omitempty"`
	Metadata     []RoutingMetadataSignal     `mapstructure:"metadata"      yaml:"metadata,omitempty"`
	RoleBinding  []RoutingRoleBindingSignal  `mapstructure:"role_binding"  yaml:"role_binding,omitempty"`
	KB           []RoutingKBSignal           `mapstructure:"kb"            yaml:"kb,omitempty"`
	Classifier   []RoutingClassifierSignal   `mapstructure:"classifier"    yaml:"classifier,omitempty"`
}

// RoutingKeywordSignalV2 extends keyword matching with BM25, n-gram, and
// fuzzy matching methods.
type RoutingKeywordSignalV2 struct {
	Name           string   `mapstructure:"name"            yaml:"name"`
	Keywords       []string `mapstructure:"keywords"        yaml:"keywords"`
	Operator       string   `mapstructure:"operator"        yaml:"operator,omitempty"`
	Method         string   `mapstructure:"method"          yaml:"method,omitempty"` // bm25 | ngram | fuzzy
	CaseSensitive  bool     `mapstructure:"case_sensitive"  yaml:"case_sensitive,omitempty"`
	BM25Threshold  float64  `mapstructure:"bm25_threshold"  yaml:"bm25_threshold,omitempty"`
	NGramThreshold float64  `mapstructure:"ngram_threshold" yaml:"ngram_threshold,omitempty"`
	FuzzyThreshold float64  `mapstructure:"fuzzy_threshold" yaml:"fuzzy_threshold,omitempty"`
}

// RoutingEmbeddingSignal defines vector-similarity based routing signals.
type RoutingEmbeddingSignal struct {
	Name              string   `mapstructure:"name"               yaml:"name"`
	Threshold         float64  `mapstructure:"threshold"          yaml:"threshold,omitempty"`
	AggregationMethod string   `mapstructure:"aggregation_method" yaml:"aggregation_method,omitempty"`
	Candidates        []string `mapstructure:"candidates"         yaml:"candidates,omitempty"`
	QueryModality     string   `mapstructure:"query_modality"     yaml:"query_modality,omitempty"`
}

// RoutingDomainSignal classifies request domain using MMLU categories and
// per-model domain scores.
type RoutingDomainSignal struct {
	Name           string             `mapstructure:"name"            yaml:"name"`
	Description    string             `mapstructure:"description"     yaml:"description,omitempty"`
	MMLUCategories []string           `mapstructure:"mmlu_categories" yaml:"mmlu_categories,omitempty"`
	ModelScores    map[string]float64 `mapstructure:"model_scores"    yaml:"model_scores,omitempty"`
}

// RoutingComplexityCandidates lists candidate models for a complexity tier.
type RoutingComplexityCandidates struct {
	Models          []string `mapstructure:"models"           yaml:"models,omitempty"`
	ImageCandidates []string `mapstructure:"image_candidates" yaml:"image_candidates,omitempty"`
	Composer        string   `mapstructure:"composer"         yaml:"composer,omitempty"`
}

// RoutingComplexitySignal classifies prompt difficulty and maps to tiers.
type RoutingComplexitySignal struct {
	Name        string                      `mapstructure:"name"        yaml:"name"`
	Threshold   float64                     `mapstructure:"threshold"   yaml:"threshold,omitempty"`
	Description string                      `mapstructure:"description" yaml:"description,omitempty"`
	Hard        RoutingComplexityCandidates `mapstructure:"hard"        yaml:"hard,omitempty"`
	Easy        RoutingComplexityCandidates `mapstructure:"easy"        yaml:"easy,omitempty"`
}

// RoutingContextSignal evaluates input context length boundaries.
type RoutingContextSignal struct {
	Name        string `mapstructure:"name"        yaml:"name"`
	MinTokens   int    `mapstructure:"min_tokens"  yaml:"min_tokens,omitempty"`
	MaxTokens   int    `mapstructure:"max_tokens"  yaml:"max_tokens,omitempty"`
	Description string `mapstructure:"description" yaml:"description,omitempty"`
}

// RoutingStructureFeature defines a structural feature to detect.
type RoutingStructureFeature struct {
	Type      string `mapstructure:"type"      yaml:"type"`
	Source    string `mapstructure:"source"    yaml:"source,omitempty"`
	Predicate string `mapstructure:"predicate" yaml:"predicate,omitempty"`
}

// RoutingStructureSignal detects structural patterns in the request.
type RoutingStructureSignal struct {
	Name        string                  `mapstructure:"name"        yaml:"name"`
	Description string                  `mapstructure:"description" yaml:"description,omitempty"`
	Feature     RoutingStructureFeature `mapstructure:"feature"     yaml:"feature,omitempty"`
}

// RoutingModalitySignal detects input modality (text, image, audio, etc.).
type RoutingModalitySignal struct {
	Name        string `mapstructure:"name"        yaml:"name"`
	Description string `mapstructure:"description" yaml:"description,omitempty"`
}

// RoutingLanguageSignal detects the input language.
type RoutingLanguageSignal struct {
	Name        string  `mapstructure:"name"        yaml:"name"`
	Description string  `mapstructure:"description" yaml:"description,omitempty"`
	Threshold   float64 `mapstructure:"threshold"   yaml:"threshold,omitempty"`
}

// RoutingPIISignal detects personally identifiable information.
type RoutingPIISignal struct {
	Name            string   `mapstructure:"name"              yaml:"name"`
	Threshold       float64  `mapstructure:"threshold"         yaml:"threshold,omitempty"`
	IncludeHistory  bool     `mapstructure:"include_history"   yaml:"include_history,omitempty"`
	PIITypesAllowed []string `mapstructure:"pii_types_allowed" yaml:"pii_types_allowed,omitempty"`
	Description     string   `mapstructure:"description"       yaml:"description,omitempty"`
}

// RoutingJailbreakSignal detects jailbreak or prompt injection attempts.
type RoutingJailbreakSignal struct {
	Name              string   `mapstructure:"name"              yaml:"name"`
	Method            string   `mapstructure:"method"            yaml:"method,omitempty"`
	Threshold         float64  `mapstructure:"threshold"         yaml:"threshold,omitempty"`
	IncludeHistory    bool     `mapstructure:"include_history"   yaml:"include_history,omitempty"`
	Description       string   `mapstructure:"description"       yaml:"description,omitempty"`
	JailbreakPatterns []string `mapstructure:"jailbreak_patterns" yaml:"jailbreak_patterns,omitempty"`
	BenignPatterns    []string `mapstructure:"benign_patterns"   yaml:"benign_patterns,omitempty"`
}

// RoutingFactCheckSignal flags requests requiring factual verification.
type RoutingFactCheckSignal struct {
	Name        string `mapstructure:"name"        yaml:"name"`
	Description string `mapstructure:"description" yaml:"description,omitempty"`
}

// RoutingUserFeedbackSignal incorporates user feedback signals.
type RoutingUserFeedbackSignal struct {
	Name        string `mapstructure:"name"        yaml:"name"`
	Description string `mapstructure:"description" yaml:"description,omitempty"`
}

// RoutingReaskSignal detects when a user is re-asking or rephrasing.
type RoutingReaskSignal struct {
	Name          string  `mapstructure:"name"           yaml:"name"`
	Description   string  `mapstructure:"description"    yaml:"description,omitempty"`
	Threshold     float64 `mapstructure:"threshold"      yaml:"threshold,omitempty"`
	LookbackTurns int     `mapstructure:"lookback_turns" yaml:"lookback_turns,omitempty"`
}

// RoutingPreferenceExample provides labeled examples for preference detection.
type RoutingPreferenceExample struct {
	Input string `mapstructure:"input" yaml:"input"`
	Label string `mapstructure:"label" yaml:"label"`
}

// RoutingPreferenceSignal detects user preferences or style requests.
type RoutingPreferenceSignal struct {
	Name        string                     `mapstructure:"name"        yaml:"name"`
	Description string                     `mapstructure:"description" yaml:"description,omitempty"`
	Examples    []RoutingPreferenceExample `mapstructure:"examples"    yaml:"examples,omitempty"`
	Threshold   float64                    `mapstructure:"threshold"   yaml:"threshold,omitempty"`
}

// RoutingConversationFeature defines a conversation-level feature to detect.
type RoutingConversationFeature struct {
	Type      string `mapstructure:"type"      yaml:"type"`
	Source    string `mapstructure:"source"    yaml:"source,omitempty"`
	Predicate string `mapstructure:"predicate" yaml:"predicate,omitempty"`
}

// RoutingConversationSignal evaluates conversation-level features.
type RoutingConversationSignal struct {
	Name        string                     `mapstructure:"name"        yaml:"name"`
	Description string                     `mapstructure:"description" yaml:"description,omitempty"`
	Feature     RoutingConversationFeature `mapstructure:"feature"     yaml:"feature,omitempty"`
}

// RoutingEventTemporal defines time-window constraints for event signals.
type RoutingEventTemporal struct {
	WindowSeconds int    `mapstructure:"window_seconds" yaml:"window_seconds,omitempty"`
	Operator      string `mapstructure:"operator"       yaml:"operator,omitempty"` // within | after | before
}

// RoutingEventSignal routes based on system or application events.
type RoutingEventSignal struct {
	Name        string               `mapstructure:"name"         yaml:"name"`
	Description string               `mapstructure:"description"  yaml:"description,omitempty"`
	EventTypes  []string             `mapstructure:"event_types"  yaml:"event_types,omitempty"`
	Severities  []string             `mapstructure:"severities"   yaml:"severities,omitempty"`
	ActionCodes []string             `mapstructure:"action_codes" yaml:"action_codes,omitempty"`
	Temporal    RoutingEventTemporal `mapstructure:"temporal"     yaml:"temporal,omitempty"`
}

// RoutingMetadataSignal routes based on request metadata key-value pairs.
type RoutingMetadataSignal struct {
	Name        string `mapstructure:"name"        yaml:"name"`
	Description string `mapstructure:"description" yaml:"description,omitempty"`
	Key         string `mapstructure:"key"         yaml:"key"`
	Predicate   string `mapstructure:"predicate"   yaml:"predicate,omitempty"`
}

// RoutingRoleBindingSignal routes based on RBAC role bindings.
type RoutingRoleBindingSignal struct {
	Name        string   `mapstructure:"name"        yaml:"name"`
	Description string   `mapstructure:"description" yaml:"description,omitempty"`
	Role        string   `mapstructure:"role"        yaml:"role"`
	Subjects    []string `mapstructure:"subjects"    yaml:"subjects,omitempty"`
}

// RoutingKBSignal routes based on knowledge base similarity matches.
type RoutingKBSignal struct {
	Name   string `mapstructure:"name"   yaml:"name"`
	KB     string `mapstructure:"kb"     yaml:"kb"`
	Target string `mapstructure:"target" yaml:"target,omitempty"`
	Match  string `mapstructure:"match"  yaml:"match,omitempty"`
}

// RoutingClassifierSignal uses a trained classifier model for signal detection.
type RoutingClassifierSignal struct {
	Name         string   `mapstructure:"name"          yaml:"name"`
	Description  string   `mapstructure:"description"   yaml:"description,omitempty"`
	Type         string   `mapstructure:"type"          yaml:"type,omitempty"` // zero_shot | trained | llm
	ModelPath    string   `mapstructure:"model_path"    yaml:"model_path,omitempty"`
	Model        string   `mapstructure:"model"         yaml:"model,omitempty"`
	Labels       []string `mapstructure:"labels"        yaml:"labels,omitempty"`
	UseCPU       bool     `mapstructure:"use_cpu"       yaml:"use_cpu,omitempty"`
	Instructions string   `mapstructure:"instructions"  yaml:"instructions,omitempty"`
}

// ---------------------------------------------------------------------------
// Algorithm configuration types
// ---------------------------------------------------------------------------

// RoutingAlgorithmConfig wraps the algorithm selection and type-specific
// configuration. Only one of the embedded configs should be non-nil.
type RoutingAlgorithmConfig struct {
	Type         string                    `mapstructure:"type"          yaml:"type"`
	Confidence   *ConfidenceAlgorithmCfg   `mapstructure:"confidence"    yaml:"confidence,omitempty"`
	Automix      *AutomixAlgorithmCfg      `mapstructure:"automix"       yaml:"automix,omitempty"`
	Hybrid       *HybridAlgorithmCfg       `mapstructure:"hybrid"        yaml:"hybrid,omitempty"`
	RouterDC     *RouterDCAlgorithmCfg     `mapstructure:"router_dc"     yaml:"router_dc,omitempty"`
	Remom        *RemomAlgorithmCfg        `mapstructure:"remom"         yaml:"remom,omitempty"`
	Fusion       *FusionAlgorithmCfg       `mapstructure:"fusion"        yaml:"fusion,omitempty"`
	Workflows    *WorkflowsAlgorithmCfg    `mapstructure:"workflows"     yaml:"workflows,omitempty"`
	LatencyAware *LatencyAwareAlgorithmCfg `mapstructure:"latency_aware" yaml:"latency_aware,omitempty"`
	MultiFactor  *MultiFactorAlgorithmCfg  `mapstructure:"multi_factor"  yaml:"multi_factor,omitempty"`
	Prompt       *PromptAlgorithmCfg       `mapstructure:"prompt"        yaml:"prompt,omitempty"`
	Ratings      *RatingsAlgorithmCfg      `mapstructure:"ratings"       yaml:"ratings,omitempty"`
}

// ConfidenceAlgorithmCfg configures confidence-based model selection.
type ConfidenceAlgorithmCfg struct {
	ConfidenceMethod    string             `mapstructure:"confidence_method"   yaml:"confidence_method,omitempty"`
	Threshold           float64            `mapstructure:"threshold"           yaml:"threshold,omitempty"`
	HybridWeights       map[string]float64 `mapstructure:"hybrid_weights"      yaml:"hybrid_weights,omitempty"`
	EscalationOrder     []string           `mapstructure:"escalation_order"    yaml:"escalation_order,omitempty"`
	CostQualityTradeoff float64            `mapstructure:"cost_quality_tradeoff" yaml:"cost_quality_tradeoff,omitempty"`
	TokenFilter         int                `mapstructure:"token_filter"        yaml:"token_filter,omitempty"`
	OnError             string             `mapstructure:"on_error"            yaml:"on_error,omitempty"`
}

// AutomixAlgorithmCfg configures automatic model mixing with escalation.
type AutomixAlgorithmCfg struct {
	VerificationThreshold  float64 `mapstructure:"verification_threshold" yaml:"verification_threshold,omitempty"`
	MaxEscalations         int     `mapstructure:"max_escalations"        yaml:"max_escalations,omitempty"`
	CostAwareRouting       bool    `mapstructure:"cost_aware_routing"     yaml:"cost_aware_routing,omitempty"`
	CostQualityTradeoff    float64 `mapstructure:"cost_quality_tradeoff"  yaml:"cost_quality_tradeoff,omitempty"`
	DiscountFactor         float64 `mapstructure:"discount_factor"        yaml:"discount_factor,omitempty"`
	UseLogprobVerification bool    `mapstructure:"use_logprob_verification" yaml:"use_logprob_verification,omitempty"`
}

// HybridAlgorithmCfg blends multiple routing strategies.
type HybridAlgorithmCfg struct {
	ExperienceWeight    float64 `mapstructure:"experience_weight"     yaml:"experience_weight,omitempty"`
	RouterDCWeight      float64 `mapstructure:"router_dc_weight"      yaml:"router_dc_weight,omitempty"`
	AutomixWeight       float64 `mapstructure:"automix_weight"        yaml:"automix_weight,omitempty"`
	CostWeight          float64 `mapstructure:"cost_weight"           yaml:"cost_weight,omitempty"`
	QualityGapThreshold float64 `mapstructure:"quality_gap_threshold" yaml:"quality_gap_threshold,omitempty"`
	NormalizeScores     bool    `mapstructure:"normalize_scores"      yaml:"normalize_scores,omitempty"`
}

// RouterDCAlgorithmCfg configures description-contrastive routing.
type RouterDCAlgorithmCfg struct {
	Temperature         float64 `mapstructure:"temperature"           yaml:"temperature,omitempty"`
	DimensionSize       int     `mapstructure:"dimension_size"        yaml:"dimension_size,omitempty"`
	MinSimilarity       float64 `mapstructure:"min_similarity"        yaml:"min_similarity,omitempty"`
	UseQueryContrastive bool    `mapstructure:"use_query_contrastive" yaml:"use_query_contrastive,omitempty"`
	UseModelContrastive bool    `mapstructure:"use_model_contrastive" yaml:"use_model_contrastive,omitempty"`
	RequireDescriptions bool    `mapstructure:"require_descriptions"  yaml:"require_descriptions,omitempty"`
	UseCapabilities     bool    `mapstructure:"use_capabilities"      yaml:"use_capabilities,omitempty"`
}

// RemomAlgorithmCfg configures Reasoning-over-Models (ReMoM) multi-model
// orchestration with breadth-first exploration.
type RemomAlgorithmCfg struct {
	BreadthSchedule        []int              `mapstructure:"breadth_schedule"        yaml:"breadth_schedule,omitempty"`
	ModelDistribution      map[string]float64 `mapstructure:"model_distribution"      yaml:"model_distribution,omitempty"`
	Temperature            float64            `mapstructure:"temperature"             yaml:"temperature,omitempty"`
	IncludeReasoning       bool               `mapstructure:"include_reasoning"       yaml:"include_reasoning,omitempty"`
	CompactionStrategy     string             `mapstructure:"compaction_strategy"     yaml:"compaction_strategy,omitempty"`
	CompactionTokens       int                `mapstructure:"compaction_tokens"       yaml:"compaction_tokens,omitempty"`
	SynthesisTemplate      string             `mapstructure:"synthesis_template"      yaml:"synthesis_template,omitempty"`
	SynthesisModel         string             `mapstructure:"synthesis_model"         yaml:"synthesis_model,omitempty"`
	MaxConcurrent          int                `mapstructure:"max_concurrent"          yaml:"max_concurrent,omitempty"`
	MaxCompletionTokens    int                `mapstructure:"max_completion_tokens"   yaml:"max_completion_tokens,omitempty"`
	RoundTimeoutSeconds    int                `mapstructure:"round_timeout_seconds"   yaml:"round_timeout_seconds,omitempty"`
	MinSuccessfulResponses int                `mapstructure:"min_successful_responses" yaml:"min_successful_responses,omitempty"`
	OnError                string             `mapstructure:"on_error"                yaml:"on_error,omitempty"`
}

// FusionAlgorithmCfg configures multi-model fusion with analysis.
type FusionAlgorithmCfg struct {
	Model               string   `mapstructure:"model"                 yaml:"model,omitempty"`
	AnalysisModels      []string `mapstructure:"analysis_models"       yaml:"analysis_models,omitempty"`
	MaxConcurrent       int      `mapstructure:"max_concurrent"        yaml:"max_concurrent,omitempty"`
	MaxCompletionTokens int      `mapstructure:"max_completion_tokens" yaml:"max_completion_tokens,omitempty"`
	RoundTimeoutSeconds int      `mapstructure:"round_timeout_seconds" yaml:"round_timeout_seconds,omitempty"`
	Temperature         float64  `mapstructure:"temperature"           yaml:"temperature,omitempty"`
	IncludeAnalysis     bool     `mapstructure:"include_analysis"      yaml:"include_analysis,omitempty"`
	OnError             string   `mapstructure:"on_error"              yaml:"on_error,omitempty"`
	Grounding           string   `mapstructure:"grounding"             yaml:"grounding,omitempty"`
}

// WorkflowsPlannerCfg configures the planner component of workflow routing.
type WorkflowsPlannerCfg struct {
	Model               string  `mapstructure:"model"                 yaml:"model,omitempty"`
	MaxSteps            int     `mapstructure:"max_steps"             yaml:"max_steps,omitempty"`
	MaxParallel         int     `mapstructure:"max_parallel"          yaml:"max_parallel,omitempty"`
	MaxCompletionTokens int     `mapstructure:"max_completion_tokens" yaml:"max_completion_tokens,omitempty"`
	RoundTimeoutSeconds int     `mapstructure:"round_timeout_seconds" yaml:"round_timeout_seconds,omitempty"`
	Temperature         float64 `mapstructure:"temperature"           yaml:"temperature,omitempty"`
	OnError             string  `mapstructure:"on_error"              yaml:"on_error,omitempty"`
}

// WorkflowsAlgorithmCfg configures workflow-based multi-step routing.
type WorkflowsAlgorithmCfg struct {
	Mode     string              `mapstructure:"mode"     yaml:"mode,omitempty"`
	Template string              `mapstructure:"template" yaml:"template,omitempty"`
	Planner  WorkflowsPlannerCfg `mapstructure:"planner"  yaml:"planner,omitempty"`
}

// LatencyAwareAlgorithmCfg configures latency-based model selection using
// percentile-based SLO thresholds.
type LatencyAwareAlgorithmCfg struct {
	TPOTPercentile float64 `mapstructure:"tpot_percentile" yaml:"tpot_percentile,omitempty"`
	TTFTPercentile float64 `mapstructure:"ttft_percentile" yaml:"ttft_percentile,omitempty"`
	Description    string  `mapstructure:"description"     yaml:"description,omitempty"`
}

// MultiFactorWeights holds the relative weights for multi-factor scoring.
type MultiFactorWeights struct {
	Quality float64 `mapstructure:"quality" yaml:"quality,omitempty"`
	Latency float64 `mapstructure:"latency" yaml:"latency,omitempty"`
	Cost    float64 `mapstructure:"cost"    yaml:"cost,omitempty"`
	Load    float64 `mapstructure:"load"    yaml:"load,omitempty"`
}

// MultiFactorSLO defines service-level objectives for multi-factor routing.
type MultiFactorSLO struct {
	MaxTPOTMs    float64 `mapstructure:"max_tpot_ms"    yaml:"max_tpot_ms,omitempty"`
	MaxTTFTMs    float64 `mapstructure:"max_ttft_ms"    yaml:"max_ttft_ms,omitempty"`
	MaxCostPer1M float64 `mapstructure:"max_cost_per_1m" yaml:"max_cost_per_1m,omitempty"`
	MaxInflight  int     `mapstructure:"max_inflight"   yaml:"max_inflight,omitempty"`
}

// MultiFactorAlgorithmCfg configures multi-factor routing combining quality,
// latency, cost, and load signals.
type MultiFactorAlgorithmCfg struct {
	Weights           MultiFactorWeights `mapstructure:"weights"            yaml:"weights,omitempty"`
	SLO               MultiFactorSLO     `mapstructure:"slo"                yaml:"slo,omitempty"`
	LatencyPercentile float64            `mapstructure:"latency_percentile" yaml:"latency_percentile,omitempty"`
	OnNoCandidates    string             `mapstructure:"on_no_candidates"   yaml:"on_no_candidates,omitempty"`
}

// PromptAlgorithmCfg configures LLM-prompt-based routing decisions.
type PromptAlgorithmCfg struct {
	Model          string `mapstructure:"model"           yaml:"model,omitempty"`
	Instructions   string `mapstructure:"instructions"    yaml:"instructions,omitempty"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds" yaml:"timeout_seconds,omitempty"`
}

// RatingsAlgorithmCfg configures ratings-based model selection.
type RatingsAlgorithmCfg struct {
	MaxConcurrent int    `mapstructure:"max_concurrent" yaml:"max_concurrent,omitempty"`
	OnError       string `mapstructure:"on_error"       yaml:"on_error,omitempty"`
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

// RoutingDecisionV2 is the expanded decision rule supporting tiered routing,
// output contracts, plugins, adaptations, and event emission.
type RoutingDecisionV2 struct {
	Name           string                 `mapstructure:"name"            yaml:"name"`
	Description    string                 `mapstructure:"description"     yaml:"description,omitempty"`
	Priority       int                    `mapstructure:"priority"        yaml:"priority"`
	Tier           string                 `mapstructure:"tier"            yaml:"tier,omitempty"`
	OutputContract string                 `mapstructure:"output_contract" yaml:"output_contract,omitempty"`
	Rules          RoutingRulesV2         `mapstructure:"rules"           yaml:"rules,omitempty"`
	ModelRefs      []RoutingModelRefV2    `mapstructure:"model_refs"      yaml:"model_refs,omitempty"`
	Algorithm      RoutingAlgorithmConfig `mapstructure:"algorithm"       yaml:"algorithm,omitempty"`
	Plugins        []RoutingPluginConfig  `mapstructure:"plugins"         yaml:"plugins,omitempty"`
	Adaptations    []RoutingAdaptation    `mapstructure:"adaptations"     yaml:"adaptations,omitempty"`
	Emits          []string               `mapstructure:"emits"           yaml:"emits,omitempty"`
	Annotations    map[string]string      `mapstructure:"annotations"     yaml:"annotations,omitempty"`
}

// RoutingRulesV2 supports compound AND/OR/NOT logic with nested children.
type RoutingRulesV2 struct {
	Operator   string               `mapstructure:"operator"   yaml:"operator,omitempty"` // AND | OR | NOT
	Conditions []RoutingConditionV2 `mapstructure:"conditions" yaml:"conditions,omitempty"`
	Children   []RoutingRulesV2     `mapstructure:"children"   yaml:"children,omitempty"`
}

// RoutingConditionV2 is an expanded condition supporting nested sub-conditions,
// confidence thresholds, and error handling.
type RoutingConditionV2 struct {
	Type          string               `mapstructure:"type"           yaml:"type"`
	Name          string               `mapstructure:"name"           yaml:"name,omitempty"`
	Operator      string               `mapstructure:"operator"       yaml:"operator,omitempty"`
	Conditions    []RoutingConditionV2 `mapstructure:"conditions"     yaml:"conditions,omitempty"`
	Label         string               `mapstructure:"label"          yaml:"label,omitempty"`
	Predicate     string               `mapstructure:"predicate"      yaml:"predicate,omitempty"`
	OnError       string               `mapstructure:"on_error"       yaml:"on_error,omitempty"`
	MinConfidence float64              `mapstructure:"min_confidence" yaml:"min_confidence,omitempty"`
}

// RoutingModelRefV2 references a model with reasoning and LoRA configuration.
type RoutingModelRefV2 struct {
	Model                string  `mapstructure:"model"                 yaml:"model"`
	UseReasoning         bool    `mapstructure:"use_reasoning"         yaml:"use_reasoning,omitempty"`
	ReasoningEffort      string  `mapstructure:"reasoning_effort"      yaml:"reasoning_effort,omitempty"`
	ReasoningDescription string  `mapstructure:"reasoning_description" yaml:"reasoning_description,omitempty"`
	LoRAName             string  `mapstructure:"lora_name"             yaml:"lora_name,omitempty"`
	Weight               float64 `mapstructure:"weight"                yaml:"weight,omitempty"`
}

// RoutingAdaptation defines runtime adaptations applied to a decision.
type RoutingAdaptation struct {
	Type   string                 `mapstructure:"type"   yaml:"type"`
	Config map[string]interface{} `mapstructure:"config" yaml:"config,omitempty"`
}

// ---------------------------------------------------------------------------
// Plugin types
// ---------------------------------------------------------------------------

// RoutingPluginConfig is the generic plugin wrapper with a type discriminator
// and free-form configuration.
type RoutingPluginConfig struct {
	Type          string                 `mapstructure:"type"          yaml:"type"`
	Configuration map[string]interface{} `mapstructure:"configuration" yaml:"configuration,omitempty"`
}

// ResponseCachePlugin configures response caching for routing decisions.
type ResponseCachePlugin struct {
	TTLSeconds   int    `mapstructure:"ttl_seconds"     yaml:"ttl_seconds,omitempty"`
	MaxEntries   int    `mapstructure:"max_entries"     yaml:"max_entries,omitempty"`
	KeyStrategy  string `mapstructure:"key_strategy"    yaml:"key_strategy,omitempty"`
	Backend      string `mapstructure:"backend"         yaml:"backend,omitempty"`
	InvalidateOn string `mapstructure:"invalidate_on"   yaml:"invalidate_on,omitempty"`
}

// ContextCompressionPlugin configures context window compression.
type ContextCompressionPlugin struct {
	Strategy       string `mapstructure:"strategy"        yaml:"strategy,omitempty"` // truncate | summarize | sliding_window
	MaxTokens      int    `mapstructure:"max_tokens"      yaml:"max_tokens,omitempty"`
	SummaryModel   string `mapstructure:"summary_model"   yaml:"summary_model,omitempty"`
	PreserveSystem bool   `mapstructure:"preserve_system" yaml:"preserve_system,omitempty"`
}

// RAGPlugin configures retrieval-augmented generation integration.
type RAGPlugin struct {
	Store          string  `mapstructure:"store"          yaml:"store,omitempty"`
	TopK           int     `mapstructure:"top_k"          yaml:"top_k,omitempty"`
	ScoreThreshold float64 `mapstructure:"score_threshold" yaml:"score_threshold,omitempty"`
	IncludeSource  bool    `mapstructure:"include_source" yaml:"include_source,omitempty"`
	ChunkOverlap   int     `mapstructure:"chunk_overlap"  yaml:"chunk_overlap,omitempty"`
}

// MemoryPlugin configures conversation memory management.
type MemoryPlugin struct {
	Backend      string `mapstructure:"backend"        yaml:"backend,omitempty"`
	MaxTurns     int    `mapstructure:"max_turns"      yaml:"max_turns,omitempty"`
	SummaryAfter int    `mapstructure:"summary_after"  yaml:"summary_after,omitempty"`
	SummaryModel string `mapstructure:"summary_model"  yaml:"summary_model,omitempty"`
	PersistStore string `mapstructure:"persist_store"  yaml:"persist_store,omitempty"`
}

// ToolsPlugin configures tool/function calling integration.
type ToolsPlugin struct {
	AllowedTools  []string `mapstructure:"allowed_tools"  yaml:"allowed_tools,omitempty"`
	MaxIterations int      `mapstructure:"max_iterations" yaml:"max_iterations,omitempty"`
	Parallel      bool     `mapstructure:"parallel"       yaml:"parallel,omitempty"`
	StrictMode    bool     `mapstructure:"strict_mode"    yaml:"strict_mode,omitempty"`
}

// SystemPromptPlugin configures system prompt injection/override.
type SystemPromptPlugin struct {
	Prepend  string `mapstructure:"prepend"  yaml:"prepend,omitempty"`
	Append   string `mapstructure:"append"   yaml:"append,omitempty"`
	Override string `mapstructure:"override" yaml:"override,omitempty"`
}

// HeaderMutationPlugin configures HTTP header manipulation for upstream calls.
type HeaderMutationPlugin struct {
	Add    map[string]string `mapstructure:"add"    yaml:"add,omitempty"`
	Remove []string          `mapstructure:"remove" yaml:"remove,omitempty"`
	Set    map[string]string `mapstructure:"set"    yaml:"set,omitempty"`
}

// HallucinationPlugin configures hallucination detection and mitigation.
type HallucinationPlugin struct {
	Method       string  `mapstructure:"method"        yaml:"method,omitempty"` // selfcheck | crosscheck | grounding
	Threshold    float64 `mapstructure:"threshold"     yaml:"threshold,omitempty"`
	GroundingDoc string  `mapstructure:"grounding_doc" yaml:"grounding_doc,omitempty"`
	OnDetect     string  `mapstructure:"on_detect"     yaml:"on_detect,omitempty"` // warn | block | retry
}

// ---------------------------------------------------------------------------
// Projection types
// ---------------------------------------------------------------------------

// RoutingProjectionsConfig defines score projections, partitions, and mappings
// used to transform signals into routing dimensions.
type RoutingProjectionsConfig struct {
	Partitions []RoutingPartition `mapstructure:"partitions" yaml:"partitions,omitempty"`
	Scores     []RoutingScore     `mapstructure:"scores"     yaml:"scores,omitempty"`
	Mappings   []RoutingMapping   `mapstructure:"mappings"   yaml:"mappings,omitempty"`
}

// RoutingPartition defines a named partition of the model space.
type RoutingPartition struct {
	Name   string   `mapstructure:"name"   yaml:"name"`
	Models []string `mapstructure:"models" yaml:"models,omitempty"`
	Tags   []string `mapstructure:"tags"   yaml:"tags,omitempty"`
}

// RoutingScore defines a computed score dimension.
type RoutingScore struct {
	Name       string             `mapstructure:"name"       yaml:"name"`
	Expression string             `mapstructure:"expression" yaml:"expression,omitempty"`
	Weights    map[string]float64 `mapstructure:"weights"    yaml:"weights,omitempty"`
	Normalize  bool               `mapstructure:"normalize"  yaml:"normalize,omitempty"`
}

// RoutingMapping maps signals to model dimensions.
type RoutingMapping struct {
	Signal    string            `mapstructure:"signal"    yaml:"signal"`
	Dimension string            `mapstructure:"dimension" yaml:"dimension,omitempty"`
	Transform string            `mapstructure:"transform" yaml:"transform,omitempty"`
	Params    map[string]string `mapstructure:"params"    yaml:"params,omitempty"`
}

// ---------------------------------------------------------------------------
// Recipe and Entrypoint types
// ---------------------------------------------------------------------------

// RoutingRecipe defines a reusable routing configuration template.
type RoutingRecipe struct {
	Name        string             `mapstructure:"name"        yaml:"name"`
	Description string             `mapstructure:"description" yaml:"description,omitempty"`
	Routing     RoutingRecipeBlock `mapstructure:"routing"     yaml:"routing,omitempty"`
}

// RoutingRecipeBlock is the routing configuration within a recipe.
type RoutingRecipeBlock struct {
	Models    []string               `mapstructure:"models"    yaml:"models,omitempty"`
	Algorithm RoutingAlgorithmConfig `mapstructure:"algorithm" yaml:"algorithm,omitempty"`
	Signals   []string               `mapstructure:"signals"   yaml:"signals,omitempty"`
	Plugins   []RoutingPluginConfig  `mapstructure:"plugins"   yaml:"plugins,omitempty"`
}

// RoutingEntrypoint maps virtual model names to a recipe.
type RoutingEntrypoint struct {
	ModelNames []string `mapstructure:"model_names" yaml:"model_names"`
	Recipe     string   `mapstructure:"recipe"      yaml:"recipe"`
}

// ---------------------------------------------------------------------------
// Global config
// ---------------------------------------------------------------------------

// RoutingGlobalConfig defines cluster-wide routing services, stores, and
// integration points.
type RoutingGlobalConfig struct {
	Router       RoutingGlobalRouter       `mapstructure:"router"        yaml:"router,omitempty"`
	Services     RoutingGlobalServices     `mapstructure:"services"      yaml:"services,omitempty"`
	Stores       RoutingGlobalStores       `mapstructure:"stores"        yaml:"stores,omitempty"`
	ModelCatalog RoutingGlobalModelCatalog `mapstructure:"model_catalog" yaml:"model_catalog,omitempty"`
	Integrations RoutingGlobalIntegrations `mapstructure:"integrations"  yaml:"integrations,omitempty"`
}

// RoutingGlobalRouter defines global router-level settings.
type RoutingGlobalRouter struct {
	Port           int    `mapstructure:"port"            yaml:"port,omitempty"`
	MetricsPort    int    `mapstructure:"metrics_port"    yaml:"metrics_port,omitempty"`
	HealthEndpoint string `mapstructure:"health_endpoint" yaml:"health_endpoint,omitempty"`
	LogLevel       string `mapstructure:"log_level"       yaml:"log_level,omitempty"`
	MaxConcurrent  int    `mapstructure:"max_concurrent"  yaml:"max_concurrent,omitempty"`
}

// RoutingGlobalServices defines external service endpoints used by the router.
type RoutingGlobalServices struct {
	EmbeddingEndpoint  string `mapstructure:"embedding_endpoint" yaml:"embedding_endpoint,omitempty"`
	EmbeddingModel     string `mapstructure:"embedding_model"    yaml:"embedding_model,omitempty"`
	ClassifierEndpoint string `mapstructure:"classifier_endpoint" yaml:"classifier_endpoint,omitempty"`
	GuardrailEndpoint  string `mapstructure:"guardrail_endpoint" yaml:"guardrail_endpoint,omitempty"`
}

// RoutingGlobalStores defines storage backends for routing state.
type RoutingGlobalStores struct {
	VectorDB    string `mapstructure:"vector_db"    yaml:"vector_db,omitempty"`
	Cache       string `mapstructure:"cache"        yaml:"cache,omitempty"`
	Persistence string `mapstructure:"persistence"  yaml:"persistence,omitempty"`
}

// RoutingGlobalModelCatalog configures the model catalog source.
type RoutingGlobalModelCatalog struct {
	Source   string `mapstructure:"source"   yaml:"source,omitempty"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	Refresh  string `mapstructure:"refresh"  yaml:"refresh,omitempty"`
}

// RoutingGlobalIntegrations configures third-party integrations.
type RoutingGlobalIntegrations struct {
	Telemetry  RoutingTelemetryIntegration `mapstructure:"telemetry"  yaml:"telemetry,omitempty"`
	Guardrails RoutingGuardrailIntegration `mapstructure:"guardrails" yaml:"guardrails,omitempty"`
}

// RoutingTelemetryIntegration configures telemetry export for routing decisions.
type RoutingTelemetryIntegration struct {
	Enabled    bool    `mapstructure:"enabled"    yaml:"enabled,omitempty"`
	Endpoint   string  `mapstructure:"endpoint"   yaml:"endpoint,omitempty"`
	SampleRate float64 `mapstructure:"sample_rate" yaml:"sample_rate,omitempty"`
}

// RoutingGuardrailIntegration configures guardrail enforcement on routed requests.
type RoutingGuardrailIntegration struct {
	Enabled  bool   `mapstructure:"enabled"  yaml:"enabled,omitempty"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	Mode     string `mapstructure:"mode"     yaml:"mode,omitempty"` // block | warn | log
}

// ---------------------------------------------------------------------------
// Context config (DC-specific identity extraction)
// ---------------------------------------------------------------------------

// RoutingContextConfig configures identity and header passthrough for routing
// decisions. Used by Defense Claw to extract session, user, and group info
// from upstream requests.
type RoutingContextConfig struct {
	SessionHeaders     []string `mapstructure:"session_headers"    yaml:"session_headers,omitempty"`
	UserIDHeaders      []string `mapstructure:"user_id_headers"    yaml:"user_id_headers,omitempty"`
	UserGroupHeaders   []string `mapstructure:"user_group_headers" yaml:"user_group_headers,omitempty"`
	PassthroughHeaders []string `mapstructure:"passthrough_headers" yaml:"passthrough_headers,omitempty"`
	GuardrailSignals   bool     `mapstructure:"guardrail_signals"  yaml:"guardrail_signals,omitempty"`
}
