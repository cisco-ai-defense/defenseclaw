// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

// Semantic routing keys added in 1.0.10: the in-process classifier choice,
// the routing policy (global, organization floor in routing.admin, and the
// tighten-only overlay in guardrail.profiles.<name>.routing) and route-only
// mode for hook connectors. Absent keys keep the 1.0.9 meaning.

// RoutingMinProductVersion is the first release that reads the keys
// listed by UsesMinProductVersion1010Keys.
const RoutingMinProductVersion = "1.0.10"

// Classifier names (routing.classifier).
const (
	RoutingClassifierRules     = "rules"
	RoutingClassifierSystemOne = "systemone"
	RoutingClassifierVLLMSR    = "vllm_sr"
)

// routing.on_classifier_error values.
const (
	RoutingOnErrorOriginal = "original"
	RoutingOnErrorRules    = "rules"
)

// API families a routed backend can serve without translation.
const (
	RoutingAPIChat      = "chat"
	RoutingAPIMessages  = "messages"
	RoutingAPIResponses = "responses"
	RoutingAPIConverse  = "converse"
	RoutingAPIInvoke    = "invoke"
)

// RoutingAPIs is the closed set of routing.models[].apis values.
var RoutingAPIs = []string{RoutingAPIChat, RoutingAPIMessages, RoutingAPIResponses, RoutingAPIConverse, RoutingAPIInvoke}

// Bedrock upstream auth modes (routing.models[].bedrock.auth and
// routing.route_only.upstreams.<c>.bedrock.auth). passthrough forwards the
// agent bearer key; the others make the gateway sign with SigV4.
const (
	RoutingBedrockAuthPassthrough    = "passthrough"
	RoutingBedrockAuthProfile        = "profile"
	RoutingBedrockAuthInstanceRole   = "instance_role"
	RoutingBedrockAuthIAMCredentials = "iam_credentials"
)

// Rules-classifier condition types (routing.decisions[].conditions[].type).
const (
	RoutingConditionKeyword   = "keyword"
	RoutingConditionConnector = "connector"
	RoutingConditionAPIFamily = "api_family"
	RoutingConditionRequest   = "request"
)

// RoutingRequestConditions are the names a request condition accepts.
var RoutingRequestConditions = []string{"has_tools", "tool_turn", "has_images", "long_context"}

// RoutingLockableKeys are the names routing.admin.locked accepts. The
// first three are the keys a guardrail profile overlay may otherwise set;
// the rest are global keys a managed CLI shows as locked.
var RoutingLockableKeys = []string{
	"default_alias", "categories", "allow_user_override",
	"classifier", "models", "min_confidence", "on_classifier_error",
	"sensitive", "systemone", "route_only",
}

// RoutingPolicyConfig is the tighten-only overlay of
// guardrail.profiles.<name>.routing. routing.admin carries the same fields
// as the organization floor (RoutingAdminConfig.Policy).
type RoutingPolicyConfig struct {
	// AllowedAliases limits routing to these routing.models aliases; nil
	// adds no limit, an explicit empty list is refused.
	AllowedAliases []string `mapstructure:"allowed_aliases" yaml:"allowed_aliases,omitempty"`
	// DeniedProviders removes every alias of these providers.
	DeniedProviders []string `mapstructure:"denied_providers" yaml:"denied_providers,omitempty"`
	// DefaultAlias is used when the classifier picks nothing that survives.
	DefaultAlias string `mapstructure:"default_alias" yaml:"default_alias,omitempty"`
	// Categories maps a classifier category to an alias.
	Categories map[string]string `mapstructure:"categories" yaml:"categories,omitempty"`
	// AllowUserOverride lets a request that names an allowed alias as its
	// model keep it; false from any layer wins.
	AllowUserOverride *bool `mapstructure:"allow_user_override" yaml:"allow_user_override,omitempty"`
}

// RoutingAdminConfig is routing.admin, the organization floor. Profiles
// only tighten it. S11 adds rules, budgets and visibility.
type RoutingAdminConfig struct {
	AllowedAliases    []string          `mapstructure:"allowed_aliases"     yaml:"allowed_aliases,omitempty"`
	DeniedProviders   []string          `mapstructure:"denied_providers"    yaml:"denied_providers,omitempty"`
	DefaultAlias      string            `mapstructure:"default_alias"       yaml:"default_alias,omitempty"`
	Categories        map[string]string `mapstructure:"categories"          yaml:"categories,omitempty"`
	AllowUserOverride *bool             `mapstructure:"allow_user_override" yaml:"allow_user_override,omitempty"`
	// Locked names keys (RoutingLockableKeys) that profiles may not set and
	// that the CLI shows as locked.
	Locked []string `mapstructure:"locked" yaml:"locked,omitempty"`
}

// Policy returns the floor part of routing.admin.
func (a *RoutingAdminConfig) Policy() RoutingPolicyConfig {
	if a == nil {
		return RoutingPolicyConfig{}
	}
	return RoutingPolicyConfig{
		AllowedAliases:    a.AllowedAliases,
		DeniedProviders:   a.DeniedProviders,
		DefaultAlias:      a.DefaultAlias,
		Categories:        a.Categories,
		AllowUserOverride: a.AllowUserOverride,
	}
}

// IsLocked reports whether routing.admin.locked names key.
func (a *RoutingAdminConfig) IsLocked(key string) bool {
	if a == nil {
		return false
	}
	for _, k := range a.Locked {
		if k == key {
			return true
		}
	}
	return false
}

// RoutingSensitiveConfig narrows the allowed set to Aliases when the
// pre-call guardrail verdict is at or above SeverityAtLeast or one of the
// keyword Signals matches (best effort: neither catches prose PII).
type RoutingSensitiveConfig struct {
	SeverityAtLeast string   `mapstructure:"severity_at_least" yaml:"severity_at_least,omitempty"`
	Signals         []string `mapstructure:"signals"           yaml:"signals,omitempty"`
	Aliases         []string `mapstructure:"aliases"           yaml:"aliases,omitempty"`
}

// RoutingSystemOneConfig configures the optional System One classifier.
type RoutingSystemOneConfig struct {
	// UseDecisionModel reuses decision_model.base_url, model and credential
	// (nil = true).
	UseDecisionModel *bool  `mapstructure:"use_decision_model" yaml:"use_decision_model,omitempty"`
	BaseURL          string `mapstructure:"base_url"           yaml:"base_url,omitempty"`
	Model            string `mapstructure:"model"              yaml:"model,omitempty"`
	APIKeyEnv        string `mapstructure:"api_key_env"        yaml:"api_key_env,omitempty"`
	Credential       string `mapstructure:"credential"         yaml:"credential,omitempty"`
	// TimeoutMs caps one classification (0 = 300, at most 1000).
	TimeoutMs int `mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty"`
}

// RoutingSystemOneDefaultTimeoutMs and RoutingSystemOneMaxTimeoutMs bound
// routing.systemone.timeout_ms.
const (
	RoutingSystemOneDefaultTimeoutMs = 300
	RoutingSystemOneMaxTimeoutMs     = 1000
)

// EffectiveUseDecisionModel reports whether systemone reuses decision_model.
func (s *RoutingSystemOneConfig) EffectiveUseDecisionModel() bool {
	return s == nil || s.UseDecisionModel == nil || *s.UseDecisionModel
}

// EffectiveTimeoutMs returns timeout_ms with its default.
func (s *RoutingSystemOneConfig) EffectiveTimeoutMs() int {
	if s == nil || s.TimeoutMs <= 0 {
		return RoutingSystemOneDefaultTimeoutMs
	}
	return s.TimeoutMs
}

// RoutingBedrockAuthConfig says how the gateway authenticates a routed
// Bedrock call.
type RoutingBedrockAuthConfig struct {
	Region          string `mapstructure:"region"            yaml:"region,omitempty"`
	Auth            string `mapstructure:"auth"              yaml:"auth,omitempty"`
	Profile         string `mapstructure:"profile"           yaml:"profile,omitempty"`
	AccessKeyEnv    string `mapstructure:"access_key_env"    yaml:"access_key_env,omitempty"`
	SecretKeyEnv    string `mapstructure:"secret_key_env"    yaml:"secret_key_env,omitempty"`
	SessionTokenEnv string `mapstructure:"session_token_env" yaml:"session_token_env,omitempty"`
	// The *_credential names are protected credentials on a standalone
	// managed host, where the *_env names are refused.
	AccessKeyCredential    string `mapstructure:"access_key_credential"    yaml:"access_key_credential,omitempty"`
	SecretKeyCredential    string `mapstructure:"secret_key_credential"    yaml:"secret_key_credential,omitempty"`
	SessionTokenCredential string `mapstructure:"session_token_credential" yaml:"session_token_credential,omitempty"`
}

// RoutingUpstreamConfig is the passthrough upstream of one route-only
// connector, written by routing enable from the agent configuration.
type RoutingUpstreamConfig struct {
	BaseURL string                    `mapstructure:"base_url" yaml:"base_url,omitempty"`
	API     string                    `mapstructure:"api"      yaml:"api,omitempty"`
	Bedrock *RoutingBedrockAuthConfig `mapstructure:"bedrock"  yaml:"bedrock,omitempty"`
}

// RoutingRouteOnlyConfig is routing.route_only: hook connectors whose model
// traffic goes through the gateway API listener under /r/<connector>/ for
// routing and usage only (no guardrail scan; hooks keep deciding).
type RoutingRouteOnlyConfig struct {
	Connectors []string                         `mapstructure:"connectors" yaml:"connectors,omitempty"`
	Upstreams  map[string]RoutingUpstreamConfig `mapstructure:"upstreams"  yaml:"upstreams,omitempty"`
}

// IsZero reports whether route_only sets nothing.
func (r RoutingRouteOnlyConfig) IsZero() bool {
	return len(r.Connectors) == 0 && len(r.Upstreams) == 0
}

// RouteOnlyCapableConnectors are the connectors with routing capability
// base_url in 1.0.10.
var RouteOnlyCapableConnectors = []string{"claudecode", "codex"}
