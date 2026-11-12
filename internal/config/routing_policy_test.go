// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func boolp(v bool) *bool { return &v }

func TestRoutingPolicyKeysAbsentKeep109Meaning(t *testing.T) {
	cfg := validRoutingConfigForTest()
	if got := cfg.EffectiveClassifier(); got != RoutingClassifierVLLMSR {
		t.Fatalf("absent classifier = %q, want vllm_sr", got)
	}
	if got := cfg.EffectiveOnClassifierError(); got != RoutingOnErrorOriginal {
		t.Fatalf("absent on_classifier_error = %q, want original", got)
	}
	c := &Config{Routing: cfg}
	if keys := c.UsesMinProductVersion1010Keys(); keys != nil {
		t.Fatalf("a 1.0.9 routing block needs 1.0.10 keys %v", keys)
	}
}

func TestRoutingPolicyKeysValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*RoutingConfig)
		want string // "" = valid
	}{
		{"rules classifier", func(r *RoutingConfig) { r.Classifier = "rules" }, ""},
		{"bad classifier", func(r *RoutingConfig) { r.Classifier = "llm" }, "classifier"},
		{"min_confidence high", func(r *RoutingConfig) { r.MinConfidence = 1.5 }, "min_confidence"},
		{"on error", func(r *RoutingConfig) { r.OnClassifierError = "deny" }, "on_classifier_error"},
		{"default alias unknown", func(r *RoutingConfig) { r.DefaultAlias = "nope" }, "default_alias"},
		{"categories ok", func(r *RoutingConfig) { r.Categories = map[string]string{"code": "reasoning"} }, ""},
		{"categories bad name", func(r *RoutingConfig) { r.Categories = map[string]string{"Code!": "fast"} }, "categories key"},
		{"categories unknown alias", func(r *RoutingConfig) { r.Categories = map[string]string{"code": "x"} }, "unknown model alias"},
		{"sensitive ok", func(r *RoutingConfig) {
			r.Sensitive = &RoutingSensitiveConfig{SeverityAtLeast: "high", Aliases: []string{"fast"}}
		}, ""},
		{"sensitive no aliases", func(r *RoutingConfig) { r.Sensitive = &RoutingSensitiveConfig{SeverityAtLeast: "HIGH"} }, "sensitive.aliases"},
		{"systemone timeout", func(r *RoutingConfig) { r.SystemOne = &RoutingSystemOneConfig{TimeoutMs: 5000} }, "timeout_ms"},
		{"systemone own endpoint missing", func(r *RoutingConfig) {
			r.Classifier = "systemone"
			r.SystemOne = &RoutingSystemOneConfig{UseDecisionModel: boolp(false)}
		}, "systemone.base_url"},
		{"apis ok", func(r *RoutingConfig) { r.Models[1].APIs = []string{"responses"} }, ""},
		{"apis bad", func(r *RoutingConfig) { r.Models[1].APIs = []string{"gemini"} }, "apis[0]"},
		{"apis empty", func(r *RoutingConfig) { r.Models[1].APIs = []string{} }, "apis must not be empty"},
		{"bedrock on openai", func(r *RoutingConfig) { r.Models[1].Bedrock = &RoutingBedrockAuthConfig{Auth: "profile", Profile: "p"} }, "only valid for provider bedrock"},
		{"route only ok", func(r *RoutingConfig) {
			r.RouteOnly = RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: "messages"}}}
		}, ""},
		{"route only unsupported", func(r *RoutingConfig) { r.RouteOnly = RoutingRouteOnlyConfig{Connectors: []string{"cursor"}} }, "no route-only support"},
		{"route only upstream no url", func(r *RoutingConfig) {
			r.RouteOnly = RoutingRouteOnlyConfig{Upstreams: map[string]RoutingUpstreamConfig{"codex": {}}}
		}, "base_url must be set"},
		{"bedrock iam needs keys", func(r *RoutingConfig) {
			r.RouteOnly = RoutingRouteOnlyConfig{Upstreams: map[string]RoutingUpstreamConfig{"claudecode": {BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", Bedrock: &RoutingBedrockAuthConfig{Auth: "iam_credentials"}}}}
		}, "iam_credentials needs"},
		{"admin locked bad", func(r *RoutingConfig) { r.Admin = &RoutingAdminConfig{Locked: []string{"rules"}} }, "not a lockable key"},
		{"admin empty allowed", func(r *RoutingConfig) { r.Admin = &RoutingAdminConfig{AllowedAliases: []string{}} }, "allowed_aliases must not be empty"},
		{"connector condition on vllm", func(r *RoutingConfig) {
			r.Decisions = append(r.Decisions, RoutingDecisionRule{Name: "c", Conditions: []RoutingCondition{{Type: "connector", Name: "codex"}}, ModelRefs: []string{"fast"}})
		}, "needs classifier rules"},
		{"connector condition on rules", func(r *RoutingConfig) {
			r.Classifier = "rules"
			r.Decisions = append(r.Decisions, RoutingDecisionRule{Name: "c", Conditions: []RoutingCondition{{Type: "connector", Name: "codex"}}, ModelRefs: []string{"fast"}})
		}, ""},
		{"api family condition bad", func(r *RoutingConfig) {
			r.Classifier = "rules"
			r.Decisions = append(r.Decisions, RoutingDecisionRule{Name: "c", Conditions: []RoutingCondition{{Type: "api_family", Name: "gemini"}}, ModelRefs: []string{"fast"}})
		}, "must be one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRoutingConfigForTest()
			tc.mut(&r)
			err := r.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func tightenProviders() map[string]string {
	return map[string]string{"fast": "ollama", "reasoning": "openai", "claude": "anthropic", "local": "ollama"}
}

func TestTightenRoutingPolicyCombineMatrix(t *testing.T) {
	providers := tightenProviders()
	base := RoutingPolicyConfig{
		AllowedAliases:    []string{"fast", "reasoning", "claude"},
		DeniedProviders:   []string{"azure"},
		DefaultAlias:      "reasoning",
		Categories:        map[string]string{"code": "reasoning", "chat": "fast"},
		AllowUserOverride: boolp(true),
	}
	got, err := TightenRoutingPolicy(base, &RoutingPolicyConfig{
		AllowedAliases:    []string{"fast", "claude", "local"},
		DeniedProviders:   []string{"Anthropic"},
		AllowUserOverride: boolp(false),
		Categories:        map[string]string{"chat": "fast"},
	}, providers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.AllowedAliases, []string{"fast", "claude"}) {
		t.Fatalf("allowed = %v (intersection keeps base order)", got.AllowedAliases)
	}
	if !reflect.DeepEqual(got.DeniedProviders, []string{"azure", "Anthropic"}) {
		t.Fatalf("denied = %v (union)", got.DeniedProviders)
	}
	if got.UserOverrideAllowed() {
		t.Fatal("allow_user_override: false must win")
	}
	if got.DefaultAlias != "" {
		t.Fatalf("default = %q: the floor default reasoning is no longer allowed and the overlay named none", got.DefaultAlias)
	}
	if !reflect.DeepEqual(got.Categories, map[string]string{"chat": "fast"}) {
		t.Fatalf("categories = %v (entries whose alias is not allowed drop)", got.Categories)
	}
	if got.AliasAllowed("claude", providers) {
		t.Fatal("claude is allowed but its provider is denied")
	}
	if !reflect.DeepEqual(base.AllowedAliases, []string{"fast", "reasoning", "claude"}) || len(base.Categories) != 2 {
		t.Fatal("TightenRoutingPolicy modified its base")
	}
}

func TestTightenRoutingPolicyNilOverlayCopies(t *testing.T) {
	base := RoutingPolicyConfig{AllowedAliases: []string{"fast"}, Categories: map[string]string{"a": "fast"}, AllowUserOverride: boolp(true)}
	got, err := TightenRoutingPolicy(base, nil, tightenProviders(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got.AllowedAliases[0] = "x"
	got.Categories["a"] = "x"
	*got.AllowUserOverride = false
	if base.AllowedAliases[0] != "fast" || base.Categories["a"] != "fast" || !*base.AllowUserOverride {
		t.Fatal("the result aliases its base")
	}
}

func TestTightenRoutingPolicyContradictions(t *testing.T) {
	providers := tightenProviders()
	base := RoutingPolicyConfig{AllowedAliases: []string{"fast", "reasoning"}}
	for name, tc := range map[string]struct {
		overlay RoutingPolicyConfig
		locked  []string
		field   string
	}{
		"empty intersection":   {RoutingPolicyConfig{AllowedAliases: []string{"claude"}}, nil, "allowed_aliases"},
		"denied removes all":   {RoutingPolicyConfig{DeniedProviders: []string{"ollama", "OPENAI"}}, nil, "denied_providers"},
		"default not allowed":  {RoutingPolicyConfig{DefaultAlias: "claude"}, nil, "default_alias"},
		"category not allowed": {RoutingPolicyConfig{Categories: map[string]string{"x": "claude"}}, nil, "categories"},
		"locked default":       {RoutingPolicyConfig{DefaultAlias: "fast"}, []string{"default_alias"}, "default_alias"},
		"locked categories":    {RoutingPolicyConfig{Categories: map[string]string{}}, []string{"categories"}, "categories"},
		"locked user override": {RoutingPolicyConfig{AllowUserOverride: boolp(false)}, []string{"allow_user_override"}, "allow_user_override"},
	} {
		t.Run(name, func(t *testing.T) {
			overlay := tc.overlay
			locked := func(k string) bool { return slices.Contains(tc.locked, k) }
			_, err := TightenRoutingPolicy(base, &overlay, providers, locked)
			var c *RoutingPolicyContradictionError
			if !errors.As(err, &c) || c.Field != tc.field {
				t.Fatalf("err = %v, want a contradiction on %s", err, tc.field)
			}
		})
	}
}

func TestRoutingProfilesValidateAgainstAdminFloor(t *testing.T) {
	cfg := &Config{Routing: validRoutingConfigForTest()}
	cfg.Routing.Admin = &RoutingAdminConfig{AllowedAliases: []string{"fast"}, Locked: []string{"default_alias"}}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{
		"eng": {Routing: &RoutingPolicyConfig{AllowedAliases: []string{"fast", "reasoning"}}},
	}
	if err := cfg.validateRoutingProfiles(); err != nil {
		t.Fatalf("a profile that intersects to the floor is valid: %v", err)
	}
	p, err := cfg.RoutingPolicyForProfile("eng")
	if err != nil || !reflect.DeepEqual(p.AllowedAliases, []string{"fast"}) {
		t.Fatalf("eng policy = %+v, %v", p, err)
	}
	cfg.Guardrail.Profiles["ctr"] = GuardrailProfile{Routing: &RoutingPolicyConfig{DefaultAlias: "fast"}}
	if err := cfg.validateRoutingProfiles(); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("a profile setting a locked key = %v, want refused", err)
	}
	delete(cfg.Guardrail.Profiles, "ctr")
	cfg.Guardrail.Profiles["bad"] = GuardrailProfile{Routing: &RoutingPolicyConfig{AllowedAliases: []string{"nope"}}}
	if err := cfg.validateRoutingProfiles(); err == nil || !strings.Contains(err.Error(), "unknown model alias") {
		t.Fatalf("unknown alias in a profile = %v", err)
	}
}

func TestRoutingSecureClientRefusesAdminAndRouteOnly(t *testing.T) {
	cfg := &Config{Routing: validRoutingConfigForTest()}
	cfg.Routing.Admin = &RoutingAdminConfig{AllowedAliases: []string{"fast"}}
	if err := cfg.validateSecureClientRouting(); err != nil {
		t.Fatalf("OSS config refused: %v", err)
	}
	cfg.DeploymentMode = string(DeploymentModeManagedEnterprise)
	cfg.Enterprise.Profile = "secure_client"
	if !cfg.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client config")
	}
	if err := cfg.validateSecureClientRouting(); err == nil {
		t.Fatal("routing.admin under Secure Client must be refused")
	}
	cfg.Routing.Admin = nil
	cfg.Routing.RouteOnly.Connectors = []string{"codex"}
	if err := cfg.validateSecureClientRouting(); err == nil {
		t.Fatal("routing.route_only under Secure Client must be refused")
	}
}

func TestUsesMinProductVersion1010KeysListsNewKeys(t *testing.T) {
	cfg := &Config{Routing: validRoutingConfigForTest()}
	cfg.Routing.Classifier = "rules"
	cfg.Routing.Admin = &RoutingAdminConfig{AllowedAliases: []string{"fast"}}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"eng": {Routing: &RoutingPolicyConfig{}}}
	got := cfg.UsesMinProductVersion1010Keys()
	for _, want := range []string{"routing.classifier", "routing.admin", "guardrail.profiles.*.routing"} {
		if !slices.Contains(got, want) {
			t.Fatalf("keys = %v, missing %s", got, want)
		}
	}
}
