// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

var routingCategoryPattern = lazyregexp.New(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

const routingMaxCategories = 256

var routingSeverities = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}

// EffectiveClassifier returns routing.classifier; absent keeps the 1.0.9
// meaning (the vLLM Semantic Router container or remote classifier).
func (r *RoutingConfig) EffectiveClassifier() string {
	if r == nil || strings.TrimSpace(r.Classifier) == "" {
		return RoutingClassifierVLLMSR
	}
	return strings.TrimSpace(r.Classifier)
}

// EffectiveOnClassifierError returns routing.on_classifier_error with its
// 1.0.9 default (send the request unchanged).
func (r *RoutingConfig) EffectiveOnClassifierError() string {
	if r == nil || strings.TrimSpace(r.OnClassifierError) == "" {
		return RoutingOnErrorOriginal
	}
	return strings.TrimSpace(r.OnClassifierError)
}

// GlobalPolicy returns the routing.* policy keys as a RoutingPolicyConfig
// (the layer routing.admin and the profiles tighten).
func (r *RoutingConfig) GlobalPolicy() RoutingPolicyConfig {
	if r == nil {
		return RoutingPolicyConfig{}
	}
	override := r.AllowUserOverride
	return RoutingPolicyConfig{DefaultAlias: r.DefaultAlias, Categories: r.Categories, AllowUserOverride: &override}
}

// RoutingDefaultAPIs is the API set of a provider when routing.models[].apis
// is empty.
func RoutingDefaultAPIs(provider string) []string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "anthropic":
		return []string{RoutingAPIMessages}
	case "openai", "azure":
		return []string{RoutingAPIChat, RoutingAPIResponses}
	case "bedrock":
		return []string{RoutingAPIConverse, RoutingAPIInvoke, RoutingAPIChat}
	default:
		return []string{RoutingAPIChat}
	}
}

// EffectiveAPIs returns the API families of one backend.
func (m RoutingModelBackend) EffectiveAPIs() []string {
	if len(m.APIs) == 0 {
		return RoutingDefaultAPIs(m.Provider)
	}
	return m.APIs
}

func validRoutingSeverity(v string) bool {
	return slices.Contains(routingSeverities, strings.ToUpper(strings.TrimSpace(v)))
}

func (m RoutingModelBackend) validatePolicyKeys(i int) error {
	field := fmt.Sprintf("models[%d]", i)
	seen := map[string]bool{}
	for j, api := range m.APIs {
		if !slices.Contains(RoutingAPIs, api) {
			return fmt.Errorf("%s.apis[%d] %q must be one of %s", field, j, api, strings.Join(RoutingAPIs, ", "))
		}
		if seen[api] {
			return fmt.Errorf("%s.apis[%d] %q is duplicated", field, j, api)
		}
		seen[api] = true
	}
	if m.APIs != nil && len(m.APIs) == 0 {
		return fmt.Errorf("%s.apis must not be empty (leave the key out for the provider default)", field)
	}
	if c := strings.TrimSpace(m.Credential); c != "" && !ValidEnterpriseCredentialName(c) {
		return fmt.Errorf("%s.credential %q is not a valid credential name", field, m.Credential)
	}
	if m.Bedrock != nil {
		if !strings.EqualFold(strings.TrimSpace(m.Provider), "bedrock") {
			return fmt.Errorf("%s.bedrock is only valid for provider bedrock", field)
		}
		if err := m.Bedrock.validate(field + ".bedrock"); err != nil {
			return err
		}
	}
	return nil
}

func (b *RoutingBedrockAuthConfig) validate(field string) error {
	if b == nil {
		return nil
	}
	switch b.Auth {
	case "", RoutingBedrockAuthPassthrough, RoutingBedrockAuthProfile, RoutingBedrockAuthInstanceRole, RoutingBedrockAuthIAMCredentials:
	default:
		return fmt.Errorf("%s.auth %q must be passthrough, profile, instance_role or iam_credentials", field, b.Auth)
	}
	if b.Region != "" && !routingModelIdentifierPattern.MatchString(b.Region) {
		return fmt.Errorf("%s.region %q is not a valid region name", field, b.Region)
	}
	if b.Auth == RoutingBedrockAuthProfile && strings.TrimSpace(b.Profile) == "" {
		return fmt.Errorf("%s.auth profile needs profile", field)
	}
	for name, v := range map[string]string{"access_key_env": b.AccessKeyEnv, "secret_key_env": b.SecretKeyEnv, "session_token_env": b.SessionTokenEnv} {
		if v != "" && !routingEnvNamePattern.MatchString(v) {
			return fmt.Errorf("%s.%s %q is not a valid environment variable name", field, name, v)
		}
	}
	for name, v := range map[string]string{"access_key_credential": b.AccessKeyCredential, "secret_key_credential": b.SecretKeyCredential, "session_token_credential": b.SessionTokenCredential} {
		if v != "" && !ValidEnterpriseCredentialName(v) {
			return fmt.Errorf("%s.%s %q is not a valid credential name", field, name, v)
		}
	}
	if b.Auth == RoutingBedrockAuthIAMCredentials {
		hasEnv := b.AccessKeyEnv != "" && b.SecretKeyEnv != ""
		hasCred := b.AccessKeyCredential != "" && b.SecretKeyCredential != ""
		if !hasEnv && !hasCred {
			return fmt.Errorf("%s.auth iam_credentials needs access_key_env and secret_key_env (or the *_credential names)", field)
		}
	}
	return nil
}

// validatePolicyKeys checks the 1.0.10 routing keys. aliases maps every
// routing.models alias to its provider.
func (r *RoutingConfig) validatePolicyKeys(aliases map[string]string) error {
	switch r.Classifier {
	case "", RoutingClassifierRules, RoutingClassifierSystemOne, RoutingClassifierVLLMSR:
	default:
		return fmt.Errorf("classifier %q must be rules, systemone or vllm_sr", r.Classifier)
	}
	if math.IsNaN(r.MinConfidence) || r.MinConfidence < 0 || r.MinConfidence > 1 {
		return fmt.Errorf("min_confidence must be between 0 and 1, got %v", r.MinConfidence)
	}
	switch r.OnClassifierError {
	case "", RoutingOnErrorOriginal, RoutingOnErrorRules:
	default:
		return fmt.Errorf("on_classifier_error %q must be original or rules", r.OnClassifierError)
	}
	if err := validateRoutingPolicy("", r.GlobalPolicy(), aliases); err != nil {
		return err
	}
	if s := r.Sensitive; s != nil {
		if !validRoutingSeverity(s.SeverityAtLeast) {
			return fmt.Errorf("sensitive.severity_at_least %q must be LOW, MEDIUM, HIGH or CRITICAL", s.SeverityAtLeast)
		}
		if len(s.Aliases) == 0 {
			return fmt.Errorf("sensitive.aliases must name at least one routing.models alias")
		}
		if err := validateRoutingAliasList("sensitive.aliases", s.Aliases, aliases); err != nil {
			return err
		}
	}
	if err := r.SystemOne.validate(r.EffectiveClassifier() == RoutingClassifierSystemOne); err != nil {
		return err
	}
	if err := r.RouteOnly.validate(); err != nil {
		return err
	}
	if a := r.Admin; a != nil {
		if err := validateRoutingPolicy("admin.", a.Policy(), aliases); err != nil {
			return err
		}
		seen := map[string]bool{}
		for i, k := range a.Locked {
			if !slices.Contains(RoutingLockableKeys, k) {
				return fmt.Errorf("admin.locked[%d]: %q is not a lockable key (lockable: %s)", i, k, strings.Join(RoutingLockableKeys, ", "))
			}
			if seen[k] {
				return fmt.Errorf("admin.locked[%d]: %q is duplicated", i, k)
			}
			seen[k] = true
		}
		if a.Locked != nil && len(a.Locked) == 0 {
			return fmt.Errorf("admin.locked must not be empty (leave the key out to lock nothing)")
		}
	}
	return nil
}

func validateRoutingAliasList(field string, list []string, aliases map[string]string) error {
	seen := map[string]bool{}
	for i, a := range list {
		if _, ok := aliases[a]; !ok {
			return fmt.Errorf("%s[%d] references unknown model alias %q", field, i, a)
		}
		if seen[a] {
			return fmt.Errorf("%s[%d] %q is duplicated", field, i, a)
		}
		seen[a] = true
	}
	return nil
}

// validateRoutingPolicy checks one policy layer on its own. prefix is the
// dotted key prefix for messages ("", "admin." or a profile path).
func validateRoutingPolicy(prefix string, p RoutingPolicyConfig, aliases map[string]string) error {
	if p.AllowedAliases != nil && len(p.AllowedAliases) == 0 {
		return fmt.Errorf("%sallowed_aliases must not be empty (leave the key out for no limit)", prefix)
	}
	if err := validateRoutingAliasList(prefix+"allowed_aliases", p.AllowedAliases, aliases); err != nil {
		return err
	}
	if p.DeniedProviders != nil && len(p.DeniedProviders) == 0 {
		return fmt.Errorf("%sdenied_providers must not be empty (leave the key out to deny nothing)", prefix)
	}
	for i, d := range p.DeniedProviders {
		if strings.TrimSpace(d) == "" || len(d) > routingProviderMaxBytes {
			return fmt.Errorf("%sdenied_providers[%d] must be a provider name", prefix, i)
		}
	}
	if d := p.DefaultAlias; d != "" {
		if _, ok := aliases[d]; !ok {
			return fmt.Errorf("%sdefault_alias references unknown model alias %q", prefix, d)
		}
	}
	if len(p.Categories) > routingMaxCategories {
		return fmt.Errorf("%scategories must not have more than %d entries", prefix, routingMaxCategories)
	}
	for _, cat := range sortedKeys(p.Categories) {
		if !routingCategoryPattern.MatchString(cat) {
			return fmt.Errorf("%scategories key %q must match %s", prefix, cat, routingCategoryPattern.String())
		}
		if _, ok := aliases[p.Categories[cat]]; !ok {
			return fmt.Errorf("%scategories[%s] references unknown model alias %q", prefix, cat, p.Categories[cat])
		}
	}
	return nil
}

func (s *RoutingSystemOneConfig) validate(selected bool) error {
	if s == nil {
		return nil
	}
	if s.TimeoutMs < 0 || s.TimeoutMs > RoutingSystemOneMaxTimeoutMs {
		return fmt.Errorf("systemone.timeout_ms must be between 0 and %d", RoutingSystemOneMaxTimeoutMs)
	}
	if strings.TrimSpace(s.BaseURL) != "" {
		if err := ValidateDecisionModelURL(s.BaseURL); err != nil {
			return fmt.Errorf("systemone.base_url: %w", err)
		}
	}
	if s.APIKeyEnv != "" && !routingEnvNamePattern.MatchString(s.APIKeyEnv) {
		return fmt.Errorf("systemone.api_key_env %q is not a valid environment variable name", s.APIKeyEnv)
	}
	if c := strings.TrimSpace(s.Credential); c != "" && !ValidEnterpriseCredentialName(c) {
		return fmt.Errorf("systemone.credential %q is not a valid credential name", s.Credential)
	}
	if selected && !s.EffectiveUseDecisionModel() && (strings.TrimSpace(s.BaseURL) == "" || strings.TrimSpace(s.Model) == "") {
		return fmt.Errorf("classifier systemone with use_decision_model false needs systemone.base_url and systemone.model")
	}
	return nil
}

func (r RoutingRouteOnlyConfig) validate() error {
	seen := map[string]bool{}
	for i, c := range r.Connectors {
		if !slices.Contains(RouteOnlyCapableConnectors, c) {
			return fmt.Errorf("route_only.connectors[%d] %q has no route-only support (supported: %s)", i, c, strings.Join(RouteOnlyCapableConnectors, ", "))
		}
		if seen[c] {
			return fmt.Errorf("route_only.connectors[%d] %q is duplicated", i, c)
		}
		seen[c] = true
	}
	if r.Connectors != nil && len(r.Connectors) == 0 {
		return fmt.Errorf("route_only.connectors must not be empty (leave the key out for none)")
	}
	for _, c := range sortedKeys(r.Upstreams) {
		u := r.Upstreams[c]
		field := "route_only.upstreams." + c
		if !slices.Contains(RouteOnlyCapableConnectors, c) {
			return fmt.Errorf("%s: %q has no route-only support", field, c)
		}
		if strings.TrimSpace(u.BaseURL) == "" {
			return fmt.Errorf("%s.base_url must be set", field)
		}
		if err := validateRoutingURL(field+".base_url", u.BaseURL); err != nil {
			return err
		}
		if u.API != "" && !slices.Contains(RoutingAPIs, u.API) {
			return fmt.Errorf("%s.api %q must be one of %s", field, u.API, strings.Join(RoutingAPIs, ", "))
		}
		if err := u.Bedrock.validate(field + ".bedrock"); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
