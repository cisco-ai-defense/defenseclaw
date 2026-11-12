// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RoutingPolicyContradictionError is returned when a tighter layer leaves
// no usable route (for example an allowed_aliases intersection that is
// empty) or names a value the floor forbids.
type RoutingPolicyContradictionError struct {
	Field   string
	Message string
}

func (e *RoutingPolicyContradictionError) Error() string { return e.Message }

// TightenRoutingPolicy combines a routing policy floor with a tighter
// overlay, in the style of TightenOpenShellAdmin: allowed_aliases
// intersect, denied_providers union, allow_user_override false wins, and
// default_alias and categories come from the overlay when the combined
// policy still allows them. A value the floor forbids is a contradiction,
// not a silent drop. providers maps each routing.models alias to its
// provider. locked reports keys the overlay may not set (nil = none). A
// nil overlay returns a copy of base. Neither input is modified.
func TightenRoutingPolicy(base RoutingPolicyConfig, overlay *RoutingPolicyConfig, providers map[string]string, locked func(string) bool) (RoutingPolicyConfig, error) {
	out := RoutingPolicyConfig{
		AllowedAliases:    slices.Clone(base.AllowedAliases),
		DeniedProviders:   slices.Clone(base.DeniedProviders),
		DefaultAlias:      base.DefaultAlias,
		Categories:        maps.Clone(base.Categories),
		AllowUserOverride: cloneBoolPtr(base.AllowUserOverride),
	}
	if overlay == nil {
		return out, nil
	}
	if locked != nil {
		for _, k := range []struct {
			key string
			set bool
		}{
			{"default_alias", overlay.DefaultAlias != ""},
			{"categories", overlay.Categories != nil},
			{"allow_user_override", overlay.AllowUserOverride != nil},
		} {
			if k.set && locked(k.key) {
				return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: k.key, Message: fmt.Sprintf("routing: %s is locked by routing.admin", k.key)}
			}
		}
	}
	if overlay.AllowedAliases != nil {
		if out.AllowedAliases == nil {
			out.AllowedAliases = slices.Clone(overlay.AllowedAliases)
		} else {
			var kept []string
			for _, a := range out.AllowedAliases {
				if slices.Contains(overlay.AllowedAliases, a) {
					kept = append(kept, a)
				}
			}
			if len(kept) == 0 {
				return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: "allowed_aliases", Message: fmt.Sprintf(
					"routing: allowed_aliases [%s] leaves no model (the floor allows [%s])",
					strings.Join(overlay.AllowedAliases, ", "), strings.Join(out.AllowedAliases, ", "))}
			}
			out.AllowedAliases = kept
		}
	}
	out.DeniedProviders = unionStrings(out.DeniedProviders, overlay.DeniedProviders, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) })
	out.AllowUserOverride = falseWins(out.AllowUserOverride, overlay.AllowUserOverride)
	if len(out.AllowedAliases) > 0 && !slices.ContainsFunc(out.AllowedAliases, func(a string) bool { return out.AliasAllowed(a, providers) }) {
		return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: "denied_providers", Message: "routing: denied_providers removes every allowed model"}
	}
	if d := overlay.DefaultAlias; d != "" {
		if !out.AliasAllowed(d, providers) {
			return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: "default_alias", Message: fmt.Sprintf("routing: default_alias %q is not allowed by the floor", d)}
		}
		out.DefaultAlias = d
	}
	if out.DefaultAlias != "" && !out.AliasAllowed(out.DefaultAlias, providers) {
		// The floor default is no longer allowed after narrowing; the
		// overlay did not name a replacement, so there is no default.
		out.DefaultAlias = ""
	}
	if overlay.Categories != nil {
		if out.Categories == nil {
			out.Categories = map[string]string{}
		}
		for _, cat := range sortedKeys(overlay.Categories) {
			alias := overlay.Categories[cat]
			if !out.AliasAllowed(alias, providers) {
				return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: "categories", Message: fmt.Sprintf("routing: categories[%s] names %q, which the floor does not allow", cat, alias)}
			}
			out.Categories[cat] = alias
		}
	}
	for cat, alias := range out.Categories {
		if !out.AliasAllowed(alias, providers) {
			delete(out.Categories, cat)
		}
	}
	return out, nil
}

// AliasAllowed reports whether alias is in the allowed set (nil = all) and
// its provider is not denied.
func (p RoutingPolicyConfig) AliasAllowed(alias string, providers map[string]string) bool {
	if alias == "" {
		return false
	}
	if p.AllowedAliases != nil && !slices.Contains(p.AllowedAliases, alias) {
		return false
	}
	provider, known := providers[alias]
	if !known {
		return false
	}
	for _, d := range p.DeniedProviders {
		if strings.EqualFold(strings.TrimSpace(d), provider) {
			return false
		}
	}
	return true
}

// UserOverrideAllowed reports the combined allow_user_override (unset =
// false).
func (p RoutingPolicyConfig) UserOverrideAllowed() bool {
	return p.AllowUserOverride != nil && *p.AllowUserOverride
}

func cloneBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// RoutingProviders maps every routing.models alias to its provider.
func (r *RoutingConfig) RoutingProviders() map[string]string {
	out := make(map[string]string, len(r.Models))
	for _, m := range r.Models {
		out[m.Name] = strings.TrimSpace(m.Provider)
	}
	return out
}

// RoutingFloor returns routing.* tightened by routing.admin: the policy
// every caller gets before a profile overlay.
func (c *Config) RoutingFloor() (RoutingPolicyConfig, error) {
	r := &c.Routing
	if r.Admin == nil {
		return TightenRoutingPolicy(r.GlobalPolicy(), nil, nil, nil)
	}
	admin := r.Admin.Policy()
	return TightenRoutingPolicy(r.GlobalPolicy(), &admin, r.RoutingProviders(), nil)
}

// RoutingPolicyForProfile returns the floor tightened by the routing
// overlay of guardrail profile name ("" or a profile without one = floor).
func (c *Config) RoutingPolicyForProfile(name string) (RoutingPolicyConfig, error) {
	floor, err := c.RoutingFloor()
	if err != nil {
		return RoutingPolicyConfig{}, err
	}
	p, ok := c.Guardrail.Profiles[name]
	if name == "" || !ok || p.Routing == nil {
		return floor, nil
	}
	return TightenRoutingPolicy(floor, p.Routing, c.Routing.RoutingProviders(), c.Routing.Admin.IsLocked)
}

// validateRoutingProfiles checks routing.admin against routing.* and every
// guardrail profile routing overlay: its own values, then the combined
// policy (contradictions and locked keys are load errors).
func (c *Config) validateRoutingProfiles() error {
	r := c.Routing
	if r.EffectiveClassifier() == RoutingClassifierSystemOne && r.SystemOne.EffectiveUseDecisionModel() &&
		(strings.TrimSpace(c.DecisionModel.BaseURL) == "" || strings.TrimSpace(c.DecisionModel.Model) == "") {
		return fmt.Errorf("config: routing.classifier systemone reuses decision_model, which needs base_url and model (or set routing.systemone.use_decision_model: false with its own base_url and model)")
	}
	if _, err := c.RoutingFloor(); err != nil {
		return fmt.Errorf("config: routing.admin: %w", err)
	}
	providers := c.Routing.RoutingProviders()
	for _, name := range sortedKeys(c.Guardrail.Profiles) {
		p := c.Guardrail.Profiles[name]
		if p.Routing == nil {
			continue
		}
		prefix := "guardrail.profiles[" + strconv.Quote(name) + "].routing."
		if err := validateRoutingPolicy(prefix, *p.Routing, providers); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if _, err := c.RoutingPolicyForProfile(name); err != nil {
			return fmt.Errorf("config: guardrail profile %q: %w", name, err)
		}
	}
	return nil
}

// validateSecureClientRouting refuses the 1.0.10 routing policy and
// route-only keys under the Secure Client integration, whose behavior stays
// byte-identical. Profiles are refused there already.
func (c *Config) validateSecureClientRouting() error {
	if !c.SecureClientIntegration() {
		return nil
	}
	if c.Routing.Admin != nil {
		return fmt.Errorf("config: routing.admin is not supported with the Secure Client integration")
	}
	if !c.Routing.RouteOnly.IsZero() {
		return fmt.Errorf("config: routing.route_only is not supported with the Secure Client integration")
	}
	return nil
}

// RoutingMinVersionKeysInRaw lists the 1.0.10 routing keys a config.yaml
// writes, read from the YAML itself so an explicit zero value (for example
// allow_user_override: false or a profile routing: {}) counts: a 1.0.9
// device refuses the key whatever its value.
func RoutingMinVersionKeysInRaw(raw []byte) []string {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil
	}
	var keys []string
	if routing, ok := doc["routing"].(map[string]any); ok {
		for _, k := range []string{"classifier", "min_confidence", "on_classifier_error", "default_alias", "categories", "allow_user_override", "sensitive", "systemone", "route_only", "admin"} {
			if _, set := routing[k]; set {
				keys = append(keys, "routing."+k)
			}
		}
		if models, ok := routing["models"].([]any); ok {
			for _, m := range models {
				entry, _ := m.(map[string]any)
				_, apis := entry["apis"]
				_, cred := entry["credential"]
				_, bedrock := entry["bedrock"]
				if apis || cred || bedrock {
					keys = append(keys, "routing.models[].apis/credential/bedrock")
					break
				}
			}
		}
		if decisions, ok := routing["decisions"].([]any); ok {
		decisionLoop:
			for _, d := range decisions {
				entry, _ := d.(map[string]any)
				conds, _ := entry["conditions"].([]any)
				for _, c := range conds {
					cond, _ := c.(map[string]any)
					if t, _ := cond["type"].(string); t != "" && !strings.EqualFold(strings.TrimSpace(t), RoutingConditionKeyword) {
						keys = append(keys, "routing.decisions[].conditions[].type")
						break decisionLoop
					}
				}
			}
		}
	}
	if guardrail, ok := doc["guardrail"].(map[string]any); ok {
		if profiles, ok := guardrail["profiles"].(map[string]any); ok {
			for _, p := range profiles {
				entry, _ := p.(map[string]any)
				if _, set := entry["routing"]; set {
					keys = append(keys, "guardrail.profiles.*.routing")
					break
				}
			}
		}
	}
	return keys
}
