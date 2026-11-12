// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
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
		for key, set := range map[string]bool{
			"default_alias":       overlay.DefaultAlias != "",
			"categories":          overlay.Categories != nil,
			"allow_user_override": overlay.AllowUserOverride != nil,
		} {
			if set && locked(key) {
				return RoutingPolicyConfig{}, &RoutingPolicyContradictionError{Field: key, Message: fmt.Sprintf("routing: %s is locked by routing.admin", key)}
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

// UsesMinProductVersion1010Keys lists the routing keys cfg sets that only
// 1.0.10 and later read.
func (c *Config) UsesMinProductVersion1010Keys() []string {
	if c == nil {
		return nil
	}
	r := c.Routing
	var keys []string
	add := func(set bool, key string) {
		if set {
			keys = append(keys, key)
		}
	}
	add(r.Classifier != "", "routing.classifier")
	add(r.MinConfidence != 0, "routing.min_confidence")
	add(r.OnClassifierError != "", "routing.on_classifier_error")
	add(r.DefaultAlias != "", "routing.default_alias")
	add(r.Categories != nil, "routing.categories")
	add(r.AllowUserOverride, "routing.allow_user_override")
	add(r.Sensitive != nil, "routing.sensitive")
	add(r.SystemOne != nil, "routing.systemone")
	add(!r.RouteOnly.IsZero(), "routing.route_only")
	add(r.Admin != nil, "routing.admin")
	models := false
	for _, m := range r.Models {
		models = models || m.APIs != nil || m.Credential != "" || m.Bedrock != nil
	}
	add(models, "routing.models[].apis/credential/bedrock")
	conditions := false
	for _, d := range r.Decisions {
		for _, cond := range d.Conditions {
			conditions = conditions || !strings.EqualFold(strings.TrimSpace(cond.Type), RoutingConditionKeyword)
		}
	}
	add(conditions, "routing.decisions[].conditions[].type")
	for _, name := range sortedKeys(c.Guardrail.Profiles) {
		if c.Guardrail.Profiles[name].Routing != nil {
			keys = append(keys, "guardrail.profiles.*.routing")
			break
		}
	}
	return keys
}
