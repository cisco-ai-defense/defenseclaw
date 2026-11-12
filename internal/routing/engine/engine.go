// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Options are the gateway-side parts of an engine.
type Options struct {
	// Classifier serves classifier systemone or vllm_sr (the gateway owns
	// their HTTP clients). Unused for rules.
	Classifier Classifier
	// Admin is the S11 evaluator; nil narrows nothing.
	Admin AdminEvaluator
	// Managed is true on a standalone managed host (deny is managed-only).
	Managed bool
	// CredentialOK reports whether the gateway can authenticate a call to
	// b for this request (inbound passthrough or a gateway-held key).
	CredentialOK func(b Backend, r Request) bool
	// Sticky is the conversation cache shared across generations (nil = a
	// private one). It is used only with classifier systemone.
	Sticky *StickyCache
}

// Engine is built once per config generation and is safe for concurrent
// use. A nil *Engine decides passthrough.
type Engine struct {
	backends      map[string]Backend
	providers     map[string]string
	matcher       *signalMatcher
	rules         *rulesClassifier
	classifier    Classifier
	onError       string
	minConfidence float64
	sensitive     *config.RoutingSensitiveConfig
	unconditional string
	floor         config.RoutingPolicyConfig
	overlays      map[string]*config.RoutingPolicyConfig
	locked        func(string) bool
	admin         AdminEvaluator
	managed       bool
	credentialOK  func(Backend, Request) bool
	sticky        *StickyCache
	// capabilityFilter is off for vllm_sr, whose 1.0.9 configs used
	// free-form capabilities.
	capabilityFilter bool
}

// New builds the engine of a validated config. It returns nil when routing
// is disabled.
func New(cfg *config.Config, opts Options) (*Engine, error) {
	if cfg == nil || !cfg.Routing.Enabled {
		return nil, nil
	}
	r := cfg.Routing
	floor, err := cfg.RoutingFloor()
	if err != nil {
		return nil, err
	}
	e := &Engine{
		backends:      map[string]Backend{},
		providers:     r.RoutingProviders(),
		matcher:       newSignalMatcher(r.Signals),
		rules:         newRulesClassifier(r),
		onError:       r.EffectiveOnClassifierError(),
		minConfidence: r.MinConfidence,
		sensitive:     r.Sensitive,
		unconditional: unconditionalDefault(r),
		floor:         floor,
		overlays:      map[string]*config.RoutingPolicyConfig{},
		locked:        r.Admin.IsLocked,
		admin:         opts.Admin,
		managed:       opts.Managed,
		credentialOK:  opts.CredentialOK,
	}
	if r.EffectiveClassifier() == config.RoutingClassifierSystemOne {
		e.sticky = opts.Sticky
		if e.sticky == nil {
			e.sticky = NewStickyCache()
		}
	}
	e.capabilityFilter = r.EffectiveClassifier() != config.RoutingClassifierVLLMSR
	for _, m := range r.Models {
		e.backends[m.Name] = Backend{
			Alias: m.Name, Provider: strings.TrimSpace(m.Provider), Model: m.Model,
			BaseURL: strings.TrimRight(strings.TrimSpace(m.BaseURL), "/"), APIs: m.EffectiveAPIs(),
			APIKeyEnv: m.APIKeyEnv, Credential: m.Credential, Capabilities: m.Capabilities, Bedrock: m.Bedrock,
		}
	}
	for name, p := range cfg.Guardrail.Profiles {
		if p.Routing != nil {
			e.overlays[name] = p.Routing
		}
	}
	switch r.EffectiveClassifier() {
	case config.RoutingClassifierRules:
		e.classifier = e.rules
	default:
		e.classifier = opts.Classifier
	}
	return e, nil
}

// Backend returns the catalog entry of alias.
func (e *Engine) Backend(alias string) (Backend, bool) {
	if e == nil {
		return Backend{}, false
	}
	b, ok := e.backends[alias]
	return b, ok
}

func toPolicy(p config.RoutingPolicyConfig) Policy {
	return Policy{AllowedAliases: p.AllowedAliases, DeniedProviders: p.DeniedProviders, DefaultAlias: p.DefaultAlias, Categories: p.Categories, AllowUserOverride: p.UserOverrideAllowed()}.clone()
}

func fromPolicy(p Policy) config.RoutingPolicyConfig {
	o := p.AllowUserOverride
	return config.RoutingPolicyConfig{AllowedAliases: p.AllowedAliases, DeniedProviders: p.DeniedProviders, DefaultAlias: p.DefaultAlias, Categories: p.Categories, AllowUserOverride: &o}
}

// policyFor returns the floor, tightened by every profile overlay of a
// verified caller. A contradiction between profiles leaves no alias
// allowed (routing fails closed to the original request).
func (e *Engine) policyFor(req Request) Policy {
	cur := e.floor
	if !req.Caller.Verified {
		return toPolicy(cur)
	}
	for _, name := range req.Profiles {
		overlay, ok := e.overlays[name]
		if !ok {
			continue
		}
		next, err := config.TightenRoutingPolicy(cur, overlay, e.providers, e.locked)
		if err != nil {
			cur.AllowedAliases = []string{}
			return toPolicy(cur)
		}
		cur = next
	}
	return toPolicy(cur)
}

func (e *Engine) aliasAllowed(p Policy, alias string) bool {
	if p.AllowedAliases != nil && !slices.Contains(p.AllowedAliases, alias) {
		return false
	}
	return fromPolicy(p).AliasAllowed(alias, e.providers)
}

func (e *Engine) providerDenied(p Policy, provider string) bool {
	for _, d := range p.DeniedProviders {
		if provider != "" && strings.EqualFold(strings.TrimSpace(d), provider) {
			return true
		}
	}
	return false
}

var capabilityWords = []string{"tools", "vision", "long_context"}

// eligible reports whether alias can serve req and, when not, which filter
// removed it.
func (e *Engine) eligible(p Policy, alias string, req Request) (Backend, string) {
	b, ok := e.backends[alias]
	if !ok {
		return Backend{}, "unknown_alias"
	}
	if !e.aliasAllowed(p, alias) {
		return Backend{}, "policy"
	}
	if req.APIFamily != config.RoutingAPIChat && !slices.Contains(b.APIs, req.APIFamily) {
		return Backend{}, "api"
	}
	if e.capabilityFilter && slices.ContainsFunc(b.Capabilities, func(c string) bool { return slices.Contains(capabilityWords, c) }) {
		need := map[string]bool{"tools": req.HasTools, "vision": req.HasImages, "long_context": req.LongContext}
		for c, needed := range need {
			if needed && !slices.Contains(b.Capabilities, c) {
				return Backend{}, "capability"
			}
		}
	}
	if e.credentialOK != nil && !e.credentialOK(b, req) {
		return Backend{}, "credential"
	}
	return b, ""
}
