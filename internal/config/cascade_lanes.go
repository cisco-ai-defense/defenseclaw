// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// CascadeConfig is guardrail.cascade (S7 cascade configuration, plans S7/CASCADE-CONFIG.md).
// Only the per-lane live/shadow switches are here so far; the rest of the
// block (unknown tier, judge role, confirm fallback, policy, admin locks) is
// added by the cascade-config lane in the same struct.
type CascadeConfig struct {
	// Lanes holds one live/shadow switch per registered lane (off | shadow | on).
	// A lane that ships shadow-only accepts off | shadow; "on" is refused.
	Lanes CascadeLanes `mapstructure:"lanes" yaml:"lanes,omitempty"`
}

// CascadeLanes are the per-lane switches. Empty means the lane's shipped
// default (shadow for both lanes), so a config that never names the block
// loads with the shipped behavior.
type CascadeLanes struct {
	// Effects is the effect-model rule lane: off (today's ActionFacts rules
	// only) or shadow (compute and record effect verdicts beside today's, never
	// changing the answer). guardrail.effects_rules_tier picks how far it may
	// block once the lane ships live.
	Effects string `mapstructure:"effects" yaml:"effects,omitempty"`
	// SecretFlow is Secret flow tracking (guardrail.secret_flow holds its other
	// settings). It runs only while Effects is not off: it reads the same effect
	// model.
	SecretFlow string `mapstructure:"secret_flow" yaml:"secret_flow,omitempty"`
}

// cascadeLaneSpec describes one lane: its shipped default, the values it
// accepts in this release and the open gaps that keep "on" out.
type cascadeLaneSpec struct {
	name    string
	def     string
	allowed []string
	gaps    string
	get     func(CascadeLanes) string
}

var cascadeLaneRegistry []cascadeLaneSpec

// registerCascadeLane adds a lane to the registry. Validate, the shipped
// defaults and the schema test read the registry, so a new lane is one call.
func registerCascadeLane(name, def string, allowed []string, gaps string, get func(CascadeLanes) string) {
	cascadeLaneRegistry = append(cascadeLaneRegistry, cascadeLaneSpec{name: name, def: def, allowed: allowed, gaps: gaps, get: get})
}

func init() {
	// Both lanes ship shadow-only in 1.0.10 (the effect model under them still has
	// P1s open, GAP-0191..0193, GAP-0208, GAP-0216, GAP-0217), so "on" is refused.
	const effectGaps = "GAP-0191, GAP-0192, GAP-0193, GAP-0208, GAP-0216, GAP-0217"
	registerCascadeLane("effects", "shadow", []string{"off", "shadow"}, effectGaps, func(l CascadeLanes) string { return l.Effects })
	registerCascadeLane("secret_flow", "shadow", []string{"off", "shadow"}, effectGaps, func(l CascadeLanes) string { return l.SecretFlow })
}

// CascadeLaneNames returns the registered lane names, for the schema test and docs.
func CascadeLaneNames() []string {
	out := make([]string, 0, len(cascadeLaneRegistry))
	for _, l := range cascadeLaneRegistry {
		out = append(out, l.name)
	}
	return out
}

// CascadeLaneAllowed returns the values a lane accepts in this release.
func CascadeLaneAllowed(name string) []string {
	for _, l := range cascadeLaneRegistry {
		if l.name == name {
			return append([]string(nil), l.allowed...)
		}
	}
	return nil
}

func (l CascadeLanes) value(name string) string {
	for _, s := range cascadeLaneRegistry {
		if s.name == name {
			if v := s.get(l); v != "" {
				return v
			}
			return s.def
		}
	}
	return ""
}

// EffectsMode is the effective effects lane value (the shipped default when unset).
func (l CascadeLanes) EffectsMode() string { return l.value("effects") }

// SecretFlowMode is the effective secret-flow lane value (the shipped default when unset).
func (l CascadeLanes) SecretFlowMode() string { return l.value("secret_flow") }

// Validate checks every registered lane: a known value, and one this release
// accepts for that lane.
func (c CascadeConfig) Validate() error {
	for _, s := range cascadeLaneRegistry {
		v := s.get(c.Lanes)
		if v == "" {
			continue
		}
		switch v {
		case "off", "shadow", "on":
		default:
			return fmt.Errorf("guardrail.cascade.lanes.%s %q must be one of off, shadow, on", s.name, v)
		}
		ok := false
		for _, a := range s.allowed {
			if a == v {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("guardrail.cascade.lanes.%s %q is not available in 1.0.10 (%s); allowed: %s", s.name, v, s.gaps, strings.Join(s.allowed, ", "))
		}
	}
	return nil
}
