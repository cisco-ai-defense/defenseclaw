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
// default, so a config that never names the block loads with the shipped
// behavior. Every lane takes the same values (off, shadow, on), read the same
// way: trimmed and in any case (normalizeCascadeLaneValue).
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
	// NonShell is the MCP and app tool lane (internal/toolshape and the
	// gateway's nonShellToolFindings and shellToolFindings). It ships on. Only
	// on is live; shadow and off are the same for this lane: it computes
	// nothing and adds nothing, so the verdicts are those of a build without
	// it. A pointer, so a value that is set (an empty one included) is told
	// from no value: no value is on, an empty value is refused at load.
	NonShell *string `mapstructure:"nonshell" yaml:"nonshell,omitempty"`
}

// Lane values under guardrail.cascade.lanes.
const (
	CascadeLaneOff    = "off"
	CascadeLaneShadow = "shadow"
	CascadeLaneOn     = "on"
)

// cascadeLaneSpec describes one lane: its shipped default, the values it
// accepts in this release and the open gaps that keep "on" out. get returns
// the lane's value as written and whether it is set.
type cascadeLaneSpec struct {
	name    string
	def     string
	allowed []string
	gaps    string
	get     func(CascadeLanes) (string, bool)
}

var cascadeLaneRegistry []cascadeLaneSpec

// registerCascadeLane adds a lane to the registry. Validate, the shipped
// defaults and the schema test read the registry, so a new lane is one call.
func registerCascadeLane(name, def string, allowed []string, gaps string, get func(CascadeLanes) (string, bool)) {
	cascadeLaneRegistry = append(cascadeLaneRegistry, cascadeLaneSpec{name: name, def: def, allowed: allowed, gaps: gaps, get: get})
}

// setIfNotEmpty is get for a string lane: an empty string is no value.
func setIfNotEmpty(v string) (string, bool) { return v, v != "" }

func init() {
	// Both lanes ship shadow-only in 1.0.10 (the effect model under them still has
	// P1s open, GAP-0191..0193, GAP-0208, GAP-0216, GAP-0217), so "on" is refused.
	const effectGaps = "GAP-0191, GAP-0192, GAP-0193, GAP-0208, GAP-0216, GAP-0217"
	shadowOnly := []string{CascadeLaneOff, CascadeLaneShadow}
	registerCascadeLane("effects", CascadeLaneShadow, shadowOnly, effectGaps, func(l CascadeLanes) (string, bool) { return setIfNotEmpty(l.Effects) })
	registerCascadeLane("secret_flow", CascadeLaneShadow, shadowOnly, effectGaps, func(l CascadeLanes) (string, bool) { return setIfNotEmpty(l.SecretFlow) })
	// The non-shell lane ships live (review rounds 5 to 7, LIVE). It has no
	// third state: off is shadow.
	registerCascadeLane("nonshell", CascadeLaneOn, []string{CascadeLaneOff, CascadeLaneShadow, CascadeLaneOn}, "", func(l CascadeLanes) (string, bool) {
		if l.NonShell == nil {
			return "", false
		}
		return *l.NonShell, true
	})
}

// normalizeCascadeLaneValue is a lane value as the loader and the gateway read
// it: trimmed and lower-cased.
func normalizeCascadeLaneValue(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func cascadeLaneValue(v string) bool {
	return v == CascadeLaneOff || v == CascadeLaneShadow || v == CascadeLaneOn
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

// value is the effective value of a lane: its shipped default when unset, else
// the normalized value. A value Validate refuses as no lane value reads as
// shadow, so a config that skipped the loader can not turn a lane on (or
// silently off) by a spelling.
func (l CascadeLanes) value(name string) string {
	for _, s := range cascadeLaneRegistry {
		if s.name == name {
			v, set := s.get(l)
			if !set {
				return s.def
			}
			if n := normalizeCascadeLaneValue(v); cascadeLaneValue(n) {
				return n
			}
			return CascadeLaneShadow
		}
	}
	return ""
}

// EffectsMode is the effective effects lane value (the shipped default when unset).
func (l CascadeLanes) EffectsMode() string { return l.value("effects") }

// SecretFlowMode is the effective secret-flow lane value (the shipped default when unset).
func (l CascadeLanes) SecretFlowMode() string { return l.value("secret_flow") }

// NonShellMode is the effective non-shell lane value: on when unset, else on,
// shadow or off. Only on is live (shadow and off add nothing).
func (l CascadeLanes) NonShellMode() string { return l.value("nonshell") }

// Validate checks every registered lane that is set: a lane value (off,
// shadow or on, trimmed, any case), and one this release accepts for that
// lane. Any other value, an empty one included, is refused with the key named:
// a lane is never silently on or off.
func (c CascadeConfig) Validate() error {
	for _, s := range cascadeLaneRegistry {
		raw, set := s.get(c.Lanes)
		if !set {
			continue
		}
		v := normalizeCascadeLaneValue(raw)
		if !cascadeLaneValue(v) {
			return fmt.Errorf("guardrail.cascade.lanes.%s %q must be one of off, shadow, on", s.name, raw)
		}
		ok := false
		for _, a := range s.allowed {
			if a == v {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("guardrail.cascade.lanes.%s %q is not available in 1.0.10 (%s); allowed: %s", s.name, raw, s.gaps, strings.Join(s.allowed, ", "))
		}
	}
	return nil
}
