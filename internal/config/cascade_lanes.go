// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"slices"
	"strings"
)

// The two lanes guardrail.cascade.lanes carried before the rest of the
// cascade block (s7/rules-flow): the effect-model rule lane and Secret flow
// tracking. They are registered lanes of the cascade (RegisterCascadeLane),
// so validation, explain, the locks and the profile meet treat them like
// every other lane. Both ship shadow-only in 1.0.10 (the effect model under
// them still has P1s open), and both are read at the top level only: the
// gateway runs them for the whole process, so a connector or profile scope
// may not set them (Global).
//
// The MCP and app tool lane (s7/nonshell) is a registered lane too. It ships
// on and is Global as well: a connector or profile value is refused at load,
// never ignored, so a scoped off cannot leave the lane silently on (GAP-0472).

// CascadeLaneEffects and CascadeLaneSecretFlow are the lane names.
const (
	CascadeLaneEffects    = "effects"
	CascadeLaneSecretFlow = "secret_flow"
	CascadeLaneNonShell   = "nonshell"
)

func init() {
	const effectGaps = "GAP-0191, GAP-0192, GAP-0193, GAP-0208, GAP-0216, GAP-0217"
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneEffects, Default: CascadeLaneShadow, ShadowOnly: effectGaps, Global: true,
		Description: "effect-model rules: off (today's ActionFacts rules only) or shadow (record effect verdicts beside today's, never change the answer); guardrail.effects_rules_tier picks how far it may block once it ships live",
	})
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneSecretFlow, Default: CascadeLaneShadow, ShadowOnly: effectGaps, Global: true,
		Description: "Secret flow tracking (guardrail.secret_flow holds its settings); runs only while the effects lane is not off",
	})
	// The non-shell lane ships live (review rounds 5 to 7, LIVE). It has no
	// third state: off is shadow.
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneNonShell, Default: CascadeLaneOn, Global: true,
		Description: "the MCP and app tool lane (internal/toolshape and the gateway's nonShellToolFindings and shellToolFindings): on (default) judges them; shadow and off compute nothing and add nothing, so the verdicts are those of a build without the lane",
	})
}

// CascadeLaneValues is a scope's guardrail.cascade.lanes: lane name to off,
// shadow or on. A lane it does not name keeps its shipped default.
type CascadeLaneValues map[string]string

// mode is the value of lane name in l alone (the top level), its default
// when unset. The gateway reads the global lanes through it; a scoped
// decision reads EffectiveCascade.LaneMode.
func (l CascadeLaneValues) mode(name string) string {
	lane, ok := cascadeLane(name)
	if !ok {
		return ""
	}
	if v, set := l[name]; set && !cascadeLaneValue(cascadeOr(v, "")) {
		// A value Validate refuses as no lane value (an empty one included)
		// reads as shadow, so a config that skipped the loader can not turn a
		// lane on (or silently off) by a spelling.
		return CascadeLaneShadow
	}
	if v, set := l[name]; set && v != "" {
		return cascadeOr(v, CascadeLaneOff)
	}
	return lane.Default
}

// EffectsMode is the effective effects lane value (the shipped default when unset).
func (l CascadeLaneValues) EffectsMode() string { return l.mode(CascadeLaneEffects) }

// SecretFlowMode is the effective secret-flow lane value (the shipped default when unset).
func (l CascadeLaneValues) SecretFlowMode() string { return l.mode(CascadeLaneSecretFlow) }

// NonShellMode is the effective non-shell lane value: on when unset, else on,
// shadow or off. Only on is live (shadow and off add nothing).
func (l CascadeLaneValues) NonShellMode() string { return l.mode(CascadeLaneNonShell) }

// checkCascadeLanesSource refuses, with the key named, a lane the source
// names without a value: `lane:` or `lane: null` for any lane, and `lane: ""`.
// Decoding reads those as no value (the lane's shipped default), but the
// gateway's schema pass refuses them, so a loader that skips the schema pass
// (LoadFromFile) must refuse them too: one reading of a config for every
// consumer (GAP-0545). The same holds for a top-level value the schema refuses
// (not a string, not exactly a value the lane takes in this release): without
// this, LoadFromFile would replace the cascade with its fallback where the
// gateway refuses the file.
func checkCascadeLanesSource(plain map[string]any) error {
	guardrail, _ := plain["guardrail"].(map[string]any)
	cascade, _ := guardrail["cascade"].(map[string]any)
	lanes, _ := cascade["lanes"].(map[string]any)
	for _, s := range CascadeLanes() {
		v, present := lanes[s.Name]
		if !present {
			continue
		}
		if v == nil {
			return fmt.Errorf("config: guardrail.cascade.lanes.%s has no value; set it to one of off, shadow, on or remove the key", s.Name)
		}
		if str, ok := v.(string); ok && str == "" {
			return fmt.Errorf("config: guardrail.cascade.lanes.%s is empty; set it to one of off, shadow, on or remove the key", s.Name)
		}
		allowed := CascadeLaneAllowed(s.Name)
		str, ok := v.(string)
		switch {
		case !ok || !cascadeLaneValue(str):
			return fmt.Errorf("config: guardrail.cascade.lanes.%s %v is not one of %s (exact values)", s.Name, v, strings.Join(allowed, ", "))
		case !slices.Contains(allowed, str):
			return fmt.Errorf("config: guardrail.cascade.lanes.%s: on is not available in 1.0.10: the lane ships shadow-only (%s); allowed: %s", s.Name, s.ShadowOnly, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// SetLane sets lane name of the top-level cascade ("" unsets it). It copies
// the map before writing, so a configuration derived from c is unchanged.
func (c *CascadeConfig) SetLane(name, value string) {
	lanes := make(CascadeLaneValues, len(c.Lanes)+1)
	for k, v := range c.Lanes {
		lanes[k] = v
	}
	if value == "" {
		delete(lanes, name)
	} else {
		lanes[name] = value
	}
	if len(lanes) == 0 {
		lanes = nil
	}
	c.Lanes = lanes
}

// CascadeLaneNames returns the registered lane names, sorted, for the schema test and docs.
func CascadeLaneNames() []string {
	lanes := CascadeLanes()
	out := make([]string, len(lanes))
	for i, l := range lanes {
		out[i] = l.Name
	}
	return out
}

// CascadeLaneAllowed returns the values a lane accepts in this release.
func CascadeLaneAllowed(name string) []string {
	lane, ok := cascadeLane(name)
	if !ok {
		return nil
	}
	if lane.ShadowOnly != "" {
		return []string{CascadeLaneOff, CascadeLaneShadow}
	}
	return []string{CascadeLaneOff, CascadeLaneShadow, CascadeLaneOn}
}
