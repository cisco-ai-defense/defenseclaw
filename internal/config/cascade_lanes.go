// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

// The two lanes guardrail.cascade.lanes carried before the rest of the
// cascade block (s7/rules-flow): the effect-model rule lane and Secret flow
// tracking. They are registered lanes of the cascade (RegisterCascadeLane),
// so validation, explain, the locks and the profile meet treat them like
// every other lane. Both ship shadow-only in 1.0.10 (the effect model under
// them still has P1s open), and both are read at the top level only: the
// gateway runs them for the whole process, so a connector or profile scope
// may not set them (Global).

// CascadeLaneEffects and CascadeLaneSecretFlow are the lane names.
const (
	CascadeLaneEffects    = "effects"
	CascadeLaneSecretFlow = "secret_flow"
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
	if v, set := l[name]; set && v != "" {
		return cascadeOr(v, CascadeLaneOff)
	}
	return lane.Default
}

// EffectsMode is the effective effects lane value (the shipped default when unset).
func (l CascadeLaneValues) EffectsMode() string { return l.mode(CascadeLaneEffects) }

// SecretFlowMode is the effective secret-flow lane value (the shipped default when unset).
func (l CascadeLaneValues) SecretFlowMode() string { return l.mode(CascadeLaneSecretFlow) }

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
