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
// every other lane. The effects lane ships on (DET111, 1.0.11): its verdicts
// join today's as raises only. Secret flow stays shadow-only (its gaps are
// open). Both are read at the top level only: the
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
	// The open gaps that keep secret flow shadow-only.
	const secretFlowGaps = "GAP-0191, GAP-0192, GAP-0193, GAP-0208"
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneEffects, Default: CascadeLaneOn, Global: true,
		Description: "effect-model rules: on (default: effect verdicts join today's as raises only, never lowering one; an unknown effect reaches the unknown tier only with a reach reason), shadow (record them, never change the answer) or off (today's ActionFacts rules only); guardrail.effects_rules_tier picks how far a known effect may block",
	})
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneSecretFlow, Default: CascadeLaneShadow, ShadowOnly: secretFlowGaps, Global: true,
		Description: "Secret flow tracking (guardrail.secret_flow holds its settings); runs only while the effects lane is not off",
	})
	// The non-shell lane ships live (review rounds 5 to 7, LIVE). It has no
	// third state: off is shadow.
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneNonShell, Default: CascadeLaneOn, Global: true,
		Description: "the MCP and app tool lane (internal/toolshape and the gateway's nonShellToolFindings and shellToolFindings): on (default) judges them; shadow and off compute nothing and add nothing, so the verdicts are those of a build without the lane",
	})
}

// The tool judge's own stages (rel-1-0-10:GAP-0636) are registered lanes as
// well, settable per connector and profile. They act only where
// guardrail.judge is on for the connector, which is opt-in and off by
// default, so with the judge off they change nothing. Each ships on: it is
// the judge as measured (BENCH-gemma4). shadow is accepted as for every lane
// and acts as off: these stages add or skip a judge question and have no
// verdict of their own to record.
const (
	// CascadeLaneJudgeReadSkip: with regex_judge, a call the rules did not
	// flag and the parser proves only reads is not sent to the judge.
	CascadeLaneJudgeReadSkip = "judge_read_skip"
	// CascadeLaneJudgeUnmodeledAlert: in the default pack a lone needs_review
	// finding on a call the parser does not model (MCP and other tools)
	// keeps its alert (GAP-0397); off makes it audit-only like a modeled call.
	CascadeLaneJudgeUnmodeledAlert = "judge_unmodeled_alert"
	// CascadeLaneJudgeToolResultContext: the tool-result judges (injection,
	// and PII for a listed tool) get the tool, its call, what the call did
	// and the user's request next to the output, in nonce sections.
	CascadeLaneJudgeToolResultContext = "judge_tool_result_context"
)

func init() {
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneJudgeReadSkip, Default: CascadeLaneOn,
		Description: "LLM judge (when on for the connector, regex_judge): do not ask about a call the rules did not flag and the parser proves only reads; off asks about every call the rules leave open",
	})
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneJudgeUnmodeledAlert, Default: CascadeLaneOn,
		Description: "LLM judge (when on for the connector): a lone needs_review finding on a call the parser does not model keeps its alert in the default pack; off records it without an alert",
	})
	RegisterCascadeLane(CascadeLane{
		Name: CascadeLaneJudgeToolResultContext, Default: CascadeLaneOn,
		Description: "LLM judge (when on for the connector): the tool-result judges (injection, and PII for a listed tool) see the tool, its call (arguments redacted), what the call did and the user's request next to the output; off judges the output alone",
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
	if v, set := l[name]; set && !lane.accepts(cascadeOr(v, "")) {
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
	// A block the source names without a value (`guardrail:`, `cascade: null`,
	// `lanes: ~`) decodes as the defaults, but the gateway's schema pass
	// refuses it: refuse it here too, with the key named.
	if v, present := plain["guardrail"]; present && v == nil {
		return fmt.Errorf("config: guardrail has no value; give it settings or remove the key")
	}
	guardrail, _ := plain["guardrail"].(map[string]any)
	if v, present := guardrail["cascade"]; present && v == nil {
		return fmt.Errorf("config: guardrail.cascade has no value; give it settings or remove the key")
	}
	cascade, _ := guardrail["cascade"].(map[string]any)
	if v, present := cascade["lanes"]; present && v == nil {
		return fmt.Errorf("config: guardrail.cascade.lanes has no value; name the lanes (one of %s) or remove the key", strings.Join(CascadeLaneNames(), ", "))
	}
	lanes, _ := cascade["lanes"].(map[string]any)
	for _, s := range CascadeLanes() {
		v, present := lanes[s.Name]
		if !present {
			continue
		}
		// The values the lane takes: off, shadow, on, or its own list (the
		// alignment lane: off, shadow, alert, block; GAP-0823).
		allowed := strings.Join(CascadeLaneAllowed(s.Name), ", ")
		if v == nil {
			return fmt.Errorf("config: guardrail.cascade.lanes.%s has no value; set it to one of %s or remove the key", s.Name, allowed)
		}
		str, ok := v.(string)
		switch {
		case ok && str == "":
			return fmt.Errorf("config: guardrail.cascade.lanes.%s is empty; set it to one of %s or remove the key", s.Name, allowed)
		case ok && slices.Contains(CascadeLaneAllowed(s.Name), str):
		case ok && str == CascadeLaneOn && s.ShadowOnly != "":
			return fmt.Errorf("config: guardrail.cascade.lanes.%s: on is not available in 1.0.10: the lane ships shadow-only (%s); allowed: %s", s.Name, s.ShadowOnly, allowed)
		default:
			return fmt.Errorf("config: guardrail.cascade.lanes.%s %v is not one of %s (exact values)", s.Name, v, allowed)
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
	if lane.Values != nil {
		return append([]string(nil), lane.Values...)
	}
	if lane.ShadowOnly != "" {
		return []string{CascadeLaneOff, CascadeLaneShadow}
	}
	return []string{CascadeLaneOff, CascadeLaneShadow, CascadeLaneOn}
}
