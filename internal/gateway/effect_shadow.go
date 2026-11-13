// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// The effect-model rule lane (S7). It runs the pure effect extractor
// (internal/effects) and the protected-set projector (internal/effectrules)
// beside today's ActionFacts rules and answers in three tiers:
//
//   - a known effect on a protected target (or a known attack tool) takes the
//     severity path today's protected-file rules take;
//   - an unknown effect that could touch a protected set takes the unknown
//     tier: alert in OSS default and permissive, block in strict and in every
//     managed install (there is no ask yet; S8 owns the confirm path and maps
//     the effect_unknown disposition to it);
//   - otherwise clean.
//
// guardrail.effects_rules decides the lane: off (skip entirely, no cost),
// shadow (compute and measure beside today's, never change the answer) or on
// (the effect verdict participates). The lane ships shadow; the lead flips it
// to on once the corpus numbers hold.

type effectRulesMode string

const (
	effectRulesOff    effectRulesMode = "off"
	effectRulesShadow effectRulesMode = "shadow"
	effectRulesOn     effectRulesMode = "on"
)

// effectResolverOverride, when set, replaces the file-system link resolver in
// computeEffectShadow. It is nil in production (the hookpaths reader is used)
// and set by the s7bench harness to a lexical resolver, because the harness
// has no real user home to follow links through.
var effectResolverOverride func(string) (string, bool)

type effectTier string

const (
	effectTierClean   effectTier = "clean"
	effectTierKnown   effectTier = "known"
	effectTierUnknown effectTier = "unknown"
)

// EffectShadowResult is the effect lane's answer for one call. It is private
// in-process measurement material: value-free except for the protected-set
// names and the deciding effect's program and kind.
type EffectShadowResult struct {
	Mode    string   `json:"mode"`
	Tier    string   `json:"tier"`
	Action  string   `json:"action"`
	Sets    []string `json:"sets,omitempty"`
	Program string   `json:"program,omitempty"`
	Kind    string   `json:"kind,omitempty"`
}

// effectsRulesModeFor reads the live generation's config. An absent generation
// (tests, early boot) is off, so the lane never runs unasked.
func effectsRulesModeFor() effectRulesMode {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return effectRulesOff
	}
	switch effectRulesMode(g.Config.Guardrail.EffectsRules) {
	case effectRulesShadow:
		return effectRulesShadow
	case effectRulesOn:
		return effectRulesOn
	default:
		return effectRulesOff
	}
}

// mutatingEffectKind reports a kind that changes a target: a protected-file
// mutation takes the severity path, a read of a protected target does not.
func mutatingEffectKind(kind string) bool {
	switch effects.Kind(kind) {
	case effects.KindWrite, effects.KindAppend, effects.KindDelete,
		effects.KindLink, effects.KindPermissionChange:
		return true
	default:
		return false
	}
}

// effectCall builds the pure-extractor call and options from a trusted action
// input. ok is false when there is nothing executable to analyze.
func effectCall(connector string, in actionfacts.Input) (effects.Call, effects.Options, bool) {
	flavor := effects.FlavorPOSIX
	dialect := effects.DialectNone
	switch in.DialectHint {
	case actionfacts.DialectPowerShell:
		flavor, dialect = effects.FlavorWindows, effects.DialectPowerShell
	case actionfacts.DialectCMD:
		flavor, dialect = effects.FlavorWindows, effects.DialectCMD
	case actionfacts.DialectPOSIX:
		dialect = effects.DialectPOSIX
	}
	opts := effects.Options{Flavor: flavor, Dialect: dialect, Home: in.ActiveHome, CWD: in.CWD}

	switch {
	case in.Command != "":
		return effects.Call{Surface: effects.SurfaceShell, Tool: in.Tool, Command: in.Command}, opts, true
	case len(in.Argv) > 0:
		return effects.Call{Surface: effects.SurfaceArgv, Tool: in.Tool, Argv: in.Argv}, opts, true
	case len(in.Args) > 0:
		return effects.Normalize(connector, in.Tool, in.Args), opts, true
	default:
		return effects.Call{}, opts, false
	}
}

// computeEffectShadow runs the effect lane for one request and returns its
// verdict. It never mutates the request or today's findings. The protected-set
// grade follows links through the hook's own reader (read-only).
func computeEffectShadow(request trustedActionRequest, mode effectRulesMode) EffectShadowResult {
	res := EffectShadowResult{Mode: string(mode), Tier: string(effectTierClean), Action: guardrailActionAllow}
	call, opts, ok := effectCall(request.Connector, request.Input)
	if !ok {
		return res
	}
	result := effects.Extract(call, opts)
	facts := effectrules.Project(result, effectrules.Env{
		Home:    request.Input.ActiveHome,
		Flavor:  opts.Flavor,
		Resolve: effectResolverOverride,
	})
	tier, sets, program, kind := classifyEffectFacts(facts)
	res.Tier, res.Sets, res.Program, res.Kind = string(tier), sets, program, kind
	res.Action = effectTierAction(tier, kind, sets, request.StrictPolicy || request.ManagedInstall)
	return res
}

// classifyEffectFacts folds the projected effects into one tier and names the
// deciding effect. Known wins over unknown; the first deciding effect in call
// order is reported.
func classifyEffectFacts(facts []*semanticpb.EffectFact) (effectTier, []string, string, string) {
	var unknownSets []string
	var unknownProgram, unknownKind string
	foundUnknown := false
	for _, f := range facts {
		t := f.GetTarget()
		if t.GetType() != "path" {
			continue
		}
		known, maybe := protectedSetsByState(t)
		fullyKnown := f.GetTargetState() == "known" && f.GetRoleState() == "known" && f.GetKind() != string(effects.KindOpaque)
		if fullyKnown && len(known) > 0 {
			return effectTierKnown, known, f.GetOrigin().GetProgram(), f.GetKind()
		}
		if !fullyKnown && (len(known) > 0 || len(maybe) > 0) && !foundUnknown {
			foundUnknown = true
			unknownSets = appendUnique(known, maybe)
			unknownProgram, unknownKind = f.GetOrigin().GetProgram(), f.GetKind()
		}
	}
	if foundUnknown {
		return effectTierUnknown, unknownSets, unknownProgram, unknownKind
	}
	return effectTierClean, nil, "", ""
}

// protectedSetsByState splits a target's protected matches into the sets it is
// known to be in and the sets it may be in.
func protectedSetsByState(t *semanticpb.EffectTarget) (known, maybe []string) {
	for _, m := range t.GetProtected() {
		switch m.GetState() {
		case semantic.ProtectedKnown:
			known = append(known, m.GetSet())
		case semantic.ProtectedUnknown:
			maybe = append(maybe, m.GetSet())
		}
	}
	return known, maybe
}

func appendUnique(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(append([]string(nil), a...), b...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// effectTierAction maps a tier to the guardrail action the lane would take.
// strictOrManaged is true for the strict profile and every managed install,
// which fail closed on the unknown tier.
func effectTierAction(tier effectTier, kind string, sets []string, strictOrManaged bool) string {
	switch tier {
	case effectTierKnown:
		// A known mutation takes today's protected-file family path. Only the
		// families that block in the balanced default block here: SSH
		// authorized-keys and control files, and DefenseClaw self-protection
		// state. A shell-rc, agent-config or credential mutation alerts (as
		// persistence.shell_profile_write does), so a benign ~/.bashrc PATH
		// export or a config edit is not a false block. A known read of
		// credentials is a sensitive read (alert); other reads are not escalated.
		if mutatingEffectKind(kind) {
			if effectSetContains(sets, effectrules.SetSSHAuthorizedKeys) ||
				effectSetContains(sets, effectrules.SetSelfProtection) {
				return guardrailActionBlock
			}
			return guardrailActionAlert
		}
		if effectSetContains(sets, effectrules.SetCredentials) {
			return guardrailActionAlert
		}
		return guardrailActionAllow
	case effectTierUnknown:
		// Unknown effect touching a protected set: alert in OSS default and
		// permissive, block in strict and every managed install. There is no
		// ask yet (S8 owns the confirm path).
		if strictOrManaged {
			return guardrailActionBlock
		}
		return guardrailActionAlert
	default:
		return guardrailActionAllow
	}
}

func effectSetContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// effectShadowContextKey marks the outermost trusted-action dispatch so the
// effect lane runs once per call, not once per nested statement or twin.
type effectShadowContextKey struct{}

func markOutermostEffectDispatch(ctx context.Context) (context.Context, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Value(effectShadowContextKey{}) != nil {
		return ctx, false
	}
	return context.WithValue(ctx, effectShadowContextKey{}, struct{}{}), true
}

// effectShadowFindings turns an effect verdict into rule findings for the ON
// lane. Clean or allow verdicts carry no finding. An alert-tier verdict is
// capped at an alert in every profile; a block-tier verdict contributes to
// enforcement so the profile threshold maps its severity to the action. The
// effect disposition lets S8 map the unknown tier to ask later; the effect
// proof is authoritative only when the lane is ON.
func effectShadowFindings(res EffectShadowResult, mode effectRulesMode) []RuleFinding {
	if res.Tier == string(effectTierClean) || res.Action == guardrailActionAllow {
		return nil
	}
	rid := "effect.protected_target_" + res.Tier
	title := "Effect-model protected-target verdict"
	severity := "HIGH"
	if res.Tier == string(effectTierKnown) && mutatingEffectKind(res.Kind) {
		severity = "CRITICAL"
	}
	disposition := findingDispositionEffectKnown
	if res.Tier == string(effectTierUnknown) {
		disposition = findingDispositionEffectUnknown
	}
	tags := append([]string{"effects", res.Tier}, res.Sets...)
	f := RuleFinding{
		RuleID:     rid,
		Title:      title,
		Severity:   severity,
		Confidence: 0.9,
		Tags:       tags,
	}
	f.disposition = disposition
	f.proof = newFindingProof(findingProofEffect, rid, mode == effectRulesOn)
	switch res.Action {
	case guardrailActionAlert:
		f.enforcement = findingEnforcementAlertOnly
	default:
		f.enforcement = findingEnforcementInherit
	}
	return []RuleFinding{f}
}
