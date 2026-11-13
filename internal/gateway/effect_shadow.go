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

// effectTierMode is how far the effect lane may block: restricted (the
// owner's listed-command tier) or full (the full effect model).
type effectTierMode string

const (
	tierRestricted effectTierMode = "restricted"
	tierFull       effectTierMode = "full"
)

// effectsRulesTierFor reads the live generation's effects_rules_tier.
// Absent or unknown is restricted (the shipped default).
func effectsRulesTierFor() effectTierMode {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return tierRestricted
	}
	if effectTierMode(g.Config.Guardrail.EffectsRulesTier) == tierFull {
		return tierFull
	}
	return tierRestricted
}

// effectResolverOverride, when set, replaces the file-system link resolver in
// computeEffectShadow. It is nil in production (the hookpaths reader is used)
// and set by the s7bench harness to a lexical resolver, because the harness
// has no real user home to follow links through.
var effectResolverOverride func(string) (string, bool)

type effectTier string

const (
	effectTierClean      effectTier = "clean"
	effectTierUnknown    effectTier = "unknown"
	effectTierRestricted effectTier = "restricted"
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
func computeEffectShadow(request trustedActionRequest, mode effectRulesMode, tier effectTierMode) EffectShadowResult {
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
	c := classifyEffects(result, facts, opts.Flavor, tier)
	strictOrManaged := request.StrictPolicy || request.ManagedInstall
	res.Sets, res.Program, res.Kind = c.sets, c.program, c.kind
	switch {
	case c.restricted:
		res.Tier = string(effectTierRestricted)
	case c.touches:
		res.Tier = string(effectTierUnknown)
	}
	res.Action = effectAction(c.touches, c.restrictedRuling, strictOrManaged)
	return res
}

// effectClass is the protected-tier read of one call: whether any effect
// touches a protected set at all, whether an effect is restricted-tier
// eligible (a listed command, every token accounted, an exact canonical
// known protected member), and whether that eligible effect is on a family
// that blocks in the OSS default (the existing authorized-keys / self-
// protection ruling). sets/program/kind describe the deciding effect for
// reporting only.
type effectClass struct {
	touches          bool
	restricted       bool
	restrictedRuling bool
	sets             []string
	program          string
	kind             string
}

// classifyEffects applies the owner's three answers (2026-11-13): a known
// mutation by a listed command on an exact canonical protected path is the
// restricted tier (block); anything else that touches a protected set,
// including any UNKNOWN effect that could reach one, is the unknown tier;
// otherwise clean.
func classifyEffects(result effects.Result, facts []*semanticpb.EffectFact, flavor effects.Flavor, tier effectTierMode) effectClass {
	var c effectClass
	fullyAccounted := len(result.Unknowns) == 0
	var touchSets []string
	for _, f := range facts {
		t := f.GetTarget()
		if t.GetType() != "path" {
			continue
		}
		known, maybe := protectedSetsByState(t)
		if len(known) == 0 && len(maybe) == 0 {
			continue
		}
		kind := f.GetKind()
		mutating := mutatingEffectKind(kind)
		unknownEffect := f.GetTargetState() != "known" || f.GetRoleState() != "known" || kind == string(effects.KindOpaque)
		// Relevance: a mutation touching a protected set; a credential read; or
		// any UNKNOWN effect that could reach a protected set (R5F-1). A benign
		// read of a config file (shell rc, agent config) is not escalated.
		relevant := false
		switch {
		case mutating:
			relevant = true
		case unknownEffect:
			relevant = true
		case kind == string(effects.KindRead) && (effectSetContains(known, effectrules.SetCredentials) || effectSetContains(maybe, effectrules.SetCredentials)):
			relevant = true
		}
		if !relevant {
			continue
		}
		c.touches = true
		touchSets = append(touchSets, append(append([]string(nil), known...), maybe...)...)
		if c.program == "" && c.kind == "" {
			c.program, c.kind = f.GetOrigin().GetProgram(), kind
		}
		// Restricted eligibility: a mutation, every token accounted, this
		// effect fully known, by a listed command, on an exact canonical known
		// member of a named set.
		if !mutating || !fullyAccounted ||
			f.GetTargetState() != "known" || f.GetRoleState() != "known" || len(f.GetReasons()) != 0 {
			continue
		}
		// The restricted tier gates blocking to a reviewed command list; the
		// full tier trusts the effect model for any mutating command.
		if tier == tierRestricted &&
			!effectrules.RestrictedBlockCommand(f.GetOrigin().GetProgram(), effects.Surface(f.GetOrigin().GetSurface())) {
			continue
		}
		if !effectrules.CanonicalAbsolute(t.GetPath(), flavor) {
			continue
		}
		for _, m := range t.GetProtected() {
			if m.GetState() != semantic.ProtectedKnown || m.GetReason() != "exact" || m.GetSet() == effectrules.SetOutsideHome {
				continue
			}
			c.restricted = true
			if m.GetSet() == effectrules.SetSSHAuthorizedKeys || m.GetSet() == effectrules.SetSelfProtection {
				c.restrictedRuling = true
			}
		}
	}
	c.sets = dedupeStrings(touchSets)
	return c
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
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

// effectAction maps the protected-tier read to the guardrail action. An effect
// that touches a protected set blocks in strict and every managed install, and
// blocks in the OSS default only when a restricted-tier effect is on a
// ruling family (authorized-keys / self-protection); otherwise it alerts in
// default and permissive. There is no ask yet (S8 owns the confirm path).
func effectAction(touches, restrictedRuling, strictOrManaged bool) string {
	if !touches {
		return guardrailActionAllow
	}
	if strictOrManaged || restrictedRuling {
		return guardrailActionBlock
	}
	return guardrailActionAlert
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
	if res.Tier == string(effectTierRestricted) {
		severity = "CRITICAL"
	}
	disposition := findingDispositionEffectUnknown
	if res.Tier == string(effectTierRestricted) {
		disposition = findingDispositionEffectKnown
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
