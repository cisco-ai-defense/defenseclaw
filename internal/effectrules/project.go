// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// Env carries everything the projection needs that the pure extractor does
// not: the active home, the path flavor, a link resolver (nil uses the hook's
// file-system reader), and a test for a file the same session created.
type Env struct {
	Home   string
	Flavor effects.Flavor
	// Resolve follows a write path through links; nil falls back to
	// hookpaths.ResolveWriteTarget.
	Resolve func(string) (string, bool)
	// AgentCreated reports whether an earlier call of this session wrote the
	// target keyed by effects.Target.Key(). Nil means no session memory.
	AgentCreated func(key string) bool
}

// Project maps a pure effect result onto the CEL activation's effect list and
// grades each path target against the protected sets. It never reads or
// mutates anything the extractor already decided; only link following and the
// protected-set grade touch the file system, read-only.
func Project(res effects.Result, env Env) []*semanticpb.EffectFact {
	rsv := env.Resolve
	if rsv == nil {
		rsv = defaultResolver
	}
	flavor := env.Flavor
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	sets := buildSets(env.Home, flavor)

	effs := res.Effects
	if len(effs) > semantic.MaxEffects {
		// Honour the CEL activation bound. A truncated projection is treated
		// as unknown by the rules (the dropped effects are not graded).
		effs = effs[:semantic.MaxEffects]
	}
	out := make([]*semanticpb.EffectFact, 0, len(effs))
	for i := range effs {
		e := effs[i]
		fact := &semanticpb.EffectFact{
			Index:       int64(i + 1),
			Kind:        string(e.Kind),
			TargetState: string(e.TargetState),
			RoleState:   string(e.RoleState),
			Reasons:     reasonStrings(e.Reasons),
			Reason:      firstReason(e.Reasons),
			Cond:        e.Cond,
			Origin: &semanticpb.EffectOrigin{
				Surface:  string(e.Origin.Surface),
				Dialect:  string(e.Origin.Dialect),
				Command:  int64(e.Origin.Command),
				Program:  e.Origin.Program,
				Wrappers: append([]string(nil), e.Origin.Wrappers...),
				Depth:    int64(e.Origin.Depth),
			},
			Target: projectTarget(e.Target, e.TargetState, sets, flavor, rsv, env.AgentCreated),
		}
		if e.Data != nil {
			fact.DataKind = string(e.Data.Kind)
			fact.Sources = projectSources(e.Data.Sources)
		}
		out = append(out, fact)
	}
	return out
}

func projectTarget(
	t effects.Target,
	state effects.TargetState,
	sets map[string]protectedSet,
	flavor effects.Flavor,
	rsv resolver,
	agentCreated func(string) bool,
) *semanticpb.EffectTarget {
	pt := &semanticpb.EffectTarget{
		Type:   string(t.Type),
		Path:   t.Path,
		Glob:   t.Glob,
		Url:    t.URL,
		Scheme: t.Scheme,
		Host:   t.Host,
		Port:   int64(t.Port),
		Scope:  t.Scope,
		Link:   string(t.Link),
		Key:    t.Key(),
		Flavor: string(t.Flavor),
	}
	if agentCreated != nil && pt.Key != "" && agentCreated(pt.Key) {
		pt.AgentCreated = true
	}
	// Only filesystem targets are graded against the protected sets.
	if t.Type != effects.TargetPath {
		return pt
	}
	for _, name := range AllSets {
		grade := gradeTarget(t, state, sets[name], flavor, rsv)
		if grade == gradeNo {
			continue // absence folds to "no" in protected(); keep the list bounded
		}
		pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{
			Set:   name,
			State: string(grade),
		})
	}
	return pt
}

func projectSources(in []effects.Source) []*semanticpb.EffectSource {
	if len(in) == 0 {
		return nil
	}
	out := make([]*semanticpb.EffectSource, 0, len(in))
	for _, s := range in {
		out = append(out, &semanticpb.EffectSource{
			Kind:     string(s.Kind),
			Effect:   int64(s.Effect),
			Path:     s.Path,
			Variable: s.Variable,
		})
	}
	return out
}

func reasonStrings(in []effects.Reason) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r.Scope)+":"+string(r.Code))
	}
	return out
}

func firstReason(in []effects.Reason) string {
	if len(in) == 0 {
		return ""
	}
	return string(in[0].Code)
}
