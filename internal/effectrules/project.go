// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// Env carries everything the projection needs that the pure extractor does
// not: the active home, the path flavor, a link resolver (nil uses the hook's
// file-system reader), and a test for a file the same session created.
type Env struct {
	Home   string
	Flavor effects.Flavor
	// AccountHomes are passwd homes the effects frontend resolved from Options.Accounts.
	AccountHomes []string
	// Resolve follows a write path through links; nil falls back to
	// hookpaths.ResolveWriteTarget for the host's own path flavor and to the
	// placed path for the other flavor (resolverFor).
	Resolve func(string) (string, bool)
	// Identity reads a file's device and inode to find a hard link of a
	// protected member (one stat per resolved target); nil reads the disk
	// (DiskIdentity). Tests pass a HardLinkFixture.
	Identity IdentityFunc
	// AgentCreated reports whether an earlier call of this session wrote the
	// target keyed by effects.Target.Key(). Nil means no session memory.
	AgentCreated func(key string) bool
	// Truncated is the call's one bound record: a cap of the projection
	// (maxIdentityStats) that cut the reading short hits it. Nil: the hit is
	// only counted (IdentityCounts).
	Truncated *bounded.Truncated
}

// Project maps a pure effect result onto the CEL activation's effect list and
// grades each path target against the protected sets. It never reads or
// mutates anything the extractor already decided; only link following and the
// protected-set grade touch the file system, read-only.
func Project(res effects.Result, env Env) []*semanticpb.EffectFact {
	flavor := env.Flavor
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	rsv := env.Resolve
	if rsv == nil {
		rsv = resolverFor(flavor)
	}
	sets := buildSets(env.Home, flavor)
	if len(env.AccountHomes) > 0 {
		for name, set := range sets {
			set.homeRoots = append([]string(nil), env.AccountHomes...)
			sets[name] = set
		}
	}
	ids := newIdentityCache(env.Identity, sets, env.Truncated)

	effs := res.Effects
	if len(effs) > semantic.MaxEffects {
		// Honour the CEL activation bound. A truncated projection is treated
		// as unknown by the rules (the dropped effects are not graded).
		effs = effs[:semantic.MaxEffects]
	}
	out := make([]*semanticpb.EffectFact, 0, len(effs))
	stepUps := plainStepUpProof{}
	for i := range effs {
		e := effs[i]
		stepUps.promote(&e, flavor)
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
			Target: projectTarget(e.Target, e.TargetState, e.Kind, sets, flavor, env.Home, rsv, env.AgentCreated, ids),
		}
		if e.Data != nil {
			fact.DataKind = string(e.Data.Kind)
			fact.Sources = projectSources(e.Data.Sources)
		}
		out = append(out, fact)
	}
	holdKnownOnNameMaybe(out)
	return out
}

// holdKnownOnNameMaybe prevents one target/set from being both Known and
// R-NAME Maybe across effects of the same call. Independent known targets keep
// their own resolver proof.
func holdKnownOnNameMaybe(facts []*semanticpb.EffectFact) {
	// A resolver-known member is still Maybe when this same target/set also
	// has an R-NAME path: another effect in the call can leave the target's
	// role or placement unresolved. Keep independent Known targets intact.
	maybeNames := make(map[string]bool)
	for _, fact := range facts {
		target := fact.GetTarget()
		if fact.GetTargetState() != string(effects.TargetStateKnown) &&
			fact.GetRoleState() == string(effects.RoleStateKnown) {
			// A physical link walk, a passwd/conventional home-tail match, or
			// an inode identity is a resolver fact. It can settle an otherwise
			// lexical target; a bare exact spelling cannot.
			for _, match := range target.GetProtected() {
				switch match.GetReason() {
				case "link", ReasonLinkExact, "other_home", "inode":
					if match.GetState() == string(gradeKnown) {
						fact.TargetState = string(effects.TargetStateKnown)
					}
				}
				if fact.GetTargetState() == string(effects.TargetStateKnown) {
					break
				}
			}
		}
		uncertainEffect := fact.GetTargetState() != string(effects.TargetStateKnown) ||
			fact.GetRoleState() != string(effects.RoleStateKnown) ||
			fact.GetKind() == string(effects.KindOpaque)
		for _, match := range target.GetProtected() {
			// An inode match is direct resolver evidence for the physical file;
			// retain it when command role or placement remains uncertain.
			if uncertainEffect && match.GetState() == string(gradeKnown) && match.GetReason() != "inode" {
				match.State = string(gradeUnknown)
				match.Reason = "call_maybe"
			}
			// A link end the call just placed has an uncertain destination
			// role, not an uncertain identity of its Known source member.
			if match.GetState() == string(gradeUnknown) && match.GetReason() != "call_link" &&
				ReachForMatch(match.GetReason(), fact.GetReasons()) == ReachName {
				maybeNames[target.GetKey()+"\x00"+match.GetSet()] = true
			}
		}
	}
	for _, fact := range facts {
		target := fact.GetTarget()
		for _, match := range target.GetProtected() {
			if match.GetState() == string(gradeKnown) && match.GetReason() != "inode" &&
				maybeNames[target.GetKey()+"\x00"+match.GetSet()] {
				match.State = string(gradeUnknown)
				match.Reason = "call_maybe"
			}
		}
	}
}

func projectTarget(
	t effects.Target,
	state effects.TargetState,
	kind effects.Kind,
	sets map[string]protectedSet,
	flavor effects.Flavor,
	home string,
	rsv resolver,
	agentCreated func(string) bool,
	ids *identityCache,
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
		grade := gradeTarget(t, state, kind, sets[name], flavor, rsv)
		if grade == gradeNo {
			continue // absence folds to "no" in protected(); keep the list bounded
		}
		reason := matchBasis(t, grade, sets[name], flavor)
		if reason == "link" && t.Path != "" {
			// The resolver walked the spelling to an exact member: a write
			// that opens the path writes that member (DET111 ruling R2).
			if resolved, ok := rsv(t.Path); ok && resolved != "" && memberExact(resolved, sets[name], flavor) {
				reason = ReasonLinkExact
			}
		}
		pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{
			Set:    name,
			State:  string(grade),
			Reason: reason,
		})
	}
	// A hard link of a member is the member under another name: the name
	// reading cannot see it, the file identity does (GAP-1288/1289/1317/1318).
	if ids != nil {
		if hit, known := ids.hardLinkSets(t, rsv); len(hit) > 0 {
			addIdentityMatches(pt, hit, known)
		}
	}
	if mutatingKind(kind) {
		for _, name := range AllSets {
			if dirExact(t.Path, sets[name], flavor) && !hasExactFileMatch(pt, name) {
				pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{
					Set:    name,
					State:  string(gradeUnknown),
					Reason: "protected_dir",
				})
			}
		}
	}
	return pt
}

// hasExactFileMatch reports that an exact file member of set already matched,
// so a write to that file is handled and the protected-directory rule does
// not also fire.
func hasExactFileMatch(pt *semanticpb.EffectTarget, set string) bool {
	for _, m := range pt.GetProtected() {
		if m.GetSet() == set && m.GetReason() == "exact" {
			return true
		}
	}
	return false
}

func mutatingKind(kind effects.Kind) bool {
	switch kind {
	case effects.KindWrite, effects.KindAppend, effects.KindDelete,
		effects.KindLink, effects.KindPermissionChange:
		return true
	default:
		return false
	}
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
