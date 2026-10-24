// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The meet of guardrail profiles: what applies when several profiles may.
//
// When proven assignments select different profiles, their meet applies,
// and so it does for an unproven identity fact, on every surface strict
// does not refuse (unprovenRefusal). When one candidate enforces at least what each of the
// others does (profileCovers), it has its own name. Otherwise their meet
// is config.ProfileMeetName, "strictest.<members>": for every
// connector, its hook mode action wherever a member's hook mode is and its
// inspect mode action wherever a member's inspect mode is (each apart), the
// lowest block level and
// the strictest HILT of the members that block, the lowest alert level, the
// rules of every member's rule pack, each scanned only where its own member
// would decide it (profileMeet.ruleGeneration), the suppressions all members
// that enforce share (allows are the intersection), every sensitive tool any
// of them inspects, and the members' sandbox floors
// tightened together (config.Config.SandboxFloor). Each surface takes its
// block levels and HILT only from the members that enforce on it: the agent
// hooks from those whose hook mode is action, the inspect endpoints and the
// LLM proxy from those whose inspect mode is (profileMeet.surfaces), so an
// inspect-only member's lower block level never blocks a hook that no member
// blocks. hook_fail_mode and
// enabled are machine settings a profile cannot change, so they are the
// same for every member. The block message is the base configuration's, so
// no member's text reaches the caller.

// profileMeet is one meet a set derived, on its first use.
type profileMeet struct {
	members []string
	once    sync.Once
	// derived takes its block levels from every member that enforces on any
	// surface: ACP, sandboxes and explain read it.
	derived config.DerivedGuardrailProfile
	// surfaces is the meet as a request of one surface applies it
	// (profileSurfaceFrom): the hooks' and inspect's configurations, whose
	// block levels and HILT come only from the members that enforce on it.
	surfaces map[profileSurfaces]*config.Config
	ok       bool
	// rules and packs hold the merged rule generations and composed packs
	// by connector and member sources (meetSourcesKey).
	rules sync.Map
	packs sync.Map
}

// profileMeetLabel is how a meet is named to the account it applies to: it
// names no member, since a member may be the profile of a group the account
// is not proven to be in (privacy: users see only their own effective
// policy).
const profileMeetLabel = "strictest combination"

// profileUserLabel is the profile name shown to the account a decision is
// for: the profile's own name, or profileMeetLabel for a meet.
func profileUserLabel(name string) string {
	if config.IsProfileMeet(name) {
		return profileMeetLabel
	}
	return name
}

// derivedProfile is the derived profile name selects: one of the set's
// profiles, or a meet of them.
func (set *guardrailProfileSet) derivedProfile(name string) (config.DerivedGuardrailProfile, bool) {
	if set == nil {
		return config.DerivedGuardrailProfile{}, false
	}
	name = strings.TrimSpace(name)
	if derived, ok := set.profiles[name]; ok {
		return derived, true
	}
	if meet := set.meet(name); meet != nil {
		return meet.derived, true
	}
	return config.DerivedGuardrailProfile{}, false
}

// meet returns the meet name names, derived once, or nil when name is no
// meet of this set's profiles.
func (set *guardrailProfileSet) meet(name string) *profileMeet {
	if set == nil || set.base == nil {
		return nil
	}
	members, ok := config.ProfileMeetMembers(name)
	if !ok {
		return nil
	}
	for _, member := range members {
		if _, known := set.profiles[member]; member != "" && !known {
			return nil
		}
	}
	value, _ := set.meets.LoadOrStore(name, &profileMeet{members: members})
	meet := value.(*profileMeet)
	meet.once.Do(func() {
		fail := func(err error) {
			fmt.Fprintf(os.Stderr, "[guardrail] strictest combination of profiles %s: %v\n", strings.Join(members, ", "), err)
		}
		profile, hookModes := set.meetProfile(members, profileSurfacesAll)
		derived, err := set.base.DeriveGuardrailProfileMeet(members, profile, hookModes)
		if err != nil {
			fail(err)
			return
		}
		surfaces := map[profileSurfaces]*config.Config{}
		for _, surface := range []profileSurfaces{profileSurfaceHooks, profileSurfaceInspect} {
			surfaceProfile, surfaceHookModes := set.meetProfile(members, surface)
			if reflect.DeepEqual(surfaceProfile, profile) {
				surfaces[surface] = derived.Config
				continue
			}
			surfaceDerived, err := set.base.DeriveGuardrailProfileMeet(members, surfaceProfile, surfaceHookModes)
			if err != nil {
				fail(err)
				return
			}
			surfaces[surface] = surfaceDerived.Config
		}
		meet.derived, meet.surfaces, meet.ok = derived, surfaces, true
	})
	if !meet.ok {
		return nil
	}
	return meet
}

// derivedConfigOn is the configuration profile name applies on surface: a
// meet's configuration for the hooks or inspect (profileMeet.surfaces), else
// the profile's own. ok is false when name is no profile of set.
func (set *guardrailProfileSet) derivedConfigOn(name string, surface profileSurfaces) (cfg *config.Config, ok bool) {
	if meet := set.meet(strings.TrimSpace(name)); meet != nil {
		if cfg := meet.surfaces[surface]; cfg != nil {
			return cfg, true
		}
		return meet.derived.Config, true
	}
	derived, ok := set.derivedProfile(name)
	return derived.Config, ok
}

// meetMembers expands meets among names into their members.
func meetMembers(names []string) []string {
	var out []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if members, ok := config.ProfileMeetMembers(name); ok {
			out = append(out, members...)
			continue
		}
		out = append(out, name)
	}
	return compactProfiles(out)
}

// meetOf is the profile that applies when any of names may: a profile that
// covers every other one, under its own name (single), else their meet. A
// meet that cannot be derived (an internal error, logged) leaves the
// strictest of them by mode and block level.
func (set *guardrailProfileSet) meetOf(names []string, connectorName string) (name string, single bool) {
	names = meetMembers(names)
	if len(names) == 0 {
		return set.defaultProfile, true
	}
	if name, covers := set.strictestOf(names, connectorName); covers {
		return name, true
	}
	name = config.ProfileMeetName(names)
	if set.meet(name) != nil {
		return name, false
	}
	strictest, _ := set.strictestOf(names, connectorName)
	return strictest, false
}

// meetConnectors are the connectors a meet sets explicitly: every built-in
// one, and every one the configuration (its guardrail and hook settings) or
// a profile names. Any other
// connector takes the meet's global settings.
func (set *guardrailProfileSet) meetConnectors() []string {
	seen := map[string]bool{}
	add := func(name string) {
		if name = config.NormalizeConnectorName(name); name != "" {
			seen[name] = true
		}
	}
	for _, name := range connector.NewDefaultRegistry().Names() {
		add(name)
	}
	for _, name := range thresholdConnectorNamesWith(set.base, profileConnectorNames(set.base)) {
		add(name)
	}
	// A connector whose hook mode is set (claude_code.mode, codex.mode,
	// connector_hooks) gets its own hook mode in the meet too.
	for name := range set.base.ConnectorHooks {
		add(name)
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// meetSettings are the guardrail settings of a meet for one connector:
// mode is its inspect (guardrail) mode and hookMode its hook mode.
type meetSettings struct {
	mode, hookMode, block, alert string
	hilt                         config.HILTConfig
}

// memberEnforcement is how one member enforces for a connector: whether its
// hook mode and its inspect mode are action, and the lowest severity ranks
// it blocks at and asks at (HILT, 0 for none) where it enforces.
type memberEnforcement struct {
	hooks, inspect bool
	block, hilt    int
}

// memberEnforcementFor is how cfg enforces for connectorName ("" for the
// global settings): its block level is the lower of its hook and its proxy
// thresholds, its HILT the one that asks most.
func memberEnforcementFor(cfg *config.Config, connectorName string) memberEnforcement {
	e := memberEnforcement{
		hooks:   hookModeForConfig(cfg, connectorName) == "action",
		inspect: inspectMode(cfg, connectorName) == "action",
	}
	block, _ := guardrailThresholdRanks(resolveThresholds(cfg, connectorName))
	proxy, _ := guardrailThresholdRanks(resolveGuardrailThresholds(&cfg.Guardrail, connectorName))
	e.block = min(block, proxy)
	for _, hilt := range []struct {
		enabled bool
		rank    int
	}{
		{hiltEnabledForConfig(cfg, connectorName), hiltMinRankForConfig(cfg, connectorName)},
		{hiltEnabled(&cfg.Guardrail, connectorName), hiltMinRank(&cfg.Guardrail, connectorName)},
	} {
		if hilt.enabled && (e.hilt == 0 || hilt.rank < e.hilt) {
			e.hilt = hilt.rank
		}
	}
	return e
}

// enforcesOn reports whether the member enforces on one of surfaces: the
// hooks by its hook mode, inspect by its inspect mode.
func (e memberEnforcement) enforcesOn(surfaces profileSurfaces) bool {
	return e.hooks && surfaces&profileSurfaceHooks != 0 || e.inspect && surfaces&profileSurfaceInspect != 0
}

// decidesAt is the lowest severity rank the member blocks or asks at.
func (e memberEnforcement) decidesAt() int {
	if e.hilt != 0 && e.hilt < e.block {
		return e.hilt
	}
	return e.block
}

// meetSettingsFor is the meet of members' effective settings for
// connectorName ("" for the global settings) as surfaces apply them: the
// hook mode is action wherever a member's hook mode is, and the inspect mode
// wherever a member's inspect mode is, each apart, so a member that inspects
// in action mode never makes an observe hook block (review of r104
// Q-identity, continuation 4, loop round 2); the global mode, which every
// connector the meet does not name inherits for both, is action wherever
// either is. The lowest block level and the strictest HILT of the members
// that block on one of surfaces (by the hook mode on the hooks, the inspect
// mode on inspect), so an inspect-only member's block level never reaches
// the hooks, nor a hook-only member's inspect (review of r104 Q-identity,
// rc.7 loop round 1), and the lowest alert level.
func (set *guardrailProfileSet) meetSettingsFor(members []string, connectorName string, surfaces profileSurfaces) meetSettings {
	out := meetSettings{mode: "observe", hookMode: "observe"}
	blockRank, alertRank, hiltRank := 0, 0, 0
	for _, member := range members {
		cfg := set.profileConfig(member)
		_, alert := guardrailThresholdRanks(resolveThresholds(cfg, connectorName))
		if alertRank == 0 || alert < alertRank {
			alertRank = alert
		}
		e := memberEnforcementFor(cfg, connectorName)
		if !e.hooks && !e.inspect {
			continue
		}
		if e.hooks {
			out.hookMode = "action"
		}
		if e.inspect || connectorName == "" {
			out.mode = "action"
		}
		if !e.enforcesOn(surfaces) {
			continue
		}
		if blockRank == 0 || e.block < blockRank {
			blockRank = e.block
		}
		if e.hilt != 0 && (hiltRank == 0 || e.hilt < hiltRank) {
			hiltRank = e.hilt
		}
	}
	if blockRank == 0 {
		// No member blocks: the meet observes, at the lowest alert level.
		blockRank = severityCritical
	}
	out.block, out.alert = severityName(blockRank), severityName(min(alertRank, blockRank))
	out.hilt = config.HILTConfig{MinSeverity: "HIGH"}
	if hiltRank != 0 {
		out.hilt = config.HILTConfig{Enabled: true, MinSeverity: severityName(hiltRank)}
	}
	return out
}

// meetProfile is the guardrail profile whose settings are the meet of
// members for every connector as surfaces apply it (meetSettingsFor), and
// the hook mode of each
// connector it names, which the meet sets apart from its inspect mode
// (config.Config.DeriveGuardrailProfileMeet). Its rule pack is the base
// configuration's: the meet's rules are merged from every member
// (meetRuleGeneration), and its block levels are explicit, so no pack
// posture decides them.
func (set *guardrailProfileSet) meetProfile(members []string, surfaces profileSurfaces) (config.GuardrailProfile, map[string]string) {
	global := set.meetSettingsFor(members, "", surfaces)
	hilt := global.hilt
	profile := config.GuardrailProfile{Mode: global.mode, BlockAt: global.block, AlertAt: global.alert, HILT: &hilt,
		Connectors: map[string]config.PerConnectorGuardrailConfig{}}
	hookModes := map[string]string{}
	for _, name := range set.meetConnectors() {
		s := set.meetSettingsFor(members, name, surfaces)
		connectorHILT := s.hilt
		profile.Connectors[name] = config.PerConnectorGuardrailConfig{Mode: s.mode, BlockAt: s.block, AlertAt: s.alert, HILT: &connectorHILT}
		hookModes[name] = s.hookMode
	}
	return profile, hookModes
}

// memberRuleGeneration is the rule generation member scans connectorName
// with: its profile's pack, else the base generation's.
func (set *guardrailProfileSet) memberRuleGeneration(ctx context.Context, member, connectorName string) *compiledRulePackCategories {
	if derived, ok := set.profiles[member]; ok && derived.Config != nil {
		resolved := &resolvedGuardrailProfile{decision: profileDecision{Name: member}, set: set, derived: derived.Config}
		if generation := resolved.ruleGeneration(connectorName); generation != nil {
			return generation
		}
	}
	return pinnedRuleGeneration(ctx, connectorName)
}

// meetSourcesKey keys a merged rule generation or pack by its sources.
func meetSourcesKey[T any](connectorName string, sources []*T) string {
	key := connectorName
	for _, source := range sources {
		key += fmt.Sprintf("|%p", source)
	}
	return key
}

// ruleGeneration is the rule generation of the meet for connectorName on
// the surface the request is marked with (profileSurfaceFrom). Each rule
// keeps its member: it is scanned when a member that enforces on that
// surface has it at a severity that member blocks or asks at, or when it is
// below the lowest level any member that enforces there blocks or asks at,
// so it can only alert. A rule only a member that observes there has, or
// one below its own member's levels but at another member's, is not
// scanned, so the meet never blocks what no member alone blocks (review of
// r104 Q-identity, review at 9e7531fb: an inspect-only member's CRITICAL
// rule blocked hooks at the other member's level). When no member enforces
// there, the meet observes and scans every member's rules. The generations
// are combined, not compiled again (mergeRuleGenerations).
func (m *profileMeet) ruleGeneration(ctx context.Context, set *guardrailProfileSet, connectorName string) *compiledRulePackCategories {
	surface := profileSurfaceFrom(ctx)
	type memberRules struct {
		generation  *compiledRulePackCategories
		enforcement memberEnforcement
	}
	var members []memberRules
	var generations []*compiledRulePackCategories
	floor := 0
	for _, member := range m.members {
		generation := set.memberRuleGeneration(ctx, member, connectorName)
		if generation == nil {
			continue
		}
		e := memberEnforcementFor(set.profileConfig(member), connectorName)
		if e.enforcesOn(surface) && (floor == 0 || e.decidesAt() < floor) {
			floor = e.decidesAt()
		}
		members = append(members, memberRules{generation: generation, enforcement: e})
		generations = append(generations, generation)
	}
	if len(members) == 0 {
		return nil
	}
	key := fmt.Sprintf("%d|", surface) + meetSourcesKey(connectorName, generations)
	if cached, ok := m.rules.Load(key); ok {
		return cached.(*compiledRulePackCategories)
	}
	var sources []*compiledRulePackCategories
	for _, member := range members {
		generation := member.generation
		if floor != 0 {
			e := member.enforcement
			generation = generation.withRules(func(rule PatternRule) bool {
				rank := guardrailSeverityRank(rule.Severity)
				return rank < floor || e.enforcesOn(surface) && rank >= e.decidesAt()
			})
		}
		if !slices.Contains(sources, generation) {
			sources = append(sources, generation)
		}
	}
	merged := sources[0]
	if len(sources) > 1 {
		merged = mergeRuleGenerations(sources)
	}
	value, _ := m.rules.LoadOrStore(key, merged)
	return value.(*compiledRulePackCategories)
}

// enforcers are the members that enforce for connectorName on surfaces,
// every member when none does (the meet observes there).
func (m *profileMeet) enforcers(set *guardrailProfileSet, connectorName string, surfaces profileSurfaces) []string {
	var out []string
	for _, member := range m.members {
		if memberEnforcementFor(set.profileConfig(member), connectorName).enforcesOn(surfaces) {
			out = append(out, member)
		}
	}
	if len(out) == 0 {
		return m.members
	}
	return out
}

// withRules is g with only the rules keep keeps, g itself when it keeps
// every one. Its compiled programs are shared, not compiled again.
func (g *compiledRulePackCategories) withRules(keep func(PatternRule) bool) *compiledRulePackCategories {
	out := &compiledRulePackCategories{ruleIdentityTitles: g.ruleIdentityTitles,
		overridden: g.overridden, added: g.added, dispatchCost: g.dispatchCost}
	dropped := false
	for _, category := range g.categories {
		kept := ruleCategory{Name: category.Name}
		for _, rule := range category.Rules {
			if keep(rule) {
				kept.Rules = append(kept.Rules, rule)
			} else {
				dropped = true
			}
		}
		out.categories = append(out.categories, kept)
	}
	for _, rule := range g.semanticRules {
		if keep(rule.rule) {
			out.semanticRules = append(out.semanticRules, rule)
		} else {
			dropped = true
		}
	}
	if !dropped {
		return g
	}
	return out
}

// mergeRuleGenerations combines sources' already compiled rules: each
// category keeps every rule any source has, a rule two sources define the
// same way once. Nothing is compiled again, so no limit of one generation
// can fail the union and drop a member's rules: each source is within the
// limits on its own, and the union's semantic dispatch may spend the cost
// budget of every source (dispatchMaxCost), as each member alone would
// (review of r104 Q-identity, review at 9e7531fb: a union over the semantic
// rule limit scanned with the largest member alone). Definitions of one
// rule ID that differ are all kept, the strongest first, since a scan
// reports a rule ID once, from the first definition that matches.
func mergeRuleGenerations(sources []*compiledRulePackCategories) *compiledRulePackCategories {
	merged := &compiledRulePackCategories{ruleIdentityTitles: map[string]map[string]struct{}{}}
	var categories []ruleCategory
	index := map[string]int{}
	asRule := func(rule PatternRule) PatternRule { return rule }
	ofSemantic := func(rule compiledSemanticRule) PatternRule { return rule.rule }
	for _, source := range sources {
		merged.overridden, merged.added = max(merged.overridden, source.overridden), max(merged.added, source.added)
		merged.dispatchCost += source.dispatchMaxCost()
		for id, titles := range source.ruleIdentityTitles {
			if merged.ruleIdentityTitles[id] == nil {
				merged.ruleIdentityTitles[id] = map[string]struct{}{}
			}
			for title := range titles {
				merged.ruleIdentityTitles[id][title] = struct{}{}
			}
		}
		for _, category := range source.categories {
			i, ok := index[category.Name]
			if !ok {
				categories = append(categories, ruleCategory{Name: category.Name})
				i = len(categories) - 1
				index[category.Name] = i
			}
			for _, rule := range category.Rules {
				categories[i].Rules = insertRuleDefinition(categories[i].Rules, rule, asRule)
			}
		}
		for _, rule := range source.semanticRules {
			merged.semanticRules = insertRuleDefinition(merged.semanticRules, rule, ofSemantic)
		}
	}
	merged.categories = cloneRuleCategories(categories)
	return merged
}

// insertRuleDefinition adds rule to rules unless one of them defines it the
// same way, before the first other definition of its ID with a lower
// severity, else last.
func insertRuleDefinition[T any](rules []T, rule T, definition func(T) PatternRule) []T {
	added := definition(rule)
	at := len(rules)
	for i, have := range rules {
		existing := definition(have)
		if samePatternRule(existing, added) {
			return rules
		}
		if at == len(rules) && strings.EqualFold(existing.ID, added.ID) &&
			guardrailSeverityRank(existing.Severity) < guardrailSeverityRank(added.Severity) {
			at = i
		}
	}
	return slices.Insert(rules, at, rule)
}

// samePatternRule reports whether two rules are one definition.
func samePatternRule(a, b PatternRule) bool {
	pattern := func(r PatternRule) string {
		if r.Pattern == nil {
			return ""
		}
		return r.Pattern.String()
	}
	return a.ID == b.ID && a.Title == b.Title && a.Severity == b.Severity && a.Expression == b.Expression &&
		a.ToolCallOnly == b.ToolCallOnly && a.Confidence == b.Confidence && pattern(a) == pattern(b) &&
		slices.Equal(a.Tags, b.Tags) && a.markedMigratedLiteral == b.markedMigratedLiteral
}

// memberRulePack is the composed pack member scans connector with (the
// judge suppressions and sensitive tools): its profile's pack, else the
// base generation's.
func (a *APIServer) memberRulePack(ctx context.Context, set *guardrailProfileSet, member, connectorName string) *guardrail.RulePack {
	if derived, ok := set.profiles[member]; ok && derived.Config != nil {
		key := effectiveRulePackKey(derived.Config, connectorName)
		if key != effectiveRulePackKey(set.base, connectorName) {
			if pack := set.packs[key]; pack != nil {
				return pack
			}
			if retry := set.missing[key]; retry != nil {
				if pack := retry.rulePack(time.Now()); pack != nil {
					return pack
				}
			}
		}
	}
	return a.generationRulePack(ctx, connectorName)
}

// generationRulePack is the composed pack of the request's generation for
// connectorName: the connector's scope, else the global pack.
func (a *APIServer) generationRulePack(ctx context.Context, connectorName string) *guardrail.RulePack {
	g := a.decisionGeneration(ctx)
	if g == nil {
		return nil
	}
	if pack := g.RulePacks["conn:"+connectorName]; pack != nil {
		return pack
	}
	return g.RulePacks["global"]
}

// rulePack is the composed pack of the meet for connectorName on the
// request's surface: of the members that enforce there (all of them when
// none does, enforcers), the first one's pack with only the suppressions
// every one's pack has, and every sensitive tool any one's pack inspects, at
// its strictest. A member that only observes there adds no tool to inspect,
// as it adds no rule (ruleGeneration).
func (m *profileMeet) rulePack(ctx context.Context, a *APIServer, set *guardrailProfileSet, connectorName string) *guardrail.RulePack {
	var sources []*guardrail.RulePack
	missing := false
	for _, member := range m.enforcers(set, connectorName, profileSurfaceFrom(ctx)) {
		pack := a.memberRulePack(ctx, set, member, connectorName)
		if pack == nil {
			missing = true
			continue
		}
		if !slices.Contains(sources, pack) {
			sources = append(sources, pack)
		}
	}
	switch {
	case len(sources) == 0:
		return nil
	case len(sources) == 1 && !missing:
		return sources[0]
	}
	key := meetSourcesKey(connectorName, sources)
	if missing {
		key += "|missing"
	}
	if cached, ok := m.packs.Load(key); ok {
		return cached.(*guardrail.RulePack)
	}
	merged := mergeRulePacks(sources, missing)
	value, _ := m.packs.LoadOrStore(key, merged)
	return value.(*guardrail.RulePack)
}

// mergeRulePacks is sources[0] with the suppressions of every source (none
// when one source has no pack, missing) and the sensitive tools of any.
func mergeRulePacks(sources []*guardrail.RulePack, missing bool) *guardrail.RulePack {
	merged := *sources[0]
	if merged.Suppressions != nil {
		supps := *merged.Suppressions
		keep := func(rp *guardrail.RulePack, has func(*guardrail.SuppressionsConfig) bool) bool {
			return rp.Suppressions != nil && has(rp.Suppressions)
		}
		supps.PreJudgeStrips = slices.DeleteFunc(slices.Clone(supps.PreJudgeStrips), func(s guardrail.PreJudgeStrip) bool {
			return missing || slices.ContainsFunc(sources[1:], func(rp *guardrail.RulePack) bool {
				return !keep(rp, func(c *guardrail.SuppressionsConfig) bool {
					return slices.ContainsFunc(c.PreJudgeStrips, func(o guardrail.PreJudgeStrip) bool { return reflect.DeepEqual(o, s) })
				})
			})
		})
		supps.FindingSupps = slices.DeleteFunc(slices.Clone(supps.FindingSupps), func(s guardrail.FindingSuppression) bool {
			return missing || slices.ContainsFunc(sources[1:], func(rp *guardrail.RulePack) bool {
				return !keep(rp, func(c *guardrail.SuppressionsConfig) bool {
					return slices.ContainsFunc(c.FindingSupps, func(o guardrail.FindingSuppression) bool { return reflect.DeepEqual(o, s) })
				})
			})
		})
		supps.ToolSuppressions = slices.DeleteFunc(slices.Clone(supps.ToolSuppressions), func(s guardrail.ToolSuppression) bool {
			return missing || slices.ContainsFunc(sources[1:], func(rp *guardrail.RulePack) bool {
				return !keep(rp, func(c *guardrail.SuppressionsConfig) bool {
					return slices.ContainsFunc(c.ToolSuppressions, func(o guardrail.ToolSuppression) bool { return reflect.DeepEqual(o, s) })
				})
			})
		})
		merged.Suppressions = &supps
	}
	var tools *guardrail.SensitiveToolsConfig
	for _, source := range sources {
		if source.SensitiveTools == nil {
			continue
		}
		if tools == nil {
			tools = &guardrail.SensitiveToolsConfig{Version: source.SensitiveTools.Version}
		}
		for _, tool := range source.SensitiveTools.Tools {
			i := slices.IndexFunc(tools.Tools, func(have guardrail.SensitiveTool) bool { return have.Name == tool.Name })
			if i < 0 {
				tools.Tools = append(tools.Tools, tool)
				continue
			}
			have := &tools.Tools[i]
			have.ResultInspection = have.ResultInspection || tool.ResultInspection
			have.JudgeResult = have.JudgeResult || tool.JudgeResult
			if tool.MinEntitiesAlert > 0 && (have.MinEntitiesAlert <= 0 || tool.MinEntitiesAlert < have.MinEntitiesAlert) {
				have.MinEntitiesAlert = tool.MinEntitiesAlert
			}
		}
	}
	merged.SensitiveTools = tools
	return &merged
}
