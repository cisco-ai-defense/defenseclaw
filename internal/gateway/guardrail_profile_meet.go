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
// rules of every member's rule pack (a rule any member enforces is enforced),
// the suppressions all members share (allows are the intersection), every
// sensitive tool any member inspects, and the members' sandbox floors
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
		hookBlock := hookModeForConfig(cfg, connectorName) == "action"
		inspectBlock := inspectMode(cfg, connectorName) == "action"
		_, alert := guardrailThresholdRanks(resolveThresholds(cfg, connectorName))
		if alertRank == 0 || alert < alertRank {
			alertRank = alert
		}
		if !hookBlock && !inspectBlock {
			continue
		}
		if hookBlock {
			out.hookMode = "action"
		}
		if inspectBlock || connectorName == "" {
			out.mode = "action"
		}
		if !(hookBlock && surfaces&profileSurfaceHooks != 0) && !(inspectBlock && surfaces&profileSurfaceInspect != 0) {
			continue
		}
		block, _ := guardrailThresholdRanks(resolveThresholds(cfg, connectorName))
		proxy, _ := guardrailThresholdRanks(resolveGuardrailThresholds(&cfg.Guardrail, connectorName))
		for _, rank := range []int{block, proxy} {
			if blockRank == 0 || rank < blockRank {
				blockRank = rank
			}
		}
		for _, hilt := range []struct {
			enabled bool
			rank    int
		}{
			{hiltEnabledForConfig(cfg, connectorName), hiltMinRankForConfig(cfg, connectorName)},
			{hiltEnabled(&cfg.Guardrail, connectorName), hiltMinRank(&cfg.Guardrail, connectorName)},
		} {
			if hilt.enabled && (hiltRank == 0 || hilt.rank < hiltRank) {
				hiltRank = hilt.rank
			}
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

// meetRuleGeneration is the rule generation of the meet for connectorName:
// every rule of every member's generation, a rule all of them define the
// same way once. A merge that does not compile (over the semantic rule
// limits) keeps the largest member generation and is logged.
func (m *profileMeet) ruleGeneration(ctx context.Context, set *guardrailProfileSet, connectorName string) *compiledRulePackCategories {
	var sources []*compiledRulePackCategories
	for _, member := range m.members {
		if generation := set.memberRuleGeneration(ctx, member, connectorName); generation != nil && !slices.Contains(sources, generation) {
			sources = append(sources, generation)
		}
	}
	switch len(sources) {
	case 0:
		return nil
	case 1:
		return sources[0]
	}
	key := meetSourcesKey(connectorName, sources)
	if cached, ok := m.rules.Load(key); ok {
		return cached.(*compiledRulePackCategories)
	}
	merged, err := mergeRuleGenerations(sources)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] strictest combination %s: merging the rule packs of its profiles: %v; it scans with the largest one\n", m.derived.Name, err)
		merged = sources[0]
		for _, source := range sources[1:] {
			if ruleCount(source) > ruleCount(merged) {
				merged = source
			}
		}
	}
	value, _ := m.rules.LoadOrStore(key, merged)
	return value.(*compiledRulePackCategories)
}

func ruleCount(generation *compiledRulePackCategories) int {
	count := 0
	for _, category := range generation.categories {
		count += len(category.Rules)
	}
	return count
}

// mergeRuleGenerations compiles the union of sources' categories: each
// category keeps every rule any source has, a rule two sources define the
// same way once.
func mergeRuleGenerations(sources []*compiledRulePackCategories) (*compiledRulePackCategories, error) {
	var categories []ruleCategory
	index := map[string]int{}
	overridden, added := 0, 0
	for _, source := range sources {
		overridden, added = max(overridden, source.overridden), max(added, source.added)
		for _, category := range source.categories {
			i, ok := index[category.Name]
			if !ok {
				categories = append(categories, ruleCategory{Name: category.Name})
				i = len(categories) - 1
				index[category.Name] = i
			}
			for _, rule := range category.Rules {
				if !slices.ContainsFunc(categories[i].Rules, func(have PatternRule) bool { return samePatternRule(have, rule) }) {
					categories[i].Rules = append(categories[i].Rules, rule)
				}
			}
		}
	}
	merged, err := compileRulePackGeneration(categories)
	if err != nil {
		return nil, err
	}
	merged.overridden, merged.added = overridden, added
	return merged, nil
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

// rulePack is the composed pack of the meet for connectorName: the first
// member's pack with only the suppressions every member's pack has, and
// every sensitive tool any member's pack inspects, at its strictest.
func (m *profileMeet) rulePack(ctx context.Context, a *APIServer, set *guardrailProfileSet, connectorName string) *guardrail.RulePack {
	var sources []*guardrail.RulePack
	missing := false
	for _, member := range m.members {
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
