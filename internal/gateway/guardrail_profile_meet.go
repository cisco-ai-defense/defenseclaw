// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"maps"
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
// When proven assignments select different profiles, their meet applies.
// For an unproven identity fact, the meet is diagnostic context and the
// request is refused. When one candidate enforces at least what each of the
// others does (profileCovers), it has its own name. Otherwise their meet
// is config.ProfileMeetName, "strictest.<members>": for every
// connector, hook and inspect action wherever a member blocks on that path,
// the lowest block level and strictest HILT of members that block, the lowest
// alert level, and the rules of the rule pack of every member that blocks on
// that connector, each scanned as that member scans it (a rule any member
// enforces there is enforced, also where two packs define one rule ID
// differently; a member that only observes there adds none, and when none
// blocks the meet observes with every member's rules), the suppressions those members share (allows are the
// intersection), every sensitive tool any of them inspects, and the members'
// sandbox floors
// tightened together (config.Config.SandboxFloor). hook_fail_mode and
// enabled are machine settings a profile cannot change, so they are the
// same for every member. The block message is the base configuration's, so
// no member's text reaches the caller.

// profileMeet is one meet a set derived, on its first use.
type profileMeet struct {
	members []string
	once    sync.Once
	derived config.DerivedGuardrailProfile
	ok      bool
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
		profile, hookModes := set.meetProfile(members)
		derived, err := set.base.DeriveGuardrailProfileMeet(members, profile, hookModes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] strictest combination of profiles %s: %v\n", strings.Join(members, ", "), err)
			return
		}
		meet.derived, meet.ok = derived, true
	})
	if !meet.ok {
		return nil
	}
	return meet
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

// meetOf is the profile that applies when any of names may, compared on
// the scopes the request scans (scans): a profile that covers every other
// one there, under its own name (single), else their meet. A meet that
// cannot be derived (an internal error, logged) leaves the strictest of
// them by mode and block level.
func (set *guardrailProfileSet) meetOf(names, scans []string) (name string, single bool) {
	names = meetMembers(names)
	if len(names) == 0 {
		return set.defaultProfile, true
	}
	if name, covers := set.strictestOf(names, scans); covers {
		return name, true
	}
	name = config.ProfileMeetName(names)
	if set.meet(name) != nil {
		return name, false
	}
	strictest, _ := set.strictestOf(names, scans)
	return strictest, false
}

// requestScanScopes are the rule scopes ctx's decision on connectorName
// compares profiles on and checks merges for: the one scope an inspect
// route recorded (profileRuleScanConnectorKey), else profileCoverConnectors.
// Every name is canonicalConnectorRulePackKey's, the one the scans use.
func (set *guardrailProfileSet) requestScanScopes(ctx context.Context, connectorName string) []string {
	if ctx != nil {
		if scan, scoped := ctx.Value(profileRuleScanConnectorKey{}).(string); scoped {
			return []string{canonicalConnectorRulePackKey(scan)}
		}
	}
	return set.profileCoverConnectors(connectorName)
}

// blockingMembers are the members of a meet that block on connectorName by
// hook or inspect mode.
func (set *guardrailProfileSet) blockingMembers(members []string, connectorName string) []string {
	var out []string
	for _, member := range members {
		cfg := set.profileConfig(member)
		if hookModeForConfig(cfg, connectorName) == "action" || inspectMode(cfg, connectorName) == "action" {
			out = append(out, member)
		}
	}
	return out
}

// enforcingMembers are the members of a meet whose rules it scans
// connectorName with: those that block there (blockingMembers). A member
// that only observes on connectorName adds no rule, so the meet never turns
// its observation into a block. When no member blocks there, the meet
// observes with every member's rules.
func (set *guardrailProfileSet) enforcingMembers(members []string, connectorName string) []string {
	if out := set.blockingMembers(members, connectorName); len(out) > 0 {
		return out
	}
	return members
}

// meetConnectors are the connectors a meet sets explicitly: every built-in
// one, and every one the configuration or a profile names. Any other
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
	// The meet's explicit mode clears inherited hook modes, so a
	// connector whose hook mode only connector_hooks sets is listed too.
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

// meetSettings are the inspect and hook settings of a meet for one connector.
type meetSettings struct {
	inspectMode, hookMode string
	block, alert          string
	hilt                  config.HILTConfig
}

// meetSettingsFor is the meet of members' effective settings for
// connectorName ("" for the global settings). Hook and inspect action modes
// are independent; thresholds and HILT cover every member that blocks on
// either path.
func (set *guardrailProfileSet) meetSettingsFor(members []string, connectorName string) meetSettings {
	out := meetSettings{inspectMode: "observe", hookMode: "observe"}
	blockRank, alertRank, hiltRank := 0, 0, 0
	for _, member := range members {
		cfg := set.profileConfig(member)
		hookBlock := hookModeForConfig(cfg, connectorName) == "action"
		inspectBlock := inspectMode(cfg, connectorName) == "action"
		if hookBlock {
			out.hookMode = "action"
		}
		if inspectBlock {
			out.inspectMode = "action"
		}
		_, alert := guardrailThresholdRanks(resolveThresholds(cfg, connectorName))
		if alertRank == 0 || alert < alertRank {
			alertRank = alert
		}
		if !hookBlock && !inspectBlock {
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

// meetProfile returns the inspect policy and the hook modes that differ from
// it. Its rules are merged from every member (meetRuleGeneration); explicit
// levels keep a pack posture from deciding them.
func (set *guardrailProfileSet) meetProfile(members []string) (config.GuardrailProfile, map[string]string) {
	global := set.meetSettingsFor(members, "")
	hilt := global.hilt
	profile := config.GuardrailProfile{Mode: global.inspectMode, BlockAt: global.block, AlertAt: global.alert, HILT: &hilt,
		Connectors: map[string]config.PerConnectorGuardrailConfig{}}
	hookModes := map[string]string{}
	for _, name := range set.meetConnectors() {
		s := set.meetSettingsFor(members, name)
		connectorHILT := s.hilt
		profile.Connectors[name] = config.PerConnectorGuardrailConfig{Mode: s.inspectMode, BlockAt: s.block, AlertAt: s.alert, HILT: &connectorHILT}
		if s.hookMode != s.inspectMode {
			hookModes[name] = s.hookMode
		}
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

// meetRuleGenerationResult is a merged rule generation of a meet, or why its
// rules could not be compiled as one.
type meetRuleGenerationResult struct {
	generation *compiledRulePackCategories
	err        error
}

// ruleGeneration is the rule generation of the meet for connectorName: the
// generations of the members whose rules it scans there (enforcingMembers),
// each scanned with its own rules (compiledRulePackCategories.members).
// Where a member blocks, their union must compile as one generation, within
// its rule and cost limits; a merge that does not must refuse the decision
// (refuseUncompiledMeet), since substituting any one member would silently
// drop the others' rules. Where no member blocks the meet only observes, so
// those limits never turn the observation into a refusal.
func (m *profileMeet) ruleGeneration(ctx context.Context, set *guardrailProfileSet, connectorName string) (*compiledRulePackCategories, error) {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	var sources []*compiledRulePackCategories
	for _, member := range set.enforcingMembers(m.members, connectorName) {
		if generation := set.memberRuleGeneration(ctx, member, connectorName); generation != nil && !slices.Contains(sources, generation) {
			sources = append(sources, generation)
		}
	}
	switch len(sources) {
	case 0:
		return nil, nil
	case 1:
		return sources[0], nil
	}
	key := meetSourcesKey(connectorName, sources)
	if cached, ok := m.rules.Load(key); ok {
		result := cached.(meetRuleGenerationResult)
		return result.generation, result.err
	}
	var merged *compiledRulePackCategories
	var err error
	if len(set.blockingMembers(m.members, connectorName)) == 0 {
		merged = observedRuleGenerations(sources)
	} else if merged, err = mergeRuleGenerations(sources); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] strictest combination %s: merging the rule packs of its profiles: %v; requests are refused\n", m.derived.Name, err)
	}
	value, _ := m.rules.LoadOrStore(key, meetRuleGenerationResult{generation: merged, err: err})
	result := value.(meetRuleGenerationResult)
	return result.generation, result.err
}

// refuseUncompiledMeet checks every rule generation this request can scan
// (scans, requestScanScopes: the scope an inspect route recorded, else a
// connector's own scope, else the global and gateway connector scopes of an
// unscoped decision). Another connector's failed merge never refuses the
// request; a failed merge of a scope it scans always does, so no scan
// substitutes the base pack. Only a scope where a member blocks can fail
// (ruleGeneration), so an observing meet is never refused. The member names and compiler error remain in
// the administrator's log.
func (set *guardrailProfileSet) refuseUncompiledMeet(ctx context.Context, decision profileDecision, scans []string) profileDecision {
	if decision.Refused != "" {
		return decision
	}
	meet := set.meet(decision.Name)
	if meet == nil {
		return decision
	}
	for _, scope := range scans {
		if _, err := meet.ruleGeneration(ctx, set, scope); err != nil {
			decision.Refused = "DefenseClaw refused this request: the strictest combination of rule packs could not be compiled; ask an administrator to check the profile rule packs"
			return decision
		}
	}
	return decision
}

// mergeRuleGenerations is the generation that scans with each of sources'
// own rules (members). Its lookups use the union of their categories
// (unionRuleCategories), which must compile as one generation, within the
// rule and cost limits of one.
func mergeRuleGenerations(sources []*compiledRulePackCategories) (*compiledRulePackCategories, error) {
	merged, err := compileRulePackGeneration(unionRuleCategories(sources))
	if err != nil {
		return nil, err
	}
	merged.members = sources
	for _, source := range sources {
		merged.overridden, merged.added = max(merged.overridden, source.overridden), max(merged.added, source.added)
	}
	return merged, nil
}

// observedRuleGenerations is mergeRuleGenerations where no member blocks:
// the same members and union, never compiled as one, so no limit of one
// generation refuses an observation.
func observedRuleGenerations(sources []*compiledRulePackCategories) *compiledRulePackCategories {
	merged := &compiledRulePackCategories{
		categories:         cloneRuleCategories(unionRuleCategories(sources)),
		ruleIdentityTitles: map[string]map[string]struct{}{},
		members:            sources,
	}
	for _, source := range sources {
		for ruleID, titles := range source.ruleIdentityTitles {
			if merged.ruleIdentityTitles[ruleID] == nil {
				merged.ruleIdentityTitles[ruleID] = map[string]struct{}{}
			}
			maps.Copy(merged.ruleIdentityTitles[ruleID], titles)
		}
	}
	return merged
}

// unionRuleCategories is the union of sources' categories: each category
// keeps every rule any source has, a rule two sources define the same way
// once.
func unionRuleCategories(sources []*compiledRulePackCategories) []ruleCategory {
	var categories []ruleCategory
	index := map[string]int{}
	for _, source := range sources {
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
	return categories
}

// strongestRuleFindings combines the findings of several scans of one
// request: one finding per rule (key), the strongest of them
// (strongerRuleFinding), where the rule first appeared.
func strongestRuleFindings(lists [][]RuleFinding, key func(string) string) []RuleFinding {
	var out []RuleFinding
	positions := map[string]int{}
	for _, findings := range lists {
		for _, finding := range findings {
			k := key(finding.RuleID)
			if i, seen := positions[k]; seen {
				if strongerRuleFinding(finding, out[i]) {
					out[i] = finding
				}
				continue
			}
			positions[k] = len(out)
			out = append(out, finding)
		}
	}
	return out
}

// strongerRuleFinding reports whether a enforces more than b: it may block
// where b only alerts or detects, else its severity is higher, else its
// confidence.
func strongerRuleFinding(a, b RuleFinding) bool {
	weight := func(f RuleFinding) int {
		switch {
		case f.contributesToEnforcement():
			return 2
		case f.contributesToAlertOnly():
			return 1
		}
		return 0
	}
	if wa, wb := weight(a), weight(b); wa != wb {
		return wa > wb
	}
	ra := severityRank[strings.ToUpper(strings.TrimSpace(a.Severity))]
	rb := severityRank[strings.ToUpper(strings.TrimSpace(b.Severity))]
	if ra != rb {
		return ra > rb
	}
	return a.Confidence > b.Confidence
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

// rulePack is the composed pack of the meet for connectorName, over the
// members whose rules it scans there (enforcingMembers): the first one's
// pack with only the suppressions every one's pack has, and every sensitive
// tool any one's pack inspects, at its strictest.
func (m *profileMeet) rulePack(ctx context.Context, a *APIServer, set *guardrailProfileSet, connectorName string) *guardrail.RulePack {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	var sources []*guardrail.RulePack
	missing := false
	for _, member := range set.enforcingMembers(m.members, connectorName) {
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
