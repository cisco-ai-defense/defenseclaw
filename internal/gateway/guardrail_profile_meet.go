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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The meet of guardrail profiles: what applies when several profiles may.
//
// When proven assignments select different profiles, their meet applies.
// For an unproven identity fact, the meet is diagnostic context and the
// request is refused. When one candidate covers every other one, it retains
// its own name. Otherwise the meet is config.ProfileMeetName,
// "strictest.<members>". Every member scans with its own rules, including an
// observer, and the audit records each finding with that member's name.
// Each member's mode, thresholds and HILT decide only its own findings. The
// final action is the strongest member action; an observer contributes at
// most an alert. Members share one semantic budget in proven assignment order.
//
// The derived meet configuration retains a path-specific mode for response
// handling, a diagnostic coverage projection and the combined sandbox floor.
// It does not decide the action of a member's rule finding. The base block
// message prevents a member's text from reaching the caller.

// profileMeet is one meet a set derived, on its first use.
type profileMeet struct {
	members []string
	once    sync.Once
	// derived is the meet for a request on any path; onPath holds the
	// configuration each path decides with (pathConfig).
	derived config.DerivedGuardrailProfile
	onPath  [profilePathCount]*config.Config
	ok      bool
	// rules caches the per-member scan generations by connector and source.
	rules sync.Map
}

func meetMemberContext(ctx context.Context, resolved *resolvedGuardrailProfile, member string) context.Context {
	memberResolved := &resolvedGuardrailProfile{
		decision: resolved.decision,
		set:      resolved.set,
		derived:  resolved.set.profileConfig(member),
	}
	memberResolved.decision.Name = member
	return context.WithValue(ctx, resolvedGuardrailProfileKey{}, memberResolved)
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
		anyProfile, anyHooks := set.meetProfile(members, profilePathAny)
		for _, path := range profilePaths {
			profile, hookModes := anyProfile, anyHooks
			if path != profilePathAny {
				if profile, hookModes = set.meetProfile(members, path); reflect.DeepEqual(profile, anyProfile) && reflect.DeepEqual(hookModes, anyHooks) {
					meet.onPath[path] = meet.derived.Config
					continue
				}
			}
			derived, err := set.base.DeriveGuardrailProfileMeet(members, profile, hookModes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] strictest combination of profiles %s: %v\n", strings.Join(members, ", "), err)
				return
			}
			if path == profilePathAny {
				meet.derived = derived
			}
			meet.onPath[path] = derived.Config
		}
		meet.ok = true
	})
	if !meet.ok {
		return nil
	}
	return meet
}

// pathConfig is the configuration the meet decides a request on path with.
func (m *profileMeet) pathConfig(path profilePath) *config.Config {
	if cfg := m.onPath[path]; cfg != nil {
		return cfg
	}
	return m.derived.Config
}

// profilePath is the path a request's decision is for: the hook route, an
// inspect endpoint or the LLM proxy (both decide by the inspect mode), or
// none in particular (any).
type profilePath uint8

const (
	profilePathAny profilePath = iota
	profilePathHook
	profilePathInspect
	profilePathCount
)

// profilePaths lists every path, any first.
var profilePaths = [...]profilePath{profilePathAny, profilePathHook, profilePathInspect}

type profilePathKey struct{}

// withProfilePath records the path of the request on ctx, before its
// profile is resolved.
func withProfilePath(ctx context.Context, path profilePath) context.Context {
	return context.WithValue(ctx, profilePathKey{}, path)
}

// requestProfilePath is the path of the request on ctx: the one its route
// recorded (withProfilePath), else inspect for a request the inspect
// middleware scoped (profileRuleScanConnectorKey), else any.
func requestProfilePath(ctx context.Context) profilePath {
	if ctx == nil {
		return profilePathAny
	}
	if path, ok := ctx.Value(profilePathKey{}).(profilePath); ok {
		return path
	}
	if _, scoped := ctx.Value(profileRuleScanConnectorKey{}).(string); scoped {
		return profilePathInspect
	}
	return profilePathAny
}

// blocksOn reports whether a profile whose hook and inspect modes block as
// hook and inspect do blocks on path.
func blocksOn(path profilePath, hook, inspect bool) bool {
	switch path {
	case profilePathHook:
		return hook
	case profilePathInspect:
		return inspect
	}
	return hook || inspect
}

// configBlocksOn reports whether cfg blocks on connectorName on path.
func configBlocksOn(cfg *config.Config, connectorName string, path profilePath) bool {
	return blocksOn(path, hookModeForConfig(cfg, connectorName) == "action", inspectMode(cfg, connectorName) == "action")
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
// compares profiles on: the one scope an inspect
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

// enforcingMembers are the members whose rules can affect enforcement on a
// path. All members are still scanned and audited by ruleGeneration.
func (set *guardrailProfileSet) enforcingMembers(members []string, connectorName string, path profilePath) []string {
	var out []string
	for _, member := range members {
		if configBlocksOn(set.profileConfig(member), connectorName, path) {
			out = append(out, member)
		}
	}
	if len(out) == 0 {
		return members
	}
	return out
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
// connectorName ("" for the global settings) on path. Hook and inspect
// action modes are independent; thresholds and HILT cover every member that
// blocks on path (on either for profilePathAny).
func (set *guardrailProfileSet) meetSettingsFor(members []string, connectorName string, path profilePath) meetSettings {
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
		if !blocksOn(path, hookBlock, inspectBlock) {
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

// meetProfile returns the inspect policy of the meet on path and the hook
// modes that differ from it. Its rules are its members' (ruleGeneration);
// explicit levels keep a pack posture from deciding them.
func (set *guardrailProfileSet) meetProfile(members []string, path profilePath) (config.GuardrailProfile, map[string]string) {
	global := set.meetSettingsFor(members, "", path)
	hilt := global.hilt
	profile := config.GuardrailProfile{Mode: global.inspectMode, BlockAt: global.block, AlertAt: global.alert, HILT: &hilt,
		Connectors: map[string]config.PerConnectorGuardrailConfig{}}
	hookModes := map[string]string{}
	for _, name := range set.meetConnectors() {
		s := set.meetSettingsFor(members, name, path)
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

// ruleGeneration is the rule generation of the meet for connectorName: every
// member is scanned with its own rules (compiledRulePackCategories.members). Each
// was compiled within the rule and cost limits of one generation, and their
// union is never compiled as one, so no limit of one generation drops a
// member's rule or refuses a request: a scan of the meet costs at most its
// members' scans.
func (m *profileMeet) ruleGeneration(ctx context.Context, set *guardrailProfileSet, connectorName string) *compiledRulePackCategories {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	// Meet names are sorted for stable identity, but the first proven
	// assignment must get its rules judged before other members spend the
	// shared semantic budget.
	order := m.members
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil && resolved.set == set && set.meet(resolved.decision.Name) == m {
		order = make([]string, 0, len(m.members))
		for _, candidate := range resolved.decision.Candidates {
			if slices.Contains(m.members, candidate) && !slices.Contains(order, candidate) {
				order = append(order, candidate)
			}
		}
		for _, member := range m.members {
			if !slices.Contains(order, member) {
				order = append(order, member)
			}
		}
	}
	var sources []*compiledRulePackCategories
	var names []string
	for _, member := range order {
		if generation := set.memberRuleGeneration(ctx, member, connectorName); generation != nil {
			sources = append(sources, generation)
			names = append(names, member)
		}
	}
	if len(sources) == 0 {
		return nil
	}
	key := meetSourcesKey(connectorName, sources) + "|" + strings.Join(names, "|")
	if cached, ok := m.rules.Load(key); ok {
		return cached.(*compiledRulePackCategories)
	}
	value, _ := m.rules.LoadOrStore(key, meetRuleGenerationWithNames(sources, names))
	return value.(*compiledRulePackCategories)
}

// meetRuleGeneration is the generation that scans with each of sources' own
// rules (members). Its categories and rule titles are their union, for
// lookups only.
func meetRuleGeneration(sources []*compiledRulePackCategories) *compiledRulePackCategories {
	return meetRuleGenerationWithNames(sources, nil)
}

func meetRuleGenerationWithNames(sources []*compiledRulePackCategories, names []string) *compiledRulePackCategories {
	merged := &compiledRulePackCategories{
		categories:         cloneRuleCategories(unionRuleCategories(sources)),
		ruleIdentityTitles: map[string]map[string]struct{}{},
		members:            sources,
		memberNames:        slices.Clone(names),
		budgetNote:         new(sync.Once),
	}
	for _, source := range sources {
		merged.overridden, merged.added = max(merged.overridden, source.overridden), max(merged.added, source.added)
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
