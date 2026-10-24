// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"sort"
	"strings"
	"sync"
	"weak"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// The single threshold model. guardrail.block_at / alert_at decide, with the
// S3 precedence profile.connectors[c] > profile > guardrail.connectors[c] >
// global (a profile-derived configuration already carries the profile
// layers); a level left unset takes the selected rule pack's posture
// default. The alert level is clamped to the block level.

// packPostures caches the manifest posture of every pack directory a
// generation build loaded, so resolution on the request path never reads a
// file. It is keyed by directory only, never by pack name: a name resolves
// to its directory through the configuration of the generation asking, so a
// reload candidate that points a name at another pack and is then rejected
// does not change the running generation's levels. A pack without a
// manifest posture is recorded as "", so a pack whose manifest drops the
// field falls back to the folder-name table again.
//
// A build only notes the postures it read (notePackPosture); they become
// visible here when the generation publishes (publishPackPostures), so an
// edit of a pack's manifest in a candidate that is then rejected does not
// change the levels hooks and sandbox decisions use under the running
// generation.
var packPostures sync.Map // directory -> posture

// pendingPackPostures holds what builds read until a generation publishes.
var pendingPackPostures sync.Map // directory -> posture

// configPackPostures holds, for each configuration a generation build
// resolved levels for (its base configuration and each derived profile
// configuration), the manifest postures that build read, by directory. A
// request deciding with that configuration resolves with them, so a
// generation published while it is in flight does not change its levels
// (GAP-0927). Keys are weak: an entry goes with its configuration.
var configPackPostures sync.Map // weak.Pointer[config.Config] -> map[string]string

// bindPackPostures records postures as the ones cfg resolves with.
func bindPackPostures(cfg *config.Config, postures map[string]string) {
	if cfg == nil || postures == nil {
		return
	}
	key := weak.Make(cfg)
	if _, loaded := configPackPostures.Swap(key, postures); !loaded {
		runtime.AddCleanup(cfg, func(key weak.Pointer[config.Config]) { configPackPostures.Delete(key) }, key)
	}
}

// boundPackPostures is what bindPackPostures recorded for cfg, or nil.
func boundPackPostures(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	if v, ok := configPackPostures.Load(weak.Make(cfg)); ok {
		return v.(map[string]string)
	}
	return nil
}

// packPostureFor is packPosture for a configuration a generation build
// bound postures to (bindPackPostures): the posture that build read for the
// directory, else the process-wide one.
func packPostureFor(cfg *config.Config, ref config.RulePackRef, dir string) string {
	if postures := boundPackPostures(cfg); postures != nil {
		key := strings.TrimSpace(dir)
		if key == "" {
			key = strings.TrimSpace(ref.Dir)
		}
		if raw, ok := postures[key]; ok {
			return postureFromManifest(ref, key, raw)
		}
	}
	return packPosture(ref, dir)
}

// postureFromManifest is the posture of ref's pack at dir whose manifest
// posture is raw ("" for none): raw, else a built-in pack's own name, else
// the folder-name table.
func postureFromManifest(ref config.RulePackRef, dir, raw string) string {
	if raw != "" {
		return raw
	}
	if ref.Name != "" && config.IsBuiltinRulePack(ref.Name) {
		return ref.Name
	}
	return guardrailProfileForDir(dir)
}

func rememberPackPosture(dir, posture string) {
	if dir = strings.TrimSpace(dir); dir != "" {
		packPostures.Store(dir, posture)
	}
}

func notePackPosture(dir, posture string) {
	if dir = strings.TrimSpace(dir); dir != "" {
		pendingPackPostures.Store(dir, posture)
	}
}

// publishPackPostures makes the postures the published generation's build
// read the ones the request path resolves with.
func publishPackPostures() {
	pendingPackPostures.Range(func(dir, posture any) bool {
		packPostures.Store(dir, posture)
		pendingPackPostures.Delete(dir)
		return true
	})
}

// packPosture returns the posture of ref's pack at dir (its resolved
// directory; "" uses ref.Dir): the manifest posture a generation recorded
// for that directory, a built-in pack's own name, else the folder-name
// table (guardrailProfileForDir).
func packPosture(ref config.RulePackRef, dir string) string {
	if dir = strings.TrimSpace(dir); dir == "" {
		dir = strings.TrimSpace(ref.Dir)
	}
	raw := ""
	if dir != "" {
		if v, ok := packPostures.Load(dir); ok {
			raw = v.(string)
		}
	}
	return postureFromManifest(ref, dir, raw)
}

// guardrailRulePackDir is the directory of ref for a caller that holds only
// the guardrail block: a custom_packs entry's path, else ref.Dir (a built-in
// name needs policy_dir and keeps its own posture).
func guardrailRulePackDir(gc *config.GuardrailConfig, ref config.RulePackRef) string {
	if gc != nil && ref.Name != "" {
		if custom, ok := gc.CustomPacks[ref.Name]; ok {
			return strings.TrimSpace(custom.Path)
		}
	}
	return ref.Dir
}

func packLabel(ref config.RulePackRef, posture string) string {
	if ref.Name != "" {
		return ref.Name
	}
	return posture
}

// resolveThresholds returns the block and alert levels for connector ("" for
// the global scope) of cfg, a base or profile-derived configuration, with
// the postures its generation build read (packPostureFor).
func resolveThresholds(cfg *config.Config, connector string) ResolvedThresholds {
	if cfg == nil {
		return thresholdsFromLevels(nil, "", "default", config.RulePackRef{})
	}
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return thresholdsFromLevels(&cfg.Guardrail, connector, packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)), ref)
}

func resolveThresholdsWith(cfg *config.Config, connector string, posture func(config.RulePackRef, string) string) ResolvedThresholds {
	if cfg == nil {
		return thresholdsFromLevels(nil, "", "default", config.RulePackRef{})
	}
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return thresholdsFromLevels(&cfg.Guardrail, connector, posture(ref, cfg.ResolveRulePackDir(ref)), ref)
}

// buildingPackPostures resolves postures for the generation being built and
// records them: what its build just read (not yet published), else what the
// published generations read. The table and the configurations the build
// binds them to (bindPackPostures) then decide with the same postures.
type buildingPackPostures map[string]string

func (b buildingPackPostures) posture(ref config.RulePackRef, dir string) string {
	if dir = strings.TrimSpace(dir); dir == "" {
		dir = strings.TrimSpace(ref.Dir)
	}
	if dir == "" {
		return postureFromManifest(ref, dir, "")
	}
	raw, seen := b[dir]
	if !seen {
		if v, ok := pendingPackPostures.Load(dir); ok {
			raw = v.(string)
		} else if v, ok := packPostures.Load(dir); ok {
			raw = v.(string)
		}
		b[dir] = raw
	}
	return postureFromManifest(ref, dir, raw)
}

// ConfigThresholds is resolveThresholds for a caller outside the gateway
// (`defenseclaw-gateway policy show`). No generation build ran in that
// process, so it reads the pack's manifest posture itself, as the gateway
// recorded it when it loaded the pack.
func ConfigThresholds(cfg *config.Config, connector string) ResolvedThresholds {
	connector = config.NormalizeConnectorName(connector)
	if cfg != nil {
		dir := cfg.ResolveRulePackDir(cfg.EffectiveRulePackRefForConnector(connector))
		rememberPackPosture(dir, guardrail.ReadPackPosture(dir))
	}
	return resolveThresholds(cfg, connector)
}

// resolvePackThresholds is the rule pack's posture levels alone, without
// guardrail.block_at / alert_at (the Secure Client content surfaces).
func resolvePackThresholds(cfg *config.Config, connector string) ResolvedThresholds {
	if cfg == nil {
		return thresholdsFromLevels(nil, "", "default", config.RulePackRef{})
	}
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return thresholdsFromLevels(nil, connector, packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)), ref)
}

// resolveGuardrailThresholds is resolveThresholds for a caller that holds
// only the guardrail block.
func resolveGuardrailThresholds(gc *config.GuardrailConfig, connector string) ResolvedThresholds {
	if gc == nil {
		return thresholdsFromLevels(nil, "", "default", config.RulePackRef{})
	}
	ref := gc.EffectiveRulePackRef(connector)
	return thresholdsFromLevels(gc, connector, packPosture(ref, guardrailRulePackDir(gc, ref)), ref)
}

func thresholdsFromLevels(gc *config.GuardrailConfig, connector, posture string, ref config.RulePackRef) ResolvedThresholds {
	packBlock, packAlert := guardrailProfileThresholds(posture)
	out := ResolvedThresholds{
		Block:  severityName(packBlock),
		Alert:  severityName(packAlert),
		Source: "pack-default:" + packLabel(ref, posture),
	}
	if gc == nil {
		return out
	}
	blockAt, alertAt := gc.EffectiveBlockAt(connector), gc.EffectiveAlertAt(connector)
	if blockAt != "" {
		out.Block = blockAt
	}
	if alertAt != "" {
		out.Alert = alertAt
	}
	if blockAt != "" || alertAt != "" {
		out.Source = "config:" + thresholdConfigPath(gc, connector)
	}
	// Anything that blocks also alerts: report the alert level the gateway
	// enforces (guardrailThresholdRanks clamps the same way).
	if guardrailSeverityRank(out.Alert) > guardrailSeverityRank(out.Block) && guardrailSeverityRank(out.Block) > severityNone {
		out.Alert = out.Block
	}
	return out
}

// thresholdConfigPath names the guardrail scope whose levels apply.
func thresholdConfigPath(gc *config.GuardrailConfig, connector string) string {
	if connector != "" && (gc.EffectiveBlockAt(connector) != gc.EffectiveBlockAt("") ||
		gc.EffectiveAlertAt(connector) != gc.EffectiveAlertAt("")) {
		return "guardrail.connectors." + config.NormalizeConnectorName(connector)
	}
	return "guardrail"
}

// guardrailThresholdRanks returns the block and alert ranks, with the alert
// rank clamped to the block rank so anything that blocks also alerts.
func guardrailThresholdRanks(r ResolvedThresholds) (blockThreshold int, alertThreshold int) {
	blockThreshold = guardrailSeverityRank(r.Block)
	if blockThreshold <= severityNone {
		blockThreshold = severityCritical
	}
	alertThreshold = guardrailSeverityRank(r.Alert)
	if alertThreshold <= severityNone {
		alertThreshold = severityMedium
	}
	return blockThreshold, min(alertThreshold, blockThreshold)
}

func severityName(rank int) string {
	switch rank {
	case severityCritical:
		return "CRITICAL"
	case severityHigh:
		return "HIGH"
	case severityMedium:
		return "MEDIUM"
	case severityLow:
		return "LOW"
	default:
		return ""
	}
}

// buildThresholdTable resolves every (profile, connector) pair of cfg: the
// base configuration and each derived profile, for the global scope and
// every connector either configures. It binds the postures it read to cfg
// and each derived configuration (bindPackPostures), so a pair resolved
// later from them, and every decision made with them, uses the same ones.
func buildThresholdTable(cfg *config.Config, profiles *guardrailProfileSet) thresholdTable {
	table := thresholdTable{}
	if cfg == nil {
		return table
	}
	postures := buildingPackPostures{}
	connectors := thresholdConnectorNames(cfg)
	fill := func(profile string, derived *config.Config) {
		table[thresholdKey{Profile: profile}] = resolveThresholdsWith(derived, "", postures.posture)
		for _, name := range connectors {
			table[thresholdKey{Profile: profile, Connector: name}] = resolveThresholdsWith(derived, name, postures.posture)
		}
	}
	fill("", cfg)
	if profiles != nil {
		for name, derived := range profiles.profiles {
			fill(name, derived.Config)
		}
	}
	// A connector first seen after the build takes the application
	// protection pack, when one is set.
	if scope, ok := applicationProtectionRulePackScope(cfg); ok {
		postures.posture(scope.ref, scope.dir)
	}
	bindPackPostures(cfg, postures)
	if profiles != nil {
		for _, derived := range profiles.profiles {
			bindPackPostures(derived.Config, postures)
		}
	}
	return table
}

func thresholdConnectorNames(cfg *config.Config) []string {
	return thresholdConnectorNamesWith(cfg, profileConnectorNames(cfg))
}

// thresholdConnectorNamesWith is thresholdConnectorNames with the profile
// connector names (profileConnectorNames) listed by the caller: every profile
// derived from one configuration shares its guardrail.profiles, and listing
// them again for each of 1,000 profiles made the generation build quadratic
// (GAP-0276).
func thresholdConnectorNamesWith(cfg *config.Config, profileNames []string) []string {
	seen := map[string]struct{}{}
	add := func(name string) {
		if name = config.NormalizeConnectorName(name); name != "" {
			seen[name] = struct{}{}
		}
	}
	for _, name := range cfg.ActiveConnectors() {
		add(name)
	}
	for name := range cfg.Guardrail.Connectors {
		add(name)
	}
	for _, name := range profileNames {
		add(name)
	}
	for name := range cfg.ApplicationProtection.Connectors {
		add(name)
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveThresholds returns the levels of generation g for one connector and
// profile ("" for none). Pairs the table did not precompute (a connector
// first seen after the build) resolve from the generation's configuration.
func ResolveThresholds(g *Generation, connector, profile string) ResolvedThresholds {
	connector = config.NormalizeConnectorName(connector)
	if g == nil {
		return resolveThresholds(nil, connector)
	}
	if r, ok := g.Thresholds[thresholdKey{Profile: profile, Connector: connector}]; ok {
		return r
	}
	cfg := g.Config
	if profile != "" && g.Profiles != nil {
		if derived, ok := g.Profiles.derivedProfile(profile); ok {
			cfg = derived.Config
		}
	}
	return resolveThresholds(cfg, connector)
}

// thresholdScopeKey carries the connector a proxy request serves, so the
// inspector's OPA input resolves that connector's levels.
type thresholdScopeKey struct{}

func withThresholdConnector(ctx context.Context, connector string) context.Context {
	if ctx == nil || strings.TrimSpace(connector) == "" {
		return ctx
	}
	return context.WithValue(ctx, thresholdScopeKey{}, config.NormalizeConnectorName(connector))
}

func thresholdConnectorFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	name, _ := ctx.Value(thresholdScopeKey{}).(string)
	return name
}

// requestProfile returns the profile of a proxy request under generation g,
// or nil. Like profileProxyOverride it applies only to a request with a
// verified subject.
func requestProfile(ctx context.Context, g *Generation) *resolvedGuardrailProfile {
	if g == nil || g.Profiles == nil {
		return nil
	}
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || resolved.set != g.Profiles {
		resolved = resolveGuardrailProfileFor(ctx, g.Profiles)
	}
	if resolved == nil || resolved.derived == nil || resolved.decision.SubjectSource == "" {
		return nil
	}
	return resolved
}

// requestPolicyConfig is the configuration a request without an API server
// decides with: its generation's (requestGeneration), or its verified
// profile's derived configuration. nil before the first generation.
func requestPolicyConfig(ctx context.Context) *config.Config {
	g := requestGeneration(ctx)
	if g == nil {
		return nil
	}
	if resolved := requestProfile(ctx, g); resolved != nil {
		return resolved.derived
	}
	return g.Config
}

// requestThresholds resolves input.thresholds for a request: its generation
// (requestGeneration), its verified profile and its connector.
func requestThresholds(ctx context.Context) policy.ThresholdsInput {
	g := requestGeneration(ctx)
	profile := ""
	var meet *config.Config
	if resolved := requestProfile(ctx, g); resolved != nil {
		profile = resolved.decision.Name
		if config.IsProfileMeet(profile) {
			// The meet as the proxy's surface applies it
			// (profileMeet.surfaces), which no table holds.
			meet = resolved.derived
		}
	}
	if g != nil && g.Config != nil && g.Config.SecureClientIntegration() {
		// The 1.0 proxy verdict sent no thresholds, so the policy used the
		// data.json levels and trust level (as /v1/guardrail/evaluate does),
		// whatever the rule pack.
		return policy.SecureClientGuardrailThresholds(g.Config.PolicyDir)
	}
	resolved := ResolveThresholds(g, thresholdConnectorFrom(ctx), profile)
	if meet != nil {
		resolved = resolveThresholds(meet, thresholdConnectorFrom(ctx))
	}
	block, alert := guardrailThresholdRanks(resolved)
	trust := config.CiscoTrustFull
	if g != nil && g.Config != nil {
		trust = g.Config.Guardrail.EffectiveCiscoTrustLevel()
	}
	return policy.ThresholdsInput{Block: block, Alert: alert, CiscoTrustLevel: trust}
}
