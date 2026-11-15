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

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// guardrail.cascade: what each layer of the guardrail cascade (rules ->
// System One -> LLM judge) does with its outcome, the unknown tier, the
// per-lane live/shadow switches, the Rego final-decision policy and the
// administrator's locks. Where a layer runs and how it is reached stay in
// the released keys (guardrail.judge, guardrail.detection_strategy*,
// decision_model); the rules keep block_at / alert_at / hilt / mode. An
// empty block is exactly the behaviour without it.
//
// Scopes follow block_at: guardrail.profiles.P.connectors.C >
// guardrail.profiles.P > guardrail.connectors.C > guardrail.cascade. Policy
// and admin exist at the top level only. System One routing is global in
// decision_model and overridden per scope in cascade.system_one.

// Cascade actions, weakest first. log records the finding without an alert.
const (
	CascadeAllow   = "allow"
	CascadeLog     = "log"
	CascadeAlert   = "alert"
	CascadeConfirm = "confirm"
	CascadeBlock   = "block"
)

// Other cascade values.
const (
	// CascadeUnknownPack: the unknown and TRUNCATED tier of the pack (the
	// ONE BOUND RULE: strict blocks, default and permissive alert).
	CascadeUnknownPack = "pack"
	// CascadeFromRules keeps the rule verdict (judge no_verdict, System One
	// on_unsure).
	CascadeFromRules = "rules"
	// CascadeNoVerdictUnknown raises a call the judge gave no verdict on to
	// the unknown tier.
	CascadeNoVerdictUnknown = "unknown"

	CascadeLaneOff    = "off"
	CascadeLaneShadow = "shadow"
	CascadeLaneOn     = "on"
	// CascadeLaneAlert and CascadeLaneBlock are the live values of a lane
	// that emits its own finding (CascadeLane.Values), at that action.
	CascadeLaneAlert = "alert"
	CascadeLaneBlock = "block"

	// DefaultCascadePolicyTimeout bounds one Rego evaluation on the hook path.
	DefaultCascadePolicyTimeout = 5 * time.Millisecond
	maxCascadePolicyTimeoutMs   = 50

	// CascadeLastGoodFile is the last-known-good cascade the gateway keeps in
	// the data directory: the fallback for an invalid cascade at start.
	CascadeLastGoodFile = "cascade-last-good.json"

	maxCascadePolicyModuleBytes = 256 << 10
)

// CascadeActionRank orders the cascade actions (allow 0 .. block 4); -1 for
// a value that is not one.
func CascadeActionRank(action string) int {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case CascadeAllow:
		return 0
	case CascadeLog:
		return 1
	case CascadeAlert:
		return 2
	case CascadeConfirm, "ask":
		return 3
	case CascadeBlock, "deny":
		return 4
	}
	return -1
}

// CascadeActionName is the action of rank r (CascadeActionRank).
func CascadeActionName(rank int) string {
	switch {
	case rank <= 0:
		return CascadeAllow
	case rank == 1:
		return CascadeLog
	case rank == 2:
		return CascadeAlert
	case rank == 3:
		return CascadeConfirm
	}
	return CascadeBlock
}

// CascadeJudgeConfig is the LLM judge's role.
type CascadeJudgeConfig struct {
	// MaxAction caps what the judge lane (in cascade 3 with System One's
	// floor) can decide: block (default), confirm, alert or log.
	MaxAction string `mapstructure:"max_action" yaml:"max_action,omitempty" json:"max_action,omitempty"`
	// BlockNeedsSystemOne: a judge block stands only when System One also
	// confidently blocked the call; otherwise it is a confirm.
	BlockNeedsSystemOne *bool `mapstructure:"block_needs_system_one" yaml:"block_needs_system_one,omitempty" json:"block_needs_system_one,omitempty"`
	// NoVerdict is what a call gets when the judge gives no verdict: rules
	// (default: the rule verdict) or unknown (at least the unknown tier).
	// An escalated CRITICAL under hook_fail_mode closed still blocks.
	NoVerdict string `mapstructure:"no_verdict" yaml:"no_verdict,omitempty" json:"no_verdict,omitempty"`
}

// IsZero reports an unset judge block.
func (j CascadeJudgeConfig) IsZero() bool {
	return j.MaxAction == "" && j.BlockNeedsSystemOne == nil && j.NoVerdict == ""
}

// CascadeSystemOneConfig is System One's outcome handling and, below the top
// level, a scope's override of the decision_model routing.
type CascadeSystemOneConfig struct {
	// Routing overrides (connector and profile scopes only): the global
	// values are decision_model.allow_threshold, block_threshold,
	// block_risk_score and escalate_rule_flagged. 0 / nil inherit.
	AllowThreshold      float64 `mapstructure:"allow_threshold" yaml:"allow_threshold,omitempty" json:"allow_threshold,omitempty"`
	BlockThreshold      float64 `mapstructure:"block_threshold" yaml:"block_threshold,omitempty" json:"block_threshold,omitempty"`
	BlockRiskScore      float64 `mapstructure:"block_risk_score" yaml:"block_risk_score,omitempty" json:"block_risk_score,omitempty"`
	EscalateRuleFlagged *bool   `mapstructure:"escalate_rule_flagged" yaml:"escalate_rule_flagged,omitempty" json:"escalate_rule_flagged,omitempty"`
	// OnUnsure (cascade 2, System One without the judge): confirm (default:
	// the agent asks, or its confirm fallback), alert, or rules (System One
	// adds nothing; the rule verdict stands).
	OnUnsure string `mapstructure:"on_unsure" yaml:"on_unsure,omitempty" json:"on_unsure,omitempty"`
}

// IsZero reports an unset System One block.
func (s CascadeSystemOneConfig) IsZero() bool {
	return s.AllowThreshold == 0 && s.BlockThreshold == 0 && s.BlockRiskScore == 0 &&
		s.EscalateRuleFlagged == nil && s.OnUnsure == ""
}

func (s CascadeSystemOneConfig) routingSet() []string {
	var out []string
	if s.AllowThreshold != 0 {
		out = append(out, "allow_threshold")
	}
	if s.BlockThreshold != 0 {
		out = append(out, "block_threshold")
	}
	if s.BlockRiskScore != 0 {
		out = append(out, "block_risk_score")
	}
	if s.EscalateRuleFlagged != nil {
		out = append(out, "escalate_rule_flagged")
	}
	return out
}

// CascadeScope is the part of guardrail.cascade a connector or profile scope
// may set.
type CascadeScope struct {
	// Unknown is the unknown and TRUNCATED tier: pack (default), alert,
	// confirm or block. Never below alert.
	Unknown   string                 `mapstructure:"unknown" yaml:"unknown,omitempty" json:"unknown,omitempty"`
	Judge     CascadeJudgeConfig     `mapstructure:"judge" yaml:"judge,omitempty" json:"judge,omitempty"`
	SystemOne CascadeSystemOneConfig `mapstructure:"system_one" yaml:"system_one,omitempty" json:"system_one,omitempty"`
	// Lanes maps a registered lane (RegisterCascadeLane) to off, shadow or on.
	Lanes CascadeLaneValues `mapstructure:"lanes" yaml:"lanes,omitempty" json:"lanes,omitempty"`
}

// IsZero reports an unset scope.
func (s CascadeScope) IsZero() bool {
	return s.Unknown == "" && s.Judge.IsZero() && s.SystemOne.IsZero() && len(s.Lanes) == 0
}

// CascadePolicyConfig is the Rego final-decision policy (top level only).
type CascadePolicyConfig struct {
	// Module is the Rego module (package defenseclaw.cascade), pinned by
	// sha256. Unset turns the policy off.
	Module AssetFileRef `mapstructure:"module" yaml:"module,omitempty" json:"module,omitempty"`
	// Lowest is the lowest action the policy may set on a call a layer
	// flagged (default alert); Highest the highest (default block).
	Lowest  string `mapstructure:"lowest" yaml:"lowest,omitempty" json:"lowest,omitempty"`
	Highest string `mapstructure:"highest" yaml:"highest,omitempty" json:"highest,omitempty"`
	// TimeoutMs bounds one evaluation (default 5, max 50).
	TimeoutMs int `mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
}

// IsZero reports an unset policy block.
func (p CascadePolicyConfig) IsZero() bool {
	return p.Module.IsZero() && p.Lowest == "" && p.Highest == "" && p.TimeoutMs == 0
}

// CascadeAdminConfig holds the administrator's locks (top level only).
type CascadeAdminConfig struct {
	// Locked names keys no connector or profile scope may set (see
	// CascadeLockableKeys).
	Locked []string `mapstructure:"locked" yaml:"locked,omitempty" json:"locked,omitempty"`
	// CriticalFloor is the lowest action a proven CRITICAL finding can end
	// at, whatever the cascade or the policy decides: alert (default),
	// confirm, block, or log (the explicit opt-out).
	CriticalFloor string `mapstructure:"critical_floor" yaml:"critical_floor,omitempty" json:"critical_floor,omitempty"`
}

// IsZero reports an unset admin block.
func (a CascadeAdminConfig) IsZero() bool { return len(a.Locked) == 0 && a.CriticalFloor == "" }

// CascadeConfig is guardrail.cascade.
type CascadeConfig struct {
	Unknown   string                 `mapstructure:"unknown" yaml:"unknown,omitempty" json:"unknown,omitempty"`
	Judge     CascadeJudgeConfig     `mapstructure:"judge" yaml:"judge,omitempty" json:"judge,omitempty"`
	SystemOne CascadeSystemOneConfig `mapstructure:"system_one" yaml:"system_one,omitempty" json:"system_one,omitempty"`
	Lanes     CascadeLaneValues      `mapstructure:"lanes" yaml:"lanes,omitempty" json:"lanes,omitempty"`
	Policy    CascadePolicyConfig    `mapstructure:"policy" yaml:"policy,omitempty" json:"policy,omitempty"`
	Admin     CascadeAdminConfig     `mapstructure:"admin" yaml:"admin,omitempty" json:"admin,omitempty"`

	// policySource is the module the load verified (ReadVerified) or the
	// last-known-good copy; the generation compiles these bytes, never a
	// second read of the file.
	policySource []byte
	// invalid is set when the load replaced an invalid cascade with its
	// fallback (CascadeInvalid).
	invalid *CascadeInvalid
	// ignored lists the narrower-scope values the load did not apply: a
	// value the administrator locked, or a connector or profile cascade that
	// does not validate (enforceCascadeOverlays). The top-level cascade stays.
	ignored []CascadeIgnored
	// candidateErr is the full validation error of the document as written
	// (ValidateCascade), before the load ignored or replaced anything:
	// writers refuse it (CascadeCandidateError).
	candidateErr error
}

// CascadeIgnored is one narrower-scope value the gateway does not apply.
type CascadeIgnored struct {
	// Path is the config path of the value (guardrail.profiles.p.block_at).
	Path string `json:"path"`
	// Reason says why it is ignored and what applies instead.
	Reason string `json:"reason"`
}

// Ignored lists the narrower-scope values the load did not apply.
func (c CascadeConfig) Ignored() []CascadeIgnored { return slices.Clone(c.ignored) }

// IgnoredMessage is the operator message for the ignored values, "" when
// there are none.
func (c CascadeConfig) IgnoredMessage() string {
	if len(c.ignored) == 0 {
		return ""
	}
	parts := make([]string, len(c.ignored))
	for i, ig := range c.ignored {
		parts[i] = ig.Path + ": " + ig.Reason
	}
	return "guardrail.cascade: the gateway does not apply " + fmt.Sprint(len(c.ignored)) +
		" narrower-scope setting(s); the administrator's top-level values apply: " + strings.Join(parts, "; ")
}

// IsZero reports an unset cascade block.
func (c CascadeConfig) IsZero() bool {
	return c.scope().IsZero() && c.Policy.IsZero() && c.Admin.IsZero()
}

func (c CascadeConfig) scope() CascadeScope {
	return CascadeScope{Unknown: c.Unknown, Judge: c.Judge, SystemOne: c.SystemOne, Lanes: c.Lanes}
}

// PolicySource is the verified Rego module of the policy, nil when the
// policy is off.
func (c CascadeConfig) PolicySource() []byte { return c.policySource }

// Invalid is the fallback the load applied for an invalid cascade, nil when
// the cascade was valid.
func (c CascadeConfig) Invalid() *CascadeInvalid { return c.invalid }

// CascadeInvalid describes an invalid cascade and the fallback in effect.
type CascadeInvalid struct {
	// Error is the validation error (the key and the fix).
	Error string `json:"error"`
	// Fallback is "last_known_good" or "pack_defaults".
	Fallback string `json:"fallback"`
	// SavedAt is when the last-known-good cascade was saved.
	SavedAt string `json:"saved_at,omitempty"`
	// Weaker lists what the intended cascade asked for that the fallback
	// does not give.
	Weaker []string `json:"weaker,omitempty"`
}

// Message is the operator message for the invalid cascade.
func (i *CascadeInvalid) Message() string {
	if i == nil {
		return ""
	}
	fallback := "the rule pack defaults (no guardrail.cascade settings)"
	if i.Fallback == "last_known_good" {
		fallback = "the last-known-good cascade"
		if i.SavedAt != "" {
			fallback += " saved " + i.SavedAt
		}
	}
	msg := "guardrail.cascade is invalid: " + i.Error + "; the guardrail decides with " + fallback +
		" until the configuration is fixed"
	if len(i.Weaker) > 0 {
		msg += ". This is WEAKER than the configuration you wrote: " + strings.Join(i.Weaker, "; ")
	}
	return msg
}

// Fallback names.
const (
	CascadeFallbackLastGood = "last_known_good"
	CascadeFallbackPack     = "pack_defaults"
)

// CascadeLane is one registered live/shadow switch.
type CascadeLane struct {
	// Name is the key under guardrail.cascade.lanes.
	Name string
	// Default is the shipped value: off, shadow or on.
	Default string
	// ShadowOnly, when set, is why the lane cannot be on in this release
	// (for example "open review findings GAP-0216, GAP-0217"): the lane then
	// accepts off and shadow only.
	ShadowOnly string
	// Description is shown by explain.
	Description string
	// Values, when set, is the value set of a lane that emits its own
	// finding at an action the admin picks (for example off, shadow, alert,
	// block). Nil means off, shadow and on.
	Values []string
	// Global, when set, makes the lane a process-wide switch: only the top
	// level (guardrail.cascade.lanes) may set it.
	Global bool
}

var (
	cascadeLanesMu     sync.RWMutex
	cascadeLanes       = map[string]CascadeLane{}
	cascadeLanesSorted []CascadeLane
)

// RegisterCascadeLane adds a lane switch. Lanes register from an init
// function of this package, so every binary validates the same set. A
// second registration of a name panics.
func RegisterCascadeLane(lane CascadeLane) {
	cascadeLanesMu.Lock()
	defer cascadeLanesMu.Unlock()
	lane.Name = strings.TrimSpace(lane.Name)
	if lane.Name == "" || !lane.accepts(lane.Default) {
		panic(fmt.Sprintf("config: cascade lane %q: bad registration", lane.Name))
	}
	if lane.ShadowOnly != "" && lane.Default == CascadeLaneOn {
		panic(fmt.Sprintf("config: cascade lane %q: a shadow-only lane cannot default to on", lane.Name))
	}
	if _, dup := cascadeLanes[lane.Name]; dup {
		panic(fmt.Sprintf("config: cascade lane %q registered twice", lane.Name))
	}
	cascadeLanes[lane.Name] = lane
	cascadeLanesSorted = append(cascadeLanesSorted, lane)
	sort.Slice(cascadeLanesSorted, func(i, j int) bool { return cascadeLanesSorted[i].Name < cascadeLanesSorted[j].Name })
}

// CascadeLanes lists the registered lanes, sorted by name.
func CascadeLanes() []CascadeLane {
	cascadeLanesMu.RLock()
	defer cascadeLanesMu.RUnlock()
	return slices.Clone(cascadeLanesSorted)
}

func cascadeLane(name string) (CascadeLane, bool) {
	cascadeLanesMu.RLock()
	defer cascadeLanesMu.RUnlock()
	lane, ok := cascadeLanes[name]
	return lane, ok
}

func cascadeLaneValue(v string) bool {
	return v == CascadeLaneOff || v == CascadeLaneShadow || v == CascadeLaneOn
}

// accepts reports whether v is one of the values of the lane.
func (l CascadeLane) accepts(v string) bool {
	if l.Values != nil {
		return slices.Contains(l.Values, v)
	}
	return cascadeLaneValue(v)
}

// CascadeLockableKeys are the names guardrail.cascade.admin.locked accepts.
// A group name (judge, system_one, lanes) locks every key under it.
var CascadeLockableKeys = []string{
	"*",
	"mode", "block_at", "alert_at", "hilt", "rule_pack", "rules",
	"unknown",
	"judge", "judge.max_action", "judge.block_needs_system_one", "judge.no_verdict",
	"system_one", "system_one.allow_threshold", "system_one.block_threshold",
	"system_one.block_risk_score", "system_one.escalate_rule_flagged", "system_one.on_unsure",
	"lanes",
}

func cascadeLockable(key string) bool {
	if slices.Contains(CascadeLockableKeys, key) {
		return true
	}
	if lane, ok := strings.CutPrefix(key, "lanes."); ok {
		_, registered := cascadeLane(lane)
		return registered
	}
	return false
}

// locked reports whether key is locked: listed itself, by its group or by *.
func (a CascadeAdminConfig) locked(key string) bool {
	for _, entry := range a.Locked {
		entry = strings.TrimSpace(entry)
		if entry == "*" || entry == key {
			return true
		}
		if group, _, ok := strings.Cut(key, "."); ok && entry == group {
			return true
		}
	}
	return false
}

// keysSet lists the lockable keys a scope sets.
func (s CascadeScope) keysSet() []string {
	var out []string
	if s.Unknown != "" {
		out = append(out, "unknown")
	}
	if s.Judge.MaxAction != "" {
		out = append(out, "judge.max_action")
	}
	if s.Judge.BlockNeedsSystemOne != nil {
		out = append(out, "judge.block_needs_system_one")
	}
	if s.Judge.NoVerdict != "" {
		out = append(out, "judge.no_verdict")
	}
	for _, k := range s.SystemOne.routingSet() {
		out = append(out, "system_one."+k)
	}
	if s.SystemOne.OnUnsure != "" {
		out = append(out, "system_one.on_unsure")
	}
	for name := range s.Lanes {
		out = append(out, "lanes."+name)
	}
	sort.Strings(out)
	return out
}

// policyKeysSet lists the lockable released guardrail keys a connector or
// profile scope sets.
func policyKeysSet(pc PerConnectorGuardrailConfig) []string {
	var out []string
	if strings.TrimSpace(pc.Mode) != "" {
		out = append(out, "mode")
	}
	if strings.TrimSpace(pc.BlockAt) != "" {
		out = append(out, "block_at")
	}
	if strings.TrimSpace(pc.AlertAt) != "" {
		out = append(out, "alert_at")
	}
	if pc.HILT != nil {
		out = append(out, "hilt")
	}
	if strings.TrimSpace(pc.RulePack) != "" || strings.TrimSpace(pc.RulePackDir) != "" {
		out = append(out, "rule_pack")
	}
	if pc.Rules != nil && !pc.Rules.IsZero() {
		out = append(out, "rules")
	}
	return out
}

// cascadePolicyCheck compiles a cascade Rego module. The policy package
// registers it; a binary without that package skips the compile check.
var cascadePolicyCheck func(source []byte) error

// RegisterCascadePolicyCheck installs the Rego compile check of
// guardrail.cascade.policy.module.
func RegisterCascadePolicyCheck(check func(source []byte) error) { cascadePolicyCheck = check }

// cascadeScopeAt is one scope of the cascade with its config path.
type cascadeScopeAt struct {
	path   string
	scope  CascadeScope
	policy []string // released lockable keys the scope sets
}

// cascadeScopes lists every scope below the top level, sorted by path.
func (g *GuardrailConfig) cascadeScopes() []cascadeScopeAt {
	var out []cascadeScopeAt
	add := func(path string, pc PerConnectorGuardrailConfig) {
		at := cascadeScopeAt{path: path, policy: policyKeysSet(pc)}
		if pc.Cascade != nil {
			at.scope = *pc.Cascade
		}
		out = append(out, at)
	}
	for name, pc := range g.Connectors {
		add("guardrail.connectors."+name, pc)
	}
	for name, profile := range g.Profiles {
		fields := profile.policyFields()
		fields.Rules = profile.Rules
		fields.Cascade = profile.Cascade
		add("guardrail.profiles."+name, fields)
		for cname, pc := range profile.Connectors {
			add("guardrail.profiles."+name+".connectors."+cname, pc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// ValidateCascade checks guardrail.cascade at every scope. checkFiles also
// reads the policy module against its digest and compiles it. Writers refuse
// a configuration it rejects (CascadeCandidateError). The loader is more
// forgiving and never lets a narrower scope weaken the administrator's
// cascade: a locked value or an invalid connector or profile cascade is
// ignored and named (enforceCascadeOverlays), and only an invalid top-level
// cascade falls back (applyCascadeFallback).
func (c *Config) ValidateCascade(checkFiles bool) error {
	if c == nil {
		return nil
	}
	g := &c.Guardrail
	if c.SecureClientIntegration() {
		if !g.Cascade.IsZero() || hasScopeCascade(g) {
			return errors.New("guardrail.cascade is not available under the Secure Client integration; remove it")
		}
		return nil
	}
	errs := []error{c.validateCascadeTop(checkFiles)}
	for _, ig := range c.cascadeOverlayViolations(false) {
		errs = append(errs, errors.New(ig.Path+": "+ig.Reason))
	}
	return errors.Join(errs...)
}

// validateCascadeTop checks the top-level guardrail.cascade block: the only
// part whose error makes the load fall back.
func (c *Config) validateCascadeTop(checkFiles bool) error {
	top := c.Guardrail.Cascade
	var errs []error
	if err := validateCascadeScope("guardrail.cascade", top.scope()); err != nil {
		errs = append(errs, err)
	}
	if set := top.SystemOne.routingSet(); len(set) > 0 {
		errs = append(errs, fmt.Errorf("guardrail.cascade.system_one.%s: set it in decision_model.%s (the global System One routing); guardrail.cascade.system_one sets on_unsure only at the top level, and routing overrides under guardrail.connectors.<agent>.cascade or guardrail.profiles.<name>.cascade", set[0], set[0]))
	}
	if err := validateCascadePolicy(top.Policy, checkFiles); err != nil {
		errs = append(errs, err)
	}
	if err := validateCascadeAdmin(top.Admin); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// cascadeLockedReason is the reason of a locked value a narrower scope sets.
func cascadeLockedReason(key string) string {
	return fmt.Sprintf("%q is locked by guardrail.cascade.admin.locked; the top-level value applies (set it at the top level only, or ask the administrator to unlock it)", key)
}

// cascadeOverlayViolations lists every narrower-scope value the cascade does
// not allow: a key guardrail.cascade.admin.locked names, set by a connector
// scope (guardrail.connectors.<c>, its legacy hook mode, an
// application_protection overlay), a profile or a profile connector (the
// identity profiles are these profiles), and a connector or profile cascade
// that does not validate. With apply it also takes them out of c, so the
// gateway decides with the administrator's values: a locked value is
// dropped, an invalid scope cascade is dropped whole. Maps are copied before
// they are written.
func (c *Config) cascadeOverlayViolations(apply bool) []CascadeIgnored {
	if c == nil || c.SecureClientIntegration() {
		return nil
	}
	g := &c.Guardrail
	admin := g.Cascade.Admin
	var out []CascadeIgnored
	lockedKeys := func(keys []string) []string {
		var hit []string
		for _, key := range keys {
			if admin.locked(key) {
				hit = append(hit, key)
			}
		}
		return hit
	}
	// scope checks one connector or profile cascade and returns what the
	// gateway applies of it.
	scope := func(path string, s *CascadeScope) *CascadeScope {
		if s == nil {
			return nil
		}
		if err := validateCascadeScope(path+".cascade", *s); err != nil {
			out = append(out, CascadeIgnored{Path: path + ".cascade", Reason: err.Error() + "; this scope's cascade is not applied, the wider scopes decide"})
			return nil
		}
		hit := lockedKeys(s.keysSet())
		if len(hit) == 0 {
			return s
		}
		kept := *s
		for _, key := range hit {
			out = append(out, CascadeIgnored{Path: path + ".cascade." + key, Reason: cascadeLockedReason(key)})
			kept = withoutCascadeKey(kept, key)
		}
		return &kept
	}
	policy := func(path string, pc PerConnectorGuardrailConfig, withLevels bool) PerConnectorGuardrailConfig {
		keys := policyKeysSet(pc)
		if !withLevels {
			keys = slices.DeleteFunc(keys, func(k string) bool { return k == "block_at" || k == "alert_at" })
		}
		for _, key := range lockedKeys(keys) {
			out = append(out, CascadeIgnored{Path: path + "." + key, Reason: cascadeLockedReason(key)})
			pc = withoutPolicyKey(pc, key)
		}
		return pc
	}

	if len(g.Connectors) > 0 {
		conns := g.Connectors
		if apply {
			conns = maps.Clone(g.Connectors)
		}
		for _, name := range sortedKeys(g.Connectors) {
			path := "guardrail.connectors." + name
			pc := policy(path, g.Connectors[name], true)
			pc.Cascade = scope(path, pc.Cascade)
			if apply {
				conns[name] = pc
			}
		}
		g.Connectors = conns
	}
	if len(g.Profiles) > 0 {
		profiles := g.Profiles
		if apply {
			profiles = maps.Clone(g.Profiles)
		}
		for _, name := range sortedKeys(g.Profiles) {
			profile := g.Profiles[name]
			path := "guardrail.profiles." + name
			fields := profile.policyFields()
			fields.Rules = profile.Rules
			fields = policy(path, fields, true)
			profile.Mode, profile.HILT, profile.RulePack, profile.RulePackDir = fields.Mode, fields.HILT, fields.RulePack, fields.RulePackDir
			profile.BlockAt, profile.AlertAt, profile.Rules = fields.BlockAt, fields.AlertAt, fields.Rules
			profile.Cascade = scope(path, profile.Cascade)
			if len(profile.Connectors) > 0 {
				conns := profile.Connectors
				if apply {
					conns = maps.Clone(profile.Connectors)
				}
				for _, cname := range sortedKeys(profile.Connectors) {
					cpath := path + ".connectors." + cname
					pc := policy(cpath, profile.Connectors[cname], true)
					pc.Cascade = scope(cpath, pc.Cascade)
					if apply {
						conns[cname] = pc
					}
				}
				profile.Connectors = conns
			}
			if apply {
				profiles[name] = profile
			}
		}
		g.Profiles = profiles
	}

	ap := &c.ApplicationProtection
	if ap.Guardrail.Cascade != nil {
		out = append(out, CascadeIgnored{Path: "application_protection.guardrail.cascade", Reason: "not supported; use guardrail.cascade"})
	}
	apGuardrail := policy("application_protection.guardrail", ap.Guardrail, false)
	apGuardrail.Cascade = nil
	apConns := ap.Connectors
	if apply && len(ap.Connectors) > 0 {
		apConns = maps.Clone(ap.Connectors)
	}
	for _, name := range sortedKeys(ap.Connectors) {
		entry := ap.Connectors[name]
		path := "application_protection.connectors." + name + ".guardrail"
		if entry.Guardrail.Cascade != nil {
			out = append(out, CascadeIgnored{Path: path + ".cascade", Reason: "not supported; use guardrail.connectors." + name + ".cascade"})
		}
		entry.Guardrail = policy(path, entry.Guardrail, false)
		entry.Guardrail.Cascade = nil
		if apply {
			apConns[name] = entry
		}
	}

	// The legacy per-connector hook modes are connector overlays of mode.
	type legacyMode struct {
		path, mode string
		clear      func()
	}
	var legacy []legacyMode
	if admin.locked("mode") {
		global := NormalizeHookMode(g.Mode)
		differs := func(mode string) bool {
			mode = strings.TrimSpace(mode)
			return mode != "" && !strings.EqualFold(mode, "inherit") && NormalizeHookMode(mode) != global
		}
		if differs(c.ClaudeCode.Mode) {
			legacy = append(legacy, legacyMode{"claude_code.mode", c.ClaudeCode.Mode, func() { c.ClaudeCode.Mode = "" }})
		}
		if differs(c.Codex.Mode) {
			legacy = append(legacy, legacyMode{"codex.mode", c.Codex.Mode, func() { c.Codex.Mode = "" }})
		}
		hooks := c.ConnectorHooks
		cloned := false
		for _, name := range sortedKeys(c.ConnectorHooks) {
			if !differs(c.ConnectorHooks[name].Mode) {
				continue
			}
			legacy = append(legacy, legacyMode{"connector_hooks." + name + ".mode", c.ConnectorHooks[name].Mode, func() {
				if !cloned {
					hooks, cloned = maps.Clone(hooks), true
				}
				h := hooks[name]
				h.Mode = ""
				hooks[name] = h
				c.ConnectorHooks = hooks
			}})
		}
	}
	for _, l := range legacy {
		out = append(out, CascadeIgnored{Path: l.path, Reason: cascadeLockedReason("mode")})
	}
	if apply {
		ap.Guardrail = apGuardrail
		ap.Connectors = apConns
		for _, l := range legacy {
			l.clear()
		}
	}
	return out
}

// withoutCascadeKey is s without the lockable key (a group name drops
// every key under it).
func withoutCascadeKey(s CascadeScope, key string) CascadeScope {
	switch key {
	case "unknown":
		s.Unknown = ""
	case "judge.max_action":
		s.Judge.MaxAction = ""
	case "judge.block_needs_system_one":
		s.Judge.BlockNeedsSystemOne = nil
	case "judge.no_verdict":
		s.Judge.NoVerdict = ""
	case "system_one.allow_threshold":
		s.SystemOne.AllowThreshold = 0
	case "system_one.block_threshold":
		s.SystemOne.BlockThreshold = 0
	case "system_one.block_risk_score":
		s.SystemOne.BlockRiskScore = 0
	case "system_one.escalate_rule_flagged":
		s.SystemOne.EscalateRuleFlagged = nil
	case "system_one.on_unsure":
		s.SystemOne.OnUnsure = ""
	default:
		if lane, ok := strings.CutPrefix(key, "lanes."); ok && len(s.Lanes) > 0 {
			lanes := maps.Clone(s.Lanes)
			delete(lanes, lane)
			if len(lanes) == 0 {
				lanes = nil
			}
			s.Lanes = lanes
		}
	}
	return s
}

// withoutPolicyKey is pc without the released lockable key.
func withoutPolicyKey(pc PerConnectorGuardrailConfig, key string) PerConnectorGuardrailConfig {
	switch key {
	case "mode":
		pc.Mode = ""
	case "block_at":
		pc.BlockAt = ""
	case "alert_at":
		pc.AlertAt = ""
	case "hilt":
		pc.HILT = nil
	case "rule_pack":
		pc.RulePack, pc.RulePackDir = "", ""
	case "rules":
		pc.Rules = nil
	}
	return pc
}

// CascadeCandidateError is the guardrail.cascade error a writer refuses a
// candidate for: the full validation of the document as written (every
// scope, the locks, the policy module), the same check `config validate`,
// `config set`, setup, the TUI and the Go writers run. nil when the cascade
// is valid.
func CascadeCandidateError(cfg *Config) error {
	if cfg == nil || cfg.Guardrail.Cascade.candidateErr == nil {
		return nil
	}
	return &V8SemanticError{
		Path:     "$.guardrail.cascade",
		Summary:  cfg.Guardrail.Cascade.candidateErr.Error(),
		Expected: "a guardrail.cascade the gateway accepts",
		Action:   "fix the named key, then retry",
	}
}

func hasScopeCascade(g *GuardrailConfig) bool {
	for _, at := range g.cascadeScopes() {
		if !at.scope.IsZero() {
			return true
		}
	}
	return false
}

func cascadeOneOf(path, value string, allowed ...string) error {
	if value == "" || slices.Contains(allowed, value) {
		return nil
	}
	return fmt.Errorf("%s: %q is not one of %s", path, value, strings.Join(allowed, ", "))
}

func validateCascadeScope(path string, s CascadeScope) error {
	var errs []error
	if s.Unknown == CascadeAllow || s.Unknown == CascadeLog {
		errs = append(errs, fmt.Errorf("%s.unknown: %q would let an input DefenseClaw could not fully read pass silently; the unknown tier is never below alert (pack, alert, confirm or block)", path, s.Unknown))
	} else if err := cascadeOneOf(path+".unknown", s.Unknown, CascadeUnknownPack, CascadeAlert, CascadeConfirm, CascadeBlock); err != nil {
		errs = append(errs, err)
	}
	if err := cascadeOneOf(path+".judge.max_action", s.Judge.MaxAction, CascadeBlock, CascadeConfirm, CascadeAlert, CascadeLog); err != nil {
		errs = append(errs, err)
	}
	if err := cascadeOneOf(path+".judge.no_verdict", s.Judge.NoVerdict, CascadeFromRules, CascadeNoVerdictUnknown); err != nil {
		errs = append(errs, err)
	}
	if err := cascadeOneOf(path+".system_one.on_unsure", s.SystemOne.OnUnsure, CascadeConfirm, CascadeAlert, CascadeFromRules); err != nil {
		errs = append(errs, err)
	}
	so := s.SystemOne
	for _, f := range []struct {
		key      string
		v        float64
		min, max float64
	}{
		{"allow_threshold", so.AllowThreshold, 0, 1},
		{"block_threshold", so.BlockThreshold, 0, 1},
		{"block_risk_score", so.BlockRiskScore, 0, 2},
	} {
		if math.IsNaN(f.v) || f.v < f.min || f.v > f.max {
			errs = append(errs, fmt.Errorf("%s.system_one.%s: %v is outside %v..%v", path, f.key, f.v, f.min, f.max))
		}
	}
	names := make([]string, 0, len(s.Lanes))
	for name := range s.Lanes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// Exact values: a typo (Shadow, " on") never silently switches a lane.
		value := s.Lanes[name]
		lane, ok := cascadeLane(name)
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s.lanes.%s: no such lane in this release (lanes: %s)", path, name, cascadeLaneNames()))
		case lane.Global && path != "guardrail.cascade":
			errs = append(errs, fmt.Errorf("%s.lanes.%s: the %s lane is process-wide; set it at guardrail.cascade.lanes.%s only", path, name, name, name))
		case !lane.accepts(value):
			errs = append(errs, fmt.Errorf("%s.lanes.%s: %q is not one of %s", path, name, value, strings.Join(CascadeLaneAllowed(name), ", ")))
		case value == CascadeLaneOn && lane.ShadowOnly != "":
			errs = append(errs, fmt.Errorf("%s.lanes.%s: on is not available in 1.0.10: the lane ships shadow-only (%s); allowed: off, shadow (shadow records its verdict without changing the answer)", path, name, lane.ShadowOnly))
		}
	}
	return errors.Join(errs...)
}

func cascadeLaneNames() string {
	lanes := CascadeLanes()
	if len(lanes) == 0 {
		return "none"
	}
	names := make([]string, len(lanes))
	for i, lane := range lanes {
		names[i] = lane.Name
	}
	return strings.Join(names, ", ")
}

func validateCascadePolicy(p CascadePolicyConfig, checkFiles bool) error {
	var errs []error
	path := "guardrail.cascade.policy"
	if err := cascadeOneOf(path+".lowest", p.Lowest, CascadeAllow, CascadeLog, CascadeAlert, CascadeConfirm); err != nil {
		errs = append(errs, err)
	}
	if err := cascadeOneOf(path+".highest", p.Highest, CascadeAlert, CascadeConfirm, CascadeBlock); err != nil {
		errs = append(errs, err)
	}
	if lo, hi := cascadeOr(p.Lowest, CascadeAlert), cascadeOr(p.Highest, CascadeBlock); CascadeActionRank(lo) > CascadeActionRank(hi) {
		errs = append(errs, fmt.Errorf("%s: lowest %q is above highest %q", path, lo, hi))
	}
	if p.TimeoutMs < 0 || p.TimeoutMs > maxCascadePolicyTimeoutMs {
		errs = append(errs, fmt.Errorf("%s.timeout_ms: %d is outside 0..%d", path, p.TimeoutMs, maxCascadePolicyTimeoutMs))
	}
	if p.Module.IsZero() {
		if p.Lowest != "" || p.Highest != "" || p.TimeoutMs != 0 {
			errs = append(errs, fmt.Errorf("%s: lowest, highest and timeout_ms need a module (path and digest)", path))
		}
		return errors.Join(errs...)
	}
	if strings.TrimSpace(p.Module.Path) == "" || strings.TrimSpace(p.Module.Digest) == "" {
		errs = append(errs, fmt.Errorf("%s.module: set both path and digest (sha256:<hex> of the file)", path))
		return errors.Join(errs...)
	}
	if !filepath.IsAbs(expandPath(p.Module.Path)) {
		errs = append(errs, fmt.Errorf("%s.module.path: %q must be an absolute path", path, p.Module.Path))
	}
	if checkFiles {
		if _, err := readCascadeModule(p.Module); err != nil {
			errs = append(errs, fmt.Errorf("%s.module: %v; pin the sha256 of the file, or restore the file the digest pins", path, err))
		}
	}
	return errors.Join(errs...)
}

// readCascadeModule reads the policy module against its digest and compiles
// it (when the policy package is linked).
func readCascadeModule(ref AssetFileRef) ([]byte, error) {
	ref.Path = expandPath(ref.Path)
	info, err := os.Stat(ref.Path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxCascadePolicyModuleBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", ref.Path, maxCascadePolicyModuleBytes)
	}
	src, err := ref.ReadVerified()
	if err != nil {
		return nil, err
	}
	if cascadePolicyCheck != nil {
		if err := cascadePolicyCheck(src); err != nil {
			return nil, fmt.Errorf("rego: %v", err)
		}
	}
	return src, nil
}

func validateCascadeAdmin(a CascadeAdminConfig) error {
	var errs []error
	path := "guardrail.cascade.admin"
	if err := cascadeOneOf(path+".critical_floor", a.CriticalFloor, CascadeLog, CascadeAlert, CascadeConfirm, CascadeBlock); err != nil {
		errs = append(errs, err)
	}
	for _, key := range a.Locked {
		if !cascadeLockable(strings.TrimSpace(key)) {
			errs = append(errs, fmt.Errorf("%s.locked: %q is not a lockable key (%s, or lanes.<lane>)", path, key, strings.Join(CascadeLockableKeys, ", ")))
		}
	}
	return errors.Join(errs...)
}

func cascadeOr(v, def string) string {
	if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
		return v
	}
	return def
}

// EffectiveCascade is the cascade one call decides with: every guardrail.cascade
// value resolved for a connector of a (base or profile-derived)
// configuration, with the System One routing from decision_model.
type EffectiveCascade struct {
	// Unknown is pack, alert, confirm or block.
	Unknown                  string
	JudgeMaxAction           string
	JudgeBlockNeedsSystemOne bool
	JudgeNoVerdict           string
	SystemOneAllowThreshold  float64
	SystemOneBlockThreshold  float64
	SystemOneBlockRiskScore  float64
	SystemOneEscalateFlagged bool
	SystemOneOnUnsure        string
	// Lanes holds every registered lane's value (ResolveCascadeExplained
	// only; a decision reads LaneMode).
	Lanes map[string]string
	// laneScopes are the lane maps of the scopes, widest first.
	laneScopes [4]map[string]string
	nLanes     int
	// PolicyActive: a verified policy module is loaded.
	PolicyActive  bool
	PolicyModule  AssetFileRef
	PolicyLowest  string
	PolicyHighest string
	PolicyTimeout time.Duration
	CriticalFloor string
	Locked        []string
	// Sources maps each value's key to the config path that set it, or
	// "default" (ResolveCascadeExplained only).
	Sources map[string]string
	Invalid *CascadeInvalid
}

// IsDefault reports a cascade that decides exactly as the configuration
// without guardrail.cascade.
func (e EffectiveCascade) IsDefault() bool {
	if e.Unknown != CascadeUnknownPack || e.JudgeMaxAction != CascadeBlock || e.JudgeBlockNeedsSystemOne ||
		e.JudgeNoVerdict != CascadeFromRules || e.SystemOneOnUnsure != CascadeConfirm || e.PolicyActive ||
		e.CriticalFloor != CascadeAlert {
		return false
	}
	for _, lane := range CascadeLanes() {
		if e.LaneMode(lane.Name) != lane.Default {
			return false
		}
	}
	return true
}

// LaneMode is the value of a registered lane (its default when unset); ""
// for a name that is not registered.
func (e EffectiveCascade) LaneMode(name string) string {
	lane, ok := cascadeLane(name)
	if !ok {
		return ""
	}
	for i := e.nLanes - 1; i >= 0; i-- {
		if v, set := e.laneScopes[i][name]; set {
			return cascadeOr(v, CascadeLaneOff)
		}
	}
	return lane.Default
}

// ResolveCascade is the effective cascade for connector ("" for the global
// scope). It reads no file and allocates only when a lane is registered.
func (c *Config) ResolveCascade(connector string) EffectiveCascade {
	return c.resolveCascade(connector, false)
}

// ResolveCascadeExplained is ResolveCascade with Sources filled in.
func (c *Config) ResolveCascadeExplained(connector string) EffectiveCascade {
	return c.resolveCascade(connector, true)
}

func (c *Config) resolveCascade(connector string, explain bool) EffectiveCascade {
	e := EffectiveCascade{
		Unknown:                 CascadeUnknownPack,
		JudgeMaxAction:          CascadeBlock,
		JudgeNoVerdict:          CascadeFromRules,
		SystemOneOnUnsure:       CascadeConfirm,
		CriticalFloor:           CascadeAlert,
		PolicyLowest:            CascadeAlert,
		PolicyHighest:           CascadeBlock,
		PolicyTimeout:           DefaultCascadePolicyTimeout,
		SystemOneAllowThreshold: DefaultDecisionModelAllowThreshold,
		SystemOneBlockThreshold: DefaultDecisionModelBlockThreshold,
		SystemOneBlockRiskScore: DefaultDecisionModelBlockRiskScore,
	}
	e.SystemOneEscalateFlagged = true
	if explain {
		e.Sources = map[string]string{}
	}
	set := func(key, path string) {
		if explain {
			e.Sources[key] = path
		}
	}
	if c == nil {
		return e
	}
	if explain {
		defer func() {
			if lanes := CascadeLanes(); len(lanes) > 0 {
				e.Lanes = make(map[string]string, len(lanes))
				for _, lane := range lanes {
					e.Lanes[lane.Name] = e.LaneMode(lane.Name)
				}
			}
		}()
	}
	dm := c.DecisionModel
	e.SystemOneAllowThreshold = dm.EffectiveAllowThreshold()
	e.SystemOneBlockThreshold = dm.EffectiveBlockThreshold()
	e.SystemOneBlockRiskScore = dm.EffectiveBlockRiskScore()
	e.SystemOneEscalateFlagged = dm.EffectiveEscalateRuleFlagged()
	if explain {
		if dm.AllowThreshold > 0 {
			set("system_one.allow_threshold", "decision_model.allow_threshold")
		}
		if dm.BlockThreshold > 0 {
			set("system_one.block_threshold", "decision_model.block_threshold")
		}
		if dm.BlockRiskScore > 0 {
			set("system_one.block_risk_score", "decision_model.block_risk_score")
		}
		if dm.EscalateRuleFlagged != nil {
			set("system_one.escalate_rule_flagged", "decision_model.escalate_rule_flagged")
		}
	}
	if c.SecureClientIntegration() {
		return e
	}
	g := &c.Guardrail
	top := g.Cascade
	e.Invalid = top.invalid
	e.Locked = top.Admin.Locked
	if v := cascadeOr(top.Admin.CriticalFloor, ""); v != "" {
		e.CriticalFloor = v
		set("critical_floor", "guardrail.cascade.admin.critical_floor")
	}
	if len(top.policySource) > 0 {
		e.PolicyActive = true
		e.PolicyModule = top.Policy.Module
		set("policy.module", "guardrail.cascade.policy.module")
		if v := cascadeOr(top.Policy.Lowest, ""); v != "" {
			e.PolicyLowest = v
			set("policy.lowest", "guardrail.cascade.policy.lowest")
		}
		if v := cascadeOr(top.Policy.Highest, ""); v != "" {
			e.PolicyHighest = v
			set("policy.highest", "guardrail.cascade.policy.highest")
		}
		if top.Policy.TimeoutMs > 0 {
			e.PolicyTimeout = time.Duration(top.Policy.TimeoutMs) * time.Millisecond
			set("policy.timeout_ms", "guardrail.cascade.policy.timeout_ms")
		}
	}
	e.apply(top.scope(), "guardrail.cascade", set)
	if connector = strings.TrimSpace(connector); connector != "" {
		if pc, ok := g.connectorOverride(connector); ok && pc.Cascade != nil {
			e.apply(*pc.Cascade, "guardrail.connectors."+NormalizeConnectorName(connector)+".cascade", set)
		}
	}
	if g.profileCascade != nil {
		e.apply(*g.profileCascade, "guardrail.profiles."+g.profileName+".cascade", set)
	}
	if connector != "" {
		if pc, ok := g.profileConnectors[normalizeConnectorKey(connector)]; ok && pc.Cascade != nil {
			e.apply(*pc.Cascade, "guardrail.profiles."+g.profileName+".connectors."+NormalizeConnectorName(connector)+".cascade", set)
		}
	}
	return e
}

func (e *EffectiveCascade) apply(s CascadeScope, path string, set func(key, path string)) {
	if v := cascadeOr(s.Unknown, ""); v != "" {
		e.Unknown = v
		set("unknown", path+".unknown")
	}
	if v := cascadeOr(s.Judge.MaxAction, ""); v != "" {
		e.JudgeMaxAction = v
		set("judge.max_action", path+".judge.max_action")
	}
	if s.Judge.BlockNeedsSystemOne != nil {
		e.JudgeBlockNeedsSystemOne = *s.Judge.BlockNeedsSystemOne
		set("judge.block_needs_system_one", path+".judge.block_needs_system_one")
	}
	if v := cascadeOr(s.Judge.NoVerdict, ""); v != "" {
		e.JudgeNoVerdict = v
		set("judge.no_verdict", path+".judge.no_verdict")
	}
	so := s.SystemOne
	if so.AllowThreshold > 0 {
		e.SystemOneAllowThreshold = so.AllowThreshold
		set("system_one.allow_threshold", path+".system_one.allow_threshold")
	}
	if so.BlockThreshold > 0 {
		e.SystemOneBlockThreshold = so.BlockThreshold
		set("system_one.block_threshold", path+".system_one.block_threshold")
	}
	if so.BlockRiskScore > 0 {
		e.SystemOneBlockRiskScore = so.BlockRiskScore
		set("system_one.block_risk_score", path+".system_one.block_risk_score")
	}
	if so.EscalateRuleFlagged != nil {
		e.SystemOneEscalateFlagged = *so.EscalateRuleFlagged
		set("system_one.escalate_rule_flagged", path+".system_one.escalate_rule_flagged")
	}
	if v := cascadeOr(so.OnUnsure, ""); v != "" {
		e.SystemOneOnUnsure = v
		set("system_one.on_unsure", path+".system_one.on_unsure")
	}
	if len(s.Lanes) > 0 && e.nLanes < len(e.laneScopes) {
		e.laneScopes[e.nLanes] = s.Lanes
		e.nLanes++
		for name := range s.Lanes {
			set("lanes."+name, path+".lanes."+name)
		}
	}
}

// UnknownAction is the unknown-tier action for a pack tier
// (HookPolicyTier*): the configured value, or the pack's own (strict
// blocks, default and permissive alert).
func (e EffectiveCascade) UnknownAction(packTier string) string {
	if e.Unknown != "" && e.Unknown != CascadeUnknownPack {
		return e.Unknown
	}
	if packTier == HookPolicyTierStrict {
		return CascadeBlock
	}
	return CascadeAlert
}

// cascadeSnapshot is the last-known-good cascade: every scope's cascade and
// the policy module source.
type cascadeSnapshot struct {
	Version      int                      `json:"version"`
	SavedAt      string                   `json:"saved_at"`
	Top          CascadeConfig            `json:"top"`
	Connectors   map[string]*CascadeScope `json:"connectors,omitempty"`
	Profiles     map[string]*CascadeScope `json:"profiles,omitempty"`
	ProfileConns map[string]*CascadeScope `json:"profile_connectors,omitempty"` // "profile/connector"
	PolicySource []byte                   `json:"policy_source,omitempty"`
}

func (c *Config) cascadeSnapshotOf() cascadeSnapshot {
	g := &c.Guardrail
	snap := cascadeSnapshot{Version: 1, Top: g.Cascade, PolicySource: g.Cascade.policySource}
	snap.Top.invalid, snap.Top.policySource = nil, nil
	for name, pc := range g.Connectors {
		if pc.Cascade != nil {
			if snap.Connectors == nil {
				snap.Connectors = map[string]*CascadeScope{}
			}
			snap.Connectors[name] = pc.Cascade
		}
	}
	for name, profile := range g.Profiles {
		if profile.Cascade != nil {
			if snap.Profiles == nil {
				snap.Profiles = map[string]*CascadeScope{}
			}
			snap.Profiles[name] = profile.Cascade
		}
		for cname, pc := range profile.Connectors {
			if pc.Cascade != nil {
				if snap.ProfileConns == nil {
					snap.ProfileConns = map[string]*CascadeScope{}
				}
				snap.ProfileConns[name+"/"+cname] = pc.Cascade
			}
		}
	}
	return snap
}

func (s cascadeSnapshot) isZero() bool {
	return s.Top.IsZero() && len(s.Connectors) == 0 && len(s.Profiles) == 0 && len(s.ProfileConns) == 0
}

// applyCascadeSnapshot sets every scope's cascade from snap (scopes snap does
// not name get none). Connector and profile maps are copied before they are
// written.
func (c *Config) applyCascadeSnapshot(snap cascadeSnapshot) {
	g := &c.Guardrail
	g.Cascade = snap.Top
	g.Cascade.invalid = nil
	g.Cascade.policySource = snap.PolicySource
	if len(g.Connectors) > 0 {
		conns := make(map[string]PerConnectorGuardrailConfig, len(g.Connectors))
		for name, pc := range g.Connectors {
			pc.Cascade = snap.Connectors[name]
			conns[name] = pc
		}
		g.Connectors = conns
	}
	if len(g.Profiles) > 0 {
		profiles := make(map[string]GuardrailProfile, len(g.Profiles))
		for name, profile := range g.Profiles {
			profile.Cascade = snap.Profiles[name]
			if len(profile.Connectors) > 0 {
				conns := make(map[string]PerConnectorGuardrailConfig, len(profile.Connectors))
				for cname, pc := range profile.Connectors {
					pc.Cascade = snap.ProfileConns[name+"/"+cname]
					conns[cname] = pc
				}
				profile.Connectors = conns
			}
			profiles[name] = profile
		}
		g.Profiles = profiles
	}
}

func cascadeLastGoodPath(c *Config) string {
	if c == nil || strings.TrimSpace(c.DataDir) == "" {
		return ""
	}
	return filepath.Join(c.DataDir, CascadeLastGoodFile)
}

// WriteCascadeLastGood keeps the cascade of a configuration the gateway
// published as the last-known-good fallback, or removes it when the cascade
// is empty (an empty cascade is the pack defaults). It never writes for an
// invalid cascade or under the Secure Client integration.
func WriteCascadeLastGood(c *Config) error {
	path := cascadeLastGoodPath(c)
	if path == "" || c.Guardrail.Cascade.invalid != nil || c.SecureClientIntegration() {
		return nil
	}
	snap := c.cascadeSnapshotOf()
	if snap.isZero() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if old, err := os.ReadFile(path); err == nil {
		var prev cascadeSnapshot
		if json.Unmarshal(old, &prev) == nil {
			prev.SavedAt = ""
			cmpA, _ := json.Marshal(prev)
			cmpB, _ := json.Marshal(snap)
			if string(cmpA) == string(cmpB) {
				return nil
			}
		}
	}
	snap.SavedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// applyCascadeFallback replaces an invalid cascade (err) with the
// last-known-good one, when one was saved and still validates, else with
// the pack defaults (no cascade settings), and records why.
func (c *Config) applyCascadeFallback(err error) {
	intended := c.cascadeSnapshotOf()
	invalid := &CascadeInvalid{Error: err.Error(), Fallback: CascadeFallbackPack}
	var applied bool
	if path := cascadeLastGoodPath(c); path != "" {
		if raw, readErr := os.ReadFile(path); readErr == nil {
			var snap cascadeSnapshot
			if json.Unmarshal(raw, &snap) == nil && snap.Version == 1 {
				trial := *c
				trial.applyCascadeSnapshot(snap)
				trial.cascadeOverlayViolations(true)
				if trial.validateCascadeSnapshot() == nil {
					c.applyCascadeSnapshot(snap)
					invalid.Fallback = CascadeFallbackLastGood
					invalid.SavedAt = snap.SavedAt
					applied = true
				}
			}
		}
	}
	if !applied {
		c.applyCascadeSnapshot(cascadeSnapshot{})
	}
	invalid.Weaker = cascadeWeaker(intended, c)
	c.Guardrail.Cascade.invalid = invalid
}

// validateCascadeSnapshot validates a restored top-level cascade, compiling
// its saved module source instead of reading the file. Its narrower scopes
// are enforced, not validated (cascadeOverlayViolations).
func (c *Config) validateCascadeSnapshot() error {
	if err := c.validateCascadeTop(false); err != nil {
		return err
	}
	src := c.Guardrail.Cascade.policySource
	if c.Guardrail.Cascade.Policy.Module.IsZero() != (len(src) == 0) {
		return errors.New("last-known-good policy module is missing")
	}
	if len(src) > 0 && cascadePolicyCheck != nil {
		return cascadePolicyCheck(src)
	}
	return nil
}

// cascadeWeaker lists what the intended (invalid) cascade asked for that the
// fallback in c does not give, at every scope: a stricter unknown tier,
// judge role, no-verdict or on_unsure handling, a lane further on, a
// policy module, tighter policy limits, a CRITICAL floor, locks.
func cascadeWeaker(intended cascadeSnapshot, c *Config) []string {
	got := c.cascadeSnapshotOf()
	var out []string
	want, have := intended.Top, c.Guardrail.Cascade
	out = append(out, weakerScope("guardrail.cascade", want.scope(), have.scope())...)
	if r := CascadeActionRank(want.Admin.CriticalFloor); r > CascadeActionRank(cascadeOr(have.Admin.CriticalFloor, CascadeAlert)) {
		out = append(out, fmt.Sprintf("admin.critical_floor %s is not in effect", want.Admin.CriticalFloor))
	}
	if !want.Policy.Module.IsZero() {
		running := have.Policy.Module == want.Policy.Module && len(have.policySource) > 0
		if !running {
			out = append(out, "the Rego policy you configured is not running")
		} else {
			if CascadeActionRank(cascadeOr(want.Policy.Lowest, CascadeAlert)) > CascadeActionRank(cascadeOr(have.Policy.Lowest, CascadeAlert)) {
				out = append(out, "policy.lowest "+cascadeOr(want.Policy.Lowest, CascadeAlert)+" is not in effect")
			}
			if CascadeActionRank(cascadeOr(want.Policy.Highest, CascadeBlock)) > CascadeActionRank(cascadeOr(have.Policy.Highest, CascadeBlock)) {
				out = append(out, "policy.highest "+cascadeOr(want.Policy.Highest, CascadeBlock)+" is not in effect")
			}
		}
	}
	for _, key := range want.Admin.Locked {
		if !slices.Contains(have.Admin.Locked, key) && !have.Admin.locked(strings.TrimSpace(key)) {
			out = append(out, "admin.locked "+key+" is not enforced")
		}
	}
	scopes := []struct {
		prefix, suffix string
		want, have     map[string]*CascadeScope
	}{
		{"guardrail.connectors.", ".cascade", intended.Connectors, got.Connectors},
		{"guardrail.profiles.", ".cascade", intended.Profiles, got.Profiles},
		{"guardrail.profiles.", ".cascade", intended.ProfileConns, got.ProfileConns},
	}
	for _, sc := range scopes {
		for _, name := range sortedKeys(sc.want) {
			w := sc.want[name]
			if w == nil {
				continue
			}
			h := CascadeScope{}
			if p := sc.have[name]; p != nil {
				h = *p
			}
			path := sc.prefix + name + sc.suffix
			if p, conn, ok := strings.Cut(name, "/"); ok {
				path = "guardrail.profiles." + p + ".connectors." + conn + ".cascade"
			}
			out = append(out, weakerScope(path, *w, h)...)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// weakerScope lists the keys of one scope where have does less than want.
// An unset value counts as its default.
func weakerScope(path string, want, have CascadeScope) []string {
	var out []string
	note := func(key, value string) {
		out = append(out, path+"."+key+" "+value+" is not in effect")
	}
	if u := cascadeOr(want.Unknown, ""); u != "" && meetCascadeRank(u) > meetCascadeRank(cascadeOr(have.Unknown, CascadeUnknownPack)) {
		note("unknown", u)
	}
	if m := cascadeOr(want.Judge.MaxAction, ""); m != "" && CascadeActionRank(m) > CascadeActionRank(cascadeOr(have.Judge.MaxAction, CascadeBlock)) {
		note("judge.max_action", m)
	}
	if want.Judge.BlockNeedsSystemOne != nil && !*want.Judge.BlockNeedsSystemOne && have.Judge.BlockNeedsSystemOne != nil && *have.Judge.BlockNeedsSystemOne {
		note("judge.block_needs_system_one", "false")
	}
	if cascadeOr(want.Judge.NoVerdict, "") == CascadeNoVerdictUnknown && cascadeOr(have.Judge.NoVerdict, CascadeFromRules) != CascadeNoVerdictUnknown {
		note("judge.no_verdict", CascadeNoVerdictUnknown)
	}
	onUnsure := func(v string) int {
		switch cascadeOr(v, CascadeConfirm) {
		case CascadeConfirm:
			return 2
		case CascadeAlert:
			return 1
		}
		return 0
	}
	if o := cascadeOr(want.SystemOne.OnUnsure, ""); o != "" && onUnsure(o) > onUnsure(have.SystemOne.OnUnsure) {
		note("system_one.on_unsure", o)
	}
	for _, name := range sortedKeys(want.Lanes) {
		v := cascadeOr(want.Lanes[name], CascadeLaneOff)
		h := ""
		if have.Lanes != nil {
			h = have.Lanes[name]
		}
		if h == "" {
			if lane, ok := cascadeLane(name); ok {
				h = lane.Default
			}
		}
		if laneRank(v) > laneRank(cascadeOr(h, CascadeLaneOff)) {
			note("lanes."+name, v)
		}
	}
	return out
}

// loadCascade validates the cascade a load decoded, keeps the verified
// policy module, and makes sure no narrower scope weakens the
// administrator's cascade: a locked value or an invalid connector or
// profile cascade is ignored and named (Ignored), and only an invalid
// top-level cascade is replaced by its fallback. The full error of the
// document as written is kept for the writers (CascadeCandidateError).
func (c *Config) loadCascade() {
	if c == nil {
		return
	}
	strict := c.ValidateCascade(true)
	defer func() { c.Guardrail.Cascade.candidateErr = strict }()
	if c.SecureClientIntegration() {
		if strict != nil {
			c.applyCascadeFallback(strict)
		}
		return
	}
	ignored := c.cascadeOverlayViolations(true)
	var err error
	if strict != nil {
		err = c.validateCascadeTop(true)
	}
	if err == nil {
		if ref := c.Guardrail.Cascade.Policy.Module; !ref.IsZero() {
			src, readErr := readCascadeModule(ref)
			if readErr != nil {
				err = fmt.Errorf("guardrail.cascade.policy.module: %v", readErr)
			} else {
				c.Guardrail.Cascade.policySource = src
			}
		}
	}
	if err != nil {
		c.applyCascadeFallback(err)
		// The fallback restores the scopes it saved, under its own locks.
		for _, ig := range c.cascadeOverlayViolations(true) {
			if !slices.Contains(ignored, ig) {
				ignored = append(ignored, ig)
			}
		}
	}
	c.Guardrail.Cascade.ignored = ignored
}

// meetCascadeRank orders unknown-tier values for a profile meet: the pack's
// own tier sits between alert and confirm.
func meetCascadeRank(v string) int {
	switch v {
	case "", CascadeUnknownPack:
		return 2
	case CascadeAlert:
		return 1
	}
	return CascadeActionRank(v)
}

func laneRank(v string) int {
	switch v {
	case CascadeLaneBlock:
		return 3
	case CascadeLaneOn, CascadeLaneAlert:
		return 2
	case CascadeLaneShadow:
		return 1
	}
	return 0
}

// strictestCascadeScope is the cascade of a profile meet: per key the
// strictest of the members' values, an unset value counting as its default
// (unknown: the higher tier, a pack tier between alert and confirm; the
// judge's max_action the higher; block_needs_system_one only when every
// member sets it; no_verdict unknown when any member does; on_unsure the
// stronger of confirm, alert, rules; each lane the furthest of off, shadow,
// on). System One routing overrides are not merged: a meet routes with
// decision_model. nil when no member sets a cascade.
func strictestCascadeScope(members []*CascadeScope) *CascadeScope {
	set := false
	for _, m := range members {
		if m != nil && !m.IsZero() {
			set = true
		}
	}
	if !set {
		return nil
	}
	out := CascadeScope{Unknown: CascadeAlert, Judge: CascadeJudgeConfig{MaxAction: CascadeLog, NoVerdict: CascadeFromRules},
		SystemOne: CascadeSystemOneConfig{OnUnsure: CascadeFromRules}}
	needs := true
	onUnsure := func(v string) int {
		switch cascadeOr(v, CascadeConfirm) {
		case CascadeConfirm:
			return 2
		case CascadeAlert:
			return 1
		}
		return 0
	}
	for _, m := range members {
		s := CascadeScope{}
		if m != nil {
			s = *m
		}
		if meetCascadeRank(cascadeOr(s.Unknown, "")) > meetCascadeRank(out.Unknown) {
			out.Unknown = cascadeOr(s.Unknown, CascadeUnknownPack)
		}
		if r := CascadeActionRank(cascadeOr(s.Judge.MaxAction, CascadeBlock)); r > CascadeActionRank(out.Judge.MaxAction) {
			out.Judge.MaxAction = CascadeActionName(r)
		}
		if s.Judge.BlockNeedsSystemOne == nil || !*s.Judge.BlockNeedsSystemOne {
			needs = false
		}
		if cascadeOr(s.Judge.NoVerdict, "") == CascadeNoVerdictUnknown {
			out.Judge.NoVerdict = CascadeNoVerdictUnknown
		}
		if onUnsure(s.SystemOne.OnUnsure) > onUnsure(out.SystemOne.OnUnsure) {
			out.SystemOne.OnUnsure = cascadeOr(s.SystemOne.OnUnsure, CascadeConfirm)
		}
		for _, lane := range CascadeLanes() {
			v := lane.Default
			if value, ok := s.Lanes[lane.Name]; ok {
				v = cascadeOr(value, CascadeLaneOff)
			}
			if out.Lanes == nil {
				out.Lanes = map[string]string{}
			}
			if cur, ok := out.Lanes[lane.Name]; !ok || laneRank(v) > laneRank(cur) {
				out.Lanes[lane.Name] = v
			}
		}
	}
	if needs {
		t := true
		out.Judge.BlockNeedsSystemOne = &t
	}
	return &out
}

// meetCascadeScopes resolves each member's profile-level cascade and, for a
// connector, its profile connectors[c] cascade over it ("" for the profile
// level). A member that is not a profile (the base configuration) has no
// profile scope.
func (c *Config) meetCascadeScopes(members []string, connector string) []*CascadeScope {
	out := make([]*CascadeScope, 0, len(members))
	for _, name := range members {
		profile, ok := c.Guardrail.Profiles[name]
		if !ok {
			out = append(out, nil)
			continue
		}
		scope := CascadeScope{}
		if profile.Cascade != nil {
			scope = *profile.Cascade
		}
		if connector != "" {
			for cname, pc := range profile.Connectors {
				if normalizeConnectorKey(cname) == connector && pc.Cascade != nil {
					scope = overlayCascadeScope(scope, *pc.Cascade)
				}
			}
		}
		out = append(out, &scope)
	}
	return out
}

// overlayCascadeScope writes every set outcome key of src over dst.
func overlayCascadeScope(dst, src CascadeScope) CascadeScope {
	if src.Unknown != "" {
		dst.Unknown = src.Unknown
	}
	if src.Judge.MaxAction != "" {
		dst.Judge.MaxAction = src.Judge.MaxAction
	}
	if src.Judge.BlockNeedsSystemOne != nil {
		dst.Judge.BlockNeedsSystemOne = src.Judge.BlockNeedsSystemOne
	}
	if src.Judge.NoVerdict != "" {
		dst.Judge.NoVerdict = src.Judge.NoVerdict
	}
	if src.SystemOne.OnUnsure != "" {
		dst.SystemOne.OnUnsure = src.SystemOne.OnUnsure
	}
	if len(src.Lanes) > 0 {
		lanes := make(map[string]string, len(dst.Lanes)+len(src.Lanes))
		for k, v := range dst.Lanes {
			lanes[k] = v
		}
		for k, v := range src.Lanes {
			lanes[k] = v
		}
		dst.Lanes = lanes
	}
	return dst
}

// withMeetCascade sets the meet profile's cascade from its members.
func (c *Config) withMeetCascade(members []string, profile GuardrailProfile) GuardrailProfile {
	profile.Cascade = strictestCascadeScope(c.meetCascadeScopes(members, ""))
	if len(profile.Connectors) > 0 {
		conns := make(map[string]PerConnectorGuardrailConfig, len(profile.Connectors))
		for name, pc := range profile.Connectors {
			pc.Cascade = strictestCascadeScope(c.meetCascadeScopes(members, normalizeConnectorKey(name)))
			conns[name] = pc
		}
		profile.Connectors = conns
	}
	return profile
}

// CascadeUnknown is the unknown tier guardrail.cascade sets for connector of
// this (base or profile-derived) guardrail block: pack, alert, confirm or
// block. Under the Secure Client integration callers do not ask.
func (g *GuardrailConfig) CascadeUnknown(connector string) string {
	if g == nil {
		return CascadeUnknownPack
	}
	u := cascadeOr(g.Cascade.Unknown, CascadeUnknownPack)
	if connector = strings.TrimSpace(connector); connector != "" {
		if pc, ok := g.connectorOverride(connector); ok && pc.Cascade != nil && pc.Cascade.Unknown != "" {
			u = cascadeOr(pc.Cascade.Unknown, u)
		}
	}
	if g.profileCascade != nil && g.profileCascade.Unknown != "" {
		u = cascadeOr(g.profileCascade.Unknown, u)
	}
	if connector != "" {
		if pc, ok := g.profileConnectors[normalizeConnectorKey(connector)]; ok && pc.Cascade != nil && pc.Cascade.Unknown != "" {
			u = cascadeOr(pc.Cascade.Unknown, u)
		}
	}
	return u
}
