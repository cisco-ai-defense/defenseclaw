// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Identity-based guardrail profiles.
//
// A profile is a named set of guardrail policy overrides that applies to the
// subjects an ordered list of assignments selects:
//
//	guardrail:
//	  profiles:
//	    contractors: {mode: action, block_at: medium, connectors: {codex: {mode: observe}}}
//	  profile_assignments:          # ordered, first match wins; keys AND, values OR
//	    - {profile: contractors, match: {groups: ["CORP\\Contractors"]}}
//	  default_profile: ""           # "" keeps today's guardrail.* behaviour
//
// Precedence for a decision governed by a profile:
// profile.connectors[c] > profile field > guardrail.connectors[c] >
// application_protection overlay > global guardrail.*.
//
// Only verified subjects (a kernel- or credential-verified user and the
// directory facts resolved for it) select a profile. Headers, hook payloads
// and claimed facts never do. Profiles are rejected outright under the
// Secure Client integration, so that deployment is unchanged.

// GuardrailProfile is one entry of guardrail.profiles. Every field is
// optional; an unset field inherits through the precedence chain above.
type GuardrailProfile struct {
	// Description is free text shown by `defenseclaw guardrail profile`.
	Description string `mapstructure:"description" yaml:"description,omitempty"`
	// Mode is "observe" or "action"; empty inherits.
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// BlockAt and AlertAt are the lowest severities that block and alert
	// (CRITICAL, HIGH, MEDIUM or LOW in any case); empty inherits.
	BlockAt string `mapstructure:"block_at" yaml:"block_at,omitempty"`
	AlertAt string `mapstructure:"alert_at" yaml:"alert_at,omitempty"`
	// HILT overrides the human-in-the-loop block; nil inherits.
	HILT *HILTConfig `mapstructure:"hilt" yaml:"hilt,omitempty"`
	// RulePackDir selects a rule pack for subjects of this profile; empty
	// inherits.
	RulePackDir string `mapstructure:"rule_pack_dir" yaml:"rule_pack_dir,omitempty"`
	// BlockMessage overrides the message shown when a decision blocks.
	BlockMessage string `mapstructure:"block_message" yaml:"block_message,omitempty"`
	// Connectors holds per-connector overrides inside the profile, keyed by
	// connector name. Their enabled and hook_fail_mode keys are rejected
	// like the profile's own.
	Connectors map[string]PerConnectorGuardrailConfig `mapstructure:"connectors" yaml:"connectors,omitempty"`

	// Enabled and HookFailMode are NOT allowed in a profile: both are baked
	// into the hooks installed on the machine, so they cannot vary by
	// subject. The fields exist only so Validate can reject them with a
	// clear message; the v8 schema rejects them too.
	Enabled      *bool  `mapstructure:"enabled" yaml:"enabled,omitempty"`
	HookFailMode string `mapstructure:"hook_fail_mode" yaml:"hook_fail_mode,omitempty"`
}

// ProfileAssignment is one entry of guardrail.profile_assignments. The list
// is ordered and the first assignment whose Match selects the subject wins.
type ProfileAssignment struct {
	// Profile names an entry of guardrail.profiles.
	Profile string `mapstructure:"profile" yaml:"profile"`
	// Match selects the subjects the profile applies to.
	Match ProfileMatch `mapstructure:"match" yaml:"match"`
}

// ProfileMatch selects subjects. Set keys combine with AND and the values of
// one key combine with OR; at least one key must be set. Groups and Users
// compare against verified directory facts only.
type ProfileMatch struct {
	// Groups are directory groups: DOMAIN\Group names, group names, or SIDs
	// (including Entra S-1-12-1-... SIDs).
	Groups []string `mapstructure:"groups" yaml:"groups,omitempty"`
	// Users are principals (UPN or DOMAIN\user), account names, uids or
	// SIDs.
	Users []string `mapstructure:"users" yaml:"users,omitempty"`
	// Connectors are connector names, for example codex or claudecode.
	Connectors []string `mapstructure:"connectors" yaml:"connectors,omitempty"`
	// Agents are stable agent identities (defenseclaw.agent.identity.id,
	// "agt-" followed by 16 hex digits).
	Agents []string `mapstructure:"agents" yaml:"agents,omitempty"`
}

// Empty reports whether no selector key is set.
func (m ProfileMatch) Empty() bool {
	return len(m.Groups) == 0 && len(m.Users) == 0 && len(m.Connectors) == 0 && len(m.Agents) == 0
}

// HasProfiles reports whether any profile configuration is present.
func (g *GuardrailConfig) HasProfiles() bool {
	return g != nil && (len(g.Profiles) > 0 || len(g.ProfileAssignments) > 0 || strings.TrimSpace(g.DefaultProfile) != "")
}

var (
	guardrailProfileNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	agentIdentityPattern        = regexp.MustCompile(`^agt-[0-9a-f]{16}$`)
)

// errProfileForbiddenKey explains why enabled and hook_fail_mode cannot live
// in a profile.
const errProfileForbiddenKey = "is not allowed in a guardrail profile (it is baked into the installed hooks); set it on guardrail or guardrail.connectors instead"

// ValidateGuardrailProfiles checks guardrail.profiles,
// guardrail.profile_assignments and guardrail.default_profile. It runs at
// load, after GuardrailConfig.Validate, because the Secure Client rejection
// needs the deployment profile.
func (c *Config) ValidateGuardrailProfiles() error {
	if c == nil {
		return nil
	}
	return c.Guardrail.validateProfiles(c.SecureClientIntegration())
}

func (g *GuardrailConfig) validateProfiles(secureClient bool) error {
	if !g.HasProfiles() {
		return nil
	}
	if secureClient {
		return errors.New("guardrail.profiles, guardrail.profile_assignments and guardrail.default_profile are not supported with the Secure Client integration")
	}
	names := make([]string, 0, len(g.Profiles))
	for name := range g.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !guardrailProfileNamePattern.MatchString(name) {
			return fmt.Errorf("guardrail.profiles: invalid profile name %q (want lowercase letters, digits, '-' or '_', at most 64)", name)
		}
		if err := g.Profiles[name].validate(); err != nil {
			return fmt.Errorf("guardrail.profiles[%q]: %w", name, err)
		}
	}
	for i, assignment := range g.ProfileAssignments {
		if _, ok := g.Profiles[assignment.Profile]; !ok {
			return fmt.Errorf("guardrail.profile_assignments[%d]: unknown profile %q", i, assignment.Profile)
		}
		if assignment.Match.Empty() {
			return fmt.Errorf("guardrail.profile_assignments[%d]: match needs at least one of groups, users, connectors or agents; use guardrail.default_profile for everyone else", i)
		}
		for _, agent := range assignment.Match.Agents {
			if !agentIdentityPattern.MatchString(agent) {
				return fmt.Errorf("guardrail.profile_assignments[%d].match.agents: %q is not an agent identity (want agt- followed by 16 hex digits)", i, agent)
			}
		}
	}
	if def := strings.TrimSpace(g.DefaultProfile); def != "" {
		if _, ok := g.Profiles[def]; !ok {
			return fmt.Errorf("guardrail.default_profile: unknown profile %q", def)
		}
	}
	return nil
}

func (p GuardrailProfile) validate() error {
	if p.Enabled != nil {
		return errors.New("enabled " + errProfileForbiddenKey)
	}
	if p.HookFailMode != "" {
		return errors.New("hook_fail_mode " + errProfileForbiddenKey)
	}
	if err := validateGuardrailMode(p.Mode); err != nil {
		return err
	}
	if err := validateGuardrailLevel("block_at", p.BlockAt); err != nil {
		return err
	}
	if err := validateGuardrailLevel("alert_at", p.AlertAt); err != nil {
		return err
	}
	if p.HILT != nil {
		if err := validateGuardrailMinSeverity(p.HILT.MinSeverity); err != nil {
			return err
		}
	}
	connectors := make([]string, 0, len(p.Connectors))
	for name := range p.Connectors {
		connectors = append(connectors, name)
	}
	sort.Strings(connectors)
	seen := make(map[string]string, len(connectors))
	for _, name := range connectors {
		if strings.TrimSpace(name) == "" {
			return errors.New("connectors: empty connector name is not allowed")
		}
		if norm := normalizeConnectorKey(name); norm != "" {
			if prev, dup := seen[norm]; dup {
				return fmt.Errorf("connectors: %q and %q refer to the same connector %q; keep only one", prev, name, norm)
			}
			seen[norm] = name
		}
		pc := p.Connectors[name]
		if pc.Enabled != nil {
			return fmt.Errorf("connectors[%q]: enabled %s", name, errProfileForbiddenKey)
		}
		if pc.HookFailMode != "" {
			return fmt.Errorf("connectors[%q]: hook_fail_mode %s", name, errProfileForbiddenKey)
		}
		if err := validateGuardrailMode(pc.Mode); err != nil {
			return fmt.Errorf("connectors[%q]: %w", name, err)
		}
		if err := validateGuardrailLevel("block_at", pc.BlockAt); err != nil {
			return fmt.Errorf("connectors[%q]: %w", name, err)
		}
		if err := validateGuardrailLevel("alert_at", pc.AlertAt); err != nil {
			return fmt.Errorf("connectors[%q]: %w", name, err)
		}
		if pc.HILT != nil {
			if err := validateGuardrailMinSeverity(pc.HILT.MinSeverity); err != nil {
				return fmt.Errorf("connectors[%q]: %w", name, err)
			}
		}
	}
	return nil
}

// DerivedForProfile returns the effective configuration for subjects of the
// named profile: a deep copy of c with the profile's overrides applied. The
// empty name returns c unchanged.
//
// Every set profile field is written over guardrail.*, over every
// guardrail.connectors entry, and over application_protection.guardrail and
// its connector overlays, so the existing Effective*ForConnector resolvers
// yield the documented precedence:
//
//	profile.connectors[c] > profile field > guardrail.connectors[c] >
//	application_protection overlay > global guardrail.*
//
// profile.connectors[c] is layered by the resolvers themselves
// (policyOverride), so a profile can tune a connector without making it a
// member of guardrail.connectors. A profile mode also replaces the legacy
// per-connector hook mode (claude_code.mode, codex.mode, connector_hooks)
// for its subjects. enabled and hook_fail_mode are never copied: both are
// baked into the installed hooks. Connector membership, enablement and hook
// fail mode therefore keep reading the base configuration.
//
// The result is read-only. It must not be cloned through YAML or JSON, which
// drops the unexported profile connector layer.
func (c *Config) DerivedForProfile(name string) (*Config, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return c, nil
	}
	if c == nil {
		return nil, fmt.Errorf("guardrail profile %q: configuration is unavailable", name)
	}
	profile, ok := c.Guardrail.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("guardrail profile %q is not defined", name)
	}
	out, err := copyConfigSharingProfiles(c)
	if err != nil {
		return nil, fmt.Errorf("guardrail profile %q: %w", name, err)
	}
	applyGuardrailProfile(out, profile)
	return out, nil
}

// DerivedGuardrailProfile is one precomputed profile: its derived
// configuration and the digest of its derived guardrail policy.
type DerivedGuardrailProfile struct {
	Name   string
	Config *Config
	Digest string
}

// DeriveGuardrailProfiles derives every profile in guardrail.profiles. The
// gateway calls it at load and on every reload; nil means no profiles.
func (c *Config) DeriveGuardrailProfiles() (map[string]DerivedGuardrailProfile, error) {
	if c == nil || len(c.Guardrail.Profiles) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(c.Guardrail.Profiles))
	for name := range c.Guardrail.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(map[string]DerivedGuardrailProfile, len(names))
	for _, name := range names {
		derived, err := c.DerivedForProfile(name)
		if err != nil {
			return nil, err
		}
		digest, err := GuardrailPolicyDigest(derived)
		if err != nil {
			return nil, fmt.Errorf("guardrail profile %q: %w", name, err)
		}
		out[name] = DerivedGuardrailProfile{Name: name, Config: derived, Digest: digest}
	}
	return out, nil
}

// guardrailPolicyDigestView is the canonical form of a derived guardrail
// block that a profile digest covers: every value a profile can change and
// every value it inherits from. Secret-bearing guardrail settings (the
// upstream and judge LLM blocks) are deliberately left out, so a digest never
// commits to a credential.
type guardrailPolicyDigestView struct {
	Version           int                                    `json:"v"`
	Mode              string                                 `json:"mode"`
	BlockAt           string                                 `json:"block_at"`
	AlertAt           string                                 `json:"alert_at"`
	HILT              HILTConfig                             `json:"hilt"`
	RulePackDir       string                                 `json:"rule_pack_dir"`
	BlockMessage      string                                 `json:"block_message"`
	Connectors        map[string]PerConnectorGuardrailConfig `json:"connectors"`
	ProfileConnectors map[string]PerConnectorGuardrailConfig `json:"profile_connectors"`
	AutoProtection    PerConnectorGuardrailConfig            `json:"application_protection"`
	AutoConnectors    map[string]PerConnectorGuardrailConfig `json:"application_protection_connectors"`
	HookModes         map[string]string                      `json:"hook_modes"`
}

// GuardrailPolicyDigest returns "sha256:" + the hex SHA-256 of the canonical
// JSON of cfg's guardrail policy (see guardrailPolicyDigestView). Map keys
// marshal sorted and struct fields in declaration order, so equal policies
// always yield the same digest.
func GuardrailPolicyDigest(cfg *Config) (string, error) {
	if cfg == nil {
		return "", errors.New("guardrail policy digest: configuration is unavailable")
	}
	g := cfg.Guardrail
	view := guardrailPolicyDigestView{
		Version:        1,
		Mode:           strings.TrimSpace(g.Mode),
		BlockAt:        canonicalGuardrailLevel(g.BlockAt),
		AlertAt:        canonicalGuardrailLevel(g.AlertAt),
		HILT:           g.HILT,
		RulePackDir:    g.RulePackDir,
		BlockMessage:   g.BlockMessage,
		Connectors:     g.Connectors,
		AutoProtection: cfg.ApplicationProtection.Guardrail,
		HookModes: map[string]string{
			"claude_code": cfg.ClaudeCode.Mode,
			"codex":       cfg.Codex.Mode,
		},
	}
	if len(g.profileConnectors) > 0 {
		view.ProfileConnectors = g.profileConnectors
	}
	if len(cfg.ApplicationProtection.Connectors) > 0 {
		view.AutoConnectors = make(map[string]PerConnectorGuardrailConfig, len(cfg.ApplicationProtection.Connectors))
		for name, pc := range cfg.ApplicationProtection.Connectors {
			view.AutoConnectors[name] = pc.Guardrail
		}
	}
	for name, hook := range cfg.ConnectorHooks {
		view.HookModes["connector_hooks."+name] = hook.Mode
	}
	data, err := json.Marshal(view)
	if err != nil {
		return "", fmt.Errorf("guardrail policy digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// policyFields returns the profile's policy fields in the per-connector
// shape the overlay helpers take.
func (p GuardrailProfile) policyFields() PerConnectorGuardrailConfig {
	return PerConnectorGuardrailConfig{
		Mode:         p.Mode,
		HILT:         p.HILT,
		BlockMessage: p.BlockMessage,
		RulePackDir:  p.RulePackDir,
		BlockAt:      p.BlockAt,
		AlertAt:      p.AlertAt,
	}
}

// overlayGuardrailPolicy writes every set policy field of src over dst.
// withLevels false skips block_at and alert_at, which the
// application_protection overlays do not support. enabled and
// hook_fail_mode are never copied.
func overlayGuardrailPolicy(dst, src PerConnectorGuardrailConfig, withLevels bool) PerConnectorGuardrailConfig {
	if mode := strings.TrimSpace(src.Mode); mode != "" {
		dst.Mode = mode
	}
	if src.HILT != nil {
		hilt := *src.HILT
		dst.HILT = &hilt
	}
	if src.BlockMessage != "" {
		dst.BlockMessage = src.BlockMessage
	}
	if strings.TrimSpace(src.RulePackDir) != "" {
		dst.RulePackDir = src.RulePackDir
	}
	if withLevels {
		if level := canonicalGuardrailLevel(src.BlockAt); level != "" {
			dst.BlockAt = level
		}
		if level := canonicalGuardrailLevel(src.AlertAt); level != "" {
			dst.AlertAt = level
		}
	}
	return dst
}

// applyGuardrailProfile writes profile over a deep copy (see
// DerivedForProfile).
func applyGuardrailProfile(out *Config, profile GuardrailProfile) {
	fields := profile.policyFields()
	g := &out.Guardrail
	if mode := strings.TrimSpace(fields.Mode); mode != "" {
		g.Mode = mode
	}
	if fields.HILT != nil {
		g.HILT = *fields.HILT
	}
	if fields.BlockMessage != "" {
		g.BlockMessage = fields.BlockMessage
	}
	if strings.TrimSpace(fields.RulePackDir) != "" {
		g.RulePackDir = fields.RulePackDir
	}
	if level := canonicalGuardrailLevel(fields.BlockAt); level != "" {
		g.BlockAt = level
	}
	if level := canonicalGuardrailLevel(fields.AlertAt); level != "" {
		g.AlertAt = level
	}
	for name, pc := range g.Connectors {
		g.Connectors[name] = overlayGuardrailPolicy(pc, fields, true)
	}
	ap := &out.ApplicationProtection
	ap.Guardrail = overlayGuardrailPolicy(ap.Guardrail, fields, false)
	for name, pc := range ap.Connectors {
		pc.Guardrail = overlayGuardrailPolicy(pc.Guardrail, fields, false)
		ap.Connectors[name] = pc
	}
	if strings.TrimSpace(fields.Mode) != "" {
		clearHookModes(out, "")
	}
	g.profileConnectors = nil
	for name, pc := range profile.Connectors {
		key := normalizeConnectorKey(name)
		if key == "" {
			continue
		}
		if g.profileConnectors == nil {
			g.profileConnectors = make(map[string]PerConnectorGuardrailConfig, len(profile.Connectors))
		}
		g.profileConnectors[key] = overlayGuardrailPolicy(PerConnectorGuardrailConfig{}, pc, true)
		if strings.TrimSpace(pc.Mode) != "" {
			clearHookModes(out, key)
		}
	}
}

// clearHookModes resets the legacy per-connector hook mode (claude_code.mode,
// codex.mode, connector_hooks.<c>.mode) to inherit, for one normalized
// connector or, with "", for all, so the guardrail chain carrying the
// profile's mode decides.
func clearHookModes(out *Config, connector string) {
	if connector == "" || connector == "claudecode" {
		out.ClaudeCode.Mode = ""
	}
	if connector == "" || connector == "codex" {
		out.Codex.Mode = ""
	}
	for name, hook := range out.ConnectorHooks {
		if connector == "" || normalizeConnectorKey(name) == connector {
			hook.Mode = ""
			out.ConnectorHooks[name] = hook
		}
	}
}

// policyOverride is connectorOverride plus, on a derived configuration, the
// profile's own connectors[c] entry, which wins field by field. Connector
// membership (HasConnector), enablement and hook fail mode keep reading
// connectorOverride: a profile never changes which hooks are installed.
func (g *GuardrailConfig) policyOverride(connector string) (PerConnectorGuardrailConfig, bool) {
	pc, ok := g.connectorOverride(connector)
	if g == nil || len(g.profileConnectors) == 0 {
		return pc, ok
	}
	if profile, hit := g.profileConnectors[normalizeConnectorKey(connector)]; hit && strings.TrimSpace(connector) != "" {
		return overlayGuardrailPolicy(pc, profile, true), true
	}
	return pc, ok
}

// profileConnectorOverlay layers the profile's connectors[c] entry over an
// application_protection overlay. block_at and alert_at stay with the
// guardrail chain, which reads them through policyOverride.
func (g *GuardrailConfig) profileConnectorOverlay(connector string, overlay PerConnectorGuardrailConfig) PerConnectorGuardrailConfig {
	if g == nil || len(g.profileConnectors) == 0 || strings.TrimSpace(connector) == "" {
		return overlay
	}
	if profile, hit := g.profileConnectors[normalizeConnectorKey(connector)]; hit {
		return overlayGuardrailPolicy(overlay, profile, false)
	}
	return overlay
}

// copyConfigSharingProfiles is deepCopyConfig for a derived configuration:
// the copy shares c's profile table and assignments instead of copying
// them. A derived configuration is read-only, and the copy used to carry
// every profile again, so deriving P profiles copied P tables of P
// profiles (500 profiles took 4 s, 1000 took 17 s and 2000 took 68 s, at
// every start and reload of the gateway).
func copyConfigSharingProfiles(c *Config) (*Config, error) {
	slim := *c
	slim.Guardrail.Profiles, slim.Guardrail.ProfileAssignments = nil, nil
	out, err := deepCopyConfig(&slim)
	if err != nil {
		return nil, err
	}
	out.Guardrail.Profiles, out.Guardrail.ProfileAssignments = c.Guardrail.Profiles, c.Guardrail.ProfileAssignments
	return out, nil
}

// deepCopyConfig copies c through JSON, which keeps nil and empty maps and
// slices apart (the gateway's cloneConfig uses the same encoding).
func deepCopyConfig(c *Config) (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("copy configuration: %w", err)
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("copy configuration: %w", err)
	}
	return &out, nil
}
