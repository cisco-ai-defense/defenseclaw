// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
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

// ErrProfilesNotImplemented is returned by DerivedForProfile until profile
// resolution lands.
var ErrProfilesNotImplemented = errors.New("guardrail profiles: DerivedForProfile not implemented")

// DerivedForProfile returns the effective configuration for subjects of the
// named profile: a copy of c with the profile's overrides applied by the
// precedence above, precomputed at load and reload with a digest per
// profile. The empty name returns c unchanged.
//
// It is a stub until the profile resolver is implemented.
func (c *Config) DerivedForProfile(name string) (*Config, error) {
	if strings.TrimSpace(name) == "" {
		return c, nil
	}
	return nil, ErrProfilesNotImplemented
}
