// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// The strictest combination (meet) of several guardrail profiles.
//
// When more than one profile may apply to a request (an identity fact that
// is not proven, overlapping assignments, a pre-1.0.4 agents entry the
// upgrade could not bind), the gateway applies their meet: the most
// restrictive combination field by field. Every block of any member applies,
// allows are the intersection, the strictest HILT, mode, block level and
// sandbox requirement win, and the rule pack of every member is enforced.
// No request is refused because the profiles differ.
//
// A meet is named ProfileMeetPrefix plus its members joined by "." (the
// base configuration is "-"); '.' is never part of a profile name, and the
// name is a valid telemetry profile name. A name that would be longer than
// profileMeetNameMax is "strictest.x" plus a digest of the members, which
// only this process can resolve (ProfileMeetMembers). Sandbox registrations
// also store the members, so a hashed meet resolves after a restart.

// ProfileMeetPrefix starts the name of a meet of guardrail profiles.
const ProfileMeetPrefix = "strictest."

// profileMeetBase names the base configuration (no profile) in a meet name.
const profileMeetBase = "-"

// profileMeetNameMax bounds a readable meet name (the telemetry attribute
// takes 128 bytes).
const profileMeetNameMax = 120

// profileMeets maps every meet name this process made to its members.
var profileMeets sync.Map

// IsProfileMeet reports whether name names a meet of profiles.
func IsProfileMeet(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), ProfileMeetPrefix)
}

// profileMeetMembers sorts members, trims them and drops repeats.
func profileMeetMembers(members []string) []string {
	out := make([]string, 0, len(members))
	for _, member := range members {
		member = strings.TrimSpace(member)
		if !slices.Contains(out, member) {
			out = append(out, member)
		}
	}
	slices.Sort(out)
	return out
}

// ProfileMeetName returns the name of the meet of members ("" is the base
// configuration) and records it. One member is its own name.
func ProfileMeetName(members []string) string {
	members = profileMeetMembers(members)
	if len(members) == 1 {
		return members[0]
	}
	encoded := make([]string, len(members))
	for i, member := range members {
		encoded[i] = member
		if member == "" {
			encoded[i] = profileMeetBase
		}
	}
	joined := strings.Join(encoded, ".")
	name := ProfileMeetPrefix + joined
	if len(name) > profileMeetNameMax {
		sum := sha256.Sum256([]byte(joined))
		name = ProfileMeetPrefix + "x" + hex.EncodeToString(sum[:8])
	}
	profileMeets.LoadOrStore(name, slices.Clone(members))
	return name
}

// ProfileMeetMembers returns the members of the meet name, sorted.
func ProfileMeetMembers(name string) ([]string, bool) {
	name = strings.TrimSpace(name)
	rest, ok := strings.CutPrefix(name, ProfileMeetPrefix)
	if !ok || rest == "" {
		return nil, false
	}
	if members, ok := profileMeets.Load(name); ok {
		return slices.Clone(members.([]string)), true
	}
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return nil, false
	}
	members := make([]string, 0, len(parts))
	for _, part := range parts {
		switch {
		case part == profileMeetBase:
			members = append(members, "")
		case guardrailProfileNamePattern.MatchString(part):
			members = append(members, part)
		default:
			return nil, false
		}
	}
	return profileMeetMembers(members), true
}

// meetSandboxFloor is SandboxFloor for the meet of members: openshell.admin
// tightened by every member's sandbox section (TightenOpenShellAdmin, whose
// rules are a meet: false wins, unions of blocks, intersections of allows).
// Where no sandbox satisfies every member (a contradiction, or two members
// that require different packs), the strictest floor applies: no sandbox is
// allowed, and an agent a member requires in a sandbox does not run on the
// host either (closedMeetSandboxFloor). The contact text stays
// openshell.admin's, so no member's text is shown to the caller.
func (c *Config) meetSandboxFloor(members []string) (OpenShellAdminConfig, string, error) {
	f, err := TightenOpenShellAdmin(c.OpenShell.Admin, nil)
	if err != nil {
		return OpenShellAdminConfig{}, "", err
	}
	pack := ""
	closed := false
	for _, member := range members {
		if member == "" {
			continue
		}
		p, ok := c.Guardrail.Profiles[member]
		if !ok {
			return OpenShellAdminConfig{}, "", fmt.Errorf("guardrail profile %q is not defined", member)
		}
		if p.Sandbox == nil {
			continue
		}
		if required := strings.TrimSpace(p.Sandbox.RequiredPack); required != "" {
			if pack != "" && !sameSandboxPack(pack, required) {
				closed = true
			}
			pack = required
		}
		next, tightenErr := TightenOpenShellAdmin(f, p.Sandbox)
		if tightenErr != nil {
			closed = true
			f = closedMeetSandboxFloor(f, p.Sandbox)
			continue
		}
		f = next
	}
	if closed {
		f = closedMeetSandboxFloor(f, nil)
	}
	f.RequestAccess = c.OpenShell.Admin.RequestAccess
	digest, err := sandboxFloorDigest(f, c.OpenShell.PackDir)
	if err != nil {
		return OpenShellAdminConfig{}, "", err
	}
	return f, digest, nil
}

// closedMeetSandboxFloor is f with no sandbox allowed: the strictest floor,
// keeping the agents f and overlay require in a sandbox, which then run
// nowhere.
func closedMeetSandboxFloor(f OpenShellAdminConfig, overlay *OpenShellAdminConfig) OpenShellAdminConfig {
	off := false
	out := cloneOpenShellAdmin(f)
	if overlay != nil {
		out.RequiredFor = unionStrings(out.RequiredFor, overlay.RequiredFor, NormalizeConnectorName)
		out.EgressBlock = unionStrings(out.EgressBlock, overlay.EgressBlock, NormalizeOpenShellEgressPattern)
	}
	out.RequiredFor = canonicalConnectorNames(out.RequiredFor)
	out.Allowed, out.AllowYolo, out.AllowMount, out.AllowHostPorts = &off, &off, &off, &off
	out.AllowUnblock, out.AllowLearnMode = &off, &off
	out.MinProfile = "strict"
	return out
}

// DeriveGuardrailProfileMeet derives the meet of members (ProfileMeetName)
// whose guardrail settings are profile: the gateway computes them as the
// strictest of the members' effective inspect settings for every connector.
// hookModes contains the hook modes that differ from those inspect settings.
// The sandbox floor is the members' meet (meetSandboxFloor). Every member
// must be a profile of c or "" (the base configuration).
func (c *Config) DeriveGuardrailProfileMeet(members []string, profile GuardrailProfile, hookModes map[string]string) (DerivedGuardrailProfile, error) {
	if c == nil {
		return DerivedGuardrailProfile{}, fmt.Errorf("guardrail profile meet: configuration is unavailable")
	}
	members = profileMeetMembers(members)
	name := ProfileMeetName(members)
	if !IsProfileMeet(name) {
		return DerivedGuardrailProfile{}, fmt.Errorf("guardrail profile meet: %d members", len(members))
	}
	floor, floorDigest, err := c.meetSandboxFloor(members)
	if err != nil {
		return DerivedGuardrailProfile{}, fmt.Errorf("guardrail profile meet %s: %w", name, err)
	}
	base, err := copyConfigSharingProfiles(c)
	if err != nil {
		return DerivedGuardrailProfile{}, fmt.Errorf("guardrail profile meet %s: %w", name, err)
	}
	profile.Sandbox = nil
	derived := deriveProfileFrom(base, profile)
	for name, mode := range hookModes {
		// A profile's explicit guardrail mode clears inherited hook modes.
		// Restore only overrides that differ from the meet's inspect mode,
		// preserving the other fields of each connector's hook config.
		if hook, ok := derived.ConnectorHooks[name]; ok {
			hook.Mode = mode
			derived.ConnectorHooks[name] = hook
			continue
		}
		switch name {
		case "codex":
			derived.Codex.Mode = mode
		case "claudecode":
			derived.ClaudeCode.Mode = mode
		default:
			if derived.ConnectorHooks == nil {
				derived.ConnectorHooks = make(map[string]AgentHookConfig)
			}
			derived.ConnectorHooks[name] = AgentHookConfig{Mode: mode}
		}
	}
	digest, err := guardrailPolicyDigest(derived, floorDigest, nil)
	if err != nil {
		return DerivedGuardrailProfile{}, fmt.Errorf("guardrail profile meet %s: %w", name, err)
	}
	return DerivedGuardrailProfile{Name: name, Config: derived, Digest: digest, Sandbox: floor, SandboxDigest: floorDigest,
		policySandboxDigest: floorDigest}, nil
}
