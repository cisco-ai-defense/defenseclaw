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
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// SubstrateLauncherDefaultProfile is the launcher_atespaces key used when
// the configuration has no guardrail profiles at all.
const SubstrateLauncherDefaultProfile = "default"

// ErrSubstrateProfileNotAllowed is a create whose profile is not the
// caller's.
var ErrSubstrateProfileNotAllowed = errors.New("the profile is not assigned to the caller")

// ErrSubstrateProfileNoAtespace is a create whose profile (the caller's,
// or one an administrator named) has no launcher atespace (GAP-0541).
type ErrSubstrateProfileNoAtespace struct{ Profile string }

func (e *ErrSubstrateProfileNoAtespace) Error() string {
	return fmt.Sprintf("%v: profile %q has no launcher atespace", ErrSubstrateProfileNotAllowed, e.Profile)
}

// Unwrap keeps errors.Is(err, ErrSubstrateProfileNotAllowed) true.
func (e *ErrSubstrateProfileNoAtespace) Unwrap() error { return ErrSubstrateProfileNotAllowed }

// SubstrateLauncherProfiles resolves a create's profile from the verified
// caller (GAP-0043): the first guardrail.profile_assignments entry that
// selects the person (users, groups) or the workload
// (match.substrate.workloads), else guardrail.default_profile. A request
// may name only that profile; an administrator may name any profile that
// has launcher atespaces. The launcher atespace is the profile's first
// substrate.launcher_atespaces entry.
func SubstrateLauncherProfiles(cfg *config.Config) SubstrateProfileResolver {
	g := cfg.Guardrail
	spaces := cfg.Substrate.LauncherAtespaces
	return func(p identity.Person, requested, connector string, admin bool) (string, string, error) {
		profile := substrateCallerProfile(g, p, connector)
		if profile == "" {
			profile = SubstrateLauncherDefaultProfile
		}
		requested = strings.TrimSpace(requested)
		switch {
		case requested == "" || requested == profile:
		case admin:
			profile = requested
		default:
			return "", "", fmt.Errorf("%w: %q (the caller's is %q)", ErrSubstrateProfileNotAllowed, requested, profile)
		}
		list := spaces[profile]
		if len(list) == 0 {
			return "", "", &ErrSubstrateProfileNoAtespace{Profile: profile}
		}
		return profile, list[0], nil
	}
}

// SubstrateWorkloadEntry is the first match.substrate.workloads entry, in
// profile_assignments order, that a workload subject matches, and that
// assignment's profile; "" and "" when no entry matches, so the workload
// gets an assignment without workloads or guardrail.default_profile. The
// actor list answers a workload caller with it, so login --workload can
// warn about an entry written in another form than the token's subject
// (GAP-0542).
func SubstrateWorkloadEntry(cfg *config.Config, subject string) (entry, profile string) {
	if cfg == nil {
		return "", ""
	}
	for _, a := range cfg.Guardrail.ProfileAssignments {
		if a.Match.Substrate == nil {
			continue
		}
		for _, e := range a.Match.Substrate.Workloads {
			if substrateWorkloadMatches(e, subject) {
				return strings.TrimSpace(e), strings.TrimSpace(a.Profile)
			}
		}
	}
	return "", ""
}

// substrateCallerProfile is the profile profile_assignments give the
// caller, "" for none.
func substrateCallerProfile(g config.GuardrailConfig, p identity.Person, connector string) string {
	connector = config.NormalizeConnectorName(connector)
	for _, a := range g.ProfileAssignments {
		if substrateAssignmentSelects(a.Match, p, connector) {
			return strings.TrimSpace(a.Profile)
		}
	}
	return strings.TrimSpace(g.DefaultProfile)
}

// substrateAssignmentSelects reports whether m selects the caller of a
// create. Keys combine with AND, the values of a key with OR. Selectors
// that name an actor (atespaces, templates) or an agent identity cannot
// select a caller before the actor exists, so an entry with them never
// matches here.
func substrateAssignmentSelects(m config.ProfileMatch, p identity.Person, connector string) bool {
	return len(substrateAssignmentMisses(m, p, connector)) == 0
}

// substrateAssignmentMisses names the selector keys of m that do not select
// the caller, in a fixed order, and none when m selects it. "match" is an
// entry with no selector at all; "agent" is an entry that names an actor or
// agent (atespaces, templates, agents), which cannot select a caller before
// the actor exists; "connectors" is a connector the caller did not name.
// Only the key is named, never a value, so a person is not told another
// person's group or account (GAP-0653).
func substrateAssignmentMisses(m config.ProfileMatch, p identity.Person, connector string) []string {
	if m.Empty() && m.Substrate.Empty() {
		return []string{"match"}
	}
	var miss []string
	agent := len(m.Agents) > 0
	if s := m.Substrate; s != nil {
		agent = agent || len(s.Atespaces) > 0 || len(s.Templates) > 0
		if len(s.Workloads) > 0 && (p.Kind != identity.PersonWorkload || !anyMatches(s.Workloads, func(v string) bool {
			return substrateWorkloadMatches(v, p.Subject)
		})) {
			miss = append(miss, "workloads")
		}
	}
	if len(m.Groups) > 0 && !anyMatches(m.Groups, func(v string) bool {
		for _, g := range p.Groups {
			if strings.EqualFold(strings.TrimSpace(v), g) {
				return true
			}
		}
		return false
	}) {
		miss = append(miss, "groups")
	}
	if len(m.Users) > 0 && !anyMatches(m.Users, func(v string) bool { return substrateUserMatches(v, p) }) {
		miss = append(miss, "users")
	}
	if len(m.Connectors) > 0 && (connector == "" || !anyMatches(m.Connectors, func(v string) bool {
		return config.NormalizeConnectorName(v) == connector
	})) {
		miss = append(miss, "connectors")
	}
	if agent {
		miss = append(miss, "agent")
	}
	return miss
}

// SubstrateAssignmentMiss is one profile_assignments entry that was
// consulted for the caller and did not select it: its 1-based place in the
// list and the selector keys that failed. Profile is set for an
// administrator only; a person is not shown the profiles of assignments
// that are not theirs.
type SubstrateAssignmentMiss struct {
	Assignment int
	Profile    string
	Missing    []string
}

// SubstrateProfileWhy says how a person's profile was chosen: which
// assignment selected it, or that none did and default_profile applies, and
// the assignments that were consulted first and selected nobody like them
// (GAP-0653).
type SubstrateProfileWhy struct {
	// Profile is the profile the assignments give, "" when none applies.
	Profile string
	// DefaultProfile is guardrail.default_profile ("" when unset).
	DefaultProfile string
	// Source is "assignment" (Assignment holds its place), "default_profile"
	// or "none".
	Source     string
	Assignment int
	Unmatched  []SubstrateAssignmentMiss
}

// SubstrateProfileExplainer reports why a person gets the profile they get
// (nil in SubstrateConfig: the explain answer leaves it out).
type SubstrateProfileExplainer func(person identity.Person, admin bool) SubstrateProfileWhy

// SubstrateProfileWhyFor is the explainer over the live configuration. It
// follows substrateCallerProfile, with no connector named: an assignment
// that names a connector or an agent shows as not selecting the caller.
func SubstrateProfileWhyFor(cfg *config.Config) SubstrateProfileExplainer {
	return func(p identity.Person, admin bool) SubstrateProfileWhy {
		g := cfg.Guardrail
		why := SubstrateProfileWhy{DefaultProfile: strings.TrimSpace(g.DefaultProfile)}
		for i, a := range g.ProfileAssignments {
			miss := substrateAssignmentMisses(a.Match, p, "")
			if len(miss) == 0 {
				why.Source, why.Assignment, why.Profile = "assignment", i+1, strings.TrimSpace(a.Profile)
				return why
			}
			m := SubstrateAssignmentMiss{Assignment: i + 1, Missing: miss}
			if admin {
				m.Profile = strings.TrimSpace(a.Profile)
			}
			why.Unmatched = append(why.Unmatched, m)
		}
		why.Profile = why.DefaultProfile
		why.Source = "none"
		if why.DefaultProfile != "" {
			why.Source = "default_profile"
		}
		return why
	}
}

// View is the explain answer's fields for the why.
func (w SubstrateProfileWhy) View() map[string]any {
	out := map[string]any{"default_profile": w.DefaultProfile, "profile_source": w.Source, "effective_profile": w.Profile}
	if w.Source == "assignment" {
		out["matched_assignment"] = w.Assignment
	}
	if len(w.Unmatched) > 0 {
		list := make([]map[string]any, 0, len(w.Unmatched))
		for _, m := range w.Unmatched {
			v := map[string]any{"assignment": m.Assignment, "did_not_select_you": m.Missing}
			if m.Profile != "" {
				v["profile"] = m.Profile
			}
			list = append(list, v)
		}
		out["unmatched_assignments"] = list
	}
	return out
}

// substrateUserMatches compares a users entry with the verified principal
// (email, UPN or preferred username) or subject.
func substrateUserMatches(entry string, p identity.Person) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	return strings.EqualFold(entry, p.Principal) || entry == p.Subject
}

// substrateWorkloadMatches matches a match.substrate.workloads entry: exact,
// or a ":*" / "/*" prefix that stops on a segment boundary (GAP-0043, the
// rule identity.WorkloadSubjectPattern holds); a raw prefix or a bare "*"
// matches nothing.
func substrateWorkloadMatches(entry, subject string) bool {
	entry = strings.TrimSpace(entry)
	if !identity.WorkloadSubjectPattern.MatchString(entry) {
		return false
	}
	if prefix, ok := strings.CutSuffix(entry, "*"); ok {
		return strings.HasPrefix(subject, prefix)
	}
	return entry == subject
}
