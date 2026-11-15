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
			return "", "", fmt.Errorf("%w: profile %q has no launcher atespace", ErrSubstrateProfileNotAllowed, profile)
		}
		return profile, list[0], nil
	}
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
	if (m.Empty() && m.Substrate.Empty()) || len(m.Agents) > 0 {
		return false
	}
	if s := m.Substrate; s != nil {
		if len(s.Atespaces) > 0 || len(s.Templates) > 0 {
			return false
		}
		if len(s.Workloads) > 0 && (p.Kind != identity.PersonWorkload || !anyMatches(s.Workloads, func(v string) bool {
			return substrateWorkloadMatches(v, p.Subject)
		})) {
			return false
		}
	}
	if len(m.Connectors) > 0 && (connector == "" || !anyMatches(m.Connectors, func(v string) bool {
		return config.NormalizeConnectorName(v) == connector
	})) {
		return false
	}
	if len(m.Groups) > 0 && !anyMatches(m.Groups, func(v string) bool {
		for _, g := range p.Groups {
			if strings.EqualFold(strings.TrimSpace(v), g) {
				return true
			}
		}
		return false
	}) {
		return false
	}
	if len(m.Users) > 0 && !anyMatches(m.Users, func(v string) bool { return substrateUserMatches(v, p) }) {
		return false
	}
	return true
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

// substrateWorkloadMatches compares a workloads entry (exact, or a prefix
// with a trailing "*") with a workload subject.
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
