// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// SubstrateActorFacts are the registration facts a match.substrate reads.
// Template is "<atespace>/<name>"; Workload is the verified workload
// principal ("" for an actor of a person and for an attributed actor).
// AtespaceOwned is true for an atespace DefenseClaw created or lists (E3).
type SubstrateActorFacts struct {
	Atespace, Template, Workload string
	AtespaceOwned                bool
}

// Matches reports whether m selects the actor f: set keys combine with
// AND, an empty m selects every actor. The warning names an atespace glob
// that matched an atespace DefenseClaw does not own (it does not apply).
// guardrail.profile_assignments and routing.admin.rules share it.
func (m *ProfileMatchSubstrate) Matches(f SubstrateActorFacts) (bool, string) {
	if m == nil {
		return true, ""
	}
	if len(m.Atespaces) > 0 {
		if ok, w := MatchAtespace(m.Atespaces, f.Atespace, f.AtespaceOwned); !ok {
			return false, w
		}
	}
	if len(m.Templates) > 0 && !slices.ContainsFunc(m.Templates, func(p string) bool {
		ok, err := path.Match(p, f.Template)
		return err == nil && ok
	}) {
		return false, ""
	}
	if len(m.Workloads) > 0 && (f.Workload == "" || !slices.Contains(m.Workloads, f.Workload)) {
		return false, ""
	}
	return true, ""
}

// MatchAtespace applies E3: an exact name matches; a glob matches only an
// owned atespace and otherwise returns a warning.
func MatchAtespace(patterns []string, atespace string, owned bool) (bool, string) {
	warn := ""
	for _, p := range patterns {
		if p == atespace {
			return true, ""
		}
		if !strings.ContainsAny(p, "*?[") {
			continue
		}
		if ok, err := path.Match(p, atespace); err == nil && ok {
			if owned {
				return true, ""
			}
			warn = fmt.Sprintf("atespace %s matches the glob %q but DefenseClaw neither created nor lists it; the profile does not apply (list it by name)", atespace, p)
		}
	}
	return false, warn
}
