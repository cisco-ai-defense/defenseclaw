// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0043: the launcher profile comes from profile_assignments for the
// verified caller, not from the request.
func TestSubstrateLauncherProfilesFollowTheCaller(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.DefaultProfile = "basic"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "ci", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Workloads: []string{"repo:acme/web:*"}}}},
		{Profile: "actors-only", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Atespaces: []string{"eng-web"}}}},
		{Profile: "eng", Match: config.ProfileMatch{Groups: []string{"dc-r102-devs"}}},
		{Profile: "lead", Match: config.ProfileMatch{Users: []string{"Lead@Example.com"}}},
	}
	cfg.Substrate.LauncherAtespaces = map[string][]string{
		"eng": {"eng-web", "eng-api"}, "ci": {"ci-runs"}, "lead": {"eng-web"}, "basic": {"sandbox"}, "ops": {"ops-1"},
	}
	resolve := SubstrateLauncherProfiles(cfg)
	dev := identity.Person{Kind: identity.PersonHuman, Subject: "u1", Groups: []string{"DC-R102-DEVS"}}
	lead := identity.Person{Kind: identity.PersonHuman, Subject: "u2", Principal: "lead@example.com"}
	nobody := identity.Person{Kind: identity.PersonHuman, Subject: "u3"}
	ci := identity.Person{Kind: identity.PersonWorkload, Subject: "repo:acme/web:ref:refs/heads/main"}
	forkCI := identity.Person{Kind: identity.PersonWorkload, Subject: "repo:evil/web:ref:refs/heads/main"}
	cases := []struct {
		name           string
		p              identity.Person
		requested      string
		admin          bool
		profile, space string
		refused        bool
	}{
		{"group member gets their profile", dev, "", false, "eng", "eng-web", false},
		{"group member names their profile", dev, "eng", false, "eng", "eng-web", false},
		{"group member names another profile", dev, "ops", false, "", "", true},
		{"user entry", lead, "", false, "lead", "eng-web", false},
		{"no assignment: the default profile", nobody, "", false, "basic", "sandbox", false},
		{"no assignment cannot pick eng", nobody, "eng", false, "", "", true},
		{"bound workload", ci, "", false, "ci", "ci-runs", false},
		{"another repository's workload", forkCI, "ci", false, "", "", true},
		{"admin may pick a launcher profile", nobody, "ops", true, "ops", "ops-1", false},
		{"admin cannot pick a profile without atespaces", nobody, "actors-only", true, "", "", true},
	}
	for _, c := range cases {
		profile, space, err := resolve(c.p, c.requested, "claudecode", c.admin)
		if c.refused {
			if err == nil || !errors.Is(err, ErrSubstrateProfileNotAllowed) {
				t.Errorf("%s: %q %q %v, want a refusal", c.name, profile, space, err)
			}
			continue
		}
		if err != nil || profile != c.profile || space != c.space {
			t.Errorf("%s: %q %q %v, want %q %q", c.name, profile, space, err, c.profile, c.space)
		}
	}
	// Without any guardrail profile the "default" launcher entry applies.
	bare := &config.Config{}
	bare.Substrate.LauncherAtespaces = map[string][]string{SubstrateLauncherDefaultProfile: {"lab"}}
	if p, s, err := SubstrateLauncherProfiles(bare)(nobody, "", "", false); err != nil || p != "default" || s != "lab" {
		t.Fatalf("no profiles: %q %q %v", p, s, err)
	}
	// Found live on E1: naming that default profile is the caller's own.
	if p, _, err := SubstrateLauncherProfiles(bare)(nobody, "default", "", false); err != nil || p != "default" {
		t.Fatalf("no profiles, default named: %q %v", p, err)
	}
}

// GAP-0043 (lane R round 3): match.substrate.workloads wildcards match on
// segment boundaries only.
func TestSubstrateWorkloadWildcardBoundaries(t *testing.T) {
	for _, c := range []struct {
		entry, subject string
		want           bool
	}{
		{"repo:acme/web:*", "repo:acme/web:ref:refs/heads/main", true},
		{"repo:acme/web:*", "repo:acme/web-evil:ref:main", false},
		{"repo:acme/web*", "repo:acme/web-evil:ref:main", false},
		{"repo:acme/web*", "repo:acme/web:ref:main", false},
		{"*", "repo:anything", false},
		{"repo:acme/web:ref:refs/heads/main", "repo:acme/web:ref:refs/heads/main", true},
	} {
		if got := substrateWorkloadMatches(c.entry, c.subject); got != c.want {
			t.Errorf("%q vs %q = %v, want %v", c.entry, c.subject, got, c.want)
		}
	}
}
