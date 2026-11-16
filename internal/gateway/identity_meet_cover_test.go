// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A proven meet covers an uncertain assignment only with the rule packs it
// actually scans: those of its members that block on the request's scope,
// the first one's composed pack first. A meet's own configuration names the
// base pack, which it never scans by that reference, so an uncertain
// profile on the base pack (or on a pack only a later member brings) is not
// covered: the decision keeps the missing account fact and refuses. A
// profile that is the first member's pack, or one that only observes, is
// covered and changes nothing (loop round 3).
func TestProvenMeetCoversAnUncertainProfileOnlyWithThePacksItScans(t *testing.T) {
	stubProfileSources(t)
	root := t.TempDir()
	packA, packC := meetRulePackDir(t, root, "pa"), meetRulePackDir(t, root, "pc")
	act := func(dir string) config.GuardrailProfile {
		return config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", RulePackDir: dir}
	}
	codexOnly := func(dir string) config.GuardrailProfile {
		return config.GuardrailProfile{Mode: "action", BlockAt: "HIGH",
			Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {RulePackDir: dir}}}
	}
	for _, tc := range []struct {
		name      string
		a, b, c   config.GuardrailProfile
		connector string
		refused   bool
	}{
		{name: "uncertain profile on the base pack, codex", a: act(packA), b: act(""), c: act(packC), connector: "codex", refused: true},
		{name: "uncertain profile on the base pack, unscoped", a: act(packA), b: act(""), c: act(packC), connector: "", refused: true},
		{name: "uncertain profile on the base pack, claude code", a: act(packA), b: act(""), c: act(packC), connector: "claudecode", refused: true},
		{name: "members set codex packs only", a: codexOnly(packA), b: act(""), c: codexOnly(packC), connector: "codex", refused: true},
		{name: "uncertain profile on a later member's pack", a: act(packA), b: act(packC), c: act(packC), connector: "codex", refused: true},
		{name: "uncertain profile on the first member's pack", a: act(packA), b: act(packA), c: act(packC), connector: "codex"},
		{name: "uncertain profile only observes", a: act(packA), b: config.GuardrailProfile{Mode: "observe"}, c: act(packC), connector: "codex"},
	} {
		p := identityTestPlatforms[0]
		byName := config.ProfileAssignment{Profile: "b", Match: config.ProfileMatch{Users: []string{`.\` + p.name}}}
		byGroup := config.ProfileAssignment{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}}
		byUID := config.ProfileAssignment{Profile: "c", Match: config.ProfileMatch{Users: []string{p.id}}}
		for _, order := range [][]config.ProfileAssignment{{byName, byGroup, byUID}, {byGroup, byUID, byName}} {
			t.Run(tc.name+"/"+order[0].Profile+" first", func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "observe"
				cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"a": tc.a, "b": tc.b, "c": tc.c}
				cfg.Guardrail.ProfileAssignments = order
				set := newGuardrailProfileSetFor(t, cfg)
				// A local account on a per-user SSSD host: its uid and groups
				// are proven, which account holds the uid is not.
				subject := identityTestSubject(p, p.providers[0], stateProven, true)
				subject.holderUnproven = true

				meetName := config.ProfileMeetName([]string{"a", "c"})
				meet := set.meet(meetName)
				if meet == nil || !slices.Equal(set.enforcingMembers(meet.members, tc.connector, profilePathAny), []string{"a", "c"}) {
					t.Fatalf("fixture: meet %s enforcing members on %q are not [a c]", meetName, tc.connector)
				}
				if tc.name == "uncertain profile on the base pack, codex" &&
					(effectiveRulePackKey(meet.derived.Config, "codex") != effectiveRulePackKey(set.profileConfig("b"), "codex")) {
					t.Fatal("fixture: the meet's own configuration no longer names the base pack")
				}
				got := set.match(&subject, profileSubjectVerified, tc.connector, "")
				if !tc.refused {
					if got.Name != meetName || got.Refused != "" || len(got.Unproven) != 0 {
						t.Fatalf("decision %+v; want the meet of a and c, not refused: it scans everything b enforces", got)
					}
					return
				}
				if got.Refused == "" || !slices.Contains(got.Unproven, "account:unknown") || !slices.Contains(got.Candidates, "b") {
					t.Fatalf("decision %+v; want a refusal that keeps the missing account fact: the meet does not scan b's pack", got)
				}
				if tc.connector != "codex" {
					return
				}
				ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
				ctx = withGuardrailProfile(ctx, set, "codex")
				api := &APIServer{}
				api.guardrailProfiles.set.Store(set)
				if response, refused := api.refuseProfileHook(ctx, (&APIServer{scannerCfg: config.DefaultConfig()}).hookProfileForConnector("codex"), "codex",
					agentHookRequest{ConnectorName: "codex", HookEventName: "pre_tool_use"}, nil, nil); !refused || response.Action != "block" {
					t.Fatalf("hook did not refuse: %+v, refused=%v", response, refused)
				}
			})
		}
	}
}
