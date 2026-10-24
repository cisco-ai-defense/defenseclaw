// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Loop round 2, finding 3: a gid whose name no NSS group provider can
// confirm (a Himmelblau module DefenseClaw cannot check) no longer fails the
// account's lookup. The membership is proved; only the name is unknown. An
// assignment the proven groups satisfy applies. One that names the gid by
// its number, or names a group the gid may be, may or may not apply, so
// the request gets the strictest profile that may apply, or is refused,
// never the weaker default. Before, the whole lookup failed and every
// group assignment fell to default_lookup_failed and the weaker default,
// although the release matched the strict numeric assignment.
func TestUnconfirmedGroupNamesNeverResolveToAWeakerProfile(t *testing.T) {
	stubProfileSources(t)
	facts := useridentity.DirectoryFacts{Groups: []string{"staff", "7000"}, UnconfirmedGroups: []string{"7000"}, ResolvedAt: time.Now()}
	alice := profileSubjectFromVerified(VerifiedSubject{UserID: "1001", IDKind: useridentity.KindForID("1001"), UserName: "alice", Directory: facts}, true)
	if !slices.Equal(alice.unconfirmedGroups, []string{"7000"}) {
		t.Fatalf("subject unconfirmed groups %v, want the facts' [7000]", alice.unconfirmedGroups)
	}
	group := func(profile string, groups ...string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: profile, Match: config.ProfileMatch{Groups: groups}}
	}
	connector := config.ProfileAssignment{Profile: "watch", Match: config.ProfileMatch{Connectors: []string{"codex"}}}
	resolve := func(t *testing.T, cfg *config.Config, subject profileSubject) (*APIServer, context.Context) {
		t.Helper()
		api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
		ctx := context.WithValue(t.Context(), testVerifiedSubjectKey{}, subject)
		return api, api.withGuardrailProfileDecision(ctx, "codex")
	}
	for _, tc := range []struct {
		name              string
		cfg               *config.Config
		profile, match    string
		mode              string
		refused, unproven bool
	}{
		{name: "the numeric gid selects strict", cfg: r2BridgeConfig(group("strict", "7000")),
			profile: "strict", match: profileMatchDefaultLookupFailed, mode: "action"},
		{name: "a group the gid may be, before a weaker connector row", cfg: r2BridgeConfig(group("strict", "himmel-strict"), connector),
			profile: "strict", match: profileMatchDefaultLookupFailed, mode: "action"},
		{name: "a group the gid may be, before a weaker proven group", cfg: r2BridgeConfig(group("strict", `CORP\himmel-strict`), group("watch", "staff")),
			profile: "strict", match: profileMatchDefaultLookupFailed, mode: "action"},
		{name: "the numeric gid names a weak row before a strict group the gid may be", cfg: r2BridgeConfig(group("watch", "7000"), group("strict", "himmel-strict")),
			profile: "strict", match: profileMatchDefaultLookupFailed, mode: "action"},
		// r104 identity: a proven weaker group does not hide a strict
		// group the gid may be; the strictest wins whatever the order.
		{name: "a proven group first", cfg: r2BridgeConfig(group("watch", "staff"), group("strict", "himmel-strict")),
			profile: "strict", match: profileMatchDefaultLookupFailed, mode: "action"},
		{name: "another gid by number", cfg: r2BridgeConfig(group("strict", "7002")),
			profile: "watch", match: profileMatchDefault, mode: "observe"},
		{name: "another user's group row", cfg: r2BridgeConfig(config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"bob"}, Groups: []string{"himmel-strict"}}}),
			profile: "watch", match: profileMatchDefault, mode: "observe"},
		{name: "profiles that do not cover each other", cfg: func() *config.Config {
			cfg := r2BridgeConfig(group("entry", "himmel-strict"))
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"entry":   {Mode: "action", BlockAt: "high", RulePack: "strict"},
				"current": {Mode: "action", BlockAt: "high", RulePack: "permissive"},
			}
			cfg.Guardrail.DefaultProfile = "current"
			return cfg
		}(), profile: config.ProfileMeetName([]string{"current", "entry"}), match: profileMatchDefaultLookupFailed, mode: "action", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, ctx := resolve(t, tc.cfg, alice)
			got, mode := api.resolveProfile(ctx), api.agentHookMode(ctx, "codex")
			if got.Name != tc.profile || got.Match != tc.match || mode != tc.mode || config.IsProfileMeet(got.Name) != tc.refused {
				t.Errorf("profile %+v, mode %q; want %s (%s) as %s, meet %v", got, mode, tc.profile, tc.mode, tc.match, tc.refused)
			}
			// Once the gid is proved unnamed, the numeric row is exact again.
			proven := alice
			proven.unconfirmedGroups = nil
			if tc.name == "the numeric gid selects strict" {
				api, ctx := resolve(t, tc.cfg, proven)
				if got := api.resolveProfile(ctx); got.Name != "strict" || got.Match != profileMatchGroup {
					t.Errorf("proven gid: profile %+v, want strict as group", got)
				}
			}
		})
	}
	t.Run("a combined group decision stays combined with an unresolved agents entry", func(t *testing.T) {
		previous := profileAgentLedger
		t.Cleanup(func() { profileAgentLedger = previous })
		profileAgentLedger = func(inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) { return nil, false }
		cfg := r2BridgeConfig(group("entry", "himmel-strict"),
			config.ProfileAssignment{Profile: "current", Match: config.ProfileMatch{Agents: []string{"agt-someone-else"}}})
		cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"entry":   {Mode: "action", BlockAt: "high", RulePack: "strict"},
			"current": {Mode: "action", BlockAt: "high", RulePack: "permissive"},
		}
		cfg.Guardrail.DefaultProfile = "current"
		set := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg).guardrailProfileSet()
		got := set.matchAgent(&alice, profileSubjectVerified, "codex", "agt-alice", nil)
		if !config.IsProfileMeet(got.Name) || got.Match != profileMatchDefaultLookupFailed {
			t.Errorf("decision %+v; want the strictest combination as default_lookup_failed", got)
		}
	})
}
