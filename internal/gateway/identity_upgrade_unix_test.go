// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// upgradeBridge is a strictBridge whose managed gateway reads the upgrade's
// migration map from a guardian identity spool, as a 1.0.4 gateway
// upgraded from 1.0.0, 1.0.2 or 1.0.3 does.
type upgradeBridge struct {
	*strictBridge
	dir string
}

func newUpgradeBridge(t *testing.T, account string) *upgradeBridge {
	t.Helper()
	b := &upgradeBridge{strictBridge: newStrictBridge(t, account), dir: t.TempDir()}
	b.ledger(nil) // the 1.0.x ledger plays no part in the binding
	previousValidate, previousHome, previousDir := validateManagedGuardianAuthorization, managedHookPeerHome, currentIdentitySpoolDir()
	t.Cleanup(func() {
		validateManagedGuardianAuthorization, managedHookPeerHome = previousValidate, previousHome
		setIdentitySpoolDir(previousDir)
		legacyAgentOwners = &legacyAgentOwnerCache{}
	})
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	managedHookPeerHome = func(uid int) string { b.peer(uid); return b.homes[uid] }
	setIdentitySpoolDir(b.dir)
	legacyAgentOwners = &legacyAgentOwnerCache{}
	return b
}

// migrate writes the migration map the guardian records at its first pass
// after the upgrade: uid's account under name, with its home's identity.
func (b *upgradeBridge) migrate(uid int, name string) {
	b.t.Helper()
	b.peer(uid)
	token := enterprisehooks.LegacyAgentOwnerToken("files", b.homes[uid])
	if token == "" {
		b.t.Fatal("no token for the home")
	}
	if _, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, map[int]enterprisehooks.LegacyAgentOwner{uid: {User: name, Token: token}},
		time.Now(), nil); err != nil {
		b.t.Fatal(err)
	}
	legacyAgentOwners = &legacyAgentOwnerCache{} // read it at once, not at the next retry
}

// legacyConfig is a 1.0.x configuration carried into 1.0.4: an agents entry
// written for the agent's 1.0.x identity gets relaxed (observe), the
// default is strict (action, from LOW).
func legacyConfig(entry string, profiles map[string]config.GuardrailProfile) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{entry}}}}
	cfg.Guardrail.DefaultProfile = "strict"
	return cfg
}

var upgradeProfiles = map[string]config.GuardrailProfile{"relaxed": {Mode: "observe"}, "strict": {Mode: "action", BlockAt: "LOW"}}

// Upgrades from 1.0.0, 1.0.2 and 1.0.3 keep every agents assignment working:
// for a bare and a qualified account (Linux SSSD, macOS), the entry written
// for the agent's 1.0.x identity keeps applying, as the agent's own, to the
// account the migration map recorded. 1.0.0 to 1.0.3 derived those
// identities one way (agentidentity.LegacyAgentID), which every version row
// checks.
func TestUpgradeKeepsAgentsAssignmentsWorking(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.0.2", "1.0.3"} {
		for _, account := range []string{"alice", "alice@corp.example"} {
			t.Run(version+"/"+account, func(t *testing.T) {
				b := newUpgradeBridge(t, account)
				in := b.inputs(70001, account)
				legacy := agentidentity.LegacyAgentID(in)
				if legacy == "" || legacy == agentidentity.AgentID(in) {
					t.Fatalf("%s identity %q; want a 1.0.x identity distinct from the current one", version, legacy)
				}
				b.migrate(70001, account)
				got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: account})
				if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" {
					t.Fatalf("%s %s: %+v, mode %q; want relaxed by agent", version, account, got, mode)
				}
			})
		}
	}
}

// Without a binding (no map yet, another account under the uid, a namesake
// of another domain) the entry is a candidate: the request is refused with
// the missing agent ownership fact named. The candidate profile remains
// diagnostic context only.
func TestUnboundLegacyAgentsEntryIsACandidate(t *testing.T) {
	incomparable := map[string]config.GuardrailProfile{
		"relaxed": {Mode: "action", BlockAt: "HIGH", RulePack: "permissive"},
		"strict":  {Mode: "action", BlockAt: "HIGH", RulePack: "strict"},
	}
	for _, tc := range []struct {
		name     string
		migrate  func(b *upgradeBridge)
		profiles map[string]config.GuardrailProfile
		want     string
	}{
		{name: "no migration map", migrate: func(*upgradeBridge) {}, profiles: upgradeProfiles, want: "strict"},
		{name: "another domain's namesake was recorded", migrate: func(b *upgradeBridge) { b.migrate(70001, "alice@other.example") },
			profiles: upgradeProfiles, want: "strict"},
		{name: "the uid was handed to an account created again under the same name and home path", migrate: func(b *upgradeBridge) {
			b.migrate(70001, "alice@corp.example")
			// GAP-0503: the new account's home has another identity (SID or
			// home directory) than the one the map recorded.
			previous := legacyAgentOwnerTokenNow
			b.t.Cleanup(func() { legacyAgentOwnerTokenNow = previous })
			legacyAgentOwnerTokenNow = func(int, string) string { return "home:1:2:3" }
		}, profiles: upgradeProfiles, want: "strict"},
		{name: "profiles that do not cover each other", migrate: func(*upgradeBridge) {}, profiles: incomparable,
			want: config.ProfileMeetName([]string{"relaxed", "strict"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newUpgradeBridge(t, "alice@corp.example")
			legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice@corp.example"))
			tc.migrate(b)
			got, mode := b.hook(legacyConfig(legacy, tc.profiles), 70001, profileSubject{UserID: "70001", UserName: "alice@corp.example"})
			if got.Name != tc.want || got.Match != profileMatchDefaultLookupFailed || mode != "action" ||
				got.Refused == "" || !strings.Contains(got.Refused, "agent identity") {
				t.Fatalf("%+v, mode %q; want refused candidate %s as default_lookup_failed", got, mode, tc.want)
			}
		})
	}
}

// The migration map is read once found, and its owner check needs the
// recorded name, domain included, and the recorded incarnation.
func TestLegacyAgentOwnerBound(t *testing.T) {
	b := newUpgradeBridge(t, "alice@corp.example")
	if legacyAgentOwnerBound("70001", "alice@corp.example") {
		t.Fatal("bound before the map was written")
	}
	b.migrate(70001, "alice@corp.example")
	legacyAgentOwners = &legacyAgentOwnerCache{}
	for _, tc := range []struct {
		id, account string
		want        bool
	}{
		{"70001", "alice@corp.example", true},
		{"70001", "ALICE@CORP.EXAMPLE", true},
		{"70001", "alice", false},
		{"70001", "alice@other.example", false},
		{"70002", "alice@corp.example", false},
		{"S-1-5-21-1-2-3-1105", "alice@corp.example", false},
	} {
		if got := legacyAgentOwnerBound(tc.id, tc.account); got != tc.want {
			t.Errorf("legacyAgentOwnerBound(%s, %s) = %v, want %v", tc.id, tc.account, got, tc.want)
		}
	}
}
