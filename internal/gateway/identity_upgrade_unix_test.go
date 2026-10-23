// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
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

// The RHEL gateway has ProtectHome=yes. The root guardian can stat a local
// account's home at upgrade, while the gateway cannot stat it from its own
// mount namespace. The trusted current identity record carries that proof.
func TestUpgradeKeepsLocalAgentsAssignmentWithPrivateHome(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.0.2", "1.0.3"} {
		t.Run(version, func(t *testing.T) {
			b := newUpgradeBridge(t, "alice")
			legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
			b.migrate(70001, "alice")
			token := enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])
			record, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
				Key: "70001", User: "alice", AccountIncarnation: "files", LegacyOwnerToken: token,
				UpdatedAt: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(b.dir, "70001.json"), record, 0o640); err != nil {
				t.Fatal(err)
			}
			managedHookPeerHome = func(int) string { return "" }
			got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001,
				profileSubject{UserID: "70001", UserName: "alice"})
			if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
				t.Fatalf("%s: %+v, mode %q; want prior agents assignment", version, got, mode)
			}
		})
	}
}

// A large upgrade: the guardian's migration map records 65,536 accounts
// (enterprisehooks.maxLegacyAgentOwners) and is over 4 MiB. The agents entry
// written for alice's 1.0.x agent identity still applies to her.
func TestUpgradeKeepsAgentsAssignmentWithLargeMigrationMap(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
	b.peer(70001)
	owners := map[int]enterprisehooks.LegacyAgentOwner{70001: {User: "alice", Token: enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])}}
	for i := 0; len(owners) < 65536; i++ {
		owners[1_900_000_000+i] = enterprisehooks.LegacyAgentOwner{
			User:  fmt.Sprintf("dcad-user-%05d@corp.dclab.example.com", i),
			Token: fmt.Sprintf("sid:S-1-5-21-1004336348-1177238915-682003330-%d", 100000+i),
		}
	}
	if written, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	if info, err := os.Stat(filepath.Join(b.dir, enterprisehooks.LegacyAgentOwnersFile)); err != nil || info.Size() <= 4<<20 {
		t.Fatalf("map stat %v; want a map over 4 MiB", err)
	}
	legacyAgentOwners = &legacyAgentOwnerCache{}
	got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: "alice"})
	if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
		t.Fatalf("%+v, mode %q; want the prior agents assignment", got, mode)
	}
}

// Review of r104 Q-identity (continuation 2, loop round 2): an automounted
// home gets another device number when it is mounted again, while its inode
// and creation time stay. The migration map's token
// (home:<device>:<inode>[:<creation time>]) was compared exactly, so after
// a remount alice's 1.0.x agents entry was refused. A home created again
// (another inode, or the freed inode with another creation time) is still
// another account's.
func TestUpgradeKeepsAgentsAssignmentAfterHomeRemount(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorded string
		now      string
		bound    bool
	}{
		{"remounted on another device", "home:2049:131073:1700000000123456789", "home:47:131073:1700000000123456789", true},
		{"remounted, no creation time", "home:2049:131073", "home:47:131073", true},
		{"no creation time recorded", "home:2049:131073", "home:47:131073:1700000000123456789", true},
		{"same home", "home:2049:131073:1700000000123456789", "home:2049:131073:1700000000123456789", true},
		{"same SID", "sid:S-1-5-21-1-2-3-1105", "sid:S-1-5-21-1-2-3-1105", true},
		{"home created again, another inode", "home:2049:131073:1700000000123456789", "home:47:131074:1700000000123456789", false},
		{"home created again on the freed inode", "home:2049:131073:1700000000123456789", "home:2049:131073:1800000000000000000", false},
		{"creation time recorded, none now", "home:2049:131073:1700000000123456789", "home:47:131073", false},
		{"another SID", "sid:S-1-5-21-1-2-3-1105", "sid:S-1-5-21-1-2-3-1106", false},
		{"SID recorded, home now", "sid:S-1-5-21-1-2-3-1105", "home:2049:131073", false},
		{"home recorded, SID now", "home:2049:131073", "sid:S-1-5-21-1-2-3-1105", false},
		{"no token now", "home:2049:131073", "", false},
		{"malformed token now", "home:2049:131073", "home:x:131073", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newUpgradeBridge(t, "alice")
			legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
			b.peer(70001)
			if _, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, map[int]enterprisehooks.LegacyAgentOwner{70001: {User: "alice", Token: tc.recorded}},
				time.Now(), nil); err != nil {
				t.Fatal(err)
			}
			legacyAgentOwners = &legacyAgentOwnerCache{}
			previous := legacyAgentOwnerTokenNow
			t.Cleanup(func() { legacyAgentOwnerTokenNow = previous })
			legacyAgentOwnerTokenNow = func(int, string) string { return tc.now }
			if got := legacyAgentOwnerBound("70001", "alice"); got != tc.bound {
				t.Fatalf("recorded %q, now %q: bound=%t, want %t", tc.recorded, tc.now, got, tc.bound)
			}
			got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: "alice"})
			if tc.bound && (got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "") {
				t.Fatalf("%+v, mode %q; want the prior agents assignment", got, mode)
			}
			if !tc.bound && (got.Match != profileMatchDefaultLookupFailed || got.Refused == "") {
				t.Fatalf("%+v, mode %q; want the unbound entry refused", got, mode)
			}
		})
	}
}

// Review of r104 Q-identity (continuation 2, loop round 2): alice's home was
// not there at the guardian's first pass after the upgrade, so the map lists
// her as pending. Her 1.0.x agents entry is refused, naming the unproven
// ownership, until the guardian proves her; the gateway then reads the
// changed map within legacyAgentOwnersRetry and the entry applies again.
func TestUpgradeBindsAPendingAccountOnceProven(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
	b.peer(70001)
	if _, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, map[int]enterprisehooks.LegacyAgentOwner{
		70001: {User: "alice"}, 70002: {User: "bob", Token: "home:1:2"}}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	cfg := legacyConfig(legacy, upgradeProfiles)
	subject := profileSubject{UserID: "70001", UserName: "alice"}
	if got, _ := b.hook(cfg, 70001, subject); got.Match != profileMatchDefaultLookupFailed || got.Refused == "" {
		t.Fatalf("pending alice: %+v; want the entry refused until she is proven", got)
	}
	if written, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, map[int]enterprisehooks.LegacyAgentOwner{
		70001: {User: "alice", Token: enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])}}, time.Now(), nil); err != nil || !written {
		t.Fatalf("prove alice: written=%t err=%v", written, err)
	}
	legacyAgentOwners.mu.Lock()
	legacyAgentOwners.nextTry = time.Time{} // legacyAgentOwnersRetry has passed
	legacyAgentOwners.mu.Unlock()
	got, mode := b.hook(cfg, 70001, subject)
	if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
		t.Fatalf("proven alice: %+v, mode %q; want the prior agents assignment", got, mode)
	}
}

// More accounts than one file of the map holds: alice's owner is in a shard,
// and her 1.0.x agents entry still applies.
func TestUpgradeKeepsAgentsAssignmentInAMigrationMapShard(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
	b.peer(70001)
	owners := map[int]enterprisehooks.LegacyAgentOwner{70001: {User: "alice", Token: enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])}}
	for uid := 1; uid <= 65536; uid++ { // every one sorts before alice
		owners[uid] = enterprisehooks.LegacyAgentOwner{User: fmt.Sprintf("user%d", uid), Token: fmt.Sprintf("home:1:%d", uid)}
	}
	if written, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "legacy-agent-owners-1.map")); err != nil {
		t.Fatalf("no shard: %v", err)
	}
	legacyAgentOwners = &legacyAgentOwnerCache{}
	got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: "alice"})
	if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
		t.Fatalf("%+v, mode %q; want the prior agents assignment", got, mode)
	}
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

// Review of r104 Q-identity (continuation 3, loop round 2): a migration map
// the 1.0.4 builds before the GAP-0939 fix wrote holds, for a symlinked
// home, the symlink's own creation time. Without a current guardian record
// (a managed Mac whose guardian has not rewritten it), the gateway reads
// the home itself, and this build's token named the directory's creation
// time, so the account's 1.0.x agents entry was refused. The gateway now
// takes the earlier proof of this same home, unless the directory behind
// the symlink was created after the map.
func TestUpgradeFromAMapWithTheSymlinkProofBeforeTheFix(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory created after the map=%t", after), func(t *testing.T) {
			b := newUpgradeBridge(t, "alice")
			root := t.TempDir()
			at := time.Now()
			if after {
				time.Sleep(50 * time.Millisecond)
			}
			target, link := filepath.Join(root, "real-alice"), filepath.Join(root, "alice")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if !after {
				at = time.Now()
			}
			b.homes[70001] = link
			before := ownerTokenBeforeSymlinkFix(t, link)
			if now := enterprisehooks.LegacyAgentOwnerToken("files", link); strings.Count(before, ":") < 3 || before == now {
				t.Skipf("the file system of %s keeps no creation time (tokens %q, %q)", root, before, now)
			}
			legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
			if _, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, map[int]enterprisehooks.LegacyAgentOwner{70001: {User: "alice", Token: before}},
				at, nil); err != nil {
				t.Fatal(err)
			}
			legacyAgentOwners = &legacyAgentOwnerCache{}
			if got := legacyAgentOwnerBound("70001", "alice"); got == after {
				t.Fatalf("bound=%t; want %t", got, !after)
			}
			got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: "alice"})
			if !after && (got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "") {
				t.Fatalf("%+v, mode %q; want the prior agents assignment", got, mode)
			}
			if after && (got.Match != profileMatchDefaultLookupFailed || got.Refused == "") {
				t.Fatalf("%+v, mode %q; want the unbound entry refused", got, mode)
			}
		})
	}
}
