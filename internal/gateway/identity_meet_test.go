// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// meetTestSet is a profile set of profiles, with no assignments.
func meetTestSet(t *testing.T, profiles map[string]config.GuardrailProfile) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = profiles
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// The meet of profiles, field by field: every block of any member applies
// (the action mode wherever one blocks, the lowest block level of those
// that block), the strictest HILT of those that block, per connector.
func TestProfileMeetTable(t *testing.T) {
	hilt := func(enabled bool, severity string) *config.HILTConfig {
		return &config.HILTConfig{Enabled: enabled, MinSeverity: severity}
	}
	for _, tc := range []struct {
		name      string
		profiles  map[string]config.GuardrailProfile
		connector string
		mode      string
		blockAt   string
		hilt      bool
		hiltAt    int
	}{
		{name: "an observing member adds no block", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "HIGH"}, "b": {Mode: "observe", BlockAt: "LOW"}},
			mode:     "action", blockAt: "HIGH"},
		{name: "the lowest block level of the members that block", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "HIGH"}, "b": {Mode: "action", BlockAt: "LOW"}},
			mode:     "action", blockAt: "LOW"},
		{name: "members that only observe", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "observe", BlockAt: "LOW"}, "b": {Mode: "observe", BlockAt: "HIGH"}},
			mode:     "observe", blockAt: "CRITICAL"},
		{name: "a HILT of one member", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "HIGH")}, "b": {Mode: "action", BlockAt: "HIGH"}},
			mode:     "action", blockAt: "HIGH", hilt: true, hiltAt: severityHigh},
		{name: "the HILT that asks most", connector: "codex",
			profiles: map[string]config.GuardrailProfile{"a": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "HIGH")}, "b": {Mode: "action", BlockAt: "CRITICAL", HILT: hilt(true, "MEDIUM")}},
			mode:     "action", blockAt: "CRITICAL", hilt: true, hiltAt: severityMedium},
		{name: "a connector one member blocks", connector: "codex",
			profiles: map[string]config.GuardrailProfile{
				"a": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action", BlockAt: "MEDIUM"}}},
				"b": {Mode: "observe"}},
			mode: "action", blockAt: "MEDIUM"},
		{name: "another connector of that member observes", connector: "claudecode",
			profiles: map[string]config.GuardrailProfile{
				"a": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action", BlockAt: "MEDIUM"}}},
				"b": {Mode: "observe"}},
			mode: "observe", blockAt: "CRITICAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := meetTestSet(t, tc.profiles)
			name, single := set.meetOf([]string{"b", "a"}, tc.connector)
			if single {
				// One covers the other: it applies under its own name, and
				// enforces what the meet would.
				t.Logf("%s covers the other", name)
			}
			if !single && name != config.ProfileMeetName([]string{"a", "b"}) {
				t.Fatalf("meet named %q", name)
			}
			cfg := set.profileConfig(name)
			if got := hookModeForConfig(cfg, tc.connector); got != tc.mode {
				t.Errorf("hook mode %q, want %q", got, tc.mode)
			}
			if got := inspectMode(cfg, tc.connector); got != tc.mode {
				t.Errorf("inspect mode %q, want %q", got, tc.mode)
			}
			if tc.mode == "action" {
				if got := resolveThresholds(cfg, tc.connector).Block; got != tc.blockAt {
					t.Errorf("block_at %q, want %q", got, tc.blockAt)
				}
				if got := hiltEnabledForConfig(cfg, tc.connector); got != tc.hilt {
					t.Errorf("HILT %v, want %v", got, tc.hilt)
				}
				if tc.hilt && hiltMinRankForConfig(cfg, tc.connector) != tc.hiltAt {
					t.Errorf("HILT at %d, want %d", hiltMinRankForConfig(cfg, tc.connector), tc.hiltAt)
				}
			}
			// The meet is never weaker than a member that blocks.
			for _, member := range []string{"a", "b"} {
				m := set.profileConfig(member)
				if hookModeForConfig(m, tc.connector) == "action" {
					mb, _ := guardrailThresholdRanks(resolveThresholds(m, tc.connector))
					cb, _ := guardrailThresholdRanks(resolveThresholds(cfg, tc.connector))
					if hookModeForConfig(cfg, tc.connector) != "action" || cb > mb {
						t.Errorf("the meet blocks less than %s", member)
					}
				}
			}
		})
	}
}

// Profiles that enforce different rule packs or sandbox sections: their
// meet applies, never a refusal, and it keeps the sandbox limits of both.
func TestProfileMeetOfDifferentSandboxSections(t *testing.T) {
	set := meetTestSet(t, map[string]config.GuardrailProfile{
		"a": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}, EgressBlock: []string{"a.example"}}},
		"b": {Mode: "action", BlockAt: "LOW", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"b.example"}, AllowedHarnesses: []string{"codex", "claudecode"}}},
	})
	name, single := set.meetOf([]string{"a", "b"}, "codex")
	if single || !config.IsProfileMeet(name) {
		t.Fatalf("%q single %v; want the meet", name, single)
	}
	derived, ok := set.derivedProfile(name)
	if !ok {
		t.Fatal("the meet did not derive")
	}
	f := derived.Sandbox
	if !slices.Contains(f.RequiredFor, "codex") || !slices.Contains(f.EgressBlock, "a.example") || !slices.Contains(f.EgressBlock, "b.example") ||
		len(f.AllowedHarnesses) != 2 || resolveThresholds(derived.Config, "codex").Block != "LOW" {
		t.Fatalf("meet floor %+v, block %s; want both members' limits", f, resolveThresholds(derived.Config, "codex").Block)
	}
	// The same meet resolves after a restart from its name alone.
	if again, ok := newGuardrailProfileSetFor(t, set.base).derivedProfile(name); !ok || again.Digest != derived.Digest {
		t.Fatalf("meet %q does not resolve by name in another set", name)
	}
}

func newGuardrailProfileSetFor(t *testing.T, cfg *config.Config) *guardrailProfileSet {
	t.Helper()
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// A rule any member's pack enforces is enforced: the meet's generation has
// every rule of every member, one the members define the same way once.
func TestProfileMeetEnforcesTheRulesOfEveryPack(t *testing.T) {
	rule := func(id, pattern, severity string) PatternRule {
		return PatternRule{ID: id, Pattern: regexp.MustCompile(pattern), Title: id, Severity: severity, Confidence: 0.9}
	}
	a, err := compileRulePackGeneration([]ruleCategory{{Name: "cmd", Rules: []PatternRule{rule("R-SHARED", "rm -rf", "HIGH"), rule("R-A", "curl evil", "HIGH")}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileRulePackGeneration([]ruleCategory{
		{Name: "cmd", Rules: []PatternRule{rule("R-SHARED", "rm -rf", "HIGH")}},
		{Name: "secrets", Rules: []PatternRule{rule("R-B", "AKIA[0-9A-Z]{16}", "CRITICAL")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeRuleGenerations([]*compiledRulePackCategories{a, b})
	ids := map[string]int{}
	for _, category := range merged.categories {
		for _, r := range category.Rules {
			ids[r.ID]++
		}
	}
	if ids["R-SHARED"] != 1 || ids["R-A"] != 1 || ids["R-B"] != 1 {
		t.Fatalf("merged rules %v; want each rule once", ids)
	}
	for _, text := range []string{"rm -rf /", "curl evil.sh", "AKIAABCDEFGHIJKLMNOP"} {
		if findings := scanRuleGeneration(merged, text, "Bash", ruleScanOptions{}); len(findings) == 0 {
			t.Errorf("%q: no finding; want the member's rule to fire", text)
		}
	}
}

// Allows are the intersection: a suppression applies only when every
// member's pack has it; a sensitive tool any member inspects is inspected.
func TestProfileMeetIntersectsSuppressionsAndUnionsSensitiveTools(t *testing.T) {
	shared := guardrail.FindingSuppression{ID: "shared", FindingPattern: "PII-EMAIL"}
	only := guardrail.FindingSuppression{ID: "only-a", FindingPattern: "SECRET-KEY"}
	a := &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{FindingSupps: []guardrail.FindingSuppression{shared, only}},
		SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{{Name: "read_db", MinEntitiesAlert: 5}}}}
	b := &guardrail.RulePack{Suppressions: &guardrail.SuppressionsConfig{FindingSupps: []guardrail.FindingSuppression{shared}},
		SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{{Name: "read_db", ResultInspection: true, MinEntitiesAlert: 2}, {Name: "fetch", JudgeResult: true}}}}
	merged := mergeRulePacks([]*guardrail.RulePack{a, b}, false)
	if len(merged.Suppressions.FindingSupps) != 1 || merged.Suppressions.FindingSupps[0].ID != "shared" {
		t.Fatalf("suppressions %+v; want only the shared one", merged.Suppressions.FindingSupps)
	}
	db := merged.LookupSensitiveTool("read_db")
	if db == nil || !db.ResultInspection || db.MinEntitiesAlert != 2 || merged.LookupSensitiveTool("fetch") == nil {
		t.Fatalf("sensitive tools %+v; want every tool at its strictest", merged.SensitiveTools)
	}
	if none := mergeRulePacks([]*guardrail.RulePack{a, b}, true); len(none.Suppressions.FindingSupps) != 0 {
		t.Fatalf("a member with no pack: suppressions %+v; want none", none.Suppressions.FindingSupps)
	}
	if len(a.Suppressions.FindingSupps) != 2 {
		t.Fatal("the merge changed a member's pack")
	}
}

// Overlapping proven assignments whose profiles enforce different rules:
// their meet applies whatever the order, never one that drops the other's
// sandbox denial or block level.
func TestOverlappingProvenAssignmentsApplyTheirMeet(t *testing.T) {
	p := identityTestPlatforms[0]
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"sandboxed": {Mode: "action", BlockAt: "HIGH", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"low":       {Mode: "action", BlockAt: "LOW"},
	}
	byUser := config.ProfileAssignment{Profile: "sandboxed", Match: config.ProfileMatch{Users: []string{p.id}}}
	byGroup := config.ProfileAssignment{Profile: "low", Match: config.ProfileMatch{Groups: []string{p.group}}}
	subject := identityTestSubject(p, p.providers[1], stateProven, true)
	want := config.ProfileMeetName([]string{"low", "sandboxed"})
	for _, order := range [][]config.ProfileAssignment{{byUser, byGroup}, {byGroup, byUser}} {
		cfg.Guardrail.ProfileAssignments = order
		set := newGuardrailProfileSetFor(t, cfg)
		got := set.match(&subject, profileSubjectVerified, "codex", "")
		if got.Name != want || got.Assignment != 1 || len(got.Candidates) != 2 {
			t.Fatalf("order %+v: %+v; want %s reported as the first assignment", order, got, want)
		}
		derived, _ := set.derivedProfile(got.Name)
		if resolveThresholds(derived.Config, "codex").Block != "LOW" || !slices.Contains(derived.Sandbox.RequiredFor, "codex") {
			t.Fatalf("meet %+v; want block_at LOW and codex required in a sandbox", derived)
		}
	}
}

// Windows: 1.0.0 to 1.0.3 keyed an agent identity of a SID on the SID, as
// 1.0.4 does, so an agents entry written for it keeps matching exactly
// after the upgrade, with no migration map.
func TestUpgradeKeepsWindowsAgentsAssignments(t *testing.T) {
	in := agentidentity.Inputs{MachineHash: "m", UserID: "S-1-5-21-9-9-9-1105", Connector: "codex", InstallFP: `C:\Users\alice\.codex`, Account: `CORP\alice`}
	if agentidentity.LegacyAgentID(in) != "" {
		t.Fatal("a SID's 1.0.3 identity differs from its current one")
	}
	agent := agentidentity.AgentID(in)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"relaxed": {Mode: "observe"}, "strict": {Mode: "action", BlockAt: "LOW"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "relaxed", Match: config.ProfileMatch{Agents: []string{agent}}}}
	cfg.Guardrail.DefaultProfile = "strict"
	set := newGuardrailProfileSetFor(t, cfg)
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: in.UserID, IDKind: useridentity.KindWindowsSID, UserName: `CORP\alice`,
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceWindowsLSA, Directory: useridentity.DirectoryActiveDirectory,
			Assurance: useridentity.AssuranceVerified}}, true)
	got := set.matchAgent(&subject, profileSubjectVerified, "codex", agent, func() (profileAgentClaim, bool) { return profileAgentClaim{}, true })
	if got.Name != "relaxed" || got.Match != profileMatchAgent {
		t.Fatalf("Windows 1.0.x agents entry: %+v; want relaxed by agent", got)
	}
}

// GAP-0487: a Windows group name whose SID lookup is in flight or failed may
// name one of the token's groups: its assignment is a candidate, never a
// definite no that lets a weaker default apply. A name the directory says
// is no group is a no.
func TestPendingWindowsGroupNameIsACandidate(t *testing.T) {
	p := identityTestPlatforms[2]
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "lookup in flight", want: "strict"},
		{name: "lookup failed", err: errProfileGroupLookupsFull, want: "strict"},
		{name: "no such group", err: errProfileGroupUnknown, want: "watch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\Engineers`}}})
			set.groupSIDs = &profileGroupSIDs{entries: map[string]*profileGroupSIDEntry{
				foldKey(`CORP\Engineers`): {name: `CORP\Engineers`, err: tc.err},
			}}
			subject := identityTestSubject(p, p.providers[0], stateProven, false)
			got := set.matchUncached(&subject, profileSubjectVerified, "codex", "")
			if got.Name != tc.want {
				t.Fatalf("%+v; want %s", got, tc.want)
			}
			if tc.err != errProfileGroupUnknown &&
				!strings.Contains(unprovenReason(got), "assignment group SID is unconfirmed") {
				t.Fatalf("pending SID lookup did not refuse with its missing fact: %+v", got)
			}
			if tc.err == errProfileGroupUnknown && unprovenReason(got) != "" {
				t.Fatalf("proven absent group refused: %+v", got)
			}
		})
	}
}
