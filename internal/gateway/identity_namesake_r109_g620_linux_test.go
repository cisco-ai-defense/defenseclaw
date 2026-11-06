// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An OSS gateway can prove its process groups while the NSS account holder
// still awaits a root-only directory answer. The default policy tier keeps
// ordinary work on the configured default and reports that uncertainty;
// proven assignments, managed installs and the strict tier keep their rules.
func TestGAP0620UnconfirmedLocalNamesakeUsesOSSDefaultWithWarning(t *testing.T) {
	const localID = "700002"
	assignment := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{
		Users: []string{"alice@corp.example"},
	}}
	newSet := func(t *testing.T, mode, pack string) *guardrailProfileSet {
		t.Helper()
		set := identityTestSet(t, identityTestPlatforms[0], "watch", assignment)
		set.base.DeploymentMode = mode
		set.base.Guardrail.RulePack = pack
		return set
	}
	local := profileSubjectFromVerified(VerifiedSubject{
		UserID: localID, IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{
			Source: useridentity.SourceProcessCredentials, HolderUnproven: true,
			Groups: []string{"staff"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourceProcessOwner,
	}, true)
	for _, pack := range []string{"", "permissive"} {
		set := newSet(t, "", pack)
		got := set.match(&local, profileSubjectProcessOwner, "claudecode", "")
		if got.Name != "watch" || got.Refused != "" || got.Match != profileMatchDefaultLookupFailed ||
			!slices.Equal(got.Unproven, []string{"account:unknown"}) {
			t.Errorf("OSS pack %q: decision = %+v; want warned default", pack, got)
		}
		if warnings := profileExplainWarnings(set, got, &local); !slices.ContainsFunc(warnings, func(note string) bool {
			return strings.Contains(note, "account holder is unconfirmed")
		}) {
			t.Errorf("OSS pack %q: warnings = %q; want holder note", pack, warnings)
		}
	}
	set := newSet(t, "", "")
	inspect := set.selectProfile(&local, resolveIdentity(&local, nil), profileSubjectProcessOwner,
		"claudecode", nil, profilePathInspect, "")
	if inspect.Refused == "" || !slices.Equal(inspect.Unproven, []string{"account:unknown"}) {
		t.Errorf("inspection still needs account proof: %+v", inspect)
	}
	for _, tc := range []struct{ mode, pack string }{
		{"", "strict"}, {managed.DeploymentModeManagedEnterprise, ""},
	} {
		set := newSet(t, tc.mode, tc.pack)
		got := set.match(&local, profileSubjectProcessOwner, "claudecode", "")
		if got.Refused == "" || !slices.Equal(got.Unproven, []string{"account:unknown"}) {
			t.Errorf("mode %q pack %q: decision = %+v; want holder refusal", tc.mode, tc.pack, got)
		}
	}
	provenLocal := profileSubjectFromVerified(VerifiedSubject{
		UserID: localID, IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Groups: []string{"staff"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourceProcessOwner,
	}, true)
	if got := set.match(&provenLocal, profileSubjectProcessOwner, "claudecode", ""); got.Name != "watch" || got.Refused != "" || got.Match != profileMatchDefault {
		t.Errorf("proven local namesake = %+v; want default", got)
	}
	ad := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700003", IDKind: useridentity.KindPOSIXUID, UserName: "alice@corp.example",
		Directory: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSD,
			Principal: "alice@corp.example", UPN: "alice@corp.example", Domain: "corp.example",
			Groups: []string{"domain-users"}, AccountSID: "S-1-5-21-1-2-3-1105",
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourcePeerCredentials,
	}, true)
	if got := set.match(&ad, profileSubjectVerified, "claudecode", ""); got.Name != "strict" || got.Refused != "" || got.Match != profileMatchUser {
		t.Errorf("directory namesake = %+v; want its assigned profile", got)
	}
}

func TestReviewG620ProvenConnectorAssignmentKeepsOrdinaryOSSWork(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	for _, selected := range []string{"watch", "tooling"} {
		for _, pack := range []string{"", "permissive", "strict"} {
			set := identityTestSet(t, identityTestPlatforms[0], "watch",
				config.ProfileAssignment{Profile: selected, Match: config.ProfileMatch{Connectors: []string{"claudecode"}}},
				config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
			set.base.Guardrail.RulePack = pack
			got := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
			if pack == "strict" {
				if got.Refused == "" {
					t.Errorf("strict tier with %q assignment allowed uncertain holder: %+v", selected, got)
				}
			} else if got.Refused != "" || got.Name != selected || got.Assignment != 1 ||
				!slices.Equal(got.Unproven, []string{"account:unknown"}) {
				t.Errorf("OSS tier %q with %q assignment did not retain proven profile: %+v", pack, selected, got)
			} else if warnings := profileExplainWarnings(set, got, &subject); !slices.ContainsFunc(warnings, func(note string) bool {
				return strings.Contains(note, "account holder is unconfirmed") && strings.Contains(note, "proven assignment")
			}) {
				t.Errorf("OSS tier %q with %q assignment has no holder warning: %q", pack, selected, warnings)
			}
		}
	}
}

func TestReviewG620UnprovenAssignmentMustKeepApprovalControl(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"base": {Mode: "action", BlockAt: "CRITICAL"},
		"approval": {Mode: "action", BlockAt: "HIGH",
			HILT: &config.HILTConfig{Enabled: true, MinSeverity: "LOW"}},
	}
	cfg.Guardrail.DefaultProfile = "base"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "approval",
		Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}}}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	if got := set.match(&subject, profileSubjectProcessOwner, "claudecode", ""); got.Refused == "" && got.Name == "base" {
		t.Errorf("uncertain approval profile silently fell to base without HILT: %+v", got)
	}
}

// Proven process facts must not turn an ordinary OSS hook
// into an account-holder refusal when only a stronger threshold is possible.
func TestReviewerG620ProvenProcessAssignmentStillAllowsOrdinaryOSS(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	for _, tc := range []struct {
		name  string
		match config.ProfileMatch
	}{
		{"proven group", config.ProfileMatch{Groups: []string{"staff"}}},
		{"proven uid", config.ProfileMatch{Users: []string{"700002"}}},
		{"proven connector and group", config.ProfileMatch{Connectors: []string{"claudecode"}, Groups: []string{"staff"}}},
	} {
		for _, pack := range []string{"", "permissive", "strict"} {
			set := identityTestSet(t, identityTestPlatforms[0], "watch",
				config.ProfileAssignment{Profile: "tooling", Match: tc.match},
				config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
			set.base.Guardrail.RulePack = pack
			got := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
			if pack == "strict" {
				if got.Refused == "" {
					t.Errorf("%s strict tier: unconfirmed holder unexpectedly allowed: %+v", tc.name, got)
				}
			} else if got.Refused != "" || got.Name != "tooling" || got.Assignment != 1 ||
				!slices.Equal(got.Unproven, []string{"account:unknown"}) {
				t.Errorf("%s OSS tier %q: ordinary hook refused despite proven process assignment: %+v", tc.name, pack, got)
			}
		}
	}
}

// A warned hook allow must not hide a simultaneous inspect
// refusal in the profile explanation.
func TestReviewerG620ExplainNamesInspectionRefusal(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	set := identityTestSet(t, identityTestPlatforms[0], "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
	decide := func(path profilePath) profileDecision {
		return set.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectProcessOwner,
			"claudecode", nil, path, "")
	}
	if hook, inspect := decide(profilePathHook), decide(profilePathInspect); hook.Refused != "" || inspect.Refused == "" {
		t.Fatalf("fixture: hook=%+v inspect=%+v", hook, inspect)
	}
	decision, refusedOn, _ := set.explainOnRequestPaths("claudecode", decide)
	if decision.Refused == "" || !slices.Contains(refusedOn, "inspect") {
		t.Errorf("explain hid the inspect refusal: decision=%+v refusedOn=%v", decision, refusedOn)
	}
}

// An uncertain local namesake still protects a literal
// target and a target carried by a known shell variable.
func TestReviewerG620UncertainNamesakeKeepsProtectedHookBlock(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	set := identityTestSet(t, identityTestPlatforms[0], "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
	set.base.Guardrail.Connector = "claudecode"
	got := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
	if got.Refused != "" || got.Name != "watch" {
		t.Fatalf("fixture: %+v", got)
	}
	api := &APIServer{scannerCfg: set.base}
	api.guardrailProfiles.set.Store(set)
	ctx := context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
		decision: got, set: set, derived: set.profileConfig(got.Name),
	})
	for _, tc := range []struct{ name, command, want string }{
		{"direct", "printf marker >> ~/.ssh/authorized_keys", "block"},
		{"known value", "P=~/.ssh/authorized_keys; printf marker >> $P", "block"},
		{"ordinary", "printf marker >> notes.txt", "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []byte(`{"command":"` + tc.command + `"}`)
			response := api.evaluateAgentHook(ctx, agentHookRequest{
				ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Bash", ToolArgs: args,
			})
			if response.Action != tc.want || (tc.want == "block" && response.RawAction != "block") {
				t.Errorf("%s: action=%s raw=%s findings=%v; want %s", tc.name, response.Action, response.RawAction, response.Findings, tc.want)
			}
		})
	}
}

func TestReviewerR4G620HolderFallbackPreservesVerifiedTarget(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	for _, route := range []struct {
		name  string
		match config.ProfileMatch
	}{
		{"default", config.ProfileMatch{}},
		{"uid", config.ProfileMatch{Users: []string{"700002"}}},
		{"group", config.ProfileMatch{Groups: []string{"staff"}}},
		{"connector and group", config.ProfileMatch{Connectors: []string{"claudecode"}, Groups: []string{"staff"}}},
	} {
		for _, pack := range []string{"", "permissive", "strict"} {
			t.Run(route.name+"/"+pack, func(t *testing.T) {
				assignments := []config.ProfileAssignment{}
				if route.name != "default" {
					assignments = append(assignments, config.ProfileAssignment{Profile: "watch", Match: route.match})
				}
				assignments = append(assignments, config.ProfileAssignment{
					Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}},
				})
				set := identityTestSet(t, identityTestPlatforms[0], "watch", assignments...)
				set.base.Guardrail.RulePack = pack
				set.base.Guardrail.Connector = "claudecode"
				decision := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
				if pack == "strict" {
					if decision.Refused == "" {
						t.Fatalf("strict tier requires holder proof: %+v", decision)
					}
					return
				}
				if decision.Refused != "" || decision.Name != "watch" ||
					!slices.Equal(decision.Unproven, []string{"account:unknown"}) {
					t.Fatalf("OSS decision = %+v; want warned selection", decision)
				}
				api := &APIServer{scannerCfg: set.base}
				api.guardrailProfiles.set.Store(set)
				ctx := context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
					decision: decision, set: set, derived: set.profileConfig(decision.Name),
				})
				for _, tc := range []struct{ name, command, want string }{
					{"direct target", "echo marker >> ~/.ssh/authorized_keys", "block"},
					{"link target", "ln -s ~/.ssh/authorized_keys keylink; echo marker >> keylink", "block"},
					{"ordinary file", "echo marker >> notes.txt", "allow"},
					{"ordinary prefix", "echo marker >> authorized_keys.bak", "allow"},
				} {
					t.Run(tc.name, func(t *testing.T) {
						response := api.evaluateAgentHook(ctx, agentHookRequest{
							ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Bash",
							ToolArgs: []byte(`{"command":"` + tc.command + `"}`),
						})
						if response.Action != tc.want || (tc.want == "block" && response.RawAction != "block") {
							t.Errorf("%s: action=%s raw=%s; want %s", tc.name, response.Action, response.RawAction, tc.want)
						}
					})
				}
			})
		}
	}
}

func TestReviewerR4G620UnscopedExplainMatchesConfiguredConnector(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	for _, pack := range []string{"", "permissive", "strict"} {
		set := identityTestSet(t, identityTestPlatforms[0], "watch",
			config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
		set.base.Guardrail.RulePack = pack
		set.base.Guardrail.Connector = "claudecode"
		live := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
		unscoped := set.match(&subject, profileSubjectLookup, "", "")
		if pack == "strict" {
			if live.Refused == "" || unscoped.Refused == "" {
				t.Errorf("strict tier pack %q: live=%+v unscoped=%+v; want holder refusal", pack, live, unscoped)
			}
			continue
		}
		if live.Refused != "" || unscoped.Refused != "" || live.Name != "watch" ||
			unscoped.Name != live.Name || !slices.Equal(unscoped.Unproven, []string{"account:unknown"}) {
			t.Errorf("pack %q: live=%+v unscoped=%+v; want same warned default", pack, live, unscoped)
		}
	}
}
