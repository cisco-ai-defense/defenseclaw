// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Privacy (decision 4 of the 1.0.4 identity design). A caller whose facts
// are unproven is refused under strict. Settings, policy/explain, policy/test
// and policy/packs must name the missing fact without showing a candidate
// profile, its description or its egress policy; outside strict they answer
// under the strictest combination, and still show none of them. A live
// registration keeps its last proven profile during a re-match and stays
// live.
func TestSandboxPolicyViewsOfAnUnprovenDecisionNameNoOtherProfile(t *testing.T) {
	for _, tier := range []string{"strict", "action"} {
		t.Run(tier, func(t *testing.T) { sandboxPolicyViewsOfAnUnprovenDecision(t, tier) })
	}
}

func sandboxPolicyViewsOfAnUnprovenDecision(t *testing.T, tier string) {
	const secret = "bob-internal.example"
	setup := func(t *testing.T) *sandboxFixture {
		t.Helper()
		f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
		f.cfg.Guardrail.Profiles["bob-only"] = strictTier(t, f.cfg, config.GuardrailProfile{Description: "Bob private profile",
			Sandbox: &config.OpenShellAdminConfig{EgressAllowOnly: []string{secret}}}, tier)
		f.cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
			{Profile: "bob-only", Match: config.ProfileMatch{Users: []string{sbxBob.Name}}},
			{Profile: "bob-only", Match: config.ProfileMatch{Groups: []string{"dc-sbx-bob-team"}}},
		}, f.cfg.Guardrail.ProfileAssignments...)
		f.publishFirstGeneration()
		return f
	}
	groupsUnknown := func(f *sandboxFixture, peer managedHookPeer) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.facts[peer.UID] = useridentity.DirectoryFacts{
			Principal: peer.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Source: "sssd", GroupsPartial: true, ResolvedAt: time.Now(),
		}
	}
	leaks := func(body string) bool {
		return strings.Contains(body, "bob-only") || strings.Contains(body, "Bob private") || strings.Contains(body, secret)
	}
	views := func(t *testing.T, f *sandboxFixture, header map[string]string, registration, missingFact string) {
		t.Helper()
		for _, call := range []struct {
			name, method, path string
			body               any
		}{
			{"settings", http.MethodGet, sandboxrelay.PathSettings, nil},
			{"explain", http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Connector: "claudecode", Registration: registration}},
			{"test", http.MethodPost, sandboxrelay.PathPolicyTest, sandboxrelay.PolicyTestRequest{V: 1, Checks: []sandboxapi.PolicyCheck{{Host: "pkg.example", Port: 443}}}},
			{"packs", http.MethodGet, sandboxrelay.PathPolicyPacks, nil},
		} {
			rec := f.do(sbxAlice, call.method, call.path, call.body, header)
			if tier == "strict" && (rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), missingFact)) {
				t.Errorf("%s: %d %s; want refusal naming %s", call.name, rec.Code, rec.Body.String(), missingFact)
			}
			if tier != "strict" && rec.Code != http.StatusOK {
				t.Errorf("%s: %d %s; want an answer under the strictest combination", call.name, rec.Code, rec.Body.String())
			}
			if leaks(rec.Body.String()) {
				t.Errorf("%s: %d %s names another account's profile", call.name, rec.Code, rec.Body.String())
			}
		}
	}
	t.Run("account lookup failed", func(t *testing.T) {
		f := setup(t)
		// explain, test and packs wait identityDirectoryBudget for the lookup.
		f.coldCache(sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "", "account")
	})
	t.Run("groups unknown", func(t *testing.T) {
		f := setup(t)
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}, "", "group")
	})
	t.Run("a live registration re-matched while its facts are unproven", func(t *testing.T) {
		f := setup(t)
		f.setGroups(sbxAlice, "dc-sbx-contractors")
		resp := f.live(sbxAlice, 1)
		if resp.Registration.Provisional || resp.Banner.Profile != "contractors" {
			t.Fatalf("create: %+v %+v", resp.Registration, resp.Banner)
		}
		groupsUnknown(f, sbxAlice)
		views(t, f, map[string]string{sandboxrelay.ConnectorHeader: "claudecode", sandboxrelay.RegistrationHeader: resp.Registration.ID}, resp.Registration.ID, "group")
		// A decision is checked against the person's own floor, which no
		// proven fact gives now.
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: resp.Registration.ID, Kind: sandboxrelay.DecisionEgressBlock, Host: "example.org",
			Scope: sandboxrelay.DecisionScopeAlways,
		}, nil)
		if tier == "strict" && (rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "group membership is unconfirmed")) ||
			leaks(rec.Body.String()) {
			t.Errorf("decision: %d %s; want a refusal naming the group fact under strict, and no other profile", rec.Code, rec.Body.String())
		}
		auth, _ := f.api.sandboxAuth()
		reg, ok, err := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
		members, _ := config.ProfileMeetMembers(reg.Profile)
		if err != nil || !ok || reg.Profile != "contractors" || slices.Contains(members, "bob-only") || reg.State != sandboxreg.StateLive {
			t.Errorf("registration after the unproven re-match: %+v (%v); want the last proven contractors profile, live", reg, err)
		}
	})
}

// A configuration change while a registration's facts are unproven keeps
// its profile; once the facts are proven again, unchanged, it re-matches
// under the new configuration instead of keeping the profile of the old one.
func TestSandboxRematchAfterUnprovenFactsUsesTheNewConfiguration(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)
	if resp.Banner.Profile != "contractors" {
		t.Fatalf("create: %+v", resp.Banner)
	}
	moved := newSandboxFixtureOn(t, f)
	moved.cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
	}
	moved.publishFirstGeneration()
	moved.mu.Lock()
	moved.facts[sbxAlice.UID] = useridentity.DirectoryFacts{
		Principal: sbxAlice.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
		Source: "sssd", GroupsPartial: true, ResolvedAt: time.Now(),
	}
	moved.mu.Unlock()
	if rec := moved.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Header().Get(sandboxrelay.ProfileHeader) != "contractors" {
		t.Fatalf("hook while the groups are unknown: %d %v; want the kept contractors profile", rec.Code, rec.Header())
	}
	moved.setGroups(sbxAlice, "dc-sbx-contractors")
	if rec := moved.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK ||
		rec.Header().Get(sandboxrelay.ProfileHeader) != "engineering" {
		t.Fatalf("hook once the groups are proven again: %d %s %v; want engineering", rec.Code, rec.Body.String(), rec.Header())
	}
}
