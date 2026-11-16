// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0732: an account named in a users assignment by its local name, on a
// host where only the process credentials prove the holder, kept the
// per-user OSS install in action mode refusing every prompt: the inspect path
// had no fallback, and an unset global block_at was not read as the level the
// rule pack blocks from, so no stricter profile was found even for hooks.
type g732Config struct {
	globalMode, globalBlockAt, defaultProfile, pack, deployment string
	profile                                                     config.GuardrailProfile
}

func g732Set(t *testing.T, c g732Config) (*guardrailProfileSet, profileSubject) {
	t.Helper()
	p := identityTestPlatforms[0]
	subject := identityTestSubject(p, p.providers[0], stateProven, false)
	subject.holderUnproven = true
	cfg := &config.Config{}
	cfg.Guardrail.Mode = c.globalMode
	cfg.Guardrail.BlockAt = c.globalBlockAt
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.DefaultProfile = c.defaultProfile
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"localstrict": c.profile, "plain": {Mode: "action"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
		Profile: "localstrict", Match: config.ProfileMatch{Users: []string{p.name}},
	}}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	set.base.Guardrail.RulePack = c.pack
	set.base.DeploymentMode = c.deployment
	return set, subject
}

func g732Decide(set *guardrailProfileSet, subject *profileSubject, path profilePath) profileDecision {
	return set.selectProfile(subject, resolveIdentity(subject, nil), profileSubjectProcessOwner, "claudecode", nil, path, "")
}

func TestGAP0732LocalNameAssignmentKeepsOrdinaryPromptsOnOSS(t *testing.T) {
	action := config.GuardrailProfile{Mode: "action", BlockAt: "MEDIUM"}
	for _, tc := range []struct{ defaultProfile, pack string }{{"", ""}, {"plain", ""}, {"plain", "permissive"}} {
		for _, globalBlockAt := range []string{"", "HIGH", "CRITICAL"} {
			c := g732Config{globalMode: "action", globalBlockAt: globalBlockAt, defaultProfile: tc.defaultProfile, pack: tc.pack, profile: action}
			set, subject := g732Set(t, c)
			for _, path := range []profilePath{profilePathHook, profilePathInspect} {
				got := g732Decide(set, &subject, path)
				if got.Refused != "" || !slices.Equal(got.Unproven, []string{"account:unknown"}) || !got.holderFallback {
					t.Errorf("%+v path %d: %+v; want the warned default", c, path, got)
				}
			}
			decision, refusedOn, _ := set.explainOnRequestPaths("claudecode", func(path profilePath) profileDecision {
				return g732Decide(set, &subject, path)
			})
			if decision.Refused != "" || len(refusedOn) != 0 {
				t.Errorf("%+v: explain refused %v: %+v", c, refusedOn, decision)
			}
			if warnings := profileExplainWarnings(set, decision, &subject); !slices.ContainsFunc(warnings, func(note string) bool {
				return strings.Contains(note, "account holder is unconfirmed")
			}) {
				t.Errorf("%+v: no holder warning in %q", c, warnings)
			}
		}
	}
	// The global level already blocks from the assigned level: nothing is
	// uncertain.
	set, subject := g732Set(t, g732Config{globalMode: "action", globalBlockAt: "MEDIUM", profile: action})
	for _, path := range []profilePath{profilePathHook, profilePathInspect} {
		if got := g732Decide(set, &subject, path); got.Refused != "" || len(got.Unproven) != 0 {
			t.Errorf("covered global level, path %d: %+v", path, got)
		}
	}
}

// What the fallback does not cover keeps its account proof: the strict tier,
// managed installs, a profile that starts enforcing on a path the default only
// observes, and one that differs by more than the block level.
func TestGAP0732UnconfirmedHolderStillRefusedWhereProofIsRequired(t *testing.T) {
	action := config.GuardrailProfile{Mode: "action", BlockAt: "MEDIUM"}
	sandboxed := action
	sandboxed.Sandbox = &config.OpenShellAdminConfig{EgressBlock: []string{"blocked.example"}}
	for _, tc := range []struct {
		name string
		c    g732Config
		path profilePath
	}{
		{"strict tier hook", g732Config{globalMode: "action", defaultProfile: "plain", pack: "strict", profile: action}, profilePathHook},
		{"strict tier inspect", g732Config{globalMode: "action", defaultProfile: "plain", pack: "strict", profile: action}, profilePathInspect},
		{"managed hook", g732Config{globalMode: "action", deployment: managed.DeploymentModeManagedEnterprise, profile: action}, profilePathHook},
		{"managed inspect", g732Config{globalMode: "action", deployment: managed.DeploymentModeManagedEnterprise, profile: action}, profilePathInspect},
		{"different sandbox inspect", g732Config{globalMode: "action", profile: sandboxed}, profilePathInspect},
		{"observing default on inspect", g732Config{globalMode: "observe", profile: action}, profilePathInspect},
	} {
		set, subject := g732Set(t, tc.c)
		if got := g732Decide(set, &subject, tc.path); got.Refused == "" || !slices.Equal(got.Unproven, []string{"account:unknown"}) {
			t.Errorf("%s: %+v; want the holder refusal", tc.name, got)
		}
	}
}
