// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// surfaceModesSet is a profile set whose default, watch, observes, with
// one group assignment to profile; base sets the base configuration's
// modes (guardrail.mode, codex.mode, connector_hooks) first. The strict
// rule pack is loadable.
func surfaceModesSet(t *testing.T, base func(*config.Config), defaultProfile string, profiles map[string]config.GuardrailProfile,
	assignments ...config.ProfileAssignment) *guardrailProfileSet {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	strictTier(t, cfg, config.GuardrailProfile{}, "strict")
	if base != nil {
		base(cfg)
	}
	cfg.Guardrail.Profiles = profiles
	cfg.Guardrail.ProfileAssignments = assignments
	cfg.Guardrail.DefaultProfile = defaultProfile
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil || set == nil {
		t.Fatalf("profile set: %v", err)
	}
	return set
}

// surfaceRefusals decides d on each surface: hooks, inspect, the LLM
// proxy, and ACP and sandboxes (any surface).
func surfaceRefusals(t *testing.T, set *guardrailProfileSet, d profileDecision, connectorName string) (hook, inspect, proxy, any bool) {
	t.Helper()
	api := &APIServer{}
	api.guardrailProfiles.set.Store(set)
	ctx := context.WithValue(t.Context(), resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{decision: d, set: set})
	_, hook = api.refuseProfileHook(ctx, connector.HookProfile{}, connectorName,
		agentHookRequest{ConnectorName: connectorName, HookEventName: "pre_tool_use"}, nil, nil)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil).WithContext(ctx)
	inspect = api.refuseProfileInspect(httptest.NewRecorder(), r, "/api/v1/inspect/tool", "inspect-tool-block", "tool")
	proxy = refuseProfileProxy(httptest.NewRecorder(), r)
	any = profileRefusal(ctx, profileSurfacesAll) != ""
	return hook, inspect, proxy, any
}

// Review of r104 Q-identity (continuation 4, loop round 2): a decision
// that cannot tell which profile applies was refused when a candidate's
// global settings were strict action, also for a connector that candidate
// sets to observe, and when its inspect mode was strict action, also for
// the hooks of a connector whose hook mode observes (and the other way
// round). The release baseline applied the observe default to such a
// request. Each surface is now refused only where a candidate blocks it,
// for the request's connector: its hooks by the hook mode, inspect and the
// proxy by the inspect mode. A request without a connector reads the
// global settings. Every other surface applies the strictest combination
// in its own mode.
func TestUnprovenRefusalFollowsTheConnectorsOwnModes(t *testing.T) {
	p := identityTestPlatforms[0]
	groupsUnknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	profiles := map[string]config.GuardrailProfile{
		"watch": {Mode: "observe"},
		// Global strict action; Codex set to observe.
		"strict-codex-observe": {Mode: "action", RulePack: "strict", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}},
		// The strict pack, in the base configuration's modes.
		"strict-pack": {RulePack: "strict"},
	}
	for _, tc := range []struct {
		name      string
		base      func(*config.Config)
		profile   string
		connector string
		// The surfaces refused; hookMode and inspectMode are the modes the
		// decision applies where it is not refused.
		hook, inspect      bool
		hookMode, inspMode string
	}{
		{name: "global strict action, the connector set to observe", profile: "strict-codex-observe", connector: "codex",
			hookMode: "observe", inspMode: "observe"},
		{name: "global strict action, a connector it does not set", profile: "strict-codex-observe", connector: "hermes",
			hook: true, inspect: true},
		{name: "global strict action, a request without a connector", profile: "strict-codex-observe", connector: "",
			hook: true, inspect: true},
		{name: "strict inspect action, observe hook", profile: "strict-pack", connector: "codex",
			base: func(c *config.Config) { c.Guardrail.Mode, c.Codex.Mode = "action", "observe" },
			inspect: true, hookMode: "observe"},
		{name: "strict hook action, observe inspect", profile: "strict-pack", connector: "codex",
			base: func(c *config.Config) { c.Codex.Mode = "action" },
			hook: true, inspMode: "observe"},
		{name: "strict inspect action, observe connector_hooks entry", profile: "strict-pack", connector: "hermes",
			base: func(c *config.Config) {
				c.Guardrail.Mode = "action"
				c.ConnectorHooks = map[string]config.AgentHookConfig{"hermes": {Enabled: true, Mode: "observe"}}
			},
			inspect: true, hookMode: "observe"},
		{name: "strict action everywhere", profile: "strict-pack", connector: "codex",
			base: func(c *config.Config) { c.Guardrail.Mode = "action" }, hook: true, inspect: true},
		{name: "strict pack, observe everywhere", profile: "strict-pack", connector: "codex",
			hookMode: "observe", inspMode: "observe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := surfaceModesSet(t, tc.base, "watch", profiles, config.ProfileAssignment{Profile: tc.profile, Match: config.ProfileMatch{Groups: []string{p.group}}})
			subject := groupsUnknown
			got := set.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, tc.connector, "agt-00000000000000bb")
			if !slices.Contains(got.Unproven, "groups:unknown") {
				t.Fatalf("unproven %v; want the group fact named: %+v", got.Unproven, got)
			}
			hook, inspect, proxy, any := surfaceRefusals(t, set, got, tc.connector)
			if hook != tc.hook || inspect != tc.inspect || proxy != tc.inspect || any != (tc.hook || tc.inspect) {
				t.Fatalf("refused: hook %t, inspect %t, proxy %t, ACP/sandbox %t; want hook %t, inspect and proxy %t: %+v",
					hook, inspect, proxy, any, tc.hook, tc.inspect, got)
			}
			if (got.Refused != "") != (tc.hook || tc.inspect) || (got.Uncertain != "") != (!tc.hook || !tc.inspect) {
				t.Fatalf("refused %q, uncertain %q; want a refusal only where refused and the strictest combination named elsewhere", got.Refused, got.Uncertain)
			}
			var want []string
			if tc.hook {
				want = append(want, "hooks")
			}
			if tc.inspect {
				want = append(want, "inspect")
			}
			if got.Refused != "" && !slices.Equal(got.RefusedOn.names(), want) {
				t.Fatalf("refused surfaces %v; want %v", got.RefusedOn.names(), want)
			}
			cfg := set.profileConfig(got.Name)
			if mode := hookModeForConfig(cfg, tc.connector); !tc.hook && mode != tc.hookMode {
				t.Fatalf("hook mode %q under %q; want %s, every candidate's hook mode", mode, got.Name, tc.hookMode)
			}
			if mode := inspectMode(cfg, tc.connector); !tc.inspect && mode != tc.inspMode {
				t.Fatalf("inspect mode %q under %q; want %s, every candidate's inspect mode", mode, got.Name, tc.inspMode)
			}
		})
	}
}

// A refusal built without surfaces (RefusedOn unset) covers every one.
func TestRefusalWithoutSurfacesCoversEverySurface(t *testing.T) {
	d := profileDecision{Refused: "refused"}
	for _, surface := range []profileSurfaces{profileSurfaceHooks, profileSurfaceInspect, profileSurfacesAll} {
		if d.refusedOn(surface) == "" {
			t.Fatalf("surface %v not refused", surface)
		}
	}
	d.RefusedOn = profileSurfaceHooks
	if d.refusedOn(profileSurfaceInspect) != "" || d.refusedOn(profileSurfaceHooks) == "" || d.refusedOn(profileSurfacesAll) == "" {
		t.Fatalf("a hooks-only refusal: %+v", d)
	}
}

// Review of r104 Q-identity (continuation 4, loop round 2): the meet of
// profiles took a member's inspect action as hook action, and deriving it
// replaced the hook mode a member keeps (codex.mode, connector_hooks), so
// an unproven group fact between two profiles that differ only by their
// sandbox section made an observe Codex hook block. The meet's hook mode
// and inspect mode are now each the strictest of the members' own, for
// every connector, in a proven overlap and an unproven one alike.
func TestMeetKeepsHookAndInspectModesApart(t *testing.T) {
	p := identityTestPlatforms[0]
	groupsUnknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	profiles := map[string]config.GuardrailProfile{
		"codex-sandbox":  {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"claude-sandbox": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}},
		"watch":          {Mode: "observe"},
	}
	for _, tc := range []struct {
		name string
		base func(*config.Config)
	}{
		{name: "observe hooks, inspect in action mode", base: func(c *config.Config) {
			c.Guardrail.Mode, c.Codex.Mode, c.ClaudeCode.Mode = "action", "observe", "observe"
			c.ConnectorHooks = map[string]config.AgentHookConfig{"hermes": {Enabled: true, Mode: "observe"}}
		}},
		{name: "action hooks, inspect in observe mode", base: func(c *config.Config) {
			c.Codex.Mode = "action"
			c.ConnectorHooks = map[string]config.AgentHookConfig{"hermes": {Enabled: true, Mode: "action"}}
		}},
		{name: "a member observes, the other inspects in action mode", base: func(c *config.Config) {
			c.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action"}}
			c.Codex.Mode = "observe"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, defaultProfile := range []string{"codex-sandbox", "watch"} {
				set := surfaceModesSet(t, tc.base, defaultProfile, profiles,
					config.ProfileAssignment{Profile: "claude-sandbox", Match: config.ProfileMatch{Groups: []string{p.group}}})
				members := []string{defaultProfile, "claude-sandbox"}
				subject := groupsUnknown
				unproven := set.selectProfile(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, "codex", "agt-00000000000000bb")
				proven, _ := set.meetOf(members, "codex")
				for _, name := range []string{unproven.Name, proven} {
					if !config.IsProfileMeet(name) {
						t.Fatalf("%s: %q is no meet of %v", defaultProfile, name, members)
					}
					meet := set.profileConfig(name)
					for _, c := range append(set.meetConnectors(), "") {
						wantHook, wantInspect := "observe", "observe"
						for _, member := range members {
							cfg := set.profileConfig(member)
							if hookModeForConfig(cfg, c) == "action" {
								wantHook = "action"
							}
							if inspectMode(cfg, c) == "action" {
								wantInspect = "action"
							}
						}
						if c == "" && wantHook == "action" {
							wantInspect = "action" // the global mode, inherited by both
						}
						if got := hookModeForConfig(meet, c); got != wantHook {
							t.Errorf("%s: meet hook mode for %q is %s; want %s, the strictest member hook mode", defaultProfile, c, got, wantHook)
						}
						if got := inspectMode(meet, c); got != wantInspect {
							t.Errorf("%s: meet inspect mode for %q is %s; want %s, the strictest member inspect mode", defaultProfile, c, got, wantInspect)
						}
					}
				}
				if unproven.Refused != "" {
					t.Fatalf("%s: no member is strict, but the decision is refused: %+v", defaultProfile, unproven)
				}
			}
		})
	}
}
