// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

const sshKeyPath = "/home/u/.ssh/authorized_keys"

func exactKnown(set string) *semanticpb.ProtectedMatch {
	return &semanticpb.ProtectedMatch{Set: set, State: "known", Reason: "exact"}
}

// mkFact builds one path-target effect fact for the classifier.
func mkFact(kind, state, role, program, surface string, reasons []string, matches ...*semanticpb.ProtectedMatch) *semanticpb.EffectFact {
	return &semanticpb.EffectFact{
		Kind: kind, TargetState: state, RoleState: role, Reasons: reasons,
		Origin: &semanticpb.EffectOrigin{Program: program, Surface: surface},
		Target: &semanticpb.EffectTarget{Type: "path", Path: sshKeyPath, Flavor: "posix", Protected: matches},
	}
}

func accounted() effects.Result { return effects.Result{} }
func unaccounted() effects.Result {
	return effects.Result{Unknowns: []effects.Reason{{Code: effects.ReasonLimit}}}
}

// A listed command, every token accounted, an exact canonical known member of
// each set is the restricted tier; a ruling family (SSH / self-protection)
// additionally blocks in the OSS default.
func TestClassifyRestrictedListedCommands(t *testing.T) {
	listed := []struct{ program, surface string }{
		{"", "shell"}, // redirection
		{"cp", "shell"}, {"mv", "shell"}, {"ln", "shell"}, {"tee", "shell"},
		{"rm", "shell"}, {"install", "shell"},
		{"Set-Content", "shell"}, {"Remove-Item", "shell"}, {"New-Item", "shell"},
		{"", "file_tool"}, {"", "patch"},
	}
	for _, set := range effectrules.AllSets {
		for _, lc := range listed {
			facts := []*semanticpb.EffectFact{mkFact("write", "known", "known", lc.program, lc.surface, nil, exactKnown(set))}
			c := classifyEffects(accounted(), facts, effects.FlavorPOSIX)
			if !c.restricted {
				t.Fatalf("set %s cmd %q/%q: expected restricted tier", set, lc.program, lc.surface)
			}
			wantRuling := set == effectrules.SetSSHAuthorizedKeys || set == effectrules.SetSelfProtection
			if c.restrictedRuling != wantRuling {
				t.Fatalf("set %s cmd %q: restrictedRuling=%v want %v", set, lc.program, c.restrictedRuling, wantRuling)
			}
		}
	}
}

// An unlisted command writing to a protected set is NOT restricted; it is the
// unknown tier (a known protected touch the restricted list does not clear).
func TestClassifyUnlistedCommandIsUnknownTier(t *testing.T) {
	for _, set := range effectrules.AllSets {
		for _, prog := range []string{"python", "dd", "awk", "sqlite3"} {
			facts := []*semanticpb.EffectFact{mkFact("write", "known", "known", prog, "shell", nil, exactKnown(set))}
			c := classifyEffects(accounted(), facts, effects.FlavorPOSIX)
			if c.restricted {
				t.Fatalf("set %s unlisted cmd %q: must not be restricted", set, prog)
			}
			if !c.touches {
				t.Fatalf("set %s unlisted cmd %q: expected unknown-tier touch", set, prog)
			}
		}
	}
}

// One unaccounted flag (the call is not fully token-accounted) demotes a listed
// command to the unknown tier, never the restricted block.
func TestClassifyUnaccountedFlagIsUnknownTier(t *testing.T) {
	// call-level: an unresolved token somewhere in the command.
	facts := []*semanticpb.EffectFact{mkFact("write", "known", "known", "cp", "shell", nil, exactKnown(effectrules.SetSSHAuthorizedKeys))}
	if c := classifyEffects(unaccounted(), facts, effects.FlavorPOSIX); c.restricted || !c.touches {
		t.Fatalf("call-level unaccounted: restricted=%v touches=%v, want restricted=false touches=true", c.restricted, c.touches)
	}
	// effect-level: an unknown-flag reason on the effect itself.
	facts = []*semanticpb.EffectFact{mkFact("write", "known", "known", "cp", "shell", []string{"role:unknown_flag"}, exactKnown(effectrules.SetSSHAuthorizedKeys))}
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX); c.restricted || !c.touches {
		t.Fatalf("effect-level unaccounted: restricted=%v touches=%v, want restricted=false touches=true", c.restricted, c.touches)
	}
}

// R5F-1: an UNKNOWN effect that could reach a protected set goes to the unknown
// tier, never clean. (Git Bash / Cygwin virtual_root targets become UNKNOWN.)
func TestClassifyUnknownEffectReachesUnknownTier(t *testing.T) {
	facts := []*semanticpb.EffectFact{mkFact("write", "unknown", "known", "cp", "shell",
		[]string{"target:dynamic_cwd"}, &semanticpb.ProtectedMatch{Set: effectrules.SetOutsideHome, State: "unknown", Reason: "unresolved"})}
	c := classifyEffects(accounted(), facts, effects.FlavorPOSIX)
	if c.restricted {
		t.Fatalf("unknown effect must not be restricted")
	}
	if !c.touches {
		t.Fatalf("unknown effect that could reach a protected set must be the unknown tier, not clean")
	}
}

// A benign read of a non-credential protected file (shell rc, agent config) is
// not escalated; a credential read is.
func TestClassifyReadRelevance(t *testing.T) {
	shellRead := []*semanticpb.EffectFact{mkFact("read", "known", "known", "cat", "shell", nil, exactKnown(effectrules.SetShellRC))}
	if classifyEffects(accounted(), shellRead, effects.FlavorPOSIX).touches {
		t.Fatalf("a benign shell-rc read must not touch the protected tier")
	}
	credRead := []*semanticpb.EffectFact{mkFact("read", "known", "known", "cat", "shell", nil, exactKnown(effectrules.SetCredentials))}
	if !classifyEffects(accounted(), credRead, effects.FlavorPOSIX).touches {
		t.Fatalf("a credential read must touch the protected tier")
	}
}

func TestEffectAction(t *testing.T) {
	cases := []struct {
		name                       string
		touches, ruling, strictMgd bool
		want                       string
	}{
		{"clean allows", false, false, false, guardrailActionAllow},
		{"ruling restricted blocks in default", true, true, false, guardrailActionBlock},
		{"non-ruling touch alerts in default", true, false, false, guardrailActionAlert},
		{"any touch blocks in strict/managed", true, false, true, guardrailActionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectAction(tc.touches, tc.ruling, tc.strictMgd); got != tc.want {
				t.Fatalf("effectAction = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectShadowFindingsEnforcement(t *testing.T) {
	restricted := effectShadowFindings(EffectShadowResult{Tier: string(effectTierRestricted), Action: guardrailActionBlock, Kind: "write",
		Sets: []string{effectrules.SetSSHAuthorizedKeys}}, effectRulesOn)
	if len(restricted) != 1 || !restricted[0].contributesToEnforcement() || restricted[0].Severity != "CRITICAL" {
		t.Fatalf("restricted finding = %+v, want one enforcing CRITICAL finding", restricted)
	}
	if !restricted[0].proof.authorizes(restricted[0].RuleID) {
		t.Fatalf("restricted proof must authorize a deny in ON mode")
	}
	if restricted[0].disposition != findingDispositionEffectKnown {
		t.Fatalf("restricted disposition = %v, want effect_known", restricted[0].disposition)
	}
	alert := effectShadowFindings(EffectShadowResult{Tier: string(effectTierUnknown), Action: guardrailActionAlert, Kind: "delete",
		Sets: []string{effectrules.SetSSHAuthorizedKeys}}, effectRulesOn)
	if len(alert) != 1 || alert[0].enforcement != findingEnforcementAlertOnly || alert[0].disposition != findingDispositionEffectUnknown {
		t.Fatalf("unknown-tier finding = %+v, want one alert-only effect_unknown finding", alert)
	}
	if got := effectShadowFindings(EffectShadowResult{Tier: string(effectTierClean), Action: guardrailActionAllow}, effectRulesOn); got != nil {
		t.Fatalf("clean findings = %+v, want nil", got)
	}
}

// End to end: a redirection append to authorized_keys is the restricted ruling
// tier and blocks in every mode.
func TestComputeEffectShadowRestrictedAuthorizedKeys(t *testing.T) {
	effectResolverOverride = func(p string) (string, bool) { return p, true }
	defer func() { effectResolverOverride = nil }()
	req := trustedActionRequest{
		Connector: "claudecode",
		Input: actionfacts.Input{
			Tool: "Bash", Command: "echo k >> ~/.ssh/authorized_keys",
			ActiveHome: "/home/u", CWD: "/home/u/work", DialectHint: actionfacts.DialectPOSIX,
		},
	}
	res := computeEffectShadow(req, effectRulesShadow)
	if res.Tier != string(effectTierRestricted) {
		t.Fatalf("tier = %q, want restricted", res.Tier)
	}
	if res.Action != guardrailActionBlock {
		t.Fatalf("default action = %q, want block (ruling family)", res.Action)
	}
}
