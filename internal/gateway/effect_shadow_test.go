// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
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
			c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{})
			if !c.restricted {
				t.Fatalf("set %s cmd %q/%q: expected restricted tier", set, lc.program, lc.surface)
			}
			if set != effectrules.SetSelfProtection {
				continue
			}
			// A proven state write keeps its 1.0.10 Decide row: alert in
			// default/permissive and managed-default, block in strict packs.
			// The effects proof joins this row; its internal ruling bit is not
			// the live verdict.
			for _, tier := range boundedTestTiers {
				deployment := decide.PerUser
				if tier.managed {
					deployment = decide.Managed
				}
				decisionTier := decide.TierDefault
				switch tier.tier {
				case bounded.TierPermissive:
					decisionTier = decide.TierPermissive
				case bounded.TierStrict:
					decisionTier = decide.TierStrict
				}
				findings := []decide.Finding{{
					RuleID: decide.RuleStateWrite, Severity: decide.SevLow,
					Proof: decide.Proof{Kind: decide.KindWrite, Target: decide.TargetState, Certainty: decide.CertKnown, Source: "legacy"},
				}}
				effect := EffectShadowResult{
					Tier: string(effectTierRestricted), Action: effectAction(c.touches, c.restrictedRuling, decisionTier == decide.TierStrict),
					Sets: []string{effectrules.SetSelfProtection}, Program: lc.program,
					Kind: string(effects.KindWrite), Known: true, KnownMutation: true,
				}
				for _, finding := range effectShadowFindings(effect, effectRulesOn) {
					findings = append(findings, decide.Finding{
						RuleID: finding.RuleID, Severity: decide.ParseSeverity(finding.Severity), Proof: finding.Proof,
					})
				}
				got := decide.Decide(decide.Input{
					Findings:   findings,
					Deployment: deployment, Levels: decide.TierLevels(decisionTier),
					Tier: func() decide.Tier { return decisionTier },
				})
				want := decide.Alert
				if decisionTier == decide.TierStrict {
					want = decide.Block
				}
				if got.Action != want {
					t.Fatalf("self_protection cmd %q/%q tier %s: live Decide verdict=%s want %s",
						lc.program, lc.surface, tier.name, got.Action, want)
				}
			}
		}
	}
}

// An unlisted command stays in the unknown tier on general protected sets.
// A Known authorized_keys write takes its member-exact decision row.
func TestClassifyUnlistedCommandIsUnknownTier(t *testing.T) {
	for _, set := range effectrules.AllSets {
		for _, prog := range []string{"python", "dd", "awk", "sqlite3"} {
			facts := []*semanticpb.EffectFact{mkFact("write", "known", "known", prog, "shell", nil, exactKnown(set))}
			c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{})
			if want := set == effectrules.SetSSHAuthorizedKeys; c.restricted != want {
				t.Fatalf("set %s unlisted cmd %q: restricted=%v, want %v", set, prog, c.restricted, want)
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
	if c := classifyEffects(unaccounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}); c.restricted || !c.touches {
		t.Fatalf("call-level unaccounted: restricted=%v touches=%v, want restricted=false touches=true", c.restricted, c.touches)
	}
	// effect-level: an unknown-flag reason on the effect itself.
	facts = []*semanticpb.EffectFact{mkFact("write", "known", "known", "cp", "shell", []string{"role:unknown_flag"}, exactKnown(effectrules.SetSSHAuthorizedKeys))}
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}); c.restricted || !c.touches {
		t.Fatalf("effect-level unaccounted: restricted=%v touches=%v, want restricted=false touches=true", c.restricted, c.touches)
	}
}

// R5F-1: an UNKNOWN effect that could reach a protected set goes to the unknown
// tier, never clean. (Git Bash / Cygwin virtual_root targets become UNKNOWN.)
func TestClassifyUnknownEffectReachesUnknownTier(t *testing.T) {
	facts := []*semanticpb.EffectFact{mkFact("write", "unknown", "known", "cp", "shell",
		[]string{"target:dynamic_cwd"}, &semanticpb.ProtectedMatch{Set: effectrules.SetOutsideHome, State: "unknown", Reason: "unresolved"})}
	c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{})
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
	if classifyEffects(accounted(), shellRead, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}).touches {
		t.Fatalf("a benign shell-rc read must not touch the protected tier")
	}
	credRead := []*semanticpb.EffectFact{mkFact("read", "known", "known", "cat", "shell", nil, exactKnown(effectrules.SetCredentials))}
	if !classifyEffects(accounted(), credRead, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}).touches {
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
	maybe := effectShadowFindings(EffectShadowResult{Tier: string(effectTierUnknown), Action: guardrailActionAlert, Kind: "delete",
		Sets: []string{effectrules.SetSSHAuthorizedKeys}, Known: true, Reach: []string{effectrules.ReachName}}, effectRulesOn)
	if len(maybe) != 0 {
		t.Fatalf("unknown-tier MAYBE result created live findings: %+v", maybe)
	}
	knownMutation := EffectShadowResult{Tier: string(effectTierUnknown), Action: guardrailActionAlert,
		Kind: "write", Sets: []string{effectrules.SetSelfProtection}, Known: true}
	knownFlag := reflect.ValueOf(&knownMutation).Elem().FieldByName("KnownMutation")
	if knownFlag.IsValid() && knownFlag.CanSet() {
		knownFlag.SetBool(true)
	}
	if proof := effectFindingProof(knownMutation); proof.Certainty != decide.CertKnown {
		t.Fatalf("Known mutation proof = %+v, want Known", proof)
	}
	if findings := effectShadowFindings(knownMutation, effectRulesOn); len(findings) != 1 || findings[0].RuleID != "effect.protected_target_unknown" {
		t.Fatalf("Known mutation at unknown tier = %+v, want its live advisory finding", findings)
	}
	if got := effectShadowFindings(EffectShadowResult{Tier: string(effectTierClean), Action: guardrailActionAllow}, effectRulesOn); got != nil {
		t.Fatalf("clean findings = %+v, want nil", got)
	}
}

// End to end: a redirection append to authorized_keys is the restricted ruling
// tier and blocks in every mode.
func TestComputeEffectShadowRestrictedAuthorizedKeys(t *testing.T) {
	defer setEffectResolverIdle(t, func(p string) (string, bool) { return p, true })()
	req := trustedActionRequest{
		Connector: "claudecode",
		Input: actionfacts.Input{
			Tool: "Bash", Command: "echo k >> ~/.ssh/authorized_keys",
			ActiveHome: "/home/u", CWD: "/home/u/work", DialectHint: actionfacts.DialectPOSIX,
		},
	}
	res := computeEffectShadow(req, effectRulesShadow, tierRestricted)
	if res.Tier != string(effectTierRestricted) {
		t.Fatalf("tier = %q, want restricted", res.Tier)
	}
	if res.Action != guardrailActionBlock {
		t.Fatalf("default action = %q, want block (ruling family)", res.Action)
	}
}

// The full tier recognizes an unlisted command's known mutation of a general
// protected member; the known authorized_keys write is recognized in both tiers.
func TestClassifyFullTierUnlistedCommand(t *testing.T) {
	facts := []*semanticpb.EffectFact{mkFact("write", "known", "known", "python", "shell", nil, exactKnown(effectrules.SetSelfProtection))}
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}); c.restricted {
		t.Fatalf("restricted tier must not block an unlisted non-keys command")
	}
	c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierFull, effectReachEnv{})
	if !c.restricted {
		t.Fatalf("full tier must classify an unlisted command on a protected member: %+v", c)
	}
	keys := []*semanticpb.EffectFact{mkFact("write", "known", "known", "python", "shell", nil, exactKnown(effectrules.SetSSHAuthorizedKeys))}
	if c := classifyEffects(accounted(), keys, effects.FlavorPOSIX, tierRestricted, effectReachEnv{}); !c.restricted || !c.restrictedRuling {
		t.Fatalf("known keys write must use the keys ruling independent of program: %+v", c)
	}
}
