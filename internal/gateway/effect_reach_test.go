// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func maybeMatch(set, reason string) *semanticpb.ProtectedMatch {
	return &semanticpb.ProtectedMatch{Set: set, State: "unknown", Reason: reason}
}

// The reach reason of an unknown that a protected path placed (DET111 PLAN
// 5.3): R-NAME for an unknown effect on a known member, else the basis of
// the maybe match (glob, unresolved link, dynamic working folder).
func TestEffectReachPlaced(t *testing.T) {
	keys := effectrules.SetSSHAuthorizedKeys
	cases := []struct {
		name string
		fact *semanticpb.EffectFact
		want string
	}{
		{"known effect on a known member has no reason", mkFact("write", "known", "known", "cp", "shell", nil, exactKnown(keys)), ""},
		{"unknown role on a known member", mkFact("write", "known", "unknown", "cp", "shell", []string{"role:unknown_flag"}, exactKnown(keys)), effectrules.ReachName},
		{"glob", mkFact("write", "unknown", "known", "cp", "shell", nil, maybeMatch(keys, "glob")), effectrules.ReachGlob},
		{"unresolved link", mkFact("write", "unknown", "known", "cp", "shell", nil, maybeMatch(keys, "unresolved")), effectrules.ReachFS},
		{"dynamic cwd", mkFact("write", "unknown", "known", "cp", "shell", []string{string(effects.ReasonDynamicCWD)}, maybeMatch(keys, "dynamic")), effectrules.ReachCWD},
		{"protected folder spelling", mkFact("write", "unknown", "known", "cp", "shell", nil, maybeMatch(keys, "protected_dir")), effectrules.ReachName},
	}
	globFact := func(glob string, sets ...string) *semanticpb.EffectFact {
		f := mkFact("delete", "unknown", "known", "rm", "shell", []string{"target:glob"})
		f.Target.Path, f.Target.Glob, f.Origin.Dialect = "", glob, "posix"
		for _, s := range sets {
			f.Target.Protected = append(f.Target.Protected, maybeMatch(s, "glob"))
		}
		return f
	}
	beside := mkFact("permission_change", "known", "known", "chmod", "shell", nil, maybeMatch(keys, "dir"))
	beside.Target.Path = "/home/u/.ssh/known_hosts.d"
	cases = append(cases, []struct {
		name string
		fact *semanticpb.EffectFact
		want string
	}{
		// rel-1-0-10 GAP-0594 g594-x04 (rm -ri ~/*) and g594-c13 stay allow.
		{"~/* selects no dot name", globFact("/home/u/*", effectrules.SetShellRC, effectrules.SetSelfProtection, keys), ""},
		{"a delete of ~/* leaves the instruction files", globFact("/home/u/*", effectrules.SetAgentHookConfig), ""},
		{"~/.* selects the startup files", globFact("/home/u/.*", effectrules.SetShellRC), effectrules.ReachGlob},
		{"~/.ssh/auth* selects the keys file", globFact("/home/u/.ssh/auth*", keys), effectrules.ReachGlob},
		{"a known file beside the keys", beside, ""},
		{"~/.s* selects an ancestor of the keys file", globFact("/home/u/.s*", keys), effectrules.ReachGlob},
		{"a bracket the matcher does not model fails closed", globFact("/home/u/[!x]*", effectrules.SetShellRC), effectrules.ReachGlob},
		{"** fails closed", globFact("/home/**/authorized_keys", keys), effectrules.ReachGlob},
	}...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == "" && tc.fact.GetTarget().GetProtected()[0].GetState() == "unknown" {
				c := classifyEffects(accounted(), []*semanticpb.EffectFact{tc.fact}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"})
				if c.touches || len(c.reach) != 0 {
					t.Fatalf("touches %v reach %v, want clean (no reach reason)", c.touches, c.reach)
				}
				return
			}
			c := classifyEffects(accounted(), []*semanticpb.EffectFact{tc.fact}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"})
			if !c.touches {
				t.Fatalf("touches = false, want the unknown tier")
			}
			got := strings.Join(c.reach, ",")
			if got != tc.want {
				t.Fatalf("reach = %q, want %q", got, tc.want)
			}
		})
	}
}

// An unknown no protected path placed reaches the unknown tier only by the
// name scan of the call text (R-NAME; R-CODE beside opaque code); a known
// read accounts for its own name unless the unread part is code; an unknown
// with no reason stays clean, as in 1.0.10. An unknown operand of a known
// write is R-ROLE: counted (roleHeld), not raised.
func TestEffectReachUnplaced(t *testing.T) {
	const home = "/home/u"
	pathFact := func(kind, state, role, path string, reasons ...string) *semanticpb.EffectFact {
		return &semanticpb.EffectFact{
			Kind: kind, TargetState: state, RoleState: role, Reasons: reasons,
			Origin: &semanticpb.EffectOrigin{Program: "x", Surface: "shell"},
			Target: &semanticpb.EffectTarget{Type: "path", Path: path, Flavor: "posix"},
		}
	}
	opaque := &semanticpb.EffectFact{Kind: string(effects.KindOpaque), TargetState: "unknown", RoleState: "unknown",
		Origin: &semanticpb.EffectOrigin{Program: "python3", Surface: "shell"}, Target: &semanticpb.EffectTarget{Type: "none"}}
	cases := []struct {
		name     string
		result   effects.Result
		facts    []*semanticpb.EffectFact
		text     string
		touches  bool
		reach    string
		set      string
		roleHeld bool
	}{
		{"fully read call is never scanned", accounted(), nil, "echo ~/.ssh/authorized_keys", false, "", "", false},
		{"unread call naming the keys file", unaccounted(), nil, "frob ~/.ssh/authorized_keys", true, effectrules.ReachName, effectrules.SetSSHAuthorizedKeys, false},
		{"quoted spelling of a startup file", unaccounted(), nil, `frob ~/".bashrc"`, true, effectrules.ReachName, effectrules.SetShellRC, false},
		{"opaque code naming the keys file", accounted(), []*semanticpb.EffectFact{opaque}, `python3 -c "open('/home/u/.ssh/authorized_keys','a')"`, true, effectrules.ReachCode, effectrules.SetSSHAuthorizedKeys, false},
		{"unread call naming no member", unaccounted(), nil, "frob ~/notes.txt", false, "", "", false},
		{"a hook config mention is left to the readers", unaccounted(), nil, "frob ~/.claude/settings.json", false, "", "", false},
		{"a known read accounts for its name", unaccounted(), []*semanticpb.EffectFact{pathFact("read", "known", "known", home+"/.bashrc")}, "cat ~/.bashrc | frob", false, "", "", false},
		{"a known read beside code does not", accounted(), []*semanticpb.EffectFact{pathFact("read", "known", "known", home+"/.bashrc"), opaque}, "cat ~/.bashrc | python3 -c x", true, effectrules.ReachCode, effectrules.SetShellRC, false},
		{"unknown operand of a known write is held", accounted(), []*semanticpb.EffectFact{pathFact("write", "unknown", "known", "")}, "dd of=$OUT", false, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := classifyEffects(tc.result, tc.facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"})
			effectReachUnplaced(&c, tc.result, tc.facts, tc.text, home, effects.FlavorPOSIX)
			if c.touches != tc.touches || strings.Join(c.reach, ",") != tc.reach || c.roleHeld != tc.roleHeld {
				t.Fatalf("touches %v reach %q roleHeld %v, want %v %q %v", c.touches, strings.Join(c.reach, ","), c.roleHeld, tc.touches, tc.reach, tc.roleHeld)
			}
			if tc.set != "" && !slices.Contains(c.sets, tc.set) {
				t.Fatalf("sets %v lack %s", c.sets, tc.set)
			}
		})
	}
}

// With effectReachRoleRaises on, a held R-ROLE unknown reaches the unknown
// tier with its reason (the switch L0-BAR's benign rate per reason decides).
func TestEffectReachRoleRaisesWhenAllowed(t *testing.T) {
	prev := effectReachRoleRaises
	effectReachRoleRaises = true
	t.Cleanup(func() { effectReachRoleRaises = prev })
	facts := []*semanticpb.EffectFact{{Kind: "write", TargetState: "unknown", RoleState: "known",
		Origin: &semanticpb.EffectOrigin{Program: "dd", Surface: "shell"}, Target: &semanticpb.EffectTarget{Type: "path", Flavor: "posix"}}}
	c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"})
	effectReachUnplaced(&c, accounted(), facts, "dd of=$OUT", "/home/u", effects.FlavorPOSIX)
	if !c.touches || !slices.Contains(c.reach, effectrules.ReachRole) {
		t.Fatalf("touches %v reach %v, want the unknown tier by R-ROLE", c.touches, c.reach)
	}
}

// The unknown tier alerts in the default pack, per-user and managed alike
// (owner ruling GAP-1611/1698), and blocks in the strict pack; a restricted
// ruling family (authorized keys) blocks in every pack.
func TestEffectLaneActionPerPack(t *testing.T) {
	useEffectsRulesMode(t, "on")
	run := func(command string, strict, managed bool) EffectShadowResult {
		req := shadowLiveRequest(command)
		req.StrictPolicy, req.ManagedInstall = strict, managed
		return effectShadowRun(req, effectRulesOn, tierRestricted)[0]
	}
	for _, tc := range []struct {
		command                    string
		perUser, managed, strictly string
	}{
		{`echo k >> ~/.bashrc`, guardrailActionAlert, guardrailActionAlert, guardrailActionBlock},
		{shadowLiveWrite, guardrailActionBlock, guardrailActionBlock, guardrailActionBlock},
	} {
		if got := run(tc.command, false, false).Action; got != tc.perUser {
			t.Errorf("%q per-user default = %s, want %s", tc.command, got, tc.perUser)
		}
		if got := run(tc.command, false, true).Action; got != tc.managed {
			t.Errorf("%q managed default = %s, want %s", tc.command, got, tc.managed)
		}
		if got := run(tc.command, true, true).Action; got != tc.strictly {
			t.Errorf("%q managed strict = %s, want %s", tc.command, got, tc.strictly)
		}
	}
}

// Every reach reason has a counter; a verdict above clean counts each of its
// reasons once, and a held R-ROLE counts R-ROLE-held.
func TestEffectReachCounts(t *testing.T) {
	before := EffectReachCounts()
	for _, r := range effectrules.ReachReasons {
		if _, ok := before[r]; !ok {
			t.Fatalf("no counter for %s: %v", r, before)
		}
	}
	countEffectReach(EffectShadowResult{Tier: string(effectTierUnknown), Reach: []string{effectrules.ReachGlob, effectrules.ReachCode}})
	countEffectReach(EffectShadowResult{Tier: string(effectTierClean), Reach: []string{effectrules.ReachGlob}, RoleHeld: true})
	after := EffectReachCounts()
	for r, want := range map[string]int64{effectrules.ReachGlob: 1, effectrules.ReachCode: 1, effectrules.ReachName: 0, effectrules.ReachRole + "-held": 1, "LINK-held": 0} {
		if got := after[r] - before[r]; got != want {
			t.Errorf("%s counted %d, want %d", r, got, want)
		}
	}
}

// An effect finding carries its DET111 proof: the deciding kind, the
// strongest protected class, known for a restricted verdict and maybe with
// the first reach reason for a reached unknown, Source "effects".
func TestEffectFindingProof(t *testing.T) {
	restricted := effectShadowFindings(EffectShadowResult{Tier: string(effectTierRestricted), Action: guardrailActionBlock, Kind: "append",
		Sets: []string{effectrules.SetShellRC, effectrules.SetSSHAuthorizedKeys}}, effectRulesOn)
	want := decide.Proof{Kind: decide.KindAppend, Target: decide.TargetAuthorizedKeys, Certainty: decide.CertKnown, Source: "effects"}
	if len(restricted) != 1 || restricted[0].Proof != want {
		t.Fatalf("restricted proof = %+v, want %+v", restricted, want)
	}
	// A reached (Maybe) verdict is a shadow record: its proof is maybe with
	// the first reason, and it adds no live finding (DET111 ruling 11-22).
	reachedRes := EffectShadowResult{Tier: string(effectTierUnknown), Action: guardrailActionAlert,
		Sets: []string{effectrules.SetShellRC}, Reach: []string{effectrules.ReachCode}}
	want = decide.Proof{Kind: decide.KindWrite, Target: decide.TargetAutostart, Certainty: decide.CertMaybe, Reach: decide.ReachCode, Source: "effects"}
	if got := effectFindingProof(reachedRes); got != want {
		t.Fatalf("reached proof = %+v, want %+v", got, want)
	}
	if reached := effectShadowFindings(reachedRes, effectRulesOn); len(reached) != 0 {
		t.Fatalf("a Maybe verdict raised the live answer: %+v", reached)
	}
	// A Known mutation beside a Maybe reach does not convert the call's
	// unknown tier into a live effect verdict.
	knownRes := reachedRes
	knownRes.Known = true
	if got := effectFindingProof(knownRes); got != want {
		t.Fatalf("mixed known/Maybe proof = %+v, want shadow-only proof %+v", got, want)
	}
	if known := effectShadowFindings(knownRes, effectRulesOn); len(known) != 0 {
		t.Fatalf("a known mutation beside a Maybe reach raised live: %+v", known)
	}
}

// classifyEffects marks a call Known when one effect is a known effect on a
// known member, even when another effect only reached a set.
func TestClassifyEffectsKnownBesideReached(t *testing.T) {
	useEffectsRulesMode(t, "on")
	run := func(command string) EffectShadowResult {
		return effectShadowRun(shadowLiveRequest(command), effectRulesOn, tierRestricted)[0]
	}
	if res := run(`sed -i s/a/b/ /home/u/.bashrc`); res.Tier != string(effectTierUnknown) || !res.Known || !res.KnownMutation {
		t.Fatalf("sed -i on the known rc file: result %+v, want a known mutation with an unknown reach", res)
	} else if f := effectShadowFindings(res, effectRulesOn); len(f) != 1 ||
		f[0].RuleID != "effect.protected_target_unknown" ||
		f[0].Proof.Certainty != decide.CertMaybe || f[0].Proof.Reach != decide.ReachAdvisory {
		t.Fatalf("mixed known and Maybe effects must preserve only an advisory proof, got %+v", f)
	}
	if res := run(shadowLiveWrite); !res.Known || !res.KnownMutation {
		t.Fatalf("restricted write: result %+v, want a known mutation", res)
	} else if res.Tier != string(effectTierRestricted) || res.Action != guardrailActionBlock {
		t.Fatalf("known authorized_keys mutation = tier %s action %s, want restricted block", res.Tier, res.Action)
	} else if f := effectShadowFindings(res, effectRulesOn); len(f) != 2 ||
		f[0].RuleID != decide.RuleAuthorizedKeysWrite ||
		f[0].Proof.Certainty != decide.CertKnown ||
		f[1].RuleID != "effect.protected_target_restricted" ||
		f[1].Proof.Certainty != decide.CertKnown {
		t.Fatalf("known mutation did not carry its exact member and tier proofs: %+v", f)
	}
	// A Known credential read is handed to Decide with its exact member
	// class. The existing credential table, not the effect tier, decides it.
	res := run(`cat /home/u/.aws/credentials`)
	if res.Tier != string(effectTierUnknown) || !res.Known {
		t.Fatalf("credential read: tier %s known %v, want known read at the unknown effect tier", res.Tier, res.Known)
	}
	f := effectShadowFindings(res, effectRulesOn)
	wantProof := decide.Proof{Kind: decide.KindRead, Target: decide.TargetCredential,
		Certainty: decide.CertKnown, Set: decide.CredentialSet(".aws/credentials"), Flow: decide.FlowShown, Source: "effects"}
	if len(f) != 1 || f[0].Proof != wantProof || f[0].RuleID != decide.RuleFor(wantProof) {
		t.Fatalf("credential read findings = %+v, want its Decide row proof %+v", f, wantProof)
	}
}

// A managed enterprise gateway runs no local readers, so the live lane adds
// nothing there either.
func TestEffectLaneOffUnderManagedEnterprise(t *testing.T) {
	useEffectsRulesMode(t, "on")
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(false) })
	findings, _ := dispatchShadowLive(t, shadowLiveWrite, 0)
	for _, id := range ruleIDsOf(findings) {
		if strings.HasPrefix(id, "effect.") {
			t.Fatalf("managed enterprise dispatch carried %s", id)
		}
	}
}

// Every route reads a patch tool's envelope with the patch frontend: a Codex
// apply_patch (the envelope as the command) and an OpenCode patch
// (patchText) write the file the envelope names, like the file tools.
func TestEffectCallReadsPatchTools(t *testing.T) {
	env := "*** Begin Patch\n*** Add File: /home/u/.bashrc\n+x\n*** End Patch"
	for name, in := range map[string]actionfacts.Input{
		"codex apply_patch": {Tool: "apply_patch", Command: env, ActiveHome: "/home/u", CWD: "/home/u"},
		"opencode patch":    {Tool: "patch", Args: json.RawMessage(`{"patchText":` + strconv.Quote(env) + `}`), ActiveHome: "/home/u", CWD: "/home/u"},
	} {
		call, _, ok := effectCall("x", in, false)
		if !ok || call.Surface != effects.SurfacePatch || call.Command != env {
			t.Fatalf("%s: call %+v ok %v, want the patch surface with the envelope", name, call, ok)
		}
	}
	if call, _, _ := effectCall("hermes", actionfacts.Input{Tool: "patch", Args: json.RawMessage(`{"mode":"replace","path":"a"}`)}, false); call.Surface == effects.SurfacePatch {
		t.Fatalf("a patch call with no envelope read as a patch: %+v", call)
	}
}

// The shell's dot rule is not assumed when the call turns dot matching on or
// the reading is not POSIX.
func TestEffectReachGlobDotRule(t *testing.T) {
	f := mkFact("delete", "unknown", "known", "rm", "shell", []string{"target:glob"}, maybeMatch(effectrules.SetShellRC, "glob"))
	f.Target.Path, f.Target.Glob, f.Origin.Dialect = "", "/home/u/*", "posix"
	facts := []*semanticpb.EffectFact{f}
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, newEffectReachEnv("/home/u", "rm -ri ~/*")); c.touches {
		t.Fatalf("rm -ri ~/*: touches, want clean")
	}
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, newEffectReachEnv("/home/u", "shopt -s dotglob; rm -ri ~/*")); !c.touches {
		t.Fatalf("dotglob: clean, want R-GLOB")
	}
	f.Origin.Dialect = "powershell"
	if c := classifyEffects(accounted(), facts, effects.FlavorPOSIX, tierRestricted, newEffectReachEnv("/home/u", "Remove-Item ~/*")); !c.touches {
		t.Fatalf("powershell reading: clean, want R-GLOB")
	}
}

// A decoy envelope in a field the tool does not run cannot hide the one it
// does: every envelope of the call is read.
func TestEffectPatchTextReadsEveryEnvelope(t *testing.T) {
	decoy := "*** Begin Patch\n*** Add File: /home/u/notes.txt\n+x\n*** End Patch"
	real := "*** Begin Patch\n*** Add File: /home/u/.bashrc\n+x\n*** End Patch"
	in := actionfacts.Input{Tool: "patch", Args: json.RawMessage(`{"input":` + strconv.Quote(decoy) + `,"patchText":` + strconv.Quote(real) + `}`)}
	text := effectPatchText(in)
	if !strings.Contains(text, "/home/u/.bashrc") || !strings.Contains(text, "/home/u/notes.txt") {
		t.Fatalf("patch text %q, want both envelopes", text)
	}
}

// A write through ~/* reaches the instruction files at the home root; only a
// delete does not.
func TestEffectReachGlobWritesInstructionFiles(t *testing.T) {
	f := mkFact("write", "unknown", "known", "cp", "shell", []string{"target:glob"}, maybeMatch(effectrules.SetAgentHookConfig, "glob"))
	f.Target.Path, f.Target.Glob, f.Origin.Dialect = "", "/home/u/*", "posix"
	if c := classifyEffects(accounted(), []*semanticpb.EffectFact{f}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"}); !c.touches {
		t.Fatalf("a write through ~/* is clean, want R-GLOB on the instruction files")
	}
}

// A patch header path with a $ (an admin share) keeps its spelling on an
// unknown target, so the patch reaches the same protected name as the file
// tool's write of the same path (wincred parity, TestConnectorNativeShapes).
func TestEffectPatchKeepsDollarSpelling(t *testing.T) {
	const p = `\\localhost\c$\Users\testuser\.git-credentials`
	env := "*** Begin Patch\n*** Add File: " + p + "\n+x\n*** End Patch"
	call, opts, ok := effectCall("codex", actionfacts.Input{Tool: "apply_patch", Command: env, CWD: `C:\Users\alice`,
		ActiveHome: `C:\Users\alice`, DialectHint: actionfacts.DialectPowerShell}, true)
	if !ok {
		t.Fatal("no call")
	}
	res := effects.Extract(call, opts)
	var found bool
	for _, e := range res.Effects {
		if e.Kind == effects.KindWrite && e.Target.Spelling != "" && e.TargetState != effects.TargetStateKnown {
			found = true
		}
	}
	if !found {
		t.Fatalf("effects %+v: want an unknown write that keeps the header spelling", res.Effects)
	}
}

// A member reached only through a followed link is held (counted, not
// raised: sed -i and install replace a link, the legacy link reading judges
// it), and a read of a path whose links could not be read is no credential
// read (rel-1-0-10 GAP-1243 benign rows, GAP-1286, GAP-1308).
func TestEffectLinkAndUnresolvedReadAreHeld(t *testing.T) {
	link := mkFact("write", "known", "known", "sed", "shell", nil, &semanticpb.ProtectedMatch{Set: effectrules.SetAgentHookConfig, State: "known", Reason: "link"})
	c := classifyEffects(accounted(), []*semanticpb.EffectFact{link}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"})
	if c.touches || !c.linkHeld {
		t.Fatalf("link write: touches %v linkHeld %v, want held", c.touches, c.linkHeld)
	}
	read := mkFact("read", "known", "known", "cat", "shell", nil, maybeMatch(effectrules.SetCredentials, "unresolved"))
	if c := classifyEffects(accounted(), []*semanticpb.EffectFact{read}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"}); c.touches {
		t.Fatalf("unresolved read: touches, want clean")
	}
	write := mkFact("write", "known", "known", "cp", "shell", nil, maybeMatch(effectrules.SetCredentials, "unresolved"))
	if c := classifyEffects(accounted(), []*semanticpb.EffectFact{write}, effects.FlavorPOSIX, tierRestricted, effectReachEnv{Home: "/home/u"}); !c.touches || strings.Join(c.reach, ",") != effectrules.ReachFS {
		t.Fatalf("unresolved write: touches %v reach %v, want R-FS", c.touches, c.reach)
	}
}
