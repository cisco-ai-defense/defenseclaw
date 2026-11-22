// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	osuser "os/user"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// The effect-model rule lane (S7). It runs the pure effect extractor
// (internal/effects) and the protected-set projector (internal/effectrules)
// beside today's ActionFacts rules and answers in three tiers:
//
//   - a known effect on a protected target (or a known attack tool) takes the
//     severity path today's protected-file rules take;
//   - an unknown effect that reaches a protected set by a reach reason
//     (effectrules.Reach*, DET111 PLAN 5.3) takes the unknown tier: alert in
//     the default packs, per-user and managed alike (owner ruling GAP-1611,
//     GAP-1698), block in the strict packs (there is no ask yet; S8 owns the
//     confirm path and maps the effect_unknown disposition to it);
//   - otherwise clean.
//
// guardrail.cascade.lanes.effects decides the lane: off (skip entirely, no cost),
// shadow (compute and measure beside today's, never change the answer) or on,
// the default since DET111: the effect verdict joins today's findings as a
// raise only. It adds a finding and never removes or lowers one, so the
// decision takes the stronger of today's readers and the effect model.

type effectRulesMode string

const (
	effectRulesOff    effectRulesMode = "off"
	effectRulesShadow effectRulesMode = "shadow"
	effectRulesOn     effectRulesMode = "on"
)

// effectTierMode is how far the effect lane may block: restricted (the
// owner's listed-command tier) or full (the full effect model).
type effectTierMode string

const (
	tierRestricted effectTierMode = "restricted"
	tierFull       effectTierMode = "full"
)

// effectsRulesTierFor reads the live generation's effects_rules_tier.
// Absent or unknown is restricted (the shipped default).
func effectsRulesTierFor() effectTierMode {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return tierRestricted
	}
	if effectTierMode(g.Config.Guardrail.EffectsRulesTier) == tierFull {
		return tierFull
	}
	return tierRestricted
}

// effectResolverOverride, when set, replaces the file-system link resolver in
// computeEffectShadow. It is nil in production (the hookpaths reader is used)
// and set by the s7bench harness to a lexical resolver, because the harness
// has no real user home to follow links through.
var effectResolverOverride func(string) (string, bool)

type effectTier string

const (
	effectTierClean      effectTier = "clean"
	effectTierUnknown    effectTier = "unknown"
	effectTierRestricted effectTier = "restricted"
)

// EffectShadowResult is the effect lane's answer for one call. It is private
// in-process measurement material: value-free except for the protected-set
// names and the deciding effect's program and kind.
type EffectShadowResult struct {
	Mode    string   `json:"mode"`
	Tier    string   `json:"tier"`
	Action  string   `json:"action"`
	Sets    []string `json:"sets,omitempty"`
	Program string   `json:"program,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	// RuleIDs names the effect rule that would fire (empty when clean).
	RuleIDs []string `json:"rule_ids,omitempty"`
	// Reason is why the run has no (or a partial) verdict: parse_budget_exceeded,
	// shadow_timeout or shadow_panic. Empty for a fully computed run.
	Reason string `json:"reason,omitempty"`
	// Reach are the reach reasons of an unknown-tier verdict (DET111 PLAN
	// 5.3); RoleHeld marks an R-ROLE unknown that was counted, not raised.
	Reach    []string `json:"reach,omitempty"`
	RoleHeld bool     `json:"role_held,omitempty"`
	// LinkHeld marks a member reached only through a followed link: counted,
	// not raised (effectProtectedSets).
	LinkHeld bool `json:"link_held,omitempty"`
	// Known marks a verdict with a Known protected mutation: a known
	// mutating effect on a known member, by a listed command (the restricted
	// tier) or not. Only a Known verdict raises the live answer; a Maybe one
	// (a reach reason only) and a known read are shadow records
	// (effectShadowFindings).
	Known bool `json:"known,omitempty"`
	// CostUS is the wall-clock cost of the run in microseconds; Effects is the
	// number of effects the extractor produced.
	CostUS  int64 `json:"cost_us,omitempty"`
	Effects int   `json:"effects,omitempty"`
}

// effectsRulesModeFor reads the live generation's config. An absent generation
// (tests, early boot) is off, so the lane never runs unasked.
func effectsRulesModeFor() effectRulesMode {
	g := currentGeneration()
	if g == nil || g.Config == nil {
		return effectRulesOff
	}
	switch effectRulesMode(g.Config.Guardrail.Cascade.Lanes.EffectsMode()) {
	case effectRulesShadow:
		return effectRulesShadow
	case effectRulesOn:
		return effectRulesOn
	default:
		return effectRulesOff
	}
}

// mutatingEffectKind reports a kind that changes a target: a protected-file
// mutation takes the severity path, a read of a protected target does not.
func mutatingEffectKind(kind string) bool {
	switch effects.Kind(kind) {
	case effects.KindWrite, effects.KindAppend, effects.KindDelete,
		effects.KindLink, effects.KindPermissionChange:
		return true
	default:
		return false
	}
}

// effectCall builds the pure-extractor call and options from a trusted action
// input. ok is false when there is nothing executable to analyze.
func effectCall(connector string, in actionfacts.Input) (effects.Call, effects.Options, bool) {
	flavor := effects.FlavorPOSIX
	dialect := effects.DialectNone
	switch in.DialectHint {
	case actionfacts.DialectPowerShell:
		flavor, dialect = effects.FlavorWindows, effects.DialectPowerShell
	case actionfacts.DialectCMD:
		flavor, dialect = effects.FlavorWindows, effects.DialectCMD
	case actionfacts.DialectPOSIX:
		dialect = effects.DialectPOSIX
	}
	opts := effects.Options{Flavor: flavor, Dialect: dialect, Home: in.ActiveHome, CWD: in.CWD,
		BSDUserland: effectBSDUserland(effectHostGOOS, flavor)}

	switch {
	case effectPatchTool(in.Tool) && effectPatchText(in) != "":
		// A patch tool's text is a patch envelope, never a shell command: a
		// Codex apply_patch carries it as the command, an OpenCode patch as
		// patchText. Both are read by the patch frontend, as the file tools
		// of the same edit are (every route, DET111 PLAN 5.2).
		return effects.Call{Surface: effects.SurfacePatch, Tool: in.Tool, Command: effectPatchText(in)}, opts, true
	case in.Command != "":
		return effects.Call{Surface: effects.SurfaceShell, Tool: in.Tool, Command: in.Command}, opts, true
	case len(in.Argv) > 0:
		return effects.Call{Surface: effects.SurfaceArgv, Tool: in.Tool, Argv: in.Argv}, opts, true
	case len(in.Args) > 0:
		return effects.Normalize(connector, in.Tool, in.Args), opts, true
	default:
		return effects.Call{}, opts, false
	}
}

// effectPatchTool names the connectors' patch tools (apply_patch for Codex,
// patch for OpenCode and Hermes).
func effectPatchTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "apply_patch", "applypatch", "apply-patch", "patch":
		return true
	}
	return false
}

// effectPatchText is the patch text a patch tool call carries: every
// distinct envelope in the command and the patch fields, joined, so a decoy
// envelope in a field the tool does not run cannot hide the one it does (the
// patch frontend reads the headers of all of them). A call with no envelope
// (Hermes' patch in replace mode) is not a patch.
func effectPatchText(in actionfacts.Input) string {
	const begin = "*** Begin Patch"
	var texts []string
	add := func(v string) {
		if strings.Contains(v, begin) && !slices.Contains(texts, v) {
			texts = append(texts, v)
		}
	}
	add(in.Command)
	var args map[string]any
	if json.Unmarshal(in.Args, &args) == nil {
		for _, k := range []string{"input", "patch", "patchText", "patch_text", "command", "content"} {
			if v, ok := args[k].(string); ok {
				add(v)
			}
		}
	}
	return strings.Join(texts, "\n")
}

// maxEffectAccountLookups bounds the passwd lookups of one call (counted
// work; S2 cap registry name gateway.maxEffectAccountLookups). A ~name past
// it stays unknown, which the lane reads as a reach (the unknown tier of its
// pack), never as a clear path.
const maxEffectAccountLookups = 4

var (
	effectAccountLookups     atomic.Int64 // passwd lookups the lane made
	effectAccountLookupsOver atomic.Int64 // ~names the cap left unknown
)

// effectLookupAccountHome is the passwd lookup (getpwnam, through os/user) of
// a ~name: the account's absolute home. A test pins it.
var effectLookupAccountHome = func(name string) (string, bool) {
	account, err := osuser.Lookup(name)
	if err != nil || !strings.HasPrefix(account.HomeDir, "/") {
		return "", false
	}
	return account.HomeDir, true
}

// effectActiveLogin is the hook account's login for the lane, from the
// trusted identity the ~<login> twin reads (trustedActiveLogins, GAP-2378):
// "" for a call that spells no ~, so such a call costs nothing.
func effectActiveLogin(ctx context.Context, in actionfacts.Input) string {
	if !strings.Contains(in.Command, "~") && !bytes.Contains(in.Args, []byte("~")) &&
		!slices.ContainsFunc(in.Argv, func(a string) bool { return strings.Contains(a, "~") }) {
		return ""
	}
	if logins := trustedActiveLogins(ctx, in.ActiveHome); len(logins) > 0 {
		return logins[0]
	}
	return ""
}

// effectAccountOptions fills the account fields of a POSIX call's options:
// Login, the hook account's login, so ~<login> names the active home as the
// shell's passwd lookup does (rel-1-0-10:GAP-1678), and Accounts, the homes of
// the other ~names the call spells, from a passwd lookup bounded by
// maxEffectAccountLookups per call and counted. A name the lookup does not
// find, or one past the cap, stays unknown (GAP-1677, GAP-0898).
func effectAccountOptions(call effects.Call, opts effects.Options, login string) effects.Options {
	if opts.Flavor == effects.FlavorWindows {
		return effectWindowsHomeOptions(opts)
	}
	if opts.Flavor != effects.FlavorPOSIX {
		return opts
	}
	opts.Login = login
	text := call.Command + "\n" + string(call.Args) + "\n" + strings.Join(call.Argv, "\n")
	if !strings.Contains(text, "~") {
		return opts
	}
	looked := 0
	for _, name := range effects.TildeAccountNames(text) {
		if login != "" && strings.EqualFold(name, login) {
			continue
		}
		if looked == maxEffectAccountLookups {
			effectAccountLookupsOver.Add(1)
			continue
		}
		looked++
		effectAccountLookups.Add(1)
		if home, ok := effectLookupAccountHome(name); ok {
			if opts.Accounts == nil {
				opts.Accounts = map[string]string{}
			}
			opts.Accounts[name] = home
		}
	}
	return opts
}

// effectWindowsHomeOptions vouches the hook account's Windows home for the
// variables that name it at session start: cmd's %USERPROFILE%, PowerShell's
// $env:USERPROFILE and Git Bash's $HOME place under the home, as the written-
// out C:\Users\<login> spelling and ~\ do, instead of an unknown target. A
// value the call itself assigns still wins (the walker's running env). Only a
// drive-absolute home is vouched.
func effectWindowsHomeOptions(opts effects.Options) effects.Options {
	h := opts.Home
	if len(h) < 3 || h[1] != ':' || (h[2] != '\\' && h[2] != '/') {
		return opts
	}
	env := make(map[string]string, len(opts.Env)+2)
	for k, v := range opts.Env {
		env[k] = v
	}
	for _, k := range []string{"USERPROFILE", "HOME"} {
		if _, ok := env[k]; !ok {
			env[k] = h
		}
	}
	opts.Env = env
	return opts
}

// effectHostGOOS is the host the hook runs on; a test pins it.
var effectHostGOOS = runtime.GOOS

// effectBSDUserland reports that a POSIX call runs the BSD tools: the hook
// runs on the agent's host, and macOS ships BSD cp, mv, ln, rm, install and
// tee, whose flags differ from GNU coreutils (rel-1-0-10 GAP-0219).
func effectBSDUserland(goos string, flavor effects.Flavor) bool {
	return goos == "darwin" && flavor == effects.FlavorPOSIX
}

// computeEffectShadow runs the effect lane for one request and returns its
// verdict. It never mutates the request or today's findings. It is the shared
// core (effectShadowRun) for one tier: the live hook and the benchmark harness
// run the same code, with the same budget, time cap and recovery.
func computeEffectShadow(request trustedActionRequest, mode effectRulesMode, tier effectTierMode) EffectShadowResult {
	return effectShadowRun(request, mode, tier)[0]
}

// effectClass is the protected-tier read of one call: whether any effect
// touches a protected set at all, whether an effect is restricted-tier
// eligible (a listed command, every token accounted, an exact canonical
// known protected member), and whether that eligible effect is on a family
// that blocks in the OSS default (the existing authorized-keys / self-
// protection ruling). sets/program/kind describe the deciding effect for
// reporting only.
type effectClass struct {
	touches          bool
	restricted       bool
	restrictedRuling bool
	sets             []string
	program          string
	kind             string
	// reach are the reach reasons (effectrules.Reach*) of the unknowns that
	// made the call touch a protected set; empty when only known effects did.
	reach []string
	// roleHeld: an unknown target of a known write or send (R-ROLE) that
	// does not raise (effectReachRoleRaises is off), counted only.
	roleHeld bool
	// linkHeld: a target in a protected set only through a link the
	// resolver followed, counted, not raised (effectProtectedSets).
	linkHeld bool
	// known: some effect is a known mutation of a known member (no reach
	// reason), whatever else the call reached.
	known bool
}

// classifyEffects applies the owner's three answers (2026-11-13): a known
// mutation by a listed command on an exact canonical protected path is the
// restricted tier (block); anything else that touches a protected set,
// including any UNKNOWN effect that could reach one, is the unknown tier;
// otherwise clean.
func classifyEffects(result effects.Result, facts []*semanticpb.EffectFact, flavor effects.Flavor, tier effectTierMode, env effectReachEnv) effectClass {
	var c effectClass
	fullyAccounted := len(result.Unknowns) == 0
	var touchSets []string
	for _, f := range facts {
		t := f.GetTarget()
		if t.GetType() != "path" {
			continue
		}
		kind := f.GetKind()
		known, maybe, linkHeld := effectProtectedSets(t, kind)
		if linkHeld {
			c.linkHeld = true
		}
		if len(known) == 0 && len(maybe) == 0 {
			continue
		}
		mutating := mutatingEffectKind(kind)
		unknownEffect := f.GetTargetState() != "known" || f.GetRoleState() != "known" || kind == string(effects.KindOpaque)
		// Relevance: a mutation touching a protected set; a credential read; or
		// any UNKNOWN effect that could reach a protected set (R5F-1). A benign
		// read of a config file (shell rc, agent config) is not escalated.
		relevant := false
		switch {
		case mutating:
			relevant = true
		case unknownEffect:
			relevant = true
		case kind == string(effects.KindRead) && (effectSetContains(known, effectrules.SetCredentials) || effectSetContains(maybe, effectrules.SetCredentials)):
			relevant = true
		}
		if !relevant {
			continue
		}
		// A target only maybe in a set reaches the unknown tier only with a
		// reach reason (DET111 PLAN 5.3); with none it stays clean, as in
		// 1.0.10.
		r := factReach(f, known, unknownEffect, env, flavor)
		if len(known) == 0 && r == "" {
			continue
		}
		c.touches = true
		touchSets = append(touchSets, append(append([]string(nil), known...), maybe...)...)
		if r != "" {
			c.reach = append(c.reach, r)
		} else if mutating {
			// A known read of a credential is the credential readers' class
			// and keeps their 1.0.10 tier (own credentials alert, GAP-0888):
			// the lane raises a mutation, it does not move a read to
			// another tier (that is decide's table).
			c.known = true
		}
		if c.program == "" && c.kind == "" {
			c.program, c.kind = f.GetOrigin().GetProgram(), kind
		}
		// Restricted eligibility: a mutation, every token accounted, this
		// effect fully known, by a listed command, on an exact canonical known
		// member of a named set.
		if !mutating || !fullyAccounted ||
			f.GetTargetState() != "known" || f.GetRoleState() != "known" || len(f.GetReasons()) != 0 {
			continue
		}
		// The restricted tier gates blocking to a reviewed command list; the
		// full tier trusts the effect model for any mutating command.
		if tier == tierRestricted &&
			!effectrules.RestrictedBlockCommand(f.GetOrigin().GetProgram(), effects.Surface(f.GetOrigin().GetSurface())) {
			continue
		}
		if !effectrules.CanonicalAbsolute(t.GetPath(), flavor) {
			continue
		}
		for _, m := range t.GetProtected() {
			if m.GetState() != semantic.ProtectedKnown || m.GetReason() != "exact" || m.GetSet() == effectrules.SetOutsideHome {
				continue
			}
			c.restricted = true
			// The authorized-keys ruling blocks in every pack. A state write
			// keeps the 1.0.10 tier of tamper.detector_state_write (alert in
			// the default packs, block in strict): the lane raises, it does
			// not move a class to another tier (that is decide's table).
			if m.GetSet() == effectrules.SetSSHAuthorizedKeys {
				c.restrictedRuling = true
			}
		}
	}
	c.sets = dedupeStrings(touchSets)
	c.reach = dedupeStrings(c.reach)
	return c
}

// factReach is the reach reason of one relevant fact: none for a known effect
// on a known member; R-NAME for an unknown effect on a known member;
// otherwise the basis of the first maybe match that holds (glob, unresolved
// link, dynamic cwd, protected folder, shape). A glob reaches only when its
// components can select a member (effectrules.GlobReaches: ~/* does not
// select ~/.ssh), and a known path beside the members only when it is one or
// an ancestor of one (effectrules.KnownPathReaches).
func factReach(f *semanticpb.EffectFact, known []string, unknownEffect bool, env effectReachEnv, flavor effects.Flavor) string {
	if len(known) > 0 {
		if unknownEffect {
			return effectrules.ReachName
		}
		return ""
	}
	t := f.GetTarget()
	for _, m := range t.GetProtected() {
		if m.GetState() != semantic.ProtectedUnknown || m.GetReason() == "link" ||
			f.GetKind() == string(effects.KindRead) && m.GetReason() == "unresolved" {
			continue
		}
		switch m.GetReason() {
		case "glob":
			// The shell's dot rule holds only in a POSIX reading of a call
			// that does not turn dot matching on.
			dotRule := f.GetOrigin().GetDialect() == string(effects.DialectPOSIX) && !env.DotGlob
			if t.GetGlob() != "" && !effectrules.GlobReaches(t.GetGlob(), env.Home, flavor, dotRule, f.GetKind() == string(effects.KindDelete), m.GetSet()) {
				continue
			}
		case "dir":
			if f.GetTargetState() == "known" && !effectrules.KnownPathReaches(t.GetPath(), env.Home, flavor, m.GetSet()) {
				continue
			}
		}
		return effectrules.ReachForMatch(m.GetReason(), f.GetReasons())
	}
	return ""
}

// effectReachEnv is what the reach rule reads beside the facts: the active
// home, and whether the call turns dot matching on for its globs (bash
// dotglob, zsh globdots or glob_dots).
type effectReachEnv struct {
	Home    string
	DotGlob bool
}

func newEffectReachEnv(home, text string) effectReachEnv {
	lower := strings.ToLower(text)
	return effectReachEnv{Home: home, DotGlob: strings.Contains(lower, "dotglob") || strings.Contains(lower, "globdots") ||
		strings.Contains(lower, "glob_dots")}
}

// effectReachRoleRaises lets R-ROLE (an unknown operand of a write or send
// the table models) raise to the unknown tier. It is off: a write to an
// unknown $OUT is too common in benign calls to alert on before its benign
// rate is measured; the shadow report counts it (roleHeld).
var effectReachRoleRaises = false

// effectReachUnplaced reaches the unknowns that no protected path placed
// (classifyEffects saw none): an unknown operand of a known write or send
// (R-ROLE), and a call not fully read whose text names a member of the
// persistence sets that no known effect accounts for (R-NAME, or R-CODE when
// the unread part is code). With no reason the call stays clean, as in
// 1.0.10.
func effectReachUnplaced(c *effectClass, result effects.Result, facts []*semanticpb.EffectFact, text, home string, flavor effects.Flavor) {
	if c.touches {
		return
	}
	unknown := len(result.Unknowns) > 0
	code := false
	accounted, reads := map[string]bool{}, map[string]bool{}
	for _, f := range facts {
		kind := f.GetKind()
		known := f.GetTargetState() == "known" && f.GetRoleState() == "known" && kind != string(effects.KindOpaque)
		if !known {
			unknown = true
		}
		if kind == string(effects.KindOpaque) || effectSetContains(f.GetReasons(), string(effects.ReasonOpaqueCode)) || f.GetDataKind() == string(effects.DataCode) {
			code = true
		}
		t := f.GetTarget()
		if t.GetType() == "path" && f.GetTargetState() == "known" && t.GetPath() != "" {
			accounted[t.GetPath()] = kind != string(effects.KindRead)
			if kind == string(effects.KindRead) {
				reads[t.GetPath()] = true
			}
		}
		if f.GetTargetState() != "known" && f.GetRoleState() == "known" &&
			(mutatingEffectKind(kind) || kind == string(effects.KindNetworkSend)) {
			c.roleHeld = true
		}
	}
	if !unknown {
		return
	}
	if c.roleHeld && effectReachRoleRaises {
		c.touches = true
		c.reach = append(c.reach, effectrules.ReachRole)
	}
	// A known read accounts for its name, unless the unread part is code that
	// may write what the call read (cat ~/.bashrc | python -c ...).
	if !code {
		for p := range reads {
			accounted[p] = true
		}
	}
	if set, ok := effectrules.TextNamesProtected(text, home, flavor, accounted); ok {
		c.touches = true
		c.sets = dedupeStrings(append(c.sets, set))
		r := effectrules.ReachName
		if code {
			r = effectrules.ReachCode
		}
		c.reach = dedupeStrings(append(c.reach, r))
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// effectProtectedSets splits a target's protected matches into the sets it
// is known to be in and the sets it may be in, leaving out what the lane does
// not raise on. A member reached only through a link the resolver followed
// (basis link) is held: whether the program writes through the link or
// replaces it (sed -i without --follow-symlinks, install, a write after a cd
// the function body runs behind) is the program table's and the resolver's
// reading, not yet the effect model's, and the legacy link reading
// (GAP-1243) judges it. A read of a path whose links could not be read
// (unresolved, /proc/self/cwd/...) is no credential read: a read reaches a
// credential by its name only.
func effectProtectedSets(t *semanticpb.EffectTarget, kind string) (known, maybe []string, linkHeld bool) {
	for _, m := range t.GetProtected() {
		switch {
		case m.GetReason() == "link":
			linkHeld = true
		case kind == string(effects.KindRead) && m.GetReason() == "unresolved":
		case m.GetState() == semantic.ProtectedKnown:
			known = append(known, m.GetSet())
		case m.GetState() == semantic.ProtectedUnknown:
			maybe = append(maybe, m.GetSet())
		}
	}
	return known, maybe, linkHeld
}

// effectAction maps the protected-tier read to the guardrail action. An effect
// that touches a protected set blocks in the strict packs, and blocks in the
// default packs (per-user and managed) only when a restricted-tier effect is
// on the authorized-keys ruling family; otherwise it alerts.
// There is no ask yet (S8 owns the confirm path).
func effectAction(touches, restrictedRuling, strict bool) string {
	if !touches {
		return guardrailActionAllow
	}
	if strict || restrictedRuling {
		return guardrailActionBlock
	}
	return guardrailActionAlert
}

func effectSetContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// effectShadowContextKey marks the outermost trusted-action dispatch so the
// effect lane runs once per call, not once per nested statement or twin.
type effectShadowContextKey struct{}

func markOutermostEffectDispatch(ctx context.Context) (context.Context, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Value(effectShadowContextKey{}) != nil {
		return ctx, false
	}
	return context.WithValue(ctx, effectShadowContextKey{}, struct{}{}), true
}

// effectShadowFindings turns an effect verdict into rule findings for the ON
// lane. Clean or allow verdicts carry no finding, and neither does a Maybe
// verdict: a protected target the lane reached only by a reach reason
// (R-NAME, R-GLOB, R-CWD, R-CODE, ...) never raises the live answer above the
// 1.0.10 readers, in any tier (DET111 ruling 2026-11-22, TRAIN T1: every one of
// its 13,572 new benign blocks was such a verdict), and neither does a known
// read (Known is a mutation). It stays a shadow record:
// the reach counters, the harness's EffectShadow stamps and the audit row
// (effectLiveFindings). A Known verdict (a known effect on a known member)
// raises: an alert-tier verdict is capped at an alert in every profile; a
// block-tier verdict contributes to enforcement so the profile threshold maps
// its severity to the action. The effect disposition lets S8 map the unknown
// tier to ask later; the effect proof is authoritative only when the lane is
// ON.
func effectShadowFindings(res EffectShadowResult, mode effectRulesMode) []RuleFinding {
	if res.Tier == string(effectTierClean) || res.Action == guardrailActionAllow {
		return nil
	}
	proof := effectFindingProof(res)
	if proof.Certainty != decide.CertKnown {
		return nil
	}
	rid := "effect.protected_target_" + res.Tier
	title := "Effect-model protected-target verdict"
	severity := "HIGH"
	if res.Tier == string(effectTierRestricted) {
		severity = "CRITICAL"
	}
	disposition := findingDispositionEffectUnknown
	if res.Tier == string(effectTierRestricted) {
		disposition = findingDispositionEffectKnown
	}
	tags := append([]string{"effects", res.Tier}, res.Sets...)
	for _, r := range res.Reach {
		tags = append(tags, "reach:"+r)
	}
	f := RuleFinding{
		RuleID:     rid,
		Title:      title,
		Severity:   severity,
		Confidence: 0.9,
		Tags:       tags,
	}
	f.disposition = disposition
	f.Proof = proof
	f.proof = newFindingProof(findingProofEffect, rid, mode == effectRulesOn)
	switch res.Action {
	case guardrailActionAlert:
		f.enforcement = findingEnforcementAlertOnly
	default:
		f.enforcement = findingEnforcementInherit
	}
	return []RuleFinding{f}
}

// effectProofSource is the Proof.Source of every effect-lane finding: the
// shadow report's key for the effect model beside the legacy readers.
const effectProofSource = "effects"

// effectFindingProof is the DET111 proof of an effect verdict (internal/
// guardrail/decide): the deciding effect's kind, the strongest protected
// class it reached, and how sure the lane is. A restricted-tier verdict, or
// one with a known mutation of a known member (Known: also by a command the
// restricted list does not name), is known, even when another effect of the
// call was only reached; any other is maybe and carries the first reach
// reason, if any (a known read has none).
func effectFindingProof(res EffectShadowResult) decide.Proof {
	p := decide.Proof{
		Kind:      effectProofKind(res.Kind),
		Target:    effectProofTarget(res.Sets),
		Certainty: decide.CertKnown,
		Source:    effectProofSource,
	}
	if res.Tier != string(effectTierRestricted) && !res.Known {
		p.Certainty = decide.CertMaybe
		if len(res.Reach) > 0 {
			p.Reach = res.Reach[0]
		}
	}
	return p
}

// effectLiveFindings runs the ON lane for one outermost dispatch: the Known
// verdict's findings join today's (raise only); a Maybe verdict adds none and
// is handed to the shadow recorder off the hook's path instead, so the audit
// log still shows what the lane reached.
func effectLiveFindings(request trustedActionRequest, mode effectRulesMode, tier effectTierMode) []RuleFinding {
	res := computeEffectShadow(request, mode, tier)
	findings := effectShadowFindings(res, mode)
	if len(findings) == 0 && res.Tier != string(effectTierClean) {
		recordEffectShadowAsync(res, request.recordEffectShadow)
	}
	return findings
}

// effectProofKind maps an effect kind to a proof kind. An opaque program is
// exec (it runs code the lane did not read); no deciding effect (a call
// reached by the name scan alone) is a write it may do.
func effectProofKind(kind string) decide.ProofKind {
	switch effects.Kind(kind) {
	case effects.KindRead:
		return decide.KindRead
	case effects.KindAppend:
		return decide.KindAppend
	case effects.KindDelete:
		return decide.KindDelete
	case effects.KindLink:
		return decide.KindLink
	case effects.KindExec, effects.KindOpaque:
		return decide.KindExec
	case effects.KindNetworkSend:
		return decide.KindSend
	case effects.KindNetworkFetch:
		return decide.KindFetch
	case effects.KindPermissionChange:
		return decide.KindPerm
	default:
		return decide.KindWrite
	}
}

// effectSetClasses is the protected class of each effect-rule set, strongest
// first: a verdict that reached several sets carries the first one here.
var effectSetClasses = []struct {
	set   string
	class decide.TargetClass
}{
	{effectrules.SetSelfProtection, decide.TargetState},
	{effectrules.SetSSHAuthorizedKeys, decide.TargetAuthorizedKeys},
	{effectrules.SetAgentHookConfig, decide.TargetHookConfig},
	{effectrules.SetCredentials, decide.TargetCredential},
	{effectrules.SetShellRC, decide.TargetAutostart},
	{effectrules.SetOutsideHome, decide.TargetSystem},
}

func effectProofTarget(sets []string) decide.TargetClass {
	for _, c := range effectSetClasses {
		if effectSetContains(sets, c.set) {
			return c.class
		}
	}
	if len(sets) > 0 {
		return decide.TargetOther
	}
	return decide.TargetNone
}
