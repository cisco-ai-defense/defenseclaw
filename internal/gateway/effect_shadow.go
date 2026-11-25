// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	osuser "os/user"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	// extract_cap_exceeded or shadow_panic. Empty for a fully computed run.
	Reason string `json:"reason,omitempty"`
	// Reach are the reach reasons of an unknown-tier verdict (DET111 PLAN
	// 5.3); RoleHeld marks an R-ROLE unknown that was counted, not raised.
	Reach    []string `json:"reach,omitempty"`
	RoleHeld bool     `json:"role_held,omitempty"`
	// LinkHeld marks a member reached only through a followed link: counted,
	// not raised (effectProtectedSets).
	LinkHeld bool `json:"link_held,omitempty"`
	// Known marks a Known protected effect, including a credential read
	// routed through its decide credential row.
	Known bool `json:"known,omitempty"`
	// KnownMutation distinguishes known writes from read proofs during handoff.
	KnownMutation bool `json:"-"`
	// LinkTo marks a call whose link names a protected member as its target
	// and puts no link at a member (decide.Proof.LinkTo).
	LinkTo bool `json:"-"`
	// RestrictedSets are the sets of the exact members that made the call
	// restricted (the restricted proof's target); Sets also has the sets the
	// call touched otherwise.
	RestrictedSets []string `json:"-"`
	// WrittenCredentialSet is the one credential file class every exact
	// credential member a restricted mutation of the call names belongs to
	// (decide.Proof.Set of the mutation proof); "" when none or several.
	WrittenCredentialSet string `json:"-"`
	// CredentialAppend marks a call with a restricted append to an exact
	// credential member: it changes a file that holds a credential, so the
	// mutation proof is an append whatever effect came first (GAP-1666/114).
	CredentialAppend bool `json:"-"`
	// ReadProofs are private decision inputs. Do not serialize member paths or
	// credential classes into the shadow telemetry record.
	ReadProofs []decide.Proof `json:"-"`
	// MutationProofs are member-exact effects writes graded by Decide: an
	// authorized_keys write, and a write through a session alias of a
	// credential member (its class rule, GAP-2025).
	MutationProofs []decide.Proof `json:"-"`
	// UploadProofs are Known reads of a credentials file outside the
	// protected sets (.env) whose content the call sends out (GAP-1641).
	UploadProofs []decide.Proof `json:"-"`
	// FetchedScriptRule is a source-to-interpreter proof from the one effects
	// read. It stays out of shadow telemetry; the live finding names the rule.
	FetchedScriptRule string `json:"-"`
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
// input. ok is false when there is nothing executable to analyze. windows is
// a call a Windows host runs (effectWindowsCall): its paths are Windows
// paths in every dialect, so Git Bash (hint POSIX) keeps the POSIX grammar
// with Windows path rules, and a shell call the hook placed in no dialect
// (a Codex shell) is not read as POSIX: the extractor infers PowerShell or
// cmd from its text, except Claude Code's Bash tool, which runs Git Bash.
func effectCall(connector string, in actionfacts.Input, windowsArg ...bool) (effects.Call, effects.Options, bool) {
	windows := len(windowsArg) > 0 && windowsArg[0]
	flavor := effects.FlavorPOSIX
	if windows {
		flavor = effects.FlavorWindows
	}
	dialect := effects.DialectNone
	switch in.DialectHint {
	case actionfacts.DialectPowerShell:
		flavor, dialect = effects.FlavorWindows, effects.DialectPowerShell
	case actionfacts.DialectCMD:
		flavor, dialect = effects.FlavorWindows, effects.DialectCMD
	case actionfacts.DialectPOSIX:
		dialect = effects.DialectPOSIX
	default:
		if windows && connector == "claudecode" && strings.EqualFold(in.Tool, "Bash") {
			dialect = effects.DialectPOSIX
		}
	}
	opts := effects.Options{Flavor: flavor, Dialect: dialect, Home: in.ActiveHome, CWD: in.CWD,
		Account:     effects.AccountRecord{Home: in.ActiveHome, Shell: in.ActiveShell},
		BSDUserland: effectBSDUserland(effectHostGOOS, flavor)}
	if flavor == effects.FlavorWindows && windowsShapedPath(in.ActiveHome) {
		opts.Env = map[string]string{"USERPROFILE": in.ActiveHome}
	}
	if (dialect == effects.DialectPOSIX || dialect == effects.DialectNone && flavor == effects.FlavorPOSIX) && in.ActiveHome != "" {
		// A POSIX shell inherits HOME from the agent: $HOME and ${HOME} name
		// the active home as ~ does, not an unread word (DET111 D3; the
		// "$HOME" spellings of rel-1-0-10:GAP-1261 read as dynamic and
		// reached no set).
		if opts.Env == nil {
			opts.Env = map[string]string{}
		}
		opts.Env["HOME"] = in.ActiveHome
	}

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

// effectWindowsCall reports a call judged as a Windows host runs it: a
// Windows hook placed it (its shell dialect selection ran), or its working
// folder or home is a drive-absolute or UNC path. The readers already read
// such a call with Windows rules; before this the lane read a Codex shell on
// a Windows host (no dialect hint) and Git Bash as POSIX paths, and the
// POSIX lexer ate the backslashes of C:\Users\...
func effectWindowsCall(request trustedActionRequest) bool {
	return request.windowsShellDialect || request.windowsDialectReadings ||
		windowsShapedPath(request.Input.CWD) || windowsShapedPath(request.Input.ActiveHome)
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

// effectMountedAccountHomes are the passwd homes behind a call's placed
// credential targets outside the conventional home roots (/mnt/home/<u>,
// /srv/homes/<u>): a candidate folder (effectrules.AccountHomeCandidates) is
// another account's home only when the passwd lookup of its last name
// returns that folder, never by its shape (rel-1-0-10:GAP-0899). The lookups
// are bounded by maxEffectAccountLookups per call and counted like the ~name
// lookups; a candidate past the cap stays unknown. A folder already in known
// (a ~name the call spells) is not looked up again.
func effectMountedAccountHomes(res effects.Result, activeHome, login string, known []string) []string {
	var homes []string
	looked := 0
	for _, root := range effectrules.AccountHomeCandidates(res, activeHome) {
		name := root[strings.LastIndexByte(root, '/')+1:]
		if name == "" || name == "." || name == ".." || name[0] == '-' || (login != "" && strings.EqualFold(name, login)) ||
			slices.ContainsFunc(known, func(h string) bool { return strings.TrimRight(h, "/") == root }) {
			continue
		}
		if looked == maxEffectAccountLookups {
			effectAccountLookupsOver.Add(1)
			continue
		}
		looked++
		effectAccountLookups.Add(1)
		if home, ok := effectLookupAccountHome(name); ok && strings.TrimRight(home, "/") == root {
			homes = append(homes, root)
		}
	}
	return homes
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
// run the same code, with the same counted budgets and recovery.
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
	// linkTo: a touching link effect names a protected member as the link's
	// target (an alias of the member) and a later command of the call uses
	// that alias (effectLinkAliasUsed); linkAt: one names a member as the
	// place a link is put. A call that puts a link at a member is judged by
	// that placement (decide.RowEffectLink), whatever the link points to.
	linkTo, linkAt bool
	// known: some protected effect is known (mutation or credential read).
	known          bool
	knownMutation  bool
	readProofs     []decide.Proof
	mutationProofs []decide.Proof
	uploadProofs   []decide.Proof
	// restrictedSets are the sets of the exact members that made the call
	// restricted: the sets the restricted verdict is about. A file of ~/.ssh
	// is also a known member of the authorized-keys set by its folder, but
	// only an exact member decides the tier (GAP-1878).
	restrictedSets []string
	// writtenCredentialSets are the credential file classes
	// (decide.CredentialSet) of the exact own-home credential members a
	// restricted-eligible mutation of the call names.
	writtenCredentialSets []string
	// credentialAppend: one of those mutations appends to the member.
	credentialAppend bool
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
		known, maybe, linkHeld := effectProtectedSets(t, kind, effectWritesThroughLink(f))
		if linkHeld {
			c.linkHeld = true
		}
		if proof, ok := knownCredentialFileUploadProof(result, f); ok && fullyAccounted && len(c.uploadProofs) == 0 {
			c.uploadProofs = append(c.uploadProofs, proof)
		}
		if len(known) == 0 && len(maybe) == 0 {
			continue
		}
		// Mixed-purpose agent configs contain ordinary model and runtime
		// settings beside DefenseClaw's hooks. A complete known write that
		// preserves the registered entries is no hook mutation; the legacy
		// readers still grade the call. Deletes, truncations and opaque data
		// keep their effect grade (GAP-1478).
		if fullyAccounted && len(known) == 1 && known[0] == effectrules.SetAgentHookConfig && len(maybe) == 0 {
			preserved := false
			if env.preservedHookConfigPaths != nil {
				_, preserved = env.preservedHookConfigPaths[effectHookConfigTargetKey(t.GetPath())]
			} else {
				preserved = effectKnownHookConfigWritePreservesRegistration(result, f, env.Home)
			}
			if preserved {
				continue
			}
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
		// A copy or move onto the DefenseClaw state folder itself, or the
		// folder moved away, is a known state write whatever member it
		// reaches: it stands as its own proof, before the reach rule
		// (rel-1-0-10:GAP-1261).
		if proof, ok := stateFolderWriteProof(f, flavor); ok {
			c.mutationProofs = appendCredentialReadProof(c.mutationProofs, proof)
		}
		r := factReach(f, known, unknownEffect, env, flavor)
		if len(known) == 0 && r == "" {
			continue
		}
		c.touches = true
		if kind == string(effects.KindLink) {
			if i := int(f.GetIndex()) - 1; effectFactIsLinkTarget(result, f) {
				c.linkTo = c.linkTo || effectLinkAliasUsed(result, i)
			} else if len(known) > 0 {
				// Only a link known to be put at a member: an unplaced link
				// end (the destination may be a folder) touches by reach.
				c.linkAt = true
			}
		}
		touchSets = append(touchSets, append(append([]string(nil), known...), maybe...)...)
		if r != "" {
			c.reach = append(c.reach, r)
		} else if mutating {
			c.known = true
			c.knownMutation = true
		} else if proof, ok := knownCredentialReadProof(result, f); ok {
			c.known = true
			c.readProofs = appendCredentialReadProof(c.readProofs, proof)
		}
		if fullyAccounted {
			for _, proof := range knownProtectedMutationProofs(f, flavor) {
				c.mutationProofs = appendCredentialReadProof(c.mutationProofs, proof)
				c.known, c.knownMutation = true, true
				// The authorized-keys ruling blocks in every pack.
				if proof.Target == decide.TargetAuthorizedKeys {
					c.restricted, c.restrictedRuling = true, true
					c.restrictedSets = append(c.restrictedSets, effectrules.SetSSHAuthorizedKeys)
				}
			}
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
		through := effectWritesThroughLink(f)
		for _, m := range t.GetProtected() {
			// An exact member, or one a write that opens its path reaches
			// through a link to the member itself (DET111 ruling R2: the
			// cell of the file written, never below the link path's). A
			// credential member is classed by its own name, which the link
			// path does not carry: through a link it keeps the unknown tier.
			exact := m.GetReason() == "exact" ||
				through && m.GetReason() == effectrules.ReasonLinkExact && m.GetSet() != effectrules.SetCredentials
			if m.GetState() != semantic.ProtectedKnown || !exact || m.GetSet() == effectrules.SetOutsideHome {
				continue
			}
			c.restricted = true
			c.restrictedSets = append(c.restrictedSets, m.GetSet())
			if m.GetSet() == effectrules.SetCredentials {
				c.writtenCredentialSets = append(c.writtenCredentialSets, decide.CredentialSet(effectCredentialMemberTail(t.GetPath())))
				c.credentialAppend = c.credentialAppend || kind == string(effects.KindAppend)
			}
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
	c.restrictedSets = dedupeStrings(c.restrictedSets)
	c.writtenCredentialSets = dedupeStrings(c.writtenCredentialSets)
	return c
}

// effectKnownHookConfigTargets is the per-call handoff from the one effect
// extraction to the legacy hook reader. An absent map never skips a finding.
type effectKnownHookConfigTargets struct {
	paths map[string]struct{}
}

func effectHookConfigTargetKey(path string) string {
	if !filepath.IsAbs(path) {
		return ""
	}
	path = filepath.Clean(path)
	if agentHookConfigFoldCase() {
		path = strings.ToLower(path)
	}
	return path
}

func (targets *effectKnownHookConfigTargets) preserves(path string) bool {
	if targets == nil {
		return false
	}
	key := effectHookConfigTargetKey(path)
	if key == "" {
		return false
	}
	_, ok := targets.paths[key]
	return ok
}

// effectPreservedHookConfigPaths records a target only if every effect on it
// is a fully known write whose resulting document keeps registered hooks.
// An unknown or incomplete extraction has no authority to relax a reader.
func effectPreservedHookConfigPaths(result effects.Result, facts []*semanticpb.EffectFact, home string) map[string]struct{} {
	safe := make(map[string]struct{})
	if len(result.Unknowns) != 0 {
		return safe
	}
	unsafe := make(map[string]struct{})
	for _, fact := range facts {
		target := fact.GetTarget()
		if target.GetType() != "path" {
			continue
		}
		key := effectHookConfigTargetKey(target.GetPath())
		if key == "" {
			continue
		}
		known, maybe, _ := effectProtectedSets(target, fact.GetKind(), effectWritesThroughLink(fact))
		if len(known) == 1 && known[0] == effectrules.SetAgentHookConfig && len(maybe) == 0 &&
			effectKnownHookConfigWritePreservesRegistration(result, fact, home) {
			safe[key] = struct{}{}
		} else {
			unsafe[key] = struct{}{}
		}
	}
	for key := range unsafe {
		delete(safe, key)
	}
	return safe
}

// effectKnownHookConfigWritePreservesRegistration proves that the one
// complete, literal write to a mixed-purpose config leaves DefenseClaw's
// registered hooks intact. It reads the same bounded before/after document
// contract as the 1.0.10 hook guard. Unknown data, missing reads and any
// deletion or truncation keep the effect finding.
func effectKnownHookConfigWritePreservesRegistration(result effects.Result, f *semanticpb.EffectFact, home string) bool {
	if f == nil || (f.GetKind() != string(effects.KindWrite) && f.GetKind() != string(effects.KindAppend)) ||
		f.GetTargetState() != "known" || f.GetRoleState() != "known" || len(f.GetReasons()) != 0 {
		return false
	}
	i := int(f.GetIndex()) - 1
	if i < 0 || i >= len(result.Effects) {
		return false
	}
	e := result.Effects[i]
	d := e.Data
	if d == nil || (d.Kind != effects.DataLiteral && d.Kind != effects.DataHeredoc && d.Kind != effects.DataHereString &&
		d.Kind != effects.DataArgument) || len(d.Sources) != 0 || d.Text == "" || d.Bytes != len(d.Text) {
		return false
	}
	path := f.GetTarget().GetPath()
	if path == "" {
		return false
	}
	guard := newAgentHookConfigGuard("", home)
	format := guard.format(path)
	// Only Codex TOML is a mixed-purpose config with an observed 1.0.10
	// benign-write cell. Other hook files keep their existing write grade.
	if format != gatewayconnector.AgentHookConfigCodexTOML {
		return false
	}
	before, exists := guard.read(path)
	if !exists {
		// A failed or unreadable file is not proof of absence. Only a
		// genuinely absent file has no registered entries to preserve.
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	after := []byte(d.Text)
	if f.GetKind() == string(effects.KindAppend) {
		if len(before)+len(after) > agentHookConfigMaxBytes {
			return false
		}
		after = append(append([]byte(nil), before...), after...)
	}
	return agentHookConfigTurnsOff(format, before, exists, after, true) == ""
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
		if m.GetState() != semantic.ProtectedUnknown || m.GetReason() == "link" || m.GetReason() == effectrules.ReasonLinkExact ||
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
	Home                     string
	DotGlob                  bool
	preservedHookConfigPaths map[string]struct{}
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
// effectFactIsLinkTarget reports a link fact that names the link's target
// (effects.Effect.LinkTarget); a fact's Index is its 1-based effect index.
func effectFactIsLinkTarget(result effects.Result, f *semanticpb.EffectFact) bool {
	i := int(f.GetIndex()) - 1
	return i >= 0 && i < len(result.Effects) && result.Effects[i].LinkTarget
}

// effectLinkAliasUsed reports that the link whose target end is effect i is
// used later in the same call: a later effect reads, writes, copies or links
// the link's own known path (ln -s ~/.ssh/authorized_keys s && cp -a s n;
// ln ~/.ssh/authorized_keys n && echo k >> n). An alias that is only made
// (a dotfiles script linking its own authorized_keys into its repo) moves
// nothing through the member in this call. The link end is the next link
// effect of the same command (effects emits target, then link).
func effectLinkAliasUsed(result effects.Result, i int) bool {
	if i < 0 || i+1 >= len(result.Effects) {
		return false
	}
	at := result.Effects[i+1]
	// The link end's path is placed even when its state is not known (the
	// destination may be a folder): a later effect on that exact path uses
	// the alias either way. With no working folder the end is not placed;
	// a later effect on the same relative spelling then uses it.
	if at.Kind != effects.KindLink || at.LinkTarget || at.Origin.Command != result.Effects[i].Origin.Command ||
		(at.Target.Path == "" && at.Target.Spelling == "") {
		return false
	}
	for _, e := range result.Effects[i+2:] {
		if e.Origin.Command == at.Origin.Command {
			continue
		}
		if at.Target.Path != "" && e.Target.Path == at.Target.Path ||
			at.Target.Path == "" && e.Target.Path == "" && e.Target.Spelling == at.Target.Spelling {
			return true
		}
	}
	return false
}

// effectProtectedSets is the known and maybe sets of a fact's target. A member
// reached only through a link the resolver followed is held (counted, not
// raised), unless through: the write opens the path it names, so the file the
// link reaches is the file written (effectWritesThroughLink). Such a known
// member takes the cell of the file the link reaches, never lower than the
// link path's own (DET111 ruling R2); an unresolved link keeps its floor.
func effectProtectedSets(t *semanticpb.EffectTarget, kind string, through bool) (known, maybe []string, linkHeld bool) {
	for _, m := range t.GetProtected() {
		switch {
		case (m.GetReason() == "link" || m.GetReason() == effectrules.ReasonLinkExact) && !(through && m.GetState() == semantic.ProtectedKnown):
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

// effectWritesThroughLink reports a content write that opens the path it
// names on every path of the call: a PowerShell content cmdlet (Set-Content,
// Add-Content, Out-File, Tee-Object) writes the file a final link reaches,
// as the FileSystem provider opens it. On Linux and macOS no 1.0.10 link
// reading follows a PowerShell path, so the held member was an allow
// (rel-1-0-10:GAP-1142, pwsh -Command Add-Content -Path link-state). A
// program that may replace the link instead (sed -i, install, mv, Move-Item,
// Copy-Item, New-Item) and a write that runs only on some paths (a function
// body run behind a cd) stay held, the legacy link reading their floor
// (rel-1-0-10:GAP-1243 benign rows, GAP-1286, GAP-1308).
func effectWritesThroughLink(f *semanticpb.EffectFact) bool {
	if f.GetCond() || f.GetOrigin().GetDialect() != string(effects.DialectPowerShell) {
		return false
	}
	switch effects.Kind(f.GetKind()) {
	case effects.KindWrite, effects.KindAppend:
	default:
		return false
	}
	switch strings.ToLower(f.GetOrigin().GetProgram()) {
	case "set-content", "add-content", "out-file", "tee-object":
		return true
	}
	return false
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

// effectShadowFindings turns a Known mutation or credential read into
// findings for the ON lane. A mutation with any Maybe reach remains in the
// shadow record. Credential reads go through Decide with a member-specific
// proof, so the existing 1.0.10 read row supplies the verdict.
func effectShadowFindings(res EffectShadowResult, mode effectRulesMode) []RuleFinding {
	var findings []RuleFinding
	for _, proof := range res.MutationProofs {
		ruleID := decide.RuleFor(proof)
		if ruleID == "" {
			continue
		}
		f := RuleFinding{RuleID: ruleID, Title: "Known protected file write", Severity: decide.PlainWriteSeverity(ruleID).String(),
			Confidence: 1, Proof: proof}
		if proof.Target == decide.TargetState {
			// The 1.0.10 tamper.detector_state_write title (GAP-0747, GAP-1261).
			f.Title = "DefenseClaw security state mutation"
		}
		f.proof = newFindingProof(findingProofEffect, ruleID, mode == effectRulesOn)
		findings = append(findings, f)
	}
	for _, proof := range res.UploadProofs {
		f := RuleFinding{RuleID: credentialFileExternalUploadRuleID, Title: "Credentials file content sent to an external destination",
			Severity: "HIGH", Confidence: 1, Proof: proof}
		f.proof = newFindingProof(findingProofEffect, credentialFileExternalUploadRuleID, mode == effectRulesOn)
		findings = append(findings, f)
	}
	for _, proof := range res.ReadProofs {
		ruleID := decide.RuleFor(proof)
		if ruleID == "" {
			continue
		}
		f := RuleFinding{RuleID: ruleID, Title: "Known credential read", Severity: "HIGH", Confidence: 1, Proof: proof}
		f.proof = newFindingProof(findingProofEffect, ruleID, mode == effectRulesOn)
		findings = append(findings, f)
	}
	if res.Tier == string(effectTierClean) || res.Action == guardrailActionAllow ||
		(res.Tier != string(effectTierRestricted) && !res.KnownMutation) {
		return findings
	}
	proof := effectFindingProof(res)
	if proof.Certainty != decide.CertKnown {
		return findings
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
		f.Proof = f.Proof.Advise()
	default:
		f.Proof = f.Proof.Enforce()
	}
	return append(findings, f)
}

// stateFolderWriteProof is the known DefenseClaw state write of a mutation of
// the state folder (~/.defenseclaw) itself, the classifier's protected_dir
// basis: a copy or move whose landing is the folder (cp -rt ~ .defenseclaw,
// cp -rT x ~/.defenseclaw, cp -r .defenseclaw ~/: the source's contents
// merge into the state root, over whatever members it holds), or the folder
// moved away or removed (mv -St ~/.defenseclaw x). Which member it reaches is
// unknown; that it rewrites DefenseClaw's own state is not, so the proof is
// Known on the state class and takes the state-write row (the GAP-0747
// cell: an alert in default and permissive, a block in strict, per user and
// managed). A write that may land inside the folder as a new child
// (dest_may_be_dir: cp -r proj ~/.defenseclaw with the folder there) and a
// write, mode change or link of an unlisted child keep their 1.0.10 cell:
// DefenseClaw's own tools and their users keep files there
// (observability-stack, connector-radar, notes; owner agent traces), and a
// new non-state entry is not state (rel-1-0-10:GAP-1285). The program must
// write the operand (role known) and the path must be canonical and literal.
func stateFolderWriteProof(f *semanticpb.EffectFact, flavor effects.Flavor) (decide.Proof, bool) {
	if f == nil || f.GetRoleState() != "known" {
		return decide.Proof{}, false
	}
	switch effects.Kind(f.GetKind()) {
	case effects.KindWrite, effects.KindAppend:
		for _, r := range f.GetReasons() {
			if strings.HasSuffix(r, string(effects.ReasonDestMayBeDir)) {
				return decide.Proof{}, false
			}
		}
	case effects.KindDelete:
	default:
		return decide.Proof{}, false
	}
	t := f.GetTarget()
	if t.GetType() != "path" || t.GetGlob() != "" || !effectrules.CanonicalAbsolute(t.GetPath(), flavor) {
		return decide.Proof{}, false
	}
	for _, m := range t.GetProtected() {
		if m.GetSet() == effectrules.SetSelfProtection && m.GetState() == semantic.ProtectedUnknown && m.GetReason() == "protected_dir" {
			return decide.Proof{Kind: effectProofKind(f.GetKind()), Target: decide.TargetState,
				Certainty: decide.CertKnown, Source: effectProofSource}, true
		}
	}
	return decide.Proof{}, false
}

// knownProtectedMutationProofs are the decision proofs of one Known write,
// append or delete of an exact member of a protected set, whatever program
// the program table modeled it for (redirection, cp, tee, sort -o, rsync, a
// sed w command, an interpreter's open().write or os.remove): the spelling
// gets the 1.0.10
// rule of the plain spelling on that member and that rule's cell (GAP-1865,
// generalized to the restricted sets by the DET111 ruling of 2026-11-23:
// GAP-1478, GAP-1500, GAP-0662, GAP-0506). It reads the resolved target, not
// a reviewed program list. A shell profile write stays content-decided
// (RowEffectContentDecided, GAP-1795) and an own SSH private key write has
// no 1.0.10 rule (RowEffectOwnKeyWrite, GAP-1878): neither makes a proof. A
// Maybe target or an unknown role makes none either.
func knownProtectedMutationProofs(f *semanticpb.EffectFact, flavor effects.Flavor) []decide.Proof {
	var kind decide.ProofKind
	switch f.GetKind() {
	case string(effects.KindWrite):
		kind = decide.KindWrite
	case string(effects.KindAppend):
		kind = decide.KindAppend
	case string(effects.KindDelete):
		// rm FILE and python3 -c 'os.remove(FILE)' are one delete (GAP-1478).
		kind = decide.KindDelete
	default:
		return nil
	}
	if f.GetTargetState() != "known" || f.GetRoleState() != "known" || len(f.GetReasons()) != 0 ||
		!effectrules.CanonicalAbsolute(f.GetTarget().GetPath(), flavor) {
		return nil
	}
	var proofs []decide.Proof
	for _, match := range f.GetTarget().GetProtected() {
		if match.GetState() != "known" {
			continue
		}
		p := decide.Proof{Kind: kind, Certainty: decide.CertKnown, Source: effectProofSource}
		switch match.GetSet() {
		case effectrules.SetSSHAuthorizedKeys:
			// The exact file and a known account-home match carry the same
			// proof through an identity-preserving wrapper.
			if r := match.GetReason(); r != "exact" && r != "other_home" {
				continue
			}
			p.Target = decide.TargetAuthorizedKeys
		case effectrules.SetSelfProtection:
			p.Target = decide.TargetState
		case effectrules.SetAgentHookConfig:
			p.Target = decide.TargetHookConfig
		case effectrules.SetCredentials:
			p.Target = decide.TargetCredential
			p.Set = decide.CredentialSet(effectCredentialMemberTail(f.GetTarget().GetPath()))
		default:
			continue
		}
		if p.Target != decide.TargetAuthorizedKeys && match.GetReason() != "exact" {
			continue
		}
		if decide.RuleFor(p) == "" {
			continue
		}
		proofs = append(proofs, p)
	}
	return proofs
}

// knownCredentialReadProof extracts the one 1.0.10 credential class a Known
// read names, and where its content goes in the call (effectReadFlow). A
// Maybe target, unknown role or non-credential file never makes a decision
// proof.
func knownCredentialReadProof(result effects.Result, f *semanticpb.EffectFact) (decide.Proof, bool) {
	if f == nil || f.GetKind() != string(effects.KindRead) ||
		f.GetTargetState() != "known" || f.GetRoleState() != "known" {
		return decide.Proof{}, false
	}
	var target decide.TargetClass
	knownCredential := false
	for _, match := range f.GetTarget().GetProtected() {
		if match.GetSet() != effectrules.SetCredentials || match.GetState() != "known" {
			continue
		}
		switch match.GetReason() {
		case "exact":
			target, knownCredential = decide.TargetCredential, true
		case "other_home":
			target, knownCredential = decide.TargetOtherHomeCredential, true
		}
	}
	if !knownCredential {
		return decide.Proof{}, false
	}
	tail := effectCredentialMemberTail(f.GetTarget().GetPath())
	set := decide.CredentialSet(tail)
	if set == "" {
		return decide.Proof{}, false
	}
	flow := effectReadFlow(result, int(f.GetIndex())-1)
	if target == decide.TargetOtherHomeCredential && flow == decide.FlowNone &&
		effects.SummaryReader(f.GetOrigin().GetProgram()) {
		// A digest or a count of another account's credential file whose
		// output goes nowhere else (sha256sum, md5sum or cksum of a key file
		// in another home; not cmp, whose options may print the bytes,
		// GAP-2212) shows none of its bytes. 1.0.10 allows it in
		// every tier, as its readers name no such read, and the effects
		// reading makes no read proof for it either: the read row of another
		// home's file made it a strict and managed-strict block, an FPR raise
		// over 1.0.10 on the owner transcripts, which the exact wrapper twin
		// then gave the sudo form too (GAP-2200). The own-home read of that
		// shape is the shadow record of RowEffectRead; a read shown, sent or
		// copied out keeps its row (GAP-0888, GAP-0898).
		return decide.Proof{}, false
	}
	return decide.Proof{Kind: decide.KindRead, Target: target, Certainty: decide.CertKnown,
		Set: set, Source: effectProofSource, Flow: flow}, true
}

// maxEffectFlowHops bounds the copies of copies a read's content is
// followed through (counted work, never wall clock).
const maxEffectFlowHops = 8

// effectReadFlow is where the content of read effect i goes in the call
// (DET111 GAP-1846): shown on the call's output (effects marks it), sent by
// a network send whose data comes from it, or copied by a write whose data
// comes from it to another folder (cp, mv, install, a redirect). A copy
// beside the file (install key key.bak), a discard (> /dev/null) or a
// summary (grep -c, wc) keeps it local. A copy's own content is followed
// on: a later send of the copy is a send, and so is a send of a copy of
// the copy (a later read of a file the flow wrote carries its content:
// cat .env > a && cp a b && curl --data-binary @b, GAP-1641).
func effectReadFlow(result effects.Result, i int) decide.ReadFlow {
	flow, _ := effectReadFlowTo(result, i)
	return flow
}

// effectReadFlowTo is effectReadFlow and, for a sent read, the target of
// the send (a network send's endpoint or a remote copy's destination).
func effectReadFlowTo(result effects.Result, i int) (decide.ReadFlow, effects.Target) {
	if i < 0 || i >= len(result.Effects) || result.Effects[i].Kind != effects.KindRead {
		return decide.FlowNone, effects.Target{}
	}
	read := result.Effects[i]
	if read.Shown {
		return decide.FlowShown, effects.Target{}
	}
	from := map[int]bool{i + 1: true}
	written := map[string]bool{}
	flow, hops := decide.FlowNone, 0
	for j := i + 1; j < len(result.Effects) && hops < maxEffectFlowHops; j++ {
		e := result.Effects[j]
		if e.Kind == effects.KindRead {
			// A read of a file the flow wrote (cp a b after cat .env > a)
			// carries the content on to the effects whose data comes from it.
			if k := e.Target.Key(); k != "" && written[k] {
				from[j+1] = true
			}
			continue
		}
		if e.Data == nil || !slices.ContainsFunc(e.Data.Sources, func(s effects.Source) bool {
			return s.Kind == effects.SourceEffect && from[s.Effect]
		}) {
			continue
		}
		switch e.Kind {
		case effects.KindNetworkSend:
			return decide.FlowSent, e.Target
		case effects.KindWrite, effects.KindAppend:
			// The null device is lowered as no target (> /dev/null).
			if e.Target.Type == effects.TargetNone || effectDiscardPath(e.Target.Path) || effectDiscardPath(e.Target.Spelling) {
				continue
			}
			hops++
			from[j+1] = true
			if k := e.Target.Key(); k != "" {
				written[k] = true
			}
			if e.Target.Type == effects.TargetRemote {
				return decide.FlowSent, e.Target
			}
			if !effectSameFolder(e.Target, read.Target) {
				flow = decide.FlowCopied
			}
		}
	}
	return flow, effects.Target{}
}

// knownCredentialFileUploadProof is the proof of a Known read of a
// credentials file outside the protected sets (a .env: any shape of the
// credentials-file table, actionfacts.MatchCredentialFileShape) whose
// content the call sends to a destination that is not loopback or private,
// through copies of copies (effectReadFlowTo, the GAP-1846 content flow):
// cat .env > f && curl -d @f URL is the upload curl -d @.env URL is, and
// takes the 1.0.10 rule of that plain spelling (GAP-1641). A read that is
// only shown, copied or kept local raises nothing here (the 1.0.10 .env
// reader still grades it), and a file of a protected credential class takes
// its own read row (knownCredentialReadProof).
func knownCredentialFileUploadProof(result effects.Result, f *semanticpb.EffectFact) (decide.Proof, bool) {
	if f == nil || f.GetKind() != string(effects.KindRead) || f.GetTargetState() != "known" ||
		f.GetRoleState() != "known" || len(f.GetReasons()) != 0 {
		return decide.Proof{}, false
	}
	path := f.GetTarget().GetPath()
	_, ok := actionfacts.MatchCredentialFileShape(path)
	if !ok || decide.CredentialSet(effectCredentialMemberTail(path)) != "" {
		return decide.Proof{}, false
	}
	flow, to := effectReadFlowTo(result, int(f.GetIndex())-1)
	if flow != decide.FlowSent || !effectSendExternal(to) {
		return decide.Proof{}, false
	}
	return decide.Proof{Kind: decide.KindSend, Target: decide.TargetOther, Certainty: decide.CertKnown,
		Source: effectProofSource, Flow: decide.FlowSent}, true
}

// effectSendExternal reports a send destination the 1.0.10 upload rule
// counts as external: a public or unknown host (NETWORK_SCOPE_PUBLIC or
// _UNKNOWN), not a loopback, private or link-local address.
func effectSendExternal(t effects.Target) bool {
	host := t.Host
	if host == "" && t.URL != "" {
		if u, err := url.Parse(t.URL); err == nil {
			host = u.Hostname()
		}
	}
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified())
	}
	return true
}

// effectDiscardPath is the null device: what is written there goes nowhere.
func effectDiscardPath(p string) bool {
	switch strings.ToLower(strings.ReplaceAll(p, "\\", "/")) {
	case "/dev/null", "nul", "//./nul":
		return true
	}
	return false
}

// effectSameFolder reports two known paths in one folder (an unknown or
// unplaced destination is never the same folder).
func effectSameFolder(a, b effects.Target) bool {
	if a.Path == "" || b.Path == "" {
		return false
	}
	da, db := pathpkg.Dir(strings.ReplaceAll(a.Path, "\\", "/")), pathpkg.Dir(strings.ReplaceAll(b.Path, "\\", "/"))
	if a.CaseFold || b.CaseFold {
		return strings.EqualFold(da, db)
	}
	return da == db
}

// effectCredentialMemberTail finds the protected member spelling in a path;
// the classifier has already proved the target Known, so this extracts the
// member-relative table key without making a second path-resolution decision.
func effectCredentialMemberTail(path string) string {
	parts := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	for i := range parts {
		tail := strings.Join(parts[i:], "/")
		if decide.CredentialSet(tail) != "" {
			return tail
		}
	}
	return ""
}

// appendCredentialReadProof adds next unless a proof of the same class and
// content flow is already there. The flow is part of the key: wc -l X; cat X
// reads X twice, a local count then a show, and the show keeps its own proof
// (and its class read row) instead of being folded into the count's record
// (T23 review P3-2). Mutation proofs carry no flow.
func appendCredentialReadProof(proofs []decide.Proof, next decide.Proof) []decide.Proof {
	for _, proof := range proofs {
		if proof.Target == next.Target && proof.Set == next.Set && proof.Flow == next.Flow {
			return proofs
		}
	}
	return append(proofs, next)
}

// effectProofSource is the Proof.Source of every effect-lane finding: the
// shadow report's key for the effect model beside the legacy readers.
const effectProofSource = "effects"

// effectFindingProof is the DET111 proof of an effect verdict
// (internal/guardrail/decide): the deciding effect's kind, the strongest
// protected class it reached, and its certainty. A Known mutation raises only
// when the call has no Maybe reach; credential reads carry separate
// member-specific Decide proofs.
func effectFindingProof(res EffectShadowResult) decide.Proof {
	sets := res.Sets
	if res.Tier == string(effectTierRestricted) && len(res.RestrictedSets) > 0 {
		sets = res.RestrictedSets
	}
	p := decide.Proof{
		Kind:      effectProofKind(res.Kind),
		Target:    effectProofTarget(sets),
		Certainty: decide.CertKnown,
		Source:    effectProofSource,
		LinkTo:    res.LinkTo,
	}
	if p.Target == decide.TargetCredential {
		p.Set = res.WrittenCredentialSet
		// The call's kind is its first effect; an append to the credential
		// file is what the tier row reads (decide.RowEffectOwnKeyWrite records
		// only a write or mode change of the key).
		if res.CredentialAppend {
			p.Kind = decide.KindAppend
		}
	}
	if res.Tier != string(effectTierRestricted) && (!res.KnownMutation || len(res.Reach) > 0) {
		p.Certainty = decide.CertMaybe
		if len(res.Reach) > 0 {
			p.Reach = res.Reach[0]
		}
	}
	return p
}

// effectFetchedScriptRule is the bounded GAP-1554/GAP-1273 proof: one
// literal curl/wget response is the sole DataCode source of a POSIX shell
// reading its script. The frontend supplies that edge only when stdout reaches
// the shell through a pipe, here-string or nested here-document. This does
// not read remote content or infer a sink from mere co-occurrence.
func effectFetchedScriptRule(result effects.Result) string {
	const maxFetchScriptEffects = 256
	if result.Dialect != effects.DialectPOSIX || len(result.Unknowns) != 0 ||
		len(result.Effects) > maxFetchScriptEffects {
		return ""
	}
	for _, sink := range result.Effects {
		if sink.Kind != effects.KindExec || sink.Data == nil ||
			sink.Data.Kind != effects.DataCode || len(sink.Data.Sources) != 1 {
			continue
		}
		switch sink.Origin.Program {
		case "sh", "bash", "dash", "zsh", "ksh", "ash", "yash":
		case "":
			if sink.TargetState != effects.TargetStateUnknown ||
				!slices.ContainsFunc(sink.Reasons, func(r effects.Reason) bool {
					return r.Code == effects.ReasonOpaqueCode
				}) {
				continue
			}
		default:
			continue
		}
		source := sink.Data.Sources[0]
		if source.Kind != effects.SourceEffect || source.Effect < 1 ||
			source.Effect > len(result.Effects) {
			continue
		}
		fetch := result.Effects[source.Effect-1]
		if fetch.Kind != effects.KindNetworkFetch ||
			fetch.TargetState != effects.TargetStateKnown ||
			fetch.RoleState != effects.RoleStateKnown ||
			fetch.Target.Type != effects.TargetURL || fetch.Target.URL == "" ||
			len(fetch.Reasons) != 0 {
			continue
		}
		switch fetch.Origin.Program {
		case "curl", "curl.exe":
			return "CMD-PIPE-CURL"
		case "wget", "wget.exe":
			return "CMD-PIPE-WGET"
		}
	}
	return ""
}

// effectLiveFindings runs the ON lane for one outermost dispatch: the Known
// verdict's findings join today's (raise only); a Maybe verdict adds none and
// is handed to the shadow recorder off the hook's path instead, so the audit
// log still shows what the lane reached.
func effectLiveFindings(request trustedActionRequest, mode effectRulesMode, tier effectTierMode, generation func() *compiledRulePackCategories) []RuleFinding {
	res := computeEffectShadow(request, mode, tier)
	findings := withEffectClassWriteSeverity(effectShadowFindings(res, mode), generation)
	if ruleID := res.FetchedScriptRule; ruleID != "" {
		if severity := effectRuleSeverity(generation(), ruleID); severity != "" {
			f := RuleFinding{RuleID: ruleID, Title: "Fetched script supplied to a shell",
				Severity: severity, Confidence: 1}
			f.Proof = f.Proof.Advise() // the plain CMD-PIPE cell is alert-only
			f.proof = newFindingProof(findingProofEffect, ruleID, mode == effectRulesOn)
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 && res.Tier != string(effectTierClean) {
		recordEffectShadowAsync(res, request.recordEffectShadow)
	}
	return findings
}

// withEffectClassWriteSeverity gives a credential write finding (a write
// through a session alias of the member, GAP-2025) the severity the call's
// rule pack gives the member's class rule (PATH-NPMRC MEDIUM, PATH-KUBE HIGH,
// PATH-SSH-KEY CRITICAL): that rule is what grades the plain write of the
// member, whatever the program (the restricted effect finding of the plain
// spelling folds into it, decide.FoldsIntoLegacy). So the finding carries
// that rule's cell, not a proof row: its Decide proof is the reader's (zero),
// as the plain spelling's deciding finding is; a Known credential write proof
// would take decide.RowProtectedFile, an alert floor the plain write does not
// have in permissive. The gateway proof (findingProofEffect) still names the
// effects lane. The strictest member of a profile combination decides. A
// pack without the class rule grades no class write, as it grades no plain
// one, so the finding is dropped. The generation is read only when there is
// such a finding.
//
// The call's own restricted finding is kept beside it: an alias write keeps
// the T23 restricted cell in every pack, the call taking the stronger of the
// class cell and that one (DET111 ruling on GAP-2114 and GAP-2121), and a
// call that also writes the member by an effects-only spelling keeps the
// cell of that write alone.
//
// A class finding is marked floorRaiseOnly (a reading 1.0.10 did not have:
// its proof is the reader's, zero, but no 1.0.10 reader made it), so no
// effect finding of the call folds into it (foldTargetsFor); a real reader
// finding of the class still takes the restricted finding, as for the plain
// write.
func withEffectClassWriteSeverity(findings []RuleFinding, generation func() *compiledRulePackCategories) []RuleFinding {
	out := findings[:0]
	for _, f := range findings {
		// Only the class rule finding of a credential write: the call's
		// effect.protected_target_<tier> finding has a credential proof too
		// and keeps its own grading.
		if f.Proof.Kind != decide.KindRead && f.Proof.Source == decide.SourceEffects &&
			(f.Proof.Target == decide.TargetCredential || f.Proof.Target == decide.TargetOtherHomeCredential) &&
			f.RuleID != "" && f.RuleID == decide.RuleFor(f.Proof) {
			severity := effectRuleSeverity(generation(), f.RuleID)
			if severity == "" {
				continue
			}
			f.Severity, f.Proof, f.floorRaiseOnly = severity, decide.Proof{}, true
		}
		out = append(out, f)
	}
	return out
}

// effectRuleSeverity is the highest severity a generation (and each member
// of a profile combination) gives rule id; "" when no rule has the id.
func effectRuleSeverity(g *compiledRulePackCategories, id string) string {
	if g == nil {
		return ""
	}
	best := ""
	for _, category := range g.categories {
		for _, rule := range category.Rules {
			if strings.EqualFold(rule.ID, id) && decide.ParseSeverity(rule.Severity) > decide.ParseSeverity(best) {
				best = strings.ToUpper(strings.TrimSpace(rule.Severity))
			}
		}
	}
	for _, member := range g.members {
		if s := effectRuleSeverity(member, id); decide.ParseSeverity(s) > decide.ParseSeverity(best) {
			best = s
		}
	}
	return best
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
