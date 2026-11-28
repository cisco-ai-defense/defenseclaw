// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Env carries everything the projection needs that the pure extractor does
// not: the active home, the path flavor, a link resolver (nil uses the hook's
// file-system reader), and a test for a file the same session created.
type Env struct {
	Home   string
	Flavor effects.Flavor
	// AccountHomes are passwd homes the effects frontend resolved from Options.Accounts.
	AccountHomes []string
	// Resolve follows a write path through links; nil falls back to
	// hookpaths.ResolveWriteTarget for the host's own path flavor and to the
	// placed path for the other flavor (resolverForWith).
	Resolve func(string) (string, bool)
	// HostResolve, when Resolve is nil, replaces hookpaths.ResolveWriteTarget
	// as the resolver of the host's own path flavor (resolverForWith): the
	// gateway passes the hook call's target memo, so a target graded against
	// every set and its hard link identity is walked once per call, with the
	// answers the readers of the call already hold. Nil reads the disk
	// (rel-1-0-10:GAP-2302).
	HostResolve func(string) (string, bool)
	// Identity reads a file's device and inode to find a hard link of a
	// protected member (one stat per resolved target); nil reads the disk
	// (DiskIdentity). Tests pass a HardLinkFixture.
	Identity IdentityFunc
	// AgentCreated reports whether an earlier call of this session wrote the
	// target keyed by effects.Target.Key(). Nil means no session memory.
	AgentCreated func(key string) bool
	// Lstat reads a path the resolver settles: a copy or move destination
	// that may be a directory (settleDestFile), a find root and the hook
	// config members below it (findDeletedMembers); nil is hookpaths.Lstat,
	// the hook's share-bounded reader.
	Lstat func(path string) (os.FileInfo, error)
	// ShortPath expands the 8.3 short components of a Windows path
	// (settleWindowsShortName); nil is the Windows host's file system
	// (hookpaths.ExpandWindowsShortPath), none on another host.
	ShortPath func(path string) (string, bool)
	// Truncated is the call's one bound record: a cap of the projection
	// (maxIdentityStats) that cut the reading short hits it. Nil: the hit is
	// only counted (IdentityCounts).
	Truncated *bounded.Truncated
}

// Project maps a pure effect result onto the CEL activation's effect list and
// grades each path target against the protected sets. It never reads or
// mutates anything the extractor already decided; only link following and the
// protected-set grade touch the file system, read-only.
func Project(res effects.Result, env Env) []*semanticpb.EffectFact {
	flavor := env.Flavor
	if flavor == "" {
		flavor = effects.FlavorPOSIX
	}
	rsv := env.Resolve
	if rsv == nil {
		rsv = resolverForWith(flavor, env.HostResolve)
	}
	sets := buildSets(env.Home, flavor)
	if len(env.AccountHomes) > 0 {
		for name, set := range sets {
			set.homeRoots = append([]string(nil), env.AccountHomes...)
			sets[name] = set
		}
	}
	ids := newIdentityCache(env.Identity, sets, env.Truncated)

	effs := res.Effects
	if len(effs) > semantic.MaxEffects {
		// Honour the CEL activation bound. A truncated projection is treated
		// as unknown by the rules (the dropped effects are not graded).
		effs = effs[:semantic.MaxEffects]
	}
	out := make([]*semanticpb.EffectFact, 0, len(effs))
	stepUps := plainStepUpProof{}
	for i := range effs {
		e := effs[i]
		stepUps.promote(&e, flavor)
		settleDestFile(&e, flavor, rsv, env.Lstat)
		settleWindowsShortName(&e, flavor, env.ShortPath)
		fact := &semanticpb.EffectFact{
			Index:       int64(i + 1),
			Kind:        string(e.Kind),
			TargetState: string(e.TargetState),
			RoleState:   string(e.RoleState),
			Reasons:     reasonStrings(e.Reasons),
			Reason:      firstReason(e.Reasons),
			Cond:        e.Cond,
			Origin: &semanticpb.EffectOrigin{
				Surface:  string(e.Origin.Surface),
				Dialect:  string(e.Origin.Dialect),
				Command:  int64(e.Origin.Command),
				Program:  e.Origin.Program,
				Wrappers: append([]string(nil), e.Origin.Wrappers...),
				Depth:    int64(e.Origin.Depth),
			},
			Target: projectTarget(e.Target, e.TargetState, e.Kind, sets, flavor, env.Home, rsv, env.AgentCreated, ids),
		}
		if e.Data != nil {
			fact.DataKind = string(e.Data.Kind)
			fact.Sources = projectSources(e.Data.Sources)
		}
		out = append(out, fact)
		// A find delete reaching an existing hook config member is a Known
		// delete of that member, beside the root's own delete.
		for _, member := range findDeletedMembers(e, sets[SetAgentHookConfig], flavor, env.Lstat) {
			if len(out) >= semantic.MaxEffects {
				break
			}
			mt := effects.Target{Type: effects.TargetPath, Path: member, Link: e.Target.Link, Flavor: e.Target.Flavor}
			out = append(out, &semanticpb.EffectFact{
				Index: fact.Index, Kind: fact.Kind, TargetState: string(effects.TargetStateKnown), RoleState: fact.RoleState,
				Cond: fact.Cond, Origin: fact.Origin,
				Target: projectTarget(mt, effects.TargetStateKnown, e.Kind, sets, flavor, env.Home, rsv, env.AgentCreated, ids),
			})
		}
	}
	holdKnownOnNameMaybe(out)
	return out
}

// settleDestFile is the resolver's answer for a copy or move destination
// that may be a directory (dest_may_be_dir: cp, mv, rsync, Copy-Item with
// one bare destination). When the write resolver's path is, on disk, an
// existing regular file, the program writes that file itself, so the target
// is Known and takes the cell of the same write spelled by redirection
// (rel-1-0-10:GAP-1677/GAP-1678: cp proj/notes.txt ~alias/.claude/settings.json
// against the ~/ control). A directory, a missing or unreadable path, a
// glob, a link the resolver could not walk, a non-canonical spelling or a
// path of the other flavor keeps the reason (unknown), as before.
func settleDestFile(e *effects.Effect, flavor effects.Flavor, rsv resolver, stat func(string) (os.FileInfo, error)) {
	if e.Kind != effects.KindWrite && e.Kind != effects.KindAppend || e.TargetState == effects.TargetStateKnown ||
		e.RoleState != effects.RoleStateKnown || e.Target.Type != effects.TargetPath || e.Target.Path == "" ||
		e.Target.Glob != "" || len(e.Reasons) == 0 {
		return
	}
	for _, r := range e.Reasons {
		if r.Code != effects.ReasonDestMayBeDir || r.Scope != effects.ScopeTarget {
			return
		}
	}
	if (flavor == effects.FlavorWindows) != (hostGOOS == "windows") || !CanonicalAbsolute(e.Target.Path, flavor) {
		return
	}
	resolved, ok := rsv(e.Target.Path)
	if !ok || resolved == "" {
		return
	}
	if stat == nil {
		stat = hookpaths.Lstat
	}
	info, err := stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	e.TargetState = effects.TargetStateKnown
	e.Reasons = nil
}

// findDeletedMembers is the resolver's answer for find ROOT -name PATTERN
// -delete (the extractor's Lexical ROOT/**/PATTERN on a Known subtree
// delete): the agent hook config members that exist below the root as
// regular files and whose name the pattern matches, which the call deletes
// (rel-1-0-10:GAP-1573c: ln -s ~/.claude d && find d/ -name '*.json'
// -delete takes the cell of the same delete of settings.json). The root is
// the folder the call's own link names (Physical), spelled with a trailing
// separator (find -P descends a link root only then) and absent before the
// call (ln makes it, not a link inside an existing folder); or a real
// folder, not a link. An opaque or catch-all selection (*), another set, a
// glob root or the other flavor adds nothing.
func findDeletedMembers(e effects.Effect, hook protectedSet, flavor effects.Flavor, lstat func(string) (os.FileInfo, error)) []string {
	t := e.Target
	if e.Kind != effects.KindDelete || !t.Subtree || e.TargetState != effects.TargetStateKnown ||
		e.RoleState != effects.RoleStateKnown || len(e.Reasons) != 0 || t.Glob != "" || t.Path == "" ||
		(flavor == effects.FlavorWindows) != (hostGOOS == "windows") {
		return nil
	}
	sep := "/"
	if flavor == effects.FlavorWindows {
		sep = `\`
	}
	root := t.Path
	if t.Physical != "" {
		root = t.Physical
	}
	name, ok := strings.CutPrefix(t.Lexical, strings.TrimRight(root, `/\`)+sep+"**"+sep)
	if !ok || name == "" || name == "*" || strings.ContainsAny(name, `/\`) || !CanonicalAbsolute(root, flavor) {
		return nil
	}
	if lstat == nil {
		lstat = hookpaths.Lstat
	}
	if t.Physical != "" {
		if !strings.HasSuffix(t.Spelling, "/") && !strings.HasSuffix(t.Spelling, `\`) {
			return nil
		}
		if _, err := lstat(t.Path); !errors.Is(err, fs.ErrNotExist) {
			return nil
		}
	}
	if info, err := lstat(root); err != nil || !info.IsDir() {
		return nil
	}
	var members []string
	for _, m := range hook.files {
		if canon(m, flavor) == canon(root, flavor) || !atOrUnder(canon(m, flavor), canon(root, flavor)) {
			continue
		}
		base := m[strings.LastIndexAny(m, `/\`)+1:]
		if matched, err := path.Match(name, base); err != nil || !matched {
			continue
		}
		if info, err := lstat(m); err == nil && info.Mode().IsRegular() {
			members = append(members, m)
		}
	}
	return members
}

// settleWindowsShortName is the resolver's answer for a Windows path the
// extractor refused only for an 8.3-looking component (non_canonical_path
// with a Lexical candidate: SSH~1\authorized_keys from the home, AUTHOR~1
// in .ssh): on a Windows host the file system expands the existing short
// components, and the long path is the Known target the call opens
// (rel-1-0-10:GAP-1553). A component that does not expand, any other reason,
// and a path of the other flavor keep the reason, as before.
func settleWindowsShortName(e *effects.Effect, flavor effects.Flavor, expand func(string) (string, bool)) {
	if flavor != effects.FlavorWindows || e.TargetState == effects.TargetStateKnown || e.RoleState != effects.RoleStateKnown ||
		e.Target.Type != effects.TargetPath || e.Target.Glob != "" || e.Target.Path != "" || len(e.Reasons) == 0 ||
		!strings.Contains(e.Target.Lexical, "~") {
		return
	}
	for _, r := range e.Reasons {
		if r.Code != effects.ReasonNonCanonicalPath || r.Scope != effects.ScopeTarget {
			return
		}
	}
	if expand == nil {
		if hostGOOS != "windows" {
			return
		}
		expand = hookpaths.ExpandWindowsShortPath
	}
	long, ok := expand(e.Target.Lexical)
	if !ok || strings.Contains(long, "~") || !CanonicalAbsolute(long, flavor) {
		return
	}
	e.Target.Path = long
	e.TargetState = effects.TargetStateKnown
	e.Reasons = nil
}

// holdKnownOnNameMaybe prevents one target/set from being both Known and
// R-NAME Maybe across effects of the same call. Independent known targets keep
// their own resolver proof.
func holdKnownOnNameMaybe(facts []*semanticpb.EffectFact) {
	// A resolver-known member is still Maybe when this same target/set also
	// has an R-NAME path: another effect in the call can leave the target's
	// role or placement unresolved. Keep independent Known targets intact.
	maybeNames := make(map[string]bool)
	for _, fact := range facts {
		target := fact.GetTarget()
		if fact.GetTargetState() != string(effects.TargetStateKnown) &&
			fact.GetRoleState() == string(effects.RoleStateKnown) {
			// A physical link walk, a passwd/conventional home-tail match, or
			// an inode identity is a resolver fact. It can settle an otherwise
			// lexical target; a bare exact spelling cannot.
			for _, match := range target.GetProtected() {
				switch match.GetReason() {
				case "link", ReasonLinkExact, "other_home", "inode":
					if match.GetState() == string(gradeKnown) {
						fact.TargetState = string(effects.TargetStateKnown)
					}
				}
				if fact.GetTargetState() == string(effects.TargetStateKnown) {
					break
				}
			}
		}
		uncertainEffect := fact.GetTargetState() != string(effects.TargetStateKnown) ||
			fact.GetRoleState() != string(effects.RoleStateKnown) ||
			fact.GetKind() == string(effects.KindOpaque)
		namedMutation := EnvInputNamedMutation(fact)
		for _, match := range target.GetProtected() {
			// An inode match is direct resolver evidence for the physical file;
			// retain it when command role or placement remains uncertain. So
			// is the exact member a named mutation writes when only an env
			// input of its program is unaccounted (EnvInputNamedMutation).
			keep := match.GetReason() == "inode" ||
				namedMutation && (match.GetReason() == "exact" || match.GetReason() == "other_home")
			if uncertainEffect && match.GetState() == string(gradeKnown) && !keep {
				match.State = string(gradeUnknown)
				match.Reason = "call_maybe"
			}
			// A link end the call just placed has an uncertain destination
			// role, not an uncertain identity of its Known source member.
			if match.GetState() == string(gradeUnknown) && match.GetReason() != "call_link" &&
				ReachForMatch(match.GetReason(), fact.GetReasons()) == ReachName {
				maybeNames[target.GetKey()+"\x00"+match.GetSet()] = true
			}
		}
	}
	for _, fact := range facts {
		target := fact.GetTarget()
		for _, match := range target.GetProtected() {
			if match.GetState() == string(gradeKnown) && match.GetReason() != "inode" &&
				maybeNames[target.GetKey()+"\x00"+match.GetSet()] {
				match.State = string(gradeUnknown)
				match.Reason = "call_maybe"
			}
		}
	}
}

func projectTarget(
	t effects.Target,
	state effects.TargetState,
	kind effects.Kind,
	sets map[string]protectedSet,
	flavor effects.Flavor,
	home string,
	rsv resolver,
	agentCreated func(string) bool,
	ids *identityCache,
) *semanticpb.EffectTarget {
	pt := &semanticpb.EffectTarget{
		Type:   string(t.Type),
		Path:   t.Path,
		Glob:   t.Glob,
		Url:    t.URL,
		Scheme: t.Scheme,
		Host:   t.Host,
		Port:   int64(t.Port),
		Scope:  t.Scope,
		Link:   string(t.Link),
		Key:    t.Key(),
		Flavor: string(t.Flavor),
	}
	if agentCreated != nil && pt.Key != "" && agentCreated(pt.Key) {
		pt.AgentCreated = true
	}
	// Only filesystem targets are graded against the protected sets.
	if t.Type != effects.TargetPath {
		return pt
	}
	for _, name := range AllSets {
		grade := gradeTarget(t, state, kind, sets[name], flavor, rsv)
		if grade == gradeNo {
			continue // absence folds to "no" in protected(); keep the list bounded
		}
		reason := matchBasis(t, grade, sets[name], flavor)
		if reason == "link" && t.Path != "" {
			// The resolver walked the spelling to an exact member: a write
			// that opens the path writes that member (DET111 ruling R2).
			if resolved, ok := rsv(t.Path); ok && resolved != "" && memberExact(resolved, sets[name], flavor) {
				reason = ReasonLinkExact
			}
		}
		pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{
			Set:    name,
			State:  string(grade),
			Reason: reason,
		})
	}
	// A hard link of a member is the member under another name: the name
	// reading cannot see it, the file identity does (GAP-1288/1289/1317/1318).
	if ids != nil {
		if hit, known := ids.hardLinkSets(t, rsv); len(hit) > 0 {
			addIdentityMatches(pt, hit, known)
		}
	}
	if mutatingKind(kind) {
		for _, name := range AllSets {
			if dirExact(t.Path, sets[name], flavor) && !hasExactFileMatch(pt, name) {
				pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{
					Set:    name,
					State:  string(gradeUnknown),
					Reason: "protected_dir",
				})
			}
		}
	}
	return pt
}

// hasExactFileMatch reports that an exact file member of set already matched,
// so a write to that file is handled and the protected-directory rule does
// not also fire.
func hasExactFileMatch(pt *semanticpb.EffectTarget, set string) bool {
	for _, m := range pt.GetProtected() {
		if m.GetSet() == set && m.GetReason() == "exact" {
			return true
		}
	}
	return false
}

func mutatingKind(kind effects.Kind) bool {
	switch kind {
	case effects.KindWrite, effects.KindAppend, effects.KindDelete,
		effects.KindLink, effects.KindPermissionChange:
		return true
	default:
		return false
	}
}

func projectSources(in []effects.Source) []*semanticpb.EffectSource {
	if len(in) == 0 {
		return nil
	}
	out := make([]*semanticpb.EffectSource, 0, len(in))
	for _, s := range in {
		out = append(out, &semanticpb.EffectSource{
			Kind:     string(s.Kind),
			Effect:   int64(s.Effect),
			Path:     s.Path,
			Variable: s.Variable,
		})
	}
	return out
}

// envInputReasons are the reasons of a path effect the call names whose
// only unknown is an env input of its program the allow list does not
// account for (effects.ReasonEnvInput, always beside unknown_flag).
var envInputReasons = []string{
	string(effects.ScopeRole) + ":" + string(effects.ReasonUnknownFlag),
	string(effects.ScopeRole) + ":" + string(effects.ReasonEnvInput),
}

// EnvInput reports a fact whose role the call words decide but for an
// unaccounted env input of its program (a NAME= prefix, env or sudo NAME=,
// an export, PATH, or a changed HOME: sudo, doas, env -i): the program may
// read config of its own, so the fact is not fully known, but the target and
// role it names are (rel-1-0-10:GAP-1478).
func EnvInput(fact *semanticpb.EffectFact) bool {
	return fact.GetTargetState() == string(effects.TargetStateKnown) &&
		slices.Equal(fact.GetReasons(), envInputReasons)
}

// EnvInputNamedMutation reports an EnvInput write, append or delete: sudo
// rsync --log-file=MEMBER or FOO=1 rsync --log-file=MEMBER writes MEMBER as
// the unwrapped spelling does, so its exact protected match stays known
// (GAP-1478).
func EnvInputNamedMutation(fact *semanticpb.EffectFact) bool {
	switch effects.Kind(fact.GetKind()) {
	case effects.KindWrite, effects.KindAppend, effects.KindDelete:
		return EnvInput(fact)
	}
	return false
}

func reasonStrings(in []effects.Reason) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r.Scope)+":"+string(r.Code))
	}
	return out
}

func firstReason(in []effects.Reason) string {
	if len(in) == 0 {
		return ""
	}
	return string(in[0].Code)
}
