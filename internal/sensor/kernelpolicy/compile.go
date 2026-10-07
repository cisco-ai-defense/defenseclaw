// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	kernel "github.com/defenseclaw/defenseclaw/policies/kernel"
)

// Scope selects the users and connectors of one controls-family policy.
type Scope struct {
	// Mode is the mode the policy is loaded in.
	Mode PolicyMode
	// UIDs are the users the policy covers. Both the uid condition and every
	// path come from exactly these users.
	UIDs []int
	// Connectors limits which enrolled connectors are anchored; nil means
	// every enrolled CLI connector.
	Connectors map[string]bool
}

func (s Scope) allows(connector string) bool {
	if !IsCLIConnector(connector) {
		return false
	}
	return s.Connectors == nil || s.Connectors[connector]
}

// Input is everything Compile reads.
type Input struct {
	Enrollment Enrollment
	Installs   []Install
	Roots      []Root
	FS         FS
	// Observe and Connect select the two post-only policies.
	Observe bool
	Connect bool
	// Controls and Burnin select the controls families; nil omits the family.
	Controls *Scope
	Burnin   *Scope
}

// Compiled is the result of a Compile.
type Compiled struct {
	Policies []Policy
	// Notes explain what was left out and why (no anchors, a path outside its
	// home, a lint finding), for status.
	Notes []string
	// OverLimit counts roots left out of a pid anchor by the 64-pid limit.
	OverLimit int
	// Anchored counts roots in a pid anchor per uid.
	Anchored map[int]int
}

// Compile renders the policies Input asks for. It never widens: a path that
// does not resolve inside its home is left out, an empty anchor list is never
// emitted (a selector without values would match far more than intended), and
// a lint finding drops the selector, or the policy, that caused it.
func Compile(in Input) (Compiled, error) {
	set, err := kernel.Load()
	if err != nil {
		return Compiled{}, err
	}
	fsys := in.FS
	if fsys == nil {
		fsys = OSFS()
	}
	out := Compiled{Anchored: map[int]int{}}
	homes, notes := resolveHomes(fsys, in.Enrollment)
	out.Notes = append(out.Notes, notes...)
	add := func(family Family, mode PolicyMode, tp tracingPolicy, meta Policy, lintOpts LintOptions) error {
		policy, dropped, err := finalize(family, mode, tp, meta, lintOpts)
		out.Notes = append(out.Notes, dropped...)
		if err != nil {
			return err
		}
		if policy != nil {
			out.Policies = append(out.Policies, *policy)
		}
		return nil
	}
	lintOpts := LintOptions{Homes: homeList(homes), FS: fsys}

	if in.Observe {
		tp, meta, notes := compileObserve(fsys, set, homes)
		out.Notes = append(out.Notes, notes...)
		if err := add(FamilyObserve, "", tp, meta, lintOpts); err != nil {
			return Compiled{}, err
		}
	}
	if in.Connect {
		tp := compileConnect(set)
		if err := add(FamilyConnect, "", tp, Policy{}, lintOpts); err != nil {
			return Compiled{}, err
		}
	}
	for _, item := range []struct {
		family Family
		scope  *Scope
	}{{FamilyControls, in.Controls}, {FamilyBurnin, in.Burnin}} {
		if item.scope == nil {
			continue
		}
		tp, meta, notes, over := compileControls(fsys, set, in, *item.scope, homes)
		out.Notes = append(out.Notes, notes...)
		out.OverLimit += over
		if len(tp.Spec.LsmHooks) == 0 {
			continue
		}
		if err := add(item.family, item.scope.Mode, tp, meta, lintOpts); err != nil {
			return Compiled{}, err
		}
	}
	countAnchored(&out, in)
	sort.SliceStable(out.Policies, func(i, j int) bool {
		return familyRank(out.Policies[i].Family) < familyRank(out.Policies[j].Family)
	})
	return out, nil
}

func familyRank(f Family) int {
	for i, family := range Families {
		if family == f {
			return i
		}
	}
	return len(Families)
}

// countAnchored records how many roots each user has in a pid anchor.
func countAnchored(out *Compiled, in Input) {
	for _, policy := range out.Policies {
		if policy.Family != FamilyControls && policy.Family != FamilyBurnin {
			continue
		}
		anchored := map[int]bool{}
		for _, pid := range policy.PIDs {
			anchored[pid] = true
		}
		for _, root := range in.Roots {
			if anchored[root.PID] {
				out.Anchored[root.UID]++
			}
		}
	}
}

func homeList(homes map[int]string) []string {
	seen := map[string]bool{}
	for _, home := range homes {
		seen[home] = true
	}
	return sortedKeys(seen)
}

// resolveHomes resolves each enrolled uid's home once.
func resolveHomes(fsys FS, e Enrollment) (map[int]string, []string) {
	homes := map[int]string{}
	var notes []string
	for _, uid := range e.UIDs() {
		home := e.HomeOf(uid)
		real, err := fsys.EvalSymlinks(home)
		if err != nil || !filepath.IsAbs(real) || real == "/" {
			notes = append(notes, fmt.Sprintf("home_unresolved:%d", uid))
			continue
		}
		if info, err := fsys.Stat(real); err != nil || !info.IsDir() {
			notes = append(notes, fmt.Sprintf("home_unresolved:%d", uid))
			continue
		}
		homes[uid] = real
	}
	return homes, notes
}

// resolveUnder resolves a home-relative name to the path the kernel will
// report when it is opened: symlinks resolved, and only when the result stays
// strictly inside the home. A name that does not exist yet keeps its name
// below its deepest existing ancestor, so a file created later is still named.
func resolveUnder(fsys FS, home, rel string, dir bool) (string, bool) {
	full := filepath.Join(home, rel)
	if real, err := fsys.EvalSymlinks(full); err == nil {
		if !inside(home, real) || real == home {
			return "", false
		}
		full = real
	} else {
		ancestor, rest := filepath.Dir(full), filepath.Base(full)
		for ancestor != home && ancestor != "/" && ancestor != "." {
			if real, err := fsys.EvalSymlinks(ancestor); err == nil {
				if !inside(home, real) {
					return "", false
				}
				full = filepath.Join(real, rest)
				break
			}
			rest = filepath.Join(filepath.Base(ancestor), rest)
			ancestor = filepath.Dir(ancestor)
		}
	}
	if dir {
		full += "/"
	}
	return full, true
}

// maxResolvedPath bounds a resolved path. The user controls what a link in
// the home points to; a value Tetragon would refuse to load must drop that
// one path, not the policy every other user shares.
const maxResolvedPath = 512

// usablePath reports whether a resolved path may become a policy value. For an
// Override selector it also refuses the paths lint rule 4 forbids, which a
// user could reach by pointing a key name at, say, a provider credential.
// Each refusal drops the one path and is reported; it never changes what the
// other users are protected from.
func usablePath(resolved string, override bool) bool {
	if len(resolved) > maxResolvedPath || !utf8.ValidString(resolved) {
		return false
	}
	for _, r := range resolved {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return !override || forbiddenOverride(resolved) == ""
}

// pathsFor resolves a control's exact files and directories for every home.
func pathsFor(fsys FS, homes []string, files, dirs []string, override bool) (exact, prefixes, notes []string) {
	one := func(home, rel string, dir bool) (string, bool) {
		resolved, ok := resolveUnder(fsys, home, strings.TrimSuffix(rel, "/"), dir)
		switch {
		case !ok:
			notes = append(notes, "path_outside_home:"+filepath.Join(home, rel))
		case !usablePath(resolved, override):
			notes = append(notes, "path_not_usable:"+filepath.Join(home, rel))
			ok = false
		}
		return resolved, ok
	}
	for _, home := range homes {
		for _, rel := range files {
			if resolved, ok := one(home, rel, false); ok {
				exact = append(exact, resolved)
			}
		}
		for _, rel := range dirs {
			if resolved, ok := one(home, rel, true); ok {
				prefixes = append(prefixes, resolved)
			}
		}
	}
	return dedupe(exact), dedupe(prefixes), notes
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	return sortedKeys(seen)
}

func hostNS() []tpNamespace {
	return []tpNamespace{{Namespace: "Pid", Operator: "In", Values: []string{hostNamespace}}}
}

func basePolicy() tracingPolicy {
	return tracingPolicy{APIVersion: apiVersion, Kind: kindPolicy}
}

// fileArgs are the arguments of the file_open hook: the opened file, its
// open mode and the opener's uid. The uid is read from the open's credentials,
// so it names the user whose process opened the file, not a file owner.
func fileArgs(withUID bool) []tpArg {
	args := []tpArg{
		{Index: 0, Type: "file"},
		{Index: 0, Type: "uint32", Resolve: "f_mode", Label: "f_mode"},
	}
	if withUID {
		args = append(args, tpArg{Index: 0, Type: "uint32", Resolve: "f_cred.uid.val", Label: "opener_uid"})
	}
	return args
}

const writeMask = "2" // FMODE_WRITE: refused before O_TRUNC truncates (trunc_check.out)

func postAction(rateLimit string) tpAction {
	return tpAction{Action: "Post", RateLimit: rateLimit, RateLimitScope: "process"}
}

func compileObserve(fsys FS, set kernel.Set, homes map[int]string) (tracingPolicy, Policy, []string) {
	homeDirs := homeList(homes)
	tp := basePolicy()
	exactHook := tpLsm{Hook: "file_open", Args: fileArgs(false)}
	prefixHook := tpLsm{Hook: "file_open", Args: fileArgs(false)}
	var notes []string
	for _, group := range set.Observe.Groups {
		files, dirs, access := group.Files, group.Dirs, group.Access
		if group.FromControl != "" {
			control, _ := set.Control(group.FromControl)
			files, dirs = control.Files, control.Dirs
		}
		var exact, prefixes []string
		if group.Scope == "system" {
			exact = append(exact, files...)
			prefixes = append(prefixes, dirs...)
		} else {
			var n []string
			exact, prefixes, n = pathsFor(fsys, homeDirs, files, dirs, false)
			notes = append(notes, n...)
		}
		selector := func(operator string, values []string) tpSelector {
			sel := tpSelector{
				MatchNamespaces: hostNS(),
				MatchArgs:       []tpMatchArg{{Index: 0, Operator: operator, Values: values}},
				MatchActions:    []tpAction{postAction(set.Observe.RateLimit)},
			}
			if access == kernel.AccessWrite {
				sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Index: 1, Operator: "Mask", Values: []string{writeMask}})
			}
			return sel
		}
		if len(exact) > 0 {
			exactHook.Selectors = append(exactHook.Selectors, selector("Equal", exact))
		}
		if len(prefixes) > 0 {
			prefixHook.Selectors = append(prefixHook.Selectors, selector("Prefix", prefixes))
		}
	}
	for _, hook := range []tpLsm{exactHook, prefixHook} {
		if len(hook.Selectors) > 0 {
			tp.Spec.LsmHooks = append(tp.Spec.LsmHooks, hook)
		}
	}
	return tp, Policy{}, notes
}

func compileConnect(set kernel.Set) tracingPolicy {
	tp := basePolicy()
	tp.Spec.Kprobes = []tpKprobe{{
		Call:    "tcp_connect",
		Syscall: false,
		Args:    []tpArg{{Index: 0, Type: "sock"}},
		Selectors: []tpSelector{{
			MatchArgs:    []tpMatchArg{{Index: 0, Operator: "NotDAddr", Values: append([]string(nil), set.Connect.ExcludeDestinations...)}},
			MatchActions: []tpAction{postAction(set.Connect.RateLimit)},
		}},
	}}
	return tp
}

func validBinary(p string) bool {
	return p != "" && len(p) <= maxBinaryLen && path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

// compileControls renders one controls-family policy.
//
// Equal and Prefix cannot share one matchArgs entry, so the exact names and
// the directories of kernel.persistence_write live in two file_open hooks of
// the same policy (Tetragon supports repeated hooks, with an instance
// counter). Each hook stays inside the 5-selector budget:
//
//	hook 0: NoPost ssh exemption, ssh keys (binaries, pids), persistence files (binaries, pids)
//	hook 1: persistence directories (binaries, pids)
func compileControls(fsys FS, set kernel.Set, in Input, scope Scope, homes map[int]string) (tracingPolicy, Policy, []string, int) {
	var notes []string
	uidSet := map[int]bool{}
	for _, uid := range scope.UIDs {
		if _, ok := homes[uid]; ok && in.Enrollment.Has(uid) {
			uidSet[uid] = true
		}
	}
	uids := make([]int, 0, len(uidSet))
	for uid := range uidSet {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	tp := basePolicy()
	if len(uids) == 0 {
		return tp, Policy{}, append(notes, "controls: no enrolled user"), 0
	}
	var homeDirs []string
	for _, uid := range uids {
		homeDirs = append(homeDirs, homes[uid])
	}

	// Anchors.
	bins := map[string]bool{}
	for _, install := range in.Installs {
		if uidSet[install.UID] && scope.allows(install.Connector) {
			for _, native := range install.Native {
				if validBinary(native) {
					bins[native] = true
				}
			}
		}
	}
	var pids []int
	over := 0
	for _, root := range in.Roots {
		if !uidSet[root.UID] || !scope.allows(root.Connector) {
			continue
		}
		if len(pids) >= MaxPIDs {
			over++
			continue
		}
		pids = append(pids, root.PID)
		if root.Native && validBinary(root.Exe) {
			bins[root.Exe] = true
		}
	}
	sort.Ints(pids)
	binList := sortedKeys(bins)
	if over > 0 {
		notes = append(notes, fmt.Sprintf("%s:%d", WarnRootsOverLimit, over))
	}

	ssh, _ := set.Control(kernel.ControlSSHPrivateKeyRead)
	persist, _ := set.Control(kernel.ControlPersistenceWrite)
	sshFiles, _, n1 := pathsFor(fsys, homeDirs, ssh.Files, nil, true)
	persistFiles, persistDirs, n2 := pathsFor(fsys, homeDirs, persist.Files, persist.Dirs, true)
	notes = append(notes, n1...)
	notes = append(notes, n2...)

	uidValues := make([]string, len(uids))
	for i, uid := range uids {
		uidValues[i] = strconv.Itoa(uid)
	}
	override := func(anchor string, operator string, paths []string, write bool) tpSelector {
		sel := tpSelector{MatchNamespaces: hostNS()}
		switch anchor {
		case "binaries":
			sel.MatchBinaries = []tpBinaries{{Operator: "In", Values: binList, FollowChildren: true}}
		default:
			sel.MatchPIDs = []tpPIDs{{Operator: "In", FollowForks: true, Values: pids}}
		}
		sel.MatchArgs = []tpMatchArg{{Index: 0, Operator: operator, Values: paths}}
		if write {
			sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Index: 1, Operator: "Mask", Values: []string{writeMask}})
		}
		sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Index: 2, Operator: "Equal", Values: uidValues})
		eperm := eperm
		sel.MatchActions = []tpAction{{Action: "Override", ArgError: &eperm}, {Action: "Post"}}
		return sel
	}
	// anchored returns the bin and pid selectors for paths: an empty anchor
	// list is never emitted.
	anchored := func(operator string, paths []string, write bool) []tpSelector {
		if len(paths) == 0 {
			return nil
		}
		var out []tpSelector
		if len(binList) > 0 {
			out = append(out, override("binaries", operator, paths, write))
		}
		if len(pids) > 0 {
			out = append(out, override("pids", operator, paths, write))
		}
		return out
	}

	exactHook := tpLsm{Hook: "file_open", Args: fileArgs(true)}
	sshSelectors := anchored("Equal", sshFiles, false)
	if exempt := resolveExempt(fsys, ssh.ExemptBinaries); len(sshSelectors) > 0 && len(exempt) > 0 {
		// The exemption comes first: a NoPost selector that matches wins over
		// the Override selectors after it (exempt_order.out).
		exactHook.Selectors = append(exactHook.Selectors, tpSelector{
			MatchBinaries: []tpBinaries{{Operator: "In", Values: exempt}},
			MatchArgs:     []tpMatchArg{{Index: 0, Operator: "Equal", Values: sshFiles}},
			MatchActions:  []tpAction{{Action: "NoPost"}},
		})
	}
	exactHook.Selectors = append(exactHook.Selectors, sshSelectors...)
	exactHook.Selectors = append(exactHook.Selectors, anchored("Equal", persistFiles, true)...)
	prefixHook := tpLsm{Hook: "file_open", Args: fileArgs(true)}
	prefixHook.Selectors = anchored("Prefix", persistDirs, true)
	for _, hook := range []tpLsm{exactHook, prefixHook} {
		if len(hook.Selectors) > 0 {
			tp.Spec.LsmHooks = append(tp.Spec.LsmHooks, hook)
		}
	}
	if len(tp.Spec.LsmHooks) == 0 {
		return tp, Policy{}, append(notes, ReasonNoAnchors), over
	}
	meta := Policy{UIDs: uids, PIDs: pids, Binaries: binList, Paths: PathIndex{Exact: map[string]string{}, Prefixes: map[string]string{}}}
	for _, p := range sshFiles {
		meta.Paths.Exact[p] = kernel.ControlSSHPrivateKeyRead
	}
	for _, p := range persistFiles {
		meta.Paths.Exact[p] = kernel.ControlPersistenceWrite
	}
	for _, p := range persistDirs {
		meta.Paths.Prefixes[p] = kernel.ControlPersistenceWrite
	}
	return tp, meta, notes, over
}

// resolveExempt resolves the ssh programs that exist on this host. A program
// that is missing is simply not exempted.
func resolveExempt(fsys FS, candidates []string) []string {
	seen := map[string]bool{}
	for _, candidate := range candidates {
		real, err := fsys.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if info, err := fsys.Stat(real); err != nil || !info.Mode().IsRegular() {
			continue
		}
		if validBinary(real) {
			seen[real] = true
		}
	}
	return sortedKeys(seen)
}

// finalize names, renders and lints tp. A selector that breaks a rule is
// removed; if the policy still breaks one, it is dropped. Removing a selector
// can only narrow what is denied, with one exception: the ssh exemption. A
// finding in any NoPost selector therefore drops the whole policy.
func finalize(family Family, mode PolicyMode, tp tracingPolicy, meta Policy, opts LintOptions) (*Policy, []string, error) {
	var dropped []string
	for attempt := 0; attempt < 4; attempt++ {
		if len(tp.Spec.LsmHooks)+len(tp.Spec.Kprobes) == 0 {
			return nil, dropped, nil
		}
		hash, _, err := bodyHash(tp)
		if err != nil {
			return nil, dropped, err
		}
		tp.Metadata.Name = policyName(family, hash)
		data, err := render(family, tp, mode)
		if err != nil {
			return nil, dropped, err
		}
		violations := Lint(data, opts)
		if len(violations) == 0 {
			meta.Family, meta.Name, meta.Mode, meta.YAML, meta.tp = family, tp.Metadata.Name, mode, data, tp
			return &meta, dropped, nil
		}
		remove := map[[2]int]bool{}
		for _, v := range violations {
			dropped = append(dropped, fmt.Sprintf("kernel_policy_lint:%s:%s", family, v))
			if v.Hook < 0 || v.Selector < 0 || (v.Hook >= len(tp.Spec.LsmHooks)) {
				return nil, dropped, nil
			}
			if isNoPost(tp.Spec.LsmHooks[v.Hook].Selectors[v.Selector]) {
				return nil, dropped, nil
			}
			remove[[2]int{v.Hook, v.Selector}] = true
		}
		var hooks []tpLsm
		for h, hook := range tp.Spec.LsmHooks {
			var kept []tpSelector
			for s, selector := range hook.Selectors {
				if !remove[[2]int{h, s}] {
					kept = append(kept, selector)
				}
			}
			if len(kept) > 0 {
				hook.Selectors = kept
				hooks = append(hooks, hook)
			}
		}
		tp.Spec.LsmHooks = hooks
	}
	return nil, dropped, nil
}
