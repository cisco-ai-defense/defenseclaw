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
	// Compile also adds ready users without a safe enforcing anchor to Burnin,
	// unless an operator deleted that family.
	Controls      *Scope
	Burnin        *Scope
	BurninDeleted bool
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
	compileFamily := func(family Family, scope *Scope) error {
		if scope == nil {
			return nil
		}
		tp, meta, notes, over := compileControls(fsys, set, in, *scope, homes)
		out.Notes = append(out.Notes, notes...)
		out.OverLimit += over
		if len(tp.Spec.LsmHooks) == 0 {
			return nil
		}
		return add(family, scope.Mode, tp, meta, lintOpts)
	}
	if err := compileFamily(FamilyControls, in.Controls); err != nil {
		return Compiled{}, err
	}
	burnin := in.Burnin
	if in.BurninDeleted {
		burnin = nil
	}
	if in.Controls != nil && in.Controls.Mode == PolicyEnforce && !in.BurninDeleted {
		// The enforcing policy has at most one binary uid. Ready users it
		// cannot safely deny stay measured by the monitor-only family.
		enforced := map[int]bool{}
		for _, policy := range out.Policies {
			if policy.Family == FamilyControls && policy.Mode == PolicyEnforce {
				for _, uid := range policy.UIDs {
					enforced[uid] = true
				}
			}
		}
		potential := map[int]bool{}
		for _, root := range in.Roots {
			if in.Controls.allows(root.Connector) {
				potential[root.UID] = true
			}
		}
		for _, install := range in.Installs {
			if in.Controls.allows(install.Connector) && len(install.Native) > 0 {
				potential[install.UID] = true
			}
		}
		var monitorUIDs []int
		for _, uid := range in.Controls.UIDs {
			if !enforced[uid] && potential[uid] {
				monitorUIDs = append(monitorUIDs, uid)
			}
		}
		if len(monitorUIDs) > 0 {
			if burnin == nil {
				copyScope := *in.Controls
				copyScope.Mode, copyScope.UIDs = PolicyMonitor, monitorUIDs
				burnin = &copyScope
			} else {
				copyScope := *burnin
				copyScope.UIDs = dedupeInts(append(append([]int(nil), burnin.UIDs...), monitorUIDs...))
				copyScope.Connectors = unionConnectors(burnin.Connectors, in.Controls.Connectors)
				burnin = &copyScope
			}
		}
	}
	if err := compileFamily(FamilyBurnin, burnin); err != nil {
		return Compiled{}, err
	}
	countAnchored(&out, in)
	sort.SliceStable(out.Policies, func(i, j int) bool {
		return familyRank(out.Policies[i].Family) < familyRank(out.Policies[j].Family)
	})
	return out, nil
}

func dedupeInts(values []int) []int {
	seen := map[int]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]int, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func unionConnectors(a, b map[string]bool) map[string]bool {
	if a == nil || b == nil {
		return nil
	}
	out := make(map[string]bool, len(a)+len(b))
	for connector, enabled := range a {
		if enabled {
			out[connector] = true
		}
	}
	for connector, enabled := range b {
		if enabled {
			out[connector] = true
		}
	}
	return out
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
				MatchArgs:       []tpMatchArg{{Args: []int{0}, Operator: operator, Values: values}},
				MatchActions:    []tpAction{postAction(set.Observe.RateLimit)},
			}
			if access == kernel.AccessWrite {
				sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Args: []int{1}, Operator: "Mask", Values: []string{writeMask}})
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
			MatchArgs:    []tpMatchArg{{Args: []int{0}, Operator: "NotDAddr", Values: append([]string(nil), set.Connect.ExcludeDestinations...)}},
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
// Equal and Prefix cannot share one matchArgs entry. Enforcing policies and
// monitor policies with no live root use binary selectors in separate exact
// and directory hooks. A monitor policy with live roots uses PID selectors
// grouped four at a time, packed into repeated hooks of at most five
// selectors. The SSH NoPost exemption precedes SSH key selectors in each
// relevant hook.
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
	// A binary selector can carry only one uid set. Keep its binaries from
	// one uid: taking the union of both would deny one enrolled user's
	// ordinary process when it runs the other user's agent binary. The PID
	// selector covers verified roots only in monitor mode: a numeric PID can
	// be recycled between reconciles, so it must never cause an Override.
	binsByUID := map[int]map[string]bool{}
	addBin := func(uid int, native string) {
		if !validBinary(native) {
			return
		}
		if binsByUID[uid] == nil {
			binsByUID[uid] = map[string]bool{}
		}
		binsByUID[uid][native] = true
	}
	for _, install := range in.Installs {
		if uidSet[install.UID] && scope.allows(install.Connector) {
			for _, native := range install.Native {
				addBin(install.UID, native)
			}
		}
	}
	var pids []int
	over := 0
	pidOnly := false
	for _, root := range in.Roots {
		if !uidSet[root.UID] || !scope.allows(root.Connector) {
			continue
		}
		if root.Native {
			addBin(root.UID, root.Exe)
		} else {
			pidOnly = true
		}
		if scope.Mode == PolicyEnforce {
			continue
		}
		if len(pids) >= MaxPIDs {
			over++
			continue
		}
		pids = append(pids, root.PID)
	}
	sort.Ints(pids)
	binaryUID := 0
	for _, uid := range uids {
		if len(binsByUID[uid]) > 0 {
			binaryUID = uid
			break
		}
	}
	if len(binsByUID) > 1 && scope.Mode == PolicyEnforce {
		notes = append(notes, WarnBinaryScopeLimited)
	}
	binList := sortedKeys(binsByUID[binaryUID])
	// A monitor policy with live roots uses disjoint PID groups. Keeping the
	// binary selector as well would count an open twice when followChildren
	// and followForks both recognize the same descendant.
	if scope.Mode != PolicyEnforce && len(pids) > 0 {
		binList = nil
		binaryUID = 0
	}
	if over > 0 {
		notes = append(notes, fmt.Sprintf("%s:%d", WarnRootsOverLimit, over))
	}
	// Only a session the binaries cannot cover is left to monitor; a native
	// root of the binary uid is denied through its binary.
	if scope.Mode == PolicyEnforce && pidOnly {
		notes = append(notes, WarnPIDMonitorOnly)
	}
	var homeDirs []string
	if scope.Mode == PolicyEnforce {
		if len(binList) > 0 {
			homeDirs = append(homeDirs, homes[binaryUID])
		}
	} else {
		for _, uid := range uids {
			homeDirs = append(homeDirs, homes[uid])
		}
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
	override := func(anchor string, pidValues []int, operator string, paths []string, write bool) tpSelector {
		sel := tpSelector{MatchNamespaces: hostNS()}
		switch anchor {
		case "binaries":
			sel.MatchBinaries = []tpBinaries{{Operator: "In", Values: binList, FollowChildren: true}}
		default:
			sel.MatchPIDs = []tpPIDs{{Operator: "In", FollowForks: true, Values: pidValues}}
		}
		sel.MatchArgs = []tpMatchArg{{Args: []int{0}, Operator: operator, Values: paths}}
		if write {
			sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Args: []int{1}, Operator: "Mask", Values: []string{writeMask}})
		}
		// The binaries anchor names one uid. The pid anchor names every user
		// in scope, and Tetragon's Equal on a number carries at most 4 values
		// (MAX_MATCH_VALUES): a fifth user made the whole policy fail to load
		// (GAP-0049). InMap keeps the list in a BPF hash map with no such
		// limit.
		uidMatch := tpMatchArg{Args: []int{2}, Operator: "InMap", Values: uidValues}
		if anchor == "binaries" {
			uidMatch = tpMatchArg{Args: []int{2}, Operator: "Equal", Values: []string{strconv.Itoa(binaryUID)}}
		}
		sel.MatchArgs = append(sel.MatchArgs, uidMatch)
		eperm := eperm
		sel.MatchActions = []tpAction{{Action: "Override", ArgError: &eperm}, {Action: "Post"}}
		return sel
	}
	// The first PID group shares the normal hooks. Later groups are packed
	// into repeated hooks, with at most five selectors in each.
	firstPIDs := pids[:min(len(pids), maxPIDsPerSelector)]
	anchored := func(operator string, paths []string, write bool) []tpSelector {
		if len(paths) == 0 {
			return nil
		}
		var out []tpSelector
		if len(binList) > 0 {
			out = append(out, override("binaries", nil, operator, paths, write))
		}
		if len(firstPIDs) > 0 {
			out = append(out, override("pids", firstPIDs, operator, paths, write))
		}
		return out
	}

	exactHook := tpLsm{Hook: "file_open", Args: fileArgs(true)}
	sshSelectors := anchored("Equal", sshFiles, false)
	exempt := resolveExempt(fsys, ssh.ExemptBinaries)
	exemption := func() tpSelector {
		// The exemption comes first: a NoPost selector that matches wins over
		// the Override selectors after it (exempt_order.out).
		return tpSelector{
			MatchBinaries: []tpBinaries{{Operator: "In", Values: exempt}},
			MatchArgs:     []tpMatchArg{{Args: []int{0}, Operator: "Equal", Values: sshFiles}},
			MatchActions:  []tpAction{{Action: "NoPost"}},
		}
	}
	if len(sshSelectors) > 0 && len(exempt) > 0 {
		exactHook.Selectors = append(exactHook.Selectors, exemption())
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
	if len(pids) > maxPIDsPerSelector {
		// Several selectors for the same path can share a hook. This keeps a
		// 64-root policy to a small number of LSM instances while each PID
		// selector remains inside Tetragon's effective four-value limit.
		tp.Spec.LsmHooks = nil
		groups := make([][]int, 0, (len(pids)+maxPIDsPerSelector-1)/maxPIDsPerSelector)
		for i := 0; i < len(pids); i += maxPIDsPerSelector {
			groups = append(groups, pids[i:min(i+maxPIDsPerSelector, len(pids))])
		}
		hook := tpLsm{Hook: "file_open", Args: fileArgs(true)}
		flush := func() {
			if len(hook.Selectors) > 0 {
				tp.Spec.LsmHooks = append(tp.Spec.LsmHooks, hook)
			}
			hook = tpLsm{Hook: "file_open", Args: fileArgs(true)}
		}
		if len(sshFiles) > 0 {
			for _, group := range groups {
				if len(hook.Selectors) == 0 && len(exempt) > 0 {
					hook.Selectors = append(hook.Selectors, exemption())
				}
				if len(hook.Selectors) == MaxSelectors {
					flush()
					if len(exempt) > 0 {
						hook.Selectors = append(hook.Selectors, exemption())
					}
				}
				hook.Selectors = append(hook.Selectors, override("pids", group, "Equal", sshFiles, false))
			}
		}
		if len(persistFiles) > 0 {
			for _, group := range groups {
				if len(hook.Selectors) == MaxSelectors {
					flush()
				}
				hook.Selectors = append(hook.Selectors, override("pids", group, "Equal", persistFiles, true))
			}
		}
		flush()
		if len(persistDirs) > 0 {
			for _, group := range groups {
				if len(hook.Selectors) == MaxSelectors {
					flush()
				}
				hook.Selectors = append(hook.Selectors, override("pids", group, "Prefix", persistDirs, true))
			}
			flush()
		}
	}
	if len(tp.Spec.LsmHooks) == 0 {
		return tp, Policy{}, append(notes, ReasonNoAnchors), over
	}
	policyUIDs := uids
	if scope.Mode == PolicyEnforce {
		policyUIDs = []int{binaryUID}
	}
	meta := Policy{UIDs: policyUIDs, PIDs: pids, BinaryUID: binaryUID, Binaries: binList, Paths: PathIndex{Exact: map[string]string{}, Prefixes: map[string]string{}}}
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
