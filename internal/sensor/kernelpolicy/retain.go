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

import "sort"

// A controls policy gets a new name whenever its binaries anchor changes: an
// agent that updates itself adds a version to its versions directory, and
// removing the old one shrinks the list again. Tetragon marks an agent's
// processes for matchBinaries followChildren only when the agent starts, so
// the replacement does not deny for a session that was already running, and
// deleting the policy it started under left that session monitored until it
// restarted (#1156). retain keeps such a policy loaded, in enforce, while a
// live session only it marked runs, and lets the delete step remove it once
// the last of them exits.
//
// It keeps nothing when the plan does not enforce (a pause, a mode change, a
// missing approval: the demote step already moved the policy to monitor), for
// a user the plan no longer denies for through a binaries anchor, for a
// session of a connector the plan no longer enforces for its user, or for a
// policy Tetragon does not list enabled in enforce mode (an operator's
// set-mode, a failSafe). The decision is made again on every pass from the
// applied record (anchor and load ticks, in the state file) and the live
// roots, so a restarted helper keeps the same policies.

// anchorOf is the binaries anchor of a controls policy: its binary uid and a
// copy of its binaries, or zero and nil when it has none.
func anchorOf(p Policy) (int, []string) {
	if p.BinaryUID <= 0 || len(p.Binaries) == 0 {
		return 0, nil
	}
	return p.BinaryUID, append([]string(nil), p.Binaries...)
}

// binaryMark is what one loaded controls policy marked: the sessions of its
// binary uid started from one of its binaries after it loaded.
type binaryMark struct {
	binaries  map[string]bool
	loadTicks uint64
}

func newBinaryMark(binaries []string, loadTicks uint64) binaryMark {
	set := make(map[string]bool, len(binaries))
	for _, binary := range binaries {
		set[binary] = true
	}
	return binaryMark{binaries: set, loadTicks: loadTicks}
}

// marked reports whether the policy marked root. A load time that is not
// known (the process scan failed right after the load) proves nothing; a
// load with no process alive (load ticks 1, as at a boot before any login)
// marked every later session.
func (m binaryMark) marked(root Root) bool {
	return root.Native && m.binaries[root.Exe] && m.loadTicks > 0 && root.StartTicks > m.loadTicks
}

// retain sets c.retained and c.retainedRoots for this pass. desired is the
// plan's policies, listed what Tetragon reported at the start of the pass.
func (c *Controller) retain(desired map[string]Policy, listed map[string]LoadedPolicy, wantEnforce bool) {
	c.retained, c.retainedRoots = map[string]int{}, map[rootKey]bool{}
	if !wantEnforce {
		return
	}
	keepers := map[int][]binaryMark{}
	index := map[int]PathIndex{}
	for _, name := range sortedPolicyNames(desired) {
		p := desired[name]
		if p.Family != FamilyControls || p.Mode != PolicyEnforce || p.BinaryUID <= 0 || len(p.Binaries) == 0 {
			continue
		}
		keepers[p.BinaryUID] = append(keepers[p.BinaryUID], newBinaryMark(p.Binaries, c.st.Applied[name].LoadTicks))
		index[p.BinaryUID] = p.Paths
	}
	type candidate struct {
		name      string
		uid       int
		loadTicks uint64
		roots     []rootKey
	}
	var candidates []candidate
	for _, name := range sortedKeys(c.recorded) {
		if _, want := desired[name]; want {
			continue
		}
		family, _ := FamilyOfName(name)
		lp, present := listed[name]
		applied, ok := c.st.Applied[name]
		if family != FamilyControls || !present || lp.State != StateEnabled || !lp.Mode.Enforcing() || !ok ||
			applied.Pending || applied.BinaryUID <= 0 || len(applied.Binaries) == 0 || len(keepers[applied.BinaryUID]) == 0 {
			continue
		}
		own := newBinaryMark(applied.Binaries, applied.LoadTicks)
		var roots []rootKey
		for _, root := range c.roots.Roots {
			if root.UID == applied.BinaryUID && own.marked(root) && !markedByAny(keepers[root.UID], root) && c.stillEnforced(root) {
				roots = append(roots, rootKey{root.PID, root.StartTicks})
			}
		}
		if len(roots) > 0 {
			candidates = append(candidates, candidate{name: name, uid: applied.BinaryUID, loadTicks: applied.LoadTicks, roots: roots})
		}
	}
	// The user can make the anchor change (a file in its versions directory)
	// while sessions run, so the policies kept are bounded: the newest ones,
	// whose sessions are the most recent. A session left out is reported as
	// predating the controls, as before.
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].loadTicks > candidates[j].loadTicks })
	for i, kept := range candidates {
		if i >= maxRetainedControls {
			break
		}
		c.retained[kept.name] = len(kept.roots)
		for _, key := range kept.roots {
			c.retainedRoots[key] = true
		}
		// A restarted helper compiles no index for a policy the plan no
		// longer wants; the replacement's covers the same home.
		c.tallyMu.Lock()
		entry := c.names[kept.name]
		if len(entry.index.Exact)+len(entry.index.Prefixes) == 0 {
			entry.index = index[kept.uid]
			c.names[kept.name] = entry
		}
		c.tallyMu.Unlock()
	}
}

// stillEnforced reports whether the plan still denies for root's connector
// for its user: the intent enforces it and the user is enrolled for it. A
// kept policy must not go on denying for a connector taken out of enforce.
func (c *Controller) stillEnforced(root Root) bool {
	return contains(c.cfg.Intent.EnforceConnectors, root.Connector) && contains(c.enrollment.Connectors(root.UID), root.Connector)
}

// maxRetainedControls bounds the replaced controls policies kept loaded for
// their sessions at once.
const maxRetainedControls = 4

func markedByAny(marks []binaryMark, root Root) bool {
	for _, mark := range marks {
		if mark.marked(root) {
			return true
		}
	}
	return false
}

func sortedPolicyNames(policies map[string]Policy) []string {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
