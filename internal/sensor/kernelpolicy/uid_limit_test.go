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
	"strings"
	"testing"
)

// manyUsers is a world of n enrolled Codex users, each with a live session.
// A machine-policy fleet enrolls every eligible account, so this is the
// normal shape of a shared host, not an edge case.
func manyUsers(t *testing.T, n int) (*world, RootSet) {
	t.Helper()
	var targets strings.Builder
	targets.WriteString("targets:\n")
	var procs []Proc
	for i := 0; i < n; i++ {
		uid := 2001 + i
		fmt.Fprintf(&targets, "- user: dcuser%d\n  uid: %d\n  user_home: /home/dcuser%d\n  connector: codex\n", i, uid, i)
		procs = append(procs, codexProc(6001+i, 1, uint64(100+i), uid))
	}
	w := newWorld(t, targets.String())
	for i := 0; i < n; i++ {
		w.fs.mkdir(fmt.Sprintf("/home/dcuser%d", i))
	}
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	roots := w.roots(procs...)
	if len(roots.Roots) != n {
		t.Fatalf("roots = %d, want %d", len(roots.Roots), n)
	}
	return w, roots
}

// Tetragon's Equal on a numeric argument takes at most 4 values. The pid
// anchor carried every user in scope in one Equal list, so the fifth user
// with a session made Tetragon refuse the whole controls policy
// ("selector does not support more than 4 values", GAP-0049).
func TestControlsLoadWithMoreThanFourUsers(t *testing.T) {
	w, roots := manyUsers(t, 7)
	uids := w.enroll.UIDs()
	monitor := w.compile(Input{Observe: true, Connect: true, Controls: &Scope{Mode: PolicyMonitor, UIDs: uids}, Roots: roots.Roots})
	// Enforce with every user ready: script-hosted sessions are pid-only, so
	// they stay measured by the monitor-only family, which carries all seven.
	enforce := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: uids}, Roots: roots.Roots})
	for name, c := range map[string]Compiled{"monitor": monitor, "enforce": enforce} {
		for _, note := range c.Notes {
			if strings.HasPrefix(note, "kernel_policy_lint") {
				t.Fatalf("%s: lint dropped a selector: %v", name, c.Notes)
			}
		}
		family := FamilyControls
		if name == "enforce" {
			family = FamilyBurnin
		}
		p := policyOf(t, c, family)
		if len(p.UIDs) != 7 || len(p.PIDs) != 7 {
			t.Fatalf("%s: uids %v pids %v, want all seven", name, p.UIDs, p.PIDs)
		}
		pidSelectors := 0
		seenPIDs := map[int]bool{}
		for _, hook := range p.tp.Spec.LsmHooks {
			for _, sel := range hook.Selectors {
				if len(sel.MatchPIDs) == 0 {
					continue
				}
				pidSelectors++
				if len(sel.MatchPIDs[0].Values) > maxPIDsPerSelector {
					t.Fatalf("%s: %d values in one pid selector", name, len(sel.MatchPIDs[0].Values))
				}
				for _, pid := range sel.MatchPIDs[0].Values {
					seenPIDs[pid] = true
				}
				uid := sel.MatchArgs[len(sel.MatchArgs)-1]
				if uid.position() != 2 || uid.Operator != "InMap" || len(uid.Values) != 7 {
					t.Fatalf("%s: pid anchor uid filter = %+v, want InMap of all seven uids", name, uid)
				}
			}
		}
		if pidSelectors != 6 || len(seenPIDs) != 7 {
			t.Fatalf("%s: %d pid selectors covering %d roots, want six selectors covering all seven", name, pidSelectors, len(seenPIDs))
		}
		// No policy of the set carries a numeric list Tetragon would refuse.
		for _, policy := range c.Policies {
			for _, hook := range policy.tp.Spec.LsmHooks {
				for _, sel := range hook.Selectors {
					for _, arg := range sel.MatchArgs {
						if numericArg(hook.Args[arg.position()]) && !mapOperator(arg.Operator) && len(arg.Values) > maxNumericValues {
							t.Errorf("%s %s: args %v %s has %d values", name, policy.Name, arg.Args, arg.Operator, len(arg.Values))
						}
					}
				}
			}
			if v := Lint(policy.YAML, LintOptions{Homes: homeList(map[int]string{
				2001: "/home/dcuser0", 2002: "/home/dcuser1", 2003: "/home/dcuser2", 2004: "/home/dcuser3",
				2005: "/home/dcuser4", 2006: "/home/dcuser5", 2007: "/home/dcuser6",
			}), FS: w.fs}); len(v) != 0 {
				t.Fatalf("%s %s fails lint: %v", name, policy.Name, v)
			}
		}
	}
}
