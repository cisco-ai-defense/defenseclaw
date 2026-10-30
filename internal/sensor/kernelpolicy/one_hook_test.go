// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package kernelpolicy

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-0218: Tetragon 1.7.0 pins the maps of every lsmhooks entry under the
// hook name, so a second file_open entry in one policy overwrites the first
// entry's selectors and only the last entry ever matches
// (cilium/tetragon#4578). The controls policy rendered its SSH key and shell
// profile selectors in a first file_open entry and the autostart directories
// in a second one: the anchored agent's key read matched nothing, with no
// event and no deny, and the observe policy posted only its directory
// selectors. Every policy must carry at most one entry per hook.
func TestEveryCompiledPolicyHasOneEntryPerLSMHook(t *testing.T) {
	w := newWorld(t, baseTargets)
	live := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002))
	var crowd []Proc
	for i := 0; i < 12; i++ {
		crowd = append(crowd, codexProc(7000+i, 1, uint64(1000+i), 1001))
	}
	crowded := newWorld(t, baseTargets)
	crowdRoots := crowded.roots(crowd...)
	many, manyRoots := manyUsers(t, 7)
	both := []int{1001, 1002}
	cases := []struct {
		name string
		w    *world
		in   Input
	}{
		{"observe and connect", w, Input{Observe: true, Connect: true}},
		{"monitor with live roots", w, Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: both}, Roots: live.Roots}},
		{"monitor on binaries", w, Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: both}}},
		{"enforce with burn-in", w, Input{Observe: true, Controls: &Scope{Mode: PolicyEnforce, UIDs: both}, Roots: live.Roots}},
		{"monitor over the pid budget", crowded, Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: both}, Roots: crowdRoots.Roots}},
		{"seven users", many, Input{Observe: true, Controls: &Scope{Mode: PolicyMonitor, UIDs: many.enroll.UIDs()}, Roots: manyRoots.Roots}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.w.compile(tc.in)
			if len(c.Policies) == 0 {
				t.Fatalf("no policy compiled (notes %v)", c.Notes)
			}
			for _, note := range c.Notes {
				if strings.HasPrefix(note, "kernel_policy_lint") {
					t.Fatalf("lint dropped a selector: %v", c.Notes)
				}
			}
			for _, p := range c.Policies {
				seen := map[string]int{}
				for _, hook := range p.tp.Spec.LsmHooks {
					seen[hook.Hook]++
					if len(hook.Selectors) > MaxSelectors {
						t.Fatalf("%s: %d selectors in %s", p.Name, len(hook.Selectors), hook.Hook)
					}
				}
				for name, n := range seen {
					if n != 1 {
						t.Fatalf("%s: %d %s entries; Tetragon 1.7.0 runs only the last one:\n%s", p.Name, n, name, p.YAML)
					}
				}
				if got := strings.Count(string(p.YAML), "- hook: file_open"); got > 1 {
					t.Fatalf("%s renders %d file_open entries:\n%s", p.Name, got, p.YAML)
				}
			}
		})
	}
}

// The enforcing controls of the AD user of GAP-0218, pinned selector by
// selector: one file_open entry whose first selector exempts ssh, whose
// second denies the user's SSH private keys below the trusted launch path
// and the resolved ELF, and whose third and fourth deny writes to the shell
// profiles and the autostart directories.
func TestEnforcingControlsDenyTheKeyReadInTheirOnlyHook(t *testing.T) {
	const (
		uid   = 94404135
		home  = "/home/engineer@example.test"
		alias = "/opt/agents/bin/claude"
		exe   = "/opt/agents/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
	)
	w := newWorld(t, `targets:
- user: engineer@example.test
  uid: 94404135
  user_home: /home/engineer@example.test
  connector: claudecode
`)
	w.fs.mkdir(home)
	w.fs.elf(exe)
	w.fs.symlink(alias, "../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	c := w.compile(Input{Observe: true, Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{uid}}})
	golden(t, "enforce-launch-alias", c)

	p := policyOf(t, c, FamilyControls)
	// One file_open entry, then one entry each of path_link and
	// path_rename (the authorized keys names).
	if hookCount(p, "file_open") != 1 || hookCount(p, "path_link") != 1 || hookCount(p, "path_rename") != 1 || hookCount(p, "path_symlink") != 1 || len(p.tp.Spec.LsmHooks) != 4 {
		t.Fatalf("%d hook entries, want one per hook name:\n%s", len(p.tp.Spec.LsmHooks), p.YAML)
	}
	hook := p.tp.Spec.LsmHooks[0]
	if hook.Hook != "file_open" || len(hook.Args) != 3 || hook.Args[2].Resolve != "f_cred.uid.val" {
		t.Fatalf("hook = %s args %+v", hook.Hook, hook.Args)
	}
	sel := hook.Selectors
	if len(sel) != 4 {
		t.Fatalf("%d selectors, want exemption, key, profiles, autostart:\n%s", len(sel), p.YAML)
	}
	if sel[0].MatchActions[0].Action != "NoPost" || len(sel[0].MatchBinaries) != 1 || sel[0].MatchBinaries[0].FollowChildren {
		t.Fatalf("selector 0 = %+v, want the ssh exemption first", sel[0])
	}
	keys := []string{home + "/.ssh/id_dsa", home + "/.ssh/id_ecdsa", home + "/.ssh/id_ed25519", home + "/.ssh/id_rsa"}
	want := []struct {
		operator string
		paths    []string
		mask     bool
	}{
		{"Equal", keys, false},
		{"Equal", []string{home + "/.bash_profile", home + "/.bashrc", home + "/.profile", home + "/.ssh/authorized_keys", home + "/.ssh/authorized_keys2", home + "/.zshrc"}, true},
		{"Prefix", []string{home + "/.config/autostart/", home + "/.config/systemd/user/"}, true},
	}
	for i, wantSel := range want {
		s := sel[i+1]
		if len(s.MatchBinaries) != 1 || !s.MatchBinaries[0].FollowChildren || s.MatchBinaries[0].Operator != "In" ||
			fmt.Sprint(s.MatchBinaries[0].Values) != fmt.Sprint([]string{alias, exe}) {
			t.Fatalf("selector %d binaries = %+v, want the launch path and the ELF with followChildren", i+1, s.MatchBinaries)
		}
		if len(s.MatchPIDs) != 0 {
			t.Fatalf("selector %d has a reusable pid anchor", i+1)
		}
		if len(s.MatchNamespaces) != 1 || s.MatchNamespaces[0].Values[0] != hostNamespace {
			t.Fatalf("selector %d namespaces = %+v", i+1, s.MatchNamespaces)
		}
		args := s.MatchArgs
		if args[0].position() != 0 || args[0].Operator != wantSel.operator || fmt.Sprint(args[0].Values) != fmt.Sprint(wantSel.paths) {
			t.Fatalf("selector %d path = %+v, want %s %v", i+1, args[0], wantSel.operator, wantSel.paths)
		}
		next := 1
		if wantSel.mask {
			if args[1].position() != 1 || args[1].Operator != "Mask" || fmt.Sprint(args[1].Values) != "[2]" {
				t.Fatalf("selector %d mode = %+v, want the write mask", i+1, args[1])
			}
			next = 2
		}
		if len(args) != next+1 || args[next].position() != 2 || args[next].Operator != "Equal" ||
			fmt.Sprint(args[next].Values) != "[94404135]" {
			t.Fatalf("selector %d uid = %+v, want Equal 94404135", i+1, args[next:])
		}
		if len(s.MatchActions) != 2 || s.MatchActions[0].Action != "Override" || *s.MatchActions[0].ArgError != eperm ||
			s.MatchActions[1].Action != "Post" {
			t.Fatalf("selector %d actions = %+v", i+1, s.MatchActions)
		}
	}

	// The observe policy posts the same key read: also one entry.
	observe := policyOf(t, c, FamilyObserve)
	if len(observe.tp.Spec.LsmHooks) != 1 {
		t.Fatalf("observe has %d hook entries:\n%s", len(observe.tp.Spec.LsmHooks), observe.YAML)
	}
	found := false
	for _, s := range observe.tp.Spec.LsmHooks[0].Selectors {
		if s.MatchArgs[0].Operator == "Equal" && len(s.MatchArgs) == 1 && containsStr(s.MatchArgs[0].Values, home+"/.ssh/id_rsa") {
			found = true
		}
	}
	if !found {
		t.Fatalf("observe does not post a read of the key:\n%s", observe.YAML)
	}
}
