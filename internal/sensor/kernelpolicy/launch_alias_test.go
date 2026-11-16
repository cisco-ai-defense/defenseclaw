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
	"strings"
	"testing"
	"time"
)

func TestTrustedNativeLaunchAliasCoversLargeUID(t *testing.T) {
	const (
		uid   = 94404135
		home  = "/home/engineer@example.test"
		alias = "/opt/agents/bin/claude"
		exe   = "/opt/agents/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
	)
	h := newHarness(t, enforceIntent(Digest()), `targets:
- user: engineer@example.test
  uid: 94404135
  user_home: /home/engineer@example.test
  connector: claudecode
`)
	h.w.fs.mkdir(home)
	h.w.fs.elf(exe)
	h.w.fs.symlink(alias, "../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
	h.w.installs = ResolveInstalls(h.w.fs, h.w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	h.pass()
	h.burnedIn(uid, 24*time.Hour)
	h.pass()

	// The policy must match both names: kernels can use either the exec name
	// or the resolved executable for matchBinaries.
	p := policyOf(t, h.w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{uid}}}), FamilyControls)
	if !hasBinary(p, alias) || !hasBinary(p, exe) || p.BinaryUID != uid || len(p.PIDs) != 0 {
		t.Fatalf("controls anchor: uid=%d binaries=%v pids=%v", p.BinaryUID, p.Binaries, p.PIDs)
	}
	if !strings.Contains(string(p.YAML), home+"/.ssh/id_rsa") ||
		!strings.Contains(string(p.YAML), "\"94404135\"") {
		t.Fatalf("controls lost the scoped path or uid: %s", p.YAML)
	}
	selectors := selectorsOf(t, p)
	if selectors[0][0].MatchActions[0].Action != "NoPost" {
		t.Fatal("SSH exemption must precede refusal")
	}

	root := nativeProc(4001, 1, 300, uid, exe)
	root.Launch = alias
	root.Cmdline[0] = "different-argv0"
	h.procs = []Proc{root}
	h.pass()
	if state := userState(h, uid); state.State != UIDEnforcing || state.AnchoredRoots != 1 {
		t.Fatalf("trusted alias session = %+v, want one enforcing session", state)
	}
	if got := h.status().Roots.Anchored; got != 1 {
		t.Fatalf("roots.anchored = %d, want 1", got)
	}

	// A process using a name absent from the loaded selector cannot make
	// status claim that the policy covers its session.
	root.PID = 4002
	root.Launch = "/tmp/other-claude"
	h.procs = []Proc{root}
	h.pass()
	if state := userState(h, uid); state.State != UIDArmed || state.AnchoredRoots != 0 {
		t.Fatalf("uncovered session = %+v, want armed with no anchor", state)
	}
}

// A root keeps the exec name the kernel recorded even when it is not a
// trusted launch path, and an exec under another name in the same process
// replaces the root, so its Launch never outlives the name it was proven for.
func TestTrackerFollowsTheExecNameOfANativeRoot(t *testing.T) {
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

	p := nativeProc(4001, 1, 300, uid, exe)
	p.Launch = "/tmp/other-claude"
	for pass := 0; pass < 2; pass++ {
		set := w.roots(p)
		if len(set.Roots) != 1 || set.Roots[0].Launch != "" || set.Roots[0].execName != p.Launch {
			t.Fatalf("pass %d: untrusted exec name root = %+v", pass, set.Roots)
		}
	}
	p.Launch = alias
	if set := w.roots(p); len(set.Roots) != 1 || set.Roots[0].Launch != alias {
		t.Fatalf("re-exec under the trusted name = %+v", set.Roots)
	}
}
