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

func TestGoldenZeroEnrolled(t *testing.T) {
	w := newWorld(t, "targets: []\n")
	scope := &Scope{Mode: PolicyMonitor, UIDs: w.enroll.UIDs()}
	c := w.compile(Input{Observe: true, Connect: true, Controls: scope})
	if hasFamily(c, FamilyControls) {
		t.Fatalf("a controls policy with nobody enrolled: %v", c.Notes)
	}
	// Observe covers only the system paths; no home appears.
	observe := policyOf(t, c, FamilyObserve)
	if strings.Contains(string(observe.YAML), "/home/") {
		t.Fatalf("observe names a home with nobody enrolled:\n%s", observe.YAML)
	}
	if !strings.Contains(string(observe.YAML), "/etc/shadow") {
		t.Fatalf("observe lost the system paths:\n%s", observe.YAML)
	}
	golden(t, "zero-enrolled", c)
}

func TestGoldenEnrolledWithoutAgentEmitsNoOverride(t *testing.T) {
	w := newWorld(t, `targets:
- user: carol
  uid: 1003
  user_home: /home/carol
  connector: claudecode
`)
	scope := &Scope{Mode: PolicyEnforce, UIDs: w.enroll.UIDs()}
	c := w.compile(Input{Observe: true, Controls: scope, Roots: w.roots().Roots})
	if hasFamily(c, FamilyControls) {
		t.Fatal("a controls policy for a user with no install and no live root")
	}
	if !containsStr(c.Notes, ReasonNoAnchors) {
		t.Fatalf("notes = %v, want %q", c.Notes, ReasonNoAnchors)
	}
	for _, p := range c.Policies {
		if strings.Contains(string(p.YAML), "Override") {
			t.Fatalf("Override in %s:\n%s", p.Name, p.YAML)
		}
	}
	golden(t, "enrolled-no-agent", c)
}

func TestGoldenTwoUsersMixedInstalls(t *testing.T) {
	w := newWorld(t, baseTargets)
	roots := w.roots(
		nativeProc(4001, 1, 100, 1001, aliceClaudeNew),
		codexProc(4002, 1, 110, 1001),
		codexProc(5001, 1, 120, 1002),
	)
	if len(roots.Roots) != 3 {
		t.Fatalf("roots = %+v", roots.Roots)
	}
	scope := &Scope{Mode: PolicyMonitor, UIDs: w.enroll.UIDs()}
	c := w.compile(Input{Observe: true, Connect: true, Controls: scope, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)

	if fmt.Sprint(p.UIDs) != "[1001 1002]" || fmt.Sprint(p.PIDs) != "[4001 4002 5001]" {
		t.Fatalf("uids %v pids %v", p.UIDs, p.PIDs)
	}
	// Live monitor sessions use disjoint PID selectors. A binary selector
	// beside them could report the same descendant open a second time.
	if len(p.Binaries) != 0 {
		t.Errorf("monitor binaries anchor overlaps live pid anchors: %v", p.Binaries)
	}
	hooks := selectorsOf(t, p)
	if len(hooks) != 2 {
		t.Fatalf("hooks = %d, want the exact-name hook and the directory hook", len(hooks))
	}
	// hook 0: NoPost exemption, ssh and persistence PID selectors.
	if len(hooks[0]) != 3 || len(hooks[1]) != 1 {
		t.Fatalf("selector counts %d/%d, want 3/1", len(hooks[0]), len(hooks[1]))
	}
	if hooks[0][0].MatchActions[0].Action != "NoPost" {
		t.Fatalf("the ssh exemption must come first: %+v", hooks[0][0])
	}
	golden(t, "two-users", c)
}

func TestAutoUpdateKeepsRunningOldVersionAnchored(t *testing.T) {
	w := newWorld(t, baseTargets)
	old := nativeProc(4001, 1, 100, 1001, aliceClaudeOld)
	if roots := w.roots(old); len(roots.Roots) != 1 {
		t.Fatalf("roots = %+v", roots.Roots)
	}
	// The auto-update removes the old file from the versions directory and
	// moves the launcher; the running session is still a root.
	delete(w.fs.nodes, aliceClaudeOld)
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	roots := w.roots(old, nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	scope := &Scope{Mode: PolicyEnforce, UIDs: []int{1001}}
	c := w.compile(Input{Controls: scope, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	if !hasBinary(p, aliceClaudeOld) || !hasBinary(p, aliceClaudeNew) {
		t.Fatalf("binaries = %v, want old and new", p.Binaries)
	}
	if len(p.PIDs) != 0 {
		t.Fatalf("enforcing policy has reusable pid anchors: %v", p.PIDs)
	}
	golden(t, "auto-update", c)

	// Once the old session exits it is no longer anchored.
	roots = w.roots(nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	c = w.compile(Input{Controls: scope, Roots: roots.Roots})
	p = policyOf(t, c, FamilyControls)
	if hasBinary(p, aliceClaudeOld) || len(p.PIDs) != 0 {
		t.Fatalf("binaries %v pids %v after the old session exited", p.Binaries, p.PIDs)
	}
}

func TestSixtyFiveRootsAnchorSixtyFour(t *testing.T) {
	w := newWorld(t, baseTargets)
	var procs []Proc
	for i := 0; i < 65; i++ {
		procs = append(procs, codexProc(7000+i, 1, uint64(1000+i), 1001))
	}
	roots := w.roots(procs...)
	if len(roots.Roots) != 65 {
		t.Fatalf("roots = %d", len(roots.Roots))
	}
	c := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1001}}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	if len(p.PIDs) != MaxPIDs || c.OverLimit != 1 {
		t.Fatalf("anchored %d, over limit %d", len(p.PIDs), c.OverLimit)
	}
	if p.PIDs[len(p.PIDs)-1] != 7063 {
		t.Fatalf("the oldest sessions must win the budget; last pid = %d", p.PIDs[len(p.PIDs)-1])
	}
	if !anyContains(c.Notes, WarnRootsOverLimit) {
		t.Fatalf("notes = %v", c.Notes)
	}
	// Tetragon evaluates only four values in a matchPIDs selector. Every
	// anchored root must appear in a selector it will actually evaluate.
	seen := map[int]int{}
	for _, hook := range selectorsOf(t, p) {
		for _, sel := range hook {
			for _, pids := range sel.MatchPIDs {
				if len(pids.Values) > 4 {
					t.Fatalf("%d pids in one selector", len(pids.Values))
				}
				for _, pid := range pids.Values {
					seen[pid]++
				}
			}
		}
	}
	if seen[7004] == 0 || seen[7063] == 0 {
		t.Fatalf("later roots are absent from effective pid selectors: %v", seen)
	}
	if hooks := len(p.tp.Spec.LsmHooks); hooks > 12 {
		t.Fatalf("%d LSM hook instances for 64 roots, want at most 12", hooks)
	}
}

func TestBurnInUserNextToReadyUser(t *testing.T) {
	w := newWorld(t, baseTargets)
	roots := w.roots(
		nativeProc(4001, 1, 100, 1001, aliceClaudeNew),
		codexProc(5001, 1, 120, 1002),
	)
	connectors := map[string]bool{"claudecode": true, "codex": true}
	c := w.compile(Input{
		Observe:  true,
		Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001}, Connectors: connectors},
		Burnin:   &Scope{Mode: PolicyMonitor, UIDs: []int{1002}, Connectors: connectors},
		Roots:    roots.Roots,
	})
	controls, burnin := policyOf(t, c, FamilyControls), policyOf(t, c, FamilyBurnin)
	if fmt.Sprint(controls.UIDs) != "[1001]" || fmt.Sprint(burnin.UIDs) != "[1002]" {
		t.Fatalf("controls %v burnin %v", controls.UIDs, burnin.UIDs)
	}
	if controls.Mode != PolicyEnforce || burnin.Mode != PolicyMonitor {
		t.Fatalf("modes %s/%s", controls.Mode, burnin.Mode)
	}
	if !strings.Contains(string(controls.YAML), "value: enforce") || !strings.Contains(string(burnin.YAML), "value: monitor") {
		t.Fatal("the mode must travel in the YAML, so a policy is never loaded enforcing and flipped")
	}
	// The users' anchors never mix.
	if hasBinary(burnin, aliceClaudeNew) || fmt.Sprint(burnin.PIDs) != "[5001]" || len(controls.PIDs) != 0 {
		t.Fatalf("anchors leaked: burnin %v %v controls %v %v", burnin.Binaries, burnin.PIDs, controls.Binaries, controls.PIDs)
	}
	if controls.Name == burnin.Name {
		t.Fatal("two policies with one name")
	}
	golden(t, "burnin-split", c)
}

func TestHeuristicAndIDERootsNeverAnchor(t *testing.T) {
	w := newWorld(t, baseTargets)
	heuristic := Proc{PID: 8001, PPID: 1, StartTicks: 200, UID: 1001, EUID: 1001, Host: true, Exe: "/usr/bin/tmux",
		Cmdline: []string{"tmux", "new", "-s", "langchain"}, Comm: "tmux"}
	framework := Proc{PID: 8002, PPID: 8001, StartTicks: 210, UID: 1001, EUID: 1001, Host: true, Exe: "/usr/bin/python3",
		Cmdline: []string{"python3", "-m", "langchain_app"}, Comm: "python3"}
	ide := Proc{PID: 8003, PPID: 1, StartTicks: 220, UID: 1001, EUID: 1001, Host: true,
		Exe: "/home/alice/.cursor/cursor", Cmdline: []string{"/home/alice/.cursor/cursor"}, Comm: "cursor"}
	stranger := Proc{PID: 8004, PPID: 1, StartTicks: 230, UID: 1999, EUID: 1999, Host: true, Exe: "/usr/local/bin/claude",
		Cmdline: []string{"claude"}, Comm: "claude"}
	containerized := nativeProc(8005, 1, 240, 1001, aliceClaudeNew)
	containerized.Host = false
	roots := w.roots(heuristic, framework, ide, stranger, containerized)
	if len(roots.Roots) != 0 {
		t.Fatalf("roots = %+v; none of these is an enrolled agent", roots.Roots)
	}
	reasons := map[string]bool{}
	for _, o := range roots.Observed {
		reasons[o.Reason] = true
	}
	for _, want := range []string{ReasonHeuristicRoot, ReasonIDEHosted, ReasonNotEnrolled} {
		if !reasons[want] {
			t.Errorf("observed-only lacks %q: %+v", want, roots.Observed)
		}
	}
	c := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1001}}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	if len(p.PIDs) != 0 {
		t.Fatalf("pid anchor = %v; only enrolled installs may anchor", p.PIDs)
	}
	for _, sel := range selectorsOf(t, p)[0] {
		if len(sel.MatchPIDs) > 0 {
			t.Fatal("a pid selector without an enrolled live root")
		}
	}
}

func TestRootUnderRootIsNotSpent(t *testing.T) {
	w := newWorld(t, baseTargets)
	parent := nativeProc(4001, 1, 100, 1001, aliceClaudeNew)
	child := nativeProc(4002, 4001, 110, 1001, aliceClaudeNew) // Claude running itself as a helper
	roots := w.roots(parent, child)
	if len(roots.Roots) != 1 || roots.Roots[0].PID != 4001 {
		t.Fatalf("roots = %+v; a descendant of a root is covered by followForks", roots.Roots)
	}
}

func TestPathsResolveLikeTheKernelReportsThem(t *testing.T) {
	w := newWorld(t, `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: claudecode
`)
	// A dotfile manager: .bashrc is a link into the home, .zshrc a link out of it,
	// .config is a link into the home and .ssh/id_rsa does not exist yet.
	w.fs.file("/home/alice/dotfiles/bashrc", 0o644)
	w.fs.symlink("/home/alice/.bashrc", "dotfiles/bashrc")
	w.fs.file("/etc/shared-zshrc", 0o644)
	w.fs.symlink("/home/alice/.zshrc", "/etc/shared-zshrc")
	w.fs.mkdir("/home/alice/dotfiles/config")
	w.fs.symlink("/home/alice/.config", "dotfiles/config")
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew))
	c := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1001}}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	text := string(p.YAML)
	for _, want := range []string{
		"/home/alice/dotfiles/bashrc",               // the link's target is what the kernel reports
		"/home/alice/dotfiles/config/systemd/user/", // a missing name below a linked parent
		"/home/alice/.ssh/id_rsa",                   // a key that does not exist yet is still named
	} {
		if !strings.Contains(text, want) {
			t.Errorf("policy lacks %s:\n%s", want, text)
		}
	}
	for _, bad := range []string{"/home/alice/.bashrc\n", "/etc/shared-zshrc", "/home/alice/.zshrc"} {
		if strings.Contains(text, bad) {
			t.Errorf("policy names %q, which resolves outside the home or is a second name", bad)
		}
	}
	if !anyContains(c.Notes, "path_outside_home:/home/alice/.zshrc") {
		t.Fatalf("notes = %v", c.Notes)
	}
}

func TestSSHExemptionNeedsTheBinariesToExist(t *testing.T) {
	w := newWorld(t, baseTargets)
	delete(w.fs.nodes, "/usr/bin/ssh-add")
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew))
	c := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1001}}, Roots: roots.Roots})
	first := selectorsOf(t, policyOf(t, c, FamilyControls))[0][0]
	if got := fmt.Sprint(first.MatchBinaries[0].Values); got != "[/usr/bin/ssh /usr/bin/ssh-keygen]" {
		t.Fatalf("exempt binaries = %s", got)
	}
	if first.MatchBinaries[0].FollowChildren {
		t.Fatal("the exemption must not follow children")
	}
}

func TestEnforceScopeGetsASeparateNameFromPIDMonitorScope(t *testing.T) {
	w := newWorld(t, baseTargets)
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew))
	build := func(mode PolicyMode, extra ...Root) Policy {
		c := w.compile(Input{Controls: &Scope{Mode: mode, UIDs: []int{1001}}, Roots: append(append([]Root{}, roots.Roots...), extra...)})
		return policyOf(t, c, FamilyControls)
	}
	monitor, enforce := build(PolicyMonitor), build(PolicyEnforce)
	if monitor.Name == enforce.Name {
		t.Fatal("a PID monitor policy must not be promoted in place to enforcement")
	}
	more := build(PolicyMonitor, Root{UID: 1001, PID: 4999, StartTicks: 999, Connector: "codex"})
	if more.Name == monitor.Name {
		t.Fatal("a new monitored pid anchor must change the name")
	}
	moreEnforce := build(PolicyEnforce, Root{UID: 1001, PID: 4999, StartTicks: 999, Connector: "codex"})
	if moreEnforce.Name != enforce.Name {
		t.Fatal("a script pid must not change an enforcing policy")
	}
	if !IsDefenseClawName(monitor.Name) || !IsDefenseClawName(enforce.Name) {
		t.Fatalf("names %q %q", monitor.Name, enforce.Name)
	}
	if _, err := monitor.withMode(PolicyEnforce); err == nil {
		t.Fatal("a monitor policy with PID selectors must not be promoted in place")
	}
	back, err := enforce.withMode(PolicyMonitor)
	if err != nil || back.Name != enforce.Name {
		t.Fatalf("safe demotion failed: %v", err)
	}
}

// A user controls the links in their own home. None of them may change what
// the other users of the policy are protected from or scoped to.
func TestHostileLinksDropOnlyTheirOwnPath(t *testing.T) {
	w := newWorld(t, baseTargets)
	w.fs.file("/home/alice/.aws/credentials", 0o600)
	w.fs.symlink("/home/alice/.ssh/id_rsa", "../.aws/credentials") // points a key name at a provider credential
	long := "/home/alice/" + strings.Repeat("d/", 300) + "target"
	w.fs.file(long, 0o600)
	w.fs.symlink("/home/alice/.ssh/id_ecdsa", long) // a value Tetragon would refuse to load
	w.fs.file("/home/alice/bad\nname", 0o600)
	w.fs.symlink("/home/alice/.ssh/id_dsa", "/home/alice/bad\nname")
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002))
	c := w.compile(Input{Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{1001, 1002}}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	text := string(p.YAML)
	for _, want := range []string{"/home/alice/.ssh/id_ed25519", "/home/bob/.ssh/id_rsa", "/home/bob/.ssh/id_ecdsa", "/home/bob/.ssh/id_dsa", "/home/alice/.bashrc"} {
		if !strings.Contains(text, want) {
			t.Errorf("one user's links removed %s for everyone", want)
		}
	}
	for _, bad := range []string{"/home/alice/.aws", "d/d/d/d", "bad"} {
		if strings.Contains(text, bad) {
			t.Errorf("policy names %q", bad)
		}
	}
	for _, note := range c.Notes {
		if strings.HasPrefix(note, "kernel_policy_lint") {
			t.Fatalf("a lint finding dropped a selector shared by every user: %v", c.Notes)
		}
	}
	if n := 0; true {
		for _, note := range c.Notes {
			if strings.HasPrefix(note, "path_not_usable:") {
				n++
			}
		}
		if n != 3 {
			t.Fatalf("notes = %v, want the three hostile links reported", c.Notes)
		}
	}
	if got := len(selectorsOf(t, p)[0]); got != 3 {
		t.Fatalf("%d selectors in hook 0, want exemption and both PID controls", got)
	}
}

func TestALinkOutOfTheHomeCannotNameASystemProgramAsAnAnchor(t *testing.T) {
	w := newWorld(t, baseTargets)
	w.fs.elf("/usr/bin/bash")
	// Alice points her launcher at a root-owned, perfectly trusted shell.
	delete(w.fs.nodes, "/home/alice/.local/bin/claude")
	w.fs.symlink("/home/alice/.local/bin/claude", "/usr/bin/bash")
	installs := ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	for _, in := range installs {
		for _, native := range in.Native {
			if native == "/usr/bin/bash" {
				t.Fatalf("%+v: the shared binaries anchor would have put every enrolled user's shell in scope", in)
			}
		}
	}
	w.installs = installs
	c := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001, 1002}}, Roots: w.roots().Roots})
	for _, p := range c.Policies {
		if strings.Contains(string(p.YAML), "/usr/bin/bash") {
			t.Fatalf("a system shell is an anchor:\n%s", p.YAML)
		}
	}
}
