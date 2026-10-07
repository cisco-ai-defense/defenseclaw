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
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// Proc is one live process as the helper's /proc scan saw it.
type Proc struct {
	PID        int
	PPID       int
	StartTicks uint64 // /proc/<pid>/stat field 22; with PID it survives pid reuse
	UID        int
	EUID       int
	Exe        string // /proc/<pid>/exe, " (deleted)" removed
	Cwd        string
	Cmdline    []string
	Comm       string
	// Host is true for a process in the helper's own pid namespace. A
	// container's process can share a home path and even a binary name with
	// a host one; it never joins a host anchor.
	Host bool
}

// ProcSource lists the live processes. The second argument of the production
// scan is the enrolled-uid test, so processes of other users are read only as
// far as their names.
type ProcSource func() ([]Proc, error)

// Root is a live process that is an enrolled agent: its uid is enrolled for
// the connector, it runs in the host pid namespace, and it either is the
// install's ELF or runs the install's entry script.
type Root struct {
	UID        int
	PID        int
	StartTicks uint64
	Connector  string
	Exe        string
	// Native roots contribute their exe path to the binaries anchor;
	// script-hosted roots never do (that path is a shared interpreter).
	Native bool
}

// Observed counts processes that look like agents but are never anchored,
// with the reason. They are reported, never silently dropped.
type Observed struct {
	UID       int    `json:"uid"`
	Reason    string `json:"reason"`
	Identity  string `json:"identity,omitempty"`
	Connector string `json:"connector,omitempty"`
	Count     int    `json:"count"`
}

// RootSet is the result of one scan.
type RootSet struct {
	Roots    []Root
	Observed []Observed
}

type rootKey struct {
	pid   int
	ticks uint64
}

// Tracker remembers roots across scans, so a root stays a root until it
// exits even when its install has since been replaced (an auto-update moves
// the symlink, not the running binary).
type Tracker struct {
	known map[rootKey]Root
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker { return &Tracker{known: map[rootKey]Root{}} }

// interpreterNames are the programs whose first script argument identifies
// what they run. Any other program that merely names an agent's entry file
// (an editor, grep) is not a root.
func isInterpreter(exe string) bool {
	name := strings.ToLower(tactics.BaseName(exe))
	switch name {
	case "node", "nodejs", "bun", "deno", "ruby", "perl", "sh", "bash", "dash", "zsh", "ksh", "uv":
		return true
	}
	return strings.HasPrefix(name, "python")
}

// scriptArg returns the resolved file an interpreter process was asked to
// run: its first non-flag argument, when that is a path.
func scriptArg(fsys FS, p Proc) string {
	if len(p.Cmdline) < 2 || !isInterpreter(p.Exe) {
		return ""
	}
	for _, arg := range p.Cmdline[1:] {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		if !strings.Contains(arg, "/") {
			return ""
		}
		if !filepath.IsAbs(arg) {
			if p.Cwd == "" {
				return ""
			}
			arg = filepath.Join(p.Cwd, arg)
		}
		resolved, err := fsys.EvalSymlinks(arg)
		if err != nil {
			return ""
		}
		return resolved
	}
	return ""
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

var ideIdentities = map[string]bool{
	"cursor": true, "copilot-language-server": true, "code": true, "antigravity": true, "kiro": true,
}

// Update classifies the scan. installs must be the current resolution for the
// enrollment; procs the current process table.
func (t *Tracker) Update(fsys FS, procs []Proc, installs []Install, enrollment Enrollment) RootSet {
	byUID := map[int][]Install{}
	for _, install := range installs {
		byUID[install.UID] = append(byUID[install.UID], install)
	}
	live := map[rootKey]Proc{}
	byPID := map[int]Proc{}
	for _, p := range procs {
		live[rootKey{p.PID, p.StartTicks}] = p
		byPID[p.PID] = p
	}
	// Forget roots that exited (or whose pid was reused).
	for key := range t.known {
		if _, ok := live[key]; !ok {
			delete(t.known, key)
		}
	}
	for _, p := range procs {
		key := rootKey{p.PID, p.StartTicks}
		if _, ok := t.known[key]; ok || !p.Host || p.UID != p.EUID || !enrollment.Has(p.UID) {
			continue
		}
		for _, install := range byUID[p.UID] {
			native := p.Exe != "" && contains(install.Native, p.Exe)
			if !native {
				entry := scriptArg(fsys, p)
				if entry == "" || !contains(install.Entries, entry) {
					continue
				}
			}
			t.known[key] = Root{UID: p.UID, PID: p.PID, StartTicks: p.StartTicks,
				Connector: install.Connector, Exe: p.Exe, Native: native}
			break
		}
	}
	// A root under another root of the same user is covered by the ancestor's
	// followForks; anchoring it too only spends the pid budget.
	isRoot := func(pid int) bool {
		p, ok := byPID[pid]
		if !ok {
			return false
		}
		_, ok = t.known[rootKey{p.PID, p.StartTicks}]
		return ok
	}
	hasRootAncestor := func(p Proc) bool {
		seen := 0
		for parent := p.PPID; parent > 1 && seen < 64; seen++ {
			if isRoot(parent) {
				return true
			}
			next, ok := byPID[parent]
			if !ok {
				return false
			}
			parent = next.PPID
		}
		return false
	}
	var set RootSet
	for key, root := range t.known {
		if hasRootAncestor(live[key]) {
			continue
		}
		set.Roots = append(set.Roots, root)
	}
	sort.Slice(set.Roots, func(i, j int) bool {
		a, b := set.Roots[i], set.Roots[j]
		if a.StartTicks != b.StartTicks {
			return a.StartTicks < b.StartTicks
		}
		return a.PID < b.PID
	})
	set.Observed = observedOnly(procs, byPID, enrollment, isRoot, hasRootAncestor)
	return set
}

// observedOnly reports agent-looking processes that are not anchored: users
// that are not enrolled, IDE-hosted surfaces and heuristic matches. Nothing
// here ever reaches an anchor.
func observedOnly(procs []Proc, byPID map[int]Proc, enrollment Enrollment,
	isRoot func(int) bool, hasRootAncestor func(Proc) bool) []Observed {
	type key struct {
		uid              int
		reason, identity string
	}
	counts := map[key]int{}
	for _, p := range procs {
		if !p.Host || isRoot(p.PID) || hasRootAncestor(p) {
			continue
		}
		if !enrollment.Has(p.UID) {
			if tactics.IsAgentProcess(p.Comm) {
				counts[key{p.UID, ReasonNotEnrolled, strings.ToLower(tactics.BaseName(p.Comm))}]++
			}
			continue
		}
		identity := tactics.AgentIdentity(p.Exe, strings.Join(p.Cmdline, " "))
		if identity == "" {
			continue
		}
		reason := ReasonHeuristicRoot
		if ideIdentities[identity] {
			reason = ReasonIDEHosted
		}
		counts[key{p.UID, reason, identity}]++
	}
	out := make([]Observed, 0, len(counts))
	for k, n := range counts {
		out = append(out, Observed{UID: k.uid, Reason: k.reason, Identity: k.identity, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Identity < b.Identity
	})
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}
