// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

type ownHookLookup struct{ refs []ProcessRef }

func (l ownHookLookup) Lineage(string, int) []ProcessRef                 { return l.refs }
func (l ownHookLookup) LineageAt(string, string, time.Time) []ProcessRef { return l.refs }

// GAP-0404: a curl the blocklist refused was too short for the process
// tree, so the only curl seen around it was DefenseClaw's own hook's, and
// sandbox destinations named it `curl <- claude-code-hoo <- ... <- claude`.
// A lineage inferred for a connection (paired with a proxy open, or looked
// up by program and time) that runs through one of DefenseClaw's hook
// scripts is not the agent's: the row keeps only the binary. The agent's
// own lineage stays.
func TestAShortConnectionIsNotNamedAfterDefenseClawsOwnHook(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	hook := []sandboxapi.DestinationProcess{
		{PID: 90, PPID: 89, Exe: "/usr/bin/curl", Comm: "curl"},
		{PID: 89, PPID: 88, Exe: "/usr/bin/bash", Comm: "claude-code-hoo"},
		{PID: 88, PPID: 50, Exe: "/usr/bin/bash", Comm: "claude-code-hoo"},
		{PID: 50, PPID: 1, Exe: "/usr/local/bin/claude", Comm: "claude"},
	}
	agent := []sandboxapi.DestinationProcess{
		{PID: 91, PPID: 60, Exe: "/usr/bin/curl", Comm: "curl"},
		{PID: 60, PPID: 50, Exe: "/usr/bin/sh", Comm: "sh"},
		{PID: 50, PPID: 1, Exe: "/usr/local/bin/claude", Comm: "claude"},
	}
	paired := func(lineage []sandboxapi.DestinationProcess) *destRow {
		r := &destRow{Host: "pastebin.com", proxyAt: []proxyRequest{{at: at, denied: true}}}
		if !r.attributeProxied([]proxyOpen{{binary: "/usr/bin/curl", pid: lineage[0].PID, at: at, lineage: lineage}}, at.Add(time.Minute)) {
			t.Fatal("the refused request was not paired")
		}
		return r
	}
	if r := paired(hook); !slices.Equal(r.Binaries, []string{"/usr/bin/curl"}) || r.Lineage != nil {
		t.Fatalf("paired with the hook's curl: binaries %v, lineage %+v; want curl only", r.Binaries, r.Lineage)
	}
	if r := paired(agent); !slices.Equal(r.Lineage, agent) {
		t.Fatalf("paired with the agent's curl: lineage %+v, want the agent's", r.Lineage)
	}

	refs := func(lineage []sandboxapi.DestinationProcess) []ProcessRef {
		var out []ProcessRef
		for _, p := range lineage {
			out = append(out, ProcessRef{PID: p.PID, PPID: p.PPID, Exe: p.Exe, Comm: p.Comm})
		}
		return out
	}
	m := &Manager{procs: ownHookLookup{refs(hook)}}
	if l := m.actorLineage("box", "/usr/bin/curl", 0, at); l != nil {
		t.Fatalf("pid-less lookup through the hook: %+v, want none", l)
	}
	m = &Manager{procs: ownHookLookup{refs(agent)}}
	if l := m.actorLineage("box", "/usr/bin/curl", 0, at); len(l) != len(agent) {
		t.Fatalf("pid-less lookup of the agent's curl: %+v", l)
	}

	for _, p := range []sandboxapi.DestinationProcess{
		{Exe: "/sandbox/.defenseclaw/hooks/claude-code-hook.sh"}, {Comm: "inspect-tool.sh"}, {Comm: "inspect-tool-re"}, {Comm: "codex-hook.sh"},
	} {
		if !ownHookLineage([]sandboxapi.DestinationProcess{p}) {
			t.Errorf("%+v is DefenseClaw's hook", p)
		}
	}
	for _, p := range []sandboxapi.DestinationProcess{{Comm: "claude"}, {Comm: "my-hook.sh"}, {Exe: "/usr/bin/bash", Comm: "bash"}} {
		if ownHookLineage([]sandboxapi.DestinationProcess{p}) {
			t.Errorf("%+v is not DefenseClaw's hook", p)
		}
	}
}
