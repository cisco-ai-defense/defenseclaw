// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

func TestProfileMeetNames(t *testing.T) {
	if got := ProfileMeetName([]string{"watch", "strict", "watch"}); got != "strictest.strict.watch" {
		t.Fatalf("meet name %q", got)
	}
	if got := ProfileMeetName([]string{"strict"}); got != "strict" {
		t.Fatalf("one member: %q; want its own name", got)
	}
	withBase := ProfileMeetName([]string{"", "strict"})
	if withBase != "strictest.-.strict" {
		t.Fatalf("meet with the base configuration: %q", withBase)
	}
	if members, ok := ProfileMeetMembers(withBase); !ok || !slices.Equal(members, []string{"", "strict"}) {
		t.Fatalf("members %q, %v", members, ok)
	}
	// A name this process never made resolves from the name alone (a
	// sandbox registration stored it before a restart).
	if members, ok := ProfileMeetMembers("strictest.contractors.engineering"); !ok || !slices.Equal(members, []string{"contractors", "engineering"}) {
		t.Fatalf("parsed members %q, %v", members, ok)
	}
	for _, bad := range []string{"strict", "strictest.", "strictest.only", "strictest.Bad.x", "strictest.a..b"} {
		if _, ok := ProfileMeetMembers(bad); ok {
			t.Fatalf("%q parsed as a meet", bad)
		}
	}
	long := []string{strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60)}
	name := ProfileMeetName(long)
	if len(name) > profileMeetNameMax || !IsProfileMeet(name) {
		t.Fatalf("long meet name %q", name)
	}
	if members, ok := ProfileMeetMembers(name); !ok || len(members) != 3 {
		t.Fatalf("long meet members %q, %v", members, ok)
	}
}

// The meet's sandbox floor tightens openshell.admin by every member: false
// wins, blocks and requirements are unions, allows intersections. Where no
// sandbox satisfies every member, no sandbox runs and an agent a member
// requires in one does not run on the host either.
func TestProfileMeetSandboxFloor(t *testing.T) {
	off := false
	cfg := &Config{}
	cfg.OpenShell.Admin.RequestAccess = "ask IT"
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{
		"a":       {Sandbox: &OpenShellAdminConfig{RequiredFor: []string{"codex"}, EgressBlock: []string{"a.example"}, AllowedHarnesses: []string{"codex", "claudecode"}, RequestAccess: "ask team a"}},
		"b":       {Sandbox: &OpenShellAdminConfig{EgressBlock: []string{"b.example"}, AllowedHarnesses: []string{"codex"}, AllowYolo: &off}},
		"nobox":   {Sandbox: &OpenShellAdminConfig{Allowed: &off}},
		"pack-1":  {Sandbox: &OpenShellAdminConfig{RequiredPack: "/etc/packs/one"}},
		"pack-2":  {Sandbox: &OpenShellAdminConfig{RequiredPack: "/etc/packs/two"}},
		"no-rule": {},
	}
	floor, _, err := cfg.SandboxFloor(ProfileMeetName([]string{"a", "b", "no-rule"}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(floor.RequiredFor, []string{"codex"}) || !slices.Contains(floor.EgressBlock, "a.example") || !slices.Contains(floor.EgressBlock, "b.example") ||
		!slices.Equal(floor.AllowedHarnesses, []string{"codex"}) || floor.AllowYolo == nil || *floor.AllowYolo || floor.RequestAccess != "ask IT" {
		t.Fatalf("floor %+v; want both members' limits and the organization's contact", floor)
	}
	for _, members := range [][]string{{"a", "nobox"}, {"pack-1", "pack-2"}} {
		floor, _, err := cfg.SandboxFloor(ProfileMeetName(members))
		if err != nil {
			t.Fatalf("%v: %v; a meet is never refused", members, err)
		}
		if floor.Allowed == nil || *floor.Allowed || floor.MinProfile != "strict" {
			t.Fatalf("%v: floor %+v; want no sandbox", members, floor)
		}
	}
	floor, _, _ = cfg.SandboxFloor(ProfileMeetName([]string{"a", "nobox"}))
	if !slices.Contains(floor.RequiredFor, "codex") {
		t.Fatalf("closed floor %+v dropped the agent a member requires in a sandbox", floor)
	}
	if _, _, err := cfg.SandboxFloor(ProfileMeetName([]string{"a", "missing"})); err == nil {
		t.Fatal("a meet of an undefined profile resolved")
	}
}
