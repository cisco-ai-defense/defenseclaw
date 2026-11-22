// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// This must be maybe when cp's parser knows the destination spelling but
// cannot decide whether the existing destination is a directory.
func TestDET111UnresolvedEffectTargetCannotBeKnownProtectedMatch(t *testing.T) {
	const home = "/home/alice"
	opts := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: home + "/project"}
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell,
		Command: "cp project/notes.txt ~/.claude/settings.json"}, opts)
	facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX,
		Resolve: func(p string) (string, bool) { return p, true }})
	found := false
	for _, fact := range facts {
		if fact.GetKind() != string(effects.KindWrite) || fact.GetTargetState() == string(effects.TargetStateKnown) {
			continue
		}
		for _, match := range fact.GetTarget().GetProtected() {
			if match.GetSet() != SetAgentHookConfig {
				continue
			}
			found = true
			if match.GetState() == string(gradeKnown) {
				t.Fatalf("unresolved cp target was graded known: %+v", match)
			}
		}
	}
	if !found {
		t.Fatal("cp destination did not expose the expected protected config match")
	}
}

// A name-based Maybe for one target/set must not coexist with a Known grade
// for that same target/set, including when another effect in the call resolved
// it. A separate Known target keeps its independent resolver proof.
func TestDET111RNameMaybeCannotCarryKnownInSameCall(t *testing.T) {
	const home = "/home/alice"
	result := effects.Result{Effects: []effects.Effect{
		{Kind: effects.KindWrite, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
			Target: effects.Target{Type: effects.TargetPath, Path: home + "/.ssh/id_rsa", Flavor: effects.FlavorPOSIX}},
		{Kind: effects.KindWrite, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateUnknown,
			Target: effects.Target{Type: effects.TargetPath, Path: home + "/.ssh/id_rsa", Flavor: effects.FlavorPOSIX}},
		{Kind: effects.KindWrite, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
			Target: effects.Target{Type: effects.TargetPath, Path: home + "/.defenseclaw/config.yaml", Flavor: effects.FlavorPOSIX}},
	}}
	facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX})
	seenMaybe, seenIndependentKnown := false, false
	for _, fact := range facts {
		for _, match := range fact.GetTarget().GetProtected() {
			if match.GetSet() == SetCredentials {
				if match.GetState() == string(gradeKnown) {
					t.Fatalf("same target/set retained Known beside an unresolved name: %+v", match)
				}
				seenMaybe = seenMaybe || match.GetState() == string(gradeUnknown)
			}
			if match.GetSet() == SetSelfProtection && match.GetState() == string(gradeKnown) {
				seenIndependentKnown = true
			}
		}
	}
	if !seenMaybe {
		t.Fatal("call with an unknown role on a protected name had no Maybe")
	}
	if !seenIndependentKnown {
		t.Fatal("independent Known target lost its resolver proof")
	}
}

// AccountHomes is absent at a64; reflection keeps this fail-before test
// buildable there while the current projector consumes the bounded home set.
func TestDET111PasswdHomeTailNeedsAccountHomeFact(t *testing.T) {
	const activeHome, peerHome = "/home/alice", "/srv/homes/bob"
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell,
		Command: "cat /srv/homes/bob/.aws/credentials"}, effects.Options{
		Flavor: effects.FlavorPOSIX, Home: activeHome, CWD: activeHome + "/proj",
	})
	env := Env{Home: activeHome, Flavor: effects.FlavorPOSIX}
	homes := reflect.ValueOf(&env).Elem().FieldByName("AccountHomes")
	if homes.IsValid() && homes.CanSet() {
		homes.Set(reflect.ValueOf([]string{peerHome}))
	}
	facts := Project(result, env)
	for _, fact := range facts {
		for _, match := range fact.GetTarget().GetProtected() {
			if match.GetSet() == SetCredentials && match.GetState() == string(gradeKnown) &&
				match.GetReason() == "other_home" {
				return
			}
		}
	}
	t.Fatal("literal passwd-home credential tail was not Known")
}
