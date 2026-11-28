// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func TestDET111R3HomeShapedProtectedTailsAreKnown(t *testing.T) {
	const home = "/home/alice"
	o := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: home + "/proj"}
	cases := []struct {
		command string
		set     string
		known   bool
	}{
		{command: "cat /home/bob/.aws/credentials", set: SetCredentials, known: true},
		{command: "cat /Users/peer/.ssh/id_rsa", set: SetCredentials, known: true},
		{command: "cat /root/.git-credentials", set: SetCredentials, known: true},
		{command: "cat /home/alice/proj/.aws/credentials", set: SetCredentials},
		{command: "cat /tmp/notes/.aws/credentials", set: SetCredentials},
	}
	for _, tc := range cases {
		facts := Project(effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.command}, o), Env{
			Home: home, Flavor: effects.FlavorPOSIX,
		})
		var got *semanticpb.ProtectedMatch
		for _, fact := range facts {
			for _, match := range fact.GetTarget().GetProtected() {
				if match.GetSet() == tc.set {
					copy := match
					got = copy
				}
			}
		}
		if got == nil {
			t.Fatalf("%s: no %s protected match", tc.command, tc.set)
		}
		if tc.known && (got.GetState() != "known" || got.GetReason() != "other_home") {
			t.Errorf("%s: protection = %+v, want known other_home", tc.command, got)
		}
		if !tc.known && got.GetState() == "known" {
			t.Errorf("%s: protection = %+v, want Maybe for a tail outside a home root", tc.command, got)
		}
	}
}

func TestDET111R3TildePeerDotDotUsesResolvedHomePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the peer/.. step up is placed by plainStepUpProof, which is a POSIX-host proof (promote returns on a Windows host) and place reads POSIX absolute paths; a Windows temp folder is a drive path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "active")
	peer := filepath.Join(root, "peer")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(peer, 0o700); err != nil {
		t.Fatal(err)
	}
	o := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: home}
	command := "echo k >> " + peer + "/../active/.ssh/authorized_keys"
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: command}, o)
	facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX})
	for _, fact := range facts {
		for _, match := range fact.GetTarget().GetProtected() {
			if match.GetSet() == SetSSHAuthorizedKeys && match.GetState() == "known" {
				return
			}
		}
	}
	t.Fatal("passwd-home dot-dot path was not resolved to the known active-home member")
}
