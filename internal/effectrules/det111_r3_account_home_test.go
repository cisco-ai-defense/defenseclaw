// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestDET111R3PasswdHomeTailIsKnown(t *testing.T) {
	const home = "/home/alice"
	const peer = "/srv/homes/bob"
	o := effects.Options{
		Flavor: effects.FlavorPOSIX, Home: home, CWD: home + "/proj",
		Accounts: map[string]string{"bob": peer},
	}
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: "cat ~bob/.aws/credentials"}, o)
	facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX, AccountHomes: []string{peer}})
	for _, fact := range facts {
		for _, protection := range Protected(fact.GetTarget()) {
			if protection.Set == SetCredentials {
				if protection.Certainty != "known" || protection.Class != "other_home_credential" {
					t.Fatalf("passwd home protection = %+v, want known other_home_credential", protection)
				}
				return
			}
		}
	}
	t.Fatal("passwd home credential read has no protected match")
}
