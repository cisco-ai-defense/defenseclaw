// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"slices"
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

// DET111 S4-R3, rel-1-0-10:GAP-0899: a credential path outside the shaped
// home roots names a candidate home for the passwd lookup (never a home by
// its shape), and a candidate the lookup returned (Env.AccountHomes) makes the
// read a known other-home credential read; without it the read keeps the
// 1.0.10 maybe.
func TestDET111R3MountedAccountHomes(t *testing.T) {
	px, _, _, _, _, _ := r3Opts()
	extract := func(command string) effects.Result {
		return effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: command}, px)
	}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{`cat /mnt/home/bob/.ssh/id_rsa`, []string{"/mnt/home/bob"}},
		{`cat /srv/homes/eve/.aws/credentials`, []string{"/srv/homes/eve"}},
		{`base64 /mnt/home/bob/.git-credentials`, []string{"/mnt/home/bob"}},
		{`cat /home/bob/.ssh/id_rsa`, nil},  // a shaped home root: the classifier places it
		{`cat /home/dcku/.ssh/id_rsa`, nil}, // the active home
		{`cat /mnt/data/report.csv`, nil},
		{`cat /mnt/home/bob/notes.txt`, nil},
		{`cat $X/.ssh/id_rsa`, nil}, // not placed
	} {
		if got := AccountHomeCandidates(extract(tc.command), px.Home); !slices.Equal(got, tc.want) {
			t.Errorf("%q: candidates %q, want %q", tc.command, got, tc.want)
		}
	}
	class := func(command string, homes []string) []Protection {
		var out []Protection
		for _, f := range Project(extract(command), Env{Home: px.Home, Flavor: px.Flavor, AccountHomes: homes,
			Resolve: func(p string) (string, bool) { return p, true }}) {
			out = append(out, Protected(f.Target)...)
		}
		return out
	}
	has := func(ps []Protection, class, certainty string) bool {
		return slices.ContainsFunc(ps, func(p Protection) bool { return p.Class == class && p.Certainty == certainty })
	}
	if got := class(`cat /mnt/home/bob/.ssh/id_rsa`, []string{"/mnt/home/bob"}); !has(got, "other_home_credential", "known") {
		t.Errorf("passwd home: %+v, want a known other-home credential", got)
	}
	if got := class(`cat /mnt/home/bob/.ssh/id_rsa`, nil); has(got, "other_home_credential", "known") {
		t.Errorf("no passwd home: %+v, want no known match (the shape alone is a maybe)", got)
	}
	if got := class(`cat /mnt/home/bob/notes.txt`, []string{"/mnt/home/bob"}); len(got) != 0 {
		t.Errorf("an ordinary file of the passwd home: %+v, want no protected match", got)
	}
}
