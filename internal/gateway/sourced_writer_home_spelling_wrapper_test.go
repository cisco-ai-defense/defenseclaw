// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// homeScriptFolder writes the writer wk.sh and the ordinary ok.sh in a
// folder of the account home that is outside the project, and names it
// through links chain links (zero is no link at all).
func homeScriptFolder(t *testing.T, f b36ManagedHookFixture, links int) {
	t.Helper()
	live := filepath.Join(f.home, "chain", "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "wk.sh"), []byte("echo marker >> $HOME/.ssh/authorized_keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ok.sh", "safe.sh"} {
		if err := os.WriteFile(filepath.Join(live, name), []byte("echo ordinary >> report.txt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if links > 0 {
		if err := os.Symlink(gatewayLinkChain(t, links, live), filepath.Join(f.home, "chain", "d")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
}

// TestSourcedWriterNamedByHomeSpellingInAWrapperIsBlockedFromAnyFolder: a
// script named by ~ or $HOME inside a shell command string (bash -c, sh -c,
// a login shell, env or sudo around it, nested strings) is the file in the
// account home whichever folder the hook reports as the working folder, with
// or without folder links, as the same command typed at the top level is. A
// write it makes to the keys file is blocked in the default and the strict
// profile; the ordinary script is allowed
// (rel-1-0-9:GAP-1035).
//
// Each launcher, each spelling of the home and each builtin appears in at
// least one row with its ordinary twin, and the link counts are walked by
// a few rows each: the launcher and the link walk are independent steps, so
// the cross product adds no behaviour and ran for ten minutes under -race.
func TestSourcedWriterNamedByHomeSpellingInAWrapperIsBlockedFromAnyFolder(t *testing.T) {
	// pair is the writer (block) and the ordinary script (allow) named by
	// the same form, which holds one %s for the script name.
	pair := func(name, where, form string) []r106Reader2Row {
		return []r106Reader2Row{
			{name + " writer", where, fmt.Sprintf(form, "wk.sh"), "block"},
			{name + " ordinary", where, fmt.Sprintf(form, "ok.sh"), "allow"},
		}
	}
	for _, links := range []int{0, 1, 3, hookpaths.SystemLinkLimit() - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir := "live"
			if links > 0 {
				dir = "d"
			}
			at := "/chain/" + dir + "/%s"
			var rows []r106Reader2Row
			switch links {
			case 0:
				for _, r := range []struct{ name, where, form string }{
					{"bash -c source $HOME", "project", `bash -c "source $HOME` + at + `"`},
					{"sh -c bash ${HOME}", "project", `sh -c "bash ${HOME}` + at + `"`},
					{"bash -lc sh quoted $HOME", "project", `bash -lc "sh \"$HOME\"` + at + `"`},
					{"env sudo bash -c dot ~", "project", `env X=1 sudo bash -c ". ~` + at + `"`},
					{"zsh -c dot $HOME", "project", `zsh -c ". $HOME` + at + `"`},
					{"nested sh in bash after echo", "project", `bash -c "echo go && sh -c \". ~` + at + `\""`},
					{"absolute spelling from home", "home", `bash -c ". {H}` + at + `"`},
				} {
					rows = append(rows, pair(r.name, r.where, r.form)...)
				}
			case 1:
				rows = pair("bash -c dot ~", "project", `bash -c ". ~`+at+`"`)
			case 3:
				rows = pair("sh -c bash ${HOME}", "project", `sh -c "bash ${HOME}`+at+`"`)
			default:
				rows = pair("bash -lc source $HOME", "project", `bash -lc "source $HOME`+at+`"`)
			}
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { homeScriptFolder(t, f, links) })
		})
	}
}
