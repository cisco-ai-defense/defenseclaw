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
func TestSourcedWriterNamedByHomeSpellingInAWrapperIsBlockedFromAnyFolder(t *testing.T) {
	launchers := []string{
		``, `bash -c`, `sh -c`, `bash -lc`, `bash -l -c`, `env X=1 bash -c`, `sudo bash -c`, `zsh -c`,
	}
	for _, links := range []int{0, 1, 3, hookpaths.SystemLinkLimit() - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir := "live"
			if links > 0 {
				dir = "d"
			}
			var rows []r106Reader2Row
			for _, launcher := range launchers {
				for _, spelling := range []string{"~", "$HOME", "${HOME}", `\"$HOME\"`, "{H}"} {
					for _, builtin := range []string{".", "source", "bash", "sh"} {
						if launcher == "" && (builtin == "bash" || builtin == "sh") {
							continue
						}
						form := func(script string) string {
							inner := builtin + " " + spelling + "/chain/" + dir + "/" + script
							if launcher == "" {
								return inner
							}
							return launcher + " \"" + inner + "\""
						}
						if spelling == `\"$HOME\"` && launcher == "" {
							continue
						}
						rows = append(rows,
							r106Reader2Row{launcher + " " + builtin + " " + spelling + " writer", "project", form("wk.sh"), "block"},
							r106Reader2Row{launcher + " " + builtin + " " + spelling + " ordinary", "project", form("ok.sh"), "allow"},
						)
					}
				}
			}
			rows = append(rows,
				r106Reader2Row{"nested sh in bash", "project", `bash -c "sh -c \". ~/chain/` + dir + `/wk.sh\""`, "block"},
				r106Reader2Row{"chained after echo", "project", `bash -c "echo go && . ~/chain/` + dir + `/wk.sh"`, "block"},
				r106Reader2Row{"chained ordinary", "project", `bash -c "echo go && . ~/chain/` + dir + `/ok.sh"`, "allow"},
				r106Reader2Row{"absolute spelling", "project", `bash -c ". ` + "{H}" + `/chain/` + dir + `/wk.sh"`, "block"},
				r106Reader2Row{"from home", "home", `bash -c ". ~/chain/` + dir + `/wk.sh"`, "block"},
			)
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { homeScriptFolder(t, f, links) })
		})
	}
}
