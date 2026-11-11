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

// outsideScriptFolders writes the writer wk.sh and the ordinary ok.sh in a
// folder beside the home (shared) and in a folder of the project, through
// homeScriptFolder in the home outside the project, and links home/chain/in
// to the folder of the project.
func outsideScriptFolders(t *testing.T, f b36ManagedHookFixture, links int) {
	t.Helper()
	homeScriptFolder(t, f, links)
	shared := filepath.Join(f.homes, "shared")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	inProject := filepath.Join(f.project, "ordinary")
	for _, folder := range []string{shared, inProject} {
		for name, body := range map[string]string{
			"wk.sh": "echo marker >> $HOME/.ssh/authorized_keys\n",
			"ok.sh": "echo ordinary >> report.txt\n",
		} {
			if err := os.WriteFile(filepath.Join(folder, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(inProject, filepath.Join(f.home, "chain", "in")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
}

// TestSourcedWriterOutsideTheWorkingFolderIsBlockedOnEveryRoute: a script a
// source, dot, bash or sh command names is the file the system opens, wherever
// it lies and however the name spells it: .. from the project into the home or
// beside it, a ~ or $HOME or full path in the home that passes a link back
// into the project, a full path beside the home, with or without folder
// links on the way. A write it makes to the keys file is blocked in the
// default and the strict profile by a per-user gateway and by a managed one,
// which cannot open the home and judges the hook client reading; the
// ordinary script is allowed in every spelling
// (rel-1-0-9:GAP-1035, GAP-1038, GAP-1039).
func TestSourcedWriterOutsideTheWorkingFolderIsBlockedOnEveryRoute(t *testing.T) {
	for _, links := range []int{0, 1, 3, hookpaths.SystemLinkLimit() - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir := "live"
			if links > 0 {
				dir = "d"
			}
			spellings := []string{
				"../chain/" + dir + "/%s",
				"./../chain/" + dir + "/%s",
				"../project/../chain/" + dir + "/%s",
				"{H}/chain/" + dir + "/%s",
				"{H}/../shared/%s",
				"../../shared/%s",
				"~/chain/in/%s",
				"$HOME/chain/in/%s",
				"{H}/chain/in/%s",
				"../chain/in/%s",
			}
			commands := []string{
				". %s", "source %s", "bash %s", "sh %s", `bash -c ". %s"`, `sh -c "bash %s"`, `bash -lc ". %s"`, `env A=1 bash -c ". %s"`,
			}
			var rows []r106Reader2Row
			for _, spelling := range spellings {
				for _, command := range commands {
					build := func(script string) string { return fmt.Sprintf(command, fmt.Sprintf(spelling, script)) }
					rows = append(rows,
						r106Reader2Row{command + " " + spelling + " writer", "project", build("wk.sh"), "block"},
						r106Reader2Row{command + " " + spelling + " ordinary", "project", build("ok.sh"), "allow"},
					)
				}
			}
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { outsideScriptFolders(t, f, links) })
		})
	}
}
