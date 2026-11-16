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
//
// Every spelling and every command form appears in at least one row with its
// ordinary twin, and the link counts are walked by a row each: the spelling,
// the command form and the link walk are independent steps, so the cross
// product adds no behaviour and ran for over three minutes under -race.
func TestSourcedWriterOutsideTheWorkingFolderIsBlockedOnEveryRoute(t *testing.T) {
	for _, links := range []int{0, 1, 3, hookpaths.SystemLinkLimit() - 1} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir := "live"
			if links > 0 {
				dir = "d"
			}
			// row is the writer (block) and the ordinary script (allow) named
			// by the spelling inside the command form; %s in both is the name.
			row := func(command, spelling string) []r106Reader2Row {
				build := func(script string) string { return fmt.Sprintf(command, fmt.Sprintf(spelling, script)) }
				return []r106Reader2Row{
					{command + " " + spelling + " writer", "project", build("wk.sh"), "block"},
					{command + " " + spelling + " ordinary", "project", build("ok.sh"), "allow"},
				}
			}
			var rows []r106Reader2Row
			switch links {
			case 0:
				for _, r := range [][2]string{
					{". %s", "../chain/" + dir + "/%s"},
					{"source %s", "./../chain/" + dir + "/%s"},
					{"bash %s", "../project/../chain/" + dir + "/%s"},
					{"sh %s", "{H}/chain/" + dir + "/%s"},
					{`bash -c ". %s"`, "{H}/../shared/%s"},
					{`sh -c "bash %s"`, "../../shared/%s"},
					{`bash -lc ". %s"`, "~/chain/in/%s"},
					{`env A=1 bash -c ". %s"`, "$HOME/chain/in/%s"},
					{". %s", "{H}/chain/in/%s"},
					{"bash %s", "../chain/in/%s"},
				} {
					rows = append(rows, row(r[0], r[1])...)
				}
			case 1:
				rows = row(`bash -c ". %s"`, "../project/../chain/"+dir+"/%s")
			case 3:
				rows = row(`sh -c "bash %s"`, "{H}/chain/"+dir+"/%s")
			default:
				rows = row(". %s", "../chain/"+dir+"/%s")
			}
			r106Reader2CheckWith(t, rows, func(t *testing.T, f b36ManagedHookFixture) { outsideScriptFolders(t, f, links) })
		})
	}
}
