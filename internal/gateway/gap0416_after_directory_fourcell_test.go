// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0416: the destination is interpreted after entering a different
// directory. Keep the ordinary destination paired with the protected one.
func TestGAP0416AfterDirectoryFourCell(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	work := filepath.Join(project, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../.ssh/authorized_keys", filepath.Join(work, "disklink")); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range []struct {
				name, command, want string
			}{
				// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
				{"protected", `cd ~/proj/work && f=disklink; cp ../a.txt $f`, "alert"},
				{"ordinary", `cd ~/proj/work && f=out.txt; cp ../a.txt $f`, "allow"},
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					var hide func(map[string]string)
					if managed {
						hide = func(map[string]string) {
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, hide)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if !strings.HasPrefix(got, `{"action":"`+row.want+`"`) ||
						row.want == "alert" && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%s = %.300s, want %s", row.name, got, row.want)
					}
				})
			}
		}
	}
}
