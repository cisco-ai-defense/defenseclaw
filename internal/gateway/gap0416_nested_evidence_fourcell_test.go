// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0416: a placed sibling call does not place a later nested destination.
// An ordinary destination with the same call shape remains allowed.
func TestGAP0416NestedTargetWithPlacedSiblingFourCell(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	work := filepath.Join(project, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../.ssh/authorized_keys", filepath.Join(work, "disklink")); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range []struct {
				name, command, want string
				changedEvidence     bool
			}{
				{"after-directory", `cd ~/proj/work && f=disklink; cp ../a.txt $f`, "block", false},
				{"nested-target", `pushd ~/proj/work && f=disklink; echo hi; for x in 1; do cp ../a.txt $f; done`, "block", true},
				{"ordinary-nested-target", `pushd ~/proj/work && f=/dev/null; echo hi; for x in 1; do cp ../a.txt $f; done`, "allow", false},
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					var evidence func(map[string]string)
					if managed {
						evidence = func(targets map[string]string) {
							if row.changedEvidence {
								for key, value := range targets {
									if value == keys {
										targets[key] = filepath.Join(work, "out2.txt")
									}
								}
								delete(targets, hookpaths.ActionDecisionKey)
							}
							if err := os.Chmod(home, 0); err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
						}
					}
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, evidence)
					if managed {
						if err := os.Chmod(home, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if !strings.HasPrefix(got, `{"action":"`+row.want+`"`) ||
						row.want == "block" && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%s = %.300s, want %s", row.name, got, row.want)
					}
				})
			}
		}
	}
}
