// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0353GitBashDriveRootSudoers(t *testing.T) {
	const cwd = `E:\Users\fixture\project`
	rows := []struct {
		name, command, cwd string
		moved              bool
		main, dropin       bool
	}{
		{"redirect", `echo configured > E:/etc/sudoers`, cwd, false, true, false},
		{"append", `echo configured >> F:/private/etc/sudoers`, cwd, false, true, false},
		{"copy", `cp fixture E:/etc/sudoers`, cwd, false, true, false},
		{"after cd", `echo configured > E:/etc/sudoers # after cd`, `E:\Users\fixture\other`, true, true, false},
		{"case and dot", `echo configured > E:/EtC/./SuDoErS`, cwd, false, true, false},
		{"drop-in", `echo configured > E:/etc/sudoers.d/lane`, cwd, false, false, true},
		{"project path", `echo configured > E:/Users/fixture/project/etc/sudoers`, cwd, false, false, false},
		{"sibling path", `echo configured > E:/etc/sudoers.bak`, cwd, false, false, false},
		{"other root", `echo configured > E:/var/etc/sudoers`, cwd, false, false, false},
		{"project after cd", `echo configured > E:/Users/fixture/project/etc/sudoers # after cd`, `E:\Users\fixture\other`, true, false, false},
		{"POSIX workspace", `echo configured > E:/etc/sudoers`, "/repo", false, false, false},
		{"relative project path", `echo configured > etc/sudoers`, cwd, false, false, false},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "gap0353-gitbash-drive-root"
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					args, err := json.Marshal(map[string]any{"command": row.command})
					if err != nil {
						t.Fatal(err)
					}
					input := actionfacts.Input{
						Tool: "Bash", Args: args, CWD: row.cwd,
						ActiveHome: `E:\Users\fixture`, DialectHint: actionfacts.DialectPOSIX,
						MovedWindowsShellCWD: row.moved,
					}
					findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: row.command, Connector: connector, EnforcementCapable: true,
					})
					finding := findingWithID(findings, "PATH-ETC-SUDOERS")
					want := row.main || row.dropin && profile == "strict"
					if (finding != nil && finding.contributesToEnforcement()) != want {
						t.Fatalf("sudoers finding=%v, want=%t, findings=%v", finding, want, FindingStrings(findings))
					}
					if !want {
						for _, other := range findings {
							if other.contributesToEnforcement() {
								t.Fatalf("benign enforcement: %v", FindingStrings(findings))
							}
						}
					}
				})
			}
		})
	}
}
