// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A Windows hook resolves a rooted file-tool or PowerShell target on the
// current drive. The sudoers rule must follow that resolved identity while
// retaining the shipped profile posture and leaving neighboring files quiet.
func TestGAP0353WindowsSudoersResolvedPaths(t *testing.T) {
	const cwd = `C:\Users\fixture\project`
	patch := func(target string) string {
		return "*** Begin Patch\n*** Update File: " + target + "\n@@\n a\n+b\n*** End Patch\n"
	}
	rows := []struct {
		name, tool, field, value, cwd string
		dialect                       actionfacts.Dialect
		main, dropin                  bool
	}{
		{"Write rooted", "Write", "file_path", "/etc/sudoers", cwd, "", true, false},
		{"Write dot", "Write", "file_path", "/etc/./sudoers", cwd, "", true, false},
		{"Write double slash", "Write", "file_path", "/etc//sudoers", cwd, "", true, false},
		{"Write uppercase", "Write", "file_path", "/ETC/SUDOERS", cwd, "", true, false},
		{"Write private", "Write", "file_path", "/private/etc/sudoers", cwd, "", true, false},
		{"Write drive slash", "Write", "file_path", "C:/etc/sudoers", cwd, "", true, false},
		{"Write drive backslash", "Write", "file_path", `C:\etc\sudoers`, cwd, "", true, false},
		{"Edit rooted", "Edit", "file_path", "/etc/sudoers", cwd, "", true, false},
		{"MultiEdit rooted", "MultiEdit", "file_path", "/etc/sudoers", cwd, "", true, false},
		{"Codex redirect", "Bash", "command", "echo configured > /etc/sudoers", cwd, actionfacts.DialectPowerShell, true, false},
		{"Codex append", "Bash", "command", "echo configured >> /etc/sudoers", cwd, actionfacts.DialectPowerShell, true, false},
		{"Codex tee", "Bash", "command", "tee /etc/sudoers", cwd, actionfacts.DialectPowerShell, true, false},
		{"Codex patch", "apply_patch", "command", patch("/etc/sudoers"), cwd, "", true, false},
		{"Write drop-in", "Write", "file_path", "/etc/sudoers.d/lane", cwd, "", false, true},
		{"Write project file", "Write", "file_path", `C:\Users\fixture\project\etc\sudoers`, cwd, "", false, false},
		{"Write root neighbor", "Write", "file_path", "/etc/hosts", cwd, "", false, false},
		{"Write name neighbor", "Write", "file_path", "/etc/sudoers.bak", cwd, "", false, false},
		{"Write slash-drive neighbor", "Write", "file_path", "/c/etc/sudoers", cwd, "", false, false},
		{"Read main", "Read", "file_path", "/etc/sudoers", cwd, "", false, false},
		{"POSIX project drive spelling", "Write", "file_path", "C:/etc/sudoers", "/repo", "", false, false},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "gap0353-windows-resolved"
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, row := range rows {
				row := row
				t.Run(row.name, func(t *testing.T) {
					fields := map[string]any{row.field: row.value}
					switch row.tool {
					case "Write":
						fields["content"] = "configured\n"
					case "Edit":
						fields["old_string"], fields["new_string"] = "a", "b"
					case "MultiEdit":
						fields["edits"] = []any{map[string]any{"old_string": "a", "new_string": "b"}}
					}
					args, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					input := actionfacts.Input{Tool: row.tool, Args: args, CWD: row.cwd, DialectHint: row.dialect, ActiveHome: `C:\Users\fixture`}
					facts := actionfacts.Analyze(input)
					if !facts.Authoritative() || !facts.EnforcementEligible() {
						t.Fatalf("path facts unavailable: %+v", facts.Parse)
					}
					if row.main && row.cwd == cwd {
						resolved := false
						for _, path := range facts.Paths {
							if path.Flavor == actionfacts.PathFlavorWindows &&
								(strings.EqualFold(path.Resolved, "C:/etc/sudoers") || strings.EqualFold(path.Resolved, "C:/private/etc/sudoers")) {
								resolved = true
							}
						}
						if !resolved {
							t.Fatalf("main path was not resolved on the current drive: %+v", facts.Paths)
						}
					}
					findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: row.value, Connector: connector, EnforcementCapable: true,
					})
					finding := findingWithID(findings, "PATH-ETC-SUDOERS")
					want := row.main || row.dropin && profile == "strict"
					if want {
						if finding == nil || !finding.contributesToEnforcement() || finding.Evidence != "" {
							t.Fatalf("sudoers finding=%+v, want semantic finding: %v", finding, FindingStrings(findings))
						}
					} else {
						if finding != nil {
							t.Fatalf("neighbor named sudoers: %v", FindingStrings(findings))
						}
						for _, other := range findings {
							if other.contributesToEnforcement() {
								t.Fatalf("neighbor received an enforcement finding: %v", FindingStrings(findings))
							}
						}
					}
				})
			}
		})
	}
}
