// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// A file in a vendor machine-policy folder that DefenseClaw does not publish
// is an ordinary file; the published settings file, a drop-in directory and
// the folder itself stay protected, and so do the Windows 8.3 names of them
// (rel-1-0-6:GAP-0734 review 9 M2).
func TestFileToolVendorFolderOrdinaryFileAllowsAndPublishedSettingsStayBlocked(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive"} {
			for _, file := range []string{
				"/etc/claude-code/notes.txt", "/etc/codex/notes.txt", "/Library/Application Support/ClaudeCode/notes.txt",
			} {
				input := map[string]any{"file_path": file, "content": "x"}
				if _, got := postFileToolCell(t, home, project, "Write", input, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("ordinary vendor-folder file %q managed=%t pack=%q: %.200s", file, managed, pack, got)
				}
			}
		}
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range []string{
				"/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/50-x.json",
				"/etc/codex/requirements.toml", "/Library/Application Support/ClaudeCode/managed-settings.json",
			} {
				input := map[string]any{"file_path": file, "content": "x"}
				if _, got := postFileToolCell(t, home, project, "Write", input, managed, pack); !strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("published settings %q managed=%t pack=%q allowed: %.200s", file, managed, pack, got)
				}
			}
		}
	}
}

func TestFileToolWindowsVendorFolderOrdinaryFileAndShortNameShapeAllowAndAliasesStayBlocked(t *testing.T) {
	const home = `C:\Users\tester`
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive"} {
			for _, file := range []string{
				`C:\Program Files\ClaudeCode\notes.txt`,
				`C:\P~1\ClaudeCode\managed-settings.json`,
				`C:\PROG~1\ClaudeCode\managed-settings.json`,
				`C:\Program Files\ClaudeCode\MANAGE~0.JSO`,
				`C:\Program Files\ClaudeCode\MANAGE~5.JSO`,
				`C:\PROGRA~0\ClaudeCode\managed-settings.json`,
				`C:\PROGRA~5\ClaudeCode\managed-settings.json`,
				`C:\ProgramData\OpenAI\CODEX~1\requirements.toml`,
				`C:\ProgramData\CURSOR~1\hooks.json`,
			} {
				input := map[string]any{"file_path": file, "content": "x"}
				if _, got := postFileToolCell(t, home, home+`\proj`, "Write", input, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("ordinary file %q managed=%t pack=%q: %.200s", file, managed, pack, got)
				}
			}
		}
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range []string{
				`C:\Program Files\ClaudeCode\managed-settings.json`,
				`//localhost/C$/Program Files/ClaudeCode/managed-settings.json`,
			} {
				input := map[string]any{"file_path": file, "content": "x"}
				if _, got := postFileToolCell(t, home, home+`\proj`, "Write", input, managed, pack); !strings.HasPrefix(got, fileToolBlockPrefix) {
					t.Errorf("protected alias %q managed=%t pack=%q allowed: %.200s", file, managed, pack, got)
				}
			}
		}
	}
}
