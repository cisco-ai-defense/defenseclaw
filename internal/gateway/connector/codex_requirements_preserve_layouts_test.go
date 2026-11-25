// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-1754: the layouts of an administrator's requirements.toml that
// TestGAP1737CodexRequirementsKeepAdministratorText does not use. Each one
// is installed, repaired and removed on both profiles, and the
// administrator's lines, comments included, survive all three.

// codexAdminLines is the administrator's non-blank lines of text.
func codexAdminLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func requireCodexAdminLines(t *testing.T, label string, got []byte, lines []string) {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(string(got), line+"\n") {
			t.Fatalf("%s lost the administrator line %q:\n%s", label, line, got)
		}
	}
}

func TestGAP1754CodexRequirementsKeepAdministratorLayouts(t *testing.T) {
	const groupA = "[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n# IT logger A\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\a.exe'\n"
	const groupB = "[[hooks.PostToolUse]]\nmatcher = \"Bash\"\n# IT logger B\n[[hooks.PostToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\b.exe'\n"
	const groupC = "[[hooks.PreToolUse]]\nmatcher = \"Write\"\n# IT logger C\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\c.exe'\n"
	layouts := []struct {
		name string
		text func(dir string) string
		// wholeRender: the editor cannot narrow a root dotted hooks key, so
		// the file is rendered whole and the administrator's values (not
		// their comments) are what survives. kept names a value to find in
		// the decoded document after install and after removal.
		wholeRender bool
		kept        func(doc map[string]interface{}) bool
	}{
		// One event's blocks are not next to each other: another event's
		// block sits between them.
		{"split event blocks", func(string) string { return "# IT policy\n[hooks]\n# IT hooks\n" + groupA + groupB + groupC }, false, nil},
		// The administrator wrote the managed dir (the protected one) as a
		// dotted key at the root, and a dotted features key beside it.
		{"root dotted hooks keys", func(dir string) string {
			return "# IT policy\nhooks.windows_managed_dir = '" + dir + "' # IT dir\nfeatures.web_search = false # IT search\n"
		}, true, func(doc map[string]interface{}) bool {
			features, _ := doc["features"].(map[string]interface{})
			return features != nil && features["web_search"] == false
		}},
		{"root dotted hooks key before a hook group", func(dir string) string {
			return "# IT policy\nhooks.windows_managed_dir = '" + dir + "' # IT dir\n\n" + groupA
		}, true, func(doc map[string]interface{}) bool {
			hooks, _ := doc["hooks"].(map[string]interface{})
			groups, _ := hooks["PreToolUse"].([]interface{})
			for _, group := range groups {
				if strings.Contains(fmt.Sprint(group), `IT\a.exe`) {
					return true
				}
			}
			return false
		}},
	}
	for name, opts := range map[string]WindowsCodexMachineRequirementsOptions{
		"secure client": testWindowsCodexMachineOptions(),
		"standalone":    standaloneWindowsCodexMachineOptions(),
	} {
		for _, layout := range layouts {
			t.Run(name+"/"+layout.name, func(t *testing.T) {
				text := layout.text(opts.ManagedDir)
				raw := []byte(text)
				installed, changed, err := reconcileWindowsCodexRequirements(raw, opts, false)
				if err != nil || !changed {
					t.Fatalf("install changed=%v err=%v", changed, err)
				}
				if err := verifyWindowsCodexRequirementsBytes(installed, opts); err != nil {
					t.Fatalf("the installed file does not verify: %v\n%s", err, installed)
				}
				lines := codexAdminLines(text)
				requireKept := func(label string, got []byte) {
					t.Helper()
					if !layout.wholeRender {
						requireCodexAdminLines(t, label, got, lines)
						return
					}
					doc := map[string]interface{}{}
					if err := parseCodexTOML(got, &doc); err != nil || !layout.kept(doc) {
						t.Fatalf("%s lost the administrator's value (err=%v):\n%s", label, err, got)
					}
				}
				requireKept("install", installed)
				repaired, changed, err := reconcileWindowsCodexRequirements(installed, opts, true)
				if err != nil || changed || string(repaired) != string(installed) {
					t.Fatalf("a repair of an intact file rewrote it (changed=%v err=%v):\n%s", changed, err, repaired)
				}
				removed, _, err := removeWindowsCodexRequirementsOwnedChanges(installed, raw, opts)
				if err != nil {
					t.Fatalf("removal: %v", err)
				}
				requireKept("removal", removed)
				if strings.Contains(string(removed), "defenseclaw-hook") {
					t.Fatalf("removal left a DefenseClaw hook group:\n%s", removed)
				}
			})
		}
	}
}

// A dotted root key that names another managed directory is refused, as the
// table form is, and the file is left as it was.
func TestGAP1754CodexRequirementsRefuseAConflictingDottedManagedDir(t *testing.T) {
	for name, opts := range map[string]WindowsCodexMachineRequirementsOptions{
		"secure client": testWindowsCodexMachineOptions(),
		"standalone":    standaloneWindowsCodexMachineOptions(),
	} {
		t.Run(name, func(t *testing.T) {
			raw := "# IT policy\nhooks.windows_managed_dir = 'C:\\IT\\old' # IT dir\n"
			out, changed, err := reconcileWindowsCodexRequirements([]byte(raw), opts, false)
			if err == nil || changed || !strings.Contains(err.Error(), "conflicts with protected managed directory") {
				t.Fatalf("a conflicting managed dir must be refused: changed=%v err=%v\n%s", changed, err, out)
			}
		})
	}
}

// Removal takes DefenseClaw's group out from between two administrator
// groups of the same event, the later one added after the install.
func TestGAP1754CodexRequirementsRemovalBetweenAdministratorGroups(t *testing.T) {
	const first = "# IT policy\n[hooks]\n[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n# IT logger first\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\first.exe'\n"
	const later = "\n[[hooks.PreToolUse]]\nmatcher = \"Write\"\n# IT logger later\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\IT\\later.exe'\n"
	for name, opts := range map[string]WindowsCodexMachineRequirementsOptions{
		"secure client": testWindowsCodexMachineOptions(),
		"standalone":    standaloneWindowsCodexMachineOptions(),
	} {
		t.Run(name, func(t *testing.T) {
			installed, _, err := reconcileWindowsCodexRequirements([]byte(first), opts, false)
			if err != nil {
				t.Fatal(err)
			}
			// The administrator appends a group after DefenseClaw's.
			edited := append(append([]byte{}, installed...), later...)
			removed, _, err := removeWindowsCodexRequirementsOwnedChanges(edited, []byte(first), opts)
			if err != nil {
				t.Fatalf("removal: %v", err)
			}
			requireCodexAdminLines(t, "removal", removed, codexAdminLines(first+later))
			if strings.Contains(string(removed), "defenseclaw-hook") {
				t.Fatalf("removal left a DefenseClaw hook group:\n%s", removed)
			}
			if err := verifyWindowsCodexRequirementsBytes(removed, opts); err == nil {
				t.Fatalf("a file without DefenseClaw's groups must not verify as installed:\n%s", removed)
			}
		})
	}
}
