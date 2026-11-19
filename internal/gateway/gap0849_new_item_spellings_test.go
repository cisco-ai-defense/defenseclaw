// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// gap0849ItemTypeSpellings are spellings of New-Item's -ItemType that
// PowerShell binds to it (checked natively for rel-1-0-10:GAP-0849): a
// prefix of the Type alias, an en dash, em dash or horizontal bar, -ItemType:
// with the value in the next word or attached. Each is applied to the plain
// "New-Item -ItemType " of a row, so the row text is otherwise the plain
// row's; the last three also spell New-Item as its ni alias.
var gap0849ItemTypeSpellings = []struct{ id, newItem, itemType string }{
	{"T1-alias-prefix-ty", "New-Item ", "-Ty "},
	{"T2-alias-prefix-typ", "New-Item ", "-typ "},
	{"T3-endash-name", "New-Item ", "–ItemType "},
	{"T4-colon-space", "New-Item ", "-ItemType: "},
	{"T8-emdash-alias", "New-Item ", "—Type "},
	{"T10-hbar-name", "New-Item ", "―ItemType "},
	{"T11-colon-inline", "New-Item ", "-ItemType:"},
	{"T12-ni-alias-ty", "ni ", "-Ty "},
	{"T13-ni-alias-name", "ni ", "-ItemType "},
	{"T14-ni-alias-endash", "NI ", "–ItemType "},
}

// rel-1-0-10:GAP-0849 (cert L73, TST-6523: Codex strict on Windows): a
// symbolic link to a target the command computes, then a write through it,
// was blocked as persistence.ssh_authorized_keys_command in the -ItemType
// spelling and allowed in the -ty, en dash and -ItemType: spellings. A
// PowerShell script whose first statement the shell parser cannot read (the
// cert form: an assignment from a parenthesized expression) was read for
// links by the literal -ItemType text alone. Every row here is a GAP-0749
// row of TestGAP0749PowerShellLinkAndMoveAreNotAKeyWrite (or that row after
// such a first statement), sent through the Windows hook routes of Claude
// Code (PowerShell tool), Codex (shell_command) and Copilot (powershell), per
// user and as a managed peer, in all five tiers. Every spelling of a row gets
// the verdict and the rules of the plain spelling; on a Windows host the
// link rows block and the file and folder rows allow, as on rel.
func TestGAP0849NewItemSpellingsGetThePlainVerdict(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), filepath.Join(proj, "uuid")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(home, ".defenseclaw", "config.yaml")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sep := string(filepath.Separator)
	rel := func(name string) string { return "." + sep + name }
	abs := func(name string) string { return filepath.Join(proj, name) }
	newLink := func(name, target string) string {
		return fmt.Sprintf("New-Item -ItemType SymbolicLink -Path %s -Target %s", name, target)
	}
	// computed is the cert form's first statement: the shell parser cannot
	// read it, and it computes the link target.
	const computed = `$t = Join-Path $env:TEMP ("gap0849-" + [guid]::NewGuid()); `
	const keysRule = "persistence.ssh_authorized_keys_command"
	windows := runtime.GOOS == "windows"
	rows := []struct {
		name, command string
		// link: on a Windows host the row blocks with keysRule in every tier;
		// benign: it allows with no rule on every host.
		link, benign bool
	}{
		{"link to a dynamic target, write through it", newLink(abs("link"), "$env:GAP0749") + "; Add-Content " + abs("link") + " marker", true, false},
		{"computed target, relative link, write through it", computed + newLink(rel("lnk"), "$t") + "; Add-Content " + rel("lnk") + " marker", true, false},
		{"computed first statement, link to the keys file, write through it", computed + newLink(abs("link"), keys) + "; Add-Content " + abs("link") + " marker", true, false},
		{"link to the keys file, write through it", newLink(abs("link"), keys) + "; Add-Content " + abs("link") + " marker", true, false},
		{"link inside the project, write through it", newLink(abs("link"), abs("uuid")) + "; Add-Content " + abs("link") + " marker", false, false},
		{"a folder and a file, no link", "New-Item -ItemType Directory -Path " + abs("d") + "; New-Item -ItemType File -Path " + abs("d") + sep + "f", false, true},
		{"computed first statement, a folder, a write in it", computed + "New-Item -ItemType Directory -Path " + rel("d") + "; Add-Content " + rel("d") + sep + "f.txt marker", false, true},
		{"computed first statement, a file, a write to it", computed + "New-Item -ItemType File -Path " + rel("f.txt") + "; Add-Content " + rel("f.txt") + " marker", false, true},
	}
	spell := func(command string, spelling struct{ id, newItem, itemType string }) string {
		return strings.ReplaceAll(strings.ReplaceAll(command, "-ItemType ", spelling.itemType), "New-Item ", spelling.newItem)
	}
	for _, connector := range []string{"claudecode", "codex", "copilot"} {
		for _, cell := range []string{"default", "permissive", "strict", "managed", "managed-strict"} {
			posture, managed := cell, false
			switch cell {
			case "managed":
				posture, managed = "default", true
			case "managed-strict":
				posture, managed = "strict", true
			}
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s %s %s", connector, cell, row.name), func(t *testing.T) {
					plainAction, plainRules := powerShellProtectedRoute(t, home, proj, connector, posture, managed, row.command)
					slices.Sort(plainRules)
					switch {
					case row.benign && (plainAction != "allow" || len(plainRules) != 0):
						t.Fatalf("plain: action %q rules %v, want allow with no rule", plainAction, plainRules)
					case row.link && windows && (plainAction != "block" || !slices.Contains(plainRules, keysRule)):
						t.Fatalf("plain: action %q rules %v, want block with %s", plainAction, plainRules, keysRule)
					}
					for _, spelling := range gap0849ItemTypeSpellings {
						command := spell(row.command, spelling)
						action, rules := powerShellProtectedRoute(t, home, proj, connector, posture, managed, command)
						slices.Sort(rules)
						if action != plainAction || !slices.Equal(rules, plainRules) {
							t.Errorf("%s: action %q rules %v, want the plain spelling's %q %v", spelling.id, action, rules, plainAction, plainRules)
						}
					}
				})
			}
		}
	}
}
