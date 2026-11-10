// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// droppedCharPatchVerdict is the verdict of a typed Codex apply_patch of file
// under directive ("Move to" moves a project file to it), with the patch in
// the given input field, on a Windows host or a POSIX one.
func droppedCharPatchVerdict(t *testing.T, connector, field, directive, home, cwd, file string, windows bool) (string, map[string]bool) {
	t.Helper()
	patch := "*** Begin Patch\n*** " + directive + ": " + file + "\n*** End Patch"
	switch directive {
	case "Add File":
		patch = "*** Begin Patch\n*** Add File: " + file + "\n+# note\n*** End Patch"
	case "Update File":
		patch = "*** Begin Patch\n*** Update File: " + file + "\n@@\n-a\n+b\n*** End Patch"
	case "Move to":
		patch = "*** Begin Patch\n*** Update File: old.txt\n*** Move to: " + file + "\n@@\n-a\n+b\n*** End Patch"
	}
	raw, err := json.Marshal(map[string]string{field: patch})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "apply_patch", Args: raw, CWD: cwd, ActiveHome: home}
	if windows {
		input.DialectHint = actionfacts.DialectPowerShell
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// droppedCharSpellings are the spellings of a target that the patch tool opens
// as the plain name: a tab or a carriage return inside the last name, before
// it, or after it.
func droppedCharSpellings(dir, file string) []string {
	var out []string
	for _, drop := range []string{"\t", "\r", "\t\r"} {
		cut := len(file) - 3
		out = append(out, dir+file[:cut]+drop+file[cut:], dir+drop+file, dir+file+drop)
	}
	return out
}

// A typed apply_patch target spelled with a tab or a carriage return opens the
// file of the plain name, so it gets the verdict of that name, for Add, Update,
// Delete and Move to, in every profile and input field, on a POSIX and a
// Windows host; a lookalike or ordinary name stays an ordinary file.
func TestTypedPatchOfCredentialFileSpelledWithDroppedCharactersIsJudgedLikeItsName(t *testing.T) {
	for _, host := range []struct {
		name, home, sep, cwd string
		windows              bool
		files                []string
	}{
		{"posix", "/Users/alice", "/", "/Users/alice/project", false, []string{".netrc", ".git-credentials", ".aws/credentials", ".kube/config"}},
		{"windows", `C:\Users\r109yws.d-2`, `\`, `C:\Users\r109yws.d-2\project`, true, []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`}},
	} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			connector := "typed-patch-dropped-" + host.name + "-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, field := range []string{"input", "command", "patch"} {
				for _, directive := range []string{"Add File", "Update File", "Delete File", "Move to"} {
					for _, file := range host.files {
						plainAction, plainRules := droppedCharPatchVerdict(t, connector, field, directive, host.home, host.cwd, host.home+host.sep+file, host.windows)
						if len(plainRules) == 0 || plainAction == "allow" {
							t.Fatalf("%s %s %s: plain %s %s: %s %v, want a finding", host.name, profile, field, directive, file, plainAction, plainRules)
						}
						for _, target := range droppedCharSpellings(host.home+host.sep, file) {
							action, rules := droppedCharPatchVerdict(t, connector, field, directive, host.home, host.cwd, target, host.windows)
							if action != plainAction || !sameRules(ownerKeys(rules), ownerKeys(plainRules)) {
								t.Errorf("%s %s %s: %s %q: %s %v, want the verdict of the plain name: %s %v",
									host.name, profile, field, directive, target, action, rules, plainAction, plainRules)
							}
						}
					}
					for _, ordinary := range []string{"notes.txt", "main.go", ".netrc.example", strings.Join([]string{".aws", "credentials.example"}, host.sep)} {
						for _, target := range droppedCharSpellings(host.home+host.sep+"project"+host.sep, ordinary) {
							if action, rules := droppedCharPatchVerdict(t, connector, field, directive, host.home, host.cwd, target, host.windows); action != "allow" {
								t.Errorf("%s %s %s: %s %q: %s %v, want allow", host.name, profile, field, directive, target, action, rules)
							}
						}
					}
				}
			}
		}
	}
}
