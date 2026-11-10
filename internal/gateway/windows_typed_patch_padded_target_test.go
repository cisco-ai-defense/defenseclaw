// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// paddedPatchVerdictIn is the verdict of a typed Codex apply_patch of file
// under directive, with the patch in the given input field.
func paddedPatchVerdictIn(t *testing.T, connector, field, directive, home, cwd, file string) (string, map[string]bool) {
	t.Helper()
	body := ""
	switch directive {
	case "Add File":
		body = "+# note\n"
	case "Update File":
		body = "@@\n-a\n+b\n"
	}
	raw, err := json.Marshal(map[string]string{field: "*** Begin Patch\n*** " + directive + ": " + file + "\n" + body + "*** End Patch"})
	if err != nil {
		t.Fatal(err)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "apply_patch", Args: raw, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
		LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// A typed apply_patch target that ends in white space, or in dots and white
// space, opens the same file as the name without them. It gets the verdict of
// that name for Add, Update and Delete, in every profile, from the input or
// the command field; a lookalike name stays an ordinary file.
func TestWindowsTypedPatchOfCredentialFilePaddedAtTheEndIsJudgedLikeItsName(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-typed-patch-padded-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, field := range []string{"input", "command"} {
			for _, directive := range []string{"Add File", "Update File", "Delete File"} {
				for _, file := range []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`} {
					plainAction, plainRules := paddedPatchVerdictIn(t, connector, field, directive, home, home+`\project`, home+`\`+file)
					if len(plainRules) == 0 || plainAction == "allow" {
						t.Fatalf("%s %s: plain %s %s: %s %v, want a finding", profile, field, directive, file, plainAction, plainRules)
					}
					for _, prefix := range []string{home + `\`, `\\.\` + home + `\`, `//./C:/Users/r109yws.d-2/`} {
						for _, pad := range []string{" ", "  ", ". ", " . ", "\t"} {
							target := prefix + file + pad
							action, rules := paddedPatchVerdictIn(t, connector, field, directive, home, home+`\project`, target)
							if action != plainAction || !sameRules(ownerKeys(rules), ownerKeys(plainRules)) {
								t.Errorf("%s %s: %s %q: %s %v, want the verdict of the plain name: %s %v",
									profile, field, directive, target, action, rules, plainAction, plainRules)
							}
						}
					}
				}
				for _, ordinary := range []string{`.netrc.bak  `, `notes.txt  `, `project\.netrc.example. `, `.aws\credentials.example `} {
					action, rules := paddedPatchVerdictIn(t, connector, field, directive, home, home+`\project`, home+`\`+ordinary)
					if action != "allow" {
						t.Errorf("%s %s: %s %q: %s %v, want allow", profile, field, directive, ordinary, action, rules)
					}
				}
			}
		}
	}
}
