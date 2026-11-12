// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
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

// droppedCharSampleSpellings is one spelling of each position (inside the
// last name, before it, after it) with a different dropped character.
func droppedCharSampleSpellings(dir, file string) []string {
	cut := len(file) - 3
	return []string{dir + file[:cut] + "\t" + file[cut:], dir + "\r" + file, dir + file + "\t\r"}
}

// A typed apply_patch target spelled with a tab or a carriage return opens the
// file of the plain name, so it gets the verdict of that name, for Add, Update,
// Delete and Move to, in every profile and input field, on a POSIX and a
// Windows host; a lookalike or ordinary name stays an ordinary file. The first
// credential file takes every spelling, the others and the other input fields
// one of each position: the name is read by one reader whatever file or field
// it came from. The file system answers for no short name, as in the other
// Windows name tests, so the run costs no file system lookup per call.
func TestTypedPatchOfCredentialFileSpelledWithDroppedCharactersIsJudgedLikeItsName(t *testing.T) {
	useShortNames(t, map[string]string{})
	posixHome := hostFixturePath("/Users/alice")
	posixFiles := []string{".netrc", ".git-credentials", filepath.FromSlash(".aws/credentials"), filepath.FromSlash(".kube/config")}
	hosts := []struct {
		name, home, sep, cwd string
		windows              bool
		files                []string
	}{
		{"posix", posixHome, string(filepath.Separator), filepath.Join(posixHome, "project"), false, posixFiles},
		{"windows", `C:\Users\r109yws.d-2`, `\`, `C:\Users\r109yws.d-2\project`, true, []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`}},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "typed-patch-dropped-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, host := range hosts {
			verdict := func(field, directive, target string) (string, map[string]bool) {
				return droppedCharPatchVerdict(t, connector, field, directive, host.home, host.cwd, target, host.windows)
			}
			for _, field := range []string{"input", "command", "patch"} {
				for _, directive := range []string{"Add File", "Update File", "Delete File", "Move to"} {
					for i, file := range host.files {
						if field != "input" && i > 0 {
							break
						}
						plainAction, plainRules := verdict(field, directive, host.home+host.sep+file)
						if len(plainRules) == 0 || plainAction == "allow" {
							t.Fatalf("%s %s %s: plain %s %s: %s %v, want a finding", host.name, profile, field, directive, file, plainAction, plainRules)
						}
						spellings := droppedCharSampleSpellings(host.home+host.sep, file)
						if i == 0 && field == "input" {
							spellings = droppedCharSpellings(host.home+host.sep, file)
						}
						for _, target := range spellings {
							action, rules := verdict(field, directive, target)
							if action != plainAction || !sameRules(ownerKeys(rules), ownerKeys(plainRules)) {
								t.Errorf("%s %s %s: %s %q: %s %v, want the verdict of the plain name: %s %v",
									host.name, profile, field, directive, target, action, rules, plainAction, plainRules)
							}
						}
					}
					ordinaries := []string{"notes.txt", ".netrc.example", strings.Join([]string{".aws", "credentials.example"}, host.sep)}
					if field != "input" {
						ordinaries = ordinaries[:1]
					}
					for _, ordinary := range ordinaries {
						for _, target := range droppedCharSampleSpellings(host.home+host.sep+"project"+host.sep, ordinary) {
							if action, rules := verdict(field, directive, target); action != "allow" {
								t.Errorf("%s %s %s: %s %q: %s %v, want allow", host.name, profile, field, directive, target, action, rules)
							}
						}
					}
				}
			}
		}
	}
}
