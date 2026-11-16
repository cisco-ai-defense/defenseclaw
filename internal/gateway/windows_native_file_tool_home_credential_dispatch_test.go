// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsFileToolVerdict runs a native Windows file tool call through the
// trusted dispatch exactly as the hook sends it: the raw tool arguments are
// the call text, and the active home is the one the hook reports.
func windowsFileToolVerdict(t *testing.T, connector, tool, home, file string) (string, map[string]bool) {
	t.Helper()
	args := map[string]string{"file_path": file}
	switch tool {
	case "Write":
		args["content"] = "# note"
	case "Edit":
		args["old_string"], args["new_string"] = "before", "after"
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: tool, Args: raw, CWD: home + `\project`, ActiveHome: home}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// A native Write or Edit of a credential file in the Windows home of the user
// gets the verdict of the same name elsewhere, whether the tool spells the
// path with backslashes (escaped in the call text) or with slashes, in every
// profile and for any account-name shape.
func TestWindowsNativeFileToolWriteOfActiveHomeCredentialFileIsJudgedInEverySpelling(t *testing.T) {
	homes := []string{`C:\Users\alice`, `C:\Users\alice.smith`, `C:\Users\dc-user`, `c:\users\ALICE.SMITH`, `D:\Profiles\bob`}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-home-credential-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, home := range homes {
			for _, credential := range windowsHomeCredentialFiles {
				for _, tool := range []string{"Write", "Edit"} {
					rel := credential.rel
					// The slash spelling is judged by the path rules as they
					// read it; the backslash spelling must get the same verdict.
					slashAction, slashRules := windowsFileToolVerdict(t, connector, tool, home, home+"/"+rel)
					action, rules := windowsFileToolVerdict(t, connector, tool, home, home+`\`+strings.ReplaceAll(rel, "/", `\`))
					if len(rules) == 0 || action != slashAction || !sameRules(rules, slashRules) {
						t.Errorf("%s %s home=%q %s: backslash %s %v, slash %s %v", profile, tool, home, rel, action, rules, slashAction, slashRules)
					}
					if credential.rule == "PATH-NETRC" && (action != "block" || !rules[credential.rule]) {
						t.Errorf("%s %s home=%q %s: %s %v, want block by %s", profile, tool, home, rel, action, rules, credential.rule)
					}
				}
			}
		}
	}
}

func sameRules(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if !b[id] {
			return false
		}
	}
	return true
}

// Ordinary files in the same home, text that merely names a credential path,
// a read of the credential file and a write in another user's home keep the
// verdict they had: allowed, allowed, never blocked, and that of the name.
func TestWindowsNativeFileToolNeighboursOfActiveHomeCredentialFileKeepTheirVerdict(t *testing.T) {
	const connector = "windows-native-home-credential-neighbours"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home := `C:\Users\alice.smith`
	for _, ordinary := range []string{`notes.txt`, `.netrc.example`, `.npmrc.bak`, `project\netrc.md`} {
		for _, tool := range []string{"Write", "Edit"} {
			if action, rules := windowsFileToolVerdict(t, connector, tool, home, home+`\`+ordinary); action != "allow" {
				t.Errorf("%s of %s: %s %v, want allow", tool, ordinary, action, rules)
			}
		}
	}
	for _, content := range []string{`reference C:/Users/alice.smith/.netrc`, `reference C:\Users\alice.smith\.netrc`} {
		raw, _ := json.Marshal(map[string]string{"file_path": home + `\project\notes.txt`, "content": content})
		input := actionfacts.Input{Tool: "Write", Args: raw, CWD: home + `\project`, ActiveHome: home}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
		})
		if action := buildVerdict(findings, "tool_call").Action; action != "allow" {
			t.Errorf("notes mentioning %q: %s %v, want allow", content, action, FindingStrings(findings))
		}
	}
	for _, file := range []string{home + `\.netrc`, home + `\.aws\credentials`} {
		if action, _ := windowsFileToolVerdict(t, connector, "Read", home, file); action == "block" {
			t.Errorf("Read of %s blocked, want the alert it had", file)
		}
	}
	for _, file := range []string{`C:\Users\alice.smith2\notes.txt`, `C:\Users\other\notes.txt`} {
		if action, rules := windowsFileToolVerdict(t, connector, "Write", home, file); action != "allow" {
			t.Errorf("Write of %s: %s %v, want allow", file, action, rules)
		}
	}
}
