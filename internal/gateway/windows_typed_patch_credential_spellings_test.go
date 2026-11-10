// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsPatchVerdictIn is the verdict of a typed Codex apply_patch that
// writes or deletes file, called from the working directory cwd.
func windowsPatchVerdictIn(t *testing.T, connector, directive, home, cwd, file string) (string, map[string]bool) {
	t.Helper()
	body := ""
	if directive == "Add File" {
		body = "+# note\n"
	}
	raw, err := json.Marshal(map[string]string{"input": "*** Begin Patch\n*** " + directive + ": " + file + "\n" + body + "*** End Patch"})
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

// A typed apply_patch target that Windows opens as a credential file of the
// user's home gets the verdict of the plain drive path, in every profile and
// from any working directory: the extended-length and device forms, and the
// admin share of this machine under localhost, a loopback address or the
// machine name, bare or below \\?\UNC\, with either separator.
func TestWindowsTypedPatchOfCredentialFileIsJudgedInEverySpellingWindowsOpens(t *testing.T) {
	useShortNames(t, map[string]string{"NETRC~1": ".netrc", "R109YW~1": "r109yws.d-2"})
	// The typed patch reader and the path rules name this machine the same way.
	windowsLocalHostname = os.Hostname
	machine, err := os.Hostname()
	if err != nil || machine == "" {
		t.Skip("this machine has no name")
	}
	const home = `C:\Users\r109yws.d-2`
	files := []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`, `.NETRC`}
	spellings := []string{
		`\\?\` + home + `\`, `\\.\` + home + `\`, `\\?\C:\Users\R109YW~1\`,
		`\\localhost\c$\Users\r109yws.d-2\`, `\\LOCALHOST\C$\Users\r109yws.d-2\`,
		`\\127.0.0.1\C$\Users\r109yws.d-2\`, `\\::1\c$\Users\r109yws.d-2\`,
		`\\0--1.ipv6-literal.net\c$\Users\r109yws.d-2\`, `\\` + machine + `\c$\Users\r109yws.d-2\`,
		`\\?\UNC\localhost\c$\Users\r109yws.d-2\`, `\\?\UNC\127.0.0.1\C$\Users\r109yws.d-2\`,
		`\\localhost/c$/Users/r109yws.d-2/`,
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-typed-patch-spellings-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		// Win32 reads no slash as a separator after the exact prefix, so this
		// is no spelling of the file; a write of it still gets the finding the
		// file gets.
		if action, rules := windowsPatchVerdictIn(t, connector, "Add File", home, home+`\project`, `\\?\C:/Users/r109yws.d-2/.netrc`); action != "block" {
			t.Errorf("%s: slashes after the extended-length prefix: %s %v, want block", profile, action, rules)
		}
		for _, file := range files {
			for _, directive := range []string{"Add File", "Delete File"} {
				plainAction, plainRules := windowsPatchVerdictIn(t, connector, directive, home, home+`\project`, home+`\`+file)
				// A write is judged in every profile; a delete of the plain name
				// may be an ordinary action in a profile, and its spellings then are.
				if directive == "Add File" && (len(plainRules) == 0 || plainAction == "allow") {
					t.Fatalf("%s: plain %s %s: %s %v, want a finding", profile, directive, file, plainAction, plainRules)
				}
				for _, prefix := range spellings {
					for _, cwd := range []string{home + `\project`, `C:\work`, `D:\work`} {
						target := prefix + file
						action, rules := windowsPatchVerdictIn(t, connector, directive, home, cwd, target)
						if action != plainAction || !sameRules(ownerKeys(rules), ownerKeys(plainRules)) {
							t.Errorf("%s %s cwd=%q %q: %s %v, want %s %v", profile, directive, cwd, target, action, rules, plainAction, plainRules)
						}
					}
				}
			}
		}
	}
}

// Ordinary files in those spellings stay allowed, and so does a patch of a
// file on another host's share, which names no file of this machine.
func TestWindowsTypedPatchOfOrdinaryFileStaysAllowedInEverySpelling(t *testing.T) {
	useShortNames(t, map[string]string{"R109YW~1": "r109yws.d-2"})
	const home = `C:\Users\r109yws.d-2`
	const connector = "windows-typed-patch-spellings-ordinary"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, target := range []string{
		`\\?\` + home + `\project\main.go`, `\\.\` + home + `\notes.txt`, `\\localhost\c$\Users\r109yws.d-2\notes.txt`,
		`\\127.0.0.1\c$\Users\r109yws.d-2\project\README.md`, `\\::1\c$\work\main.go`,
		`\\?\UNC\localhost\c$\work\main.go`, `\\?\` + home + `\.netrc.bak`, `\\localhost\c$\Users\r109yws.d-2\.aws\credentials.example`,
		`\\?\C:\work\.netrc`, `\\localhost\c$\ProgramData\.aws\credentials`,
	} {
		for _, directive := range []string{"Add File", "Delete File"} {
			if action, rules := windowsPatchVerdictIn(t, connector, directive, home, home+`\project`, target); action != "allow" {
				t.Errorf("%s %q: %s %v, want allow", directive, target, action, rules)
			}
		}
	}
}
