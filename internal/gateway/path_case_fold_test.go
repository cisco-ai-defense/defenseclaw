// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func withPathCaseFoldHost(t *testing.T, fold bool) {
	t.Helper()
	saved := pathCaseFoldHost
	pathCaseFoldHost = fold
	t.Cleanup(func() { pathCaseFoldHost = saved })
}

// pathCaseVerdict runs one tool call through the trusted dispatch as the hook
// sends it and returns the action and the rules that fired.
func pathCaseVerdict(t *testing.T, connector, tool, home string, args map[string]string) (string, map[string]bool) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: tool, Args: raw, CWD: home + "/project", ActiveHome: home}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

func pathCaseFileCall(tool, file string) map[string]string {
	if tool == "Write" {
		return map[string]string{"file_path": file, "content": "# note"}
	}
	return map[string]string{"file_path": file, "old_string": "before", "new_string": "after"}
}

// caseVariantSpellings are other letter cases of the credential files the
// path rules name, as a case-insensitive file system reads them.
var caseVariantSpellings = map[string][]string{
	".netrc":              {".NETRC", ".NetRc"},
	".git-credentials":    {".GIT-CREDENTIALS", ".Git-Credentials"},
	".aws/credentials":    {".AWS/CREDENTIALS", ".Aws/Credentials"},
	".kube/config":        {".KUBE/CONFIG"},
	".docker/config.json": {".Docker/Config.JSON"},
	".npmrc":              {".NPMRC"},
	".pypirc":             {".PyPiRC"},
}

// On a host whose file system names a file in any letter case, a native Write
// or Edit of a credential file gets the verdict of the exact-case spelling,
// in every profile, for a home of any shape, written with ~ or in full, and
// whatever the letter case of the home folders.
func TestCaseFoldingHostJudgesTypedCredentialFileWriteInAnyLetterCase(t *testing.T) {
	withPathCaseFoldHost(t, true)
	homes := []string{"/Users/alice", "/Users/alice.smith", "/Users/dc-user"}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "case-fold-host-typed-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, home := range homes {
			for _, credential := range credentialFileSpellings {
				exactAction, exactRules := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", home+"/"+credential.rel))
				if !exactRules[credential.rule] {
					t.Fatalf("%s home=%q: exact-case write of %s matches %v, want %s", profile, home, credential.rel, exactRules, credential.rule)
				}
				for _, name := range caseVariantSpellings[credential.rel] {
					for _, base := range []string{home, "~", strings.ToUpper(home[:len("/Users")]) + home[len("/Users"):], strings.ToLower(home)} {
						for _, tool := range []string{"Write", "Edit"} {
							file := base + "/" + name
							action, rules := pathCaseVerdict(t, connector, tool, home, pathCaseFileCall(tool, file))
							if action != exactAction || !sameRules(rules, exactRules) {
								t.Errorf("%s %s home=%q file=%q: %s %v, want %s %v", profile, tool, home, file, action, rules, exactAction, exactRules)
							}
						}
					}
				}
			}
		}
	}
}

// A shell command that reads or writes a credential file is judged the same
// in any letter case of the file name, as the file system reads it.
func TestCaseFoldingHostJudgesShellCredentialFileAccessInAnyLetterCase(t *testing.T) {
	withPathCaseFoldHost(t, true)
	const home = "/Users/alice"
	for _, profile := range []string{"default", "strict"} {
		connector := "case-fold-host-shell-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, template := range []string{"cat %s", "echo token >> %s", "cp %s /tmp/copy"} {
			for _, credential := range credentialFileSpellings {
				exactAction, exactRules := pathCaseVerdict(t, connector, "Bash", home, map[string]string{"command": strings.Replace(template, "%s", "~/"+credential.rel, 1)})
				for _, name := range caseVariantSpellings[credential.rel] {
					command := strings.Replace(template, "%s", "~/"+name, 1)
					action, rules := pathCaseVerdict(t, connector, "Bash", home, map[string]string{"command": command})
					if action != exactAction || !sameRules(rules, exactRules) {
						t.Errorf("%s %q: %s %v, want %s %v", profile, command, action, rules, exactAction, exactRules)
					}
				}
			}
		}
	}
}

// A home written in another Unicode normalization form is the same folder on
// the file system, so the credential file below it gets the exact verdict.
func TestCaseFoldingHostJudgesCredentialFileUnderADecomposedHome(t *testing.T) {
	withPathCaseFoldHost(t, true)
	const home = "/Users/Émile.d"
	connector := "case-fold-host-normalization"
	installToolCallCorpusProfileConnector(t, connector, "default")
	exactAction, exactRules := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", home+"/.netrc"))
	if exactAction != "block" || !exactRules["PATH-NETRC"] {
		t.Fatalf("exact write: %s %v, want block by PATH-NETRC", exactAction, exactRules)
	}
	for _, file := range []string{
		"/Users/Émile.d/.netrc",
		"/Users/Émile.d/.NETRC",
		"/USERS/émile.d/.NETRC",
		"/Users/émile.d/.NetRc",
	} {
		action, rules := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", file))
		if action != exactAction || !sameRules(rules, exactRules) {
			t.Errorf("%q: %s %v, want %s %v", file, action, rules, exactAction, exactRules)
		}
	}
}

// Look-alike names stay what they were: the verdict of a name that is not a
// credential file does not change with the host, in any letter case.
func TestCaseFoldingHostKeepsOrdinaryNeighboursOfCredentialFilesAllowed(t *testing.T) {
	const home = "/Users/alice"
	neighbours := []string{
		home + "/.netrc.bak", home + "/.NETRC.BAK", home + "/Projects/Netrc.go", home + "/NOTES/.NPMRC-notes.md",
		home + "/project/.Aws/readme.txt", home + "/Documents/Credentials.txt", "/tmp/Data/Config",
	}
	connector := "case-fold-host-neighbours"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, file := range neighbours {
		// The twin spelled in lower case is the verdict any host gives it.
		withPathCaseFoldHost(t, false)
		wantAction, _ := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", strings.ToLower(file)))
		withPathCaseFoldHost(t, true)
		action, _ := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", file))
		if action != wantAction || action != "allow" {
			t.Errorf("%q: %s, want %s (allow)", file, action, wantAction)
		}
	}
}

// A host with a case-sensitive file system keeps the spelling it was given: a
// different case is a different file there.
func TestCaseSensitiveHostKeepsLetterCaseOfCredentialFileNames(t *testing.T) {
	withPathCaseFoldHost(t, false)
	const home = "/Users/alice"
	connector := "case-sensitive-host"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, file := range []string{home + "/.NETRC", "~/.GIT-CREDENTIALS", home + "/.AWS/CREDENTIALS"} {
		action, rules := pathCaseVerdict(t, connector, "Write", home, pathCaseFileCall("Write", file))
		if action != "allow" || len(rules) != 0 {
			t.Errorf("%q: %s %v, want allow with no rule", file, action, rules)
		}
	}
}
