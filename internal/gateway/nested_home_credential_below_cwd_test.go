// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// hostFixturePath spells a fixture path written as /Users/alice/x or Users/alice/x
// the way this host spells it: a Windows host reads a rooted path only with a
// drive letter and uses backslashes, so the same fixture is the home and the
// project of a Windows user there.
func hostFixturePath(path string) string {
	if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") {
		path = "C:" + path
	}
	return filepath.FromSlash(path)
}

// nestedHomeVerdict is the action and rules of one typed call (a Claude Code
// Write, or a Codex apply_patch with the directive given) naming file, called
// from cwd with the given active home. Nothing is read from the file system.
func nestedHomeVerdict(t *testing.T, connector, directive, home, cwd, file string) (string, map[string]bool) {
	t.Helper()
	var tool string
	var raw []byte
	var err error
	if directive == "" {
		tool = "Write"
		raw, err = json.Marshal(map[string]string{"file_path": file, "content": "# note"})
	} else {
		tool = "apply_patch"
		body := ""
		switch directive {
		case "Add File":
			body = "+# note\n"
		case "Update File":
			body = "@@\n-a\n+b\n"
		}
		raw, err = json.Marshal(map[string]string{"command": "*** Begin Patch\n*** " + directive + ": " + file + "\n" + body + "*** End Patch"})
	}
	if err != nil {
		t.Fatal(err)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: tool, Args: raw, CWD: cwd, ActiveHome: home},
		LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// A credential file in a Users or home folder of the active account is a home
// credential file wherever the folder is: below the working directory of the
// call as everywhere else (the home of the user under another parent). A
// typed apply_patch (Add, Update) and a Write get the same verdict from any
// working directory, absolute or relative to it, in every profile.
func TestNestedHomeCredentialBelowTheWorkingDirectoryIsJudgedLikeAnyOther(t *testing.T) {
	home := hostFixturePath("/Users/alice")
	cases := []struct{ relative, rule string }{
		{"Users/alice/.netrc", "PATH-NETRC"},
		{"a/b/Users/alice/.git-credentials", "PATH-GIT-CREDS"},
		{"a/Users/alice/.aws/credentials", "PATH-AWS-CREDS"},
		{"newdir/home/alice/.netrc", "PATH-NETRC"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "nested-home-below-cwd-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, cwd := range []string{hostFixturePath("/Users/alice/project"), hostFixturePath("/tmp/work"), home} {
			for _, tc := range cases {
				for _, directive := range []string{"", "Add File", "Update File"} {
					for _, file := range []string{filepath.Join(cwd, hostFixturePath(tc.relative)), hostFixturePath(tc.relative)} {
						if action, rules := nestedHomeVerdict(t, connector, directive, home, cwd, file); action != "block" || !rules[tc.rule] {
							t.Errorf("%s cwd=%s %q %q: %s %v, want a block with %s", profile, cwd, directive, file, action, rules, tc.rule)
						}
					}
				}
			}
		}
	}
}

// Ordinary files stay allowed: a copy of a credential file, a file of an
// account folder that is no credential file, and a credential file of a
// project that is in no home folder or in the home folder of another account
// (the project fixture rule: a project that keeps the homes of test accounts).
func TestNestedHomeFolderBelowTheWorkingDirectoryKeepsOrdinaryFilesAllowed(t *testing.T) {
	home, cwd := hostFixturePath("/Users/alice"), hostFixturePath("/Users/alice/project")
	for _, profile := range []string{"default", "permissive"} {
		connector := "nested-home-ordinary-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, relative := range []string{
			"Users/alice/notes.txt", "Users/alice/.netrc.bak", "Users/alice/.git-credentials.bak", "Users/alice/.aws/credentials.example",
			"Users/alice/.aws/config", "users-guide/alice/.netrc", "homework/alice/.netrc", "Users/.netrc", ".netrc", "sub/.aws/credentials",
			"Users/bob/.netrc", "home/fixture/.git-credentials", "Users/bob/.aws/credentials",
		} {
			for _, directive := range []string{"", "Add File", "Delete File"} {
				if action, rules := nestedHomeVerdict(t, connector, directive, home, cwd, filepath.Join(cwd, hostFixturePath(relative))); action != "allow" {
					t.Errorf("%s %q %q: %s %v, want allow", profile, directive, relative, action, rules)
				}
			}
		}
	}
}

// The same holds for a Windows spelling of the home and of the nested folder.
func TestNestedWindowsHomeCredentialBelowTheWorkingDirectoryIsJudgedLikeAnyOther(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	const connector = "nested-windows-home-below-cwd"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, cwd := range []string{`C:\work`, home + `\project`} {
		for _, relative := range []string{`a\Users\r109yws.d-2\.netrc`, `a\USERS\R109YWS.D-2\.NETRC`, `b\Users\r109yws.d-2\.aws\credentials`} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, cwd+`\`+relative); action != "block" {
				t.Errorf("cwd=%q %q: %s %v, want block", cwd, relative, action, rules)
			}
		}
		for _, relative := range []string{`a\Users\r109yws.d-2\notes.txt`, `home\fixture\.netrc`, `Users\bob\.netrc`} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, cwd+`\`+relative); action != "allow" {
				t.Errorf("cwd=%q %q: %s %v, want allow", cwd, relative, action, rules)
			}
		}
	}
}

// A read through a link in the project of the user reaches the credential
// file the client resolved, as a write does, on a gateway that cannot follow
// links itself: the read gets the finding of the direct name.
func TestTypedReadThroughClientResolvedLinkGetsTheFindingOfTheDirectName(t *testing.T) {
	home, project := hostFixturePath("/Users/alice"), hostFixturePath("/Users/alice/project")
	installToolCallCorpusProfileConnector(t, "typed-read-link", "default")
	read := func(path string, evidence map[string]string) map[string]bool {
		raw, err := json.Marshal(map[string]string{"file_path": path})
		if err != nil {
			t.Fatal(err)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "Read", Args: raw, CWD: project, ActiveHome: home},
			LegacyText: string(raw), Connector: "typed-read-link", EnforcementCapable: true,
			SkipLocalFilesystemResolution: true, ResolvedWriteTargets: evidence,
		})
		rules := make(map[string]bool)
		for _, finding := range findings {
			rules[finding.RuleID] = true
		}
		return rules
	}
	for _, target := range []string{
		"/Users/alice/.netrc", "/Users/alice/.git-credentials", "/Users/alice/.aws/credentials", "/private/tmp/fx/Users/alice/.netrc",
	} {
		target = hostFixturePath(target)
		link := filepath.Join(project, "lnk")
		direct := read(target, nil)
		linked := read(link, map[string]string{link: target})
		if len(direct) == 0 || !sameRules(ownerKeys(direct), ownerKeys(linked)) {
			t.Errorf("%s: direct %v, through the link %v, want the same non-empty finding", target, direct, linked)
		}
	}
	if rules := read(filepath.Join(project, "lnk"), map[string]string{filepath.Join(project, "lnk"): filepath.Join(project, "notes.txt")}); len(rules) != 0 {
		t.Errorf("a link to an ordinary file raises %v", rules)
	}
}
