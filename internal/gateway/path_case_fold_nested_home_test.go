// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// On a case-folding host the rules also read a path as given. A credential
// file in a Users/<account> folder below some parent (a temporary folder, a
// mounted volume) is not under the root of a home, so the folded spelling
// cannot tell its folder from an ordinary one; the given spelling keeps the
// verdict it always had, and a link to it gets that verdict too.
func TestCaseFoldingHostReadsAPathAsGivenToo(t *testing.T) {
	withPathCaseFoldHost(t, true)
	texts := typedTargetRuleTexts("/work/Users/fixture/.netrc", "/Users/alice", false)
	if !slices.Contains(texts, "/work/Users/fixture/.netrc") {
		t.Errorf("texts %q lack the path as given", texts)
	}
	if !slices.Contains(typedTargetRuleTexts("/Users/alice/.NETRC", "/Users/alice", false), "/Users/alice/.netrc") {
		t.Error("the folded reading of a credential file in the home is missing")
	}
	withPathCaseFoldHost(t, false)
	if texts := typedTargetRuleTexts("/work/Users/fixture/.netrc", "/Users/alice", false); len(texts) != 1 {
		t.Errorf("a case-sensitive host reads one spelling, got %q", texts)
	}
}

// caseFoldNestedVerdict is the action and the rules of a Write to file, with
// the working folder of the call and the connector profile given.
func caseFoldNestedVerdict(t *testing.T, connector, project, file string) (string, map[string]bool) {
	t.Helper()
	return caseFoldNestedVerdictInTier(t, connector, project, file, false)
}

// caseFoldNestedVerdictInTier is caseFoldNestedVerdict in the strict policy
// tier when strict is set.
func caseFoldNestedVerdictInTier(t *testing.T, connector, project, file string, strict bool) (string, map[string]bool) {
	t.Helper()
	raw, err := json.Marshal(pathCaseFileCall("Write", file))
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Write", Args: raw, CWD: project, ActiveHome: "/Users/alice"}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
		StrictPolicy: strict,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// caseFoldNestedFixture creates the file at relative below root, with its
// folders, and a link to it in a project folder; it returns both names.
func caseFoldNestedFixture(t *testing.T, root, relative string) (file, link string) {
	t.Helper()
	file = filepath.Join(root, relative)
	project := filepath.Join(root, "project")
	for _, dir := range []string{filepath.Dir(file), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, []byte("machine example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(project, "linked-"+filepath.Base(relative))
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	return file, link
}

func TestCaseFoldingHostLinkToACredentialFileBelowAParentGetsTheVerdictOfItsName(t *testing.T) {
	withPathCaseFoldHost(t, true)
	root := t.TempDir()
	project := filepath.Join(root, "project")
	protected, linked := caseFoldNestedFixture(t, root, "Users/fixture/.netrc")
	_, benign := caseFoldNestedFixture(t, root, "project/notes.txt")
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "case-fold-nested-home-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		directAction, directRules := caseFoldNestedVerdict(t, connector, project, protected)
		if !directRules["PATH-NETRC"] {
			t.Fatalf("%s: the direct name matches %v, want PATH-NETRC", profile, directRules)
		}
		if action, rules := caseFoldNestedVerdict(t, connector, project, linked); action != directAction || !rules["PATH-NETRC"] {
			t.Errorf("%s: link to the credential file = %s %v, want %s with PATH-NETRC", profile, action, rules, directAction)
		}
		if action, rules := caseFoldNestedVerdict(t, connector, project, benign); action != "allow" {
			t.Errorf("%s: link to an ordinary file = %s %v, want allow", profile, action, rules)
		}
	}
}

// The file system names a file in any letter case, at every folder of the
// path, so the spelling of the Users folder and of the credential names below
// it decide nothing: a nested path in any case, and a link to it, is judged
// as the exact-case name is.
func TestCaseFoldingHostNestedCredentialFileIsJudgedInEveryLetterCase(t *testing.T) {
	withPathCaseFoldHost(t, true)
	cases := []struct{ relative, rule string }{
		{"Users/fixture/.NETRC", "PATH-NETRC"},
		{"users/fixture/.netrc", "PATH-NETRC"},
		{"USERS/fixture/.Netrc", "PATH-NETRC"},
		{"uSeRs/Fixture/.NetRC", "PATH-NETRC"},
		{"Users/fixture/.GIT-CREDENTIALS", "PATH-GIT-CREDS"},
		{"users/fixture/.Git-Credentials", "PATH-GIT-CREDS"},
		{"users/fixture/.AWS/CREDENTIALS", "PATH-AWS-CREDS"},
		{"Users/fixture/.AWS/credentials", "PATH-AWS-CREDS"},
		{"HOME/fixture/.NETRC", "PATH-NETRC"},
		{"Home/fixture/.Netrc", "PATH-NETRC"},
		{"work/users/fixture/.netrc", "PATH-NETRC"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "case-fold-nested-case-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, tc := range cases {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			file, link := caseFoldNestedFixture(t, root, tc.relative)
			for name, target := range map[string]string{"direct": file, "link": link} {
				if action, rules := caseFoldNestedVerdict(t, connector, project, target); action == "allow" || !rules[tc.rule] {
					t.Errorf("%s %s %s: %s %v, want a block with %s", profile, tc.relative, name, action, rules, tc.rule)
				}
			}
		}
	}
}

// A name that only starts like a credential file, below a Users folder in any
// letter case, is an ordinary file: it and its link are allowed. That includes
// a copy of the AWS credentials file (credentials.bak) in the default and
// permissive tiers; the strict tier keeps such a copy protected, and the
// credentials file itself is protected in every tier (the test above). A
// template or sample (credentials.sample, credentials.example) is not a copy:
// it is allowed in every tier (rel-1-0-6:GAP-1009, substrate-1:GAP-0210).
func TestCaseFoldingHostLinkToAnOrdinaryNeighbourOfACredentialFileIsAllowed(t *testing.T) {
	withPathCaseFoldHost(t, true)
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "case-fold-nested-neighbour-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, relative := range []string{
			"Users/fixture/.netrc.bak", "users/fixture/.NETRC.old", "Users/fixture/.git-credentials.bak",
			"USERS/fixture/notes.txt", "Users/fixture/.awsnotes", "Users/fixture/.aws/config.sample",
			"users/fixture/.AWS/Credentials.Sample", "Users/fixture/.aws/credentials.example",
		} {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			file, link := caseFoldNestedFixture(t, root, relative)
			for name, target := range map[string]string{"direct": file, "link": link} {
				if action, rules := caseFoldNestedVerdict(t, connector, project, target); action != "allow" {
					t.Errorf("%s %s %s: %s %v, want allow", profile, relative, name, action, rules)
				}
			}
		}
		for _, relative := range []string{
			"Users/fixture/.aws/credentials.bak", "users/fixture/.AWS/Credentials.Bak", "Users/fixture/.aws/credentials.old",
		} {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			file, link := caseFoldNestedFixture(t, root, relative)
			for name, target := range map[string]string{"direct": file, "link": link} {
				action, rules := caseFoldNestedVerdictInTier(t, connector, project, target, profile == "strict")
				if profile == "strict" && (action != "block" || !rules["PATH-AWS-CREDS"]) {
					t.Errorf("strict %s %s: %s %v, want a block with PATH-AWS-CREDS", relative, name, action, rules)
				}
				if profile != "strict" && action != "allow" {
					t.Errorf("%s %s %s: %s %v, want allow", profile, relative, name, action, rules)
				}
			}
		}
	}
}
