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

func TestCaseFoldingHostLinkToACredentialFileBelowAParentGetsTheVerdictOfItsName(t *testing.T) {
	withPathCaseFoldHost(t, true)
	root := t.TempDir()
	home := filepath.Join(root, "Users", "fixture")
	project := filepath.Join(root, "project")
	for _, dir := range []string{home, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(home, ".netrc")
	ordinary := filepath.Join(project, "notes.txt")
	for file, content := range map[string]string{protected: "machine example.invalid\n", ordinary: "notes"} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linked, benign := filepath.Join(project, "linked.txt"), filepath.Join(project, "ordinary-link.txt")
	if err := os.Symlink(protected, linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ordinary, benign); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "case-fold-nested-home-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		verdict := func(file string) (string, map[string]bool) {
			raw, err := json.Marshal(pathCaseFileCall("Write", file))
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Write", Args: raw, CWD: project, ActiveHome: "/Users/alice"}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
			})
			rules := make(map[string]bool)
			for _, finding := range findings {
				rules[finding.RuleID] = true
			}
			return buildVerdict(findings, "tool_call").Action, rules
		}
		directAction, directRules := verdict(protected)
		if !directRules["PATH-NETRC"] {
			t.Fatalf("%s: the direct name matches %v, want PATH-NETRC", profile, directRules)
		}
		if action, rules := verdict(linked); action != directAction || !rules["PATH-NETRC"] {
			t.Errorf("%s: link to the credential file = %s %v, want %s with PATH-NETRC", profile, action, rules, directAction)
		}
		if action, rules := verdict(benign); action != "allow" {
			t.Errorf("%s: link to an ordinary file = %s %v, want allow", profile, action, rules)
		}
	}
}
