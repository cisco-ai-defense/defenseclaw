// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const redirectReductionMarker = "dc-block-marker"

// installRedirectReductionRules publishes a connector generation with
// marker command rules: CRITICAL expressions over argv.
func installRedirectReductionRules(t *testing.T, connector string, rules ...PatternRule) {
	t.Helper()
	ruleCategoriesMu.Lock()
	savedCategories, hadCategories := connectorRuleCategories[connector]
	savedGeneration, hadGeneration := connectorRuleGenerations[connector]
	ruleCategoriesMu.Unlock()
	t.Cleanup(func() {
		ruleCategoriesMu.Lock()
		if hadCategories {
			connectorRuleCategories[connector] = savedCategories
		} else {
			delete(connectorRuleCategories, connector)
		}
		if hadGeneration {
			connectorRuleGenerations[connector] = savedGeneration
		} else {
			delete(connectorRuleGenerations, connector)
		}
		ruleCategoriesMu.Unlock()
	})
	generation, err := compileRulePackGeneration([]ruleCategory{{
		Name:  "test-marker",
		Rules: rules,
	}})
	if err != nil {
		t.Fatal(err)
	}
	publishConnectorRulePackOverrides(connector, generation)
}

func redirectReductionRule(id, pattern, expression string) PatternRule {
	return PatternRule{
		ID:           id,
		Pattern:      regexp.MustCompile(pattern),
		Expression:   expression,
		ToolCallOnly: true,
		Title:        "Test marker (" + id + ")",
		Severity:     "CRITICAL",
		Confidence:   1,
	}
}

func TestTrustedActionBlocksCommandRuleWithRuntimeExpandedRedirectTarget(t *testing.T) {
	const connector = "redirect-reduction-test"
	argvMarker := `f.commands.exists(c, c.argv.exists(a, a == "` + redirectReductionMarker + `"))`
	installRedirectReductionRules(t, connector,
		// The marker rule: an argv expression with a regex fallback.
		redirectReductionRule("TEST-MARKER-BLOCK", redirectReductionMarker, argvMarker),
		// A match that more redirects could undo must not count on the view.
		redirectReductionRule(
			"TEST-MARKER-NO-STDOUT-REDIRECT",
			redirectReductionMarker,
			argvMarker+` && !f.commands.exists(c, c.redirects.exists(r, r.fd == 1))`,
		),
		// The authoring guide's form: require a complete argv. A kept
		// command's argv_complete comes from a complete analysis.
		redirectReductionRule(
			"TEST-MARKER-COMPLETE-ARGV",
			redirectReductionMarker,
			`f.commands.exists(c, c.argv_complete && c.argv.exists(a, a == "`+redirectReductionMarker+`"))`,
		),
	)

	const (
		blocks        = "block"
		detectionOnly = "detection-only"
		absent        = "absent"
	)
	tests := []struct {
		name    string
		command string
		want    map[string]string
	}{
		{
			name:    "tilde target",
			command: "echo " + redirectReductionMarker + " > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			name:    "no redirect",
			command: "echo " + redirectReductionMarker,
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": blocks, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// An expanding argument is not reduced: the argv is not static.
			name:    "expanding argument",
			command: "echo " + redirectReductionMarker + " $SUFFIX > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// A command after && might not run, so a match on it stays
			// detection-only.
			name:    "chained command",
			command: "cd /tmp && echo " + redirectReductionMarker + " > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// The first command of an && or || list always runs, so rules
			// decide on the list's unconditional commands. A rule that
			// negates over commands does not: a left-out command might run.
			name:    "first command of an && list",
			command: "echo " + redirectReductionMarker + " && echo done",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var recorded actionfacts.Facts
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "/home/alice/project",
					ActiveHome:  "/home/alice",
					DialectHint: actionfacts.DialectPOSIX,
				},
				LegacyText:         test.command,
				Connector:          connector,
				EnforcementCapable: true,
				record: func(facts actionfacts.Facts, _ []RuleFinding) {
					recorded = facts
				},
			})
			for ruleID, want := range test.want {
				finding := findingWithID(findings, ruleID)
				got := absent
				if finding != nil {
					got = detectionOnly
					if finding.contributesToEnforcement() {
						got = blocks
					}
				}
				if got != want {
					t.Errorf("%s = %s, want %s; findings=%v", ruleID, got, want, FindingStrings(findings))
				}
			}
			verdict := buildVerdict(findings, "tool_call")
			wantAction := guardrailActionAllow
			if test.want["TEST-MARKER-BLOCK"] == blocks {
				wantAction = guardrailActionBlock
			}
			if verdict.Action != wantAction {
				t.Errorf("verdict = %q, want %q; findings=%v", verdict.Action, wantAction, FindingStrings(findings))
			}
			// The audit keeps the facts of the whole action, not the view.
			if recorded.Commands == nil {
				t.Fatal("dispatch did not record the action facts")
			}
			for _, command := range recorded.Commands {
				for _, redirect := range command.Redirects {
					if redirect.Expands && recorded.Authoritative() {
						t.Fatalf("recorded facts were replaced by the reduced view: %+v", recorded.Parse)
					}
				}
			}
		})
	}
}

// A rule that negates over commands or operations must decide on the facts
// a complete analysis derives. The first view of a runtime-expanded
// redirect target kept the partial parse's commands, which had skipped
// wrapper expansion (sudo, sh -c) and the redirect's write operation, and
// only reset argv_complete: so `sudo systemctl status sshd > ~/x.txt` had no
// systemctl child and was blocked by a rule that allows it with any static
// target. The view is now the complete analysis of a static-target twin.
func TestTrustedActionRedirectReductionDecidesNegationOnCompleteFacts(t *testing.T) {
	const connector = "redirect-reduction-negation-test"
	const write = "defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_WRITE"
	installRedirectReductionRules(t, connector,
		redirectReductionRule("CUSTOM-SUDO-NOT-SYSTEMCTL", `a^`,
			`f.commands.exists(c, c.program == "sudo") && !f.commands.exists(c, c.program == "systemctl")`),
		redirectReductionRule("CUSTOM-BASH-NOT-GIT", `a^`,
			`f.commands.exists(c, c.program == "bash") && !f.commands.exists(c, c.program == "git")`),
		redirectReductionRule("CUSTOM-ECHO-WITHOUT-WRITE", `a^`,
			`f.commands.exists(c, c.program == "echo") && !f.commands.exists(c, `+write+` in c.operations)`),
	)
	tests := []struct {
		name    string
		command string
		// blocked lists the rules that block; every other rule is absent.
		blocked []string
	}{
		{name: "sudo systemctl, tilde target", command: "sudo systemctl status sshd > ~/x.txt"},
		{name: "sudo systemctl, static target", command: "sudo systemctl status sshd > /tmp/x.txt"},
		{name: "sudo systemctl, no redirect", command: "sudo systemctl status sshd"},
		{name: "sudo id, tilde target", command: "sudo id > ~/x.txt", blocked: []string{"CUSTOM-SUDO-NOT-SYSTEMCTL"}},
		{name: "bash git, tilde target", command: "bash -c 'git status' > ~/x.txt"},
		{name: "bash git, static target", command: "bash -c 'git status' > /tmp/x.txt"},
		{name: "echo, tilde target", command: "echo hi > ~/x.txt"},
		{name: "echo, HOME target", command: "echo hi > $HOME/x.txt"},
		{name: "echo, no redirect", command: "echo hi", blocked: []string{"CUSTOM-ECHO-WITHOUT-WRITE"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "/home/alice/project",
					ActiveHome:  "/home/alice",
					DialectHint: actionfacts.DialectPOSIX,
				},
				LegacyText:         test.command,
				Connector:          connector,
				EnforcementCapable: true,
			})
			want := map[string]bool{}
			for _, id := range test.blocked {
				want[id] = true
			}
			for _, id := range []string{"CUSTOM-SUDO-NOT-SYSTEMCTL", "CUSTOM-BASH-NOT-GIT", "CUSTOM-ECHO-WITHOUT-WRITE"} {
				finding := findingWithID(findings, id)
				blocks := finding != nil && finding.contributesToEnforcement()
				if blocks != want[id] || (finding != nil && !blocks) {
					t.Errorf("%s: finding=%v blocks=%t, want blocks=%t; findings=%v", id, finding != nil, blocks, want[id], FindingStrings(findings))
				}
			}
			wantAction := guardrailActionAllow
			if len(test.blocked) > 0 {
				wantAction = guardrailActionBlock
			}
			if verdict := buildVerdict(findings, "tool_call"); verdict.Action != wantAction {
				t.Errorf("verdict = %q, want %q; findings=%v", verdict.Action, wantAction, FindingStrings(findings))
			}
		})
	}
}
