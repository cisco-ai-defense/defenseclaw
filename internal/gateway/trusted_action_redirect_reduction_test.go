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
	"strings"
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
		// An expanded word may be any argument, so negation over argv is unsafe.
		redirectReductionRule(
			"TEST-MARKER-NOT-N",
			redirectReductionMarker,
			`f.commands.exists(c, "`+redirectReductionMarker+`" in c.argv && !c.argv.exists(a, a == "-n"))`,
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
			// A lone command's "~/" target resolves in the trusted home
			// (GAP-1666), so the analysis is complete and sees the redirect.
			name:    "tilde target",
			command: "echo " + redirectReductionMarker + " > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": absent, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// GAP-0029: a parameter after a static directory is a file path.
			name:    "static directory target with a parameter",
			command: "echo " + redirectReductionMarker + " > /tmp/dc-x-$USER.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// GAP-0029: the static echo runs whatever the runtime-expanded
			// words elsewhere expand to, so a rule over its argv blocks.
			name:    "command substitution in the target",
			command: "echo " + redirectReductionMarker + " > /var/tmp/dc-x-$(id -u).txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			name:    "PWD target",
			command: "echo " + redirectReductionMarker + " > $PWD/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			name:    "expansion in another command of the pipeline",
			command: "echo " + redirectReductionMarker + " | tee /var/tmp/dc-x-$USER.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// A runtime cd or a function could change what the echo runs.
			name:    "after a runtime-expanded cd",
			command: "cd $DIR; echo " + redirectReductionMarker + " > $PWD/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			name:    "after a function definition",
			command: "echo() { :; }; echo " + redirectReductionMarker + " > $PWD/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			name:    "no redirect",
			command: "echo " + redirectReductionMarker,
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": blocks, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// GAP-0029: a runtime-expanded argument becomes zero or more
			// words, so the static marker is still an argument of echo. Its
			// argv is not complete.
			name:    "expanding argument",
			command: "echo " + redirectReductionMarker + " $USER > /var/tmp/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly, "TEST-MARKER-NOT-N": detectionOnly},
		},
		{
			name:    "quoted expanding argument",
			command: "echo " + redirectReductionMarker + ` "$USER" > /var/tmp/dc-x.txt`,
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			name:    "expanding argument and target",
			command: "echo " + redirectReductionMarker + " $USER > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// The program itself expands: nothing certain runs.
			name:    "expanding program",
			command: "$CMD " + redirectReductionMarker,
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// A runtime-expanded export could change what echo runs.
			name:    "after a runtime-expanded export",
			command: "export PATH=$DIR; echo " + redirectReductionMarker + " $USER",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// A list is judged as if every command runs; its runtime-expanded
			// target is left out as for a single command.
			name:    "chained command",
			command: "cd /tmp && echo " + redirectReductionMarker + " > ~/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// A block stops the whole call, so a command after && or || is
			// judged as if it runs.
			name:    "command after && and ||",
			command: "cd /tmp && echo " + redirectReductionMarker + " || true",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": blocks, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// A rule that negates over commands decides on every command of
			// the list, as for the same commands joined by ";": a later
			// command's redirect turns it off.
			name:    "negation over a later command",
			command: "echo " + redirectReductionMarker + " && echo done > /tmp/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": absent, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			// A list in the background is not reduced.
			name:    "background list",
			command: "cd /tmp && echo " + redirectReductionMarker + " &",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			// GAP-0029: an && or || list member with a runtime-expanded
			// argument is judged as the same list with static words is.
			name:    "expanding argument first in an && list",
			command: "echo " + redirectReductionMarker + " $USER && echo done",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-COMPLETE-ARGV": detectionOnly, "TEST-MARKER-NOT-N": detectionOnly},
		},
		{
			name:    "expanding argument after && with a target",
			command: "true && echo " + redirectReductionMarker + " $USER > /var/tmp/dc-x.txt",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			name:    "expanding argument between static cd and echo",
			command: "cd /var/tmp && echo " + redirectReductionMarker + " $USER > dc-x.txt && echo done",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-COMPLETE-ARGV": detectionOnly},
		},
		{
			name:    "expanding argument after ||",
			command: "false || echo " + redirectReductionMarker + " $USER",
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks},
		},
		{
			name:    "expanding argument after a runtime cd in an && list",
			command: "cd $DIR && echo " + redirectReductionMarker + " $USER",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly},
		},
		{
			// GAP-1639: a PowerShell profile runs only before the body, so
			// the body's match counts without -NoProfile.
			name:    "pwsh -Command without -NoProfile",
			command: `pwsh -Command "echo ` + redirectReductionMarker + ` > C:/Users/alice/dc-x.txt"`,
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-NO-STDOUT-REDIRECT": detectionOnly, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			name:    "powershell -NoLogo -Command without -NoProfile",
			command: `powershell -NoLogo -Command "echo ` + redirectReductionMarker + `"`,
			want:    map[string]string{"TEST-MARKER-BLOCK": blocks, "TEST-MARKER-COMPLETE-ARGV": blocks},
		},
		{
			name:    "pwsh -Command in a list",
			command: `cd $DIR; pwsh -Command "echo ` + redirectReductionMarker + `"`,
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly},
		},
		{
			name:    "expanding argument under if",
			command: "if test -n \"$X\"; then echo " + redirectReductionMarker + " $USER; fi",
			want:    map[string]string{"TEST-MARKER-BLOCK": detectionOnly},
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

// TestTrustedActionCorpusBlocksWithRuntimeExpandedRedirectTarget is the
// corpus differential for built-in rules (#925): a POSIX corpus action that
// blocks with an absolute redirect target also blocks with a target the
// shell expands at run time, and one that does not block never starts to.
// It also pins the review of every built-in code prerequisite: one that
// holds on a redirect-target view and its static-target twin holds on the
// action with a concrete target too. A rule whose prerequisite needs a
// PowerShell or cmd action is inactive on the view, which is POSIX-only, and
// keeps its fallback on the whole action.
func TestTrustedActionCorpusBlocksWithRuntimeExpandedRedirectTarget(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	var posix []toolCallCorpusCase
	for _, test := range cases {
		command := strings.TrimSpace(test.Command)
		if command == "" || len(test.Argv) != 0 {
			continue
		}
		input := toolCallCorpusActionFactsInput(test)
		if test.Dialect == actionfacts.DialectPowerShell || test.Dialect == actionfacts.DialectCMD {
			input.Command = command + ` > "$HOME/out.txt"`
			if _, _, ok := actionfacts.DynamicRedirectTargetReduction(input, actionfacts.Analyze(input)); ok {
				t.Errorf("%s: %s action reduced", test.ID, test.Dialect)
			}
			continue
		}
		if strings.ContainsAny(command[len(command)-1:], `&|\`) ||
			strings.Contains(command, "<<") || strings.Contains(command, "\n") {
			continue
		}
		posix = append(posix, test)
	}

	var prerequisites []semanticOwner
	for id, owner := range semanticOwners {
		if owner.prerequisite != nil {
			owner.id = id
			prerequisites = append(prerequisites, owner)
		}
	}
	for _, test := range posix {
		base := strings.TrimSpace(test.Command)
		input := toolCallCorpusActionFactsInput(test)
		input.Command = base + " > ~/.ssh/authorized_keys"
		view, twin, ok := actionfacts.DynamicRedirectTargetReduction(input, actionfacts.Analyze(input))
		if !ok {
			continue
		}
		input.Command = base + " > " + input.ActiveHome + "/.ssh/authorized_keys"
		concrete := actionfacts.Analyze(input)
		if !concrete.Authoritative() {
			continue
		}
		for _, owner := range prerequisites {
			if owner.eligible(view) && owner.eligible(twin) && !owner.eligible(concrete) {
				t.Errorf("%s: prerequisite of %s holds on the view but not on %q",
					test.ID, owner.id, input.Command)
			}
		}
	}

	const connector = "redirect-reduction-corpus"
	for _, profile := range toolCallCorpusProfiles {
		t.Run(profile, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, connector, profile)
			blocks := func(test toolCallCorpusCase, command, home string) bool {
				input := toolCallCorpusActionFactsInput(test)
				input.Command = command
				input.ActiveHome = home
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:              input,
					LegacyText:         command,
					Connector:          connector,
					EnforcementCapable: true,
				})
				return buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			}
			for _, test := range posix {
				base := strings.TrimSpace(test.Command)
				for _, home := range []string{"/home/alice", ""} {
					want := blocks(test, base+" > /home/alice/out.txt", home)
					for _, target := range []string{"~/out.txt", `"$HOME/out.txt"`, "out-*.txt"} {
						if got := blocks(test, base+" > "+target, home); got != want {
							t.Errorf("%s home=%q target %s: block = %t, absolute target block = %t",
								test.ID, home, target, got, want)
						}
					}
				}
			}
		})
	}
}

// GAP-1450: OpenClaw's exec tool reaches /api/v1/inspect/tool with its
// execution controls next to the command. An argv_complete block rule must
// block the call with yieldMs as it does without.
func TestInspectToolBlocksOpenClawExecWithControls(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	installRedirectReductionRules(t, "openclaw", redirectReductionRule(
		"TEST-MARKER-BLOCK", redirectReductionMarker,
		`f.commands.exists(c, c.argv_complete && c.argv.exists(a, a == "`+redirectReductionMarker+`"))`,
	))
	for _, args := range []string{
		`{"command":"echo dc-block-marker > /tmp/dc-x.txt"}`,
		`{"command":"echo dc-block-marker > /tmp/dc-x.txt","yieldMs":10000}`,
		`{"command":"echo dc-block-marker > /tmp/dc-x.txt","timeout":30,"background":true,"workdir":"/tmp"}`,
		// GAP-1450: arguments left for the parser (env, elevated) keep the
		// call's parse partial; the command judged on its own still blocks.
		`{"command":"echo dc-block-marker > /tmp/dc-x.txt","env":{"DCX":"1"},"yieldMs":5000}`,
		`{"command":"echo dc-block-marker > /tmp/dc-x.txt","elevated":false}`,
	} {
		_, verdict := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","args":`+args+`}`)
		if verdict.Action != guardrailActionBlock || verdict.Severity != "CRITICAL" {
			t.Errorf("exec %s = %s %s (%s), want a CRITICAL block", args, verdict.Action, verdict.Severity, verdict.Reason)
		}
	}
	_, verdict := postInspectForConnector(t, api, "openclaw",
		`{"tool":"exec","args":{"command":"echo hello > /tmp/dc-x.txt","env":{"DCX":"1"}}}`)
	if verdict.Action == guardrailActionBlock {
		t.Errorf("benign exec with env = %s (%s), want no block", verdict.Action, verdict.Reason)
	}
}

// GAP-1451: an OpenClaw block is a finding attributed to connector openclaw
// with target openclaw:exec, and its inspect-tool-block row carries the
// verdict's severity.
func TestInspectToolBlockAttributesOpenClawFinding(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	installRedirectReductionRules(t, "openclaw", redirectReductionRule(
		"TEST-MARKER-BLOCK", redirectReductionMarker,
		`f.commands.exists(c, c.argv.exists(a, a == "`+redirectReductionMarker+`"))`,
	))
	_, verdict := postInspectForConnector(t, api, "openclaw",
		`{"tool":"exec","args":{"command":"echo dc-block-marker > /tmp/dc-x.txt"}}`)
	if verdict.Action != guardrailActionBlock {
		t.Fatalf("verdict = %s, want block", verdict.Action)
	}
	events, err := api.store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	var finding, block bool
	for _, event := range events {
		switch event.Action {
		case "scan-finding":
			finding = true
			target := auditStringValue(event.Structured["defenseclaw.finding.target_ref"])
			if event.Connector != "openclaw" || target != "openclaw:exec" || event.Severity != "CRITICAL" {
				t.Errorf("scan-finding connector=%q target=%q severity=%q, want openclaw, openclaw:exec, CRITICAL",
					event.Connector, target, event.Severity)
			}
		case "inspect-tool-block":
			block = true
			if event.Connector != "openclaw" || event.Severity != "CRITICAL" {
				t.Errorf("inspect-tool-block connector=%q severity=%q, want openclaw, CRITICAL", event.Connector, event.Severity)
			}
		}
	}
	if !finding || !block {
		t.Fatalf("finding=%t block=%t, want both rows", finding, block)
	}
}
