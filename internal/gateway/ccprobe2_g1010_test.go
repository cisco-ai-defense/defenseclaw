// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-1010: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha f1ccff5b7a lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"strings"
	"testing"
)

// TestTrustedActionCorpusBlocksWithRuntimeExpandedRedirectTarget is the
// corpus differential for built-in rules (#925): a POSIX corpus action that
// blocks with an absolute redirect target also blocks with a target the
// shell expands at run time. A glob without a resolved protected target does
// not create a hard block when the corresponding absolute target is ordinary.
// It also pins the review of every built-in code prerequisite: one that
// holds on a redirect-target view and its static-target twin holds on the
// action with a concrete target too. A rule whose prerequisite needs a
// PowerShell or cmd action is inactive on the view, which is POSIX-only, and
// keeps its fallback on the whole action.
func TestCCP2G1010_TrustedActionCorpusBlocksWithRuntimeExpandedRedirectTarget(t *testing.T) {
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
			strings.Contains(command, "<<") || strings.Contains(command, "\n") ||
			strings.Contains(command, "#{") {
			// The corpus uses #{name} as a comment placeholder; a
			// redirect appended to that line would not execute.
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

	// The corpus rows of a profile run concurrently: they are independent
	// calls, as a gateway answers them. One row after another this test
	// took 321 s of a CI race shard and 123 s on four cores of dc-build-2
	// under -race; concurrently 35 s (rel-1-0-6:GAP-0252).
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
			eachConcurrently(len(posix), func(i int) {
				test := posix[i]
				base := strings.TrimSpace(test.Command)
				for _, home := range []string{"/home/alice", ""} {
					want := blocks(test, base+" > /home/alice/out.txt", home)
					for _, target := range []string{"~/out.txt", `"$HOME/out.txt"`, "out-*.txt"} {
						wantTarget := want
						if got := blocks(test, base+" > "+target, home); got != wantTarget {
							t.Errorf("%s home=%q target %s: block = %t, want %t",
								test.ID, home, target, got, wantTarget)
						}
					}
				}
			})
		})
	}
}
