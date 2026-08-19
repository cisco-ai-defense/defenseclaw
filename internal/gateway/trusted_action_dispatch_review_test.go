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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTrustedNestedExecutionActionsCloneActiveAgentFiles(t *testing.T) {
	activeAgentFiles := []string{"/repo/AGENTS.md"}
	want := append([]string(nil), activeAgentFiles...)
	input := actionfacts.Input{
		Tool:             "shell",
		Command:          `eval 'printf updated > /repo/AGENTS.md'`,
		CWD:              "/repo",
		ActiveHome:       "/home/alice",
		ActiveAgentFiles: activeAgentFiles,
	}
	actions := trustedNestedExecutionActions(input, actionfacts.Analyze(input))
	if len(actions) == 0 {
		t.Fatal("static nested execution produced no projected actions")
	}

	nonRaw := 0
	for index := range actions {
		if actions[index].rawFallback {
			continue
		}
		nonRaw++
		if !slices.Equal(actions[index].input.ActiveAgentFiles, want) {
			t.Fatalf(
				"nested input active files = %q, want %q",
				actions[index].input.ActiveAgentFiles,
				want,
			)
		}
		if !slices.Equal(actions[index].facts.ActiveAgentFiles, want) {
			t.Fatalf(
				"nested facts active files = %q, want %q",
				actions[index].facts.ActiveAgentFiles,
				want,
			)
		}
	}
	if nonRaw == 0 {
		t.Fatal("static nested execution produced only raw fallbacks")
	}

	activeAgentFiles[0] = "/mutated/source"
	for index := range actions {
		if actions[index].rawFallback {
			continue
		}
		if !slices.Equal(actions[index].input.ActiveAgentFiles, want) ||
			!slices.Equal(actions[index].facts.ActiveAgentFiles, want) {
			t.Fatalf("nested action retained caller-owned active-file storage: %+v", actions[index])
		}
		actions[index].input.ActiveAgentFiles[0] = "/mutated/projection"
		if !slices.Equal(actions[index].facts.ActiveAgentFiles, want) {
			t.Fatalf("nested facts retained projected-input storage: %+v", actions[index])
		}
	}
}

func TestTrustedInlineCommandOwnerRequiresAuthoritativeFacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		proven  func(actionfacts.Facts) bool
	}{
		{
			name:    "Perl",
			command: `perl -e 'print 1'`,
			proven:  trustedPerlInlineCommandOwnerProven,
		},
		{
			name:    "Ruby",
			command: `ruby -e 'puts 1'`,
			proven:  trustedRubyInlineCommandOwnerProven,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: test.command,
			})
			if !facts.Authoritative() || !test.proven(facts) {
				t.Fatalf("complete inline command was not proven: %+v", facts)
			}
			facts.Parse.Status = actionfacts.StatusPartial
			if test.proven(facts) {
				t.Fatalf("partial inline command was proven: %+v", facts)
			}
		})
	}
}

func TestTrustedSemanticOwnerRuleIndexCoversClaimedIDs(t *testing.T) {
	for ownerID, expected := range semanticOwners {
		expected.id = ownerID
		for _, ruleID := range expected.claimedIDs(true) {
			actual, ok := trustedSemanticOwnerClaimingRule(strings.ToLower(ruleID))
			if !ok || actual.id != ownerID {
				t.Fatalf(
					"semantic owner for %q = %q, %t; want %q",
					ruleID,
					actual.id,
					ok,
					ownerID,
				)
			}
		}
	}
}
