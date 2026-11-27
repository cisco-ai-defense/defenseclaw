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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const gap1960RuleID = "secrets.sql_sensitive_server_file_read"

// TestGAP1960SQLCLIFormsHaveAuthoritativeCorpusRows pins GAP-1960: the shipped
// CEL expression of secrets.sql_sensitive_server_file_read selects the psql,
// mysql and mariadb command-line forms, so the authoritative tool-call corpus
// needs one positive row per client that the shipped expression, in every
// profile, evaluates true on. Without such rows the expression has no corpus
// target and the CEL corpus matrix gate is red (113/114 expressions).
func TestGAP1960SQLCLIFormsHaveAuthoritativeCorpusRows(t *testing.T) {
	_, rules := loadShippedGuardrailCELRules(t)
	var targeted []guardrailCELRule
	for _, rule := range rules {
		if rule.id == gap1960RuleID {
			targeted = append(targeted, rule)
		}
	}
	if len(targeted) == 0 {
		t.Fatalf("no shipped profile carries %s as a CEL rule", gap1960RuleID)
	}

	covered := map[string]int{"psql": 0, "mysql": 0, "mariadb": 0}
	for _, row := range readSecurityCorpus[toolCallCorpusCase](t, actionFactsSecurityCorpus) {
		if row.RuleID != gap1960RuleID || !row.IsAttack {
			continue
		}
		words := strings.Fields(row.Command)
		if len(words) == 0 {
			continue
		}
		client := words[0]
		if _, want := covered[client]; !want {
			continue
		}
		facts := actionfacts.Analyze(toolCallCorpusActionFactsInput(row))
		if !facts.Authoritative() {
			t.Fatalf("corpus row %q is not authoritative; the CEL matrix skips it", row.ID)
		}
		projection, code := semantic.Project(facts)
		if code != semantic.ProjectionOK {
			t.Fatalf("corpus row %q does not project: %v", row.ID, code)
		}
		for _, rule := range targeted {
			hit, evalCode := rule.program.EvalBool(t.Context(), projection)
			if evalCode != semantic.EvalOK {
				t.Fatalf("profile %s row %q: eval %v", rule.profile, row.ID, evalCode)
			}
			if !hit.Matched {
				t.Fatalf("profile %s: %s does not select corpus row %q (%s)", rule.profile, gap1960RuleID, row.ID, client)
			}
		}
		covered[client]++
	}
	for client, rows := range covered {
		if rows == 0 {
			t.Errorf("no authoritative positive corpus row for the %s command-line form of %s", client, gap1960RuleID)
		}
	}
}

// TestGAP1960SQLCLIExpressionLeavesOrdinaryCommandsAlone is the benign twin:
// an ordinary non-SQL command stays outside the same expression in every
// profile, so widening the corpus did not widen the selector.
func TestGAP1960SQLCLIExpressionLeavesOrdinaryCommandsAlone(t *testing.T) {
	_, rules := loadShippedGuardrailCELRules(t)
	for _, command := range []string{"ls -la", "git status", "cat README.md"} {
		facts := actionfacts.Analyze(toolCallCorpusActionFactsInput(toolCallCorpusCase{
			ID: "gap1960-benign", RuleID: gap1960RuleID, Tool: "shell", Command: command,
		}))
		projection, code := semantic.Project(facts)
		if code != semantic.ProjectionOK {
			t.Fatalf("%q does not project: %v", command, code)
		}
		for _, rule := range rules {
			if rule.id != gap1960RuleID {
				continue
			}
			hit, evalCode := rule.program.EvalBool(t.Context(), projection)
			if evalCode != semantic.EvalOK || hit.Matched {
				t.Errorf("profile %s: %s selected the ordinary command %q (matched=%v code=%v)", rule.profile, gap1960RuleID, command, hit.Matched, evalCode)
			}
		}
	}
}
