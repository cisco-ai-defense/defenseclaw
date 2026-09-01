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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const actionFactsSecurityCorpus = "toolcall/corpus.jsonl"

var textOnlySecurityCorpora = []string{
	"e2e/corpus.jsonl",
	"eval_corpus/exfil/corpus.jsonl",
	"eval_corpus/injection/corpus.jsonl",
	"eval_corpus/pii/corpus.jsonl",
	"eval_corpus/tool_injection/corpus.jsonl",
	"judge/corpus.jsonl",
	"regex/corpus.jsonl",
}

type guardrailCELRule struct {
	profile    string
	category   string
	id         string
	expression string
	program    *semantic.Program
}

type securityCorpusIdentity struct {
	ID string `json:"id"`
}

// TestGuardrailProfilesCELActionFactsCorpusMatrix is the exhaustive native
// compatibility gate for shipped CEL. Every profile is loaded, every embedded
// typed-f expression is compiled as authored, and every compiled program is
// evaluated against every CEL-targeted tool-call case whose ActionFacts are
// authoritative and project successfully, matching the production boundary.
//
// The other security-suite corpora carry text for regex, judge, or HTTP
// surfaces. They cannot construct the authenticated ActionFacts input that
// owns this CEL surface, so the test inventories and reports them separately
// instead of treating them as semantic-rule coverage.
func TestGuardrailProfilesCELActionFactsCorpusMatrix(t *testing.T) {
	profiles, rules := loadShippedGuardrailCELRules(t)
	if len(profiles) == 0 || len(rules) == 0 {
		t.Fatal("shipped guardrail CEL inventory is empty")
	}

	wantCorpora := append([]string{actionFactsSecurityCorpus}, textOnlySecurityCorpora...)
	sort.Strings(wantCorpora)
	if got := discoverSecuritySuiteCorpora(t); !slices.Equal(got, wantCorpora) {
		t.Fatalf("security corpus classification changed: got %v, want %v", got, wantCorpora)
	}

	textOnlyCases := 0
	for _, relative := range textOnlySecurityCorpora {
		rows := readSecurityCorpus[securityCorpusIdentity](t, relative)
		if len(rows) == 0 {
			t.Fatalf("text-only corpus %q is empty", relative)
		}
		requireUniqueCorpusIDs(t, relative, rows)
		textOnlyCases += len(rows)
		t.Logf("text-only corpus %s: %d cases (not ActionFacts-applicable)", relative, len(rows))
	}

	allToolCallCases := readSecurityCorpus[toolCallCorpusCase](t, actionFactsSecurityCorpus)
	if len(allToolCallCases) == 0 {
		t.Fatal("tool-call corpus is empty")
	}

	ruleIDs := make(map[string]struct{})
	uniqueExpressions := make(map[string]struct{})
	expressionsByRuleID := make(map[string]map[string]struct{})
	profileRuleCounts := make(map[string]int, len(profiles))
	for _, rule := range rules {
		ruleIDs[rule.id] = struct{}{}
		uniqueExpressions[rule.expression] = struct{}{}
		profileRuleCounts[rule.profile]++
		if expressionsByRuleID[rule.id] == nil {
			expressionsByRuleID[rule.id] = make(map[string]struct{})
		}
		expressionsByRuleID[rule.id][rule.expression] = struct{}{}
	}

	seenToolCallIDs := make(map[string]struct{}, len(allToolCallCases))
	celTargeted := make([]toolCallCorpusCase, 0, len(allToolCallCases))
	for _, corpusCase := range allToolCallCases {
		if strings.TrimSpace(corpusCase.ID) == "" || strings.TrimSpace(corpusCase.RuleID) == "" {
			t.Fatal("tool-call corpus id and rule_id are required")
		}
		if _, duplicate := seenToolCallIDs[corpusCase.ID]; duplicate {
			t.Fatalf("tool-call corpus repeats id %q", corpusCase.ID)
		}
		seenToolCallIDs[corpusCase.ID] = struct{}{}
		if _, hasCEL := ruleIDs[corpusCase.RuleID]; !hasCEL {
			continue
		}
		celTargeted = append(celTargeted, corpusCase)
	}
	if len(celTargeted) == 0 {
		t.Fatal("tool-call corpus has no CEL-targeted ActionFacts cases")
	}

	evaluations := 0
	applicableCases := 0
	nonAuthoritativeCases := 0
	projectionRejectedCases := 0
	coveredRuleIDs := make(map[string]struct{})
	coveredExpressions := make(map[string]struct{})
	for _, corpusCase := range celTargeted {
		facts := actionfacts.Analyze(toolCallCorpusActionFactsInput(corpusCase))
		if !facts.Authoritative() {
			nonAuthoritativeCases++
			continue
		}
		projection, projectionCode := semantic.Project(facts)
		if projectionCode != semantic.ProjectionOK {
			projectionRejectedCases++
			continue
		}
		applicableCases++
		coveredRuleIDs[corpusCase.RuleID] = struct{}{}
		for expression := range expressionsByRuleID[corpusCase.RuleID] {
			coveredExpressions[expression] = struct{}{}
		}
		for _, rule := range rules {
			_, evalCode := rule.program.EvalBool(t.Context(), projection)
			if evalCode != semantic.EvalOK {
				t.Fatalf(
					"evaluate profile=%q category=%q rule=%q case=%q: %s",
					rule.profile,
					rule.category,
					rule.id,
					corpusCase.ID,
					evalCode,
				)
			}
			evaluations++
		}
	}
	if applicableCases == 0 {
		t.Fatal("tool-call corpus has no authoritative, projectable CEL cases")
	}
	if len(coveredExpressions) != len(uniqueExpressions) {
		t.Fatalf(
			"authoritative tool-call corpus targets %d/%d shipped CEL expressions",
			len(coveredExpressions),
			len(uniqueExpressions),
		)
	}

	wantEvaluations := len(rules) * applicableCases
	if evaluations != wantEvaluations {
		t.Fatalf("CEL evaluations=%d, want complete matrix of %d", evaluations, wantEvaluations)
	}
	for _, profile := range profiles {
		t.Logf("profile %s: %d CEL rule instances", profile, profileRuleCounts[profile])
	}
	t.Logf(
		"guardrail CEL corpus matrix: profiles=%d rule_instances=%d rule_ids=%d unique_expressions=%d toolcall_cases=%d cel_targeted_cases=%d applicable_cases=%d non_authoritative_cel_targets=%d projection_rejected_cel_targets=%d structured_non_cel_targets=%d text_only_cases=%d evaluations=%d",
		len(profiles),
		len(rules),
		len(ruleIDs),
		len(uniqueExpressions),
		len(allToolCallCases),
		len(celTargeted),
		applicableCases,
		nonAuthoritativeCases,
		projectionRejectedCases,
		len(allToolCallCases)-len(celTargeted),
		textOnlyCases,
		evaluations,
	)
	if len(coveredRuleIDs) != len(ruleIDs) {
		t.Logf(
			"targeted-rule coverage: %d/%d CEL rule IDs; every rule still runs over every applicable case and all %d unique expressions are targeted",
			len(coveredRuleIDs),
			len(ruleIDs),
			len(uniqueExpressions),
		)
	}
}

func loadShippedGuardrailCELRules(t *testing.T) ([]string, []guardrailCELRule) {
	t.Helper()
	root := guardrailPoliciesRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read shipped guardrail profiles: %v", err)
	}
	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			profiles = append(profiles, entry.Name())
		}
	}
	sort.Strings(profiles)

	rules := make([]guardrailCELRule, 0)
	for _, profile := range profiles {
		pack := mustLoadRulePack(t, filepath.Join(root, profile))
		if pack == nil {
			t.Fatalf("profile %q returned a nil rule pack", profile)
		}
		if err := pack.Validate(); err != nil {
			t.Fatalf("validate shipped profile %q: %v", profile, err)
		}
		compiler, err := semantic.NewCompiler()
		if err != nil {
			t.Fatalf("construct CEL compiler for profile %q: %v", profile, err)
		}
		profileRules := 0
		for _, ruleFile := range pack.RuleFiles {
			for _, rule := range ruleFile.Rules {
				if rule.Expression == "" {
					continue
				}
				if strings.TrimSpace(rule.Expression) != rule.Expression {
					t.Fatalf("profile %q rule %q CEL has outer whitespace", profile, rule.ID)
				}
				program, compileCode := compiler.Compile(rule.Expression)
				if compileCode != semantic.CompileOK {
					t.Fatalf(
						"compile profile=%q category=%q rule=%q: %s",
						profile,
						ruleFile.Category,
						rule.ID,
						compileCode,
					)
				}
				rules = append(rules, guardrailCELRule{
					profile:    profile,
					category:   ruleFile.Category,
					id:         rule.ID,
					expression: rule.Expression,
					program:    program,
				})
				profileRules++
			}
		}
		if profileRules == 0 {
			t.Fatalf("shipped profile %q has no CEL expressions", profile)
		}
	}
	sort.Slice(rules, func(left, right int) bool {
		if rules[left].profile != rules[right].profile {
			return rules[left].profile < rules[right].profile
		}
		if rules[left].category != rules[right].category {
			return rules[left].category < rules[right].category
		}
		return rules[left].id < rules[right].id
	})
	return profiles, rules
}

func discoverSecuritySuiteCorpora(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("testdata", "security_suite")
	corpora := make([]string, 0, 1+len(textOnlySecurityCorpora))
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "corpus.jsonl" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		corpora = append(corpora, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatalf("discover security-suite corpora: %v", err)
	}
	sort.Strings(corpora)
	return corpora
}

func readSecurityCorpus[T any](t *testing.T, relative string) []T {
	t.Helper()
	return readJSONL[T](t, strings.Split(filepath.ToSlash(relative), "/")...)
}

func requireUniqueCorpusIDs(t *testing.T, relative string, rows []securityCorpusIdentity) {
	t.Helper()
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.ID) == "" {
			t.Fatalf("corpus %q contains a blank id", relative)
		}
		if _, duplicate := seen[row.ID]; duplicate {
			t.Fatalf("corpus %q repeats id %q", relative, row.ID)
		}
		seen[row.ID] = struct{}{}
	}
}
