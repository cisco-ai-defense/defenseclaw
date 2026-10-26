// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func shippedRulePatterns(t *testing.T, contentOnly bool) map[string]*regexp.Regexp {
	t.Helper()
	patterns := make(map[string]*regexp.Regexp)
	root := guardrailPoliciesRoot(t)
	for _, profile := range []string{"default", "strict", "permissive"} {
		rp, err := guardrail.LoadRulePack(filepath.Join(root, profile))
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := compileRulePackCategories(rp)
		if err != nil {
			t.Fatal(err)
		}
		for _, category := range compiled.categories {
			for _, rule := range category.Rules {
				if rule.Pattern != nil && (!contentOnly || !rule.ToolCallOnly) {
					patterns[profile+"/"+rule.ID] = rule.Pattern
				}
			}
		}
	}
	return patterns
}

// The literal check only skips a text the rule cannot match: for every
// shipped rule and every sample text, a regexp match implies mayMatch.
func TestRuleLiteralPrefilterNeverSkipsAMatch(t *testing.T) {
	seen := make(map[string]bool)
	var texts []string
	add := func(text string) {
		if text != "" && !seen[text] {
			seen[text] = true
			texts = append(texts, text)
		}
	}
	for _, dir := range []string{"../../policies/guardrail", "../../policies/guardrail-use-cases", "testdata"} {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if ext := filepath.Ext(path); ext != ".yaml" && ext != ".jsonl" && ext != ".json" && ext != ".md" {
				return nil
			}
			if data, readErr := os.ReadFile(path); readErr == nil && len(data) < 4<<20 {
				for _, line := range strings.Split(string(data), "\n") {
					add(line)
					add(strings.ToUpper(line))
				}
			}
			return nil
		})
	}
	texts = append(texts, "ſecret_key = 'ſſſſſſſſſſſſſſſſſſ'", "Key", "cat /etc/ſhadow", "rm -rf /")
	matched := 0
	for name, pattern := range shippedRulePatterns(t, false) {
		for _, text := range texts {
			if !pattern.MatchString(text) {
				continue
			}
			matched++
			if !(&ruleScanText{text: text}).mayMatch(pattern) {
				t.Fatalf("%s: prefilter %q skipped a text the rule matches: %q", name, ruleRequiredLiterals(pattern), text)
			}
		}
	}
	if matched == 0 {
		t.Fatal("fixture: no sample text matched a shipped rule")
	}
}

func TestRuleRequiredLiteralsFoldCase(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		text    string
	}{
		{`(?i)secret`, "ſecret"},
		{`(?i)key`, "Key"},
		{`(?i)(?:curl|wget)\s+http`, "WGET http://x"},
		{`AKIA[0-9A-Z]{16}`, "AKIAABCDEFGHIJKLMNOP"},
	} {
		re := regexp.MustCompile(tc.pattern)
		if !re.MatchString(tc.text) || !(&ruleScanText{text: tc.text}).mayMatch(re) {
			t.Errorf("pattern %s text %q: match=%v literals=%q", tc.pattern, tc.text, re.MatchString(tc.text), ruleRequiredLiterals(re))
		}
	}
	if got := ruleRequiredLiterals(regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)); len(got) == 0 || len(got[0]) != 1 || got[0][0] != "@" {
		t.Errorf("email literals = %q, want [@] first", got)
	}
	if got := ruleRequiredLiterals(regexp.MustCompile(`a^`)); len(got) != 1 || len(got[0]) != 0 || (&ruleScanText{text: "a"}).mayMatch(regexp.MustCompile(`a^`)) {
		t.Errorf("never-matching placeholder literals = %q, want an empty set", got)
	}
	if got := ruleRequiredLiterals(regexp.MustCompile(`a?b*`)); got != nil {
		t.Errorf("optional pattern literals = %q, want none", got)
	}
}

// GAP-1230/GAP-1735/GAP-1217: a post-tool scan of ordinary project code ran
// every shipped rule's regexp over the whole text (about 10 ms per rule per
// MB). Most rules need a literal the text does not hold; their regexps no
// longer run, so the scan's regexp work is bounded by the rules that can
// match, not by the rule count.
func TestBenignPostToolTextRunsOnlyRulesThatCanMatch(t *testing.T) {
	var source strings.Builder
	source.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n)\n\n")
	for i := 0; source.Len() < 256<<10; i++ {
		fmt.Fprintf(&source, "func handler%d(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"ok %%d\", %d) }\n", i, i)
	}
	text := &ruleScanText{text: source.String()}
	patterns := shippedRulePatterns(t, true)
	run := 0
	for name, pattern := range patterns {
		if !strings.HasPrefix(name, "default/") {
			continue
		}
		if text.mayMatch(pattern) {
			run++
		}
	}
	total := 0
	for name := range patterns {
		if strings.HasPrefix(name, "default/") {
			total++
		}
	}
	t.Logf("default pack: %d of %d content rule regexps run on 256 KiB of benign Go", run, total)
	if total == 0 || run*8 > total {
		t.Fatalf("%d of %d content rule regexps run on benign code; want at most an eighth", run, total)
	}
}
