// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// prefilterAnchorsIn reports whether text holds one of set's anchors.
func prefilterAnchorsIn(set ruleAnchorSet, text string) bool {
	folded := ruleFoldCanonical(text)
	for _, anchor := range set.anchors {
		haystack := text
		if anchor.fold {
			haystack = folded
		}
		if strings.Contains(haystack, anchor.text) {
			return true
		}
	}
	return false
}

func prefilterCorpus(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(filepath.Join("testdata", "security_suite"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	corpus := b.String()
	// The case-fold variants regexp's (?i) also matches: upper case, the
	// Kelvin sign for k and the long s for s.
	var variants strings.Builder
	for _, line := range strings.Split(corpus, "\n") {
		if len(line) > 400 || variants.Len() > 200_000 {
			continue
		}
		variants.WriteString(strings.ToUpper(line) + "\n")
		variants.WriteString(strings.NewReplacer("k", "K", "K", "K", "s", "ſ").Replace(line) + "\n")
	}
	return corpus + "\n" + variants.String()
}

// Every match of every built-in rule regex contains one of the anchors the
// prefilter derived for it, over the security suite's corpus and its
// case-fold variants: the prefilter never skips a rule that would match.
func TestRulePrefilterAnchorsAreInEveryMatchOfTheBuiltInRules(t *testing.T) {
	if testing.Short() || hookAnswerRaceBuild {
		t.Skip("corpus sweep: not under -short or the race detector")
	}
	corpus := prefilterCorpus(t)
	generation := mustCompileRulePackGeneration(defaultRuleCategories())
	rules, anchored, matched := 0, 0, 0
	for _, cat := range generation.categories {
		for _, rule := range cat.Rules {
			if rule.Pattern == nil {
				continue
			}
			rules++
			set := ruleAnchorsFor(rule.Pattern)
			if !set.ok {
				continue
			}
			anchored++
			for _, loc := range rule.Pattern.FindAllStringIndex(corpus, -1) {
				matched++
				if m := corpus[loc[0]:loc[1]]; !prefilterAnchorsIn(set, m) {
					t.Errorf("rule %s matched %q but holds none of its anchors %+v", rule.ID, m, set.anchors)
				}
			}
		}
	}
	t.Logf("rules=%d anchored=%d matches checked=%d", rules, anchored, matched)
	if anchored*2 < rules {
		t.Fatalf("only %d of %d rules have anchors", anchored, rules)
	}
}

func TestRulePrefilterDerivesOnlyRequiredLiterals(t *testing.T) {
	filler := strings.Repeat("echo line benign filler for heredoc payload size\n", 200)
	cases := []struct {
		pattern string
		text    string
		match   bool
	}{
		{`(?i)secret_key\s*=`, "ſECRET_KEY =", true},
		{`(?i)(?:api[_-]?key|token)\s*[=:]`, "my ToKeN: x", true},
		{`(?i)(?:foo)?bar`, "BAR", true},
		{`(?i)(?:foo)?bar`, "foo", false},
		{`a{0,3}zz`, "zz", true},
		{`(?:x|[0-9])+done`, "7done", true},
		{`[0-9]{3}-[0-9]{4}`, "555-1234", true},
		{`(?i)\bdd\s+if=`, "DD IF=/dev/zero", true},
		{`(?i)(?:^|\n)[^\n]*ssn[^\n]*,`, "id,SSN,name", true},
		{`(?i)\x{212a}elvin`, "kelvin", true},
		{`(?s)begin.*end`, "begin\nend", true},
	}
	for _, tc := range cases {
		re := regexp.MustCompile(tc.pattern)
		for _, text := range []string{tc.text, filler + tc.text + filler} {
			if got := re.MatchString(text); got != tc.match {
				t.Fatalf("%q on %q: regexp says %v, case wants %v", tc.pattern, tc.text, got, tc.match)
			}
			scan := newRulePrefilterText(text)
			if tc.match && !scan.mayMatch(re) {
				t.Errorf("prefilter skipped %q on a text it matches (%q)", tc.pattern, tc.text)
			}
			rule := PatternRule{ID: "test", Pattern: re}
			if got := firstAcceptedRuleMatchIn(rule, scan) != nil; got != tc.match {
				t.Errorf("firstAcceptedRuleMatchIn(%q) = %v, want %v", tc.pattern, got, tc.match)
			}
		}
	}
	// A class-only pattern has no anchor: it always runs.
	if set := ruleAnchorsFor(regexp.MustCompile(`[0-9]{3}[a-z]{4}`)); set.ok {
		t.Fatalf("a class-only pattern got anchors %+v", set.anchors)
	}
}

// A 950 KB benign Bash heredoc (GAP-2279's payload) skips nearly every
// built-in rule regex, which took about 10 s of rule scanning before.
func TestRulePrefilterSkipsMostRulesForALargeBenignHeredoc(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("cat > /tmp/t8d-heredoc.sh <<'EOF2'\n")
	for sb.Len() < 950_000 {
		sb.WriteString("echo line benign filler for heredoc payload size\n")
	}
	sb.WriteString("EOF2\n")
	scan := newRulePrefilterText(sb.String())
	generation := mustCompileRulePackGeneration(defaultRuleCategories())
	rules, run := 0, 0
	for _, cat := range generation.categories {
		for _, rule := range cat.Rules {
			if rule.Pattern == nil || rule.Expression != "" {
				// An expression rule is decided by the trusted dispatcher.
				continue
			}
			rules++
			if scan.mayMatch(rule.Pattern) {
				run++
				t.Logf("runs %s expression=%t anchors=%+v", rule.ID, rule.Expression != "", ruleAnchorsFor(rule.Pattern).anchors)
			}
		}
	}
	t.Logf("rules=%d regexes run=%d", rules, run)
	if run*5 > rules {
		t.Fatalf("%d of %d rule regexes still run over the benign heredoc", run, rules)
	}
}
