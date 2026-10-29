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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

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
			if !rxprefilter.HasRequiredLiterals(rule.Pattern) {
				continue
			}
			anchored++
			for _, loc := range rule.Pattern.FindAllStringIndex(corpus, -1) {
				matched++
				if m := corpus[loc[0]:loc[1]]; !rxprefilter.RequiredLiteralsIn(rule.Pattern, m) {
					t.Errorf("rule %s matched %q, which misses a literal the prefilter requires", rule.ID, m)
				}
			}
		}
	}
	t.Logf("rules=%d anchored=%d matches checked=%d", rules, anchored, matched)
	if anchored*2 < rules {
		t.Fatalf("only %d of %d rules have anchors", anchored, rules)
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
	scan := rxprefilter.NewText(sb.String())
	generation := mustCompileRulePackGeneration(defaultRuleCategories())
	rules, run := 0, 0
	for _, cat := range generation.categories {
		for _, rule := range cat.Rules {
			if rule.Pattern == nil || rule.Expression != "" {
				// An expression rule is decided by the trusted dispatcher.
				continue
			}
			rules++
			if scan.MayMatch(rule.Pattern) {
				run++
				t.Logf("still runs: %s", rule.ID)
			}
		}
	}
	t.Logf("rules=%d regexes run=%d", rules, run)
	if run*5 > rules {
		t.Fatalf("%d of %d rule regexes still run over the benign heredoc", run, rules)
	}
}
