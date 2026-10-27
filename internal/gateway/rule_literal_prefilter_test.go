// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

	// The three profiles share most rules: a regexp with the same source
	// gives the same answers, so each distinct source is checked once (under
	// the first profile/rule name that has it). Every text is folded once,
	// before the workers start, so the workers only read it.
	byName := shippedRulePatterns(t, false)
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	var checks []ruleSoundnessCheck
	sources := make(map[string]bool)
	for _, name := range names {
		pattern := byName[name]
		if !sources[pattern.String()] {
			sources[pattern.String()] = true
			checks = append(checks, ruleSoundnessCheck{name: name, pattern: pattern})
		}
	}
	scan := make([]ruleScanText, len(texts))
	for i, text := range texts {
		scan[i] = ruleScanText{text: text, folded: foldRuleText(text), ready: true}
	}

	// The cross product (every distinct rule x every text) is the proof and
	// stays whole; it is split over GOMAXPROCS workers (serial, CI's -race
	// run took about 9 minutes).
	workers := min(runtime.GOMAXPROCS(0), len(checks))
	var (
		next    atomic.Int64
		matched atomic.Int64
		wg      sync.WaitGroup
		mu      sync.Mutex
		skipped []string
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(checks) {
					return
				}
				check := checks[i]
				for j := range scan {
					if !check.pattern.MatchString(scan[j].text) {
						continue
					}
					matched.Add(1)
					if !scan[j].mayMatch(check.pattern) {
						mu.Lock()
						skipped = append(skipped, fmt.Sprintf("%s: prefilter %q skipped a text the rule matches: %q", check.name, ruleRequiredLiterals(check.pattern), scan[j].text))
						mu.Unlock()
						break
					}
				}
			}
		}()
	}
	wg.Wait()
	sort.Strings(skipped)
	for _, msg := range skipped {
		t.Error(msg)
	}
	if matched.Load() == 0 {
		t.Fatal("fixture: no sample text matched a shipped rule")
	}
	t.Logf("%d distinct rule regexps (%d shipped) x %d texts, %d matches, %d workers", len(checks), len(byName), len(scan), matched.Load(), workers)
}

type ruleSoundnessCheck struct {
	name    string
	pattern *regexp.Regexp
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

// GAP-1933: every generation compile copies the rule regexps; the plan cache
// must not keep one entry per copy, or each reload pins a generation.
func TestRuleLiteralPlanCacheDoesNotGrowWithGenerations(t *testing.T) {
	sources := make(map[string]bool)
	generation := func() {
		for _, pattern := range shippedRulePatterns(t, false) {
			sources[pattern.String()] = true
			ruleRequiredLiterals(pattern.Copy()) //nolint:staticcheck // A generation compile copies each regexp.
		}
	}
	cached := func() int {
		count := 0
		ruleLiteralPlans.Range(func(key, _ any) bool {
			var source string
			switch k := key.(type) {
			case string:
				source = k
			case *regexp.Regexp:
				source = k.String()
			}
			if sources[source] {
				count++
			}
			return true
		})
		return count
	}
	for range 5 {
		generation()
	}
	if got, want := cached(), len(sources); got != want {
		t.Fatalf("plan cache holds %d entries for %d distinct shipped patterns after 5 generations", got, want)
	}
}
