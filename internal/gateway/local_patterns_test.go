// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// repoRoot resolves the absolute path of the repo root from this test
// file. The other rulepack tests inline this; centralizing it here
// keeps the local-patterns suite self-contained.
func repoRootFromTestFile(t *testing.T) string {
	t.Helper()
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// .../internal/gateway/local_patterns_test.go -> repo root
	return filepath.Join(filepath.Dir(selfPath), "..", "..")
}

// withLocalPatternsRestored snapshots the compiled-in baselines and
// restores them after the test. Required because ApplyLocalPatternsOverride
// mutates package globals; without restoring, later tests in the same
// package would observe an unexpected pattern set.
func withLocalPatternsRestored(t *testing.T) {
	t.Helper()
	localPatternsMu.RLock()
	saveInjection := append([]string(nil), injectionPatterns...)
	saveInjectionRegexes := append([]*regexp.Regexp(nil), injectionRegexes...)
	savePII := append([]string(nil), piiRequestPatterns...)
	savePIIData := append([]*regexp.Regexp(nil), piiDataRegexes...)
	saveSecrets := append([]string(nil), secretPatterns...)
	saveExfil := append([]string(nil), exfilPatterns...)
	localPatternsMu.RUnlock()

	t.Cleanup(func() {
		localPatternsMu.Lock()
		injectionPatterns = saveInjection
		injectionRegexes = saveInjectionRegexes
		piiRequestPatterns = savePII
		piiDataRegexes = savePIIData
		secretPatterns = saveSecrets
		exfilPatterns = saveExfil
		localPatternsMu.Unlock()
	})
}

// TestLocalPatternsDefaultsParity verifies the bundled
// rules/local-patterns.yaml in each profile produces the same in-memory
// pattern set as the compiled-in defaults. Drift between the YAML and
// Go source would mean an operator who edits the YAML thinking they
// are tuning the active scanner is in fact applying a stale baseline
// that's missing fields the gateway was using before the rule pack
// loaded — exactly the silent-downgrade scenario the YAML loader was
// added to remove.
func TestLocalPatternsDefaultsParity(t *testing.T) {
	policiesRoot := filepath.Join(repoRootFromTestFile(t), "policies", "guardrail")

	for _, profile := range []string{"default", "strict", "permissive"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			rp := mustLoadRulePack(t, filepath.Join(policiesRoot, profile))
			if rp == nil || rp.LocalPatterns == nil {
				t.Fatalf("profile=%s: LocalPatterns nil — loader did not pick up local-patterns.yaml", profile)
			}
			lp := rp.LocalPatterns

			if !reflect.DeepEqual(lp.Injection, defaultInjectionPatterns) {
				t.Errorf("profile=%s injection drift:\n yaml=%v\n go  =%v", profile, lp.Injection, defaultInjectionPatterns)
			}
			if !reflect.DeepEqual(lp.InjectionRegexes, defaultInjectionRegexSources) {
				t.Errorf("profile=%s injection_regexes drift:\n yaml=%v\n go  =%v", profile, lp.InjectionRegexes, defaultInjectionRegexSources)
			}
			if !reflect.DeepEqual(lp.PIIRequests, defaultPIIRequestPatterns) {
				t.Errorf("profile=%s pii_requests drift:\n yaml=%v\n go  =%v", profile, lp.PIIRequests, defaultPIIRequestPatterns)
			}
			if !reflect.DeepEqual(lp.PIIDataRegexes, defaultPIIDataRegexSources) {
				t.Errorf("profile=%s pii_data_regexes drift:\n yaml=%v\n go  =%v", profile, lp.PIIDataRegexes, defaultPIIDataRegexSources)
			}
			if !reflect.DeepEqual(lp.Secrets, defaultSecretPatterns) {
				t.Errorf("profile=%s secrets drift:\n yaml=%v\n go  =%v", profile, lp.Secrets, defaultSecretPatterns)
			}
			if !reflect.DeepEqual(lp.Exfiltration, defaultExfilPatterns) {
				t.Errorf("profile=%s exfiltration drift:\n yaml=%v\n go  =%v", profile, lp.Exfiltration, defaultExfilPatterns)
			}
		})
	}
}

// TestApplyLocalPatternsOverride_NilRestoresDefaults verifies that
// passing nil to the override restores the compiled-in baseline. Used
// by tests that mutated the active set and need to revert before the
// next case.
func TestApplyLocalPatternsOverride_NilRestoresDefaults(t *testing.T) {
	withLocalPatternsRestored(t)

	// Mutate first so the nil-call has something to undo.
	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:      1,
		Injection:    []string{"only-this-phrase"},
		Secrets:      []string{"only-this-secret"},
		Exfiltration: []string{"only-this-exfil"},
	}); err != nil {
		t.Fatal(err)
	}

	localPatternsMu.RLock()
	if len(injectionPatterns) != 1 || injectionPatterns[0] != "only-this-phrase" {
		t.Fatalf("injectionPatterns not overridden: %v", injectionPatterns)
	}
	localPatternsMu.RUnlock()

	if err := ApplyLocalPatternsOverride(nil); err != nil {
		t.Fatal(err)
	}

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if !reflect.DeepEqual(injectionPatterns, defaultInjectionPatterns) {
		t.Errorf("injectionPatterns not restored:\n got =%v\n want=%v", injectionPatterns, defaultInjectionPatterns)
	}
	if !reflect.DeepEqual(secretPatterns, defaultSecretPatterns) {
		t.Errorf("secretPatterns not restored:\n got =%v\n want=%v", secretPatterns, defaultSecretPatterns)
	}
	if !reflect.DeepEqual(exfilPatterns, defaultExfilPatterns) {
		t.Errorf("exfilPatterns not restored:\n got =%v\n want=%v", exfilPatterns, defaultExfilPatterns)
	}
}

// TestApplyLocalPatternsOverride_NilFieldKeepsDefault verifies the
// three-state nil-vs-empty-vs-populated semantics: a nil slice in
// guardrail.LocalPatterns means "don't override this field." Fields
// not set in the YAML must retain their compiled-in baseline so a
// partial operator YAML (e.g. one that only tunes `injection:`)
// doesn't silently wipe out secret/exfil/PII baselines.
func TestApplyLocalPatternsOverride_NilFieldKeepsDefault(t *testing.T) {
	withLocalPatternsRestored(t)

	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version: 1,
		Secrets: []string{"stale-secret-that-must-not-survive"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:   1,
		Injection: []string{"new-injection"},
		// All other fields nil: must remain at defaults.
	}); err != nil {
		t.Fatal(err)
	}

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if !reflect.DeepEqual(injectionPatterns, []string{"new-injection"}) {
		t.Errorf("injection override didn't apply: %v", injectionPatterns)
	}
	if !reflect.DeepEqual(secretPatterns, defaultSecretPatterns) {
		t.Errorf("secrets must remain at defaults when YAML omits the field; got %v", secretPatterns)
	}
	if !reflect.DeepEqual(exfilPatterns, defaultExfilPatterns) {
		t.Errorf("exfiltration must remain at defaults when YAML omits the field; got %v", exfilPatterns)
	}
}

// TestApplyLocalPatternsOverride_EmptySliceClearsField verifies the
// "explicit clear" semantics: a non-nil empty slice means the
// operator intentionally turned off that family. Mostly useful in
// permissive testbed profiles that want to disable triage entirely.
func TestApplyLocalPatternsOverride_EmptySliceClearsField(t *testing.T) {
	withLocalPatternsRestored(t)

	if err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:      1,
		Exfiltration: []string{}, // empty, not nil
	}); err != nil {
		t.Fatal(err)
	}

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if len(exfilPatterns) != 0 {
		t.Errorf("empty Exfiltration slice should clear exfilPatterns; got %v", exfilPatterns)
	}
	if !reflect.DeepEqual(injectionPatterns, defaultInjectionPatterns) {
		t.Errorf("injection must remain at defaults; got %v", injectionPatterns)
	}
}

// TestApplyLocalPatternsOverride_BadRegexRejectsAtomically verifies that an
// invalid candidate cannot partially replace the active scanner state.
func TestApplyLocalPatternsOverride_BadRegexRejectsAtomically(t *testing.T) {
	withLocalPatternsRestored(t)

	active := &guardrail.LocalPatterns{
		Version:          1,
		Injection:        []string{"active-injection"},
		InjectionRegexes: []string{`active\s+injection`},
		PIIRequests:      []string{"active-pii-request"},
		PIIDataRegexes:   []string{`active-pii-\d+`},
		Secrets:          []string{"active-secret"},
		Exfiltration:     []string{"active-exfiltration"},
	}
	if err := ApplyLocalPatternsOverride(active); err != nil {
		t.Fatal(err)
	}
	err := ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:          1,
		Injection:        []string{"candidate-injection"},
		InjectionRegexes: []string{`candidate\s+injection`},
		PIIRequests:      []string{"candidate-pii-request"},
		PIIDataRegexes: []string{
			`candidate-pii-\d+`,
			`(private-unclosed-group`,
		},
		Secrets:      []string{"candidate-secret"},
		Exfiltration: []string{"candidate-exfiltration"},
	})
	if err == nil {
		t.Fatal("invalid local-pattern candidate unexpectedly activated")
	}
	if strings.Contains(err.Error(), "private-unclosed-group") || strings.Contains(err.Error(), "error parsing regexp") {
		t.Fatalf("activation error leaked rejected regex details: %v", err)
	}

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if !reflect.DeepEqual(injectionPatterns, active.Injection) {
		t.Errorf("rejected candidate changed injection patterns: %v", injectionPatterns)
	}
	if got := regexSources(injectionRegexes); !reflect.DeepEqual(got, active.InjectionRegexes) {
		t.Errorf("rejected candidate changed injection regexes: %v", got)
	}
	if !reflect.DeepEqual(piiRequestPatterns, active.PIIRequests) {
		t.Errorf("rejected candidate changed PII request patterns: %v", piiRequestPatterns)
	}
	if got := regexSources(piiDataRegexes); !reflect.DeepEqual(got, active.PIIDataRegexes) {
		t.Errorf("rejected candidate changed PII data regexes: %v", got)
	}
	if !reflect.DeepEqual(secretPatterns, active.Secrets) {
		t.Errorf("rejected candidate changed secret patterns: %v", secretPatterns)
	}
	if !reflect.DeepEqual(exfilPatterns, active.Exfiltration) {
		t.Errorf("rejected candidate changed exfiltration patterns: %v", exfilPatterns)
	}
}

func TestCompileLocalPatternSourcesEnforcesSafeCompilerLimits(t *testing.T) {
	privatePattern := strings.Repeat("a", 2049)
	_, err := compileLocalPatternSources("injection_regexes", []string{privatePattern})
	if err == nil {
		t.Fatal("oversized local regex unexpectedly compiled")
	}
	if got, want := err.Error(), "local-patterns injection_regexes entry 0 contains an invalid regular expression: pattern exceeds size limit"; got != want {
		t.Fatalf("safe compiler error = %q, want %q", got, want)
	}
	if strings.Contains(err.Error(), privatePattern) || strings.Contains(err.Error(), "pattern too long") {
		t.Fatalf("safe compiler error leaked pattern details: %v", err)
	}

	const privateInvalidPattern = "[private-token"
	_, err = compileLocalPatternSources("injection_regexes", []string{privateInvalidPattern})
	if err == nil {
		t.Fatal("malformed local regex unexpectedly compiled")
	}
	if got, want := err.Error(), "local-patterns injection_regexes entry 0 contains an invalid regular expression: pattern syntax is invalid"; got != want {
		t.Fatalf("safe compiler error = %q, want %q", got, want)
	}
	if strings.Contains(err.Error(), privateInvalidPattern) {
		t.Fatalf("safe compiler error leaked pattern details: %v", err)
	}
}

func regexSources(regexes []*regexp.Regexp) []string {
	sources := make([]string, len(regexes))
	for i, re := range regexes {
		sources[i] = re.String()
	}
	return sources
}
