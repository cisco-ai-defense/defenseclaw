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
			rp := guardrail.LoadRulePack(filepath.Join(policiesRoot, profile))
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
	ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:      1,
		Injection:    []string{"only-this-phrase"},
		Secrets:      []string{"only-this-secret"},
		Exfiltration: []string{"only-this-exfil"},
	})

	localPatternsMu.RLock()
	if len(injectionPatterns) != 1 || injectionPatterns[0] != "only-this-phrase" {
		t.Fatalf("injectionPatterns not overridden: %v", injectionPatterns)
	}
	localPatternsMu.RUnlock()

	ApplyLocalPatternsOverride(nil)

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

	ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:   1,
		Injection: []string{"new-injection"},
		// All other fields nil: must remain at defaults.
	})

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

	ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version:      1,
		Exfiltration: []string{}, // empty, not nil
	})

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if len(exfilPatterns) != 0 {
		t.Errorf("empty Exfiltration slice should clear exfilPatterns; got %v", exfilPatterns)
	}
	if !reflect.DeepEqual(injectionPatterns, defaultInjectionPatterns) {
		t.Errorf("injection must remain at defaults; got %v", injectionPatterns)
	}
}

// TestApplyLocalPatternsOverride_BadRegexLoggedNotPanic verifies that
// a malformed entry in `injection_regexes` is logged and dropped
// rather than panicking — operator YAML is operator-typed and a
// regex typo must not crash the gateway on rule-pack reload.
func TestApplyLocalPatternsOverride_BadRegexLoggedNotPanic(t *testing.T) {
	withLocalPatternsRestored(t)

	ApplyLocalPatternsOverride(&guardrail.LocalPatterns{
		Version: 1,
		InjectionRegexes: []string{
			`valid\s+pattern`,
			`(unclosed-group`,
			`also[valid`,
		},
	})

	localPatternsMu.RLock()
	defer localPatternsMu.RUnlock()
	if len(injectionRegexes) != 1 {
		var srcs []string
		for _, re := range injectionRegexes {
			srcs = append(srcs, re.String())
		}
		t.Errorf("expected 1 surviving regex, got %d: %s", len(injectionRegexes), strings.Join(srcs, ", "))
	}
}
